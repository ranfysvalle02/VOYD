"""A delegated read is judged as the principal *and* the actor, together.

An agent reads for somebody. The document may reach its context only if
the user may see it **and** the agent may read it on the user's behalf,
so every caller-reading rule defaults to the intersection:
`restricted_to` needs both sides to overlap, `clearance` takes the lower
rung, `mask(visible_to=...)` unmasks only if both are in the audience,
and `tenant()` is the principal's tenant, which the actor must share.

The first half is pure: rules, masks, push-down and the per-connection
decisions in `policy/delegation.py`, driven with bytes the way the pump
drives them. The second half is a real driver through a real
`voyd-wire`, with the token in `comment` and checked for in the
profiler.
"""

from __future__ import annotations

import time

import bson
import pytest

pytest.importorskip("cryptography")

from voyd.engine import Clearance, Restricted
from voyd.engine.admission import AdmissionSpec
from voyd.engine.admission.masks import Mask
from voyd.engine.admission.sides import sides, tenant_of
from voyd.engine.delegation import Issuer, keys_from_jwks
from voyd.testing import TestIssuer
from voyd.wire.codec import decode_op_msg, decode_sections, encode_op_msg
from voyd.wire.policy import (Delegations, Guard, carries_token, enforce,
                              expressible_clauses, pin_tenant,
                              rewrite_derived_read, take_token)

URL = "https://login.test"
AUD = "voyd://test"


def plain(*roles: str, user: str = "svc") -> dict:
    return {"user": user, "db": "admin", "roles": list(roles),
            "groups": list(roles)}


def delegated(p_roles=(), a_roles=(), *, tenant="acme", a_tenant=None,
              actor=True, scopes=("notes:read",)) -> dict:
    principal = {"user": "alice", "roles": list(p_roles),
                 "groups": list(p_roles), "tenant": tenant}
    return {**principal, "principal": principal,
            "actor": ({"user": "bot", "roles": list(a_roles),
                       "groups": list(a_roles), "tenant": a_tenant}
                      if actor else None),
            "scopes": list(scopes), "issuer": URL, "token": "h",
            "delegated": True}


# ---- whose claims a rule asks --------------------------------------------

def test_a_plain_connection_is_asked_exactly_as_before():
    caller = plain("support")
    assert sides(caller, "roles") == (["support"],)
    assert sides(caller, "principal.roles") == (["support"],)
    assert sides(caller, "actor.roles") == (None,)
    assert sides(None, "roles") == (None,)


def test_a_delegated_read_asks_both_sides_unless_told_one():
    caller = delegated(["support"], ["support", "admin"])
    assert sides(caller, "roles") == (["support"], ["support", "admin"])
    assert sides(caller, "principal.roles") == (["support"],)
    assert sides(caller, "actor.roles") == (["support", "admin"],)
    assert sides(caller, "scopes") == (["notes:read"],)


def test_a_user_token_with_no_actor_is_asked_as_the_principal_alone():
    caller = delegated(["support"], actor=False)
    assert sides(caller, "roles") == (["support"],)
    assert sides(caller, "actor.roles") == (None,)


# ---- the intersection, per rule -----------------------------------------

AUDIENCE_DOC = {"audience": ["legal"]}


def test_restricted_needs_both_sides_to_overlap():
    rule = Restricted(field="audience", claim="roles")
    assert not rule.refuses(AUDIENCE_DOC, caller=delegated(["legal"],
                                                           ["legal"]))
    # The user may; the agent's own roles may not.
    assert rule.refuses(AUDIENCE_DOC, caller=delegated(["legal"], ["support"]))
    # The agent's service roles cannot lift a user who may not.
    assert rule.refuses(AUDIENCE_DOC, caller=delegated(["support"],
                                                       ["legal", "admin"]))


def test_restricted_via_one_side_asks_only_that_side():
    by_user = Restricted(field="audience", claim="principal.roles")
    by_agent = Restricted(field="audience", claim="actor.roles")
    caller = delegated(["legal"], ["support"])
    assert not by_user.refuses(AUDIENCE_DOC, caller=caller)
    assert by_agent.refuses(AUDIENCE_DOC, caller=caller)
    # A plain connection has no actor, so a rule that asks one admits nothing.
    assert by_agent.refuses(AUDIENCE_DOC, caller=plain("legal"))
    assert not by_user.refuses(AUDIENCE_DOC, caller=plain("legal"))


LADDER = Clearance(order=("public", "internal", "secret"),
                   field="level", claim="roles",
                   roles=(("analyst", "internal"), ("sec", "secret")))


def test_clearance_takes_the_lower_of_the_two_rungs():
    both_secret = delegated(["sec"], ["sec"])
    user_secret_agent_internal = delegated(["sec"], ["analyst"])
    assert not LADDER.refuses({"level": "secret"}, caller=both_secret)
    assert LADDER.refuses({"level": "secret"},
                          caller=user_secret_agent_internal)
    assert not LADDER.refuses({"level": "internal"},
                              caller=user_secret_agent_internal)
    # An agent cleared for nothing clears its user for nothing.
    assert LADDER.refuses({"level": "public"}, caller=delegated(["sec"], []))


def test_a_mask_lifts_only_if_both_are_in_the_audience():
    salary = Mask(field="salary", visible_to=("hr",), via="roles")
    assert not salary.applies(delegated(["hr"], ["hr"]))
    assert salary.applies(delegated(["hr"], ["support"]))
    assert salary.applies(delegated(["support"], ["hr"]))
    assert not Mask(field="salary", visible_to=("hr",),
                    via="principal.roles").applies(delegated(["hr"], []))
    # Unchanged for a plain connection.
    assert not salary.applies(plain("hr"))
    assert salary.applies(plain("support"))


def test_the_tenant_is_the_principals_and_the_actor_must_share_it():
    assert tenant_of(delegated(tenant="acme")) == ("acme", None)
    assert tenant_of(delegated(tenant="acme", a_tenant="acme"))[0] == "acme"
    value, why = tenant_of(delegated(tenant="acme", a_tenant="globex"))
    assert value is None and "actor" in why
    value, why = tenant_of(delegated(tenant=None))
    assert value is None and "principal" in why
    assert tenant_of(delegated(tenant="acme", a_tenant="globex"),
                     "principal.tenant") == ("acme", None)


# ---- through a Guard, as the wire judges a batch --------------------------

def batch(docs: list, ns: str = "db.notes") -> bytes:
    return encode_op_msg(9, 1, 0, {"cursor": {"id": 0, "ns": ns,
                                              "firstBatch": docs}, "ok": 1})


def served(raw: bytes) -> list:
    return list(decode_op_msg(raw)[1]["cursor"]["firstBatch"])


def notes_guard() -> Guard:
    return Guard(AdmissionSpec(
        "notes", rules=(Restricted(field="audience", claim="roles"),),
        tenant="org",
        masks=(Mask(field="salary", visible_to=("hr",), via="roles"),)))


DOCS = [{"_id": 1, "org": "acme", "audience": ["hr"], "salary": 10},
        {"_id": 2, "org": "acme", "audience": ["support"], "salary": 20},
        {"_id": 3, "org": "globex", "audience": ["hr"], "salary": 30}]


def test_a_batch_is_judged_as_both_parties_and_scoped_to_the_token_tenant():
    guards = {"notes": notes_guard()}
    out = served(enforce(batch(DOCS[:2]), 9, 1, guards, False,
                         delegated(["hr"], ["hr"])))
    assert [d["_id"] for d in out] == [1] and out[0]["salary"] == 10
    out = served(enforce(batch(DOCS[:2]), 9, 1, guards, False,
                         delegated(["hr", "support"], ["support"])))
    assert [d["_id"] for d in out] == [2] and out[0]["salary"] is None
    # A batch from another tenant is refused whole under the token's.
    assert served(enforce(batch(DOCS[2:]), 9, 1, guards, False,
                          delegated(["hr"], ["hr"]))) == []


def test_existing_policies_behave_exactly_as_before_for_a_plain_connection():
    guards = {"notes": notes_guard()}
    out = served(enforce(batch(DOCS[:2]), 9, 1, guards, False, plain("hr")))
    assert [d["_id"] for d in out] == [1] and out[0]["salary"] == 10
    # The scope still comes from the batch, as it always has.
    out = served(enforce(batch(DOCS[2:]), 9, 1, guards, False, plain("hr")))
    assert [d["_id"] for d in out] == [3]


# ---- push-down keeps working under delegation -----------------------------

def test_push_down_uses_the_intersected_values():
    guard = notes_guard()
    one = expressible_clauses(guard, plain("hr"))
    assert one == [{"audience": {"$in": ["hr"]}}]
    both = expressible_clauses(guard, delegated(["hr", "legal"], ["hr"]))
    assert both == [{"$and": [{"audience": {"$in": ["hr", "legal"]}},
                              {"audience": {"$in": ["hr"]}}]}]
    clause = Clearance(order=("public", "internal", "secret"), field="level",
                       claim="roles", roles=(("analyst", "internal"),
                                             ("sec", "secret")))
    assert clause.clause_for(delegated(["sec"], ["analyst"])) == {
        "level": {"$in": ["public", "internal"]}}


def test_a_count_under_delegation_is_pushed_down_with_the_pinned_tenant():
    guards = {"notes": notes_guard()}
    claims = delegated(["hr"], ["hr"])
    pinned, why = pin_tenant({"count": "notes", "query": {}, "$db": "db"},
                             "org", "acme")
    assert why is None and pinned["query"] == {"org": "acme"}
    raw = encode_op_msg(5, 0, 0, pinned)
    pushed, refusal = rewrite_derived_read(raw, 5, 0, guards, False, claims)
    assert refusal is None and pushed is not None
    query = decode_op_msg(pushed)[1]["query"]
    assert query["org"] == "acme"
    assert {"$and": [{"audience": {"$in": ["hr"]}},
                     {"audience": {"$in": ["hr"]}}]} in query["$and"]


def test_a_reduction_after_a_vector_search_is_pinned_behind_it():
    cmd = {"aggregate": "notes", "pipeline": [
        {"$vectorSearch": {"index": "v"}}, {"$group": {"_id": None}}]}
    pinned, why = pin_tenant(cmd, "org", "acme")
    assert why is None
    assert pinned["pipeline"][1] == {"$match": {"org": "acme"}}
    guards = {"notes": notes_guard()}
    raw = encode_op_msg(5, 0, 0, {**pinned, "$db": "db"})
    pushed, refusal = rewrite_derived_read(raw, 5, 0, guards, False,
                                           delegated(["hr"], ["hr"]))
    assert refusal is None and pushed is not None


def test_a_lone_vector_search_is_left_for_backfill_and_judged_per_document():
    cmd = {"aggregate": "notes", "pipeline": [{"$vectorSearch": {}}]}
    pinned, why = pin_tenant(cmd, "org", "acme")
    assert why is None and pinned["pipeline"] == [{"$vectorSearch": {}}]


def test_a_query_naming_another_tenant_is_refused_not_overridden():
    for cmd in ({"find": "notes", "filter": {"org": "globex"}},
                {"find": "notes", "filter": {"org": {"$in": ["acme", "x"]}}},
                {"aggregate": "notes",
                 "pipeline": [{"$match": {"org": "globex"}}]}):
        pinned, why = pin_tenant(cmd, "org", "acme")
        assert pinned is None and "tenant" in why
    pinned, _ = pin_tenant({"find": "notes", "filter": {"org": "acme",
                                                        "x": 1}}, "org", "acme")
    assert pinned["filter"] == {"org": "acme", "x": 1}


# ---- the per-connection decisions, on bytes -------------------------------

IDP = TestIssuer(URL, alg="EdDSA", audience=AUD)
OTHER = TestIssuer("https://other.test", alg="ES256", audience=AUD)
KEYS = {URL: keys_from_jwks(IDP.jwks()),
        "https://other.test": keys_from_jwks(OTHER.jwks())}


def issuers(*, users=("svc-agent",)) -> dict:
    return {u: Issuer(url=u, audience=(AUD,), jwks="-", tenant="org",
                      roles="roles", actor_roles="act.roles",
                      connection_users=users)
            for u in (URL, "https://other.test")}


def connection(**kw) -> Delegations:
    return Delegations(issuers(**kw), lambda url, _now: KEYS.get(url))


def guards_with(**spec) -> dict:
    base = dict(rules=(Restricted(field="audience", claim="roles"),),
                tenant="org")
    base.update(spec)
    return {"notes": Guard(AdmissionSpec("notes", **base))}


def command(body: dict, req_id: int = 11) -> tuple[bytes, tuple]:
    raw = encode_op_msg(req_id, 0, 0, {**body, "$db": "db"})
    return raw, decode_sections(raw)


def token(sub="alice", actor="support-bot", scope="notes:read",
          idp=IDP, **kw) -> str:
    return idp.mint(sub, actor=actor, scope=scope, org="acme",
                    roles=["support"],
                    actor_claims={"roles": ["support"]}, **kw)


SVC = {"user": "svc-agent", "db": "admin", "roles": [], "groups": []}


def admit(deleg, body, guards=None, who=SVC, req_id=11):
    raw, head = command(body, req_id)
    return deleg.admit(raw, req_id, 0, head, guards or guards_with(), who)


def errmsg(raw: bytes) -> str:
    reply = decode_op_msg(raw)[1]
    assert reply["ok"] == 0
    return reply["errmsg"]


def test_the_token_is_stripped_from_the_bytes_that_go_upstream():
    t = token()
    body = {"find": "notes", "filter": {}, "comment": {"voyd": t}}
    raw, head, claims, refusal = admit(connection(), body)
    assert refusal is None and claims is not None
    assert t.encode() not in raw
    assert b"voyd" not in raw and b"comment" not in raw
    forwarded = decode_sections(raw)[1]
    assert forwarded["filter"] == {"org": "acme"}
    assert "comment" not in forwarded
    assert claims["principal"]["user"] == "alice"
    assert claims["actor"]["user"] == "support-bot"


def test_the_token_is_stripped_from_an_explain_and_from_a_get_more():
    t = token()
    deleg = connection()
    raw, _h, _c, refusal = admit(deleg, {"explain": {
        "find": "notes", "filter": {}, "comment": {"voyd": t}},
        "verbosity": "queryPlanner"})
    assert refusal is None and t.encode() not in raw and b"voyd" not in raw
    assert decode_sections(raw)[1]["explain"]["filter"] == {"org": "acme"}

    raw, _h, _c, refusal = admit(deleg, {"find": "notes", "filter": {},
                                         "comment": {"voyd": t}}, req_id=20)
    assert refusal is None
    deleg.reply(20, encode_op_msg(99, 20, 0, {"cursor": {
        "id": bson.Int64(777), "ns": "db.notes", "firstBatch": []}, "ok": 1}))
    raw, _h, claims, refusal = admit(deleg, {
        "getMore": bson.Int64(777), "collection": "notes",
        "comment": {"voyd": t}}, req_id=21)
    assert refusal is None and claims is not None
    assert t.encode() not in raw and b"voyd" not in raw


def test_a_comment_that_is_the_clients_own_is_forwarded_untouched():
    for comment in ("dashboard", {"trace": "abc"}):
        body = {"find": "notes", "filter": {"org": "acme"}, "comment": comment}
        raw, head = command(body)
        out, _h, claims, refusal = connection().admit(raw, 11, 0, head,
                                                      guards_with(), SVC)
        assert out is raw and claims is None and refusal is None
    assert not carries_token({"find": "x", "comment": "voyd"})
    assert carries_token({"explain": {"find": "x",
                                      "comment": {"voyd": "t"}}})


def test_a_comment_carrying_a_token_and_anything_else_is_refused():
    _t, _b, why = take_token({"find": "notes",
                              "comment": {"voyd": token(), "trace": 1}})
    assert "exactly" in why
    _r, _h, _c, refusal = admit(connection(), {
        "find": "notes", "comment": {"voyd": token(), "trace": 1}})
    assert refusal is not None and "exactly" in errmsg(refusal)
    _t, _b, why = take_token({"find": "notes", "comment": {"voyd": 7}})
    assert "not a string" in why


def test_a_connection_the_issuer_does_not_name_may_not_act_for_anybody():
    _r, _h, _c, refusal = admit(connection(), {
        "find": "notes", "comment": {"voyd": token()}},
        who={"user": "reporting", "roles": []})
    assert refusal is not None and "may not present" in errmsg(refusal)
    _r, _h, _c, refusal = admit(connection(), {
        "find": "notes", "comment": {"voyd": token()}}, who=None)
    assert refusal is not None and "unknown" in errmsg(refusal)
    _r, _h, claims, refusal = admit(connection(users=("*",)), {
        "find": "notes", "comment": {"voyd": token()}},
        who={"user": None, "roles": []})
    assert refusal is None and claims is not None


def test_a_token_from_an_issuer_nobody_declared_is_refused():
    stranger = TestIssuer("https://evil.test", alg="EdDSA", audience=AUD)
    _r, _h, _c, refusal = admit(connection(), {
        "find": "notes", "comment": {"voyd": token(idp=stranger)}})
    assert refusal is not None and "does not trust" in errmsg(refusal)
    bare = Delegations({}, lambda *_: None)
    _r, _h, _c, refusal = admit(bare, {"find": "notes",
                                       "comment": {"voyd": token()}})
    assert refusal is not None and "no issuer" in errmsg(refusal)


def test_multiple_issuers_each_verify_with_their_own_keys():
    _r, _h, claims, refusal = admit(connection(), {
        "find": "notes", "comment": {"voyd": token(idp=OTHER)}})
    assert refusal is None and claims["issuer"] == "https://other.test"
    # A token claiming one issuer and signed by another's key.
    forged = OTHER.mint("alice", actor="bot", iss=URL, org="acme")
    _r, _h, _c, refusal = admit(connection(), {
        "find": "notes", "comment": {"voyd": forged}})
    assert refusal is not None and "not believed" in errmsg(refusal)


def test_an_unverifiable_token_is_refused_and_the_reason_named():
    expired = token(now=time.time() - 3600, ttl=60)
    _r, _h, _c, refusal = admit(connection(), {
        "find": "notes", "comment": {"voyd": expired}})
    assert refusal is not None and "expired" in errmsg(refusal)


def test_a_missing_scope_refuses_the_read_by_name():
    guards = guards_with(scope="notes:read")
    _r, _h, _c, refusal = admit(connection(), {
        "find": "notes", "comment": {"voyd": token(scope="tickets:read")}},
        guards)
    assert refusal is not None
    said = errmsg(refusal)
    assert "notes:read" in said and "tickets:read" in said
    _r, _h, claims, refusal = admit(connection(), {
        "find": "notes", "comment": {"voyd": token(scope="notes:read x")}},
        guards)
    assert refusal is None and claims is not None


def test_delegation_required_refuses_a_plain_read_and_a_user_token():
    guards = guards_with(delegation="required")
    _r, _h, _c, refusal = admit(connection(), {"find": "notes"}, guards)
    assert refusal is not None and "delegated identity" in errmsg(refusal)
    _r, _h, _c, refusal = admit(connection(), {
        "find": "notes", "comment": {"voyd": token(actor=None)}}, guards)
    assert refusal is not None and "no_actor" in errmsg(refusal)
    _r, _h, claims, refusal = admit(connection(), {
        "find": "notes", "comment": {"voyd": token()}}, guards)
    assert refusal is None and claims is not None
    # Writes are not reads and are untouched.
    _r, _h, _c, refusal = admit(connection(), {"insert": "notes"}, guards)
    assert refusal is None


def test_delegation_forbidden_refuses_an_agent_and_serves_a_plain_read():
    guards = guards_with(delegation="forbidden")
    _r, _h, _c, refusal = admit(connection(), {
        "find": "notes", "comment": {"voyd": token()}}, guards)
    assert refusal is not None and "forbidden" in errmsg(refusal)
    _r, _h, claims, refusal = admit(connection(), {"find": "notes"}, guards)
    assert refusal is None and claims is None


def test_a_delegated_token_on_a_write_is_refused():
    _r, _h, _c, refusal = admit(connection(), {
        "insert": "notes", "comment": {"voyd": token()}})
    assert refusal is not None and "reads" in errmsg(refusal)


def test_a_delegated_read_without_a_tenant_claim_is_refused():
    t = IDP.mint("alice", actor="bot", scope="notes:read")
    _r, _h, _c, refusal = admit(connection(), {
        "find": "notes", "comment": {"voyd": t}})
    assert refusal is not None and "tenant" in errmsg(refusal)


def test_a_cursor_keeps_the_identity_that_opened_it():
    deleg = connection()
    alice = token()
    _r, _h, claims, refusal = admit(deleg, {
        "find": "notes", "comment": {"voyd": alice}}, req_id=30)
    assert refusal is None
    opened = encode_op_msg(1, 30, 0, {"cursor": {
        "id": bson.Int64(4242), "ns": "db.notes", "firstBatch": []}, "ok": 1})
    assert deleg.reply(30, opened) == claims

    # No token: the getMore continues as the identity that opened it.
    _r, _h, inherited, refusal = admit(deleg, {
        "getMore": bson.Int64(4242), "collection": "notes"}, req_id=31)
    assert refusal is None and inherited["principal"]["user"] == "alice"
    assert deleg.reply(31, encode_op_msg(2, 31, 0, {"cursor": {
        "id": bson.Int64(4242), "ns": "db.notes", "nextBatch": []},
        "ok": 1}))["principal"]["user"] == "alice"

    # Somebody else's token on alice's cursor.
    _r, _h, _c, refusal = admit(deleg, {
        "getMore": bson.Int64(4242), "collection": "notes",
        "comment": {"voyd": token(sub="bob")}}, req_id=32)
    assert refusal is not None and "different principal" in errmsg(refusal)
    # The same user through a different agent is a different identity.
    _r, _h, _c, refusal = admit(deleg, {
        "getMore": bson.Int64(4242), "collection": "notes",
        "comment": {"voyd": token(actor="other-bot")}}, req_id=33)
    assert refusal is not None

    # A token presented on a cursor opened without one.
    _r, _h, _c, refusal = admit(deleg, {
        "getMore": bson.Int64(5151), "collection": "notes",
        "comment": {"voyd": alice}}, req_id=34)
    assert refusal is not None and "not opened" in errmsg(refusal)

    # Exhausted, the binding goes; killCursors takes it too.
    deleg.reply(31, b"")
    _r, _h, _c, _ = admit(deleg, {"getMore": bson.Int64(4242),
                                  "collection": "notes"}, req_id=35)
    deleg.reply(35, encode_op_msg(3, 35, 0, {"cursor": {
        "id": bson.Int64(0), "ns": "db.notes", "nextBatch": []}, "ok": 1}))
    assert 4242 not in deleg.by_cursor


def test_a_plain_command_is_judged_as_the_connection():
    deleg = connection()
    raw, head = command({"find": "notes", "filter": {"org": "acme"}})
    out, _h, claims, refusal = deleg.admit(raw, 11, 0, head, guards_with(),
                                           SVC)
    assert out is raw and claims is None and refusal is None
    assert deleg.reply(11, b"") is None


# ---- a real driver through a real boundary --------------------------------

POLICY = '''
from voyd import guard, issuer, mask, restricted_to, tenant

issuer("{url}", audience="{aud}", jwks="{jwks}",
       connection_users=("*",), roles="roles", tenant="org",
       actor_roles="act.roles")

@guard("notes", scope="notes:read")
class Notes:
    org      = tenant()
    audience = restricted_to("roles")
    salary   = mask(visible_to=("hr",))
'''


@pytest.fixture
def wired(boundary, direct, database, tmp_path):
    from pymongo import MongoClient

    jwks = IDP.write_jwks(str(tmp_path / "jwks.json"))
    raw = direct[database]
    raw.notes.insert_many([
        {"_id": "a1", "org": "acme", "audience": ["hr"], "salary": 1},
        {"_id": "a2", "org": "acme", "audience": ["support"], "salary": 2},
        {"_id": "a3", "org": "acme", "audience": ["support", "hr"],
         "salary": 3},
        {"_id": "g1", "org": "globex", "audience": ["support", "hr"],
         "salary": 4}])
    wire = boundary(POLICY.format(url=URL, aud=AUD, jwks=jwks))
    client = MongoClient(wire.uri, serverSelectionTimeoutMS=15_000)
    try:
        yield client[database].notes
    finally:
        client.close()


def as_(user_roles, agent_roles, *, scope="notes:read", org="acme") -> dict:
    return {"voyd": IDP.mint("alice", actor="support-bot", scope=scope,
                             org=org, roles=list(user_roles),
                             actor_claims={"roles": list(agent_roles)})}


@pytest.mark.needs_mongo
def test_one_connection_two_users_the_same_query_different_rows(wired):
    hr_user = sorted((d["_id"], d["salary"]) for d in
                     wired.find({}, comment=as_(["hr", "support"],
                                                ["hr", "support"])))
    support_user = sorted((d["_id"], d["salary"]) for d in
                          wired.find({}, comment=as_(["support"],
                                                     ["hr", "support"])))
    assert hr_user == [("a1", 1), ("a2", 2), ("a3", 3)]
    assert support_user == [("a2", None), ("a3", None)]
    # The agent is narrower than its user: the mask stays on.
    narrow = sorted((d["_id"], d["salary"]) for d in
                    wired.find({}, comment=as_(["hr", "support"],
                                               ["support"])))
    assert narrow == [("a2", None), ("a3", None)]


@pytest.mark.needs_mongo
def test_a_count_is_pushed_down_as_both_parties_and_the_token_tenant(wired):
    assert wired.count_documents({}, comment=as_(["support"],
                                                 ["support"])) == 2
    # Only a3 names an audience both the hr user and the support agent hold.
    assert wired.count_documents({}, comment=as_(["hr"], ["support"])) == 1
    assert wired.count_documents({}, comment=as_(["hr"], [])) == 0


@pytest.mark.needs_mongo
def test_a_scopeless_agent_and_a_forged_tenant_are_refused(wired):
    from pymongo.errors import OperationFailure

    with pytest.raises(OperationFailure) as no_scope:
        list(wired.find({}, comment=as_(["hr"], ["hr"], scope="tickets:read")))
    assert "notes:read" in str(no_scope.value)
    with pytest.raises(OperationFailure) as other:
        list(wired.find({"org": "globex"}, comment=as_(["hr"], ["hr"])))
    assert "tenant" in str(other.value)
    # A plain read of a collection that allows it is judged as before.
    assert list(wired.find({"org": "acme"})) == []     # no server roles


@pytest.mark.needs_mongo
def test_a_cursor_continues_as_its_identity_across_batches(wired, direct,
                                                           database):
    direct[database].notes.insert_many(
        [{"_id": f"s{i}", "org": "acme", "audience": ["support"],
          "salary": i} for i in range(25)])
    got = list(wired.find({}, batch_size=5,
                          comment=as_(["support"], ["support"])))
    assert len(got) == 27 and all(d["salary"] is None for d in got)


@pytest.mark.needs_mongo
def test_the_token_never_reaches_the_server(wired, direct, database):
    db = direct[database]
    db.command("profile", 2)
    try:
        comment = as_(["support"], ["support"])
        list(wired.find({"audience": "support"}, comment=comment))
        wired.count_documents({}, comment=comment)
        seen = list(db.system.profile.find({}))
    finally:
        db.command("profile", 0)
    assert seen, "the profiler recorded nothing"
    text = str(seen)
    assert comment["voyd"] not in text
    assert "'voyd'" not in text
