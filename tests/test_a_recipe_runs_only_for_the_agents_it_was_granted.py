"""A recipe runs only for the agents it was granted, and the plan says so.

``@recipe(..., actors=(...), scopes=(...))`` makes a recipe a grant: only
a delegated identity may run it, its actor must be listed when
``actors=`` is given, and its token must hold one listed scope when
``scopes=`` is given -- both, when both are. A plain read of a granted
recipe is refused. ``recipes_for`` answers the same question for a tool
list, and ``voyd-plan`` reports a grant that widens as fail-open.

Pure, except the last test: a real driver through a real ``voyd-wire``.
"""

from __future__ import annotations

import textwrap

import bson
import pytest

from voyd.declare import load
from voyd.engine.plan import (RECIPE_CHANGED, RECIPE_GRANT_NARROWED,
                              RECIPE_GRANT_WIDENED, structural)
from voyd.testing import TestIssuer
from voyd.wire.codec import decode_sections, encode_op_msg
from voyd.wire.policy import Guard, expand_recipe, recipes_for

pytest.importorskip("cryptography")

HEAD = '''
from voyd import guard, deadline, issuer, recipe

issuer("https://login.test", audience="voyd://test", jwks="{jwks}",
       connection_users=("*",))

@guard("t"{guard_args})
class T:
    expire_at = deadline()
'''


def policy(tmp_path, body, *, guard_args="", name="voydfile"):
    jwks = tmp_path / "jwks.json"
    if not jwks.exists():
        TestIssuer().write_jwks(str(jwks))
    path = tmp_path / f"{name}.py"
    path.write_text(textwrap.dedent(HEAD.format(jwks=jwks,
                                                guard_args=guard_args))
                    + textwrap.dedent(body))
    return load(str(path))


GRANTED = '''
@recipe("open", collection="t")
def open_(): return [{"$match": {}}]

@recipe("support", collection="t", actors=("support-bot",))
def support(): return [{"$match": {}}]

@recipe("scoped", collection="t", scopes=("t:read", "t:all"))
def scoped(): return [{"$match": {}}]

@recipe("both", collection="t", actors=("support-bot",), scopes=("t:read",))
def both(): return [{"$match": {}}]
'''


def delegated(actor="support-bot", scopes=("t:read",)) -> dict:
    return {"user": "alice", "delegated": True,
            "principal": {"user": "alice", "roles": []},
            "actor": {"user": actor, "roles": []} if actor else None,
            "scopes": list(scopes), "issuer": "https://login.test",
            "token": "0" * 64}


PLAIN = {"user": "svc", "db": "admin", "roles": [], "groups": []}


@pytest.fixture
def guards(tmp_path):
    return {n: Guard(s) for n, s in policy(tmp_path, GRANTED).items()}


def run(guards, name, claims):
    body = {"aggregate": "t", "pipeline": [{"$recipe": {"name": name}}],
            "cursor": {}, "$db": "app"}
    return expand_recipe(encode_op_msg(7, 0, 0, body), 7, 0, guards, False,
                         claims)


def errmsg(refusal: bytes) -> str:
    return bson.decode(refusal[21:])["errmsg"]


@pytest.mark.parametrize("name, claims, runs", [
    ("open", PLAIN, True),
    ("open", None, True),
    ("support", delegated(), True),
    ("support", delegated(actor="billing-bot"), False),
    ("support", delegated(actor=None), False),
    ("support", PLAIN, False),
    ("scoped", delegated(scopes=("t:all",)), True),
    ("scoped", delegated(scopes=("other",)), False),
    ("scoped", delegated(actor="anyone", scopes=("t:read",)), True),
    ("both", delegated(), True),
    ("both", delegated(scopes=()), False),                # scope missing
    ("both", delegated(actor="billing-bot"), False),      # actor missing
    ("both", None, False),
])
def test_a_grant_admits_exactly_the_identities_it_names(guards, name,
                                                        claims, runs):
    out, refusal = run(guards, name, claims)
    assert (refusal is None) is runs, refusal and errmsg(refusal)
    if runs:
        assert decode_sections(out)[1]["pipeline"] == [{"$match": {}}]


def test_the_refusal_says_which_condition_failed(guards):
    _, refusal = run(guards, "support", PLAIN)
    assert "no delegated identity" in errmsg(refusal)
    _, refusal = run(guards, "support", delegated(actor="billing-bot"))
    assert "'billing-bot'" in errmsg(refusal)
    _, refusal = run(guards, "scoped", delegated(scopes=("x",)))
    assert "t:read" in errmsg(refusal) and "['x']" in errmsg(refusal)


def test_recipes_for_lists_what_this_caller_may_run(guards):
    names = lambda claims: [r.name for r in recipes_for(claims, guards)]  # noqa: E731
    assert names(None) == ["open"]
    assert names(PLAIN) == ["open"]
    assert names(delegated()) == ["both", "open", "scoped", "support"]
    assert names(delegated(actor="billing-bot")) == ["open", "scoped"]
    assert names(delegated(scopes=())) == ["open", "support"]


def test_recipes_for_takes_a_verified_identity_as_it_stands():
    from voyd.engine.delegation import Identity
    import tempfile
    import pathlib

    with tempfile.TemporaryDirectory() as tmp:
        g = {n: Guard(s) for n, s in policy(pathlib.Path(tmp),
                                            GRANTED).items()}
    who = Identity(issuer="https://login.test",
                   principal={"user": "alice", "roles": []},
                   actor={"user": "support-bot", "roles": []},
                   scopes=("t:read",), token="0" * 64, expires=0.0)
    assert [r.name for r in recipes_for(who, g)] == [
        "both", "open", "scoped", "support"]


def test_recipes_for_asks_the_collections_terms_too(tmp_path):
    g = {n: Guard(s) for n, s in policy(
        tmp_path, GRANTED, guard_args=', delegation="required", '
                                      'scope="t:read"').items()}
    assert recipes_for(PLAIN, g) == []            # required: plain refused
    assert recipes_for(delegated(actor=None), g) == []      # no actor
    assert recipes_for(delegated(scopes=("t:all",)), g) == []  # no scope
    assert [r.name for r in recipes_for(delegated(), g)] == [
        "both", "open", "scoped", "support"]


@pytest.mark.parametrize("body, match", [
    ('@recipe("a", collection="t", actors="support-bot")\n'
     'def a(): return []', "not one string"),
    ('@recipe("a", collection="t", scopes="t:read")\n'
     'def a(): return []', "not one string"),
    ('@recipe("a", collection="t", actors=("",))\n'
     'def a(): return []', "plain, non-empty"),
    ('@recipe("a", collection="t", actors=(" bot",))\n'
     'def a(): return []', "plain, non-empty"),
    ('@recipe("a", collection="t", actors=(1,))\n'
     'def a(): return []', "plain, non-empty"),
    ('@recipe("a", collection="t", actors=("b", "b"))\n'
     'def a(): return []', "twice"),
    ('@recipe("a", collection="t", scopes={"x": 1})\n'
     'def a(): return []', "list of names"),
])
def test_a_malformed_grant_fails_at_load(tmp_path, body, match):
    with pytest.raises(ValueError, match=match):
        policy(tmp_path, body)


def test_a_grant_with_no_issuer_or_on_a_forbidden_collection_fails(tmp_path):
    path = tmp_path / "noissuer" / "voydfile.py"
    path.parent.mkdir()
    path.write_text(textwrap.dedent('''
        from voyd import guard, deadline, recipe
        @guard("t")
        class T:
            expire_at = deadline()
        @recipe("a", collection="t", actors=("bot",))
        def a(): return []
    '''))
    with pytest.raises(ValueError, match="no issuer"):
        load(str(path))
    with pytest.raises(ValueError, match="forbidden"):
        policy(tmp_path, '@recipe("a", collection="t", actors=("bot",))\n'
                         'def a(): return []',
               guard_args=', delegation="forbidden"')


def _version(tmp_path, grant, name):
    body = f'@recipe("a", collection="t"{grant})\ndef a(): return []\n'
    return policy(tmp_path, body, name=name)["t"].recipes[0]


def test_the_version_covers_the_grant_and_an_ungranted_one_is_unchanged(
        tmp_path):
    plain = _version(tmp_path, "", "p")
    again = _version(tmp_path, "", "q")
    granted = _version(tmp_path, ', actors=("bot",)', "r")
    other = _version(tmp_path, ', actors=("bot", "other")', "s")
    assert plain.version == again.version
    assert len({plain.version, granted.version, other.version}) == 3
    assert "granted to actors=['bot']" in granted.describe()


def _findings(tmp_path, before, after):
    was = policy(tmp_path, f'@recipe("a", collection="t"{before})\n'
                           f'def a(): return []\n', name="current")
    now = policy(tmp_path, f'@recipe("a", collection="t"{after})\n'
                           f'def a(): return []\n', name="proposed")
    return {(s.kind, s.fails_open) for s in structural(was, now)
            if s.kind != RECIPE_CHANGED}


@pytest.mark.parametrize("before, after, expected", [
    ("", ', actors=("bot",)', {(RECIPE_GRANT_NARROWED, False)}),
    (', actors=("bot",)', "", {(RECIPE_GRANT_WIDENED, True)}),
    (', actors=("bot",)', ', actors=("bot", "other")',
     {(RECIPE_GRANT_WIDENED, True)}),
    (', actors=("bot", "other")', ', actors=("bot",)',
     {(RECIPE_GRANT_NARROWED, False)}),
    (', scopes=("x",)', ', scopes=("x", "y")', {(RECIPE_GRANT_WIDENED, True)}),
    (', actors=("bot",), scopes=("x",)', ', actors=("bot",)',
     {(RECIPE_GRANT_WIDENED, True)}),       # the scope condition dropped
    (', actors=("bot",)', ', actors=("bot",), scopes=("x",)',
     {(RECIPE_GRANT_NARROWED, False)}),
    (', actors=("a",)', ', actors=("b",)',
     {(RECIPE_GRANT_WIDENED, True), (RECIPE_GRANT_NARROWED, False)}),
    (', actors=("bot",)', ', actors=("bot",)', set()),
])
def test_the_plan_names_a_grant_that_widens_as_fail_open(tmp_path, before,
                                                         after, expected):
    assert _findings(tmp_path, before, after) == expected


# ---- live ----------------------------------------------------------------

IDP = TestIssuer("https://login.grants.test", audience="voyd://grants")

LIVE = '''
from voyd import guard, issuer, recipe, revocable, tenant

issuer("{url}", audience="{aud}", jwks="{jwks}", connection_users=("*",),
       tenant="org")

@guard("tickets", recipes_only=True)
class Tickets:
    org       = tenant()
    forgotten = revocable()

@recipe("support_context", collection="tickets", actors=("support-bot",),
        scopes=("tickets:read",))
def support_context(k: int = 10):
    return [{{"$sort": {{"_id": 1}}}}, {{"$limit": k}}]
'''


@pytest.mark.needs_mongo
def test_a_real_driver_runs_a_granted_recipe_only_as_its_agent(
        boundary, direct, database, tmp_path):
    from pymongo import MongoClient
    from pymongo.errors import OperationFailure

    jwks = IDP.write_jwks(str(tmp_path / "jwks.json"))
    direct[database].tickets.insert_many([
        {"_id": 1, "org": "acme"}, {"_id": 2, "org": "globex"},
        {"_id": 3, "org": "acme"}])
    wire = boundary(LIVE.format(url=IDP.url, aud=IDP.audience, jwks=jwks))
    client = MongoClient(wire.uri, serverSelectionTimeoutMS=15_000)
    tickets = client[database].tickets
    call = [{"$recipe": {"name": "support_context", "params": {"k": 5}}}]
    try:
        token = IDP.mint("alice", actor="support-bot", scope="tickets:read",
                         org="acme")
        got = list(tickets.aggregate(call, comment={"voyd": token}))
        # The tenant is pinned into the expansion, not in front of it.
        assert [d["_id"] for d in got] == [1, 3]
        with pytest.raises(OperationFailure, match="no delegated identity"):
            list(tickets.aggregate(call))
        other = IDP.mint("alice", actor="billing-bot", scope="tickets:read",
                         org="acme")
        with pytest.raises(OperationFailure, match="billing-bot"):
            list(tickets.aggregate(call, comment={"voyd": other}))
        scopeless = IDP.mint("alice", actor="support-bot", org="acme")
        with pytest.raises(OperationFailure, match="tickets:read"):
            list(tickets.aggregate(call, comment={"voyd": scopeless}))
    finally:
        client.close()
