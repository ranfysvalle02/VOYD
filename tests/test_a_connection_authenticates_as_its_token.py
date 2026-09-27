"""A connection that authenticates with a token reads as that token, and only.

``MONGODB-OIDC`` carries a delegated token in ``saslStart``. The boundary
verifies it, binds the connection, and every read on it is then judged as
the principal and actor it names; a ``comment`` token on it may only
narrow. ``--oidc=terminate`` answers the conversation itself and talks
upstream as the boundary; ``--oidc=passthrough`` lets the deployment
validate it too and closes the connection if the two disagree about whom
it names.

Pure first -- the conversation as bytes, and the narrowing as a function
-- then the live half: ``pymongo`` with ``authMechanism="MONGODB-OIDC"``
and a callback returning a test issuer's token, through a real
``voyd-wire --oidc=terminate``.
"""

from __future__ import annotations

import pytest

pytest.importorskip("cryptography")

import asyncio
import base64
import struct
import time

import bson

from voyd.engine.admission import AdmissionSpec
from voyd.engine.admission.rules import Restricted, revoked
from voyd.engine.delegation import Identity, Refusal, narrow
from voyd.testing import TestIssuer
from voyd.wire.codec import decode_op_msg, decode_sections, encode_op_msg
from voyd.wire.policy import Delegations, Guard, Oidc
from voyd.wire.upstream import (UpstreamAuthError, credentials,
                                scram_client_first, scram_proof)

IDP = TestIssuer("https://login.oidc.test", audience="voyd://oidc")
OTHER = TestIssuer("https://login.other.test", audience="voyd://oidc")


def issuers(**kw):
    from voyd.engine.delegation import Issuer
    return {i.url: Issuer(url=i.url, audience=(i.audience,), jwks="-",
                          connection_users=("svc",), roles="roles",
                          tenant="org", **kw)
            for i in (IDP, OTHER)}


def delegations(clock=time.time, **kw) -> Delegations:
    keys = {IDP.url: {IDP.kid: IDP.jwk()}, OTHER.url: {OTHER.kid: OTHER.jwk()}}
    return Delegations(issuers(**kw), lambda url, _now: keys.get(url),
                       clock=clock)


def msg(body: dict, req_id: int = 5) -> tuple[bytes, dict]:
    return encode_op_msg(req_id, 0, 0, body), body


def sasl_start(payload: dict, mechanism="MONGODB-OIDC", req_id=5):
    return msg({"saslStart": 1, "mechanism": mechanism,
                "payload": bson.Binary(bson.encode(payload)),
                "$db": "$external"}, req_id)


def reply_of(raw: bytes) -> dict:
    decoded = decode_op_msg(raw)
    assert decoded is not None
    return dict(decoded[1])


def token(sub="alice", actor="support-bot", **kw):
    kw.setdefault("org", "acme")
    kw.setdefault("roles", ["support"])
    return IDP.mint(sub, actor=actor, **kw)


# ---- terminate -----------------------------------------------------------

def test_terminate_answers_a_one_step_conversation_and_binds():
    d = delegations()
    oidc = Oidc("terminate", d)
    raw, body = sasl_start({"jwt": token()})
    out, answer = oidc.request(raw, 5, body)
    got = reply_of(answer)
    assert got["ok"] == 1.0 and got["done"] is True
    assert d.bound is not None and d.bound.principal["user"] == "alice"
    assert d.bound_claims["actor"]["user"] == "support-bot"


def test_terminate_refuses_a_token_it_does_not_believe():
    d = delegations()
    oidc = Oidc("terminate", d)
    forged = TestIssuer(IDP.url, audience=IDP.audience, kid=IDP.kid)
    for bad in (forged.mint("alice"), "not-a-jwt",
                IDP.mint("alice", ttl=-600),
                IDP.mint("alice", aud="voyd://elsewhere")):
        raw, body = sasl_start({"jwt": bad})
        _, answer = oidc.request(raw, 5, body)
        got = reply_of(answer)
        assert got["ok"] == 0.0 and got["code"] == 18, got
        assert d.bound is None


def test_terminate_answers_the_principal_step_then_the_token():
    d = delegations()
    d.issuers.pop(OTHER.url)
    oidc = Oidc("terminate", d)
    raw, body = sasl_start({"n": "alice"})
    _, answer = oidc.request(raw, 5, body)
    got = reply_of(answer)
    assert got["done"] is False
    assert bson.decode(bytes(got["payload"])) == {"issuer": IDP.url}
    raw, body = msg({"saslContinue": 1, "conversationId": 1,
                     "payload": bson.Binary(bson.encode({"jwt": token()})),
                     "$db": "$external"}, 6)
    _, answer = oidc.request(raw, 6, body)
    assert reply_of(answer)["done"] is True and d.bound is not None


def test_terminate_refuses_other_mechanisms_and_unauthenticated_reads():
    oidc = Oidc("terminate", delegations())
    raw, body = msg({"saslStart": 1, "mechanism": "SCRAM-SHA-256",
                     "payload": bson.Binary(b"n,,n=a,r=b"), "$db": "admin"})
    _, answer = oidc.request(raw, 5, body)
    assert reply_of(answer)["code"] == 18
    for cmd in ({"find": "notes"}, {"insert": "notes", "documents": []},
                {"listDatabases": 1}):
        raw, body = msg({**cmd, "$db": "app"})
        _, answer = oidc.request(raw, 5, body)
        assert answer is not None and reply_of(answer)["code"] == 13
    for cmd in ({"hello": 1}, {"ping": 1}, {"buildInfo": 1}):
        raw, body = msg({**cmd, "$db": "admin"})
        assert oidc.request(raw, 5, body) == (raw, None)


def test_a_terminated_connection_may_only_read():
    d = delegations()
    oidc = Oidc("terminate", d)
    raw, body = sasl_start({"jwt": token()})
    oidc.request(raw, 5, body)
    for cmd in ({"find": "notes"}, {"aggregate": "notes", "pipeline": []},
                {"getMore": 1, "collection": "notes"}, {"listIndexes": "n"}):
        raw, body = msg({**cmd, "$db": "app"})
        assert oidc.request(raw, 5, body)[1] is None, cmd
    for cmd in ({"insert": "notes", "documents": []}, {"drop": "notes"},
                {"aggregate": "notes", "pipeline": [{"$out": "x"}]},
                {"createUser": "x"}):
        raw, body = msg({**cmd, "$db": "app"})
        _, answer = oidc.request(raw, 5, body)
        assert answer is not None and "not a read" in reply_of(
            answer)["errmsg"], cmd


def test_an_expired_binding_asks_the_driver_to_reauthenticate():
    now = [time.time()]
    d = delegations(clock=lambda: now[0])
    oidc = Oidc("terminate", d)
    raw, body = sasl_start({"jwt": IDP.mint("alice", ttl=60, now=now[0])})
    oidc.request(raw, 5, body)
    now[0] += 120
    raw, body = msg({"find": "notes", "$db": "app"})
    _, answer = oidc.request(raw, 5, body)
    assert reply_of(answer)["code"] == 391


def test_speculative_authentication_never_reaches_the_deployment():
    oidc = Oidc("terminate", delegations())
    spec = {"saslStart": 1, "mechanism": "MONGODB-OIDC",
            "payload": bson.Binary(bson.encode({"jwt": token()})),
            "db": "$external"}
    raw, body = msg({"hello": 1, "speculativeAuthenticate": spec,
                     "saslSupportedMechs": "$external.alice",
                     "$db": "admin"})
    out, answer = oidc.request(raw, 5, body)
    assert answer is None
    assert reply_of(out) == {"hello": 1, "$db": "admin"}

    # And the legacy OP_QUERY handshake a driver opens with.
    query = bson.encode({"isMaster": 1, "speculativeAuthenticate": spec})
    payload = (struct.pack("<i", 0) + b"admin.$cmd\x00"
               + struct.pack("<ii", 0, -1) + query)
    legacy = struct.pack("<iiii", 16 + len(payload), 9, 0, 2004) + payload
    stripped = oidc.legacy(legacy)
    assert struct.unpack("<i", stripped[:4])[0] == len(stripped)
    body_at = stripped.index(b"admin.$cmd\x00") + 11 + 8
    assert bson.decode(stripped[body_at:]) == {"isMaster": 1}
    assert b"jwt" not in stripped


# ---- a bound connection's reads ------------------------------------------

def notes() -> dict:
    return {"notes": Guard(AdmissionSpec(
        "notes", rules=(Restricted("audience", "roles"),
                        revoked("forgotten")),
        tenant="org", scope="notes:read"))}


def admit(d, body, req_id=11):
    raw = encode_op_msg(req_id, 0, 0, body)
    return d.admit(raw, req_id, 0, decode_sections(raw), notes(),
                   {"user": None}, False)


def bound(**kw) -> Delegations:
    d = delegations()
    verdict = d.verify(token(**kw))
    assert isinstance(verdict, Identity)
    d.bind(verdict)
    return d


def test_every_read_on_a_bound_connection_is_delegated_and_pinned():
    d = bound(scope="notes:read")
    raw, head, claims, refusal = admit(d, {"find": "notes", "filter": {},
                                           "$db": "app"})
    assert refusal is None and claims["principal"]["user"] == "alice"
    assert head[1]["filter"] == {"org": "acme"}


def test_a_bound_connection_meets_the_collections_terms():
    d = bound(scope="other")
    *_, refusal = admit(d, {"find": "notes", "filter": {}, "$db": "app"})
    assert refusal is not None and b"notes:read" in refusal


def test_a_request_token_may_only_narrow_the_connection():
    d = bound(scope="notes:read tickets:read", roles=["support", "hr"])
    narrower = token(scope="notes:read", roles=["hr"])
    _, _, claims, refusal = admit(d, {"find": "notes", "filter": {},
                                      "comment": {"voyd": narrower},
                                      "$db": "app"})
    assert refusal is None
    assert claims["principal"]["roles"] == ["hr"]
    assert claims["scopes"] == ["notes:read"]
    for other in (token(sub="bob", scope="notes:read"),
                  token(actor="billing-bot", scope="notes:read"),
                  token(scope="notes:read", org="globex"),
                  OTHER.mint("alice", actor="support-bot", org="acme",
                             scope="notes:read")):
        *_, refusal = admit(d, {"find": "notes", "filter": {},
                                "comment": {"voyd": other}, "$db": "app"})
        assert refusal is not None and b"only narrow" in refusal


def test_narrow_intersects_and_never_merges():
    def ident(user="alice", actor="bot", roles=("a", "b"), scopes=("x", "y"),
              tenant="acme", issuer=IDP.url):
        return Identity(issuer=issuer,
                        principal={"user": user, "roles": list(roles),
                                   "groups": [], "tenant": tenant},
                        actor=({"user": actor, "roles": list(roles),
                                "groups": [], "tenant": tenant}
                               if actor else None),
                        scopes=tuple(scopes), token="t", expires=100.0,
                        key=(issuer, user, actor))
    got = narrow(ident(), ident(roles=("b", "c"), scopes=("y", "z")))
    assert isinstance(got, Identity)
    assert got.principal["roles"] == ["b"] and got.scopes == ("y",)
    # A connection with no actor may take one per command.
    assert isinstance(narrow(ident(actor=None), ident()), Identity)
    for asked in (ident(user="bob"), ident(actor="other"), ident(actor=None),
                  ident(tenant="globex"), ident(issuer=OTHER.url)):
        assert isinstance(narrow(ident(), asked), Refusal)


# ---- passthrough ---------------------------------------------------------

def status(user, db="$external") -> dict:
    return {"ok": 1.0, "authInfo": {
        "authenticatedUsers": [{"user": user, "db": db}],
        "authenticatedUserRoles": []}}


def test_passthrough_forwards_a_believed_token_and_binds_when_the_server_agrees():
    d = delegations(server_user="idp/{principal}")
    oidc = Oidc("passthrough", d)
    raw, body = sasl_start({"jwt": token()})
    out, answer = oidc.request(raw, 5, body)
    assert answer is None and out == raw
    assert d.bound is None                      # not until the server says so
    oidc.reply(5, encode_op_msg(1, 5, 0, {"ok": 1.0, "done": True,
                                          "conversationId": 1}))
    assert oidc.check is not None
    assert oidc.settle(status("idp/alice")) is None
    assert d.bound is not None and d.bound.principal["user"] == "alice"


def test_passthrough_closes_a_connection_the_server_names_differently():
    d = delegations(server_user="idp/{principal}")
    oidc = Oidc("passthrough", d)
    for said in (status("idp/bob"), status("alice"),
                 status("idp/alice", db="admin"), None):
        raw, body = sasl_start({"jwt": token()})
        oidc.request(raw, 5, body)
        oidc.reply(5, encode_op_msg(1, 5, 0, {"ok": 1.0, "done": True}))
        why = oidc.settle(said)
        assert why is not None and d.bound is None


def test_passthrough_refuses_an_unbelieved_token_without_forwarding_it():
    d = delegations()
    oidc = Oidc("passthrough", d)
    raw, body = sasl_start({"jwt": IDP.mint("alice", ttl=-600)})
    _, answer = oidc.request(raw, 5, body)
    assert reply_of(answer)["code"] == 18
    # A failure from the server binds nothing either.
    raw, body = sasl_start({"jwt": token()})
    oidc.request(raw, 6, body)
    oidc.reply(6, encode_op_msg(1, 6, 0, {"ok": 0.0, "code": 18}))
    assert oidc.check is None and d.bound is None


def test_passthrough_leaves_other_mechanisms_to_the_deployment():
    oidc = Oidc("passthrough", delegations())
    raw, body = msg({"saslStart": 1, "mechanism": "SCRAM-SHA-256",
                     "payload": bson.Binary(b"n,,n=a,r=b"), "$db": "admin"})
    assert oidc.request(raw, 5, body) == (raw, None)
    raw, body = msg({"find": "notes", "$db": "app"})
    assert oidc.request(raw, 5, body) == (raw, None)


def test_server_user_is_validated_at_load(tmp_path):
    from voyd.declare import load

    path = tmp_path / "voydfile.py"
    IDP.write_jwks(str(tmp_path / "jwks.json"))
    for bad in ('"alice"', '"{principal}/{principal}"', '"{sub}"'):
        path.write_text(
            "from voyd import issuer\n"
            f"issuer('{IDP.url}', audience='a', jwks='{tmp_path}/jwks.json',"
            f" connection_users=('*',), server_user={bad})\n")
        with pytest.raises(ValueError, match="server_user"):
            load(str(path))


# ---- the boundary's own upstream credentials -----------------------------

def test_scram_sha_256_matches_the_rfc_7677_test_vector():
    nonce = "rOprNGfwEbeRWgbNEkqO"
    first = scram_client_first("user", nonce)
    final, expected = scram_proof(
        "pencil", first,
        "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,"
        "s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096", nonce)
    assert final == ("c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)"
                     "hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=")
    assert base64.b64encode(expected).decode() == \
        "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="


def test_scram_refuses_a_server_that_does_not_continue_the_conversation():
    with pytest.raises(UpstreamAuthError):
        scram_proof("p", "n=u,r=abc", "r=zzz,s=AAAA,i=4096", "abc")
    with pytest.raises(UpstreamAuthError, match="iterations"):
        scram_proof("p", "n=u,r=abc", "r=abcd,s=AAAA,i=1", "abc")


def test_credentials_come_from_the_target_and_only_scram_sha_256():
    assert credentials("localhost:27017") is None
    assert credentials("mongodb://h:1/?directConnection=true") is None
    assert credentials("mongodb://svc:pw@h:1/?authSource=ops") == (
        "svc", "pw", "ops")
    assert credentials("mongodb://svc:pw@h:1/app") == ("svc", "pw", "app")
    with pytest.raises(ValueError, match="SCRAM-SHA-256"):
        credentials("mongodb://svc:pw@h:1/?authMechanism=SCRAM-SHA-1")


def test_the_upstream_handshake_checks_the_servers_signature():
    """A fake server speaking SCRAM-SHA-256 as RFC 7677 does."""
    import hashlib
    import hmac

    from voyd.wire.codec import read_message_async
    from voyd.wire.upstream import authenticate

    salt, iterations = b"saltsaltsalt", 4096
    salted = hashlib.pbkdf2_hmac("sha256", b"pw", salt, iterations)
    server_key = hmac.digest(salted, b"Server Key", "sha256")

    async def serve(reader, writer, *, honest: bool):
        raw, *_ = await read_message_async(reader)
        start = reply_of(raw)
        client_first = bytes(start["payload"]).decode()[3:]
        nonce = client_first.split("r=", 1)[1] + "server"
        server_first = (f"r={nonce},s={base64.b64encode(salt).decode()},"
                        f"i={iterations}")
        writer.write(encode_op_msg(1, 1, 0, {
            "ok": 1.0, "conversationId": 1, "done": False,
            "payload": bson.Binary(server_first.encode())}))
        raw, *_ = await read_message_async(reader)
        final = bytes(reply_of(raw)["payload"]).decode()
        without = final.rsplit(",p=", 1)[0]
        message = f"{client_first},{server_first},{without}".encode()
        key = server_key if honest else b"x" * 32
        sig = base64.b64encode(hmac.digest(key, message, "sha256")).decode()
        writer.write(encode_op_msg(2, 2, 0, {
            "ok": 1.0, "conversationId": 1, "done": True,
            "payload": bson.Binary(f"v={sig}".encode())}))
        await writer.drain()
        writer.close()

    async def run(honest: bool):
        server = await asyncio.start_server(
            lambda r, w: serve(r, w, honest=honest), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            try:
                await authenticate(reader, writer, "svc", "pw", "admin")
            finally:
                writer.close()

    asyncio.run(run(True))
    with pytest.raises(UpstreamAuthError, match="signature"):
        asyncio.run(run(False))


# ---- live ----------------------------------------------------------------

LIVE = '''
from voyd import guard, issuer, mask, restricted_to, tenant, revocable

issuer("{url}", audience="{aud}", jwks="{jwks}", connection_users=("*",),
       roles="roles", tenant="org", actor_roles="act.roles")

@guard("notes", scope="notes:read")
class Notes:
    org       = tenant()
    audience  = restricted_to("roles")
    salary    = mask(visible_to=("hr",))
    forgotten = revocable()
'''


@pytest.fixture
def oidc_wire(boundary, direct, database, tmp_path):
    jwks = IDP.write_jwks(str(tmp_path / "jwks.json"))
    direct[database].notes.insert_many([
        {"_id": "a1", "org": "acme", "audience": ["hr"], "salary": 1},
        {"_id": "a2", "org": "acme", "audience": ["support"], "salary": 2},
        {"_id": "a3", "org": "acme", "audience": ["support", "hr"],
         "salary": 3},
        {"_id": "g1", "org": "globex", "audience": ["support", "hr"],
         "salary": 4}])
    return boundary(LIVE.format(url=IDP.url, aud=IDP.audience, jwks=jwks),
                    "--oidc=terminate")


def oidc_client(wire, mint):
    from pymongo import MongoClient
    from pymongo.auth_oidc import OIDCCallback, OIDCCallbackResult

    class Callback(OIDCCallback):
        calls = 0

        def fetch(self, context):
            Callback.calls += 1
            return OIDCCallbackResult(access_token=mint())

    client = MongoClient(
        f"mongodb://127.0.0.1:{wire.port}/?directConnection=true",
        authMechanism="MONGODB-OIDC",
        authMechanismProperties={"OIDC_CALLBACK": Callback()},
        serverSelectionTimeoutMS=8000)
    return client, Callback


@pytest.mark.needs_mongo
def test_a_real_driver_authenticates_with_a_token_and_reads_as_it(
        oidc_wire, database):
    def as_(roles, agent_roles):
        return lambda: IDP.mint("alice", actor="support-bot",
                                scope="notes:read", org="acme",
                                roles=list(roles),
                                actor_claims={"roles": list(agent_roles)})

    hr, _ = oidc_client(oidc_wire, as_(["hr", "support"], ["hr", "support"]))
    support, calls = oidc_client(oidc_wire, as_(["support"], ["support"]))
    try:
        got = sorted((d["_id"], d["salary"])
                     for d in hr[database].notes.find({}))
        assert got == [("a1", 1), ("a2", 2), ("a3", 3)]
        got = sorted((d["_id"], d["salary"])
                     for d in support[database].notes.find({}))
        assert got == [("a2", None), ("a3", None)]
        assert support[database].notes.count_documents({}) == 2
        assert calls.calls >= 1
        # A request token on an authenticated connection may only narrow.
        from pymongo.errors import OperationFailure
        bob = IDP.mint("bob", actor="support-bot", scope="notes:read",
                       org="acme", roles=["support"])
        with pytest.raises(OperationFailure, match="only narrow"):
            list(support[database].notes.find({}, comment={"voyd": bob}))
        # And a bound connection only reads.
        with pytest.raises(OperationFailure, match="not a read"):
            support[database].notes.insert_one({"_id": "x"})
    finally:
        hr.close()
        support.close()


@pytest.mark.needs_mongo
def test_a_wrong_token_fails_authentication(oidc_wire, database):
    from pymongo.errors import OperationFailure

    forged = TestIssuer(IDP.url, audience=IDP.audience, kid=IDP.kid)
    for mint in (lambda: forged.mint("alice", actor="support-bot"),
                 lambda: IDP.mint("alice", actor="support-bot", ttl=-600),
                 lambda: OTHER.mint("alice", actor="support-bot")):
        client, _ = oidc_client(oidc_wire, mint)
        try:
            with pytest.raises(OperationFailure) as failed:
                list(client[database].notes.find({}))
            assert failed.value.code == 18, failed.value
        finally:
            client.close()


@pytest.mark.needs_mongo
def test_without_authenticating_nothing_is_read(oidc_wire, database):
    from pymongo import MongoClient
    from pymongo.errors import OperationFailure

    client = MongoClient(
        f"mongodb://127.0.0.1:{oidc_wire.port}/?directConnection=true",
        serverSelectionTimeoutMS=8000)
    try:
        with pytest.raises(OperationFailure, match="requires authentication"):
            list(client[database].notes.find({}))
    finally:
        client.close()
