"""A delegated token is verified by the boundary, never taken on its word.

`verify` is pure -- token, keys, clock and the issuer's declaration in, an
`Identity` or a `Refusal` out -- so every way a token can be wrong is a
unit test here, for every algorithm the verifier implements. Nothing in
this file opens a socket.
"""

from __future__ import annotations

import base64
import json
import time

import pytest

pytest.importorskip("cryptography")

from voyd import declare
from voyd.engine.delegation import (ALGORITHM, AUDIENCE, EXPIRED, ISSUER,
                                    KEY_MISMATCH, MALFORMED, NO_ACTOR,
                                    NO_PRINCIPAL, NOT_YET_VALID, SIGNATURE,
                                    UNAVAILABLE, UNKNOWN_KEY, Identity,
                                    Issuer, Refusal, keys_from_jwks,
                                    peek_issuer, verify)
from voyd.testing import TestIssuer
from voyd.wire.jwks import Trust

NOW = 1_800_000_000.0
URL = "https://login.test"
AUD = "voyd://test"


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def expected(**kw) -> Issuer:
    base = dict(url=URL, audience=(AUD,), jwks="unused.json",
                roles="roles", tenant="org", actor_roles="act.roles",
                connection_users=("*",),
                algorithms=("RS256", "ES256", "EdDSA"))
    base.update(kw)
    return Issuer(**base)


@pytest.fixture(scope="module", params=["EdDSA", "ES256", "RS256"])
def idp(request) -> TestIssuer:
    return TestIssuer(URL, alg=request.param, audience=AUD)


def keys(*issuers: TestIssuer) -> dict:
    return keys_from_jwks({"keys": [i.jwk() for i in issuers]})


def refused(got, reason: str) -> Refusal:
    assert isinstance(got, Refusal), got
    assert got.reason == reason, got
    return got


# ---- what a good token says ---------------------------------------------

def test_a_good_token_names_both_parties_and_the_grant(idp):
    token = idp.mint("alice", actor="support-bot", scope="notes:read x:y",
                     now=NOW, roles=["support"], org="acme",
                     actor_claims={"roles": ["support", "admin"]})
    got = verify(token, keys(idp), NOW, expected())
    assert isinstance(got, Identity)
    assert got.principal == {"user": "alice", "roles": ["support"],
                             "groups": [], "tenant": "acme"}
    assert got.actor == {"user": "support-bot", "roles": ["admin", "support"],
                         "groups": [], "tenant": None}
    assert got.scopes == ("notes:read", "x:y")
    assert got.key == (URL, "alice", "support-bot")
    claims = got.claims()
    assert claims["delegated"] is True and claims["user"] == "alice"
    assert claims["principal"]["tenant"] == "acme"


def test_the_token_itself_is_never_kept(idp):
    token = idp.mint("alice", actor="bot", now=NOW)
    got = verify(token, keys(idp), NOW, expected())
    assert isinstance(got, Identity)
    assert token not in json.dumps(got.claims())
    assert len(got.token) == 64                     # a sha256, not the jti
    payload = json.loads(base64.urlsafe_b64decode(
        token.split(".")[1] + "=="))
    assert payload["jti"] not in got.token


def test_a_user_token_is_a_principal_with_no_actor(idp):
    got = verify(idp.mint("alice", now=NOW), keys(idp), NOW, expected())
    assert isinstance(got, Identity) and got.actor is None
    assert got.claims()["actor"] is None


def test_a_missing_act_is_refused_when_the_read_requires_an_actor(idp):
    got = verify(idp.mint("alice", now=NOW), keys(idp), NOW, expected(),
                 require_actor=True)
    refused(got, NO_ACTOR)


def test_a_url_named_claim_is_read_as_one_claim_not_a_path(idp):
    token = idp.mint("alice", now=NOW, **{"https://ex.com/roles": ["legal"]})
    got = verify(token, keys(idp), NOW, expected(roles="https://ex.com/roles"))
    assert isinstance(got, Identity) and got.principal["roles"] == ["legal"]


def test_a_mapping_naming_an_absent_claim_yields_an_empty_value(idp):
    got = verify(idp.mint("alice", now=NOW), keys(idp), NOW,
                 expected(groups="nope.nothing"))
    assert isinstance(got, Identity) and got.principal["groups"] == []


# ---- every way it can be wrong ------------------------------------------

def test_alg_none_is_refused(idp):
    head = b64(json.dumps({"alg": "none", "kid": idp.kid}).encode())
    body = b64(json.dumps({"iss": URL, "aud": AUD, "sub": "mallory",
                           "exp": NOW + 60}).encode())
    refused(verify(f"{head}.{body}.", keys(idp), NOW, expected()), ALGORITHM)


def test_hs256_signed_with_the_public_key_as_the_secret_is_refused(idp):
    """The classic confusion: the JWKS is public, so anybody can HMAC with it."""
    import hashlib
    import hmac

    head = b64(json.dumps({"alg": "HS256", "kid": idp.kid}).encode())
    body = b64(json.dumps({"iss": URL, "aud": AUD, "sub": "mallory",
                           "exp": NOW + 60}).encode())
    secret = json.dumps(idp.jwk()).encode()
    sig = hmac.new(secret, f"{head}.{body}".encode(), hashlib.sha256).digest()
    refused(verify(f"{head}.{body}.{b64(sig)}", keys(idp), NOW, expected()),
            ALGORITHM)


def test_an_allowed_algorithm_the_issuer_did_not_list_is_refused(idp):
    token = idp.mint("alice", now=NOW)
    others = tuple(a for a in ("RS256", "ES256", "EdDSA") if a != idp.alg)
    refused(verify(token, keys(idp), NOW, expected(algorithms=others)),
            ALGORITHM)


def test_a_header_naming_another_algorithm_than_the_key_is_refused():
    """An EdDSA key named by a token that says RS256: refused before any
    signature arithmetic, whatever the signature bytes are."""
    ed = TestIssuer(URL, alg="EdDSA", audience=AUD)
    token = ed.mint("alice", now=NOW, header={"alg": "RS256"})
    refused(verify(token, keys(ed), NOW, expected()), KEY_MISMATCH)
    es = TestIssuer(URL, alg="ES256", audience=AUD)
    token = es.mint("alice", now=NOW, header={"alg": "EdDSA"})
    refused(verify(token, keys(es), NOW, expected()), KEY_MISMATCH)


def test_a_key_whose_own_alg_disagrees_with_the_header_is_refused():
    es = TestIssuer(URL, alg="ES256", audience=AUD)
    jwk = es.jwk()
    jwk["alg"] = "ES384"
    held = keys_from_jwks({"keys": [jwk]})
    refused(verify(es.mint("alice", now=NOW), held, NOW,
                   expected(algorithms=("ES256", "ES384"))), KEY_MISMATCH)


def test_an_unknown_kid_is_refused_not_fetched(idp):
    other = TestIssuer(URL, alg=idp.alg, audience=AUD)
    refused(verify(other.mint("alice", now=NOW), keys(idp), NOW, expected()),
            UNKNOWN_KEY)


def test_a_token_signed_by_a_different_key_under_the_same_kid_is_refused(idp):
    impostor = TestIssuer(URL, alg=idp.alg, kid=idp.kid, audience=AUD)
    refused(verify(impostor.mint("alice", now=NOW), keys(idp), NOW,
                   expected()), SIGNATURE)


def test_an_edited_payload_is_refused(idp):
    head, body, sig = idp.mint("alice", now=NOW).split(".")
    claims = json.loads(base64.urlsafe_b64decode(body + "=="))
    claims["sub"] = "root"
    forged = b64(json.dumps(claims).encode())
    refused(verify(f"{head}.{forged}.{sig}", keys(idp), NOW, expected()),
            SIGNATURE)


def test_expired_is_refused_and_skew_is_honoured(idp):
    token = idp.mint("alice", now=NOW - 400, ttl=300)       # exp = NOW - 100
    refused(verify(token, keys(idp), NOW, expected(skew=60)), EXPIRED)
    assert isinstance(verify(token, keys(idp), NOW, expected(skew=120)),
                      Identity)


def test_a_token_without_exp_is_refused(idp):
    token = idp.sign({"alg": idp.alg, "kid": idp.kid},
                     {"iss": URL, "aud": AUD, "sub": "alice"})
    refused(verify(token, keys(idp), NOW, expected()), EXPIRED)


def test_not_yet_valid_is_refused(idp):
    token = idp.mint("alice", now=NOW, nbf=NOW + 600)
    refused(verify(token, keys(idp), NOW, expected()), NOT_YET_VALID)
    future = idp.mint("alice", now=NOW + 600)               # iat from the future
    refused(verify(future, keys(idp), NOW, expected()), NOT_YET_VALID)


def test_the_wrong_issuer_is_refused(idp):
    token = idp.mint("alice", now=NOW, iss="https://evil.test")
    refused(verify(token, keys(idp), NOW, expected()), ISSUER)


def test_the_wrong_audience_is_refused_and_a_list_is_read(idp):
    refused(verify(idp.mint("alice", now=NOW, aud="voyd://prod"), keys(idp),
                   NOW, expected()), AUDIENCE)
    listed = idp.mint("alice", now=NOW, aud=["other", AUD])
    assert isinstance(verify(listed, keys(idp), NOW, expected()), Identity)
    refused(verify(idp.mint("alice", now=NOW, aud=None), keys(idp), NOW,
                   expected()), AUDIENCE)


def test_a_token_with_no_principal_is_refused(idp):
    refused(verify(idp.mint("", now=NOW), keys(idp), NOW, expected()),
            NO_PRINCIPAL)


def test_critical_header_extensions_are_refused(idp):
    token = idp.mint("alice", now=NOW, header={"crit": ["b64"]})
    refused(verify(token, keys(idp), NOW, expected()), MALFORMED)


@pytest.mark.parametrize("token", [
    None, "", "a.b", "a.b.c.d", "!!!.###.$$$", "e30.e30.", "x" * 20_000,
    b64(b"[1]") + "." + b64(b"{}") + ".",
    b64(b'{"alg":"EdDSA"}') + "=." + b64(b"{}") + ".AA",
])
def test_malformed_tokens_are_refused_without_raising(token):
    got = verify(token, {}, NOW, expected())
    assert isinstance(got, Refusal)
    assert got.reason in (MALFORMED, ALGORITHM)


def test_no_current_keys_is_its_own_refusal(idp):
    refused(verify(idp.mint("alice", now=NOW), None, NOW, expected()),
            UNAVAILABLE)


def test_the_issuer_a_token_claims_is_only_a_hint(idp):
    assert peek_issuer(idp.mint("alice", now=NOW)) == URL
    assert peek_issuer("garbage") is None


# ---- keys ---------------------------------------------------------------

@pytest.mark.parametrize("jwk, match", [
    ({"kty": "oct", "k": "c2VjcmV0", "kid": "h"}, "symmetric"),
    ({"kty": "RSA", "kid": "r", "n": b64(b"\x01" * 64), "e": "AQAB"},
     "under 2048"),
    ({"kty": "EC", "crv": "P-521", "kid": "e", "x": "AA", "y": "AA"}, "curve"),
    ({"kty": "OKP", "crv": "X25519", "kid": "o", "x": "AA"}, "Ed25519"),
    ({"kty": "OKP", "crv": "Ed25519", "x": b64(b"\x00" * 32)}, "kid"),
    ({"kty": "OKP", "crv": "Ed25519", "kid": "o", "x": b64(b"\x00" * 32),
      "use": "enc"}, "use"),
])
def test_a_jwks_that_is_not_public_signing_keys_is_refused(jwk, match):
    with pytest.raises(ValueError, match=match):
        keys_from_jwks({"keys": [jwk]})


def test_a_jwks_holding_a_private_key_is_refused():
    idp = TestIssuer(URL, alg="EdDSA")
    jwk = {**idp.jwk(), "d": b64(b"\x00" * 32)}
    with pytest.raises(ValueError, match="private"):
        keys_from_jwks({"keys": [jwk]})


def test_keys_go_stale_after_max_age_and_a_refresh_brings_them_back():
    idp = TestIssuer(URL, alg="EdDSA", audience=AUD)
    clock = [NOW]
    served = [True]

    def reader(_where: str) -> dict:
        if not served[0]:
            raise OSError("identity provider down")
        return keys(idp)

    trust = Trust({URL: expected(refresh=60, max_age=600)},
                  clock=lambda: clock[0], reader=reader)
    assert trust.preload() == []
    assert trust.keys(URL, NOW) is not None
    served[0] = False
    clock[0] = NOW + 300
    assert trust.load(URL) is False                  # last good set kept
    assert trust.keys(URL, clock[0]) is not None
    assert "down" in trust.why[URL]
    clock[0] = NOW + 601
    assert trust.keys(URL, clock[0]) is None         # too old to believe
    served[0] = True
    assert trust.load(URL) is True
    assert trust.keys(URL, clock[0]) is not None


def test_the_refresh_runs_off_the_request_path_on_a_timer():
    import asyncio

    idp = TestIssuer(URL, alg="EdDSA", audience=AUD)
    reads: list[float] = []

    def reader(_where: str) -> dict:
        reads.append(time.monotonic())
        return keys(idp)

    async def run() -> None:
        trust = Trust({URL: expected(refresh=0.2, max_age=10)}, reader=reader)
        trust.preload()
        stopping = asyncio.Event()
        task = asyncio.ensure_future(trust.refreshing(stopping))
        await asyncio.sleep(1.3)
        stopping.set()
        await task

    asyncio.run(run())
    assert len(reads) >= 2


# ---- the declaration ----------------------------------------------------

def declare_issuer(**kw):
    declare.ISSUERS.clear()
    base = dict(audience=AUD, jwks="keys.json", connection_users=("svc",))
    base.update(kw)
    try:
        declare.issuer(kw.pop("url", URL), **base)
        return declare.ISSUERS[URL]
    finally:
        declare.ISSUERS.clear()


@pytest.mark.parametrize("kw, match", [
    ({"algorithms": ("HS256",)}, "HS256"),
    ({"algorithms": ("none",)}, "none"),
    ({"algorithms": ("RS256", "hs512")}, "hs512"),
    ({"algorithms": ("PS256",)}, "not one of"),
    ({"algorithms": ()}, "accepts nothing"),
    ({"jwks": "http://login.test/jwks"}, "plain http"),
    ({"jwks": "ftp://x/jwks"}, "neither"),
    ({"audience": ()}, "audience"),
    ({"connection_users": ()}, "connection_users"),
    ({"skew": 3600}, "ten minutes"),
    ({"skew": -1}, "negative"),
    ({"refresh": 600, "max_age": 60}, "stale"),
])
def test_a_declaration_that_could_be_forged_against_is_refused_at_load(
        kw, match):
    with pytest.raises(ValueError, match=match):
        declare_issuer(**kw)


def test_an_issuer_declared_twice_is_refused():
    declare.ISSUERS.clear()
    try:
        declare.issuer(URL, audience=AUD, jwks="k.json",
                       connection_users=("*",))
        with pytest.raises(ValueError, match="twice"):
            declare.issuer(URL, audience=AUD, jwks="k.json",
                           connection_users=("*",))
        declare.issuer("https://other.test", audience=AUD, jwks="k2.json",
                       connection_users=("*",))
        assert len(declare.ISSUERS) == 2
    finally:
        declare.ISSUERS.clear()


def test_a_good_declaration_is_what_verify_is_handed():
    got = declare_issuer(roles="https://ex.com/roles", tenant="org",
                         jwks="https://login.test/jwks.json")
    assert got.audience == (AUD,) and got.algorithms == ("RS256", "ES256",
                                                          "EdDSA")
    assert got.permits_connection("svc") and not got.permits_connection("x")
    assert not got.permits_connection(None)


def test_a_policy_requiring_delegation_with_no_issuer_is_refused(tmp_path):
    path = tmp_path / "voydfile.py"
    path.write_text(
        "from voyd import guard, deadline\n"
        "@guard('notes', delegation='required')\n"
        "class Notes:\n"
        "    expire_at = deadline()\n")
    with pytest.raises(ValueError, match="no issuer"):
        declare.load(str(path))


@pytest.mark.parametrize("kw, match", [
    ({"delegation": "sometimes"}, "delegation"),
    ({"scope": "two words"}, "one scope"),
    ({"scope": "x", "delegation": "forbidden"}, "contradiction"),
])
def test_guard_delegation_options_are_checked_at_load(kw, match):
    with pytest.raises(ValueError, match=match):
        declare.guard("notes", **kw)
