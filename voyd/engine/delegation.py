"""A delegated identity, verified rather than believed. Pure.

An agent reads *for* somebody. The token it presents names two parties
-- the **principal** it acts for (``sub``) and the **actor** doing the
reading (``act``) -- and the grant between them (``scope``). This module
decides whether such a token is one the boundary may believe, and if so,
what it says.

``verify(token, keys, now, expected)`` is a function of its arguments:
no network, no clock of its own, no cache, no log. The keys are handed
in -- fetched off the request path by ``voyd/wire/jwks.py`` -- so a
slow identity provider cannot stall a read and a test can hand in a
dictionary. The answer is an ``Identity`` or a ``Refusal``, never an
exception, because a boundary that raises on a hostile token has made
the token's author the one who decides what happens next.

**Asymmetric signatures only.** ``RS256``/``RS384``/``RS512``,
``ES256``/``ES384`` and ``EdDSA`` (Ed25519). ``none`` and every ``HS*``
are refused at load and here: a shared secret in the proxy is a key any
operator with the proxy's configuration could mint with, and an ``HS256``
token checked against an RSA public key *as the secret* is the classic
confusion that lets anybody who can read the JWKS forge a token. The
defence is structural: the algorithm must be allowed, and the key the
``kid`` names must be the kind of key that algorithm uses -- an RSA key
for ``RS*``, a P-256 key for ``ES256``, an Ed25519 key for ``EdDSA``.

What is checked, in order: the shape; the header's ``alg`` against the
issuer's allowlist; the ``kid`` against the keys (unknown is a refusal,
not a reason to fetch); the key's type against the algorithm; the
signature; ``iss`` exactly; ``aud`` (a string or a list) against the
declared audience; ``exp`` and ``nbf`` (and an ``iat`` from the future)
with the declared skew; the principal claim; and ``act`` when the read
requires an actor.

The token itself is never kept. An ``Identity`` carries a hash of its
``jti`` (or of the token, when there is no ``jti``), because the identity
travels into claims, stages and stamps, and a bearer token in any of
those is a credential somebody else can present.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Mapping

# The algorithms this verifier implements, and the key each one needs.
# `kty` and, for elliptic curves, `crv` are part of the answer: a key of
# the wrong kind for the header's algorithm is refused before any
# signature arithmetic runs.
ALGORITHMS: dict[str, tuple[str, str | None]] = {
    "RS256": ("RSA", None),
    "RS384": ("RSA", None),
    "RS512": ("RSA", None),
    "ES256": ("EC", "P-256"),
    "ES384": ("EC", "P-384"),
    "EdDSA": ("OKP", "Ed25519"),
}
DEFAULT_ALGORITHMS = ("RS256", "ES256", "EdDSA")

# A token longer than this is not a token anybody issued for a read.
MAX_TOKEN = 16 * 1024
MIN_RSA_BITS = 2048

# Why a token was not believed. Stable strings: rendered, counted and
# asserted against.
MALFORMED = "malformed"
ALGORITHM = "algorithm"
UNKNOWN_KEY = "unknown_key"
KEY_MISMATCH = "key_mismatch"
SIGNATURE = "signature"
ISSUER = "issuer"
AUDIENCE = "audience"
EXPIRED = "expired"
NOT_YET_VALID = "not_yet_valid"
NO_PRINCIPAL = "no_principal"
NO_ACTOR = "no_actor"
UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class Issuer:
    """One identity provider the voydfile trusts, and how to read its tokens.

    Declared with ``voyd.issuer(...)``, which validates it; see
    ``voyd/declare.py``. Every claim name is a path: ``"act.sub"`` reads
    ``sub`` inside ``act``, and a name that is itself a top-level claim
    (``"https://example.com/roles"``) is read as that claim first.
    """

    url: str
    audience: tuple[str, ...]
    jwks: str
    principal: str = "sub"
    actor: str = "act.sub"
    scopes: str = "scope"
    roles: str | None = None
    groups: str | None = None
    tenant: str | None = None
    actor_roles: str | None = None
    actor_groups: str | None = None
    actor_tenant: str | None = None
    algorithms: tuple[str, ...] = DEFAULT_ALGORITHMS
    skew: float = 60.0
    # The server-reported users whose connections may present this
    # issuer's tokens. `"*"` is any connection, authenticated or not,
    # and has to be written out to mean it.
    connection_users: tuple[str, ...] = ()
    # How often keys fetched from a URL are refreshed, and how old the
    # last good set may grow before delegated reads refuse.
    refresh: float = 300.0
    max_age: float = 3600.0

    def permits_connection(self, user: Any) -> bool:
        if "*" in self.connection_users:
            return True
        return isinstance(user, str) and user in self.connection_users

    def describe(self) -> str:
        return (f"{self.url} (audience {list(self.audience)}, "
                f"{'/'.join(self.algorithms)}, keys {self.jwks}, "
                f"connections {list(self.connection_users)})")


@dataclass(frozen=True)
class Identity:
    """What a verified token says: two claim sets, a grant, and a receipt."""

    issuer: str
    principal: Mapping[str, Any]
    actor: Mapping[str, Any] | None
    scopes: tuple[str, ...]
    token: str
    expires: float
    # The fields that decide whether two identities are the same caller,
    # for a cursor bound to the one that opened it.
    key: tuple = field(default=(), compare=False)

    def claims(self) -> dict:
        """The mapping a rule reads. See ``admission/sides.py``.

        The principal's claims are also spelled flat, so anything that
        reads ``user`` finds the person the read is for, and a rule that
        asks an unqualified claim is asked of both sides.
        """
        principal = dict(self.principal)
        return {**principal,
                "principal": principal,
                "actor": dict(self.actor) if self.actor is not None else None,
                "scopes": list(self.scopes),
                "issuer": self.issuer,
                "token": self.token,
                "delegated": True}


@dataclass(frozen=True)
class Refusal:
    """Why a token was not believed. ``reason`` is stable; ``detail`` is prose."""

    reason: str
    detail: str


def _b64(part: str) -> bytes | None:
    if not part or "=" in part:
        return None
    try:
        return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
    except (ValueError, TypeError):
        return None


def _json(raw: bytes | None) -> dict | None:
    if raw is None:
        return None
    try:
        got = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None
    return got if isinstance(got, dict) else None


def _split(token: Any) -> tuple[dict, dict, bytes, bytes] | Refusal:
    if not isinstance(token, str) or not token or len(token) > MAX_TOKEN:
        return Refusal(MALFORMED, "the token is not a string of plausible size")
    parts = token.split(".")
    if len(parts) != 3:
        return Refusal(MALFORMED, "a JWT is three base64url parts")
    header, payload = _json(_b64(parts[0])), _json(_b64(parts[1]))
    signature = _b64(parts[2]) if parts[2] else b""
    if header is None or payload is None or signature is None:
        return Refusal(MALFORMED, "a part of the token does not decode")
    return header, payload, signature, f"{parts[0]}.{parts[1]}".encode()


def peek_issuer(token: Any) -> str | None:
    """The ``iss`` a token *claims*, unverified. For choosing whose keys to
    verify it with, and for nothing else."""
    parts = _split(token)
    if isinstance(parts, Refusal):
        return None
    iss = parts[1].get("iss")
    return iss if isinstance(iss, str) else None


def pick(claims: Mapping, path: str | None) -> Any:
    """A claim by name or by dotted path. ``None`` when absent."""
    if not path:
        return None
    if path in claims:
        return claims[path]
    here: Any = claims
    for step in path.split("."):
        if not isinstance(here, Mapping) or step not in here:
            return None
        here = here[step]
    return here


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return sorted({v for v in value if isinstance(v, str)})
    return []


def _scopes(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return tuple(sorted(set(value.split())))
    return tuple(_strings(value))


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _int(b: str | None) -> int | None:
    raw = _b64(b) if isinstance(b, str) else None
    return int.from_bytes(raw, "big") if raw else None


def check_key(jwk: Mapping) -> str | None:
    """Why this JWK is unusable, or ``None``. Asked when keys are loaded."""
    kty = jwk.get("kty")
    if "d" in jwk or "p" in jwk or "k" in jwk:
        return ("it carries private or symmetric key material, which a "
                "verifier must never hold")
    if jwk.get("use") not in (None, "sig"):
        return f"its use is {jwk.get('use')!r}, not 'sig'"
    if kty == "RSA":
        n, e = _int(jwk.get("n")), _int(jwk.get("e"))
        if n is None or e is None:
            return "an RSA key needs n and e"
        if n.bit_length() < MIN_RSA_BITS:
            return f"an RSA key under {MIN_RSA_BITS} bits"
        return None
    if kty == "EC":
        if jwk.get("crv") not in ("P-256", "P-384"):
            return f"curve {jwk.get('crv')!r} is not one this verifier uses"
        if _int(jwk.get("x")) is None or _int(jwk.get("y")) is None:
            return "an EC key needs x and y"
        return None
    if kty == "OKP":
        if jwk.get("crv") != "Ed25519":
            return f"curve {jwk.get('crv')!r} is not Ed25519"
        x = jwk.get("x")
        raw = _b64(x) if isinstance(x, str) else None
        if raw is None or len(raw) != 32:
            return "an Ed25519 key needs a 32-byte x"
        return None
    return f"key type {kty!r} is not one this verifier uses"


def keys_from_jwks(doc: Any) -> dict[str, dict]:
    """A JWKS document as ``{kid: jwk}``. Raises ``ValueError`` on anything
    that is not a set of usable public signing keys, by name."""
    if not isinstance(doc, Mapping) or not isinstance(doc.get("keys"), list):
        raise ValueError("a JWKS is an object with a 'keys' list")
    out: dict[str, dict] = {}
    for jwk in doc["keys"]:
        if not isinstance(jwk, Mapping):
            raise ValueError("every JWKS entry is an object")
        kid = jwk.get("kid")
        if not isinstance(kid, str) or not kid:
            raise ValueError("every key needs a kid: a token names the key it "
                             "was signed with, and an unnamed key cannot be "
                             "chosen without guessing")
        if kid in out:
            raise ValueError(f"kid {kid!r} appears twice")
        why = check_key(jwk)
        if why:
            raise ValueError(f"key {kid!r}: {why}")
        out[kid] = dict(jwk)
    return out


def _signature_holds(alg: str, jwk: Mapping, data: bytes,
                     signature: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
    from cryptography.hazmat.primitives.asymmetric.utils import (
        encode_dss_signature)

    digest = {"256": hashes.SHA256(), "384": hashes.SHA384(),
              "512": hashes.SHA512()}.get(alg[-3:])
    try:
        if alg.startswith("RS"):
            n, e = _int(jwk.get("n")), _int(jwk.get("e"))
            assert n is not None and e is not None and digest is not None
            rsa.RSAPublicNumbers(e, n).public_key().verify(
                signature, data, padding.PKCS1v15(), digest)
            return True
        if alg.startswith("ES"):
            curve: ec.EllipticCurve = (ec.SECP256R1() if jwk.get("crv") == "P-256"
                                       else ec.SECP384R1())
            size = 32 if jwk.get("crv") == "P-256" else 48
            if len(signature) != 2 * size or digest is None:
                return False
            x, y = _int(jwk.get("x")), _int(jwk.get("y"))
            assert x is not None and y is not None
            key = ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
            der = encode_dss_signature(int.from_bytes(signature[:size], "big"),
                                       int.from_bytes(signature[size:], "big"))
            key.verify(der, data, ec.ECDSA(digest))
            return True
        if alg == "EdDSA":
            raw = _b64(str(jwk.get("x")))
            assert raw is not None
            ed25519.Ed25519PublicKey.from_public_bytes(raw).verify(
                signature, data)
            return True
    except (InvalidSignature, ValueError, AssertionError):
        return False
    return False


def token_hash(payload: Mapping, token: str) -> str:
    """The receipt of a token: its ``jti``, or failing that the token, hashed
    under a label so the hash means nothing anywhere else."""
    jti = payload.get("jti")
    basis = f"jti\0{jti}" if isinstance(jti, str) and jti else f"token\0{token}"
    return hashlib.sha256(b"voyd/delegation\0" + basis.encode()).hexdigest()


def verify(token: Any, keys: Mapping[str, Mapping] | None, now: float,
           expected: Issuer, *, require_actor: bool = False
           ) -> Identity | Refusal:
    """Believe this token, or say exactly why not. See the module docstring."""
    parts = _split(token)
    if isinstance(parts, Refusal):
        return parts
    header, payload, signature, signed = parts

    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in ALGORITHMS:
        return Refusal(ALGORITHM, f"algorithm {alg!r} is not an asymmetric "
                                  f"signature this boundary verifies")
    if alg not in expected.algorithms:
        return Refusal(ALGORITHM, f"algorithm {alg!r} is not allowed for "
                                  f"{expected.url}")
    if "crit" in header:
        return Refusal(MALFORMED, "the header declares critical extensions "
                                  "this verifier does not implement")
    if keys is None:
        return Refusal(UNAVAILABLE, f"no current keys for {expected.url}")
    kid = header.get("kid")
    jwk = keys.get(kid) if isinstance(kid, str) else None
    if jwk is None:
        return Refusal(UNKNOWN_KEY, f"kid {kid!r} is not among the keys held "
                                    f"for {expected.url}; keys are refreshed "
                                    f"on a timer, never fetched for a read")
    kty, crv = ALGORITHMS[alg]
    if (jwk.get("kty") != kty or (crv is not None and jwk.get("crv") != crv)
            or jwk.get("alg") not in (None, alg)):
        return Refusal(KEY_MISMATCH, f"kid {kid!r} is a {jwk.get('kty')} "
                                     f"{jwk.get('crv') or ''} key, not one "
                                     f"{alg} signs with".replace("  ", " "))
    try:
        holds = _signature_holds(alg, jwk, signed, signature)
    except ImportError:
        return Refusal(UNAVAILABLE, "verifying a token needs `cryptography` "
                                    "(pip install 'voyd[attest]')")
    if not holds:
        return Refusal(SIGNATURE, "the signature does not verify")

    if payload.get("iss") != expected.url:
        return Refusal(ISSUER, f"issued by {payload.get('iss')!r}, not "
                               f"{expected.url!r}")
    aud = payload.get("aud")
    auds = [aud] if isinstance(aud, str) else (
        [a for a in aud if isinstance(a, str)] if isinstance(aud, list) else [])
    if not set(auds) & set(expected.audience):
        return Refusal(AUDIENCE, f"audience {aud!r} does not include "
                                 f"{list(expected.audience)}")
    exp = _number(payload.get("exp"))
    if exp is None:
        return Refusal(EXPIRED, "the token has no exp, and a delegation "
                                "that never ends is not one this accepts")
    if now >= exp + expected.skew:
        return Refusal(EXPIRED, "the token has expired")
    if "nbf" in payload:
        nbf = _number(payload.get("nbf"))
        if nbf is None or now < nbf - expected.skew:
            return Refusal(NOT_YET_VALID, "the token is not valid yet")
    if "iat" in payload:
        iat = _number(payload.get("iat"))
        if iat is None or iat > now + expected.skew:
            return Refusal(NOT_YET_VALID, "the token was issued in the future")

    user = pick(payload, expected.principal)
    if not isinstance(user, str) or not user:
        return Refusal(NO_PRINCIPAL, f"no principal in {expected.principal!r}")
    principal = {"user": user,
                 "roles": _strings(pick(payload, expected.roles)),
                 "groups": _strings(pick(payload, expected.groups)),
                 "tenant": pick(payload, expected.tenant)}
    actor_user = pick(payload, expected.actor)
    actor: dict | None = None
    if isinstance(actor_user, str) and actor_user:
        actor = {"user": actor_user,
                 "roles": _strings(pick(payload, expected.actor_roles)),
                 "groups": _strings(pick(payload, expected.actor_groups)),
                 "tenant": pick(payload, expected.actor_tenant)}
    elif require_actor:
        return Refusal(NO_ACTOR, f"no actor in {expected.actor!r}: this is a "
                                 f"user's token, not an agent acting for one")
    return Identity(issuer=expected.url, principal=principal, actor=actor,
                    scopes=_scopes(pick(payload, expected.scopes)),
                    token=token_hash(payload, token), expires=exp,
                    key=(expected.url, user,
                         actor["user"] if actor else None))
