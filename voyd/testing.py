"""A stand-in identity provider, for tests and examples. Never for production.

VOYD verifies delegated tokens and never issues them; an identity
provider does that. A suite or an example still needs tokens to present,
signed by keys the boundary can be told about, with no network and no
provider running. This mints them::

    from voyd.testing import TestIssuer

    idp = TestIssuer("https://login.test", alg="EdDSA")
    idp.write_jwks("jwks.json")            # what issuer(jwks=...) reads
    token = idp.mint("alice", actor="support-bot", scope="notes:read",
                     roles=["support"], org="acme")

The private key lives only in this object. ``write_jwks`` writes the
public half, which is all the boundary ever holds. Needs ``cryptography``
(``pip install 'voyd[attest]'``).
"""

from __future__ import annotations

import base64
import json
import time
import uuid
from typing import Any


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _int(n: int) -> str:
    return _b64(n.to_bytes((n.bit_length() + 7) // 8 or 1, "big"))


class TestIssuer:
    """One signing key and the tokens it signs. ``alg`` is ``EdDSA``,
    ``ES256`` or ``RS256``."""

    __test__ = False                    # a helper, not a pytest class

    def __init__(self, url: str = "https://login.test", *,
                 alg: str = "EdDSA", kid: str | None = None,
                 audience: str = "voyd://test"):
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

        self.url = url
        self.alg = alg
        self.kid = kid or f"{alg.lower()}-{uuid.uuid4().hex[:8]}"
        self.audience = audience
        if alg == "EdDSA":
            self.key: Any = ed25519.Ed25519PrivateKey.generate()
        elif alg == "ES256":
            self.key = ec.generate_private_key(ec.SECP256R1())
        elif alg == "RS256":
            self.key = rsa.generate_private_key(public_exponent=65537,
                                                key_size=2048)
        else:
            raise ValueError(f"TestIssuer mints EdDSA, ES256 or RS256, "
                             f"not {alg!r}")

    def jwk(self) -> dict:
        """The public key, as a JWK."""
        from cryptography.hazmat.primitives import serialization

        public = self.key.public_key()
        if self.alg == "EdDSA":
            raw = public.public_bytes(serialization.Encoding.Raw,
                                      serialization.PublicFormat.Raw)
            return {"kty": "OKP", "crv": "Ed25519", "x": _b64(raw),
                    "kid": self.kid, "alg": "EdDSA", "use": "sig"}
        numbers = public.public_numbers()
        if self.alg == "ES256":
            return {"kty": "EC", "crv": "P-256",
                    "x": _b64(numbers.x.to_bytes(32, "big")),
                    "y": _b64(numbers.y.to_bytes(32, "big")),
                    "kid": self.kid, "alg": "ES256", "use": "sig"}
        return {"kty": "RSA", "n": _int(numbers.n), "e": _int(numbers.e),
                "kid": self.kid, "alg": "RS256", "use": "sig"}

    def jwks(self, *others: "TestIssuer") -> dict:
        return {"keys": [self.jwk(), *(o.jwk() for o in others)]}

    def write_jwks(self, path: str, *others: "TestIssuer") -> str:
        with open(path, "w") as handle:
            json.dump(self.jwks(*others), handle)
        return path

    def sign(self, header: dict, payload: dict) -> str:
        """Any header and payload, signed with this key -- for tests that
        need a token that is wrong in exactly one way."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, padding
        from cryptography.hazmat.primitives.asymmetric.utils import (
            decode_dss_signature)

        signing = (_b64(json.dumps(header).encode()) + "."
                   + _b64(json.dumps(payload).encode()))
        data = signing.encode()
        if self.alg == "EdDSA":
            sig = self.key.sign(data)
        elif self.alg == "ES256":
            r, s = decode_dss_signature(
                self.key.sign(data, ec.ECDSA(hashes.SHA256())))
            sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        else:
            sig = self.key.sign(data, padding.PKCS1v15(), hashes.SHA256())
        return f"{signing}.{_b64(sig)}"

    def mint(self, sub: str, *, actor: str | None = None,
             scope: str | list[str] | None = None, ttl: float = 300,
             now: float | None = None, header: dict | None = None,
             actor_claims: dict | None = None, **claims: Any) -> str:
        """A token for ``sub``, acting through ``actor`` when given.

        ``actor_claims`` go inside ``act`` beside its ``sub``; everything
        else in ``claims`` is a top-level claim and overrides a default.
        """
        at = time.time() if now is None else now
        payload: dict[str, Any] = {
            "iss": self.url, "aud": self.audience, "sub": sub,
            "iat": int(at), "exp": int(at + ttl),
            "jti": uuid.uuid4().hex}
        if actor is not None:
            payload["act"] = {"sub": actor, **(actor_claims or {})}
        if scope is not None:
            payload["scope"] = scope if isinstance(scope, str) else " ".join(scope)
        payload.update(claims)
        head = {"alg": self.alg, "typ": "JWT", "kid": self.kid,
                **(header or {})}
        return self.sign(head, payload)
