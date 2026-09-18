"""Owner authentication: passwords and sessions.

The console never asks a human to paste an API key. Owners sign in with an
email and password, and the session lives in MongoDB with a TTL index -- the
same reaper that expires voids expires logins. Only a hash of the session
token is stored, so a database leak cannot be replayed as a login.

API keys still exist for programmatic use (see /keys in the console), they're
just no longer part of the human flow.
"""

from __future__ import annotations

import hashlib
import logging
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

log = logging.getLogger("voyd.auth")

SESSION_COOKIE = "voyd_session"
SESSION_TTL_DAYS = 30

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str | None) -> bool:
    if not password_hash or not password:
        return False
    try:
        return _hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False
    except (VerificationError, InvalidHashError):
        # The stored hash is unusable (truncated, written by another scheme, or
        # not a hash at all). Sign-in must still fail closed, but a corrupt
        # owner record is not a wrong password and must not look like one.
        log.warning("stored password hash could not be verified; treating as a "
                    "failed login")
        return False


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def hash_session_token(token: str) -> str:
    """Session tokens are high-entropy, so a fast deterministic hash is both
    safe and lookup-friendly."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_api_key() -> str:
    return "voyd_" + secrets.token_urlsafe(32)
