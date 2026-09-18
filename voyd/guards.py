"""Composable guards.

Guards are *policy data*, not code that lives only in the process that created
a void. ``Guard.require_passcode()`` is
compiled into a small dict that is stored on the voyd (as a default template)
and on each void. Any replica that can load the void can enforce the same
rules, so horizontal scale needs no shared memory.
"""

from __future__ import annotations

import logging
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from .config import GuardSpec

log = logging.getLogger("voyd.guards")

_hasher = PasswordHasher()


class Guard:
    """Factory for guard specs. See module docstring."""

    @staticmethod
    def require_passcode() -> GuardSpec:
        """Require a passcode at void creation, and on every read of the scope."""
        return GuardSpec(kind="require_passcode", params={})


def hash_passcode(passcode: str) -> str:
    return _hasher.hash(passcode)


def verify_passcode(passcode_hash: str, passcode: str | None) -> bool:
    if not passcode:
        return False
    try:
        return _hasher.verify(passcode_hash, passcode)
    except VerifyMismatchError:
        return False
    except (VerificationError, InvalidHashError):
        # A stored passcode hash we cannot parse denies access -- but a broken
        # guard is not the same event as a wrong passcode, and only one of them
        # is the owner's fault.
        log.warning("stored passcode hash could not be verified; denying access")
        return False


def compile_guard_defaults(specs: list[GuardSpec]) -> dict[str, Any]:
    """Turn a list of guard specs into the default policy dict stored on a voyd.

    ``passcode_hash`` starts as ``None`` (the passcode itself is supplied per
    void when it is created).
    """
    defaults: dict[str, Any] = {}
    for spec in specs:
        if spec.kind == "require_passcode":
            defaults["require_passcode"] = True
            defaults.setdefault("passcode_hash", None)
    return defaults


class GuardError(Exception):
    """Raised when a guard rejects a request. Carries an HTTP status."""

    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def build_void_policy(
    voyd_defaults: dict[str, Any] | None,
    *,
    passcode: str | None,
) -> dict[str, Any]:
    """Compute the concrete policy stored on a *void* at creation time.

    Void-level overrides win over the voyd defaults. If the voyd requires a
    passcode, one must be provided.
    """
    defaults = dict(voyd_defaults or {})
    policy: dict[str, Any] = {
        "passcode_hash": None,
        "require_passcode": bool(defaults.get("require_passcode", False)),
    }

    if policy["require_passcode"] or passcode:
        if not passcode:
            raise GuardError(400, "This voyd requires a passcode to create a void.")
        policy["require_passcode"] = True
        policy["passcode_hash"] = hash_passcode(passcode)

    return policy


def enforce_query(policy: dict[str, Any], *, passcode: str | None) -> None:
    """Run the guard pipeline for a *query*. Raises :class:`GuardError`.

    Querying a scope is the only way to read it, so this is the only place
    the lock has to sit. It used to also guard a byte path, and the rule then
    was that gating one and not the other would make search the way around
    the lock. With the bytes gone there is one door, which is fewer ways to
    leave it open.
    """
    if policy.get("require_passcode") and policy.get("passcode_hash"):
        if not verify_passcode(policy["passcode_hash"], passcode):
            raise GuardError(401, "Invalid or missing passcode.")
