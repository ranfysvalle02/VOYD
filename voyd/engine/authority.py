"""May this caller *do* this? The question the other two do not ask.

There are three questions here and only two of them had an answer.

    Guard       may this caller read the scope?          a passcode
    Admission   may this document reach a prompt?        rules, per document
    Authority   may this caller perform this operation?  -- nothing

The gap was invisible for a long time because the first two are so
carefully separated, and both are about *reading*. Every verb that changes
what a scope contains -- revoke, quarantine, release, shred -- was
available to anybody holding a handle, which in practice means anybody
holding the scope's passcode. So "re-admit a document an injection
detector flagged" sat behind the same credential as "search this scope",
and the only honest response was to keep those verbs off the HTTP surface
entirely. Three features blocked on one absence, which is a message about
what to build rather than three separate gaps.

**The asymmetry is the whole design.** These operations are not equally
dangerous and must not be equally available:

    withholding   revoke, quarantine, shred. They make facts *less*
                  reachable. Wrong ones are recoverable in the sense that
                  matters -- nobody was served anything they should not
                  have been.
    granting      release, and lifting any hold. It makes a fact reachable
                  again, so a mistake here is the breach the detector
                  fired about. This is the operation that needs a human,
                  a reason, and a name attached.

``Grants(may=...)`` is the claims-based implementation, and
``Grants.withholding_only()`` is the shape most services want: your
pipeline may quarantine anything it likes and may not release a single
document.

**Not attached means unchanged.** This is a library, and by default the
caller *is* the application -- it already holds the database. Demanding an
authority from a script would be theatre. But once one is attached, an
*unbound* caller raises rather than passing: the same reasoning as
``CallerRequired``, where returning everything is the breach and returning
nothing is a silent no-op on a write.

**And the record learns who.** The chain could say what was revoked, when,
and why, and could not say by whom -- so "somebody released the document
the detector flagged" was the strongest sentence available to an auditor.
``actor()`` is what an authority contributes to the ledger, and it is a
separate method from ``permits()`` on purpose: identity is worth recording
even where every caller is permitted everything.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

log = logging.getLogger("engine.authority")

# The verbs an authority is asked about. Strings, for the same reason
# refusal reasons are strings: they are logged, counted, recorded on the
# chain and read by an operator who is not holding this source.
REVOKE = "revoke"
QUARANTINE = "quarantine"
RELEASE = "release"
SHRED = "shred"
DERIVE = "derive"
# Prying the guarantee open to read what was forgotten. ``including_refused()``
# is the handle that does it, and it is a verb like the others because "who
# may see the erased rows" is exactly the question the other verbs made
# askable -- and leaving it ungated was the one hole appendix.md named.
AUDIT = "audit"

# The granting direction: operations that put a forgotten fact back in front
# of somebody. A mistake here is the breach the detector fired about, which is
# why they are named as a set rather than left for each deployment to
# rediscover. ``release`` re-admits the fact to every reader; ``audit``
# (``including_refused()``) discloses it to this one. Both are the direction a
# mistake cannot be walked back, and neither is granted by
# ``Grants.withholding_only()``.
GRANTS_REACHABILITY = frozenset({RELEASE, AUDIT})

WITHHOLDS = frozenset({REVOKE, QUARANTINE, SHRED})


class NotAuthorised(PermissionError):
    """This caller may not perform this operation.

    ``PermissionError`` rather than a local base class, because an HTTP
    layer should be able to map it to 403 without importing this module's
    taxonomy -- and because a caller who catches ``Exception`` around a
    revocation and continues has already lost.

    The message names the operation and whether it grants reachability,
    since those are the two facts a reader needs and the second is the one
    that explains why the policy is asymmetric.
    """

    def __init__(self, operation: str, collection: str,
                 held: Any = None):
        self.operation = operation
        self.collection = collection
        self.held = held
        if operation == AUDIT:
            danger = (" This operation discloses facts that were forgotten, "
                      "which is the granting direction: a disclosure cannot "
                      "be walked back.")
        elif operation in GRANTS_REACHABILITY:
            danger = (" This operation makes facts reachable again, which is "
                      "the direction a mistake cannot be walked back.")
        else:
            danger = ""
        super().__init__(
            f"not authorised to {operation} in {collection}"
            f"{f' (holds: {sorted(held)})' if held else ''}.{danger}")


class AuthorityRequired(PermissionError):
    """An authority is installed and nobody said who is asking.

    Neither available answer is acceptable, which is why this raises
    rather than picking one -- the same shape as ``CallerRequired``.
    Permitting the operation makes the authority decorative. Refusing it
    silently makes a revocation report success having done nothing, which
    is the worst failure this package has.
    """

    def __init__(self, operation: str, collection: str):
        super().__init__(
            f"{collection} has an authority installed, so {operation}() "
            f"needs to know who is asking: call .for_caller(claims) first. "
            f"Use for_caller({{}}) for an authenticated caller holding no "
            f"grants -- which will then be refused, as it should be")


@runtime_checkable
class Authority(Protocol):
    """Anything that can answer *may this caller do this*.

    Duck typed, like every other extension point here -- inherit nothing.
    A deployment that wants dual control, time-of-day limits, or a call
    out to its own policy service implements this and loses no other
    guarantee: the verbs ask, the chain records, and neither cares how the
    answer was reached.

    ``permits(operation, caller, *, collection) -> bool``
    ``actor(caller) -> str | None``   who to write on the chain
    """

    def permits(self, operation: str, caller: dict | None, *,
                collection: str) -> bool: ...

    def actor(self, caller: dict | None) -> str | None: ...


@dataclass(frozen=True)
class Grants:
    """Capabilities as a claim. The ordinary implementation.

        docs.authorised_by(Grants())

        pipeline = docs.for_caller({"sub": "indexer",
                                    "may": ["quarantine"]})
        await pipeline.quarantine(...)          # fine
        await pipeline.release(...)             # NotAuthorised

    ``may`` is a set of operation names on the caller's claims, put there
    by whatever authenticated them. This does not verify it and cannot: an
    authority that believed ``{"may": ["shred"]}`` because it was handed
    one would be an authorisation system whose only input is the
    attacker's -- the same sentence ``for_caller`` carries, for the same
    reason.

    **An unknown operation is denied.** A new verb added to this package
    is not retroactively granted to every caller holding an old token,
    which is the direction that fails safely.
    """

    claim: str = "may"
    actor_claim: str = "sub"
    # Granted to every bound caller regardless of claims. Empty by
    # default: a grant nobody typed is a grant nobody reviewed.
    always: frozenset = frozenset()

    @classmethod
    def withholding_only(cls, **kw) -> Grants:
        """Any bound caller may withhold; nobody may grant reachability.

        The shape most services want, and worth having a name so it is
        chosen rather than assembled: an indexing pipeline should be able
        to quarantine anything it finds suspicious at three in the
        morning, and should not be able to put a flagged document back in
        front of a model.
        """
        return cls(always=frozenset(WITHHOLDS), **kw)

    def permits(self, operation: str, caller: dict | None, *,
                collection: str) -> bool:
        if operation in self.always:
            return True
        held = (caller or {}).get(self.claim)
        return operation in _as_set(held)

    def actor(self, caller: dict | None) -> str | None:
        who = (caller or {}).get(self.actor_claim)
        return str(who) if who is not None else None

    def held_by(self, caller: dict | None) -> set:
        return set(self.always) | _as_set((caller or {}).get(self.claim))


@dataclass(frozen=True)
class Anyone:
    """Permits everything and still records who. Not a no-op.

    For deployments where every caller is trusted with every verb but the
    audit trail must still name them -- which is most internal tools, and
    is a real answer rather than an absence. Installing this is a
    decision; installing nothing is a default.
    """

    actor_claim: str = "sub"
    audit: bool = True

    def permits(self, operation: str, caller: dict | None, *,
                collection: str) -> bool:
        return True

    def actor(self, caller: dict | None) -> str | None:
        who = (caller or {}).get(self.actor_claim)
        return str(who) if who is not None else None


@dataclass
class Recorded:
    """Wraps an authority and keeps what it decided. For tests and review.

    Every refusal is logged at WARNING by the handle, but a deployment
    that wants to *count* attempted-and-denied operations -- which is the
    signal that somebody is probing, exactly as a climbing ``not_cleared``
    is -- needs somewhere to put them.
    """

    inner: Any
    denied: list = field(default_factory=list)
    allowed: int = 0

    def permits(self, operation: str, caller: dict | None, *,
                collection: str) -> bool:
        ok = self.inner.permits(operation, caller, collection=collection)
        if ok:
            self.allowed += 1
        else:
            self.denied.append({"operation": operation,
                                "collection": collection,
                                "actor": self.actor(caller)})
        return ok

    def actor(self, caller: dict | None) -> str | None:
        return self.inner.actor(caller)


def _as_set(value: Any) -> set:
    if value is None:
        return set()
    if isinstance(value, (str, bytes)):
        return {value}
    try:
        return set(value)
    except TypeError:
        return set()
