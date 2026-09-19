"""Who else holds a copy, and what can honestly be done about it.

Refusal is enforced at one handle. Everything downstream of it holds copies
that handle cannot reach: a cache, a mirrored index, a second service, a
message a bot posted last week. Revoke a fact and every one of those keeps
serving it.

Inherited refusal (``admission.py``) solved exactly this shape *inside* the
collection -- a summary written back now goes with its source. This module
is the same question one layer out, and the answer is deliberately smaller,
because the obvious design does not work and it is worth writing down why.

**The obvious design.** Register downstream holders; a revocation must be
acknowledged; an unacknowledged sink makes the fact "refused everywhere
until it acks". It is theatre. The fact is *already* refused locally, so
marking it refused again changes nothing, and the unacknowledged sink is
still serving its copy. The mechanism does not close anything -- it records
that something failed. Worse, if an unreachable cache can block a
revocation, erasure now depends on cache uptime, and "we could not honour
the erasure request because Redis was down" is not a sentence anybody
should be able to write.

Which generalises into the rule this module is built on:

    **You cannot enforce refusal in a system you do not control.
    You can propagate, observe, and report. That is all, and pretending
    otherwise costs more than the feature is worth.**

So the copies split three ways, and each gets a different verb:

``sealed``    the sink holds **ciphertext**. Already solved and previously
              under-claimed: shred the scope's key and every copy is noise,
              in every cache and mirror and backup, with no integration, no
              acknowledgement and no network call. This is the case to
              design *for* -- a downstream cache that stores the sealed
              value and calls back to unseal is a performance layer that
              structurally cannot outlive a revocation.

``owned``     the sink holds **plaintext** and you control it. Propagate
              best effort, record what was told and when. Attestation, not
              enforcement: this module reports that the instruction was
              issued and acknowledged, never that the copy is gone.

``derived``   not a copy but a **consequence** -- a Slack message quoting
              the fact, a fine-tune, a vendor's prompt cache with its own
              TTL and no purge API. Nothing here can reach those. What
              ``Admission.receipt_for()`` can do is make *finding* them a
              query instead of an archaeology project, which is the only
              honest offer.

``describe()`` is therefore the most valuable thing in this file. Most
teams cannot answer "who else holds this fact" at all; being able to print
the list, with the class of each, is worth more than a propagation
mechanism that overstates itself.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from .time import now

log = logging.getLogger("engine.perimeter")

SEALED = "sealed"
OWNED = "owned"
DERIVED = "derived"

# How long a single sink gets before it is recorded as unreachable. Short
# on purpose: this runs on the erasure path, and an erasure request must
# not be slower than a caller's patience because a cache is wedged.
SINK_TIMEOUT_S = 5.0


@runtime_checkable
class Sink(Protocol):
    """Something downstream that holds copies.

    Duck typed, like ``Trait`` and ``Rule`` -- inherit nothing. Two
    attributes and one coroutine:

    ``name``    what ``describe()`` prints. An operator reads this during
                an incident, so it should name a system, not a class.
    ``holds``   ``sealed``, ``owned`` or ``derived``. It decides what is
                claimed about this sink, and getting it wrong is the only
                way to make this module lie.
    ``forget(ids, *, reason)``  best effort. Return truthy on success.
    """

    name: str
    holds: str

    async def forget(self, ids: list, *, reason: str) -> Any: ...


@dataclass
class Acknowledgement:
    """What one sink said, or failed to say, about one revocation."""

    sink: str
    holds: str
    acked: bool
    at: datetime
    detail: str = ""

    def as_dict(self) -> dict:
        return {"sink": self.sink, "holds": self.holds, "acked": self.acked,
                "at": self.at.isoformat(), "detail": self.detail}


@dataclass
class Perimeter:
    """The registered holders of copies, and what each one is owed.

    Not a trait: it builds no schema and owns no collection. It is a list
    with a policy, and the policy is that **nothing here may fail an
    erasure**.
    """

    sinks: list = field(default_factory=list)

    def register(self, sink) -> Perimeter:
        for attr in ("name", "holds"):
            if not isinstance(getattr(sink, attr, None), str):
                raise ValueError(
                    f"a sink needs a string .{attr}; without it the "
                    f"perimeter cannot say who holds what, which is the "
                    f"only thing it is actually for")
        if sink.holds not in (SEALED, OWNED, DERIVED):
            raise ValueError(
                f"{sink.name}: holds must be one of {SEALED!r}, {OWNED!r}, "
                f"{DERIVED!r}. Each one is a different claim, and picking "
                f"the wrong one is how this module starts lying")
        self.sinks.append(sink)
        log.info("perimeter: registered %s (%s)", sink.name, sink.holds)
        return self

    async def forget(self, ids: list, *, reason: str
                     ) -> list[Acknowledgement]:
        """Tell every sink, concurrently, and never raise.

        Three properties, and each is load-bearing:

        **It cannot fail the erasure.** Every exception and every timeout
        becomes an unacknowledged ``Acknowledgement``, because the row is
        already refused and the caller already has their answer. An
        erasure path that can be taken down by a cache is worse than no
        propagation at all.

        **Sealed sinks are not called.** Their copy is ciphertext, and the
        key is what erases it. Calling them would be a round trip that
        achieves nothing and an acknowledgement that means less than the
        one shredding already gives.

        **Derived sinks are not called either**, and are reported as
        unreachable by construction. You cannot un-send a message. Listing
        them is the point: an incident review needs to know they exist.
        """
        out: list[Acknowledgement] = []
        pending = []
        for sink in self.sinks:
            if sink.holds == SEALED:
                out.append(Acknowledgement(
                    sink.name, SEALED, True, now(),
                    "holds ciphertext; destroying the key erases it with no "
                    "call to make"))
            elif sink.holds == DERIVED:
                out.append(Acknowledgement(
                    sink.name, DERIVED, False, now(),
                    "a consequence, not a copy -- it cannot be recalled, "
                    "only found"))
            else:
                pending.append(sink)

        if pending:
            results = await asyncio.gather(
                *(self._tell(s, ids, reason) for s in pending),
                return_exceptions=True)
            out.extend(
                r if isinstance(r, Acknowledgement)
                else Acknowledgement(s.name, OWNED, False, now(), repr(r))
                for s, r in zip(pending, results))

        missed = [a.sink for a in out if not a.acked and a.holds == OWNED]
        if missed:
            # WARNING rather than an exception, and worth the volume: the
            # fact is unreachable here and reachable there, which is a
            # real, open breach -- it is simply not one this process can
            # close by refusing harder.
            log.warning(
                "perimeter: %d sink(s) did not acknowledge a revocation and "
                "may still be serving it: %s", len(missed), ", ".join(missed))
        return out

    async def _tell(self, sink, ids: list, reason: str) -> Acknowledgement:
        try:
            async with asyncio.timeout(SINK_TIMEOUT_S):
                ok = await sink.forget(list(ids), reason=reason)
            return Acknowledgement(sink.name, OWNED, bool(ok), now(),
                                   "" if ok else "returned falsey")
        except TimeoutError:
            return Acknowledgement(sink.name, OWNED, False, now(),
                                   f"no answer in {SINK_TIMEOUT_S}s")
        except Exception as exc:  # noqa: BLE001 - see forget(): never raise
            return Acknowledgement(sink.name, OWNED, False, now(), repr(exc))

    def describe(self) -> dict:
        """Who holds copies, and what is honestly claimed about each.

        The most useful thing in this module. "Which systems hold a copy of
        this fact" is a question most teams cannot answer at all, and an
        enumerated answer -- with the verb that applies to each -- is worth
        more than a propagation mechanism that overstates itself.
        """
        by_class: dict[str, list[str]] = {}
        for sink in self.sinks:
            by_class.setdefault(sink.holds, []).append(sink.name)
        return {
            "sinks": {k: sorted(v) for k, v in by_class.items()},
            "claims": {
                SEALED: "erased by destroying the key; no call required",
                OWNED: "told, best effort; acknowledgement recorded, not "
                       "enforced",
                DERIVED: "cannot be recalled; findable via a context "
                         "receipt",
            },
        }
