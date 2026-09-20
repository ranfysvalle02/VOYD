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

**On shipped adapters: no, and it is a decision rather than a gap.** A
Redis adapter here is a Redis adapter somebody has to keep current, for a
call that is one ``DEL`` in the caller's own code -- and it would arrive
with an opinion about key naming that is wrong for most deployments. The
real risk of staying an interface is a perimeter nobody registers anything
into, so the answer is to make registering nearly free rather than to ship
vendors: ``sink(name, holds, forget=...)`` takes two lambdas, so the cost
of being honest about a cache is three lines rather than a class.

``describe()`` is therefore the most valuable thing in this file. Most
teams cannot answer "who else holds this fact" at all; being able to print
the list, with the class of each, is worth more than a propagation
mechanism that overstates itself.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Protocol, runtime_checkable

from .time import aware, now

log = logging.getLogger("engine.perimeter")

SEALED = "sealed"
OWNED = "owned"
DERIVED = "derived"
# The fourth, and the one this module did not have a name for until a
# server-side index needed one. A copy held **inside the deployment you
# control, outside the document you can write**: the vector a search node
# derived from a field and keeps in its own storage.
#
# It is not ``owned`` -- there is no endpoint to call and no acknowledgement
# to collect. It is not ``derived`` -- "cannot be recalled" is false, and
# saying so would give up a purge that is actually available. It is not
# ``sealed``, because the whole point of a server-side embedding is that the
# server read the plaintext.
#
# What makes it its own class is the verb: **it is purged by overwriting the
# field it was derived from.** That is a real erasure and it has a real cost
# -- the source text goes earlier than its deadline, so an
# ``including_refused()`` audit can no longer show what was erased. Which is
# exactly why registering one is a decision somebody types out rather than a
# default: the trade is auditability for immediacy, and it is not this
# package's to make.
INTERNAL = "internal"

# How long a single sink gets before it is recorded as unreachable. Short
# on purpose: this runs on the erasure path, and an erasure request must
# not be slower than a caller's patience because a cache is wedged.
SINK_TIMEOUT_S = 5.0

# How long an unanswered acknowledgement stays worth retrying. A day,
# because most cache evictions and most outages are shorter than that, and
# past it a "success" would be the cache having forgotten on its own --
# which is not the same fact and must not be recorded as if it were.
DEFAULT_HORIZON = timedelta(days=1)

# After this, a sealed sink's last audit is reported as stale. A week,
# because the claim it checks -- "this cache holds ciphertext" -- changes
# when somebody deploys, and most things deploy more often than that.
STALE_AFTER = timedelta(days=7)

# The chain event for an audit. Recorded like any other instruction,
# because "we checked, on this date, and here is what each sink said" is a
# fact about the world in exactly the way a revocation is.
AUDITED = "audited"


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

    And one optional coroutine, which is the difference between a claim
    and a check:

    ``verify(id)``  given an id whose key has been destroyed, return
                    truthy if this sink can **still** produce the
                    plaintext. A sealed sink that answers truthy is
                    misdeclared, and that misdeclaration is the only way
                    this module can lie -- it would report an erasure that
                    did not happen. See ``Perimeter.audit()``.
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


def sink(name: str, holds: str, *, forget=None, verify=None):
    """Build a sink from callables. Registering should cost three lines.

    The alternative to shipping vendor adapters: a deployment that keeps
    plaintext in Redis should be able to say so without writing a class,
    because the thing that makes a perimeter worthless is an empty one.

    ``forget`` may be omitted for ``sealed`` (nothing to call) and for
    ``derived`` (nothing that would work).
    """

    async def _noop(ids, *, reason):
        return True

    made = type(f"Sink_{name.replace('-', '_').replace('.', '_')}", (), {
        "name": name, "holds": holds,
        "forget": staticmethod(forget or _noop),
    })()
    if verify is not None:
        made.verify = verify
    return made


def derived_index(db, collection: str, *, field: str,
                  name: str | None = None):
    """A sink for a copy the database itself derived from a field.

    The case this exists for is server-side embedding. With
    ``auto_embed``, nothing in this process ever holds a vector -- the
    search node reads the text, embeds it, and keeps the result in storage
    no query here can write to. ``AdmissionSpec.derived_fields`` cannot
    reach it: that mechanism nulls a field *in the document*, and on an
    auto-embedding collection there is no such field.

    So the lossy copy of an erased fact outlives the erasure, quietly. The
    refusal guarantee is untouched -- the boundary still refuses the
    document -- but the promise this package makes about *derived
    encodings*, that they go immediately rather than on the reaper's
    schedule, silently stops applying. An embedding is partially
    invertible; that promise is not decorative.

    This is the purge that is actually available: **overwrite the source
    field, and the index entry goes with it.** Registering the sink is how
    a deployment says it wants that, because it is not free --

        the source text is destroyed at revocation rather than at its
        deadline, so ``including_refused()`` can no longer show an auditor
        what was erased. Immediacy is bought with auditability.

    -- and a library that made that trade by default would be deciding
    something only the deployment can. Reversible holds never reach here:
    ``Perimeter.forget`` is called on irreversible revocation only, so a
    quarantine that is later lifted does not destroy anything.

        notes.bounded_by(
            Perimeter().register(
                derived_index(db, "notes", field="text")))
    """
    label = name or f"{collection}.{field}-index"

    async def _forget(ids: list, *, reason: str) -> bool:
        if not ids:
            return True
        # ``None`` rather than ``$unset``, matching ``derived_fields``: the
        # document keeps its shape, so a reader sees an erased field rather
        # than a missing one, and nothing downstream has to special-case an
        # absent key it has always been able to read.
        await db[collection].update_many(
            {"_id": {"$in": list(ids)}}, {"$set": {field: None}})
        log.info("derived index %s: cleared %s on %d document(s) (%s)",
                 label, field, len(ids), reason)
        return True

    return sink(label, INTERNAL, forget=_forget)


@dataclass
class Perimeter:
    """The registered holders of copies, and what each one is owed.

    Not a trait: it builds no schema and owns no collection. It is a list
    with a policy, and the policy is that **nothing here may fail an
    erasure**.
    """

    sinks: list = field(default_factory=list)
    # sink name -> the last ``audit()`` result. What turns a pre-flight
    # check into something with a staleness measure; see ``audit``.
    verified: dict = field(default_factory=dict)

    def register(self, sink) -> Perimeter:
        for attr in ("name", "holds"):
            if not isinstance(getattr(sink, attr, None), str):
                raise ValueError(
                    f"a sink needs a string .{attr}; without it the "
                    f"perimeter cannot say who holds what, which is the "
                    f"only thing it is actually for")
        if sink.holds not in (SEALED, OWNED, DERIVED, INTERNAL):
            raise ValueError(
                f"{sink.name}: holds must be one of {SEALED!r}, {OWNED!r}, "
                f"{DERIVED!r}, {INTERNAL!r}. Each one is a different claim, "
                f"and picking the wrong one is how this module starts lying")
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

    async def redrive(self, store, *, older_than: timedelta | None = None
                      ) -> list[Acknowledgement]:
        """Retry the sinks that did not answer, within a deadline.

        A sink that was down during a revocation stays unacknowledged
        forever otherwise, which is an open breach sitting in an audit
        trail with nobody assigned to it.

        **Bounded, and the bound is the design.** A retry that runs a week
        later against a cache that has since evicted the key achieves
        nothing and writes a success into the record, and a false success
        is worse than a gap that is honestly marked. So an outstanding
        acknowledgement has a horizon: past it, it is not retried and is
        closed as ``expired`` -- a permanent, visible "this was never
        confirmed" rather than an optimistic one.

        ``store`` is anything with ``outstanding()`` and ``settle()``;
        ``PerimeterLog`` below is the one this package ships. Passed in
        rather than reached for, because whether these records are worth
        keeping -- and for how long -- is a retention decision, and
        retention decisions should be typed out.

        **Nothing in this package calls this on a schedule, on purpose.**
        A worker that retries erasures is a worker holding credentials for
        every registered sink, and where that runs is a deployment
        decision this library should not make quietly. What it should do
        is make the loop trivial enough that "nobody calls it" is never
        because it was awkward::

            log = PerimeterLog(engine.db)
            await log.ensure()

            while True:                       # your worker, your creds
                await perimeter.redrive(log)
                await asyncio.sleep(60)

        The one-shot form is also the right thing to put in a cron, and
        ``settled()`` below is the number to alert on: outstanding
        acknowledgements that have stopped being retried are open breaches
        with nobody assigned to them.
        """
        # ``is None``, not ``or``: ``timedelta(0)`` is falsy, so the
        # obvious spelling silently turns "expire everything now" -- the
        # thing an operator reaches for to drain a queue -- into the
        # default one-day horizon, and the retries they were trying to
        # stop all run.
        horizon = DEFAULT_HORIZON if older_than is None else older_than
        settled: list[Acknowledgement] = []
        by_name = {s.name: s for s in self.sinks}
        for row in await store.outstanding():
            sink = by_name.get(row["sink"])
            age = now() - aware(row["at"])
            if sink is None or age > horizon:
                why = ("sink is no longer registered" if sink is None else
                       f"never confirmed within {horizon}; a later retry "
                       f"would be against a cache that has moved on")
                ack = Acknowledgement(row["sink"], row.get("holds", OWNED),
                                      False, now(), f"expired: {why}")
                await store.settle(row, ack, final=True)
            else:
                ack = await self._tell(sink, row["ids"], row["reason"])
                await store.settle(row, ack, final=ack.acked)
            settled.append(ack)
        if settled:
            log.info("perimeter: re-drove %d outstanding acknowledgement(s); "
                     "%d confirmed", len(settled),
                     sum(1 for a in settled if a.acked))
        return settled

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

    async def audit(self, *, shredded_id, ledger=None, tenant=None
                    ) -> list[Acknowledgement]:
        """Turn ``holds=SEALED`` from a claim into a check.

        A sink declaring ``sealed`` is *trusted* about it, and if it
        actually caches plaintext the perimeter reports an erasure that did
        not happen. That is the one way this module can lie, and it lies in
        the direction that matters: quietly, in a compliance answer.

        So hand each sealed sink an id whose key has been destroyed and ask
        whether it can still produce the plaintext. A sink that can is
        misdeclared and says so here rather than in an incident.

        A sink with no ``verify`` is reported **unverified rather than
        passing**, which is the whole point -- a claim nobody checked and a
        claim that was checked must not look the same, and that is the same
        argument this package makes about a skipped test.

        **This is a pre-flight check, and on its own that is not enough.**
        A sink that starts caching plaintext the day after an audit is
        indistinguishable from one that never did, so the *result* is kept
        with its timestamp and ``describe()`` reports how stale it is.
        Staleness is the whole difference between a check somebody ran once
        and a check a deployment relies on: "verified 400 days ago" and
        "verified" must not read the same, which is the same complaint this
        module makes about an unchecked claim in the first place.

        Passing a ``ledger`` puts the result on the chain, so an audit that
        was run becomes a fact somebody can point at rather than a log line
        that has rotated away.
        """
        out = []
        for sink in self.sinks:
            if sink.holds != SEALED:
                continue
            check = getattr(sink, "verify", None)
            if check is None:
                out.append(Acknowledgement(
                    sink.name, SEALED, False, now(),
                    "declares it holds ciphertext and offers no verify(); "
                    "the claim is unchecked, not confirmed"))
                continue
            try:
                async with asyncio.timeout(SINK_TIMEOUT_S):
                    leaked = await check(shredded_id)
            except Exception as exc:  # noqa: BLE001 - an audit that raises
                # is an audit that did not happen, and must not read as one
                # that passed.
                out.append(Acknowledgement(sink.name, SEALED, False, now(),
                                           f"verify() raised: {exc!r}"))
                continue
            out.append(Acknowledgement(
                sink.name, SEALED, not leaked, now(),
                "" if not leaked else
                "MISDECLARED: produced plaintext for a shredded key, so "
                "every erasure this perimeter reported for it was false"))
        for ack in out:
            self.verified[ack.sink] = ack
        for bad in (a for a in out if not a.acked and "MISDECLARED" in a.detail):
            log.error("perimeter: %s", bad.detail)
        if ledger is not None and out:
            try:
                await ledger.append(
                    AUDITED, tenant=tenant, reason="perimeter audit",
                    count=sum(1 for a in out if a.acked),
                    detail={"sinks": [a.as_dict() for a in out]})
            except Exception:  # noqa: BLE001 - the audit happened; failing
                # to record it must not undo that, exactly as a revocation
                # is not undone by an unwritable chain.
                log.exception("perimeter: audited %d sealed sink(s) and could "
                              "not record it", len(out))
        return out

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
        sealed_state = {}
        for sink in self.sinks:
            if sink.holds != SEALED:
                continue
            ack = self.verified.get(sink.name)
            if ack is None:
                sealed_state[sink.name] = "never verified"
                continue
            age = now() - aware(ack.at)
            state = "verified" if ack.acked else "FAILED"
            if age > STALE_AFTER:
                state = f"{state}, {age.days}d ago (stale)"
            sealed_state[sink.name] = state
        return {
            "sinks": {k: sorted(v) for k, v in by_class.items()},
            # Reported even when empty: a deployment with sealed sinks and
            # no audits has a claim nobody has ever checked, and the
            # absence of a result is the finding.
            "sealed_claims": sealed_state,
            "claims": {
                SEALED: "erased by destroying the key; no call required",
                OWNED: "told, best effort; acknowledgement recorded, not "
                       "enforced",
                DERIVED: "cannot be recalled; findable via a context "
                         "receipt",
                INTERNAL: "purged by overwriting the field it was derived "
                          "from; costs the source text its remaining "
                          "deadline",
            },
        }


class PerimeterLog:
    """Outstanding acknowledgements, as documents. A trait.

    The document *is* the job, like everything else here -- so
    ``engine.queue(when={"acked": False})`` drives this without a broker,
    and ``redrive()`` is what a worker calls.

    Two deliberate absences. It stores ids and a reason, never document
    text: a record of an erasure that quotes the thing being erased is a
    fresh copy of it, exempt from every deadline in the system -- the same
    rule ``ledger.py`` follows. And it carries a TTL, unlike the ledger,
    because this is operational state rather than evidence: the *chain*
    records that a sink failed to answer, permanently. This is only the
    queue for doing something about it.
    """

    kind = "perimeter_log"

    def __init__(self, db, collection: str = "perimeter", *,
                 retain: timedelta = timedelta(days=30)):
        self.db = db
        self.collection = collection
        self.retain = retain

    async def ensure(self) -> bool:
        await self.db[self.collection].create_index(
            [("open", 1), ("at", 1)], name="outstanding")
        await self.db[self.collection].create_index(
            "expire_at", expireAfterSeconds=0, sparse=True)
        return True

    async def record(self, acks, *, ids: list, reason: str) -> int:
        """Persist the ones that did not answer. An acked sink needs no row."""
        pending = [a for a in acks if not a.acked and a.holds == OWNED]
        if not pending:
            return 0
        await self.db[self.collection].insert_many([{
            "sink": a.sink, "holds": a.holds,
            # Two fields, not one, because they are two questions and
            # conflating them is how "we stopped retrying" comes to read
            # as "it was confirmed":
            #   open       is there still work to do?
            #   confirmed  did the sink ever actually say yes?
            "open": True, "confirmed": False,
            "at": a.at, "attempts": 0, "detail": a.detail,
            "ids": list(ids), "reason": reason,
            "expire_at": a.at + self.retain,
        } for a in pending])
        return len(pending)

    async def outstanding(self) -> list[dict]:
        cursor = self.db[self.collection].find({"open": True}).sort("at", 1)
        return [d async for d in cursor]

    async def settled(self) -> dict:
        """The two numbers worth alerting on.

        ``open`` is work: sinks that have not answered and are still being
        retried. ``unconfirmed`` is the one that matters -- propagations
        that were given up on, which are open breaches with nobody
        assigned to them. A dashboard that shows only the first will read
        as healthy precisely when the queue has drained by expiry rather
        than by success.
        """
        coll = self.db[self.collection]
        return {
            "open": await coll.count_documents({"open": True}),
            "unconfirmed": await coll.count_documents(
                {"open": False, "confirmed": False}),
        }

    async def settle(self, row: dict, ack, *, final: bool) -> None:
        """Close a row, or leave it open for another attempt.

        A row closed *unconfirmed* stays readable rather than being
        deleted: "we never confirmed this" is a finding, and removing it
        would make the absence of a finding indistinguishable from a
        success.
        """
        await self.db[self.collection].update_one(
            {"_id": row["_id"]},
            {"$set": {"open": not (final or ack.acked),
                      "confirmed": bool(ack.acked),
                      "detail": ack.detail,
                      "settled_at": ack.at},
             "$inc": {"attempts": 1}})
