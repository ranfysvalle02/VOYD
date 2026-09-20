"""Imposing a reason, and taking one back where the reason allows it.

One engine, two verbs. ``impose`` applies a mark, ``lift`` removes one, and
every named front door -- ``revoke``, ``witness``, ``quarantine``,
``release`` -- is one of those two with a reason already filled in. Whether a
write erases the bytes, whether it stamps a deadline, and whether it has an
inverse at all are read off the *rule*, never passed in by the caller.

That is the asymmetry this module exists to encode: a revocation is an
instruction about the world and must not be undoable; a quarantine is a
hypothesis and must be.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any

from ..authority import QUARANTINE, RELEASE, REVOKE
from ..errors import (BlastRadius, Irreversible, UnboundedForgetting,
                      UnknownReason)
from ..time import now
from .reasons import LIFTED, LIFT_BATCH, QUARANTINED, REVOKED

log = logging.getLogger("engine.admission")


class MarkWrites:
    """Imposing a reason, and lifting one where the reason has an inverse.

    ``impose`` and ``lift`` are the engine; ``revoke``, ``witness``,
    ``quarantine`` and ``release`` are named front doors onto them. No
    front door has a privilege the general form lacks.
    """

    # ---- forgetting, and the one reason that can be taken back ---------
    #
    # Two verbs, not one, and the asymmetry between them is deliberate:
    #
    #   impose(reason, ...)   applies a mark. Available for every reason
    #                         whose rule declares `reversible` at all.
    #   lift(reason, ...)     removes one. Available only where that
    #                         declaration said True, and raises otherwise.
    #
    # `revoke`, `quarantine` and `release` are named front doors onto those
    # two, because the builtin reasons deserve a verb that reads like the
    # thing it does. A third-party `Marked` reason gets the general form and
    # exactly the same guarantees -- there is no privileged path.

    def _imposable(self) -> tuple:
        """The reasons on this handle that a verb can apply.

        Two things make a rule imposable, and it needs both: a ``field``,
        which is the mark, and a declared ``reversible``, which is the rule
        saying an operator sets that mark rather than the world doing it.
        A ``Deadline`` has neither -- a document is expired because time
        passed, and "imposing" that is just writing a date. ``Clearance``
        has a field but declares nothing, because the field is a label the
        document came with, not a mark this handle puts on it.
        """
        return tuple(r for r in self.rules
                     if isinstance(getattr(r, "reversible", None), bool)
                     and isinstance(getattr(r, "field", None), str))

    def _rule_for(self, reason: str):
        imposable = self._imposable()
        for rule in imposable:
            if rule.reason == reason:
                return rule
        raise UnknownReason(self.collection, reason,
                            tuple(r.reason for r in imposable))

    @staticmethod
    def _marked(rule, present: bool) -> dict:
        """Whether this rule's mark is on a document, as a query fragment.

        Both verbs need it and they need opposite halves, which is the whole
        reason it is here rather than inlined twice:

        ``impose`` must skip documents *already* carrying the mark. Without
        that it re-stamps them -- and on an irreversible reason it re-stamps
        ``expire_at`` too, so re-running an erasure would push the row's
        deletion further into the future. A retry that extends the life of
        an erased document is the worst available outcome for the one
        operation with no undo.

        ``lift`` must target only documents that *do* carry it. Without
        that, ``expect`` counts every document the filter touches rather
        than every document actually held, so the interlock guards a number
        the caller never meant.
        """
        f = rule.field
        if present:
            return {f: {"$ne": None}}
        return {"$or": [{f: None}, {f: {"$exists": False}}]}

    def _write_query(self, rule, filters: dict | None, *,
                     present: bool) -> dict:
        """The query a forgetting write runs against.

        Built from the **audit** handle, which is the correction to a
        silent no-op that predates the reversible/irreversible split and
        survived it. Refusal reasons are not mutually exclusive, and the
        ordinary read query drops every already-refused document -- so:

        - revoking a *quarantined* document matched nothing. An
          investigation concluding "this is malicious, erase it" returned 0
          and left the row carrying only the reversible mark, so the next
          ``release()`` made it reachable again.
        - revoking a document whose deadline passed thirty seconds ago
          matched nothing either. A subject erasure request for a fact that
          is still on disk, and will be for up to a sweep, was answered
          "no such document" -- with no mark, no receipt and no chain entry.

        Both are the failure this package is named after, reached through
        its own write path. The audit handle still carries the tenant and
        every unbypassable rule, so widening the write here does not widen
        who may perform it.
        """
        query = self.including_refused()._query(filters)
        clause = self._marked(rule, present)
        query["$and"] = [*query.pop("$and", []), clause]
        return query

    async def _guard(self, verb: str, filters: dict | None, query: dict, *,
                     expect: int | None, everything: bool) -> None:
        """Everything that must be true before a forgetting write happens.

        Both checks are pre-flight and both refuse rather than proceed,
        because this is the one family of calls in the package whose damage
        is done before the caller reads the return value.

        ``query`` is passed in rather than rebuilt here, and that is not a
        style choice: ``lift()`` has to count through the audit handle,
        since the rows it acts on are refused by the very rule it is
        removing. A guard that built its own query would count zero, refuse
        every ``expect``, and be indistinguishable from a broken filter.
        """
        # "Unbounded" means *narrows nothing beyond the tenant*, which is
        # not the same as an empty dict and the difference is the whole
        # value of the check. On a scoped collection an empty filter never
        # reaches here -- ``require_tenant`` rejects it first -- so a rule
        # written against ``not filters`` would fire only on the unscoped
        # case and miss every deployment that actually has tenants. The
        # dangerous call is ``revoke({"tenant": t})``: legal, scoped,
        # correct-looking, and it erases the tenant.
        narrowing = {k: v for k, v in (filters or {}).items()
                     if k != self.tenant}
        if not narrowing and not everything:
            raise UnboundedForgetting(self.collection, verb)
        if expect is None:
            return
        matched = await self.db[self.collection].count_documents(query)
        if matched != expect:
            log.warning("%s() on %s refused: matched %d, expected %d",
                        verb, self.collection, matched, expect)
            raise BlastRadius(self.collection, expect, matched)

    async def revoke(self, filters: dict | None = None, *,
                     reason: str = "revoked",
                     erase_after: timedelta | None = None,
                     expect: int | None = None,
                     everything: bool = False) -> int:
        """Make matching facts unreachable now. Bytes leave on their own time.

        This is the part no vector database has. ``delete_many`` is a storage
        operation whose effect on retrieval is "eventually"; this is a
        retrieval operation whose effect is "next read". The row is also given
        a deadline so the reaper collects it -- unreachable first, erased
        shortly after, in that order, because the reverse order is the bug.

        **There is no undo, and that is a designed property rather than a
        missing feature** -- ``Irreversible`` in ``errors.py`` carries the
        argument. Which is exactly why the two interlocks below exist: when a
        call cannot be taken back, the only place to be careful is in front
        of it.

        ``expect`` refuses the write unless the filter matches that many
        documents. ``everything=True`` is required to revoke a whole scope.
        Both are opt-in and cost nothing when unused: no extra round trip is
        issued unless ``expect`` is given.

        ``erase_after`` keeps the tombstone readable for a while through
        ``including_refused()``, for cases where you must prove *when* a fact
        stopped being reachable. The default erases as soon as the reaper
        runs.

        It is a **cap, not an extension**: up to that long, or until the
        row's existing deadline, whichever comes first. A revocation only
        ever moves a deadline earlier. Otherwise erasing a fact due in an
        hour would keep it on disk for a week, and retention that *grows*
        because somebody asked for erasure is the opposite of the request.
        When the row goes sooner than you wanted the proof to last, the
        proof was in the wrong place: the ledger has no TTL index, on
        purpose, and that is the tombstone that outlives everything.

        Note also what ``erase_after`` is not: the window in which a
        revocation could be reversed. Reversal is out of contract in it, and
        a reader who assumed otherwise would be building on the sweeper's
        schedule.
        """
        n, _ = await self.impose(REVOKED, filters, reason=reason,
                                 erase_after=erase_after, expect=expect,
                                 everything=everything)
        return n

    async def witness(self, filters: dict | None = None, *, reason: str,
                      erase_after: timedelta | None = None,
                      expect: int | None = None,
                      everything: bool = False) -> dict:
        """``revoke()``, returning the chain entry instead of the count.

        The entry is the receipt, and handing it to whoever asked for the
        erasure is the point: their copy of the hash was taken before any
        dispute existed, so a chain that later does not contain it is
        falsified by a record this database's operator never held. Without
        that, a hash chain is only evidence against people who cannot edit
        it.
        """
        n, receipt = await self.impose(REVOKED, filters, reason=reason,
                                       erase_after=erase_after, expect=expect,
                                       everything=everything)
        out = dict(receipt or {})
        out.setdefault("count", n)
        return out

    async def quarantine(self, filters: dict | None = None, *,
                         reason: str = "quarantined",
                         expect: int | None = None,
                         everything: bool = False) -> int:
        """Hold facts back from prompts without destroying them.

        The other half of ``quarantined()``, which until now was a reason
        with no verb: the rule could refuse a mark, and nothing in the
        package could put one there. A reason that only an external writer
        can set is not a feature, it is a convention -- and the response to
        a convention is the whole argument of this module.

        Unlike ``revoke()`` this stamps **no erase deadline**. The row is the
        evidence; a hold that schedules its own subject for deletion is an
        investigation with a countdown on it. Lift it with ``release()``.
        """
        n, _ = await self.impose(QUARANTINED, filters, reason=reason,
                                 expect=expect, everything=everything)
        return n

    async def release(self, filters: dict | None = None, *,
                      reason: str, expect: int | None = None,
                      everything: bool = False) -> int:
        """Lift a quarantine: these facts may reach prompts again.

        ``reason`` is required and has no default, unlike every other verb
        here. Re-admitting a document that an injection detector flagged is
        a decision somebody made, and a decision with no stated reason is
        indistinguishable on the chain from a mistake -- which is precisely
        what an auditor reading this entry is trying to tell apart.
        """
        n, _ = await self.lift(QUARANTINED, filters, reason=reason,
                               expect=expect, everything=everything)
        return n

    # ---- the general forms ---------------------------------------------

    # ---- the copy that is not stored as text ---------------------------
    #
    # Refusal and crypto-shredding both act on the *field somebody typed*.
    # Neither touches the vector sitting beside it, and the vector is a
    # lossy encoding of exactly that field -- so an erased document that
    # keeps its embedding has not been erased, it has been paraphrased into
    # a format nobody reads by eye.
    #
    # Measured in this repository rather than asserted from the literature:
    # after ``revoke()``, the surviving vector still separates its own topic
    # from another by 0.9988 against 0.7992 cosine. That is a working
    # attribute-inference oracle over a subject who asked to be forgotten,
    # and it needs no inversion model to exploit -- you ask the index
    # whether a document about X is in there, and it says yes.
    # (Text reconstruction from embeddings is a live and increasingly
    # effective research area on top of that; the membership answer above
    # is simply the floor, and the floor is already a breach.)
    #
    # So an irreversible reason destroys the derived encodings with the
    # mark, in the same write, and **not** on the reaper's schedule: the
    # whole argument of this package is that a guarantee which waits for a
    # sweeper is not a guarantee.
    #
    # A *reversible* reason must not. A quarantined document is evidence,
    # and its vector is how an investigator finds the other documents like
    # it -- destroying it is destroying the lead. That distinction is free,
    # because ``reversible`` already decides who stamps the deadline, and
    # this is the same question: is this an erasure, or a hold?

    async def impose(self, on: str, filters: dict | None = None, *,
                     reason: str | None = None,
                     erase_after: timedelta | None = None,
                     expect: int | None = None,
                     everything: bool = False) -> tuple[int, dict | None]:
        """Apply one reason's mark to matching documents.

        Returns ``(count, receipt)`` -- both of the things callers want from
        it, from one call rather than the count coming back and the receipt
        being stashed on the handle for a second method to collect. That is
        not tidiness: handles are deduplicated per collection, so a
        ``_last_receipt`` attribute was shared mutable state on an object
        every request holds, and two concurrent revocations could hand each
        caller the other's hash. Which is the same defect ``for_caller``
        returning a clone exists to prevent, reintroduced two hundred lines
        below the comment explaining it.

        Whether the erase deadline is stamped is read off the rule, not
        passed in: irreversible reasons erase, reversible ones preserve. A
        caller cannot ask for a quarantine that deletes its own evidence,
        and cannot forget to make a revocation collectable.
        """
        rule = self._rule_for(on)
        # Checked deliberately before anything else: on a write, the caller
        # check has to happen before the collection handle is even touched,
        # or the failure mode depends on which line raises first.
        self._require_caller()
        self._authorise(QUARANTINE if rule.reversible else REVOKE)
        verb = "quarantine" if rule.reversible else "revoke"
        query = self._write_query(rule, filters, present=False)
        await self._guard(verb, filters, query, expect=expect,
                          everything=everything)

        stamp = now()
        why = reason or rule.reason
        # ``$literal``, because in the pipeline form below a bare string is
        # an expression -- and ``reason`` is caller-supplied, so a value
        # beginning with ``$`` would be read as a field path and silently
        # write something else entirely.
        mark = {"$literal": {"at": stamp, "reason": why}}
        mark_set: dict = {}
        update: Any = {"$set": {rule.field: mark["$literal"]}}
        if not rule.reversible:
            # An erasure instruction, so the bytes are scheduled to go. A
            # reversible hold deliberately does not touch the deadline: the
            # row has to outlive the investigation it was held for.
            #
            # And the deadline only ever moves *earlier*. A pipeline update
            # rather than a plain ``$set`` because that invariant needs to
            # read the existing value: a row due in an hour, revoked with
            # ``erase_after=7d``, must not have its erasure pushed out to
            # seven days. Retention that grows because somebody asked for
            # erasure is the opposite of the thing being asked for.
            at = self.spec.at_field
            due = stamp + (erase_after or timedelta(0))
            # And the derived encodings go now, not on the reaper's
            # schedule. See ``_destroy_derived`` -- the vector beside an
            # erased document is a copy of it in a coat.
            for name in self.spec.derived_fields:
                mark_set[name] = None
            update = [{"$set": {
                rule.field: mark,
                # A missing or null deadline is a *pinned* row, not an
                # early one -- ``$min`` against null would keep the null
                # and leave an erased fact pinned forever, so the two
                # cases are separated rather than folded together.
                at: {"$cond": [{"$eq": [{"$type": f"${at}"}, "date"]},
                               {"$min": [f"${at}", due]}, due]},
                **mark_set,
            }}]

        # Everything made out of what this matched goes with it. Resolved
        # before the write, because afterwards the matched documents carry
        # the mark and the query that found them no longer does.
        ids, inherited = await self._descendants(query)
        result = await self.db[self.collection].update_many(
            self._with_descendants(query, filters, ids), update)
        n = result.modified_count
        self.receipts_log.record_write(
            "held" if rule.reversible else "revoked", n, why)
        if n:
            log.info("%s %d fact(s) in %s (%s)%s; unreachable as of %s",
                     rule.reason, n, self.collection, why,
                     f", {inherited} inherited" if inherited else "",
                     stamp.isoformat())
        detail: dict = {}
        if inherited:
            detail |= {"direct": len(ids), "inherited": inherited}
        # `lift` resolves its own ids; `impose` only resolves them when
        # something downstream needs them, so the extra round trip is paid
        # by the deployments that use it and by nobody else.
        if self.perimeter is not None and not rule.reversible:
            # Told after the rows are marked, never before: the fact is
            # already unreachable here, and an erasure must not wait on --
            # or be failed by -- a cache. See ``perimeter.py``.
            acks = await self.perimeter.forget(ids, reason=why)
            detail["perimeter"] = [a.as_dict() for a in acks]
            if self.perimeter_log is not None:
                # Only the ones that did not answer. An acknowledged sink
                # is already recorded on the chain and needs no queue row.
                await self.perimeter_log.record(acks, ids=ids, reason=why)
        receipt = await self._witness(
            filters or {}, event=rule.reason, reason=why, count=n, at=stamp,
            detail=detail or None)
        return n, receipt

    async def lift(self, off: str, filters: dict | None = None, *,
                   reason: str, expect: int | None = None,
                   everything: bool = False) -> tuple[int, dict | None]:
        """Remove one reason's mark, if that reason has an inverse.

        Raises ``Irreversible`` when it does not, and the check is on the
        rule rather than on a list of verb names here -- so a third-party
        reason gets the same answer as a builtin, decided by the same word
        in the same place.

        The mark is ``$unset``, not set to null. Both refuse identically
        under ``Marked.refuses`` -- it tests ``is not None`` -- so the
        difference is entirely about the sparse index ``ensure()`` builds on
        the mark field: a null keeps the row in the index forever, so a
        collection that quarantines and releases in a loop would grow an
        index of documents that are not held. The rule is unaffected either
        way; the cost is not.

        **This is the only verb here that grants reachability, and it gets
        both enforcement points because of it.** Everywhere else the query
        is the optimisation and the per-document check is the guarantee;
        this is the one write where that distinction has teeth. A
        ``Clearance`` clause is an ``$in`` over the levels the caller holds,
        and its own docstring says what it cannot express: a document
        carrying a label this deployment does not recognise. On a read that
        gap is harmless -- ``refuses()`` catches it on the way out and the
        document is withheld. On a *lift* the same gap would let a caller
        re-admit a document they are not cleared to read, which is the one
        direction where "the query missed it" is a privilege escalation
        rather than a slower query.

        So candidates are admitted one at a time through the audit handle
        first, and only their ids are unset. Batched, because an id list is
        a query and a query has a size limit -- and the alternative, one
        ``update_many`` over a filter nobody checked per document, is how
        the two halves come to disagree in the direction that matters.
        """
        rule = self._rule_for(off)
        if not rule.reversible:
            raise Irreversible(
                self.collection, rule.reason,
                tuple(r.reason for r in self._imposable() if r.reversible))
        self._require_caller()
        # The operation that grants reachability, and therefore the one an
        # authority exists to gate: a mistake here puts a flagged document
        # back in front of a model.
        self._authorise(RELEASE)
        query = self._write_query(rule, filters, present=True)
        await self._guard("release", filters, query, expect=expect,
                          everything=everything)

        stamp = now()
        audit = self.including_refused()
        # Released with the thing they were held with. A review that clears
        # a document and leaves its summaries withheld has not finished.
        ids, inherited = await self._descendants(query)
        query = self._with_descendants(query, filters, ids)
        n = 0
        batch: list = []
        cursor = self.db[self.collection].find(query, {"_id": 1, **{
            f: 1 for f in self._caller_aware_fields()}})
        async for doc in cursor:
            if audit._admit(doc) is None:
                continue
            batch.append(doc["_id"])
            if len(batch) >= LIFT_BATCH:
                n += await self._unset(rule.field, batch)
                batch = []
        if batch:
            n += await self._unset(rule.field, batch)
        self.receipts_log.record_write("lifted", n, reason)
        if n:
            log.info("lifted %s from %d fact(s) in %s (%s)",
                     rule.reason, n, self.collection, reason)
        # The chain has to record this or it is a record of one direction of
        # a two-direction transition -- intact, verifiable, and wrong about
        # whether the fact is reachable. See ledger.py.
        detail: dict = {"lifted": rule.reason}
        if inherited:
            detail |= {"direct": len(ids), "inherited": inherited}
        receipt = await self._witness(filters or {}, event=LIFTED,
                                      reason=reason, count=n, at=stamp,
                                      detail=detail)
        return n, receipt

    def _caller_aware_fields(self) -> tuple:
        """The document fields the unbypassable rules compare against.

        Projected into ``lift()``'s candidate scan so the per-document check
        has what it needs, and *only* that: the text of a quarantined
        document has no business crossing this boundary to answer a question
        about who may release it.
        """
        return tuple(f for f in (getattr(r, "field", None) for r in self.rules
                                 if not getattr(r, "bypassable", True)) if f)

    async def _unset(self, field_name: str, ids: list) -> int:
        result = await self.db[self.collection].update_many(
            {"_id": {"$in": ids}}, {"$unset": {field_name: ""}})
        return result.modified_count

    async def _witness(self, filters: dict, *, event: str, reason: str,
                       count: int, at: datetime,
                       detail: dict | None = None) -> dict | None:
        """Append to the chain, and never fail the write over it.

        Order matters and this is the unintuitive half: the rows are already
        unreachable before this runs. If appending fails, the *safe* outcome
        is the one that already happened -- the fact is refused -- and the
        loud thing to do is log it, not raise and let a caller conclude the
        revocation did not take and retry it. An unrecorded refusal is an
        audit gap; an un-refused fact is a breach. They are not the same
        size, so they do not get the same handling.

        The subject is the filter, canonicalised -- ids and a reason, never
        document text. An audit record that quotes the secret it was asked to
        forget is a fresh copy of it, exempt from every deadline here.
        """
        if self.ledger is None:
            return None
        try:
            return await self.ledger.append(
                event, tenant=self.tenant and filters.get(self.tenant),
                reason=reason, subject=filters, count=count, at=at,
                detail=detail, actor=self._actor())
        except Exception:  # noqa: BLE001 - see docstring: the write already
            # happened, and this must not undo it.
            log.exception(
                "%s %d fact(s) in %s but could not record it on the chain -- "
                "the write DID happen; the audit trail has a gap at %s",
                event, count, self.collection, at.isoformat())
            return None

    async def pin(self, filters: dict) -> int:
        """Remove a deadline. Pinning is the absence of one, not a flag."""
        return (await self.db[self.collection].update_many(
            filters, {"$set": {self.spec.at_field: None}})).modified_count
