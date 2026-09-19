"""Forgetting as a retrieval guarantee, not a storage event.

Every database can delete. None of them can *refuse*. That distinction is the
whole point of this module:

    deletion  is a storage operation -- eventually consistent, by nature.
              A TTL monitor sweeps about once a minute. An object lifecycle
              rule runs about once a day. A cron runs when it last worked.

    refusal   is a retrieval guarantee -- immediate, by construction.
              "This fact may not reach a prompt", answered on every read,
              before anything is returned.

Nobody ships the second one, so the honest answer to "when was this
forgotten?" is really "when did the sweeper get to it?" -- and in the gap
between those two, a deleted document is still being returned as a
well-scored result.

Re-checking a deadline on the way out is not hard, and an application that
knows to do it will do it correctly in the read path it was thinking about
when it learned the lesson. Then it grows a second read path, and a fifth,
and the rule is only as good as the next author's memory. A guarantee that
must be remembered is not enforced, it is suggested.

So this makes refusal structural. ``Forgetting`` is a read handle, and every
read through it refuses forgotten facts. There is no "remember to filter"
step, because there is no unfiltered ``find`` to reach for. Seeing everything
remains possible -- audit and administration need it -- but it has a name a
reviewer can grep for:

    await docs.find({"owner": who})                        # reachable only
    await docs.including_forgotten().find({"owner": who})  # deliberate

The failure mode is inverted. Before, you had to remember to be safe. Now you
have to declare that you want the unsafe thing.

**Two enforcement points, always both.** The rule is pushed into the query
where the query can express it (cheap: the database does the work) *and*
re-checked per document on the way out (authoritative). That is not
belt-and-braces paranoia. A vector index cannot filter on a deadline without
an unmigratable index change -- see ``search.py`` for the measurements -- so
hits arriving from ``$vectorSearch`` have never been filtered by anything.
``reachable()`` is what a search path calls, and it is the guarantee; the
query clause is the optimisation.

**More than one reason to forget.** A deadline is only the common one:

- ``deadline``    -- the expiry field has passed. Pinning is its absence.
- ``revoked``     -- somebody said forget this, now. A subject erasure
  request, a leaked credential, a retracted document. Unreachable on the next
  read, whatever the sweeper is doing, and without waiting for it.
- ``unreadable``  -- a deadline that is not a date, or cannot be compared.
  Fails closed: a fact whose lifetime cannot be established has no business
  in a prompt.

Plus pinning, the absence of all three. Every case collapses to one question
-- *may this reach a prompt?* -- answered in one place.

**Refusals are counted, with their limits stated.** ``receipts()`` reports
what was refused and why. ``revoked_total`` is exact. ``refused_at_boundary``
is a lower bound and is named so, because the same rule runs inside the query
and the database drops most forgotten facts server-side; counting those would
mean issuing every read twice. A signal, not a ledger.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Any, Iterable, Protocol

from .errors import require_tenant
from .time import aware, living, now

log = logging.getLogger("engine.forgetting")

# Why a fact was refused. Stable strings: they are counted, logged, and end up
# in an operator's dashboard.
DEADLINE = "deadline"
REVOKED = "revoked"
UNREADABLE = "unreadable"
QUARANTINED = "quarantined"


# ---- rules -------------------------------------------------------------
#
# A rule answers one question about one document: is there a reason this may
# not reach a prompt? The handle owns *that* there is an answer on every
# read; a rule owns *what* the answer is. Adding a reason is therefore a new
# rule rather than a new branch in a predicate that keeps growing.
#
# Two halves, and both are optional to get right in the same way:
#
#   refuses(doc)  the authoritative check, per document, on the way out.
#                 Must never raise: an exception inside a filter is how the
#                 filter gets skipped.
#   clause()      the same rule as a query fragment, or None when it cannot
#                 be expressed server-side. An optimisation, never the
#                 guarantee -- search hits never went through a query.


class Rule(Protocol):
    """One reason a document may not reach a prompt."""

    reason: str

    def refuses(self, doc: dict, *, when: datetime | None = None) -> bool: ...

    def clause(self) -> dict | None: ...


@dataclass(frozen=True)
class Deadline:
    """Expired, or carrying a deadline that cannot be read.

    Fails closed on an unreadable one: a fact whose lifetime cannot be
    established has no business in a prompt. Reported separately from an
    ordinary expiry, because a climbing ``unreadable`` count means something
    is writing deadlines it should not.
    """

    at_field: str = "expire_at"
    reason: str = DEADLINE

    def refuses(self, doc: dict, *, when: datetime | None = None) -> bool:
        return self.why(doc, when=when) is not None

    def why(self, doc: dict, *, when: datetime | None = None) -> str | None:
        exp = doc.get(self.at_field)
        if exp is None:
            return None                  # pinned: the absence of a deadline
        if not isinstance(exp, datetime):
            return UNREADABLE
        try:
            return None if aware(exp) > (when or now()) else DEADLINE
        except (TypeError, ValueError, OverflowError):
            return UNREADABLE

    def clause(self) -> dict | None:
        return living(self.at_field)


@dataclass(frozen=True)
class Marked:
    """Refused because somebody said so, and said why.

    The general form of "a field whose presence means no". ``revoked`` is an
    erasure request; ``quarantined`` is a document held back from models
    while kept for forensics. Same mechanics, different verb and different
    operational meaning, which is exactly why they are two rules and not one
    boolean.
    """

    field: str
    reason: str

    def refuses(self, doc: dict, *, when: datetime | None = None) -> bool:
        return doc.get(self.field) is not None

    def clause(self) -> dict | None:
        return {"$or": [{self.field: None}, {self.field: {"$exists": False}}]}


def revoked(field: str = "forgotten") -> Marked:
    """Forgotten on request: unreachable now, erased by the deadline."""
    return Marked(field=field, reason=REVOKED)


def quarantined(field: str = "quarantined") -> Marked:
    """Held back from models, deliberately still on disk.

    The row is evidence. A document flagged by an injection detector, or by
    a human, must stop reaching prompts *without* being destroyed -- you
    cannot investigate what you deleted. Refusal already had exactly this
    shape, so this is a rule rather than a feature.
    """
    return Marked(field=field, reason=QUARANTINED)



@dataclass(frozen=True)
class ForgettingSpec:
    """Where a collection keeps the two facts that make a document forgettable."""

    collection: str
    at_field: str = "expire_at"
    # Set by revoke(). Present means "refuse this", independently of the
    # deadline, so an erasure request does not have to wait for a sweeper and
    # does not depend on the TTL index existing at all.
    mark_field: str = "forgotten"
    # Part of the spec, and therefore part of identity, because handles are
    # deduplicated per collection by spec equality. It was not, and the
    # consequence was that declaration order silently decided whether the
    # tenant was enforced at all: a Memory builds an unscoped handle for its
    # collection, and a later ``model(tenant=...).forgettable()`` got that
    # same unscoped object back. Two declarations disagreeing about the
    # boundary must collide loudly, not resolve to whichever ran first.
    tenant: str | None = None
    # The reasons this collection refuses, in the order they are asked.
    # Empty means the two defaults -- a deadline and an explicit revocation
    # -- which is what ``forgettable()`` installs. Anything else is declared
    # by the application through ``admitting()``.
    rules: tuple[Rule, ...] = ()

    def with_defaults(self) -> ForgettingSpec:
        if self.rules:
            return self
        return replace(self, rules=(Deadline(self.at_field),
                                    revoked(self.mark_field)))

    def describe(self) -> str:
        scope = f", scoped by {self.tenant}" if self.tenant else ""
        reasons = ", ".join(r.reason for r in self.rules) or "deadline, revoked"
        return f"{self.collection}: refuses on [{reasons}]{scope}"


@dataclass
class Receipts:
    """What was refused and revoked. The audit artifact, with its limits.

    ``refused`` counts documents this handle rejected *on the way out* -- the
    authoritative per-document check. It is deliberately a **lower bound**,
    and it is worth knowing why: most forgotten facts never reach the handle
    at all, because the same rule is pushed into the query and MongoDB drops
    them server-side. Counting those too would mean running every read twice.

    So this is a signal, not a ledger. A non-zero ``refused`` means documents
    are arriving at the boundary already forgotten -- which is normal for
    search hits (the vector index has no deadline filter) and suspicious for
    anything else. ``revoked`` is exact: every fact this handle made
    unreachable, counted at the moment it happened.
    """

    refused: dict[str, int] = field(default_factory=dict)
    revoked: int = 0
    last_reason: str | None = None
    last_at: datetime | None = None

    def record(self, reason: str) -> None:
        self.refused[reason] = self.refused.get(reason, 0) + 1
        self.last_reason = reason
        self.last_at = now()

    def record_revocation(self, n: int, reason: str) -> None:
        if n:
            self.revoked += n
            self.last_reason = reason
            self.last_at = now()

    @property
    def total(self) -> int:
        return sum(self.refused.values())

    def as_dict(self) -> dict:
        return {
            # A lower bound: the query prunes most of these server-side.
            "refused_at_boundary": self.total,
            "refused_by_reason": dict(self.refused),
            # Exact: counted when it happened.
            "revoked_total": self.revoked,
            "last_reason": self.last_reason,
            "last_at": self.last_at.isoformat() if self.last_at else None,
        }


def why_unreachable(doc: dict, spec: ForgettingSpec,
                    *, when: datetime | None = None) -> str | None:
    """The first reason this document may not reach a prompt, or ``None``.

    Asks each declared rule in order and returns the first refusal. Order is
    the declared order and it is reported, not merged: an operator needs to
    know a document was *quarantined* rather than merely expired, because
    the two demand different responses.

    Never raises, whatever a rule does. A rule that throws is treated as a
    refusal and named, because an exception inside a filter is how the
    filter gets skipped -- the failure this module exists to prevent, and it
    must not come back through a third-party rule.
    """
    for rule in spec.with_defaults().rules:
        try:
            if isinstance(rule, Deadline):
                why = rule.why(doc, when=when)
                if why is not None:
                    return why
            elif rule.refuses(doc, when=when):
                return rule.reason
        except Exception:  # noqa: BLE001 - a rule must not be able to open
            # the gate by failing. Refuse, and say which rule did it.
            log.exception("rule %r raised; refusing the document", rule.reason)
            return rule.reason
    return None


class Forgetting:
    """A read handle that cannot return a forgotten fact.

    Install it on a model (``.forgettable()``) or build it directly. It is a
    trait, so ``ensure()`` gives the mark field an index -- revocation has to
    be cheap to filter on, or it will be skipped at scale.
    """

    kind = "forgetting"

    def __init__(self, db, spec: ForgettingSpec):
        self.db = db
        self.spec = spec.with_defaults()
        spec = self.spec
        self.rules: tuple[Rule, ...] = spec.rules
        self.collection = spec.collection
        self.tenant = spec.tenant
        self.receipts_log = Receipts()
        self._include = False

    # ---- schema --------------------------------------------------------

    async def ensure(self) -> bool:
        """Index every field a rule filters on.

        One index per marked field, sparse because the mark is the exception.
        A rule whose field is unindexed still *works* -- it is checked on the
        way out either way -- but its server-side clause becomes a scan, and
        a guarantee that gets expensive is a guarantee somebody eventually
        turns off.
        """
        for rule in self.rules:
            field_name = getattr(rule, "field", None)
            if field_name:
                await self.db[self.collection].create_index(field_name,
                                                            sparse=True)
        return True

    # ---- the escape hatch, deliberately named --------------------------

    def including_forgotten(self) -> Forgetting:
        """A handle that returns everything, including what was forgotten.

        Audit, administration and the reaper itself need this. It is a
        separate object rather than a flag on every call so that a review can
        grep for the phrase and find every place the guarantee was set aside.

        Note what it does *not* set aside: the tenant. Seeing forgotten rows
        is an operational need; seeing another tenant's forgotten rows is a
        breach with a nicer name.
        """
        clone = Forgetting(self.db, self.spec)
        clone.receipts_log = self.receipts_log
        clone._include = True
        return clone

    # ---- the rule ------------------------------------------------------

    def _query(self, filters: dict | None) -> dict:
        """Push refusal *and* the tenant into the query.

        The tenant check is the same ``require_scope`` the search path uses,
        deliberately: this handle once accepted a ``tenant`` and ignored it,
        so ``model(tenant="t").forgettable().find({})`` returned every
        tenant's rows while ``engine.search`` on the same model refused the
        same query. One declaration, two primitives, two answers -- which is
        the drift this module was written to remove, reappearing inside it.

        It shares the tenant rule but not the search path's blanket
        "every filter must be scalar": this handle queries the collection,
        where ``doc_id: {"$in": [...]}`` is how a batch is forgotten. The
        hazards differ, so the rules do.
        """
        q = require_tenant(self.collection, self.tenant, filters)
        if self._include:
            return q
        # Only the rules that *can* be expressed server-side. A rule with no
        # clause is not skipped -- it is simply enforced on the way out
        # instead, by _admit, which is the authoritative half anyway.
        clauses = [c for c in (r.clause() for r in self.rules) if c]
        if not clauses:
            return q
        existing = q.pop("$and", [])
        q["$and"] = [*existing, *clauses] if existing else clauses
        return q

    def _admit(self, doc: dict | None, *, when: datetime | None = None):
        """The authoritative check, on the way out.

        The query above is an optimisation. *This* is the guarantee, and it is
        the only one that holds for documents that never went through a query
        -- every hit from ``$vectorSearch``, where the deadline is deliberately
        not an index filter.
        """
        if doc is None or self._include:
            return doc
        reason = why_unreachable(doc, self.spec, when=when)
        if reason is None:
            return doc
        self.receipts_log.record(reason)
        log.debug("refused a %s document from %s", reason, self.collection)
        return None

    def reachable(self, docs: Iterable[dict], *,
                  when: datetime | None = None) -> list[dict]:
        """Filter documents that arrived from somewhere else.

        This is the search path's entry point: ``$vectorSearch`` and
        ``$rankFusion`` hits have not been through ``_query`` and never will
        be, so they are admitted one at a time, here.
        """
        return [d for d in docs if self._admit(d, when=when) is not None]

    # ---- reads: refusal is the default ---------------------------------

    async def find_one(self, filters: dict | None = None, *args, **kw):
        doc = await self.db[self.collection].find_one(self._query(filters),
                                                      *args, **kw)
        return self._admit(doc)

    async def find(self, filters: dict | None = None, *args,
                   limit: int = 0, sort: Any = None, **kw) -> list[dict]:
        cur = self.db[self.collection].find(self._query(filters), *args, **kw)
        if sort is not None:
            cur = cur.sort(*sort) if isinstance(sort, tuple) else cur.sort(sort)
        if limit:
            cur = cur.limit(limit)
        return [d async for d in cur if self._admit(d) is not None]

    def match(self, filters: dict | None = None) -> dict:
        """The refusing filter, for a pipeline that cannot use ``find``.

        An aggregation is the one read shape this handle cannot wrap, so it
        gets the rule as a value instead of a method: ``{"$match":
        docs.match({...})}``. Still one source of truth -- if the definition
        of "forgotten" changes, this changes with it.

        Note what it is *not*: the per-document check. A pipeline that emits
        whole documents should pass them through ``reachable()`` too. This is
        the right tool for counting and grouping, where there is no document
        to hand back.
        """
        return self._query(filters)

    async def count(self, filters: dict | None = None) -> int:
        """How many facts are *reachable*, which is the number a caller means.

        Counted with the same query the reads use, so a count and a find
        cannot disagree about what exists.
        """
        return await self.db[self.collection].count_documents(
            self._query(filters))

    async def exists(self, filters: dict | None = None) -> bool:
        return await self.find_one(filters) is not None

    # ---- forgetting, without waiting to be deleted ---------------------

    async def revoke(self, filters: dict, *, reason: str = "revoked",
                     erase_after: timedelta | None = None) -> int:
        """Make matching facts unreachable now. Bytes leave on their own time.

        This is the part no vector database has. ``delete_many`` is a storage
        operation whose effect on retrieval is "eventually"; this is a
        retrieval operation whose effect is "next read". The row is also given
        a deadline so the reaper collects it -- unreachable first, erased
        shortly after, in that order, because the reverse order is the bug.

        ``erase_after`` keeps the tombstone readable for a while through
        ``including_forgotten()``, for cases where you must prove *when* a fact
        stopped being reachable. The default erases as soon as the reaper runs.
        """
        stamp = now()
        mark = {"at": stamp, "reason": reason}
        result = await self.db[self.collection].update_many(
            self._query(filters),
            {"$set": {self.spec.mark_field: mark,
                      self.spec.at_field: stamp + (erase_after or timedelta(0))}},
        )
        self.receipts_log.record_revocation(result.modified_count, reason)
        if result.modified_count:
            log.info("revoked %d fact(s) in %s (%s); unreachable as of %s",
                     result.modified_count, self.collection, reason,
                     stamp.isoformat())
        return result.modified_count

    async def pin(self, filters: dict) -> int:
        """Remove a deadline. Pinning is the absence of one, not a flag."""
        return (await self.db[self.collection].update_many(
            filters, {"$set": {self.spec.at_field: None}})).modified_count

    # ---- proof ---------------------------------------------------------

    def receipts(self) -> dict:
        """What this handle has refused, and why.

        Two numbers with different strengths, and the difference is the
        honest part. ``revoked_total`` is exact. ``refused_at_boundary`` is a
        lower bound -- the same rule runs inside the query, so most forgotten
        facts are dropped by MongoDB and never counted here. Counting them
        would mean issuing every read twice.

        Read them as signals: a climbing ``unreadable`` means something is
        writing deadlines it should not, and a ``revoked_total`` with no
        erasure request behind it is worth a question.
        """
        return {"collection": self.collection,
                "policy": self.spec.describe(),
                **self.receipts_log.as_dict()}
