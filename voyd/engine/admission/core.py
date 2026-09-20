"""The state, and the two enforcement points. Everything else is downstream.

This is the class the rest of the package is a mixin onto, and the split is
not arbitrary: **the guarantee lives here and nowhere else.**

    ``_query``   pushes what it can into the database. An *optimisation*.
    ``_admit``   re-checks every document on the way out. The *guarantee*.

A capability module -- reads, marks, lineage, sealing -- may issue whatever
queries it needs, but it gets its documents past the boundary by calling
``_admit`` or something built on it. That is the module-graph statement of
the invariant in the package docstring: a rule that can express itself in a
query but not per document is not a slower rule, it is a silent hole.

Also here: the attachments (``authorised_by``, ``bounded_by``,
``witnessed_by``, ``sealed_by`` in sealing.py), which are claims about a
deployment typed out where somebody can read them, and ``_clone``, which is
load-bearing for concurrency rather than stylistic.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Self, Iterable

from ..errors import CallerRequired, require_tenant
from ..authority import AuthorityRequired, NotAuthorised
from ..time import aware
from .receipts import Receipts
from .rules import Rule
from .spec import AdmissionSpec, why_refused

log = logging.getLogger("engine.admission")


class AdmissionCore:
    """The handle's state, and the only two places refusal is decided.

    Not instantiated directly -- ``Admission`` in handle.py is the class a
    caller holds. This is its base, and the split exists so that the
    question *"what may reach a prompt?"* is answerable by reading one
    file instead of six.

    The two enforcement points are ``_query`` (pushed into the database,
    an optimisation) and ``_admit`` (per document on the way out, the
    guarantee). Every capability mixin gets its documents past the
    boundary through the second one.
    """

    kind = "admission"

    def __init__(self, db, spec: AdmissionSpec, *, engine=None):
        self.db = db
        # Optional, and only so ``search()`` below can exist. A handle built
        # by hand (tests, a script) keeps working without one and raises a
        # sentence rather than an AttributeError if asked to search.
        self.engine = engine
        self.spec = spec.with_defaults()
        spec = self.spec
        self.rules: tuple[Rule, ...] = spec.rules
        self.collection = spec.collection
        self.tenant = spec.tenant
        self.receipts_log = Receipts()
        self._include = False
        self.ledger = None
        self.perimeter = None
        self.perimeter_log = None
        # Who may *do* things here. ``None`` means this handle is not
        # serving anybody but its own application; see ``authorised_by``.
        self.authority = None
        # The instant reads are answered at. ``None`` is now, which is the
        # ordinary case and costs a single comparison.
        self._as_of: datetime | None = None
        self._caller: dict | None = None
        # Set by ``sealed_by()`` when the model declares encrypted fields.
        # ``None`` is the ordinary case and costs nothing: every read below
        # checks it once and skips the whole path.
        self.sealing = None
        # Bound and holding no claims is not the same as never bound: the
        # first is a caller entitled to nothing, the second is a code path
        # that forgot to say who is asking. Conflating them is how a read
        # returns empty and a write silently matches nothing.
        self._bound = False

    # ---- proof ---------------------------------------------------------

    def authorised_by(self, authority) -> Self:
        """Gate the verbs that change reachability. Returns ``self``.

        Attached rather than built in, because by default the caller of a
        library *is* the application -- it already holds the database, and
        demanding an authority from a script would be theatre. Installing
        one says this handle is serving somebody else, and from then on an
        unbound caller raises rather than passing.

        See ``authority.py`` for why the operations are asymmetric:
        withholding a fact and granting one back are not equally dangerous
        and must not be equally available.
        """
        self.authority = authority
        return self

    def _authorise(self, operation: str) -> None:
        """Check, and raise loudly. Never returns False.

        A boolean here would be a boolean somebody forgets to check, and
        the thing they would forget to check is whether the caller may put
        a quarantined document back in front of a model.
        """
        if self.authority is None:
            return
        if not self._bound:
            raise AuthorityRequired(operation, self.collection)
        if self.authority.permits(operation, self._caller,
                                  collection=self.collection):
            return
        held = getattr(self.authority, "held_by", None)
        # WARNING, not info: a denied write is either a bug in the caller
        # or somebody probing, and both are worth waking up to. The same
        # reasoning that counts ``not_cleared`` apart from ``deadline``.
        log.warning("refused %s on %s for %r", operation, self.collection,
                    self._actor() or "an unnamed caller")
        raise NotAuthorised(operation, self.collection,
                            held(self._caller) if held else None)

    def _actor(self) -> str | None:
        """Who to write on the chain, when anything knows."""
        if self.authority is None:
            return None
        naming = getattr(self.authority, "actor", None)
        return naming(self._caller) if naming else None

    def bounded_by(self, perimeter, *, log_to=None) -> Self:
        """Register who else holds copies. Returns ``self``.

        Attached rather than built in, for the same reason the ledger is:
        it is a claim about a deployment's architecture, and a claim about
        architecture should be typed out where somebody can read it.

        Nothing here can fail a revocation -- see ``perimeter.py``. The
        acknowledgements ride along on the receipt, so "who was told, and
        who did not answer" is part of the audit trail rather than a log
        line somebody greps for afterwards.

        ``log_to`` is a ``PerimeterLog``, and it is optional because it is
        a retention decision: keeping a queue of unconfirmed erasures is
        obviously right for some deployments and obviously unwanted for
        others, and this package does not get to pick. Without it, a sink
        that was down is recorded on the chain and never retried.
        """
        self.perimeter = perimeter
        self.perimeter_log = log_to
        return self

    def witnessed_by(self, ledger) -> Self:
        """Record every revocation on a hash chain. Returns ``self``.

        Counters answer "how much has this process refused"; a chain answers
        "show me that this fact stopped being reachable at 14:02, and that
        the record has not been edited since". Only the second one survives
        contact with an auditor, and only revocations go on it -- see
        ``ledger.py`` for why ledgering reads is the wrong trade.

        Attached rather than built in, because a chain that never expires is
        a retention decision and retention decisions should be typed out.
        """
        self.ledger = ledger
        return self

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
        if self.spec.lineage_field:
            # Multikey, and the reason it is not optional: propagation is
            # one ``$in`` over this field on every revocation. Unindexed,
            # an erasure request becomes a collection scan, and the first
            # thing anybody does with a slow erasure path is stop calling
            # it.
            await self.db[self.collection].create_index(
                self.spec.lineage_field, sparse=True)
        return True

    # ---- who is asking -------------------------------------------------

    def for_caller(self, claims: dict | None) -> Self:
        """Bind this handle to one caller's claims. Returns a new handle.

        A clone, not a setting, and that is load-bearing rather than
        stylistic: ``engine.admission()`` deduplicates handles per collection
        and hands every caller *the same object*. A ``for_caller`` that
        mutated would make the last request's identity the current one, under
        concurrency, in an access-control check -- the kind of bug that does
        not reproduce and does not error and shows the wrong tenant's
        documents to whoever asked second.

        Rules that declared ``needs_caller`` see these claims. The rest do
        not, so binding a caller onto a collection with no caller-aware rule
        changes nothing, which is the behaviour that makes it safe to call
        unconditionally in a request handler.

        Claims come from whatever already authenticated the caller. This
        method does not verify them and cannot: a handle that believed
        ``{"clearance": "secret"}`` because it was passed one would be an
        authorisation system whose only input is the attacker's.
        """
        clone = self._clone()
        clone._caller = dict(claims) if claims else {}
        clone._bound = True
        return clone

    def _clone(self) -> Self:
        clone = type(self)(self.db, self.spec, engine=self.engine)
        # Receipts are shared: a refusal is a refusal whichever derived
        # handle saw it, and a per-request clone with its own counters would
        # report nothing on /healthz.
        clone.receipts_log = self.receipts_log
        clone.ledger = self.ledger
        clone.perimeter = self.perimeter
        clone.perimeter_log = self.perimeter_log
        clone.authority = self.authority
        clone._as_of = self._as_of
        clone._include = self._include
        clone._caller = self._caller
        clone._bound = self._bound
        clone.sealing = self.sealing
        return clone

    # ---- what was reachable then ---------------------------------------

    def as_of(self, when: datetime) -> Self:
        """A handle that answers as the scope stood at ``when``.

        *"What did the model see when it said that?"* is the question after
        every AI incident, and until now the only honest answer was a log
        line held by the party being asked.

        Every rule already takes ``when``; what was missing was a handle
        that threads one instant through a whole read, and a ``Marked``
        that actually compared the mark's ``at`` instead of treating any
        mark as eternal.

        **Read this as a lower bound, not a reconstruction.** It answers
        from the rows that are still here. A row the reaper has taken is
        gone, and its absence is indistinguishable from never having
        existed -- so ``as_of`` under-reports, always in the direction of
        saying less was reachable. ``reachability_at()`` is the version
        that will say ``unknown`` rather than let that silence read as a
        denial.
        """
        clone = self._clone()
        clone._as_of = aware(when)
        return clone

    # ---- the escape hatch, deliberately named --------------------------

    def including_refused(self) -> Self:
        """A handle that returns everything, including what was forgotten.

        Audit, administration and the reaper itself need this. It is a
        separate object rather than a flag on every call so that a review can
        grep for the phrase and find every place the guarantee was set aside.

        Note what it does *not* set aside. The tenant, first: seeing
        forgotten rows is an operational need, seeing another tenant's
        forgotten rows is a breach with a nicer name. And second, any rule
        that marks itself unbypassable -- which is how the caller-aware rules
        are declared.

        That distinction is the one worth stating, because the naive version
        of this method is "skip every rule", and it was. The reasons in this
        module are not one kind of thing. A *deadline* and a *revocation* say
        the fact is forgotten, and auditing what was forgotten is precisely
        the job this handle exists for. A *clearance* says this caller may
        not have it, which is not a forgetting reason and not this handle's
        to waive: an auditor is entitled to see what was erased, and entitled
        to nothing above their own clearance. One method waiving both would
        make "let me see the deleted rows" a privilege escalation.
        """
        clone = self._clone()
        clone._include = True
        return clone

    # ---- the rule ------------------------------------------------------

    def _needs_a_caller(self) -> tuple:
        """The reasons on this handle that cannot be decided without a caller."""
        return tuple(r.reason for r in self.rules
                     if getattr(r, "needs_caller", False))

    def _require_caller(self) -> None:
        if self._bound:
            return
        reasons = self._needs_a_caller()
        if reasons:
            raise CallerRequired(self.collection, reasons)

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
        self._require_caller()
        q = require_tenant(self.collection, self.tenant, filters)
        # Only the rules that *can* be expressed server-side. A rule with no
        # clause is not skipped -- it is simply enforced on the way out
        # instead, by _admit, which is the authoritative half anyway.
        #
        # Under ``including_refused()`` the forgetting rules drop out and the
        # unbypassable ones stay, so an audit read is still bounded by who is
        # asking.
        usable = [r for r in self.rules
                  if not self._include or not getattr(r, "bypassable", True)]
        clauses = [c for c in (self._clause_of(r) for r in usable) if c]
        if not clauses:
            return q
        existing = q.pop("$and", [])
        q["$and"] = [*existing, *clauses] if existing else clauses
        return q

    def _clause_of(self, rule) -> dict | None:
        """A rule's query fragment, at the instant this handle answers for.

        The two halves have to agree, and under ``as_of()`` the naive
        version does not: the per-document check compares the mark's
        ``at`` against the instant while the *query* drops every marked
        row unconditionally, server-side, before anything is examined. So
        ``as_of`` would return an empty page and look like a scope where
        nothing was ever reachable -- a confident, wrong, and flattering
        answer.

        A rule that cannot express itself at an instant contributes no
        clause under ``as_of`` rather than a wrong one. Losing the
        optimisation is free; disagreeing with the guarantee is not.
        """
        if getattr(rule, "needs_caller", False):
            for_caller = getattr(rule, "clause_for", None)
            return for_caller(self._caller) if for_caller else None
        if self._as_of is None:
            return rule.clause()
        at_instant = getattr(rule, "clause_at", None)
        return at_instant(self._as_of) if at_instant else None

    def _admit(self, doc: dict | None, *, when: datetime | None = None,
               tally: dict[str, int] | None = None):
        """The authoritative check, on the way out.

        The query above is an optimisation. *This* is the guarantee, and it is
        the only one that holds for documents that did not pass through that
        query clause -- every hit from ``$vectorSearch``, where the deadline is
        deliberately not an index filter.
        """
        if doc is None:
            return doc
        # Loud on the per-document path as well. A handle that refused every
        # hit for want of a caller would look exactly like a scope where
        # everything is forgotten -- and that is the one diagnosis this whole
        # module exists to make impossible to reach by accident.
        self._require_caller()
        reason = why_refused(doc, self.spec, when=when or self._as_of,
                             caller=self._caller,
                             only_unbypassable=self._include)
        if reason is None:
            return doc
        if tally is None:
            self.receipts_log.record(reason)
        else:
            # Counted for this page; committed by the caller once the page is
            # final, so a refill does not count the same document twice.
            tally[reason] = tally.get(reason, 0) + 1
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

    def _classify(self, docs: list[dict], *, when: datetime | None = None
                  ) -> tuple[list[dict], dict[str, int]]:
        """Admit a candidate set without recording anything yet."""
        tally: dict[str, int] = {}
        kept = [d for d in docs
                if self._admit(d, when=when, tally=tally) is not None]
        return kept, tally
