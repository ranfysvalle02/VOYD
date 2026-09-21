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
from typing import Any, Iterable, Self

from ..errors import (CallerRequired, ScopeInvalid, ScopeRequired,
                      require_tenant)
from ..authority import AUDIT, AuthorityRequired, NotAuthorised
from ..time import aware
from .reasons import OFF_SCOPE, UNNAMED
from .receipts import Receipts
from .rules import Rule, Tabs
from .spec import AdmissionSpec, why_refused

# A tenant id a caller could legitimately pass -- ``None``, ``0``, ``""`` --
# must not be mistaken for "no tenant bound", so the sentinel is an object no
# caller can construct a reference to.
_UNSET: Any = object()

log = logging.getLogger("engine.admission")

# Stamped on a document whose embedded subjects were refused, so the page
# can count redactions without re-walking every array it just walked. Read
# and removed by the read path; never persisted, never returned to a caller.
_REDACTED = "__redacted__"


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
        # Public break-glass is re-authorised and counted at every terminal
        # read. Internal ``_unfiltered()`` clones set ``_include`` without this
        # bit because their enclosing verb already has its own authority.
        self._break_glass = False
        self.ledger = None
        # Which consequences were made out of these facts. ``None`` means
        # nothing is recording them, and ``record_use`` says so rather than
        # succeeding quietly -- see context.py.
        self.context = None
        self.perimeter = None
        self.perimeter_log = None
        # Who may *do* things here. ``None`` means this handle is not
        # serving anybody but its own application; see ``authorised_by``.
        self.authority = None
        # The instant reads are answered at. ``None`` is now, which is the
        # ordinary case and costs a single comparison.
        self._as_of: datetime | None = None
        self._caller: dict | None = None
        # The tenant *value* this handle is bound to, as opposed to
        # ``self.tenant``, which is the field name. ``_UNSET`` rather than
        # ``None`` because ``None`` is a tenant id somebody could pass, and a
        # sentinel that can be supplied by a caller is not a sentinel.
        self._scope: Any = _UNSET
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

    def contextualized_by(self, index) -> Self:
        """Record which consequences were made out of these facts. Returns ``self``.

        Attached rather than built in, for the third time in this class and
        the same reason each time: it is a retention decision. A use index
        outlives the documents it points at -- that is what makes it useful
        after an erasure and what makes keeping it a choice somebody has to
        type out.

        What it buys is the question ``lineage`` cannot answer. Lineage
        carries a refusal to the rows made out of a fact *here*. This names
        what was made out of it **out there** -- the summary that was sent,
        the ticket that was filed -- so an erasure request produces a
        worklist instead of ending at the collection boundary.

        It does not extend the guarantee, and saying so is the point:
        ``affected_by()`` returns things this package cannot unsend. An
        index that implied otherwise would be the most dangerous object in
        the repository.
        """
        self.context = index
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

    def for_tenant(self, value: Any) -> Self:
        """Bind this handle to one tenant. Returns a new handle.

        A clone for the same reason ``for_caller`` is one: handles are
        deduplicated per collection, so a method that assigned to ``self``
        would make the last request's tenant the current one, under
        concurrency, in the check that decides whose documents a caller sees.

        Binding does two things, and the second is the one that was missing.
        The tenant is supplied to the **query**, so ``find({})`` on a bound
        handle is complete rather than an error. And it is enforced **per
        document on the way out**, so a batch that never went through that
        query -- every ``$vectorSearch`` hit -- is filtered too.

        ``find``/``find_one``/``search`` bind it themselves from the tenant
        already required in their filters, so this method is for the one path
        that has no filters to read it from: handing ``reachable()`` a batch
        you assembled yourself.
        """
        clone = self._clone()
        clone._scope = value
        return clone

    def _scoped_for(self, filters: dict | None) -> Self:
        """This handle, bound to the tenant these filters name.

        Returns ``self`` unchanged when the collection has no tenant, which
        is the ordinary case and costs one attribute read. Never mutates:
        see ``for_tenant``.
        """
        if not self.tenant or self._scope is not _UNSET:
            return self
        if not filters or self.tenant not in filters:
            return self          # ``_query`` raises ScopeRequired for this
        return self.for_tenant(filters[self.tenant])

    def _off_scope(self, doc: dict) -> bool:
        """Is this document outside the tenant the read is bound to?

        The egress half of the tenant, and it exists because this module's
        own complaint applies to it. ``_query`` says: *this handle once
        accepted a tenant and ignored it, so find({}) returned every tenant's
        rows while engine.search refused the same query -- one declaration,
        two primitives, two answers.* That was fixed for the query. The same
        gap survived on the way out, where a rule that exists only as a query
        clause is what `AHA.md` step 4 calls a silent hole.

        Unknown scope admits, deliberately: the guard against an unbound read
        lives at the entry points (``reachable`` raises, the rest bind from
        their filters), so failing closed twice here would only make a
        misconfiguration look like an empty collection.
        """
        if not self.tenant or self._scope is _UNSET:
            return False
        return doc.get(self.tenant) != self._scope

    def receipts(self) -> dict:
        """What this handle has refused, and why.

        Two numbers with different strengths, and the difference is the
        honest part. ``revoked_total`` is exact. ``refused_at_boundary`` is a
        lower bound -- the same rule runs inside the query, so most forgotten
        facts are dropped by MongoDB and never counted here. Counting them
        would mean issuing every read twice.

        The wire boundary inverts that, which is worth knowing when reading
        the number: a batch handed to ``reachable()`` never went through a
        query, so every document reaches the boundary and the count is exact.

        Read them as signals: a climbing ``unreadable`` means something is
        writing deadlines it should not; a climbing ``off_scope`` means an
        index filter and a per-document check have disagreed.
        """
        return {"collection": self.collection,
                "policy": self.spec.describe(),
                **self.receipts_log.as_dict()}

    def _clone(self) -> Self:
        clone = type(self)(self.db, self.spec, engine=self.engine)
        # Receipts are shared: a refusal is a refusal whichever derived
        # handle saw it, and a per-request clone with its own counters would
        # report nothing on /healthz.
        clone.receipts_log = self.receipts_log
        clone.ledger = self.ledger
        clone.context = self.context
        clone.perimeter = self.perimeter
        clone.perimeter_log = self.perimeter_log
        clone.authority = self.authority
        clone._as_of = self._as_of
        clone._include = self._include
        clone._break_glass = self._break_glass
        clone._caller = self._caller
        clone._bound = self._bound
        clone._scope = self._scope
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

    def _unfiltered(self) -> Self:
        """The ungated escape hatch, for this package's own write paths.

        ``revoke`` has to see the row it is about to mark, ``release`` has to
        find what it is lifting, and ``derive`` has to see a refused parent
        in order to reject it. Each of those is already gated by its *own*
        verb (``_authorise(REVOKE)`` and friends), so routing them through
        the audit-gated ``including_refused()`` would demand an ``AUDIT``
        grant to perform a ``REVOKE`` -- a different question, and one that
        would break ``Grants.withholding_only()``, whose whole point is a
        pipeline that may withhold and may not disclose.

        So this is the mechanism and ``including_refused()`` is the mechanism
        plus a gate and a counter. It is private on purpose:
        ``tests/test_break_glass_is_named.py`` fails the build if any module
        outside ``core.py`` reaches for the *public* name, the same shape as
        ``test_no_module_reaches_past_the_handle.py`` for the search
        primitive.
        """
        clone = self._clone()
        clone._include = True
        return clone

    def including_refused(self) -> Self:
        """Break-glass: a handle that returns everything, forgotten included.

        This is not a permission slip, and it is not a default with a longer
        name -- it is the operator prying the guarantee open, and it is
        treated as such:

        - every terminal read asks the authority for the ``AUDIT`` grant,
          which is the same
          asymmetry ``release`` sits behind: disclosing a forgotten fact is
          the granting direction, not the withholding one. With no authority
          attached -- the library default, where the caller *is* the
          application -- this is a no-op, so an ordinary script is unchanged.
        - every terminal read increments ``including_refused_total`` on
          ``receipts()`` and records the actor/time, so a cached handle cannot
          turn one authorization into unlimited invisible reads. Constructing
          a handle and never using it records nothing.

        It is still a separate object rather than a flag on every call so a
        review can grep for the phrase and find every place the guarantee was
        set aside.

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
        clone = self._unfiltered()
        clone._break_glass = True
        return clone

    def _begin_read(self) -> None:
        """Re-authorise and record one terminal break-glass read.

        Called once at the public read boundary, never once per candidate.
        Keeping it out of ``_query`` and ``_admit`` avoids both double counts
        and an authority call per hit.
        """
        if not self._break_glass:
            return
        self._authorise(AUDIT)
        self.receipts_log.record_bypass(actor=self._actor())

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
        if self.tenant and self._scope is not _UNSET:
            # A bound handle carries the tenant, so `find({})` on it is
            # complete rather than an error -- and a filter that names a
            # *different* tenant is a contradiction rather than a narrowing,
            # so `require_tenant` is still the thing that decides.
            filters = dict(filters or {})
            filters.setdefault(self.tenant, self._scope)
            if filters[self.tenant] != self._scope:
                raise ScopeInvalid(self.collection, self.tenant,
                                   filters[self.tenant])
        q = require_tenant(self.collection, self.tenant, filters)
        # Only the rules that *can* be expressed server-side. A rule with no
        # clause is not skipped -- it is simply enforced on the way out
        # instead, by _admit, which is the authoritative half anyway.
        #
        # On a hatch handle (``including_refused()`` / ``_unfiltered()``, both
        # of which set ``_include``) the forgetting rules drop out and the
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

    def _open_tab(self) -> Tabs | None:
        """A fresh budget for one read, or ``None`` if no cumulative rule.

        One tab per read, never stored on the handle: the handle is shared
        across concurrent callers, so a running total on it would bleed one
        request's spend into another's -- see ``Tab`` for the full argument.
        Costs nothing when no cumulative rule is declared, which is the
        ordinary case: the loop finds nothing and returns ``None``, and
        ``_admit`` hands that straight through to a rule that ignores it.

        ``AdmissionSpec.with_defaults`` rejects more than one cumulative rule
        and rejects one with no ``new_tab()``. Reaching either state here would
        mean somebody bypassed construction, so this method stays small rather
        than inventing a second policy.
        """
        states: dict[int, Any] = {}
        for rule in self.rules:
            if (getattr(rule, "needs_tab", False)
                    and (not self._include
                         or not getattr(rule, "bypassable", True))):
                new_tab = getattr(rule, "new_tab", None)
                if callable(new_tab):
                    states[id(rule)] = new_tab()
        return Tabs(states) if states else None

    def _admit(self, doc: dict | None, *, when: datetime | None = None,
               tally: dict[str, int] | None = None, tab: Tabs | None = None):
        """The authoritative check, on the way out.

        The query above is an optimisation. *This* is the guarantee, and it is
        the only one that holds for documents that did not pass through that
        query clause -- every hit from ``$vectorSearch``, where the deadline is
        deliberately not an index filter.

        ``tab`` is the read's running budget, threaded through so a cumulative
        rule can charge it. ``None`` on a point read or when no budget is
        declared, in which case a cumulative rule has nothing to say.
        """
        if doc is None:
            return doc
        # Loud on the per-document path as well. A handle that refused every
        # hit for want of a caller would look exactly like a scope where
        # everything is forgotten -- and that is the one diagnosis this whole
        # module exists to make impossible to reach by accident.
        self._require_caller()
        if self._off_scope(doc):
            if tally is None:
                self.receipts_log.record(OFF_SCOPE)
            else:
                tally[OFF_SCOPE] = tally.get(OFF_SCOPE, 0) + 1
            log.debug("refused an off-scope document from %s", self.collection)
            return None
        reason = why_refused(doc, self.spec, when=when or self._as_of,
                             caller=self._caller, tab=tab,
                             only_unbypassable=self._include)
        if reason is None:
            return self._redact(doc, when=when, tally=tally)
        if tally is None:
            self.receipts_log.record(reason)
        else:
            # Counted for this page; committed by the caller once the page is
            # final, so a refill does not count the same document twice.
            tally[reason] = tally.get(reason, 0) + 1
        log.debug("refused a %s document from %s", reason, self.collection)
        return None

    def _redact(self, doc: dict, *, when: datetime | None = None,
                tally: dict[str, int] | None = None) -> dict:
        """Refuse the subjects *inside* an admitted document.

        Does nothing at all unless the spec declared ``subjects``, which is
        the ordinary case and costs one attribute read.

        **Why this exists.** Every rule in this package reads top-level
        fields, because until recently the subject and the document were the
        same thing. The embedded-document pattern breaks that, and it breaks
        it silently: a chapter carrying the exact mark ``revoke()`` writes
        reaches a prompt with its parent, is counted in no tally, and is
        attested as "nothing was refused" by ``receipt_for``. A confidently
        wrong receipt is worse than no receipt, so this is not a nicety.

        **Why redact rather than refuse the parent.** The guarantee is that
        nothing refused reaches a prompt, and removing the element satisfies
        it while keeping the document model worth using. Refusing the whole
        parent would mean one erased comment withholding an entire case file
        -- correct, catastrophic, and not what anybody asked for. The
        opposite guess, admitting the parent whole, is the bug. So the
        element goes and the count says so.

        **Why it can never be silent.** A document that comes back shorter
        than it is on disk is a lie unless the caller is told, so every
        removal lands in the same tally the document-level refusals use and
        surfaces as ``Page.redacted``. A short chapter list with an empty
        ``refused`` was the failure; it must not be the fix.

        **Why cumulative rules are not asked.** ``tab`` is deliberately not
        threaded in. A budget is a property of the set being assembled for
        one prompt, charged once per retrieval unit; charging it again per
        element would spend the same allowance twice and make a page's
        ``spent`` depend on how the corpus happens to be nested. ``Budget``
        already returns ``None`` for a ``tab`` of ``None`` -- "not a set
        read: nothing to say" -- so this needs no special case, only the
        decision written down.
        """
        path = self.spec.subjects
        if not path:
            return doc
        held = doc.get(path)
        if not isinstance(held, list) or not held:
            return doc
        kept: list = []
        removed = 0
        for element in held:
            if not isinstance(element, dict):
                # Not a subject -- a scalar in an array of scalars. Left
                # alone rather than guessed at: a rule cannot read a field
                # off a string, and dropping it would be redaction with no
                # reason to report.
                kept.append(element)
                continue
            reason = self._unnamed(element) or why_refused(
                element, self.spec, when=when or self._as_of,
                caller=self._caller, tab=None,
                only_unbypassable=self._include)
            if reason is None:
                kept.append(element)
                continue
            removed += 1
            if tally is None:
                self.receipts_log.record(reason)
            else:
                tally[reason] = tally.get(reason, 0) + 1
        if not removed:
            return doc
        log.debug("redacted %d subject(s) from a %s document",
                  removed, self.collection)
        # A shallow copy, and only on the path that actually removes
        # something. The caller may be holding this dict -- ``reachable()``
        # is handed documents from somewhere else -- and mutating it would
        # make refusal a side effect on somebody else's data.
        return {**doc, path: kept, _REDACTED: removed}

    def _unnamed(self, element: dict) -> str | None:
        """Refuse an embedded subject that cannot be addressed.

        Asked *before* the rules, and that order is the point: a subject with
        no name cannot be the target of an erasure request, cannot be named
        in a lineage, and cannot be attested to in a receipt. Whether it
        happens to be expired today is a question about a thing this
        deployment has no way to talk about tomorrow.

        This is the mechanism that keeps ``subject_key`` from being a
        convention. A convention is a rule somebody has to remember at every
        write site; this is a rule enforced at the one place every read
        passes through, so a writer that forgets the key finds out on the
        next read instead of on the day somebody tries to erase one.

        Fails closed, like an unreadable deadline. The alternative -- admit
        the anonymous element and hope -- is how a subject nobody can name
        ends up in a prompt after its erasure request was filed and applied
        to everything that *could* be named.
        """
        key = self.spec.subject_key
        if not key:
            return None
        value = element.get(key)
        if value is None or (isinstance(value, str) and not value.strip()):
            return UNNAMED
        return None

    @staticmethod
    def _harvest(docs: list[dict]) -> tuple[list[dict], int]:
        """Take the redaction marks off, and total them. The only place.

        ``_redact`` has to return one value and has to say two things -- the
        document, and how much of it is gone -- so it stamps a private key
        and this takes it off again. One strip point rather than one per read
        path, because a sentinel that escapes to a caller is a worse bug than
        the one it was added to fix, and
        ``tests/test_a_subject_is_not_always_a_document.py`` fails the build
        if it ever does.
        """
        total = 0
        out: list[dict] = []
        for doc in docs:
            n = doc.get(_REDACTED)
            if n is None:
                out.append(doc)
                continue
            total += n
            out.append({k: v for k, v in doc.items() if k != _REDACTED})
        return out, total

    def reachable(self, docs: Iterable[dict], *,
                  when: datetime | None = None) -> list[dict]:
        """Filter documents that arrived from somewhere else.

        This is the search path's entry point: ``$vectorSearch`` and
        ``$rankFusion`` hits have not been through ``_query`` and never will
        be, so they are admitted one at a time, here.

        A budget applies: this is a set being assembled for a prompt, so a
        fresh tab spans the whole list and cuts it at the token ceiling.
        """
        if self.tenant and self._scope is _UNSET:
            # The hole this guard closes. `find({})` has always raised here;
            # `reachable(batch)` returned every tenant's documents, because
            # the tenant was a query-half rule and this path has no query.
            # A search hit is exactly such a batch, so on a scoped collection
            # this was the one read path where the boundary did not hold.
            #
            # `find`/`find_one`/`search` bind the scope from the tenant their
            # filters already require. This path has no filters to read, so
            # the caller names it: `for_tenant(t).reachable(batch)`.
            raise ScopeRequired(
                self.collection, self.tenant,
                hint=(f"reachable() has no filters to read it from: bind the "
                      f"tenant with for_tenant(<{self.tenant}>).reachable(...) "
                      f"-- a batch of search hits never went through a query, "
                      f"so this is the only place the tenant can be checked"))
        self._begin_read()
        tab = self._open_tab()
        kept = [d for d in docs
                if self._admit(d, when=when, tab=tab) is not None]
        # Redactions are counted into ``receipts()`` by ``_admit`` already;
        # this path returns a bare list, so the per-read number has nowhere
        # to go and the mark is simply taken off.
        cleaned, _ = self._harvest(kept)
        return cleaned

    def _classify(self, docs: list[dict], *, when: datetime | None = None,
                  max_kept: int | None = None
                  ) -> tuple[list[dict], dict[str, int], Tabs | None, int]:
        """Admit a candidate set without recording anything yet.

        Returns the tab as well, so ``saturate`` can read how much budget was
        spent and whether it was exhausted. A fresh tab per call is deliberate:
        each refill round re-classifies the whole superset from the top, so a
        tab shared across rounds would double-charge the documents it re-sees.
        The loop stops on the round that exhausts, so per-round tabs are exact.

        ``max_kept`` matters when search over-fetches. Classification stops
        once the returned prefix is full, so a budget is charged for what the
        page selects -- not for extra candidates fetched only as refill
        insurance. After a budget overflow it keeps classifying the fetched
        tail without charging it: the latched tab refuses every later fit, but
        pure rules still run first so reason accounting is identical to
        ``find`` and ``reachable``.
        """
        tab = self._open_tab()
        tally: dict[str, int] = {}
        kept: list[dict] = []
        for doc in docs:
            admitted = self._admit(doc, when=when, tally=tally, tab=tab)
            if admitted is not None:
                kept.append(admitted)
                if max_kept is not None and len(kept) >= max_kept:
                    break
        kept, redacted = self._harvest(kept)
        return kept, tally, tab, redacted
