"""Reads that decrypt, for a collection whose fields are sealed.

``find`` and ``find_one`` get both halves of the guarantee: the rule
pushed into the collection query, *and* the per-document check on the way
out. A read that only pushed down would be narrower than the guarantee,
because a pushed-down clause cannot ask every question a rule can.
``match`` hands the filter to an aggregation, which is the one read shape
this handle cannot wrap.

These exist for the path the proxy cannot serve: a sealed collection is
read through a client that decrypts, and decryption happens in a process
holding the keys. Everything else reads through the boundary.
"""

from __future__ import annotations

import logging
from typing import Any, TYPE_CHECKING

from .receipts import Page
from ..time import now

log = logging.getLogger("engine.admission")


# What this mixin assumes ``Admission`` already provides. Declared so a
# type checker reads the composition contract that handle.py states in
# prose; see composition.py. A read also has to know what is sealed, hence ``SealingState``.
#
# Runtime base is ``object``: the protocols are never imported when the
# module actually runs, so ``Admission``'s MRO is unchanged.
if TYPE_CHECKING:
    from .composition import CoreState, SealingState

    class _Composed(CoreState, SealingState):
        pass
else:
    _Composed = object


class ReadPath(_Composed):
    """Every way out of this handle, and all of them end at ``_admit``.

    There is deliberately no unfiltered read here. ``including_refused()``
    on the core is the named escape hatch, and it is a different object so
    that a review can grep for it.
    """

    # ---- reads: refusal is the default ---------------------------------

    async def find_one(self, filters: dict | None = None, *args, **kw):
        self = self._scoped_for(filters)      # see find(), same reason
        self._begin_read()
        doc = await self.db[self.collection].find_one(self._query(filters),
                                                      *args, **kw)
        # A singleton is still prompt content. It gets its own tab rather than
        # bypassing a Budget merely because no page object is involved.
        tab = self.open_tab()
        admitted = self._admit(doc, tab=tab)
        if tab is not None and tab.exhausted:
            log.warning(
                "find_one on %s refused by budget: %s spent of %s",
                self.collection, tab.spent, tab.limit)
        if admitted is None:
            return None
        if not self.seals:
            # One document, so the redaction count has nowhere to ride; the
            # reasons are already in ``receipts()``. Stripping here is not
            # optional -- a private mark on a returned document is a field a
            # caller would persist back.
            cleaned, _ = self._harvest([admitted])
            return cleaned[0]
        kept, tally = await self._unsealed([admitted])
        self.receipts_log.record_many(tally)
        if not kept:
            return None
        cleaned, _ = self._harvest(kept)
        return cleaned[0]

    async def find(self, filters: dict | None = None, *args,
                   limit: int = 0, sort: Any = None, **kw) -> Page:
        # One value decides both halves. The tenant is already required in
        # these filters; binding it here means the per-document check on the
        # way out tests the same thing the query pushed down, rather than
        # trusting that the query did its job -- which is the whole of step 4.
        self = self._scoped_for(filters)
        self._begin_read()
        # Frozen once, threaded into every admission below, and stamped on the
        # page so a use recorded from this find commits to one instant. It is
        # a ``Page`` (a ``list`` subclass) for that reason -- callers that
        # treat it as a list are unaffected.
        evaluated_at = now()
        tab = self.open_tab()
        if tab is not None and sort is None:
            raise ValueError(
                f"{self.collection}: a cumulative rule needs a deterministic "
                "find order, because 'the first 100 tokens' is only a fact "
                "about an ordered read. Pass sort=(field, direction)")
        cur = self.db[self.collection].find(self._query(filters), *args, **kw)
        if sort is not None:
            cur = cur.sort(*sort) if isinstance(sort, tuple) else cur.sort(sort)
        # A budget applies here too -- special-casing which read enforces
        # a rule is how two enforcement points drift. A budget-truncated
        # page is short, and short is indistinguishable from "that is all
        # there was" unless the page says so, which is what ``spent`` and
        # ``refused`` below are for.
        admitted: list[dict] = []
        async for doc in cur:
            kept = self._admit(doc, when=evaluated_at, tab=tab)
            if kept is not None:
                admitted.append(kept)
                # ``limit`` is a limit on the answer, not on raw candidates.
                # Applying it in MongoDB first lets one refused candidate
                # turn a live next row into an empty page.
                if limit and len(admitted) >= limit:
                    break
            if tab is not None and tab.exhausted:
                break
        if tab is not None and tab.exhausted:
            log.warning(
                "find on %s truncated by budget: %d admitted, ~%s spent of %s",
                self.collection, len(admitted), tab.spent, tab.limit)
        if self.seals:
            # Admitted first, then decrypted. A revoked or expired document is
            # refused by its mark without anybody paying for a key lookup, and
            # only the survivors reach the KMS -- which matters because the
            # refusal rate on a live scope is most of the page.
            admitted, tally = await self._unsealed(admitted)
            self.receipts_log.record_many(tally)
        # Redactions are taken off here for the same reason ``saturate``
        # takes them off: a document that came back shorter than it is on
        # disk must not be able to look like a whole one. The reasons are
        # already in ``receipts()`` -- ``_admit`` recorded them as it went,
        # because this path passes no tally -- so this only rescues the
        # count that has to ride on the page.
        admitted, redacted = self._harvest(admitted)
        # Carried on the page rather than left in the log. A caller holding
        # a short page has to be able to tell "the budget stopped it" from
        # "there were only two", and a WARNING in somebody's aggregator is
        # not an answer the caller can act on.
        return Page(admitted, evaluated_at=evaluated_at, redacted=redacted,
                    policy_revision=self.spec.policy_revision,
                    spent=tab.spent if tab is not None else 0,
                    refused=dict(self.receipts_log.refused),
                    snapshot_complete=True)

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
        if self._break_glass:
            raise RuntimeError(
                f"{self.collection}: including_refused().match() cannot be "
                "gated per pipeline execution; use find/search/reachable so "
                "every break-glass read is re-authorised and counted")
        self._begin_read()
        return self._query(filters)
