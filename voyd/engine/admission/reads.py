"""Reads, where refusal is the default and there is no unfiltered door.

Every method here ends at ``_admit``. ``find``/``find_one``/``count`` also get
the cheap half -- the rule pushed into the collection query -- but a
``$vectorSearch`` hit never passes through that, which is why ``search`` and
``saturate`` are on the handle at all rather than left to each caller.

This module is the *only* one in the package permitted to call the engine's
search primitive, and ``tests/test_no_module_reaches_past_the_handle.py``
enforces that by name. Before the split that exemption covered a
2,393-line file; now it covers the 280 lines that legitimately need it.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from .reasons import REACHABLE, REFUSED, UNKNOWN
from .receipts import Page
from .spec import why_refused
from ..time import aware

log = logging.getLogger("engine.admission")


class ReadPath:
    """Every way out of this handle, and all of them end at ``_admit``.

    There is deliberately no unfiltered read here. ``including_refused()``
    on the core is the named escape hatch, and it is a different object so
    that a review can grep for it.
    """

    async def search(self, vector, *, text: str | None = None,
                     limit: int = 5, filters: dict | None = None,
                     when: datetime | None = None,
                     rounds: int = 3) -> Page:
        """Search this collection and admit the hits. The whole read, one call.

        This exists because the engine's own ``search()`` is a **primitive,
        not a read path**: it returns what the index ranked. Deadlines are
        deliberately not pushed into the vector index -- the measurements are
        in ``search.py`` -- so a hit arriving from ``$vectorSearch`` has never
        been filtered by anything, and admitting it is the caller's job.

        Which is precisely the shape this module was written to abolish. The
        original sin was six read paths that each had to remember a deadline
        filter; replacing it with two read paths that each had to remember to
        wrap a search is the same bug with a smaller number. Both of them did
        remember, and both wrote out their own fetch-budget guess, and the
        two guesses were the same wrong constant -- which is what a
        convention looks like just before it fails a third time.

        So the handle owns the query as well as the rule. There is now one
        named way to search a collection that refuses things, and reaching
        past it means naming the primitive on the engine, which a review can
        grep for and CI asserts no module in this package does.
        """
        if self.engine is None:
            raise RuntimeError(
                f"this {self.collection} handle was built without an engine, "
                "so it cannot search. Build it with engine.admission(...) / "
                "model(...).forgettable(), or call saturate() with your own "
                "fetch")

        async def fetch(n: int) -> list[dict]:
            return await self.engine.search(self.collection, vector,
                                            text=text, limit=n,
                                            filters=filters)

        return await self.saturate(fetch, limit=limit, when=when,
                                   rounds=rounds)

    async def saturate(self, fetch, *, limit: int,
                       when: datetime | None = None,
                       rounds: int = 3) -> Page:
        """Fill a page of ``limit`` reachable documents, refusal notwithstanding.

        Enforcing the deadline on read -- rather than in the vector index,
        for the reasons measured in ``search.py`` -- means forgotten
        documents are fetched and then dropped. They spend the fetch budget.
        Both read paths in this package knew that and both bought the same
        fixed insurance: ask for ``limit * 2``, admit, slice. Which is a
        guess, and a guess that fails in the direction this repository
        otherwise refuses to fail in:

            40 expired rows outranking 6 live ones, limit=5  ->  0 hits

        Zero. Not "fewer". The live documents were indexed, queryable and
        present, and the caller was handed an empty list that is
        indistinguishable from "nothing matched" -- the same
        fewer-rows-instead-of-an-error shape that this codebase blocks
        startup over and refuses to let a rebuilding index produce. Refusal
        is supposed to cost the *forgotten* document its place, not the page.

        So the budget is not a constant. ``fetch(n)`` is asked for candidates
        in ranking order; each round re-asks for more and re-admits the
        superset, until the page is full or the candidates run out. The next
        size is derived from the refusal rate just observed rather than
        doubled blindly -- at a 90% refusal rate, doubling takes four rounds
        to find what one round of arithmetic gets in one.

        Three things end the loop, and all three are honest:

        1. the page is full;
        2. ``fetch`` returned fewer rows than asked for -- there is nothing
           further down the ranking. This also covers the search tier's own
           ceiling (``MAX_LIMIT``): a request past it comes back short, which
           is the truth from where this sits, since no more are reachable;
        3. ``rounds`` is spent. A scope where *everything* is forgotten must
           not turn one query into an unbounded sequence of them.

        Only case 3 sets ``page.starved``, and the distinction is the
        interesting part. Case 2 can also leave the page short, and that
        short page is *complete*: the candidates are exhausted, so nothing is
        being withheld and there is nothing to go back for, however many
        refusals it took to establish. Case 3 is the opposite -- candidates
        remained and this page could not reach them -- and it is the only
        state a caller needs to treat as partial.

        Case 2 does swallow one thing worth naming: a request past the search
        tier's ``MAX_LIMIT`` comes back clamped, which is indistinguishable
        here from "that is all there is". It is reported as complete because
        from this layer it is -- no further document is reachable by any
        query this engine will issue. A deployment that needs to see past
        that ceiling needs a bigger ceiling, not a different flag.
        """
        want = max(1, int(limit))
        rounds = max(1, int(rounds))
        asked = want * 2          # the cheap first guess, unchanged
        kept: list[dict] = []
        tally: dict[str, int] = {}
        examined = 0
        exhausted = False

        for attempt in range(rounds):
            candidates = list(await fetch(asked))
            examined = len(candidates)
            kept, tally = self._classify(candidates, when=when)
            # Fewer rows than asked for: there is nothing further down the
            # ranking, so whatever the page holds is the whole answer.
            exhausted = examined < asked
            if len(kept) >= want or exhausted:
                break
            if attempt + 1 < rounds:
                asked = self._next_ask(asked, want, kept=len(kept),
                                       examined=examined)

        hits = kept[:want]
        if self.seals:
            # Decrypted after the page is chosen, so a document whose key is
            # gone costs one refusal rather than a wasted round of refill --
            # and it is counted in the same tally, under `unrecoverable`,
            # beside the deadline and the revocation.
            hits, sealed_tally = await self._unsealed(hits)
            for reason, n in sealed_tally.items():
                tally[reason] = tally.get(reason, 0) + n
        self.receipts_log.record_many(tally)
        page = Page(hits, refused=tally, examined=examined,
                    starved=len(kept) < want and not exhausted)
        if page.starved:
            # Worth a line at WARNING: it means a caller was told less than
            # the truth, which no amount of correct filtering makes fine. And
            # only here -- a short-but-complete page used to log this too,
            # which is how a useful warning becomes one people filter out.
            log.warning(
                "page starved on %s: wanted %d, admitted %d of %d examined, "
                "refused %s", self.collection, want, len(kept), examined, tally)
        return page

    @staticmethod
    def _next_ask(asked: int, want: int, *, kept: int, examined: int) -> int:
        """How many candidates to ask for next, from the rate just measured.

        The observed hit rate is the best available estimate of the one
        further down the ranking, so aim at the size that *would* have filled
        the page, with headroom. A round that admitted nothing has no rate to
        extrapolate from, so it falls back to growing hard -- that case is
        either a wholly forgotten scope (ends on ``rounds``) or a deep run of
        expired rows (ends when it clears them).
        """
        if kept == 0:
            return asked * 4
        needed = want / (kept / max(examined, 1))
        # Never shrink, and always ask for strictly more than last time, or
        # the loop re-issues an identical query and calls it progress.
        return max(asked + want, int(needed * 1.5) + 1)

    # ---- reads: refusal is the default ---------------------------------

    async def find_one(self, filters: dict | None = None, *args, **kw):
        doc = await self.db[self.collection].find_one(self._query(filters),
                                                      *args, **kw)
        admitted = self._admit(doc)
        if admitted is None or not self.seals:
            return admitted
        kept, tally = await self._unsealed([admitted])
        self.receipts_log.record_many(tally)
        return kept[0] if kept else None

    async def find(self, filters: dict | None = None, *args,
                   limit: int = 0, sort: Any = None, **kw) -> list[dict]:
        cur = self.db[self.collection].find(self._query(filters), *args, **kw)
        if sort is not None:
            cur = cur.sort(*sort) if isinstance(sort, tuple) else cur.sort(sort)
        if limit:
            cur = cur.limit(limit)
        admitted = [d async for d in cur if self._admit(d) is not None]
        if not self.seals:
            return admitted
        # Admitted first, then decrypted. A revoked or expired document is
        # refused by its mark without anybody paying for a key lookup, and
        # only the survivors reach the KMS -- which matters because the
        # refusal rate on a live scope is most of the page.
        kept, tally = await self._unsealed(admitted)
        self.receipts_log.record_many(tally)
        return kept

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

    # ---- what was reachable then ---------------------------------------

    async def reachability_at(self, filters: dict,
                              when: datetime) -> tuple[str, str]:
        """Was this document reachable at ``when``? ``(verdict, why)``.

        Three answers, and the third is the one the API exists to make
        unmissable:

        ``reachable``    the row is here and no rule refused it then.
        ``refused``      the row is here and something did. ``why`` names it.
        ``unknown``      **the row is gone.** Erased on the deadline, by
                         the reaper, weeks ago. Nothing survives from
                         which to answer.

        Returning ``refused`` for a row that has been erased is the
        confident wrong answer this whole codebase exists to eliminate --
        it would let a deployment clear itself of having served a fact by
        pointing at the absence of the evidence. So the verdict is a
        string rather than a bool, because a bool has nowhere to put
        ``unknown`` and every caller would default it to the flattering
        one.
        """
        when = aware(when)
        doc = await self.including_refused().find_one(filters)
        if doc is None:
            return UNKNOWN, ("no row survives, so nothing here can say. It "
                             "may have been reachable and later erased")
        reason = why_refused(doc, self.spec, when=when, caller=self._caller)
        return (REFUSED, reason) if reason else (REACHABLE, "")
