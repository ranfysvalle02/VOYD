"""What a fact was made out of, so a refusal travels to it.

Refusal stops a *document* reaching a prompt. It says nothing about the
paragraph an agent wrote after reading it -- and that paragraph is written
back into the same collection and keeps scoring well forever.

The fix costs no new read-path rule, which is the interesting part: the mark
already refuses any document carrying it, so what was missing is that the
mark did not travel. Transitive closure at write time makes propagation one
``$in`` at any depth instead of a recursive walk.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Iterable

from ..authority import DERIVE
from ..errors import DerivationBroken, ScopeRequired, UnknownReason
from .reasons import NOT_CLEARED
from .spec import why_refused

log = logging.getLogger("engine.admission")


class Lineage:
    """Derivation, so that a refusal reaches what was made out of the fact.

    Opt-in per collection: a store of source facts has no lineage and
    should not pay a field or an index for one.
    """

    # ---- what a fact was made out of -----------------------------------
    #
    # Refusal stops a *document* reaching a prompt. It says nothing about
    # the paragraph an agent wrote after reading it, and that paragraph is
    # written back into the same collection and keeps scoring well forever.
    # So the erasure request is honoured against the source and defeated by
    # the summary, which is the failure the whole package exists to prevent,
    # arriving through the one door it left open.
    #
    # The fix costs no new read-path rule, and that is the interesting part.
    # ``revoked()`` already refuses any document carrying the mark. What was
    # missing is that the mark did not *travel*. So:
    #
    #   derive()   writes a document with a transitively-closed ``lineage``,
    #              and refuses to write it at all if a parent is already
    #              refused -- you cannot legitimately derive a new fact from
    #              one that may not reach a prompt.
    #   impose()   marks the matched documents *and* everything carrying one
    #              of their ids in ``lineage``, in one extra query.
    #   lift()     un-marks the same set, so a released hold releases the
    #              work that was held with it.
    #
    # Transitive closure at write time is what makes propagation O(1)
    # queries instead of a recursive walk: a child's lineage is its parent's
    # lineage plus the parent, so a grandchild already names the
    # grandparent and one ``$in`` reaches the whole subtree at any depth.
    # Derivation is a DAG that only ever grows forwards, so the closure
    # cannot go stale -- a document's ancestry is fixed the moment it is
    # written.

    async def derive(self, documents, *, parents: Iterable,
                     when: datetime | None = None) -> list:
        """Write documents that were made out of other documents.

        ``parents`` are ids in this collection. Each new document gets a
        ``lineage`` naming every ancestor, transitively, and inherits the
        *earliest* deadline among its parents -- a summary of a fact that
        expires on Tuesday has no business outliving it, and picking the
        earliest is the only choice that cannot extend anything.

        **It refuses rather than writes when a parent is already refused.**
        Not because the write is unsafe in itself, but because the only
        ways to reach here are a race and a bug: something read a document
        it should not have been given, or is deriving from a handle that
        never checked. Writing the child and marking it in the same breath
        would paper over both. ``CallerRequired`` is the family
        resemblance -- every available answer is wrong, so this picks none.

        Returns the inserted ids.
        """
        field = self._require_lineage("derive")
        docs = [documents] if isinstance(documents, dict) else list(documents)
        if not docs:
            return []
        parents = list(parents)
        if not parents:
            raise ValueError(
                f"{self.collection}: derive() needs at least one parent. A "
                f"document made out of nothing is an ordinary insert")

        self._require_caller()
        self._authorise(DERIVE)
        scope = self._scope_of(docs)
        found = [d async for d in self.db[self.collection].find(
            self._query_by_id(parents, scope))]
        if len(found) != len(set(parents)):
            missing = set(parents) - {d["_id"] for d in found}
            raise DerivationBroken(self.collection, sorted(map(str, missing)),
                                   "not in this scope")
        audit = self._unfiltered()
        for parent in found:
            reason = why_refused(parent, self.spec, when=when,
                                 caller=self._caller)
            if reason is not None:
                raise DerivationBroken(
                    self.collection, [str(parent["_id"])], reason)
            if audit._admit(parent, when=when) is None:
                # Refused by an *unbypassable* rule: the caller may not read
                # this parent, so they may not launder it into a new
                # document either.
                raise DerivationBroken(
                    self.collection, [str(parent["_id"])], NOT_CLEARED)

        lineage = sorted({*parents, *(a for p in found
                                      for a in (p.get(field) or []))},
                         key=str)
        deadlines = [p[self.spec.at_field] for p in found
                     if isinstance(p.get(self.spec.at_field), datetime)]
        prepared = []
        for doc in docs:
            row = dict(doc)
            row[field] = lineage
            if deadlines:
                # Inherit the earliest, and never overwrite a shorter one
                # the caller set deliberately.
                own = row.get(self.spec.at_field)
                soonest = min(deadlines)
                row[self.spec.at_field] = (
                    min(own, soonest) if isinstance(own, datetime) else soonest)
            prepared.append(row)

        result = await self.db[self.collection].insert_many(prepared)
        log.info("derived %d document(s) in %s from %d parent(s), lineage %d "
                 "deep", len(prepared), self.collection, len(parents),
                 len(lineage))
        return list(result.inserted_ids)

    def _require_lineage(self, verb: str) -> str:
        field = self.spec.lineage_field
        if not field:
            raise UnknownReason(
                self.collection, verb,
                ("declare lineage_field on the model to track derivation",))
        return field

    def _scope_of(self, docs: list) -> dict:
        """Which tenant these new documents belong to, taken from them.

        The handle knows the tenant *field*; only the documents know the
        value. Reading it off them rather than adding a parameter also
        enforces the thing that would otherwise be a convention: a derived
        document that did not carry the tenant would be written
        unreadable, since every read path requires it.

        All of them must agree. A batch spanning two tenants has no single
        correct parent lookup, and picking the first document's answer
        would silently let one tenant's parents authorise another's child.
        """
        if not self.tenant:
            return {}
        values = {d.get(self.tenant) for d in docs}
        if len(values) != 1 or None in values:
            raise ScopeRequired(self.collection, self.tenant)
        return {self.tenant: values.pop()}

    def _query_by_id(self, ids: list, scope: dict) -> dict:
        """Ids, but still inside the tenant and still refusing nothing.

        Built through the audit query on purpose: ``derive`` has to *see* a
        refused parent in order to reject it, and a query that hid one would
        turn "this parent may not be used" into "this parent does not
        exist" -- two very different things to report.
        """
        return self._unfiltered()._query(
            {**scope, "_id": {"$in": ids}})

    async def _descendants(self, query: dict) -> tuple[list, int]:
        """Everything downstream of whatever this query matched.

        One extra ``find`` for the ids and one ``$in`` for the subtree, at
        any depth, because ``lineage`` is transitively closed when it is
        written. Returns the matched ids and how many descendants carry
        them, so the chain can record the two counts separately -- "you
        asked to erase 2 facts and 7 things made out of them went too" is
        the sentence an auditor needs, and a single total cannot say it.
        """
        field = self.spec.lineage_field
        # The ids are needed by two callers for two reasons, and the first
        # version resolved them only for the second -- so on the default
        # collection, which tracks no lineage, the perimeter was handed an
        # empty list and every sink was told that *something* had been
        # erased without being told what. A propagation that names nothing
        # is worse than none: it produces acknowledgements.
        if not (field or self.perimeter):
            return [], 0
        ids = [d["_id"] async for d in
               self.db[self.collection].find(query, {"_id": 1})]
        if not (ids and field):
            return ids, 0
        n = await self.db[self.collection].count_documents(
            {field: {"$in": ids}})
        return ids, n

    def _with_descendants(self, query: dict, filters: dict | None,
                          ids: list) -> dict:
        """The matched documents, plus everything downstream of them.

        The ``$or`` replaces the caller's *filter* -- a descendant does not
        match it, which is the whole point -- but it must not replace the
        **boundary**. The first version of this returned the bare ``$or``
        and propagation walked straight out of the tenant: a row in another
        namespace naming one of these ids would have been marked, by a
        caller who cannot even read it.

        So the guard clauses are rebuilt and kept: the tenant, and every
        unbypassable rule, which is how clearance survives the trip down
        the edge. Only the bypassable ones drop, because a descendant that
        is already expired or already held is exactly what this is here to
        reach.
        """
        field = self.spec.lineage_field
        if not (field and ids):
            return query
        scope = {self.tenant: (filters or {}).get(self.tenant)} \
            if self.tenant else {}
        guard = self._unfiltered()._query(scope)
        reach = {"$or": [{"_id": {"$in": ids}}, {field: {"$in": ids}}]}
        guard["$and"] = [*guard.pop("$and", []), reach]
        return guard
