"""A refusal reaches what was made out of the fact, on the wire.

The read path already refuses any document carrying the mark. What was
missing at the boundary is that the mark did not *travel*: a client deletes
the source, the proxy turns that into a revocation, and the summary an agent
wrote out of it keeps scoring well forever. The erasure request is honoured
against the document somebody named and defeated by the paragraph nobody
did, which is the failure this package exists to prevent arriving through
the one door it left open.

The mechanism is transitive closure at *write* time: a child's lineage is
its parent's lineage plus the parent, so a grandchild already names the
grandparent and one ``$in`` reaches the whole subtree at any depth,
instead of a recursive walk. Given the ids a delete matched, everything
downstream of them is ``{lineage: {"$in": ids}}``. Derivation is a DAG
that only grows forwards, so the closure cannot go stale.

What the boundary cannot have is a transaction. A cascade is a
multi-document write derived from a read, which this proxy does nowhere
else, and the client's own session is not ours to open one on -- doing so
would change what that client's subsequent reads see, which is a far larger
surprise than the one being fixed.

So the order is chosen instead, and it is chosen to fail in the direction
this codebase already prefers:

    1. resolve the ids the client's filter matches
    2. mark the descendants
    3. let the rewritten parent revocation go

A crash between 2 and 3 leaves the source still reachable and the
derivations already gone. That is a *visible* half-erasure -- the caller
re-runs the delete, which is idempotent, and the mark is written again to
the same value. The reverse order fails the other way: the source refused,
the summary of it still answering prompts, and nothing anywhere saying so.
One of those two failures is recoverable by retrying and the other is the
bug the whole package is about.

Step 1 is not merely an optimisation. ``deleteOne`` asks the server to pick
*one* of the documents a filter matches and does not say which, so a
boundary that cascaded from its own second look at the filter would mark the
children of a document the server then did not revoke. Resolving the ids
once and pinning both halves of the write to them removes the ambiguity
rather than narrowing it.
"""

from __future__ import annotations

import logging
from typing import Any, Mapping

log = logging.getLogger("voyd.cascade")


class Cascade:
    """The proxy's own connection, used only to make a refusal travel.

    Separate from the client's, and deliberately so. The cascade is the
    boundary's write, not the caller's: it is issued because a policy file
    said this collection tracks derivation, at a moment the caller did not
    choose, against documents the caller never named and in most cases
    cannot see. Borrowing their session to do it would put work they did
    not ask for inside a transaction they might be running, and would make
    the proxy's guarantee depend on the client's connection staying up for
    the length of it.
    """

    def __init__(self, uri: str, *, verbose: bool = False) -> None:
        self.uri = uri
        self.verbose = verbose
        self._client: Any = None
        # Counted separately from `Guard.revoked`, which tallies what the
        # *caller* asked to forget. "3 facts revoked" and "3 facts revoked
        # and 41 things made out of them went too" are different sentences
        # and an auditor needs the second one.
        self.cascaded = 0

    @staticmethod
    def wanted(guards: Mapping[str, Any]) -> bool:
        """Is any guarded collection declaring lineage at all?

        Asked before the client is dialled, because the overwhelmingly
        common policy file declares no ``lineage_field`` anywhere and has
        no business paying for a second connection pool per worker.
        """
        return any(g.spec.lineage_field for g in guards.values())

    async def open(self) -> None:
        from pymongo import AsyncMongoClient

        self._client = AsyncMongoClient(self.uri)
        log.info("cascade connection open; a revocation will reach what was "
                 "derived from the fact")

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.close()
            self._client = None

    # ---- the two halves ------------------------------------------------

    async def resolve(self, database: str, guard: Any, query: Mapping,
                      *, one: bool, sort: Any = None) -> list:
        """Which documents the client's filter actually names.

        ``one`` mirrors ``deleteOne``: the server would pick one and not
        say which, so this picks first and both halves of the write are
        pinned to the answer. ``sort`` is carried through from
        ``findAndModify``, where the caller *did* say which.
        """
        if self._client is None:
            return []
        cur = self._client[database][guard.collection].find(query, {"_id": 1})
        if sort:
            cur = cur.sort(list(sort.items()) if isinstance(sort, Mapping)
                           else sort)
        if one:
            cur = cur.limit(1)
        return [d["_id"] async for d in cur]

    async def mark_descendants(self, database: str, guard: Any, ids: list,
                               pipeline: list, filters: Mapping) -> int:
        """Everything downstream of ``ids``, at any depth, in one update.

        The tenant is carried across from the caller's own filter rather
        than dropped. A descendant does not match the caller's *filter* --
        that is the entire point of reaching it -- but it must still match
        the **boundary**. Without this, a row in another namespace naming
        one of these ids would be marked by a caller who cannot read it,
        which is a cross-tenant write dressed up as an erasure.

        The caller-aware rules are *not* rebuilt here, and cannot be:
        they decide by who is asking, per document, and no query expresses
        them. So a cascade can reach a descendant the caller could not
        have read -- in the direction of refusing more, which is the
        direction an erasure should err in.
        """
        field = guard.spec.lineage_field
        if self._client is None or not (field and ids and pipeline):
            return 0
        reach: dict = {field: {"$in": ids}}
        tenant = guard.spec.tenant
        if tenant:
            scope = filters.get(tenant) if isinstance(filters, Mapping) else None
            if scope is None:
                # A tenanted collection whose delete did not pin the tenant
                # is already refused upstream by the pushdown rules. Reaching
                # here anyway means those changed, so this refuses to guess
                # rather than cascading across every namespace at once.
                log.warning(
                    "%s declares tenant %r and this delete did not pin it; "
                    "not cascading", guard.collection, tenant)
                return 0
            reach[tenant] = scope
        result = await self._client[database][guard.collection].update_many(
            reach, pipeline)
        n = int(result.modified_count)
        self.cascaded += n
        if n and self.verbose:
            print(f"  voyd: {guard.collection}: the refusal travelled to {n} "
                  f"document(s) made out of {len(ids)}; they were marked "
                  f"first, so a crash leaves the source reachable rather "
                  f"than its summaries", flush=True)
        return n

    # ---- the write-side half -------------------------------------------

    async def parentage(self, database: str, guard: Any, parents: list,
                        document: Mapping) -> tuple[list, list, list]:
        """What a claimed derivation is really made out of.

        Returns ``(closure, deadlines, broken)``:

        ``closure`` is the *transitive* ancestry -- the named parents plus
        everything they already name. Closing it here, at write time, is
        the whole reason a cascade is one ``$in`` at any depth instead of
        a recursive walk, and it cannot go stale: derivation is a DAG that
        only grows forwards, so a document's ancestry is fixed the moment
        it is written. A boundary that stored only the named parent would
        make the cascade correct for children and silently wrong for
        grandchildren, which is worse than not having it.

        ``deadlines`` are the parents' own, so a child can inherit the
        earliest. A summary of a fact that expires on Tuesday has no
        business outliving it, and the earliest is the only choice that
        cannot extend anything.

        ``broken`` names the parents that may not be reached at all --
        missing, out of scope, or already refused. That refuses the write
        rather than marking it, because the only ways to get here are a
        race and a bug: something read a document it should not have been
        given, or is writing from a cache that never checked. Writing the
        child and marking it in the same breath would paper over both.

        The refusal test is the guard's own per-document rules, not a
        query, so an insert is judged by exactly the predicate a read is.
        Two spellings of "is this refused" would be free to disagree.
        """
        if self._client is None or not parents:
            return [], [], []
        field = guard.spec.lineage_field
        at = guard.spec.at_field
        query: dict = {"_id": {"$in": parents}}
        tenant = guard.spec.tenant
        if tenant:
            scope = document.get(tenant)
            if scope is None:
                # A derived document that does not carry the tenant would
                # be written unreadable anyway -- every read path requires
                # it -- so saying so here is strictly kinder than letting
                # the insert succeed into a hole.
                return [], [], [f"<no {tenant} on the document>"]
            query[tenant] = scope
        found = [d async for d in
                 self._client[database][guard.collection].find(query)]
        by_id = {str(d["_id"]): d for d in found}
        kept = {str(d["_id"]) for d in guard.handle.reachable(found)}
        broken = sorted(set(map(str, parents)) - kept)
        closure = sorted({*parents, *(a for d in found
                                      for a in (d.get(field) or []))}, key=str)
        deadlines = [d[at] for d in by_id.values()
                     if hasattr(d.get(at), "timestamp")]
        return closure, deadlines, broken
