"""A collection with a deadline, hybrid retrieval, and no unfiltered read.

This is a trait, not a product. It composes searchable + expiring +
forgettable into one handle because that is a common shape: a scope whose
facts must not outlive a deadline, recalled by meaning and by token.
Admission is the guarantee. This trait is one way to hold it.

The default outcome of bolting a vector index onto a retrieval path is a
corpus that only grows. Yesterday's decision, the retracted fact and the
stale config all keep scoring well forever, so retrieval quality decays
while the bill rises. The usual fixes are a cron job nobody maintains and
a relevance hack nobody trusts.

Two primitives already in this engine compose into the actual answer:

    hybrid retrieval  +  TTL  =  recall with decay

A document carries its own expiry, so the database forgets on schedule and
the vector goes with the row -- no orphaned embeddings, and no reaper
process of your own to write (MongoDB's TTL monitor is the reaper).
And because a null deadline means "keep forever" (the same property that
lets one collection hold both ephemeral and permanent records), **pinning
is the absence of a TTL** rather than a second storage path.

Deliberately *not* included: an embedding provider. You pass vectors in.
Which model to use, when to re-embed, and what to spend are decisions that
belong to the application, and a trait that picks your model for you is a
cage wearing a convenience label.
"""

from __future__ import annotations

# `...` is the "caller said nothing" sentinel for `ttl`, which is
# distinct from `ttl=None` meaning "keep this forever". Naming its
# type is what lets a checker tell those two apart.
from types import EllipsisType

import logging
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from .expiry import ExpirySpec
from .search import SearchSpec
from .time import deadline, now

log = logging.getLogger("engine.memory")


@dataclass(frozen=True)
class MemorySpec:
    """A declared decaying collection.

    ``default_ttl`` is what a working scope decays after. ``None``
    means documents are permanent unless a caller asks otherwise -- the safer
    default for a knowledge base, the wrong one for a scratchpad.
    """

    collection: str = "memories"
    scope_field: str = "scope"        # agent id, session id, tenant -- your call
    text_field: str = "text"
    vector_path: str = "embedding"
    dimensions: int = 1024
    default_ttl: timedelta | None = None
    # Scopes are usually strings -- an agent id, a session id, a user id.
    # Set "objectId" if yours are ObjectIds.
    scope_type: str = "token"

    def search_spec(self) -> SearchSpec:
        return SearchSpec(
            collection=self.collection,
            vector_path=self.vector_path,
            dimensions=self.dimensions,
            text_paths=(self.text_field,),
            tenant_field=self.scope_field,
            tenant_type=self.scope_type,
            filter_fields=("kind",),
            vector_index=f"{self.collection}_vector",
            text_index=f"{self.collection}_text",
        )

    def expiry_spec(self) -> ExpirySpec:
        # Per-document deadline: null expire_at is pinned, which is what makes
        # "remember this permanently" and "remember this for an hour" the same
        # collection instead of two subsystems.
        return ExpirySpec(collection=self.collection, at_field="expire_at")


class Memory:
    """Write and recall scoped memories."""

    kind = "memory"

    def __init__(self, engine, spec: MemorySpec):
        self.engine = engine
        self.spec = spec
        self.collection = spec.collection
        # One object owns "may this reach a prompt?". Memory does not
        # re-implement the rule, it asks the thing whose job it is -- and
        # declares its own scope field as the tenant, so the handle enforces
        # the same boundary recall does. Building it unscoped meant a later
        # ``model(tenant=...).forgettable()`` on the same collection got this
        # handle back and quietly inherited "no tenant".
        self.admission = engine.admission(spec.collection,
                                            at_field="expire_at",
                                            tenant=spec.scope_field)

    async def remember(self, scope: Any, text: str, vector: list[float], *,
                       kind: str = "note", ttl: timedelta | None | EllipsisType = ...,
                       pinned: bool = False, meta: dict | None = None) -> dict:
        """Store one memory.

        ``ttl`` defaults to the spec's; pass ``None`` or ``pinned=True`` to keep
        it forever. Returns the stored document.
        """
        if ttl is ...:
            ttl = self.spec.default_ttl
        if pinned:
            ttl = None

        doc: dict[str, Any] = {
            self.spec.scope_field: scope,
            self.spec.text_field: text,
            self.spec.vector_path: vector,
            "kind": kind,
            "created_at": now(),
            "expire_at": deadline(ttl),
            **(meta or {}),
        }
        res = await self.engine.db[self.spec.collection].insert_one(doc)
        doc["_id"] = res.inserted_id
        return doc

    async def recall(self, scope: Any, vector: list[float], *,
                     text: str | None = None, limit: int = 5,
                     kind: str | None = None) -> list[dict]:
        """Retrieve for a prompt: hybrid, scoped, and never stale.

        ``text`` is worth passing. Retrieval corpora are full of identifiers --
        error codes, ticket numbers, function names, config keys -- which is
        exactly what embeddings are worst at and lexical search is exact about.
        Supplying it moves recall to the fused tier.

        The check on the way out is not redundant with the TTL index:
        MongoDB's TTL monitor runs roughly once a minute, so an expired row
        stays readable for a short window. A forgotten fact must never
        reappear in a context window, so every hit goes through
        ``Admission`` -- which refuses an expired deadline, an unreadable
        one, and anything explicitly revoked, before it can be returned.

        That check is applied in this process rather than pushed into the
        search index, which costs something: expired hits are fetched and then
        discarded, so they spend part of the fetch budget. That budget used to
        be a fixed ``limit * 2``, and a fixed multiple is a guess -- 40
        expired rows ahead of 6 live ones returned *nothing* for a
        ``limit=5`` recall, with all six indexed and on disk. ``saturate()``
        refills instead, and says so when it cannot fill the page; see its
        docstring.

        Pushing it into the search index is possible -- ``living()`` works as
        a ``$vectorSearch`` filter, and the lexical leg can express the same
        rule -- and is deliberately not done. The reasoning and the
        measurements are in the module docstring of ``search.py``;
        the short version is that a ``vectorSearch`` definition cannot be
        migrated in place, and the read path is the layer that cannot drift.
        """
        filters: dict[str, Any] = {self.spec.scope_field: scope}
        if kind is not None:
            filters["kind"] = kind

        # One call, through the Admission handle, because the handle owns the
        # rule *and* the query. It used to own only the rule, which left this
        # method holding a fetch-budget guess -- and the other read path in
        # this package holding an identical copy of the same guess. Two
        # copies of a convention is how the six-read-paths bug started.
        return await self.admission.search(vector, text=text, limit=limit,
                                           filters=filters)

    async def forget(self, scope: Any, *, kind: str | None = None) -> int:
        """Drop a scope's memories now, rather than waiting for expiry.

        The "this session is over" / "the user asked to be forgotten" path.
        """
        q: dict[str, Any] = {self.spec.scope_field: scope}
        if kind is not None:
            q["kind"] = kind
        res = await self.engine.db[self.spec.collection].delete_many(q)
        return res.deleted_count

    async def pin(self, memory_id: Any) -> None:
        """Promote a memory to permanent by removing its deadline."""
        await self.engine.db[self.spec.collection].update_one(
            {"_id": memory_id}, {"$set": {"expire_at": None}})

    async def extend(self, memory_id: Any, ttl: timedelta) -> None:
        """Push a deadline out -- reinforcement for a memory that stays useful."""
        await self.engine.db[self.spec.collection].update_one(
            {"_id": memory_id}, {"$set": {"expire_at": deadline(ttl)}})
