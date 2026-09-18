"""Hybrid search over Atlas, with the sharp edges already filed off.

Three tiers, best first, chosen from probed capabilities:

1. ``hybrid``  -- ``$rankFusion`` over ``$vectorSearch`` + ``$search``
2. ``vector``  -- ``$vectorSearch`` alone
3. ``cosine``  -- exact, in-process, correct at small scale and a cliff past it

Two behaviours here were expensive to learn and are the main reason this is a
library rather than a snippet:

**A search index that is missing or still building returns zero rows instead of
raising.** It is indistinguishable from "nothing matched". So startup waits for
the index to become queryable, and queries refuse the Atlas path until it is --
otherwise a cold start silently reports an empty database.

**Degrading is loud.** The cosine fallback loads every vector into Python. Fine
for a demo, a cliff in production. Every fallback is logged at ERROR and counted.

Tenant scoping is pushed *into the index* (a filter field on the vector leg, a
``compound.must`` on the lexical leg) so the boundary is enforced by mongot
rather than by remembering to add a filter -- including inside both
``$rankFusion`` legs, where a miss leaks every tenant's data.

**Deadlines are deliberately not pushed into the index.** They are enforced in
the read path instead: callers apply ``live()`` to each hit (``memory.py`` in
this package does, and so should any application storing a deadline on a
searchable row). That is a decision, not an omission, and these are
the measurements behind it -- all taken against Atlas Local, MongoDB 8.x:

- ``living()`` works verbatim as a ``$vectorSearch`` filter. Both ``$or`` and
  ``$exists`` are supported there, returning exactly the null/absent/future
  set. Pushing it down is *possible*.
- The lexical leg can express the same rule with ``range`` + ``equals: null``
  + ``mustNot: exists``. It belongs in ``compound.filter``, not
  ``compound.must``: in ``must``, the nested clause contributes to relevance,
  so a document's score changes according to *how* it satisfied the deadline:
  rows matching via ``range`` or ``equals: null`` gain a full point, while a
  row with no ``expire_at`` field at all -- satisfying the rule via
  ``mustNot: exists`` -- keeps its original score. That reorders results by a
  field with nothing to do with relevance. In ``compound.filter`` the scores
  come back byte-identical to the query without the clause.
- A ``search`` index definition can be updated in place. A ``vectorSearch``
  definition **cannot**: ``update_search_index`` validates whatever it is
  given as a lexical definition and fails with ``"mappings" is required``.

So pushing deadlines down would mean a vector-index change that cannot be
migrated, on an existing deployment, to save fetching a few rows that are
already being filtered correctly -- and enforcing it on only one leg would
leave the two ``$rankFusion`` legs disagreeing about which documents exist,
which is worse than filtering both uniformly afterwards. The read path is the
layer that cannot drift, and it is also the only layer that works on the
cosine fallback, where there is no index to push anything into.

What *is* enforced here is that an index matches what the application declared:
see ``drifted()``.
"""

from __future__ import annotations

import asyncio
import logging
import math
from dataclasses import dataclass, field
from typing import Any

from pymongo.errors import CollectionInvalid, OperationFailure

from .errors import ScopeError, require_scope

log = logging.getLogger("engine.search")

# Hard ceilings. Cosine is exact and linear -- past this it is a cliff, not a
# fallback. A single query must not become a collection scan of unbounded size.
COSINE_CAP = 10_000
MAX_LIMIT = 100


def _declared_vector_fields(definition: dict) -> set[tuple]:
    """The parts of a vector definition we actually declared.

    A vectorSearch definition round-trips unchanged, so this is a faithful
    comparison rather than a heuristic.
    """
    out: set[tuple] = set()
    for f in definition.get("fields", []):
        if f.get("type") == "vector":
            out.add(("vector", f.get("path"), f.get("numDimensions"),
                     f.get("similarity")))
        else:
            out.add((f.get("type"), f.get("path")))
    return out


def _declared_text_fields(definition: dict) -> tuple[bool, dict]:
    """The declared shape of a lexical definition, ignoring Atlas's defaults.

    Atlas fills in ``indexOptions``, ``norms`` and ``store`` on a string field,
    so the definition read back is never equal to the one sent. Comparing only
    what we declared is what keeps drift detection from firing on every start.
    """
    mappings = definition.get("mappings", {})
    fields = mappings.get("fields", {}) or {}
    return bool(mappings.get("dynamic", False)), {
        path: spec.get("type") for path, spec in fields.items()}


def drifted(kind: str, wanted: dict, latest: dict | None) -> bool:
    """Has the live index stopped matching what the application declares?

    Without this, ``ensure_indexes`` skipped any index whose *name* already
    existed, so changing ``text_paths`` or ``dimensions`` in a spec left the
    old index in place and every later query used it -- silently, and forever.
    That is the quiet-fallback failure this module exists to make impossible.
    """
    if latest is None:
        return False
    if kind == "vectorSearch":
        return _declared_vector_fields(wanted) != _declared_vector_fields(latest)
    return _declared_text_fields(wanted) != _declared_text_fields(latest)


def cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return -1.0
    dot = na = nb = 0.0
    for x, y in zip(a, b):
        dot += x * y
        na += x * x
        nb += y * y
    if na == 0.0 or nb == 0.0:
        return -1.0
    return dot / (math.sqrt(na) * math.sqrt(nb))


@dataclass(frozen=True)
class SearchSpec:
    """How one collection should be searchable.

    Deliberately free of any app vocabulary: give it field names, get search.
    """

    collection: str
    vector_path: str = "embedding"
    dimensions: int = 1024
    text_paths: tuple[str, ...] = ("text",)
    tenant_field: str | None = None
    # How the tenant id is indexed for the *lexical* leg. Atlas Search needs the
    # declared type to match the stored value, and rejects the query otherwise
    # ("Path 'x' needs to be indexed as token"). ObjectId tenants -> "objectId";
    # string tenants (agent ids, session ids, slugs) -> "token".
    tenant_type: str = "objectId"
    filter_fields: tuple[str, ...] = ()
    # Ask the *server* to embed. When set, the vector index is declared with
    # ``type: autoEmbed`` and mongot produces the embedding on write and at
    # query time, so the application never holds a vector at all. Declared,
    # not probed: a deployment that cannot do it says so at index creation,
    # and ``ensure_indexes`` falls back to the ordinary vector index, loudly.
    # Adopting this is therefore safe before every deployment supports it.
    auto_embed: str | None = None
    auto_embed_modality: str = "text"
    similarity: str = "cosine"
    vector_index: str = "engine_vector_index"
    text_index: str = "engine_text_index"

    def auto_embed_definition(self) -> dict:
        """The server-side-embedding form of the vector index.

        The embedded path is the *text*, not a vector field: there is no
        vector field, because nothing in this process ever computes one --
        which is why a spec with no ``text_paths`` has nothing to embed and
        is a declaration error rather than an empty index.
        """
        if not self.text_paths:
            raise ValueError(
                f"{self.collection} declares auto_embed={self.auto_embed!r} "
                f"but no text_paths: the server embeds a text field, so there "
                f"has to be one to name")
        fields: list[dict] = [{
            "type": "autoEmbed", "path": self.text_paths[0],
            "model": self.auto_embed, "modality": self.auto_embed_modality,
        }]
        for name in self._filterable():
            fields.append({"type": "filter", "path": name})
        return {"fields": fields}

    def vector_definition(self) -> dict:
        fields: list[dict] = [{
            "type": "vector", "path": self.vector_path,
            "numDimensions": self.dimensions, "similarity": self.similarity,
        }]
        for name in self._filterable():
            fields.append({"type": "filter", "path": name})
        return {"fields": fields}

    def text_definition(self) -> dict:
        mapped: dict[str, Any] = {p: {"type": "string"} for p in self.text_paths}
        if self.tenant_field:
            mapped[self.tenant_field] = {"type": self._tenant_type()}
        for name in self.filter_fields:
            # A filter field is matched with `equals`, which needs `token` --
            # even when the same path is also indexed as searchable text.
            mapped[name] = {"type": "token"}
        return {"mappings": {"dynamic": False, "fields": mapped}}

    def _tenant_type(self) -> str:
        """Accept the names developers actually type."""
        alias = {"string": "token", "str": "token", "token": "token",
                 "objectid": "objectId", "oid": "objectId"}
        normalised = alias.get(self.tenant_type.lower())
        if normalised is None:
            raise ValueError(
                f"tenant_type must be 'objectId' or 'token', got {self.tenant_type!r}")
        return normalised

    def _filterable(self) -> tuple[str, ...]:
        tenant = (self.tenant_field,) if self.tenant_field else ()
        return tenant + self.filter_fields


@dataclass
class SearchEngine:
    """Owns index lifecycle and querying for a set of collections."""

    db: Any
    capabilities: Any
    specs: dict[str, SearchSpec] = field(default_factory=dict)
    ready: bool = False
    degraded: int = 0
    scope_refused: int = 0
    cosine_capped: int = 0
    # Indexes whose live definition no longer matches the declared spec and
    # which could not be corrected. Named, because the consequence is silent.
    stale: list[str] = field(default_factory=list)
    # Collections that asked the server to embed and did not get it. Non-empty
    # means those specs are running on the ordinary vector index and the
    # application still has to supply vectors.
    auto_embed_declined: list[str] = field(default_factory=list)
    auto_embed_active: list[str] = field(default_factory=list)
    cosine_cap: int = COSINE_CAP

    def register(self, spec: SearchSpec) -> None:
        self.specs[spec.collection] = spec

    @property
    def tier(self) -> str:
        if not self.capabilities.search:
            return "cosine"
        if not self.ready:
            return "cosine (indexes building)"
        return self.capabilities.search_tier

    @property
    def _usable(self) -> bool:
        """Only query Atlas once its indexes can actually answer."""
        return self.capabilities.search and self.ready

    # ---- index lifecycle ----------------------------------------------

    async def ensure_indexes(self, *, wait_s: float = 90.0) -> bool:
        if not self.capabilities.search or not self.specs:
            return False
        from pymongo.operations import SearchIndexModel

        for spec in self.specs.values():
            # A search index cannot be created on a collection that does not
            # exist yet -- Atlas raises NamespaceNotFound. An app that declares
            # its schema before writing any data (the normal order) would
            # otherwise get no indexes at all and silently serve the cosine
            # fallback forever.
            try:
                await self.db.create_collection(spec.collection)
            except CollectionInvalid:
                pass  # already exists (client-side check)
            except OperationFailure as exc:
                if exc.code != 48:  # NamespaceExists: a concurrent replica won.
                    log.warning("could not create collection %s: %s",
                                spec.collection, exc)

            coll = self.db[spec.collection]
            try:
                existing = {i["name"]: i
                            async for i in await coll.list_search_indexes()}
            except OperationFailure:
                existing = {}

            vector_definition = spec.vector_definition()
            if spec.auto_embed and spec.collection not in self.auto_embed_declined:
                vector_definition = await self._auto_embed_or_fall_back(
                    coll, spec, existing)

            wanted = [
                (spec.vector_index, "vectorSearch", vector_definition),
                (spec.text_index, "search", spec.text_definition()),
            ]
            for name, kind, definition in wanted:
                live = existing.get(name)
                if live is not None:
                    await self._reconcile(coll, spec, name, kind, definition, live)
                    continue
                try:
                    await coll.create_search_index(
                        SearchIndexModel(name=name, type=kind, definition=definition))
                    log.info("building %s index %s.%s", kind, spec.collection, name)
                except OperationFailure as exc:
                    # A concurrent replica won the race: not an error.
                    if "already exists" not in str(exc).lower():
                        log.warning("could not create %s.%s: %s",
                                    spec.collection, name, exc)

        self.ready = await self._await_queryable(wait_s)
        if not self.ready:
            log.warning("search indexes still building after %.0fs; using the "
                        "cosine fallback until they finish", wait_s)
        return self.ready

    # Errors that mean "this deployment cannot embed for you", as opposed to
    # "you asked for the wrong thing". Atlas Local answers the first with an
    # empty model list; a real cluster missing one model answers the second.
    _NO_AUTO_EMBED = ("supported models are: []", "not registered yet",
                      "autoembed", "unrecognized field")

    async def _auto_embed_or_fall_back(self, coll, spec, existing) -> dict:
        """Ask the server to own the embedding. Accept no for an answer.

        The point of declaring rather than probing: application code says what
        it wants once, and a deployment that cannot do it degrades to the
        ordinary vector index plus whatever embeds on the client. Nothing
        branches upstream, and the difference is visible on ``health()``
        rather than inferred from results being worse.

        Measured against ``mongodb/mongodb-atlas-local:8.2`` (mongot 0.69.1,
        edition ``localDev``): ``autoEmbed`` validates field by field and then
        reports ``supported models are: []`` -- the capability is absent, not
        misconfigured, and no credential or registration command exists to fix
        it. See BUG.md. So the fallback is the normal path locally and in CI
        today, and the same code takes the auto path wherever models exist.
        """
        from pymongo.operations import SearchIndexModel

        if spec.vector_index in existing:
            # Already built. Which shape it is was decided on a previous boot
            # and is reported below; reconciliation handles the rest.
            live = existing[spec.vector_index].get("latestDefinition") or {}
            kinds = {f.get("type") for f in live.get("fields", [])}
            if "autoEmbed" in kinds:
                self._mark_auto_embed(spec, active=True)
                return spec.auto_embed_definition()
            self._mark_auto_embed(spec, active=False)
            return spec.vector_definition()

        definition = spec.auto_embed_definition()
        try:
            await coll.create_search_index(SearchIndexModel(
                name=spec.vector_index, type="vectorSearch",
                definition=definition))
        except OperationFailure as exc:
            message = str(exc).lower()
            if not any(m in message for m in self._NO_AUTO_EMBED):
                raise
            log.error(
                "%s asked the server to embed with %r and this deployment "
                "cannot (%s). Falling back to a client-supplied vector index: "
                "the application must keep producing embeddings. This is "
                "expected on Atlas Local, which registers no models.",
                spec.collection, spec.auto_embed,
                str(exc).split(", full error")[0])
            self._mark_auto_embed(spec, active=False)
            return spec.vector_definition()

        log.info("%s: the server owns embedding (%s); no vectors are "
                 "computed in this process", spec.collection, spec.auto_embed)
        self._mark_auto_embed(spec, active=True)
        return definition

    def _mark_auto_embed(self, spec, *, active: bool) -> None:
        target, other = ((self.auto_embed_active, self.auto_embed_declined)
                         if active else
                         (self.auto_embed_declined, self.auto_embed_active))
        if spec.collection not in target:
            target.append(spec.collection)
        if spec.collection in other:
            other.remove(spec.collection)

    def embeds_itself(self, collection: str) -> bool:
        """Is the server producing this collection's vectors?

        The one question the write path and the embed worker need answered.
        """
        return collection in self.auto_embed_active

    async def _reconcile(self, coll, spec, name: str, kind: str,
                         definition: dict, live: dict) -> None:
        """An index that already exists is not automatically the right index.

        A lexical definition can be updated in place. A ``vectorSearch``
        definition **cannot** -- ``update_search_index`` validates whatever it
        is handed as a lexical definition and fails with ``"mappings" is
        required``. So a drifted vector index can only be reported, loudly,
        and corrected by a human dropping it (which rebuilds, and a building
        index answers nothing) or by declaring a new ``vector_index`` name.
        """
        ref = f"{spec.collection}.{name}"
        if not drifted(kind, definition, live.get("latestDefinition")):
            return

        if kind == "search":
            try:
                await coll.update_search_index(name, definition)
                log.warning("%s no longer matched its spec; updating it "
                            "in place", ref)
                return
            except OperationFailure as exc:
                log.error("%s has drifted and could not be updated: %s", ref, exc)
        else:
            log.error(
                "%s has drifted from its declared spec and a vectorSearch "
                "index cannot be updated in place. Queries are using the OLD "
                "definition. Prefer declaring a new vector_index name on the "
                "spec and redeploying -- ensure() blocks until the new index "
                "is queryable, so no replica serves a half-built one. "
                "Dropping it in place rebuilds, and a rebuilding index "
                "returns zero rows rather than raising. See 'Runbook: a "
                "drifted vector index' in the README.", ref)

        if ref not in self.stale:
            self.stale.append(ref)

    async def _await_queryable(self, wait_s: float) -> bool:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + wait_s
        while loop.time() < deadline:
            try:
                ready = True
                for spec in self.specs.values():
                    ready = ready and await self._queryable(spec)
                if ready:
                    return True
            except OperationFailure:
                return False
            await asyncio.sleep(1.0)
        return False

    async def _queryable(self, spec: SearchSpec) -> bool:
        idx = [i async for i in await self.db[spec.collection].list_search_indexes()]
        live = {i["name"] for i in idx if i.get("queryable")}
        return {spec.vector_index, spec.text_index} <= live

    # ---- querying ------------------------------------------------------

    async def query(self, collection: str, vector: list[float], *,
                    text: str | None = None, limit: int = 5,
                    filters: dict | None = None) -> list[dict]:
        spec = self.specs[collection]
        try:
            flt = require_scope(spec.collection, spec.tenant_field, filters)
        except ScopeError:
            # Missing tenant or a non-scalar one -- an operator in the tenant
            # position matches every tenant on all three tiers.
            self.scope_refused += 1
            raise
        limit = max(1, min(int(limit), MAX_LIMIT))

        if self.capabilities.search and not self.ready:
            self.degraded += 1
            log.warning("search indexes not queryable yet; using in-process cosine")

        if self._usable:
            try:
                if self.capabilities.rank_fusion and text:
                    return await self._hybrid(spec, vector, text, flt, limit)
                return await self._vector(spec, vector, flt, limit, text=text)
            except OperationFailure as exc:
                self.degraded += 1
                log.error(
                    "Atlas search failed (%s); degrading to in-process cosine. "
                    "This scales linearly with collection size -- investigate "
                    "rather than ignore.", exc.details.get("codeName", exc))

        return await self._cosine(spec, vector, flt, limit)

    def _vector_stage(self, spec, vector, text, flt, limit) -> dict:
        """The ``$vectorSearch`` stage, in whichever form this index takes.

        When the server owns the embedding there is no query vector to send:
        the index holds text, so the query is text and mongot embeds it with
        the same model it used on write. That symmetry is the reason this is
        worth having -- a client-side embedder can drift from the index's
        model, and this cannot.
        """
        if self.embeds_itself(spec.collection):
            if not (text or "").strip():
                # Sending query:"" would ask mongot to embed the empty string
                # and rank by whatever that lands near -- results that look
                # ordinary and mean nothing. A caller who passed only a vector
                # is on the wrong index and needs to be told, not guessed at:
                # their vector cannot be used here, because the index holds
                # text the server embedded with its own model.
                raise ValueError(
                    f"{spec.collection} is embedded by the server "
                    f"(auto_embed={spec.auto_embed!r}), so a query needs "
                    f"text: pass text=... rather than a query vector. The "
                    f"vector you supplied cannot be compared against an "
                    f"index this process never computed.")
            return {"$vectorSearch": {
                "index": spec.vector_index, "path": spec.text_paths[0],
                "query": text, "numCandidates": max(50, limit * 10),
                "limit": limit, "filter": flt,
            }}
        return {"$vectorSearch": {
            "index": spec.vector_index, "path": spec.vector_path,
            "queryVector": vector, "numCandidates": max(50, limit * 10),
            "limit": limit, "filter": flt,
        }}

    async def _vector(self, spec, vector, flt, limit, text=None) -> list[dict]:
        pipeline = [
            self._vector_stage(spec, vector, text, flt, limit),
            {"$addFields": {"score": {"$meta": "vectorSearchScore"},
                            "source": spec.collection}},
        ]
        cur = await self.db[spec.collection].aggregate(pipeline)
        return [d async for d in cur]

    async def _hybrid(self, spec, vector, text, flt, limit) -> list[dict]:
        """Vector + lexical, fused server-side. One round trip, no hand-rolled
        score normalisation, no reranking in Python."""
        must = [{"equals": {"path": k, "value": v}} for k, v in flt.items()]
        pipeline = [
            {"$rankFusion": {"input": {"pipelines": {
                "vector": [self._vector_stage(spec, vector, text, flt, limit)],
                "lexical": [
                    {"$search": {"index": spec.text_index, "compound": {
                        "must": must,
                        "should": [{"text": {"query": text,
                                             "path": list(spec.text_paths)}}],
                        "minimumShouldMatch": 1,
                    }}},
                    {"$limit": limit},
                ],
            }}}},
            {"$addFields": {"score": {"$meta": "score"}, "source": spec.collection}},
            {"$limit": limit},
        ]
        cur = await self.db[spec.collection].aggregate(pipeline)
        return [d async for d in cur]

    async def _cosine(self, spec, vector, flt, limit) -> list[dict]:
        """Exact and correct, and linear in collection size. The tier you are
        told about rather than silently given. Capped so a degraded
        deployment cannot OOM the process."""
        q = {**flt, spec.vector_path: {"$ne": None}}
        scored: list[dict] = []
        scanned = 0
        async for d in self.db[spec.collection].find(q):
            scanned += 1
            if scanned > self.cosine_cap:
                self.cosine_capped += 1
                self.degraded += 1
                log.error(
                    "cosine fallback hit cap %s on %s; refusing to grow. "
                    "This is the scale cliff -- fix search indexes.",
                    self.cosine_cap, spec.collection)
                break
            d["source"] = spec.collection
            d["score"] = cosine(vector, d.get(spec.vector_path) or [])
            scored.append(d)
        scored.sort(key=lambda d: d["score"], reverse=True)
        return scored[:limit]
