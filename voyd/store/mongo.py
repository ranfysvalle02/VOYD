"""A retrieval scope that cleans itself up.

A **void** is a vector index with a TTL, and a read path that refuses what it
has forgotten. No vector database expires a namespace, so every RAG prototype
leaks them -- and none of them can refuse a document that is on its way out,
so the index keeps answering with it until a sweeper arrives.

The reason a deadline here is trustworthy is that one thing owns it. Split this
across Postgres for metadata, Pinecone for vectors, S3 for blobs and a cron for
cleanup, and you have four expiries with four owners and four ways to drift --
the vector outliving the document is the bug class. Here it is one document
with one ``expire_at``, and the row carries its own text and vector, so
there is no second store to keep in step.

- **Scope** -- a ``voyd`` is a namespace the Host header selects; a void is a
  scope inside it. Every query below is filtered by ``voyd_id``, and the filter
  is pushed *into* the search index, because a leak here is a breach.
- **Deadline** -- the void's ``expire_at`` is inherited by every document in it.
  Mongo's TTL reaper drops the void, the documents and their vectors together.
- **Refusal** -- the reaper is eventual, so every read below goes through a
  ``Admission`` handle that cannot return an expired or revoked row. The
  deadline is enforced before the sweeper arrives, not by it.
- **Guard** -- an access policy on the scope: a passcode on every read.

Design rules honoured here:
- Embeddings live on document rows, never nested in a void (16MB wall;
  ``$vectorSearch`` returns parent docs).
- Work is a document: ``indexed: false`` is the embed job, claimed with
  ``find_one_and_update`` rather than handed to a broker.
- Text is a field. There is no upload path, so there is nothing to reclaim
  when a deadline passes beyond the row itself.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from bson import ObjectId
from pymongo import AsyncMongoClient
from pymongo.errors import CollectionInvalid, OperationFailure

from ..config import MongoConfig
from ..engine import (Deadline, EmbeddedWith, Engine, ExpirySpec, JobQueue,
                      SearchSpec, revoked)
from ..engine.search import MAX_LIMIT as SEARCH_MAX_LIMIT
# The redundant alias is the explicit re-export form: callers and tests import
# ``cosine`` from here, so this is API surface, not an unused import.
from ..engine.search import cosine as cosine
from ..engine.time import now as _utcnow

log = logging.getLogger("voyd.store")

VECTOR_INDEX = "voyd_vector_index"
TEXT_INDEX = "voyd_text_index"

# NamespaceExists: another replica created the collection between our
# list_collection_names() and our create_collection(). Benign by definition.
NAMESPACE_EXISTS = 48

# How many times a failing embed job is retried before it is parked as an error.
MAX_EMBED_ATTEMPTS = 5


class MongoStore:
    """The durable half of VOYD. Owns no HTTP and no opinions about surfaces."""

    def __init__(self, config: MongoConfig):
        self.config = config
        self.client: AsyncMongoClient | None = None
        self.db = None
        self.engine: Engine | None = None
        # Built in _declare(), once the engine exists.
        self.admission_documents = None
        self.admission_voids = None
        self.refusals = None

    async def connect(self) -> None:
        self.client = AsyncMongoClient(self.config.uri, tz_aware=True)
        await self.client.admin.command("ping")
        self.engine = Engine(self.client, self.client[self.config.db_name])
        # engine.db is the UTC-aware handle; everything here goes through it.
        self.db = self.engine.db
        await self._detect_capabilities()

    async def _detect_capabilities(self) -> None:
        assert self.engine is not None
        caps = await self.engine.connect()
        log.info("mongodb %s search=%s change_streams=%s",
                 ".".join(str(p) for p in caps.version),
                 self.engine.search_tier, caps.change_streams)

    async def close(self) -> None:
        if self.client is not None:
            await self.client.close()

    @property
    def search(self) -> bool:
        return bool(self.engine and self.engine.capabilities.search)

    @property
    def search_ready(self) -> bool:
        return bool(self.engine and self.engine.search_engine.ready)

    @property
    def degraded_searches(self) -> int:
        return self.engine.search_engine.degraded if self.engine else 0

    @property
    def search_tier(self) -> str:
        return self.engine.search_tier if self.engine else "cosine"

    # ---- schema --------------------------------------------------------

    async def ensure_schema(self, vector_dimensions: int = 1024,
                            embedding_model: str | None = None) -> None:
        """Create collections, indexes, TTL, and the Atlas search indexes."""
        db = self.db
        assert db is not None

        # Create the collections up front: a search index cannot be built
        # on a namespace that does not exist yet.
        existing = set(await db.list_collection_names())
        for name in ("owners", "voyds", "voids", "documents"):
            if name not in existing:
                try:
                    await db.create_collection(name)
                except CollectionInvalid:
                    log.debug("collection %s already exists", name)
                except OperationFailure as exc:
                    if exc.code != NAMESPACE_EXISTS:
                        raise
                    # A concurrent replica won the race to create it.
                    log.debug("collection %s created concurrently", name)

        await db.owners.create_index("api_key_hash", unique=True, sparse=True)
        await db.owners.create_index("email", unique=True, sparse=True)

        await db.voyds.create_index("slug", unique=True)
        await db.voyds.create_index("owner_id")

        await db.voids.create_index([("voyd_id", 1), ("token", 1)], unique=True)
        # TTL: docs with a past ``expire_at`` are reaped; null/absent = permanent.
        await db.voids.create_index("expire_at", expireAfterSeconds=0)
        await db.documents.create_index([("voyd_id", 1), ("token", 1)])
        await db.documents.create_index([("token", 1), ("doc_id", 1)], unique=True)
        await db.documents.create_index([("indexed", 1)])
        await db.documents.create_index("expire_at", expireAfterSeconds=0)

        if self.search:
            await self._ensure_search_indexes(vector_dimensions,
                                              model=embedding_model)

    def _declare(self, dims: int, model: str | None = None) -> None:
        """Everything this app wants MongoDB to maintain, in one place.

        ``token`` is a filter field so a void-scoped search is narrowed inside
        mongot rather than filtered afterwards in Python -- the void *is* the
        retrieval boundary, and a boundary enforced in Python is not one.
        """
        # One object per collection owns "may this reach a prompt?". Every
        # read below asks it instead of re-implementing the deadline, which is
        # how six read paths came to disagree about the rule in the first
        # place. The local _unexpired() helper is gone on purpose: a rule
        # you have to remember to apply is not enforced, it is suggested.
        # Documents refuse for three reasons; voids for the usual two. The
        # third is the model: a vector produced by a different one is not a
        # worse vector, it is an incomparable one, and ranking it returns a
        # confident number that means nothing.
        doc_rules = [Deadline(), revoked()]
        if model:
            doc_rules.append(EmbeddedWith(model))
        self.admission_documents = self.engine.admission(
            "documents", tenant="voyd_id", rules=tuple(doc_rules))
        self.admission_voids = self.engine.admission("voids", tenant="voyd_id")

        # Every revocation is witnessed on a per-namespace hash chain, so
        # "this fact stopped being reachable at 14:02" is a claim somebody can
        # check rather than one they have to take. Attached only to documents:
        # a void's own expiry is a deadline passing, not an instruction
        # anybody gave, and a ledger of clock ticks is noise that makes the
        # entries that matter harder to find.
        self.refusals = self.engine.ledger("refusals", tenant="voyd_id",
                                           key=self.config.ledger_key)
        self.admission_documents.witnessed_by(self.refusals)

        self.engine.searchable(SearchSpec(
            collection="documents",
            vector_path="embedding",
            dimensions=dims,
            text_paths=("text", "name", "filename"),
            tenant_field="voyd_id",
            filter_fields=("token",),
            vector_index=VECTOR_INDEX,
            text_index=TEXT_INDEX,
        ))

        # Expiry as declaration rather than scattered create_index calls.
        for coll in ("voids", "documents"):
            self.engine.expiring(ExpirySpec(collection=coll, at_field="expire_at"))

    async def _ensure_search_indexes(self, dims: int, *, model: str | None = None,
                                     wait_s: float = 90.0) -> None:
        """Declare what should be searchable; the engine owns the lifecycle."""
        self._declare(dims, model)
        await self.engine.ensure(search_wait_s=wait_s)

    # ---- owners --------------------------------------------------------

    async def create_owner(self, email: str, api_key_hash: str, *,
                           name: str = "") -> ObjectId:
        res = await self.db.owners.insert_one({
            "email": email,
            "api_key_hash": api_key_hash,
            "name": name,
            "created_at": _utcnow(),
        })
        return res.inserted_id

    async def count_owners(self) -> int:
        return await self.db.owners.count_documents({})

    # No ``get_owner``, ``get_owner_by_email`` or ``set_owner_api_key``: they
    # belonged to the owner plane, and the owner plane was a browser surface
    # that no longer exists. One credential, looked up one way. A duplicate
    # email is arbitrated by the unique index rather than by a read-then-write,
    # which could not have been correct anyway.
    async def get_owner_by_key_hash(self, api_key_hash: str) -> dict | None:
        return await self.db.owners.find_one({"api_key_hash": api_key_hash})

    # ---- voyds (namespaces) -------------------------------------------

    async def get_voyd_by_slug(self, slug: str) -> dict | None:
        return await self.db.voyds.find_one({"slug": slug})

    async def list_voyds(self, owner_id: ObjectId) -> list[dict]:
        cur = self.db.voyds.find({"owner_id": owner_id}).sort("created_at", -1)
        return [v async for v in cur]

    async def create_voyd(self, slug: str, owner_id: ObjectId,
                          guard_defaults: dict, *, name: str = "") -> dict:
        """Going live is an insert. There is no deploy and no provisioning."""
        doc = {
            "slug": slug,
            "owner_id": owner_id,
            "name": name or slug,
            "status": "active",
            "guards": guard_defaults,
            "created_at": _utcnow(),
        }
        await self.db.voyds.insert_one(doc)
        return doc

    # ---- voids ---------------------------------------------------------

    async def create_void(self, voyd_id: ObjectId, token: str, policy: dict,
                          expire_at: datetime | None) -> dict:
        doc = {
            "voyd_id": voyd_id,
            "token": token,
            "guards": policy,
            # No ``download_count``: it counted an operation that no longer
            # exists. It went with the byte path, and a field written on every
            # scope, read by nothing, is a schema somebody will later feel
            # obliged to keep.
            "doc_count": 0,
            "expire_at": expire_at,
            "created_at": _utcnow(),
        }
        await self.db.voids.insert_one(doc)
        return doc

    async def get_void(self, voyd_id: ObjectId, token: str) -> dict | None:
        """An expired void reads as absent, so every caller 404s on it.

        This is the gate for the whole void surface: search, describe and
        ingest all resolve the void first, so a scope that is over cannot be
        queried or added to even in the window before the reaper runs.
        """
        return await self.admission_voids.find_one(
            {"voyd_id": voyd_id, "token": token})

    async def list_voids(self, voyd_id: ObjectId) -> list[dict]:
        """Only voids that are still alive. Expired ones are gone, not hidden."""
        return await self.admission_voids.find(
            {"voyd_id": voyd_id}, sort=("created_at", -1))

    # ---- documents -----------------------------------------------------
    #
    # One row per document. ``indexed: False`` is the embed job.
    # ``expire_at`` is inherited from the void, so the row and its vector die
    # with the scope.

    def _doc(self, voyd_id: ObjectId, token: str, doc_id: str, *,
             name: str, expire_at: datetime | None, **extra) -> dict:
        return {
            "voyd_id": voyd_id,
            "token": token,
            "doc_id": doc_id,
            "name": name,
            "text": None,
            "size": None,
            "metadata": {},
            "indexed": False,
            "embedding": None,
            # Which model produced the vector above. Set with it, cleared
            # with it: the pair is never written apart.
            "embedded_with": None,
            # The document inherits the void's deadline: the text and its
            # vector expire together, because they are one row.
            "expire_at": expire_at,
            "created_at": _utcnow(),
            **extra,
        }

    async def add_document(self, voyd_id: ObjectId, token: str, doc_id: str, *,
                           text: str, name: str, metadata: dict | None = None,
                           expire_at: datetime | None = None) -> dict:
        """Text straight in. The only way in, and formerly the primary of two.

        The alternative was a presigned upload to object storage, read back
        by the embed worker. It bought a round trip, a second failure mode,
        and a second thing to reclaim when the deadline passed. Callers of a
        retrieval scope have the text.
        """
        doc = self._doc(voyd_id, token, doc_id, name=name, expire_at=expire_at,
                        text=text, metadata=metadata or {},
                        size=len(text.encode("utf-8")))
        await self.db.documents.insert_one(doc)
        await self.db.voids.update_one(
            {"voyd_id": voyd_id, "token": token}, {"$inc": {"doc_count": 1}}
        )
        return doc

    async def witness_forget(self, voyd_id: ObjectId, token: str, *,
                             doc_ids: list[str] | None = None,
                             reason: str = "revoked") -> dict:
        """Make documents unreachable now, and return the chain receipt.

        Erasure stays the deadline's job. The elegant part is that there is
        no second mechanism: forgetting a fact *is* giving it a deadline in
        the past, so one TTL index collects user-requested erasure and
        time-based expiry alike, and an erasure request is not a special
        case -- it is a deadline that has already passed.

        The receipt is the half of the audit story this database cannot
        provide on its own: a hash the caller holds, computed before
        anybody had a reason to rewrite the chain. There used to be a
        second method that did the same write and threw the receipt away;
        nothing called it.

        ``doc_ids`` omitted means the whole scope.
        """
        flt: dict[str, Any] = {"voyd_id": voyd_id, "token": token}
        if doc_ids:
            flt["doc_id"] = {"$in": list(doc_ids)}
        return await self.admission_documents.witness(flt, reason=reason)

    async def proof(self, voyd_id: ObjectId, *, token: str | None = None) -> dict:
        """The chain for a namespace, recomputed, with its limits attached."""
        assert self.refusals is not None
        report = await self.refusals.verify(tenant=voyd_id)
        # ``_id`` is dropped rather than serialised: it is assigned by the
        # database and deliberately excluded from the hash, so showing it
        # beside the entry invites somebody to include it when they
        # re-verify and conclude the chain is forged.
        entries = [{k: v for k, v in e.items() if k != "_id"}
                   for e in await self.refusals.entries(tenant=voyd_id)]
        if token is not None:
            # Filtered for display only. Verification is always over the whole
            # chain: a subset of a hash chain cannot be verified, since the
            # links run through the entries that were filtered out.
            entries = [e for e in entries
                       if (e.get("subject") or {}).get("token") == token]
        return {"chain": report, "entries": entries}

    async def get_document(self, voyd_id: ObjectId, token: str,
                           doc_id: str) -> dict | None:
        return await self.admission_documents.find_one(
            {"voyd_id": voyd_id, "token": token, "doc_id": doc_id})

    async def list_documents(self, voyd_id: ObjectId, token: str) -> list[dict]:
        return await self.admission_documents.find(
            {"voyd_id": voyd_id, "token": token}, {"embedding": 0})

    async def count_indexed(self, voyd_id: ObjectId, token: str) -> dict:
        """How much of the scope is actually queryable yet.

        Embedding is asynchronous, so "I added 50 documents" and "50 documents
        are searchable" are different facts and the caller needs both.
        """
        out = {"total": 0, "indexed": 0, "pending": 0, "failed": 0}
        cur = await self.db.documents.aggregate([
            {"$match": self.admission_documents.match(
                {"voyd_id": voyd_id, "token": token})},
            {"$group": {"_id": "$indexed", "n": {"$sum": 1}}},
        ])
        async for row in cur:
            out["total"] += row["n"]
            if row["_id"] is True:
                out["indexed"] += row["n"]
            elif row["_id"] == "error":
                out["failed"] += row["n"]
            else:
                out["pending"] += row["n"]
        return out

    # ---- embed worker claims ------------------------------------------

    def _queue(self, collection: str = "documents") -> JobQueue:
        """The embed queue: a document with ``indexed: False`` is the job."""
        return JobQueue(db=self.db, collection=collection,
                        when={"indexed": False},
                        status_field="indexed", attempts_field="embed_attempts",
                        max_attempts=MAX_EMBED_ATTEMPTS)

    async def claim_next_document(self) -> dict | None:
        return await self._queue().claim()

    async def set_embedding(self, _id, embedding: list[float] | None, *,
                            model: str | None = None) -> None:
        """Record an embedding, or park the document if it cannot be one.

        The dimension is checked against what the index declares, because a
        vector of the wrong width is not a bad vector -- it is an invisible
        document. mongot silently skips it: no error, no degraded search, and
        ``describe()`` counting it as ``indexed`` because we said so. Measured:
        a 512-wide vector in a 1024 index gave ``total=2 indexed=2 pending=0``
        while search could only ever return the other row.

        That is the exact failure this project exists to refuse -- "added" read
        as "searchable" -- so a mismatch is parked as ``error`` and shows up in
        ``describe()``'s ``failed`` count instead. The realistic cause is not
        an attacker; it is ``VOYAGE_MODEL`` changing under an index built at
        the old width.
        """
        if embedding is not None:
            declared = self._declared_dimensions()
            if declared is not None and len(embedding) != declared:
                log.error(
                    "document %s embedded to %d dimensions but the vector "
                    "index declares %d; parking it as failed rather than "
                    "storing a document mongot will silently skip. Check the "
                    "embedding model against the index definition.",
                    _id, len(embedding), declared)
                embedding = None

        # The model is stored *with* the vector, in the same write, because
        # they are one fact. Every current Voyage model is 1024-wide, so a
        # width check cannot tell a voyage-3 vector from a voyage-4 one --
        # and comparing them returns a plausible number rather than an
        # error. A vector whose model is unrecorded is an orphan.
        await self.db.documents.update_one(
            {"_id": _id},
            {"$set": {"embedding": embedding,
                      "embedded_with": model if embedding else None,
                      "indexed": True if embedding else "error"}},
        )

    def _declared_dimensions(self) -> int | None:
        """What the documents vector index was actually built for."""
        spec = self.engine.search_engine.specs.get("documents") if self.engine else None
        return spec.dimensions if spec else None

    async def release_claim(self, collection: str, _id) -> None:
        """Put a job back for another attempt, counting the try."""
        await self._queue(collection).release({"_id": _id})

    # ---- search --------------------------------------------------------

    async def vector_search(self, voyd_id: ObjectId, query_vec: list[float], *,
                            token: str | None = None, limit: int = 5,
                            query_text: str | None = None) -> list[dict]:
        """Search scoped to a voyd, and optionally narrowed to a single void.

        Tier selection, index readiness and loud degradation all live in the
        engine. What stays here is the part that is about VOYD: the boundary.
        """
        assert self.engine is not None
        # One call, through the engine's Admission handle. Not a local
        # comprehension, and not a local call to the search primitive: the
        # handle owns the rule *and* the query, so this method cannot hold a
        # stale copy of either -- which is exactly what it used to do,
        # alongside an identical copy in ``Memory.recall``.
        #
        # ``expire_at`` is deliberately not a filter field on either
        # $rankFusion leg. Both legs *can* express the rule -- that was
        # measured, and the numbers are in the module docstring of
        # ``voyd/engine/search.py`` -- but a vectorSearch definition cannot be
        # updated in place, so pushing it down would mean an unmigratable
        # index change on every existing deployment. Enforcing it on read also
        # keeps the cosine fallback correct, where there is no index to push
        # into. The cost is that expired hits spend part of the fetch budget,
        # which is why the handle refills it instead of trusting a multiple.
        return await self.admission_documents.search(
            query_vec, text=query_text, limit=min(limit, SEARCH_MAX_LIMIT),
            filters=self._search_filter(voyd_id, token))

    def _search_filter(self, voyd_id, token: str | None) -> dict:
        """Every search is bound to one namespace, and a void-scoped search to
        one void. The engine pushes this into the index, so the boundary is
        enforced by mongot rather than remembered by a caller."""
        flt: dict[str, Any] = {"voyd_id": voyd_id}
        if token is not None:
            flt["token"] = token
        return flt

