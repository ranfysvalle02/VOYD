"""A retrieval scope that cleans itself up.

A **void** is a vector index with a TTL, and a read path that refuses what it
has forgotten. No vector database expires a namespace, so every RAG prototype
leaks them -- and none of them can refuse a document that is on its way out,
so the index keeps answering with it until a sweeper arrives.

The reason a deadline here is trustworthy is that one thing owns it. Split this
across Postgres for metadata, Pinecone for vectors, S3 for blobs and a cron for
cleanup, and you have four expiries with four owners and four ways to drift --
the vector outliving the document is the bug class. Here it is one document
with one ``expire_at``, and the delete event is itself the GC trigger.

- **Scope** -- a ``voyd`` is a namespace the Host header selects; a void is a
  scope inside it. Every query below is filtered by ``voyd_id``, and the filter
  is pushed *into* the search index, because a leak here is a breach.
- **Deadline** -- the void's ``expire_at`` is inherited by every document in it.
  Mongo's TTL reaper drops the void, the documents and their vectors together.
- **Refusal** -- the reaper is eventual, so every read below goes through a
  ``Forgetting`` handle that cannot return an expired or revoked row. The
  deadline is enforced before the sweeper arrives, not by it.
- **Guard** -- an access policy on the scope: passcode, max reads. Enforced on
  every query and every byte fetched.

Design rules honoured here:
- Embeddings live on document rows, never nested in a void (16MB wall;
  ``$vectorSearch`` returns parent docs).
- Work is a document: ``indexed: false`` is the embed job; a delete event is
  the blob GC event.
- Text may arrive inline or be read from a blob. Both land in the same row,
  because retrieval should not care where the bytes came from.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any

from bson import ObjectId
from pymongo import AsyncMongoClient, ReturnDocument
from pymongo.errors import CollectionInvalid, OperationFailure

from ..config import MongoConfig
from ..engine import Engine, ExpirySpec, JobQueue, SearchSpec
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

# collMod refusing changeStreamPreAndPostImages for a reason no retry can fix:
# a standalone mongod (no oplog) or a server too old to know the option. These
# mean "no blob GC here", which is a deployment fact, not a fault.
PREIMAGE_UNSUPPORTED_CODES = {
    20,     # IllegalOperation
    59,     # CommandNotFound
    72,     # InvalidOptions
    115,    # CommandNotSupported
    40415,  # unknown field in command
}

# How many times a failing embed job is retried before it is parked as an error.
MAX_EMBED_ATTEMPTS = 5

# Text-like MIME types we will embed. Everything else is stored but not indexed.
TEXT_LIKE_PREFIXES = ("text/",)
TEXT_LIKE_EXACT = {
    "application/json",
    "application/xml",
    "application/x-yaml",
    "application/yaml",
    "application/markdown",
    "application/x-tex",
    "application/javascript",
    "application/sql",
}


def is_text_like(mime: str | None) -> bool:
    if not mime:
        return False
    m = mime.split(";")[0].strip().lower()
    return m.startswith(TEXT_LIKE_PREFIXES) or m in TEXT_LIKE_EXACT


class MongoStore:
    """The durable half of VOYD. Owns no HTTP and no opinions about surfaces."""

    def __init__(self, config: MongoConfig):
        self.config = config
        self.client: AsyncMongoClient | None = None
        self.db = None
        self.engine: Engine | None = None
        # None = not yet attempted. False = delete events will not carry the
        # pre-image, so blob GC cannot know which key to reclaim. Ops reports
        # this rather than letting a silent no-op look like an idle GC worker.
        self.pre_images: bool | None = None
        # Built in _declare(), once the engine exists.
        self.forgetting_documents = None
        self.forgetting_voids = None

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

    async def ensure_schema(self, vector_dimensions: int = 1024) -> None:
        """Create collections, indexes, TTL, and the Atlas search indexes."""
        db = self.db
        assert db is not None

        # Ensure collections exist so we can enable pre-images for GC.
        existing = set(await db.list_collection_names())
        for name in ("owners", "sessions", "voyds", "voids", "documents", "ops"):
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

        # Logins expire the same way voids do: Mongo's TTL reaper.
        await db.sessions.create_index("expire_at", expireAfterSeconds=0)
        await db.sessions.create_index("owner_id")

        await db.voyds.create_index("slug", unique=True)
        await db.voyds.create_index("owner_id")

        await db.voids.create_index([("voyd_id", 1), ("token", 1)], unique=True)
        # TTL: docs with a past ``expire_at`` are reaped; null/absent = permanent.
        await db.voids.create_index("expire_at", expireAfterSeconds=0)
        await db.documents.create_index([("voyd_id", 1), ("token", 1)])
        await db.documents.create_index([("token", 1), ("doc_id", 1)], unique=True)
        await db.documents.create_index([("indexed", 1)])
        await db.documents.create_index("expire_at", expireAfterSeconds=0)

        # Change-stream pre-images let delete events carry the object key for R2
        # GC. If this silently fails, blob GC never reclaims anything and looks
        # exactly like an idle GC worker -- a bill that grows forever with no log
        # line. So the outcome is always stated, and recorded on ``pre_images``.
        await self._enable_pre_images()

        if self.search:
            await self._ensure_search_indexes(vector_dimensions)

    async def _enable_pre_images(self) -> None:
        """Turn on ``changeStreamPreAndPostImages`` for the GC-relevant
        collections, and say out loud whether it worked."""
        db = self.db
        for name in ("voids", "documents"):
            try:
                await db.command({"collMod": name,
                                  "changeStreamPreAndPostImages": {"enabled": True}})
            except OperationFailure as exc:
                self.pre_images = False
                if exc.code in PREIMAGE_UNSUPPORTED_CODES:
                    log.info("change-stream pre-images unsupported on this "
                             "deployment (%s): blob GC via change stream is "
                             "disabled; expired voids will leave objects in R2. "
                             "Run a replica set to enable it.",
                             (exc.details or {}).get("codeName", exc))
                else:
                    log.error("could not enable change-stream pre-images on %s "
                              "(%s): blob GC will not reclaim objects", name,
                              (exc.details or {}).get("codeName", exc))
                return
        self.pre_images = True

    def _declare(self, dims: int) -> None:
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
        self.forgetting_documents = self.engine.forgetting("documents")
        self.forgetting_voids = self.engine.forgetting("voids")

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
        for coll in ("sessions", "voids", "documents"):
            self.engine.expiring(ExpirySpec(collection=coll, at_field="expire_at"))

    async def _ensure_search_indexes(self, dims: int, *, wait_s: float = 90.0) -> None:
        """Declare what should be searchable; the engine owns the lifecycle."""
        self._declare(dims)
        await self.engine.ensure(search_wait_s=wait_s)

    # ---- owners --------------------------------------------------------

    async def create_owner(self, email: str, api_key_hash: str, *,
                           password_hash: str | None = None,
                           name: str = "") -> ObjectId:
        res = await self.db.owners.insert_one({
            "email": email,
            "api_key_hash": api_key_hash,
            "password_hash": password_hash,
            "name": name,
            "created_at": _utcnow(),
        })
        return res.inserted_id

    async def count_owners(self) -> int:
        return await self.db.owners.count_documents({})

    async def get_owner_by_key_hash(self, api_key_hash: str) -> dict | None:
        return await self.db.owners.find_one({"api_key_hash": api_key_hash})

    async def get_owner_by_email(self, email: str) -> dict | None:
        return await self.db.owners.find_one({"email": email})

    async def get_owner(self, owner_id: ObjectId) -> dict | None:
        return await self.db.owners.find_one({"_id": owner_id})

    async def set_owner_api_key(self, owner_id: ObjectId, api_key_hash: str) -> None:
        await self.db.owners.update_one(
            {"_id": owner_id}, {"$set": {"api_key_hash": api_key_hash}}
        )

    # ---- sessions ------------------------------------------------------

    async def create_session(self, owner_id: ObjectId, token_hash: str,
                             ttl_days: int) -> None:
        await self.db.sessions.insert_one({
            "_id": token_hash,
            "owner_id": owner_id,
            "created_at": _utcnow(),
            "expire_at": _utcnow() + timedelta(days=ttl_days),
        })

    async def get_owner_by_session(self, token_hash: str) -> dict | None:
        session = await self.db.sessions.find_one({"_id": token_hash})
        if not session:
            return None
        return await self.get_owner(session["owner_id"])

    async def delete_session(self, token_hash: str) -> None:
        await self.db.sessions.delete_one({"_id": token_hash})

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

    async def find_free_slug(self, base: str) -> str:
        """First available slug for ``base``, suffixing -2, -3, ... on collision."""
        if await self.get_voyd_by_slug(base) is None:
            return base
        for n in range(2, 100):
            suffix = f"-{n}"
            candidate = base[: 40 - len(suffix)].strip("-") + suffix
            if await self.get_voyd_by_slug(candidate) is None:
                return candidate
        return base  # caller surfaces the duplicate error

    async def stats_for_voyds(self, voyd_ids: list[ObjectId]) -> dict:
        """Counts per voyd for the console dashboard."""
        out: dict = {vid: {"voids": 0, "documents": 0} for vid in voyd_ids}
        if not voyd_ids:
            return out
        for coll in ("voids", "documents"):
            cur = await self.db[coll].aggregate([
                {"$match": {"voyd_id": {"$in": voyd_ids}}},
                {"$group": {"_id": "$voyd_id", "n": {"$sum": 1}}},
            ])
            async for row in cur:
                if row["_id"] in out:
                    out[row["_id"]][coll] = row["n"]
        return out

    async def delete_voyd(self, slug: str) -> dict | None:
        voyd = await self.get_voyd_by_slug(slug)
        if not voyd:
            return None
        vid = voyd["_id"]
        for coll in ("voids", "documents"):
            await self.db[coll].delete_many({"voyd_id": vid})
        await self.db.voyds.delete_one({"_id": vid})
        return voyd

    # ---- voids ---------------------------------------------------------

    async def create_void(self, voyd_id: ObjectId, token: str, policy: dict,
                          expire_at: datetime | None) -> dict:
        doc = {
            "voyd_id": voyd_id,
            "token": token,
            "guards": policy,
            "download_count": 0,
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
        return await self.forgetting_voids.find_one(
            {"voyd_id": voyd_id, "token": token})

    async def list_voids(self, voyd_id: ObjectId) -> list[dict]:
        """Only voids that are still alive. Expired ones are gone, not hidden."""
        return await self.forgetting_voids.find(
            {"voyd_id": voyd_id}, sort=("created_at", -1))

    async def claim_download(self, voyd_id: ObjectId, token: str,
                             limit: int | None) -> bool:
        """Consume one download against the void's allowance. Atomically.

        Reading ``download_count`` and then incrementing it is a TOCTOU: two
        concurrent readers both see ``limit - 1``, both pass the guard, and
        both increment -- so a void with ``max_downloads: 10`` serves 11.
        Measured: limit 3, twelve concurrent readers, four served.

        So the limit goes *into the filter*. The increment only happens for a
        request that actually held a slot, which is the same
        ``find_one_and_update`` discipline the job queue uses -- and, unlike a
        Python-side check, it holds across replicas.

        Returns False when the allowance is spent, which the caller turns into
        a 410. An absent ``download_count`` counts as zero: ``$inc`` creates
        it, and a void created before this field existed must not be
        immortal.
        """
        q: dict[str, Any] = {"voyd_id": voyd_id, "token": token}
        if limit is not None:
            q["$or"] = [
                {"download_count": {"$lt": int(limit)}},
                {"download_count": {"$exists": False}},
            ]
        doc = await self.db.voids.find_one_and_update(
            q, {"$inc": {"download_count": 1}},
            return_document=ReturnDocument.AFTER,
        )
        return doc is not None

    # ---- documents -----------------------------------------------------
    #
    # One row per document, whether the text arrived inline or came from a
    # blob. ``indexed: False`` is the embed job. ``expire_at`` is inherited
    # from the void, so the row and its vector die with the scope.

    def _doc(self, voyd_id: ObjectId, token: str, doc_id: str, *,
             name: str, expire_at: datetime | None, **extra) -> dict:
        return {
            "voyd_id": voyd_id,
            "token": token,
            "doc_id": doc_id,
            "name": name,
            "text": None,
            "key": None,
            "mime": None,
            "size": None,
            "metadata": {},
            "indexed": False,
            "embedding": None,
            # The document inherits the void's deadline: text, vector and bytes
            # expire together or the boundary is a lie.
            "expire_at": expire_at,
            "created_at": _utcnow(),
            **extra,
        }

    async def add_document(self, voyd_id: ObjectId, token: str, doc_id: str, *,
                           text: str, name: str, metadata: dict | None = None,
                           expire_at: datetime | None = None) -> dict:
        """Text straight in. No blob, no presign, no upload round trip.

        This is the primary path: the caller already has the text, so making
        it stage bytes in object storage just to get them embedded would add a
        round trip and a failure mode for nothing.
        """
        doc = self._doc(voyd_id, token, doc_id, name=name, expire_at=expire_at,
                        text=text, metadata=metadata or {},
                        mime="text/plain", size=len(text.encode("utf-8")))
        await self.db.documents.insert_one(doc)
        await self.db.voids.update_one(
            {"voyd_id": voyd_id, "token": token}, {"$inc": {"doc_count": 1}}
        )
        return doc

    async def create_file(self, voyd_id: ObjectId, token: str, doc_id: str, *,
                          name: str, key: str, mime: str,
                          expire_at: datetime | None) -> dict:
        """The blob path: a document whose text will be read from storage.

        Still one row in one collection -- retrieval must not care whether the
        text arrived inline or came out of a bucket.
        """
        doc = self._doc(voyd_id, token, doc_id, name=name, expire_at=expire_at,
                        key=key, mime=mime,
                        indexed=False if is_text_like(mime) else "skip")
        await self.db.documents.insert_one(doc)
        await self.db.voids.update_one(
            {"voyd_id": voyd_id, "token": token}, {"$inc": {"doc_count": 1}}
        )
        return doc

    async def complete_file(self, voyd_id: ObjectId, token: str, doc_id: str,
                            *, size: int | None) -> dict | None:
        return await self.db.documents.find_one_and_update(
            {"voyd_id": voyd_id, "token": token, "doc_id": doc_id},
            {"$set": {"size": size, "completed_at": _utcnow()}},
            return_document=ReturnDocument.AFTER,
        )

    async def get_document(self, voyd_id: ObjectId, token: str,
                           doc_id: str) -> dict | None:
        return await self.forgetting_documents.find_one(
            {"voyd_id": voyd_id, "token": token, "doc_id": doc_id})

    async def list_documents(self, voyd_id: ObjectId, token: str) -> list[dict]:
        return await self.forgetting_documents.find(
            {"voyd_id": voyd_id, "token": token}, {"embedding": 0})

    async def count_indexed(self, voyd_id: ObjectId, token: str) -> dict:
        """How much of the scope is actually queryable yet.

        Embedding is asynchronous, so "I added 50 documents" and "50 documents
        are searchable" are different facts and the caller needs both.
        """
        out = {"total": 0, "indexed": 0, "pending": 0, "failed": 0}
        cur = await self.db.documents.aggregate([
            {"$match": self.forgetting_documents.match(
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

    async def set_embedding(self, _id, embedding: list[float] | None) -> None:
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

        await self.db.documents.update_one(
            {"_id": _id},
            {"$set": {"embedding": embedding, "indexed": True if embedding else "error"}},
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
        # Over-fetch, then drop anything past its deadline. ``expire_at`` is
        # deliberately not a filter field on either $rankFusion leg. Both legs
        # *can* express the rule -- that was measured, and the numbers are in
        # the module docstring of ``voyd/engine/search.py`` -- but a
        # vectorSearch definition cannot be updated in place, so pushing it
        # down would mean an unmigratable index change on every existing
        # deployment. Enforcing it here also keeps the cosine fallback correct,
        # where there is no index to push into. The cost of doing it this way
        # is that expired hits consume part of the fetch budget, hence the
        # doubling.
        hits = await self.engine.search(
            "documents", query_vec, text=query_text,
            limit=min(limit * 2, SEARCH_MAX_LIMIT),
            filters=self._search_filter(voyd_id, token),
        )
        # Through the engine's Forgetting handle, not a local comprehension.
        # This was the second of the two hand-written copies of the same rule;
        # one object now owns it, and counts what it refused.
        return self.forgetting_documents.reachable(hits)[:limit]

    def _search_filter(self, voyd_id, token: str | None) -> dict:
        """Every search is bound to one namespace, and a void-scoped search to
        one void. The engine pushes this into the index, so the boundary is
        enforced by mongot rather than remembered by a caller."""
        flt: dict[str, Any] = {"voyd_id": voyd_id}
        if token is not None:
            flt["token"] = token
        return flt

    # ---- ops singleton (change-stream resume token) -------------------

    async def get_resume_token(self) -> Any:
        doc = await self.db.ops.find_one({"_id": "change_stream"})
        return doc.get("resume_token") if doc else None

    async def set_resume_token(self, token: Any) -> None:
        await self.db.ops.update_one(
            {"_id": "change_stream"}, {"$set": {"resume_token": token}}, upsert=True
        )
