"""Background operations, driven entirely by MongoDB state.

Two loops, no external broker:

1. **Embed worker** (``embed_loop``): a claim-based poller. A document with
   ``indexed: false`` *is* the job. It claims one atomically, gets its text --
   inline if the caller supplied it, otherwise a bounded window read from the
   blob -- asks Voyage for an embedding, and writes it back. Claiming makes it
   safe to run multiple replicas.

2. **GC worker** (``gc_loop``): a change stream over ``voids``/``documents``. A
   delete event -- *including a TTL expiration* -- is the GC signal, so the
   deadline on a void is what reclaims its bytes. Nobody schedules a sweep.
   Requires a replica set with pre-images; on a standalone mongod it disables
   itself and logs once.
"""

from __future__ import annotations

import asyncio
import logging

from .engine import backoff
from .store.mongo import MAX_EMBED_ATTEMPTS, MongoStore
from .storage import transient_storage_errors
from .storage.base import NoObjectStorage, ObjectStorage
from .intelligence.voyage import VoyageIntelligence

log = logging.getLogger("voyd.ops")


class Ops:
    def __init__(self, store: MongoStore, storage: ObjectStorage,
                 intelligence: VoyageIntelligence, *, poll_interval: float = 2.0):
        self.store = store
        self.storage = storage
        self.intelligence = intelligence
        self.poll_interval = poll_interval
        self._tasks: list[asyncio.Task] = []
        self._stop = asyncio.Event()
        self._embed_failures = 0
        self._reactor = None

    def start(self) -> None:
        self._tasks = [
            asyncio.create_task(self.embed_loop(), name="voyd-embed"),
            asyncio.create_task(self.gc_loop(), name="voyd-gc"),
        ]

    async def stop(self) -> None:
        self._stop.set()
        if self._reactor is not None:
            await self._reactor.stop()
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            try:
                await t
            except asyncio.CancelledError:
                pass  # we asked for it: the expected outcome of cancel().
            except Exception:
                # The loop died of something other than our cancel. Shutdown
                # still proceeds, but the reason must not vanish with it.
                log.exception("background task %s failed before shutdown",
                              t.get_name())

    # ---- embed worker --------------------------------------------------

    async def embed_loop(self) -> None:
        while not self._stop.is_set():
            try:
                did_work = await self._embed_tick()
            except asyncio.CancelledError:
                raise
            except Exception:  # pragma: no cover - deliberately broad: a
                # background loop that dies on an unexpected error stops all
                # embedding for the life of the process, which is worse than
                # logging and carrying on. Cancellation is re-raised above.
                log.exception("embed tick failed")
                did_work = False
            if not did_work or self._embed_failures:
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=self._embed_pause)
                except asyncio.TimeoutError:
                    pass

    async def _embed_tick(self) -> bool:
        doc = await self.store.claim_next_document()
        if doc is None:
            return False
        await self._embed_document(doc)
        return True

    async def _embed_document(self, doc: dict) -> None:
        """Embed one document, wherever its text came from."""
        text = doc.get("text")
        if text is None and doc.get("key"):
            # The blob path: read a bounded window rather than the whole object.
            try:
                text = await self.storage.get_text_window(
                    doc["key"], max_bytes=self.intelligence.config.max_input_chars
                )
            except NoObjectStorage:
                # The API cannot create this row on a deployment with no object
                # storage, but an older row can outlive the bucket's removal.
                # No retry will ever find the bytes, so park it rather than let
                # it cycle through its attempts forever.
                log.error("document %s has a blob key but this deployment has "
                          "no object storage; parking it as unembeddable",
                          doc.get("_id"))
                await self.store.set_embedding(doc["_id"], None)
                return
            except transient_storage_errors() as exc:
                # Storage being unreachable is the world, not the document.
                await self._embed_failed(doc, exc)
                return

        if not (text or "").strip():
            # Nothing to embed is a property of the document: permanent.
            await self.store.set_embedding(doc["_id"], None)
            return

        try:
            vec = await self.intelligence.embed_document(text)
            await self.store.set_embedding(doc["_id"], vec)
            self._embed_failures = 0
        except Exception as exc:
            # Deliberately broad: the Voyage SDK raises undocumented types over
            # httpx, and every one of them -- auth, rate limit, timeout -- means
            # "retry the job", never "this document is unembeddable". Narrowing
            # here is how the queue got poisoned in the first place.
            await self._embed_failed(doc, exc)

    async def _embed_failed(self, doc: dict, exc: Exception) -> None:
        """Retry the job unless it has exhausted its attempts.

        An embedding call fails far more often for reasons outside the document
        -- an invalid key, a rate limit, a blip -- than because of the document
        itself. Those must not consume the job, or a single bad key silently
        empties the search index for good.
        """
        attempts = int(doc.get("embed_attempts", 0)) + 1
        self._embed_failures += 1

        if attempts >= MAX_EMBED_ATTEMPTS:
            log.error("giving up embedding document %s after %d attempts: %s",
                      doc.get("_id"), attempts, exc)
            await self.store.set_embedding(doc["_id"], None)
            return

        log.warning("embed attempt %d/%d failed for document %s: %s",
                    attempts, MAX_EMBED_ATTEMPTS, doc.get("_id"), exc)
        await self.store.release_claim("documents", doc["_id"])

    @property
    def _embed_pause(self) -> float:
        """Back off the whole loop after repeated failures, so a bad key costs a
        slow trickle of retries rather than a hot loop against the API.

        The engine's ``backoff`` is the same policy the job queue uses on a
        single document; reusing it keeps one curve rather than two that can
        drift apart unnoticed.
        """
        return backoff(self._embed_failures, self.poll_interval)

    # ---- GC worker -----------------------------------------------------

    async def gc_loop(self) -> None:
        """Reclaim stored objects when their documents disappear.

        A delete event *is* the GC signal -- including TTL expirations. All the
        hard parts (resume tokens, reconnection, stale-token recovery,
        unsupported deployments) live in the engine's Reactor; what stays here
        is the one thing that is about VOYD: which bucket key a deleted document
        was holding.
        """
        reactor = self.store.engine.reactor(
            name="voyd-gc",
            restore=self.store.get_resume_token,
            checkpoint=self.store.set_resume_token,
        )

        @reactor.on("delete", "documents")
        async def _document_deleted(change):
            await self._handle_delete(change)

        @reactor.on("delete", "voids")
        async def _void_deleted(change):
            await self._handle_delete(change)

        if getattr(self.store, "pre_images", None) is False:
            # Stated here too: without pre-images a delete event carries no key,
            # so this loop would run and reclaim nothing, forever.
            log.warning("gc worker started without change-stream pre-images: "
                        "R2 objects will not be reclaimed")

        self._reactor = reactor
        try:
            await reactor.run()
        finally:
            self._reactor = None

    async def _handle_delete(self, change: dict) -> None:
        coll = change.get("ns", {}).get("coll")
        pre = change.get("fullDocumentBeforeChange")
        if not pre:
            return  # no pre-image available -> cannot know the key
        if coll == "documents":
            key = pre.get("key")
            if key:  # inline documents have no blob to reclaim
                await self.storage.delete_key(key)
        elif coll == "voids":
            voyd = await self.store.db.voyds.find_one({"_id": pre.get("voyd_id")})
            if voyd:
                prefix = self.storage.void_prefix(voyd["slug"], pre["token"])
                await self.storage.delete_prefix(prefix)
