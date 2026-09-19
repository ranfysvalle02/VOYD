"""Background work, driven entirely by MongoDB state.

One loop, no external broker. The **embed worker** (``embed_loop``) is a
claim-based poller: a document with ``indexed: false`` *is* the job. It claims
one atomically, asks Voyage for an embedding, and writes it back. Claiming is
what makes it safe to run multiple replicas -- no queue, no broker, one
``find_one_and_update``.

There used to be a second loop. A change stream over ``voids``/``documents``
turned every delete -- including a TTL expiration -- into the signal to
reclaim the blob it pointed at. It went when the blob path did: with text
stored inline on the document, a deleted row has nothing left behind it to
collect, so the reaper is the whole of garbage collection.

A deployment that adopts ``auto_embed`` has no work here at all: mongot
produces the vectors, ``indexed: false`` never happens, and this loop finds
nothing to claim.
"""

from __future__ import annotations

import asyncio
import logging

from .engine.jobs import backoff
from .store.mongo import MAX_EMBED_ATTEMPTS, MongoStore
from .intelligence.voyage import VoyageIntelligence

log = logging.getLogger("voyd.ops")


class Ops:
    def __init__(self, store: MongoStore, intelligence: VoyageIntelligence,
                 *, poll_interval: float = 2.0):
        self.store = store
        self.intelligence = intelligence
        # Read once, here, rather than per document inside the try below.
        # That block catches everything on purpose -- the embedding SDK
        # raises undocumented types and every one of them means "retry" --
        # which also means a plain AttributeError in there would be
        # swallowed as a failed API call and retried forever. Config is read
        # where a mistake in it still looks like a mistake.
        self._model = getattr(intelligence.config, "model", None)
        self.poll_interval = poll_interval
        self._tasks: list[asyncio.Task] = []
        self._stop = asyncio.Event()
        self._embed_failures = 0

    def start(self) -> None:
        self._tasks = [asyncio.create_task(self.embed_loop(), name="voyd-embed")]

    async def stop(self) -> None:
        self._stop.set()
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
        """Embed one document. The text is on the row; there is nowhere else
        it could be."""
        text = doc.get("text")
        if not (text or "").strip():
            # Nothing to embed is a property of the document: permanent.
            await self.store.set_embedding(doc["_id"], None)
            return

        try:
            vec = await self.intelligence.embed_document(text)
            await self.store.set_embedding(doc["_id"], vec, model=self._model)
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
