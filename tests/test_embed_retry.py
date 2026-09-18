"""Embedding failures must be retryable, or one bad key empties the boundary.

The failure mode this guards against is quiet and permanent: with a placeholder
Voyage key, the worker burned through every file marking each one
un-embeddable. Supplying a real key later fixed nothing, because no job was left
to claim -- and search inside every void stayed empty with no error anywhere.

A 429 is the world; a malformed document is the call. Conflating them is what
poisons the queue.
"""

from __future__ import annotations

import pytest

# Exercises the HTTP service's store and Ops worker; engine-only installs skip it.
pytest.importorskip("fastapi")

from bson import ObjectId

from voyd.ops import Ops
from voyd.store.mongo import MAX_EMBED_ATTEMPTS


class BrokenIntelligence:
    """Stands in for an invalid API key: fails every call, like a real auth error."""

    class config:
        max_input_chars = 32_000
        dimensions = 1024

    def __init__(self):
        self.calls = 0

    async def embed_document(self, text):
        self.calls += 1
        raise RuntimeError("Provided API key is invalid.")


class FakeStorage:
    """The bytes are in R2 in production; here they are a dict. The worker only
    ever asks for a bounded text window, which is the whole coupling."""

    def __init__(self, text="brake pad replacement"):
        self.text = text

    async def get_text_window(self, key, max_bytes=None):
        return self.text


async def seed_job(store, name="notes.txt"):
    res = await store.db.documents.insert_one({
        "voyd_id": ObjectId(), "token": "tok", "doc_id": ObjectId().binary.hex(),
        "name": name, "key": f"k/{name}", "mime": "text/plain",
        "indexed": False, "embedding": None,
    })
    return res.inserted_id


async def test_a_failed_embed_is_retried_not_consumed(app):
    store = app.store
    ops = Ops(store, FakeStorage(), BrokenIntelligence())
    job_id = await seed_job(store)

    assert await ops._embed_tick() is True
    doc = await store.db.documents.find_one({"_id": job_id})
    assert doc["indexed"] is False, "job must go back on the queue"
    assert doc["embed_attempts"] == 1


async def test_a_valid_key_later_backfills_what_the_bad_key_failed(app):
    """The point of the whole fix."""
    store = app.store
    job_id = await seed_job(store)

    broken = Ops(store, FakeStorage(), BrokenIntelligence())
    await broken._embed_tick()
    failed = await store.db.documents.find_one({"_id": job_id})
    assert failed["indexed"] is False and failed["embedding"] is None

    class Working(BrokenIntelligence):
        async def embed_document(self, text):
            return [0.5] * 1024

    await Ops(store, FakeStorage(), Working())._embed_tick()
    doc = await store.db.documents.find_one({"_id": job_id})
    assert doc["indexed"] is True
    assert doc["embedding"] == [0.5] * 1024


async def test_a_hopeless_job_is_eventually_parked(app):
    """Retrying must be bounded, or one poisoned document blocks the queue."""
    store = app.store
    ops = Ops(store, FakeStorage(), BrokenIntelligence())
    job_id = await seed_job(store)

    for _ in range(MAX_EMBED_ATTEMPTS + 2):
        await ops._embed_tick()

    doc = await store.db.documents.find_one({"_id": job_id})
    assert doc["indexed"] == "error", "parked, not retried forever"
    assert ops.intelligence.calls <= MAX_EMBED_ATTEMPTS


async def test_empty_text_is_permanent_not_retried(app):
    """Nothing to embed is the document's own property: no point retrying."""
    store = app.store
    ops = Ops(store, FakeStorage(text="   "), BrokenIntelligence())
    job_id = await seed_job(store, name="blank.txt")

    assert await ops._embed_tick() is True
    doc = await store.db.documents.find_one({"_id": job_id})
    assert doc["indexed"] == "error"
    assert ops.intelligence.calls == 0, "must not call the API at all"


async def test_repeated_failures_back_off(app):
    ops = Ops(app.store, FakeStorage(), BrokenIntelligence(), poll_interval=2.0)
    assert ops._embed_pause == 2.0
    ops._embed_failures = 5
    assert ops._embed_pause > 2.0
    ops._embed_failures = 99
    assert ops._embed_pause == 60.0, "bounded"
