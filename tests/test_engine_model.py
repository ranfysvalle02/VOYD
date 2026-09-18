"""ModelController: one collection, tenant threaded, traits on the handle.

If these tests need eight Spec constructors to say the same thing, then
``model()`` did not earn its place. A real app should be able to declare
everything it needs on ``engine.model()``.
"""

from __future__ import annotations

import asyncio
import random
from datetime import timedelta

import pytest
from bson import ObjectId

DIMS = 8


def vec(seed: int) -> list[float]:
    random.seed(seed)
    return [random.random() for _ in range(DIMS)]


async def search_when_indexed(app, collection, vector, *, timeout=25.0, **kw):
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        hits = await app.search(collection, vector, **kw)
        if hits:
            return hits
        await asyncio.sleep(0.5)
    pytest.fail(f"mongot did not index {collection} within {timeout}s")


# ``core`` is a bare Engine on a vanilla client, from ``conftest``. The point of
# this file is that a recipes app lives on ``engine.model()`` -- so it takes the
# same throwaway Engine any stranger would.


async def test_model_is_enough_to_declare_hybrid_search(core):
    app, db = core
    app.model("recipes", tenant="kitchen_id").searchable(
        vector_path="vector", dimensions=DIMS, text_paths=("title", "body"))
    await app.ensure(search_wait_s=60)

    kid = ObjectId()
    await db.recipes.insert_one({
        "kitchen_id": kid, "title": "P0301 misfire stew",
        "body": "when cold", "vector": vec(1),
    })
    hits = await search_when_indexed(
        app, "recipes", vec(9), text="P0301", filters={"kitchen_id": kid})
    assert hits and "P0301" in hits[0]["title"]


async def test_model_threads_tenant_so_search_cannot_walk(core):
    app, db = core
    app.model("recipes", tenant="kitchen_id").searchable(
        vector_path="vector", dimensions=DIMS, text_paths=("title",))
    await app.ensure(search_wait_s=60)

    a, b = ObjectId(), ObjectId()
    await db.recipes.insert_many([
        {"kitchen_id": a, "title": "secret", "vector": vec(2)},
        {"kitchen_id": b, "title": "other", "vector": vec(2)},
    ])
    await search_when_indexed(app, "recipes", vec(2), filters={"kitchen_id": a})
    leaked = await app.search("recipes", vec(2), filters={"kitchen_id": b})
    assert all(h["kitchen_id"] == b for h in leaked)
    assert all(h["title"] != "secret" for h in leaked)


async def test_model_memory_is_search_plus_ttl(core):
    app, _ = core
    mem = app.model("memories", tenant="session").memory(
        dimensions=DIMS, default_ttl=timedelta(hours=1))
    await app.ensure(search_wait_s=60)

    await mem.remember("s1", "the code is E_QUOTA_429", vec(3))
    deadline = asyncio.get_running_loop().time() + 25
    hits = []
    while asyncio.get_running_loop().time() < deadline:
        hits = await mem.recall("s1", vec(9), text="E_QUOTA_429")
        if hits:
            break
        await asyncio.sleep(0.5)
    assert hits and "E_QUOTA_429" in hits[0]["text"]
    assert await mem.recall("s2", vec(3)) == []

