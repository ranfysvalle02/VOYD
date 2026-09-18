"""Security, scale, resiliency -- fail closed, fail loud, don't pin work.

If a test here needs the app extra, the core leaked again.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from voyd.engine import JobQueue, Reactor, ScopeRequired
from voyd.engine.capabilities import Capabilities
from voyd.engine.errors import require_scope
from voyd.engine.search import SearchSpec
from voyd.engine.time import now

# ``core`` -- a bare Engine on a vanilla client -- comes from ``conftest``. These
# tests take it directly; the boundary is honest at the harness, not just the
# import graph.


def test_require_scope_raises_when_the_tenant_is_missing():
    with pytest.raises(ScopeRequired, match="kitchen_id"):
        require_scope("recipes", "kitchen_id", None)
    with pytest.raises(ScopeRequired):
        require_scope("recipes", "kitchen_id", {"kitchen_id": None})
    assert require_scope("recipes", None, None) == {}
    assert require_scope("recipes", "kitchen_id", {"kitchen_id": "a"}) == {
        "kitchen_id": "a"}


async def test_search_without_tenant_is_a_leak_and_is_refused(core):
    app, _ = core
    app.searchable(SearchSpec(
        collection="recipes", vector_path="vector", dimensions=8,
        tenant_field="kitchen_id", tenant_type="token"))
    await app.ensure(search_wait_s=0)
    with pytest.raises(ScopeRequired, match="kitchen_id"):
        await app.search("recipes", [0.1] * 8)
    assert app.health()["search"]["scope_refused"] >= 1


async def test_cosine_fallback_caps_instead_of_growing(core):
    app, db = core
    app.searchable(SearchSpec(
        collection="recipes", vector_path="vector", dimensions=8,
        tenant_field="kitchen_id", tenant_type="token"))
    app.search_engine.capabilities = Capabilities()  # no mongot
    app.search_engine.cosine_cap = 3
    kid = "k1"
    await db.recipes.insert_many([
        {"kitchen_id": kid, "vector": [0.1] * 8} for _ in range(8)
    ])
    hits = await app.search("recipes", [0.1] * 8, filters={"kitchen_id": kid})
    assert len(hits) <= 3
    assert app.search_engine.cosine_capped >= 1
    assert app.health()["search"]["cosine_capped"] >= 1


async def test_pending_jobs_are_not_handed_to_a_second_replica(core):
    """``when={indexed: {$ne: true}}`` used to match pending and double-claim."""
    _, db = core
    q = JobQueue(db=db, collection="jobs",
                 when={"indexed": {"$ne": True}}, max_attempts=3)
    await db.jobs.insert_one({"indexed": False})
    first = await q.claim()
    assert first is not None
    assert await q.claim() is None, "held job must not be claimed twice"
    await q.release(first)
    assert await q.claim() is not None


async def test_a_crashed_worker_does_not_pin_the_job_forever(core):
    _, db = core
    q = JobQueue(db=db, collection="jobs", when={"indexed": False},
                 visibility=timedelta(seconds=1))
    await db.jobs.insert_one({"indexed": False})
    held = await q.claim()
    assert await q.claim() is None
    await db.jobs.update_one(
        {"_id": held["_id"]},
        {"$set": {"claimed_at": now() - timedelta(seconds=30)}},
    )
    again = await q.claim()
    assert again is not None
    assert again["_id"] == held["_id"]


async def test_reactor_does_not_pretend_a_failed_handler_succeeded():
    r = Reactor(db=None, name="test")

    @r.on("delete", "documents")
    async def boom(_change):
        raise RuntimeError("gc failed")

    ok = await r._dispatch({
        "operationType": "delete",
        "ns": {"coll": "documents"},
        "_id": "tok-1",
    })
    assert ok is False


async def test_queue_ensure_builds_a_claim_index(core):
    app, db = core
    app.queue("jobs", when={"indexed": False})
    report = await app.ensure(search_wait_s=0)
    assert "jobs" in report["queue"]
    idx = await db.jobs.index_information()
    assert any("indexed" in str(v.get("key")) for v in idx.values())
