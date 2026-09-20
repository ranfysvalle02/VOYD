"""The engine does not inherit the caller's environment.

Every leak we have paid for is the same shape: a setting this project's own
web layer happened to have, that a stranger's client will not. URI heuristics.
Index readiness. Tenant field type. ``tz_aware``.

This file is the early-catch program. Construct Engine the way an agent
runtime would -- a default ``AsyncMongoClient``, no ``tz_aware``, no
FastAPI -- and assert the pinned settings hold. If a test here needs the web
layer's store to pass, the engine has leaked again.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from tests.conftest import TEST_MONGO_URI, _mongo_available
from tests.conftest import throwaway_db_name
from voyd.engine import Engine, aware, deadline, live, living, now
from voyd.engine.time import UTC, bind


# ---- unit: the clock, no I/O -------------------------------------------

def test_now_is_utc_aware():
    n = now()
    assert n.tzinfo is not None
    assert n.utcoffset() == timedelta(0)


def test_aware_stamps_naive_as_utc_and_converts_the_rest():
    naive = datetime(2026, 9, 17, 12, 0, 0)
    stamped = aware(naive)
    assert stamped.tzinfo is UTC
    assert stamped.hour == 12

    eastern = datetime(2026, 9, 17, 8, 0, 0, tzinfo=timezone(timedelta(hours=-4)))
    assert aware(eastern) == datetime(2026, 9, 17, 12, 0, 0, tzinfo=UTC)
    assert aware(None) is None


def test_live_fails_closed_on_garbage_and_keeps_pinned():
    """A TypeError here is how a forgotten fact used to skip the filter."""
    assert live({}) is True
    assert live({"expire_at": None}) is True
    assert live({"expire_at": "tomorrow"}) is False
    assert live({"expire_at": 1}) is False

    future = now() + timedelta(hours=1)
    past = now() - timedelta(minutes=5)
    assert live({"expire_at": future}) is True
    assert live({"expire_at": past}) is False
    naive_past = datetime.now(UTC).replace(tzinfo=None) - timedelta(minutes=5)
    assert live({"expire_at": naive_past}) is False


def test_living_is_the_query_ttl_is_not():
    q = living("expire_at")
    assert "$or" in q
    assert {"expire_at": None} in q["$or"]
    assert any(
        isinstance(clause.get("expire_at"), dict) and "$gt" in clause["expire_at"]
        for clause in q["$or"]
    )


def test_deadline_none_is_pinned():
    assert deadline(None) is None
    d = deadline(timedelta(hours=1))
    assert d is not None and d > now()


# ---- integration: a stranger's client ----------------------------------

@pytest.fixture
async def vanilla_engine():
    """Engine on a vanilla client. This is the test that would have caught
    the tz_aware leak: the web layer's store sets tz_aware=True."""
    if not await _mongo_available(TEST_MONGO_URI):
        pytest.skip(f"no MongoDB at {TEST_MONGO_URI}")

    from pymongo import AsyncMongoClient

    raw = AsyncMongoClient(TEST_MONGO_URI)
    # core_ so conftest's leaked-database sweep covers it.
    # Via the shared helper: the sweep in conftest reads the timestamp
    # this puts in the name to tell an abandoned database from one a
    # concurrent run is using.
    name = throwaway_db_name("core_")
    handed = raw[name]
    engine = Engine(raw, handed)
    await engine.connect()
    try:
        yield engine, raw, handed
    finally:
        await raw.drop_database(name)
        await raw.close()


async def test_engine_pins_utc_without_mutating_the_caller(vanilla_engine):
    engine, raw, handed = vanilla_engine
    assert engine.db is not handed, "bind must be a new handle"
    assert engine.db.name == handed.name
    assert engine.db.codec_options.tz_aware is True
    assert engine.db.codec_options.tzinfo == UTC
    assert handed.codec_options.tz_aware is False, "caller stays naive"
    assert raw.codec_options.tz_aware is False
    again = bind(engine.db)
    assert again.codec_options.tz_aware is True


async def test_health_announces_the_clock(vanilla_engine):
    engine, _, _ = vanilla_engine
    assert engine.health()["time"] == {"tz": "UTC", "aware": True}


async def test_roundtrip_datetimes_are_aware_on_a_naive_client(vanilla_engine):
    """The crash: naive decode vs aware now(). The fix: engine.db."""
    engine, raw, handed = vanilla_engine
    await engine.db.ticks.insert_one({"created_at": now(), "n": 1})

    via_engine = await engine.db.ticks.find_one({"n": 1})
    assert via_engine["created_at"].tzinfo is not None
    assert via_engine["created_at"].utcoffset() == timedelta(0)

    via_caller = await handed.ticks.find_one({"n": 1})
    assert via_caller["created_at"].tzinfo is None, (
        "the caller's handle is still naive -- we did not mutate them")


async def test_recall_on_a_vanilla_client_does_not_crash(vanilla_engine):
    engine, _, _ = vanilla_engine
    mem = engine.model("memories", tenant="session").memory(
        dimensions=8, default_ttl=timedelta(hours=1))
    await engine.ensure(search_wait_s=60)

    vec = [0.2] * 8
    stored = await mem.remember("s1", "vanilla client memory", vec)
    assert stored["created_at"].tzinfo is not None
    assert stored["expire_at"].tzinfo is not None

    doc = await engine.db.memories.find_one({"_id": stored["_id"]})
    assert doc["expire_at"].tzinfo is not None
    assert live(doc) is True

    hits = await mem.recall("s1", vec)
    assert isinstance(hits, list)
