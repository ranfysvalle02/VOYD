"""The central claim, pinned down: a deadline is enforced twice.

``examples/forget.py`` demonstrates it and ``voyd/engine/time.py`` asserts it in
a docstring. Neither is a regression test, and the first of the two deadlines is
the one a future refactor will quietly remove -- the ``expire_at`` filter in
``recall()`` looks redundant next to the TTL index, and it is not:

1. **The query refuses an expired memory immediately.** MongoDB's TTL monitor
   runs about once a minute, so an expired document stays physically on disk for
   a window after its deadline. During that window ``recall()`` must already
   refuse it. That property needs no reaper and no sleeping, so the tests for it
   here do neither.
2. **Then the reaper takes the row, and the embedding goes with it** -- one
   document, one ``expire_at``, never a row plus a separate vector. Only that
   last test waits, and it polls with a bounded timeout.

Same rule as the rest of the engine suite: nothing from ``voyd`` except
``voyd.engine``, on the bare ``core`` Engine a stranger would get.
"""

from __future__ import annotations

import asyncio
import random
from datetime import datetime, timedelta, timezone

import pytest

from voyd.engine import live, living, now

DIMS = 8

SCOPE = "sess-deadline"
DOOMED = "the fault code is P0301"
PINNED = "the user's name is Dana"


def vec(seed: int) -> list[float]:
    random.seed(seed)
    return [random.random() for _ in range(DIMS)]


async def _memory_with_two(core, *, ttl=timedelta(hours=1)):
    """One collection, two memories: one with a deadline, one pinned forever.

    Returns the ``Memory`` handle once *both* are actually searchable -- an
    index that is still building must never be mistaken for an empty one, or
    "recall refused it" would pass for the wrong reason.
    """
    engine, db = core
    mem = engine.model("memories", tenant="scope").memory(
        default_ttl=ttl, dimensions=DIMS)
    await engine.ensure(search_wait_s=60)

    await mem.remember(SCOPE, DOOMED, vec(1))
    await mem.remember(SCOPE, PINNED, vec(1), pinned=True)

    deadline = asyncio.get_running_loop().time() + 30
    while asyncio.get_running_loop().time() < deadline:
        hits = await mem.recall(SCOPE, vec(1), text="P0301")
        if len(hits) == 2:
            return mem, db
        await asyncio.sleep(0.5)
    pytest.fail("mongot did not index the memories within 30s")


# --------------------------------------------------------------------------
# deadline 1: the query, with no reaper involved at all
# --------------------------------------------------------------------------

async def test_an_expired_memory_is_unreachable_while_its_row_is_still_on_disk(core):
    """THE WINDOW. The whole thesis, and the thing most easily refactored away.

    The deadline is moved into the past directly, so nothing waits and nothing
    depends on ``ttlMonitorSleepSecs``: the row is *provably* still present
    (``count_documents`` says 2) at the moment ``recall()`` already refuses it.
    """
    mem, db = await _memory_with_two(core)
    # Opt this database out of the reaper entirely. The window between the
    # update and the assertion is milliseconds, which against a 60s sweep is
    # about one run in fourteen thousand and was rightly left alone -- but
    # another test in this suite turns ``ttlMonitorSleepSecs`` down to 1 for
    # its own purposes, and under ``pytest -n`` that now runs *concurrently*
    # with this one. Same window, sixty times the sweep rate, by design
    # rather than by accident. The database is this test's own and is dropped
    # afterwards, so this reaches nothing else.
    await db.memories.drop_index("expire_at_1")

    await db.memories.update_one(
        {"text": DOOMED},
        {"$set": {"expire_at": now() - timedelta(minutes=5)}})

    # Physically present: the reaper has not run, and must not need to have.
    assert await db.memories.count_documents({}) == 2
    assert await db.memories.count_documents({"text": DOOMED}) == 1

    texts = {h["text"] for h in await mem.recall(SCOPE, vec(1), text="P0301")}
    assert DOOMED not in texts, (
        "an expired memory is still answering queries -- the expire_at filter "
        "in recall() is not redundant with the TTL index")


async def test_a_pinned_sibling_survives_the_expired_memory_beside_it(core):
    """The deadline is per document, not a collection-wide wipe.

    Same collection, same scope, same index. Pinning is the *absence* of a
    deadline, so this is what makes "for an hour" and "forever" one storage
    path instead of two subsystems.
    """
    mem, db = await _memory_with_two(core)

    await db.memories.update_one(
        {"text": DOOMED},
        {"$set": {"expire_at": now() - timedelta(minutes=5)}})

    texts = {h["text"] for h in await mem.recall(SCOPE, vec(1), text="Dana")}
    assert PINNED in texts
    assert DOOMED not in texts

    pinned_doc = await db.memories.find_one({"text": PINNED})
    assert pinned_doc["expire_at"] is None, "pinned is a null deadline"


async def test_a_garbage_deadline_is_refused_by_recall_not_served(core):
    """Fail closed: an ``expire_at`` that is not a date is treated as expired.

    The failure this prevents is the interesting one -- a malformed deadline
    that raises inside the filter, or worse skips it, and reaches a prompt.
    """
    mem, db = await _memory_with_two(core)

    await db.memories.update_one(
        {"text": DOOMED}, {"$set": {"expire_at": "next tuesday"}})

    assert await db.memories.count_documents({"text": DOOMED}) == 1
    texts = {h["text"] for h in await mem.recall(SCOPE, vec(1), text="P0301")}
    assert DOOMED not in texts, "a memory with an unreadable deadline was served"


# --------------------------------------------------------------------------
# the predicate itself: what "fail closed" actually means. no database.
# --------------------------------------------------------------------------

def test_an_absent_or_null_deadline_is_pinned_forever():
    """The property pinning is built on, so it is asserted rather than assumed."""
    assert live({}) is True
    assert live({"expire_at": None}) is True
    assert live({"other": 1}, "expire_at") is True


def test_a_future_deadline_lives_and_a_past_one_does_not():
    assert live({"expire_at": now() + timedelta(seconds=1)}) is True
    assert live({"expire_at": now() - timedelta(seconds=1)}) is False


def test_a_naive_deadline_is_read_as_utc_rather_than_raising():
    """BSON Date has no zone and a default client decodes it naive. Comparing
    that to an aware ``now()`` raises -- which is how a forgotten fact used to
    skip the filter entirely."""
    stamp = now().replace(tzinfo=None)
    naive_past = stamp - timedelta(hours=1)
    naive_future = stamp + timedelta(hours=1)
    assert live({"expire_at": naive_past}) is False
    assert live({"expire_at": naive_future}) is True


@pytest.mark.parametrize("garbage", [
    "next tuesday", "", 0, 1_700_000_000, 1.5, [], {}, True, b"\x00",
])
def test_a_deadline_that_is_not_a_datetime_fails_closed(garbage):
    """Not a date means dead, and never an exception."""
    assert live({"expire_at": garbage}) is False


@pytest.mark.parametrize("unshiftable", [
    # A *valid* datetime that cannot be moved to UTC: the shift runs off the
    # end of the representable range. These raised OverflowError, which was
    # not in live()'s except clause, so "never raise" was not quite true.
    datetime.max.replace(tzinfo=timezone(timedelta(hours=-14))),
    datetime.min.replace(tzinfo=timezone(timedelta(hours=14))),
])
def test_a_deadline_that_cannot_be_shifted_to_utc_fails_closed(unshiftable):
    """The other kind of unreadable deadline: a real datetime, still unusable.

    Stored BSON is always UTC millis, so this does not arrive from the
    database -- but ``live()`` is public API and callers apply it to their own
    dicts. A crash in the deadline check is how an expired fact skips the
    filter, so the answer is False (dead), not an exception.
    """
    assert live({"expire_at": unshiftable}) is False


@pytest.mark.parametrize("extreme, expected", [
    (datetime.max.replace(tzinfo=timezone.utc), True),   # the far future is live
    (datetime.max, True),                                # naive is read as UTC
    (datetime.min.replace(tzinfo=timezone.utc), False),  # the far past is dead
    (datetime.min, False),
])
def test_the_representable_extremes_are_still_answered_not_refused(extreme, expected):
    """Fail-closed must not become fail-always.

    ``datetime.max`` in UTC is a legitimate way to say "pinned"; it has to
    keep meaning live, or the fix above would have quietly made every
    far-future deadline expire.
    """
    assert live({"expire_at": extreme}) is expected


def test_live_accepts_an_explicit_instant_so_the_window_is_testable():
    at = datetime(2020, 1, 1, tzinfo=timezone.utc)
    assert live({"expire_at": at + timedelta(days=1)}, when=at) is True
    assert live({"expire_at": at - timedelta(days=1)}, when=at) is False


def test_the_query_fragment_admits_pinned_and_excludes_expired():
    """``living()`` says the same thing to the database that ``live()`` says in
    Python: null and missing are pinned, anything not yet due is live."""
    at = datetime(2020, 1, 1, tzinfo=timezone.utc)
    frag = living(when=at)
    clauses = frag["$or"]
    assert {"expire_at": None} in clauses
    assert {"expire_at": {"$exists": False}} in clauses
    assert {"expire_at": {"$gt": at}} in clauses


async def test_the_query_fragment_agrees_with_the_predicate_on_a_real_server(core):
    """Two enforcement points, one answer -- checked against MongoDB itself."""
    _, db = core
    past, future = now() - timedelta(hours=1), now() + timedelta(hours=1)
    await db.deadlines.insert_many([
        {"_id": "pinned_null", "expire_at": None},
        {"_id": "pinned_absent"},
        {"_id": "future", "expire_at": future},
        {"_id": "past", "expire_at": past},
    ])
    matched = {d["_id"] async for d in db.deadlines.find(living())}
    assert matched == {"pinned_null", "pinned_absent", "future"}

    in_python = {d["_id"] async for d in db.deadlines.find() if live(d)}
    assert in_python == matched


# --------------------------------------------------------------------------
# deadline 2: the reaper. the only test here that waits.
# --------------------------------------------------------------------------

async def test_the_embedding_leaves_with_the_document_when_the_reaper_runs(core):
    """No orphaned vectors: the row and its embedding are one document.

    Needs the real TTL monitor, so it turns ``ttlMonitorSleepSecs`` down to 1
    and restores the previous value in a ``finally``. A managed cluster refuses
    ``setParameter``; that is a skip, not a failure.
    """
    _, db = core
    admin = db.client.admin
    try:
        res = await admin.command({"setParameter": 1, "ttlMonitorSleepSecs": 1})
    except Exception as exc:  # noqa: BLE001 - managed clusters refuse this
        pytest.skip(f"server will not speed up the TTL monitor: {exc}")
    was = res.get("was", 60)

    try:
        mem, _ = await _memory_with_two(core, ttl=timedelta(seconds=3))

        vectors = {"embedding": {"$ne": None}}
        assert await db.memories.count_documents(vectors) == 2

        deadline = asyncio.get_running_loop().time() + 30
        while asyncio.get_running_loop().time() < deadline:
            if await db.memories.count_documents({"text": DOOMED}) == 0:
                break
            await asyncio.sleep(0.5)
        else:
            pytest.fail("the TTL monitor did not reap the expired memory in 30s")

        # The row went, and its embedding went with it -- not a row here and a
        # vector there.
        assert await db.memories.count_documents({}) == 1
        assert await db.memories.count_documents(vectors) == 1
        assert await db.memories.count_documents(
            {"text": DOOMED, "embedding": {"$exists": True}}) == 0

        survivors = {h["text"] for h in await mem.recall(SCOPE, vec(1))}
        assert survivors == {PINNED}, "the reaper took more than its deadline"
    finally:
        try:
            await admin.command({"setParameter": 1, "ttlMonitorSleepSecs": was})
        except Exception:  # noqa: BLE001 - best effort; it is a local knob
            pass
