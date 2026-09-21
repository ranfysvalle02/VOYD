"""`marks.py` -- 639 lines, the whole write side, and the wire writes through it.

Reads refusing is half a product. The verb that *changes* reachability is the
other half, and since `on_delete="revoke"` every `deleteOne` from any driver
lands here. It had no tests.

Four properties, and each one is a way the write could be subtly wrong while
looking right:

- it marks rather than deletes, so the row survives for the investigation;
- the deadline only ever moves **earlier** -- retention that grows because
  somebody asked for erasure is the opposite of the thing being asked for;
- the derived encodings go immediately, because a vector beside an erased
  document is a copy of it in a coat;
- a revocation cannot be taken back and a quarantine can, and the rule
  decides which -- not the caller, and not the verb.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest

from voyd.engine.time import now

from .conftest import MONGO_URI

pymongo = pytest.importorskip("pymongo")


@pytest.fixture
async def engine():
    from pymongo import AsyncMongoClient

    from voyd import Engine

    client = AsyncMongoClient(MONGO_URI)
    name = f"voyd_test_marks_{uuid.uuid4().hex[:8]}"
    eng = Engine(client, client[name])
    await eng.connect()
    try:
        yield eng
    finally:
        await client.drop_database(name)
        await client.close()


async def test_revoke_marks_and_does_not_delete(engine):
    notes = engine.model("notes").forgettable()
    await engine.ensure(search_wait_s=0)
    await engine.db.notes.insert_many([{"text": "keep"}, {"text": "forget"}])

    n = await notes.revoke({"text": "forget"}, reason="credential leaked")

    assert n == 1
    assert [d["text"] for d in await notes.find({})] == ["keep"]
    assert await engine.db.notes.count_documents({}) == 2, (
        "the row is the investigation; a revoke that deletes is a delete")
    row = await engine.db.notes.find_one({"text": "forget"})
    assert row["forgotten"]["reason"] == "credential leaked"


async def test_the_deadline_only_moves_earlier(engine):
    """A row due in a minute, revoked with a seven-day grace, must not have
    its erasure pushed out to seven days."""
    notes = engine.model("notes").forgettable()
    await engine.ensure(search_wait_s=0)
    soon = now() + timedelta(minutes=1)
    await engine.db.notes.insert_one({"text": "due soon", "expire_at": soon})

    await notes.revoke({"text": "due soon"}, reason="erasure request",
                       erase_after=timedelta(days=7))

    row = await engine.db.notes.find_one({"text": "due soon"})
    # The driver hands back a naive UTC datetime; compare like with like.
    got = row["expire_at"].replace(tzinfo=soon.tzinfo)
    assert got <= soon + timedelta(seconds=1), (
        "retention grew because somebody asked to be forgotten")


async def test_a_pinned_row_gets_a_deadline_rather_than_staying_pinned(engine):
    """The case `$min` alone gets wrong: a missing deadline is a *pinned*
    row, and `$min` against null keeps the null -- leaving an erased fact
    pinned forever."""
    notes = engine.model("notes").forgettable()
    await engine.ensure(search_wait_s=0)
    await engine.db.notes.insert_one({"text": "pinned"})

    await notes.revoke({"text": "pinned"}, reason="erasure request")

    row = await engine.db.notes.find_one({"text": "pinned"})
    assert row["expire_at"] is not None


async def test_the_derived_encoding_is_destroyed_with_the_fact(engine):
    """A vector is a lossy copy of the text that made it, and it does not
    wait for the reaper."""
    notes = engine.model("notes").forgettable()
    await engine.ensure(search_wait_s=0)
    await engine.db.notes.insert_one(
        {"text": "leaked", "embedding": [0.1, 0.2, 0.3]})

    await notes.revoke({"text": "leaked"}, reason="leak")

    row = await engine.db.notes.find_one({"text": "leaked"})
    assert row["embedding"] is None


async def test_a_quarantine_is_reversible_and_keeps_its_row_pinned(engine):
    """A hold is a hypothesis, not an instruction. It must be liftable, and
    it must *not* schedule the reaper -- the row is the evidence."""
    from voyd.engine import Deadline, quarantined

    notes = engine.model("notes").admitting(Deadline(), quarantined())
    await engine.ensure(search_wait_s=0)
    await engine.db.notes.insert_one({"text": "suspicious"})

    await notes.quarantine({"text": "suspicious"}, reason="detector")
    assert await notes.find({}) == []
    row = await engine.db.notes.find_one({"text": "suspicious"})
    assert row.get("expire_at") is None, (
        "a hold that schedules erasure destroys the evidence it was held for")

    await notes.release({"text": "suspicious"}, reason="cleared by review")
    assert [d["text"] for d in await notes.find({})] == ["suspicious"]


async def test_a_revocation_cannot_be_lifted(engine):
    """The rule decides, not the verb and not the caller. Re-admitting
    erased information is a new document with new provenance."""
    from voyd.engine import Irreversible

    notes = engine.model("notes").forgettable()
    await engine.ensure(search_wait_s=0)
    await engine.db.notes.insert_one({"text": "gone"})
    await notes.revoke({"text": "gone"}, reason="erasure request")

    with pytest.raises(Irreversible):
        await notes.lift("revoked", {"text": "gone"}, reason="second thoughts")


async def test_an_unbounded_revoke_is_refused(engine):
    """`revoke({})` would forget the collection. It has to be said out loud."""
    from voyd.engine import UnboundedForgetting

    notes = engine.model("notes").forgettable()
    await engine.ensure(search_wait_s=0)
    await engine.db.notes.insert_one({"text": "a"})

    with pytest.raises(UnboundedForgetting):
        await notes.revoke({}, reason="oops")

    assert await notes.revoke({}, reason="deliberate", everything=True) == 1
