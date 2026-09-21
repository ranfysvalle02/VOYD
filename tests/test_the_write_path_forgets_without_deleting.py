"""`marks.py` -- the whole write side, and the shape the wire mirrors.

Reads refusing is half a product. The verb that *changes* reachability is the
other half. The proxy does not call this code -- it emits the same pipeline
itself, in `_forget_pipeline`, because a fact forgotten through the wire and
one forgotten here must be the same document afterwards. Two spellings that
produced different rows would be the drift this package is about, so this
file is what pins the shape both of them have to agree on.

Driven without `Engine`. The write path never needed the handle -- it needs
a database and a spec -- and a test that could only reach it through an
import would be a test of the import.

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
async def db():
    """A throwaway database, and nothing else.

    Built without the `Engine` handle on purpose. `marks.py` never needed
    one -- it needs a database and a spec -- and the handle was the front
    door this project is in the middle of removing. A test that could only
    reach the write path through an import is a test of the import.
    """
    from pymongo import AsyncMongoClient

    client = AsyncMongoClient(MONGO_URI)
    name = f"voyd_test_marks_{uuid.uuid4().hex[:8]}"
    try:
        yield client[name]
    finally:
        await client.drop_database(name)
        await client.close()


def _notes(db, *rules):
    """The admission handle for `notes`, built straight from a spec."""
    from voyd.engine import Deadline, revoked
    from voyd.engine.admission import Admission, AdmissionSpec

    return Admission(db, AdmissionSpec(
        "notes", rules=rules or (Deadline(), revoked())).with_defaults())


async def reachable(notes, db):
    """What a read would be given, without the read path's sugar."""
    return notes.reachable([d async for d in db.notes.find({})])


async def test_revoke_marks_and_does_not_delete(db):
    notes = _notes(db)
    await db.notes.insert_many([{"text": "keep"}, {"text": "forget"}])

    n = await notes.revoke({"text": "forget"}, reason="credential leaked")

    assert n == 1
    assert [d["text"] for d in await reachable(notes, db)] == ["keep"]
    assert await db.notes.count_documents({}) == 2, (
        "the row is the investigation; a revoke that deletes is a delete")
    row = await db.notes.find_one({"text": "forget"})
    assert row["forgotten"]["reason"] == "credential leaked"


async def test_the_deadline_only_moves_earlier(db):
    """A row due in a minute, revoked with a seven-day grace, must not have
    its erasure pushed out to seven days."""
    notes = _notes(db)
    soon = now() + timedelta(minutes=1)
    await db.notes.insert_one({"text": "due soon", "expire_at": soon})

    await notes.revoke({"text": "due soon"}, reason="erasure request",
                       erase_after=timedelta(days=7))

    row = await db.notes.find_one({"text": "due soon"})
    # The driver hands back a naive UTC datetime; compare like with like.
    got = row["expire_at"].replace(tzinfo=soon.tzinfo)
    assert got <= soon + timedelta(seconds=1), (
        "retention grew because somebody asked to be forgotten")


async def test_a_pinned_row_gets_a_deadline_rather_than_staying_pinned(db):
    """The case `$min` alone gets wrong: a missing deadline is a *pinned*
    row, and `$min` against null keeps the null -- leaving an erased fact
    pinned forever."""
    notes = _notes(db)
    await db.notes.insert_one({"text": "pinned"})

    await notes.revoke({"text": "pinned"}, reason="erasure request")

    row = await db.notes.find_one({"text": "pinned"})
    assert row["expire_at"] is not None


async def test_the_derived_encoding_is_destroyed_with_the_fact(db):
    """A vector is a lossy copy of the text that made it, and it does not
    wait for the reaper."""
    notes = _notes(db)
    await db.notes.insert_one(
        {"text": "leaked", "embedding": [0.1, 0.2, 0.3]})

    await notes.revoke({"text": "leaked"}, reason="leak")

    row = await db.notes.find_one({"text": "leaked"})
    assert row["embedding"] is None


async def test_a_quarantine_is_reversible_and_keeps_its_row_pinned(db):
    """A hold is a hypothesis, not an instruction. It must be liftable, and
    it must *not* schedule the reaper -- the row is the evidence."""
    from voyd.engine import Deadline, quarantined

    notes = _notes(db, Deadline(), quarantined())
    await db.notes.insert_one({"text": "suspicious"})

    await notes.quarantine({"text": "suspicious"}, reason="detector")
    assert await reachable(notes, db) == []
    row = await db.notes.find_one({"text": "suspicious"})
    assert row.get("expire_at") is None, (
        "a hold that schedules erasure destroys the evidence it was held for")

    await notes.release({"text": "suspicious"}, reason="cleared by review")
    assert [d["text"] for d in await reachable(notes, db)] == ["suspicious"]


async def test_a_revocation_cannot_be_lifted(db):
    """The rule decides, not the verb and not the caller. Re-admitting
    erased information is a new document with new provenance."""
    from voyd.engine import Irreversible

    notes = _notes(db)
    await db.notes.insert_one({"text": "gone"})
    await notes.revoke({"text": "gone"}, reason="erasure request")

    with pytest.raises(Irreversible):
        await notes.lift("revoked", {"text": "gone"}, reason="second thoughts")


async def test_an_unbounded_revoke_is_refused(db):
    """`revoke({})` would forget the collection. It has to be said out loud."""
    from voyd.engine import UnboundedForgetting

    notes = _notes(db)
    await db.notes.insert_one({"text": "a"})

    with pytest.raises(UnboundedForgetting):
        await notes.revoke({}, reason="oops")

    assert await notes.revoke({}, reason="deliberate", everything=True) == 1
