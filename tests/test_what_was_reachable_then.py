"""``as_of(t)`` — and the answer that has to be "unknown".

*"What did the model see when it said that?"* is the question after every
AI incident, and the only answer available until now was a log line held by
the party being asked.

Two things had to be true for this to mean anything, and only one of them
was. Every rule already took ``when=``. But ``Marked`` -- the rule behind
every revocation -- **ignored it**, treating any mark as eternal. So a
document revoked at 14:05 reported as unreachable at 14:02, and a system
reconstructing what a model was allowed to see would place the erasure
before the answer that quoted the fact. An exoneration built out of a bug.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest

from voyd.engine import (REACHABLE, REFUSED, UNKNOWN, Deadline, now,
                         quarantined, revoked)


async def revoked_at(core):
    """One document, revoked, and the instant before it happened."""
    engine, db = core
    notes = engine.model("notes", tenant="t").forgettable()
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_many([{"t": "a", "doc_id": "d1"},
                                {"t": "a", "doc_id": "d2"}])
    before = now()
    await asyncio.sleep(0.05)
    await notes.revoke({"t": "a", "doc_id": "d1"}, reason="erasure request")
    return notes, before


async def test_a_mark_refuses_from_its_own_timestamp_not_forever(core):
    """The bug at the centre of the feature. A revocation is an event with
    an instant, and the mark has always carried one."""
    notes, before = await revoked_at(core)

    assert {d["doc_id"] for d in await notes.find({"t": "a"})} == {"d2"}
    assert {d["doc_id"] for d in await notes.as_of(before).find({"t": "a"})} \
        == {"d1", "d2"}


async def test_both_halves_agree_under_as_of(core):
    """The query is the optimisation and the per-document check is the
    guarantee, and they have to describe the same set at any instant.

    The naive version fails exactly here: the per-document check compares
    the mark's ``at`` while the *query* drops every marked row
    unconditionally, server-side, before anything is examined. ``as_of``
    would return an empty page and read as a scope where nothing was ever
    reachable -- confident, wrong, and flattering.
    """
    engine, db = core
    notes, before = await revoked_at(core)
    past = notes.as_of(before)

    through_query = {d["doc_id"] for d in await past.find({"t": "a"})}
    raw = [d async for d in db.notes.find({"t": "a"})]
    per_document = {d["doc_id"] for d in past.for_tenant("a").reachable(raw, when=before)}

    assert through_query == per_document == {"d1", "d2"}


async def test_a_deadline_is_also_evaluated_at_the_instant(core):
    engine, db = core
    notes = engine.model("notes", tenant="t").forgettable()
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_one({"t": "a", "doc_id": "d1",
                               "expire_at": now() - timedelta(hours=1)})

    assert await notes.find({"t": "a"}) == []
    past = notes.as_of(now() - timedelta(hours=2))
    assert [d["doc_id"] for d in await past.find({"t": "a"})] == ["d1"]


# ---- the third answer --------------------------------------------------

async def test_reachability_is_three_valued_because_rows_get_erased(core):
    """The reason this returns a string and not a bool.

    A row the reaper has taken leaves nothing to answer from. Reporting
    that as "not reachable" would let a deployment clear itself of having
    served a fact by pointing at the absence of the evidence -- and a bool
    has nowhere to put ``unknown``, so every caller would default it to
    the flattering one.
    """
    notes, before = await revoked_at(core)

    verdict, why = await notes.reachability_at({"t": "a", "doc_id": "d1"},
                                               before)
    assert (verdict, why) == (REACHABLE, "")

    verdict, why = await notes.reachability_at({"t": "a", "doc_id": "d1"},
                                               now())
    # ``deadline``, not ``revoked``: a revocation also stamps the erase
    # deadline, and the first rule in declaration order is the one
    # reported -- which is the documented behaviour and the useful one,
    # since an operator wants to know the *soonest* reason a fact stopped
    # being reachable.
    assert (verdict, why) == (REFUSED, "deadline")

    verdict, why = await notes.reachability_at({"t": "a", "doc_id": "reaped"},
                                               before)
    assert verdict == UNKNOWN
    assert "may have been reachable and later erased" in why


async def test_as_of_is_a_lower_bound_and_says_so(core):
    """It answers from the rows that survive, so it always under-reports.
    Worth pinning: a caller who reads it as a reconstruction will conclude
    less was reachable than was."""
    engine, db = core
    notes = engine.model("notes", tenant="t").forgettable()
    await engine.ensure(search_wait_s=0)
    before = now()
    await db.notes.insert_one({"t": "a", "doc_id": "survivor"})

    # The reaped document is simply not there, and nothing distinguishes
    # that from never having existed.
    assert [d["doc_id"] for d in await notes.as_of(before).find({"t": "a"})] \
        == ["survivor"]
    assert "as_of" in type(notes).as_of.__doc__
    assert "lower bound" in type(notes).as_of.__doc__


async def test_a_hold_that_was_lifted_is_reachable_again_afterwards(core):
    """The mark is gone entirely after a release, so there is nothing to
    compare an instant against -- which is correct, and worth asserting
    because ``$unset`` versus null was a deliberate choice elsewhere."""
    engine, db = core
    notes = engine.model("notes", tenant="t").admitting(
        Deadline(), revoked(), quarantined())
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_one({"t": "a", "doc_id": "d1"})

    await notes.quarantine({"t": "a", "doc_id": "d1"}, reason="detector")
    held = now()
    await notes.release({"t": "a", "doc_id": "d1"}, reason="cleared")

    assert (await notes.reachability_at({"t": "a", "doc_id": "d1"},
                                        held))[0] == REACHABLE


async def test_a_mark_with_an_unreadable_timestamp_refuses_at_every_instant(
        core):
    """A mark is operator-written and this runs inside a filter. Failing
    closed is the same direction ``Deadline`` takes for a deadline it
    cannot parse."""
    engine, db = core
    notes = engine.model("notes", tenant="t").forgettable()
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_one({"t": "a", "doc_id": "d1",
                               "forgotten": {"reason": "hand-written"}})

    assert await notes.as_of(now() - timedelta(days=1)).find({"t": "a"}) == []


# ---- it composes with the receipt --------------------------------------

async def test_a_receipt_and_as_of_answer_the_question_together(core):
    """Neither half answers *"was this context legitimate at the time?"*
    alone: the receipt commits to an instant, and ``as_of`` is what
    reconstructs the scope at it."""
    engine, db = core
    notes = engine.model("notes", tenant="t").forgettable()
    notes.witnessed_by(engine.ledger("refusals", tenant="t"))
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_many([{"t": "a", "doc_id": "d1"},
                                {"t": "a", "doc_id": "d2"}])

    page = await notes.find({"t": "a"})
    receipt = await notes.receipt_for(page)
    await asyncio.sleep(0.05)
    await notes.revoke({"t": "a", "doc_id": "d1"}, reason="erasure")

    from voyd.engine.time import aware
    from datetime import datetime
    at = aware(datetime.fromisoformat(receipt["at"]))
    replayed = await notes.as_of(at).find({"t": "a"})

    assert {str(d["_id"]) for d in replayed} == set(receipt["admitted"]), \
        "the scope as it stood then must match what the receipt committed to"


@pytest.mark.parametrize("verdict", [REACHABLE, REFUSED, UNKNOWN])
def test_the_three_verdicts_are_distinct_strings(verdict):
    assert isinstance(verdict, str)
    assert len({REACHABLE, REFUSED, UNKNOWN}) == 3
