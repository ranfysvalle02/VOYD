"""Forgetting a fact must forget the paragraph written out of it.

This is the hole the rest of the package left open, and it is the one that
matters most, because it defeats the guarantee using the guarantee's own
storage. An agent retrieves a document, summarises it, and writes the summary
back into the same collection. Later somebody asks for the source to be
erased. ``revoke()`` honours that request perfectly -- against the source.
The summary, which quotes it, keeps scoring well forever.

So the erasure is satisfied and the information is not gone, and every
receipt in the system says the system worked.

The fix costs **no new read-path rule**, which is the part worth noticing:
``revoked()`` already refuses any document carrying the mark. What was
missing is that the mark did not *travel*. ``derive()`` records what a
document was made out of, transitively closed at write time, and the
forgetting verbs carry the mark down the edge -- so propagation is one extra
``$in`` at any depth rather than a recursive walk.

The other half is the write side: you cannot derive a new document from one
that is already refused. Without it, the race is trivial -- revoke at 14:02,
write the summary at 14:03, and the contamination is clean.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from voyd.engine import (REVOKED, Clearance, Deadline,
                         DerivationBroken, UnknownReason, now, quarantined,
                         revoked)


def lineaged(engine, *, tenant="t", rules=None):
    return engine.model("notes", tenant=tenant).admitting(
        *(rules or (Deadline(), revoked(), quarantined())),
        lineage_field="lineage")


async def source(db, tenant="a", **kw):
    row = {"t": tenant, **kw}
    return (await db.notes.insert_one(row)).inserted_id


# ---- the chain of custody --------------------------------------------

async def test_erasing_a_source_erases_what_was_written_out_of_it(core):
    """The headline, at depth.

    A summary of a summary of a diagnosis is still the diagnosis, and a
    system that forgets only the first link has not forgotten anything.
    """
    engine, db = core
    notes = lineaged(engine)
    await engine.ensure(search_wait_s=0)

    diagnosis = await source(db, text="alice's diagnosis")
    summary, = await notes.derive({"t": "a", "text": "patient summary"},
                                  parents=[diagnosis])
    briefing, = await notes.derive({"t": "a", "text": "ward briefing"},
                                   parents=[summary])
    unrelated = await source(db, text="the fault code is P0301")

    assert len(await notes.find({"t": "a"})) == 4

    n = await notes.revoke({"t": "a", "_id": diagnosis}, reason="subject erasure request")
    assert n == 3, "the source and both generations downstream of it"

    reachable = [d["_id"] for d in await notes.find({"t": "a"})]
    assert reachable == [unrelated]
    assert briefing not in reachable, \
        "a summary of a summary is still the fact somebody asked to erase"


async def test_lineage_is_closed_at_write_time_not_walked_at_revoke_time(core):
    """Why propagation is one query instead of a recursive descent.

    A child's lineage is its parent's lineage plus the parent, so a
    grandchild already names the grandparent. Derivation only ever grows
    forwards, so the closure cannot go stale.
    """
    engine, db = core
    notes = lineaged(engine)
    await engine.ensure(search_wait_s=0)

    a = await source(db, text="a")
    b, = await notes.derive({"t": "a", "text": "b"}, parents=[a])
    c, = await notes.derive({"t": "a", "text": "c"}, parents=[b])

    assert (await db.notes.find_one({"_id": b}))["lineage"] == [a]
    assert sorted((await db.notes.find_one({"_id": c}))["lineage"], key=str) \
        == sorted([a, b], key=str), "the grandchild names the grandparent"


async def test_either_parent_is_enough_to_forget_the_child(core):
    """A synthesis of two facts is refused when *either* is erased.

    The tempting alternative -- refuse only when every source is gone -- is
    how a document survives by having been made out of two things.
    """
    engine, db = core
    notes = lineaged(engine)
    await engine.ensure(search_wait_s=0)

    left = await source(db, text="left")
    right = await source(db, text="right")
    merged, = await notes.derive({"t": "a", "text": "merged"},
                                 parents=[left, right])

    await notes.revoke({"t": "a", "_id": right}, reason="retracted")
    assert merged not in [d["_id"] for d in await notes.find({"t": "a"})]


async def test_a_descendant_is_scheduled_for_the_reaper_too(core):
    """Unreachable first, erased second -- for the whole subtree, or the
    bytes of the thing somebody asked to erase outlive the erasure."""
    engine, db = core
    notes = lineaged(engine)
    await engine.ensure(search_wait_s=0)

    src = await source(db, text="source")
    child, = await notes.derive({"t": "a", "text": "child"}, parents=[src])
    await notes.revoke({"t": "a", "_id": src}, reason="leaked")

    row = await db.notes.find_one({"_id": child})
    assert row is not None, "still on disk, as always"
    assert row["expire_at"] <= now()


async def test_a_derived_fact_cannot_outlive_what_it_was_made_of(core):
    """A summary of a fact that expires on Tuesday has no business
    outliving it. The earliest parent deadline wins, and a shorter one the
    caller set deliberately is never overwritten."""
    engine, db = core
    notes = lineaged(engine)
    await engine.ensure(search_wait_s=0)

    soon = await source(db, text="soon", expire_at=now() + timedelta(hours=1))
    late = await source(db, text="late", expire_at=now() + timedelta(days=30))
    child, = await notes.derive({"t": "a", "text": "child"},
                                parents=[soon, late])
    assert (await db.notes.find_one({"_id": child}))["expire_at"] \
        == (await db.notes.find_one({"_id": soon}))["expire_at"]

    own = now() + timedelta(minutes=5)
    shorter, = await notes.derive({"t": "a", "text": "shorter",
                                   "expire_at": own}, parents=[late])
    # Compared as a window, not an instant: BSON dates are milliseconds and
    # ``now()`` is microseconds, so an equality here fails on rounding
    # rather than on behaviour.
    kept = (await db.notes.find_one({"_id": shorter}))["expire_at"]
    assert abs((kept - own).total_seconds()) < 1, \
        "a deadline the caller set deliberately is shorter, so it stands"


# ---- the write side: you cannot build on a refused fact ---------------

async def test_deriving_from_a_refused_parent_raises(core):
    """Closes the trivial race: revoke at 14:02, summarise at 14:03.

    It refuses rather than writing-and-marking, because both ways of
    reaching here are bugs worth surfacing -- something read a document it
    should not have been handed, or derived from a handle that never
    checked.
    """
    engine, db = core
    notes = lineaged(engine)
    await engine.ensure(search_wait_s=0)

    src = await source(db, text="secret")
    await notes.revoke({"t": "a", "_id": src}, reason="credential leaked")

    with pytest.raises(DerivationBroken) as caught:
        await notes.derive({"t": "a", "text": "summary"}, parents=[src])
    assert "erasure gets defeated by a summary" in str(caught.value)
    assert await db.notes.count_documents({"text": "summary"}) == 0


async def test_deriving_from_a_held_parent_raises_too(core):
    """A quarantine is "this may not reach a prompt" for now, and work
    built on it inherits the doubt rather than escaping it."""
    engine, db = core
    notes = lineaged(engine)
    await engine.ensure(search_wait_s=0)

    src = await source(db, text="suspicious")
    await notes.quarantine({"t": "a", "_id": src}, reason="injection detector")

    with pytest.raises(DerivationBroken):
        await notes.derive({"t": "a", "text": "summary"}, parents=[src])


async def test_deriving_from_a_foreign_or_missing_parent_raises(core):
    """Reported identically on purpose: splitting "gone" from "forbidden"
    tells an unprivileged caller which ids exist."""
    engine, db = core
    notes = lineaged(engine)
    await engine.ensure(search_wait_s=0)
    theirs = await source(db, tenant="b", text="another tenant's")

    with pytest.raises(DerivationBroken):
        await notes.derive({"t": "a", "text": "x"}, parents=[theirs])


async def test_deriving_from_a_parent_above_your_clearance_raises(core):
    """Otherwise ``derive`` is a laundering step: read nothing, write a
    child of it, and the child carries no classification at all."""
    engine, db = core
    order = ("public", "internal", "secret")
    notes = engine.model("notes", tenant="t").admitting(
        Deadline(), revoked(), Clearance(order=order), lineage_field="lineage")
    await engine.ensure(search_wait_s=0)
    classified = await source(db, text="the plan", classification="secret")

    junior = notes.for_caller({"clearance": "public"})
    with pytest.raises(DerivationBroken):
        await junior.derive({"t": "a", "text": "gist",
                             "classification": "public"}, parents=[classified])


async def test_derive_needs_a_parent_and_a_declared_lineage_field(core):
    engine, db = core
    await engine.ensure(search_wait_s=0)

    plain = engine.model("plain", tenant="t").forgettable()
    with pytest.raises(UnknownReason):
        await plain.derive({"t": "a"}, parents=["whatever"])

    notes = lineaged(engine)
    with pytest.raises(ValueError, match="at least one parent"):
        await notes.derive({"t": "a"}, parents=[])


# ---- holds travel too, and so does releasing them ---------------------

async def test_a_hold_travels_and_so_does_the_release(core):
    """Symmetry falls out of putting propagation on the general verbs
    rather than on ``revoke``: a review that clears a document and leaves
    its summaries withheld has not finished."""
    engine, db = core
    notes = lineaged(engine)
    await engine.ensure(search_wait_s=0)

    src = await source(db, text="flagged")
    child, = await notes.derive({"t": "a", "text": "summary"}, parents=[src])

    await notes.quarantine({"t": "a", "_id": src}, reason="injection detector")
    assert await notes.find({"t": "a"}) == []

    await notes.release({"t": "a", "_id": src}, reason="reviewed: benign")
    assert {d["_id"] for d in await notes.find({"t": "a"})} == {src, child}


# ---- the chain says how far it reached --------------------------------

async def test_the_chain_records_direct_and_inherited_separately(core):
    """"You asked to erase 1 fact and 2 things made out of it went too" is
    the sentence an auditor needs, and one total cannot say it."""
    engine, db = core
    notes = lineaged(engine)
    chain = engine.ledger("refusals", tenant="t")
    notes.witnessed_by(chain)
    await engine.ensure(search_wait_s=0)

    src = await source(db, text="source")
    kid, = await notes.derive({"t": "a", "text": "kid"}, parents=[src])
    await notes.derive({"t": "a", "text": "grandkid"}, parents=[kid])

    await notes.revoke({"t": "a", "_id": src}, reason="subject request")

    entry = (await chain.entries(tenant="a"))[-1]
    assert entry["event"] == REVOKED
    assert entry["detail"] == {"direct": 1, "inherited": 2}
    assert (await chain.verify(tenant="a"))["intact"] is True


async def test_propagation_does_not_cross_the_tenant(core):
    """The boundary holds on the way down the edge as well.

    A lineage id is an ``_id``, which is unique, so this cannot leak by
    collision -- but the query is built from the tenant-scoped handle
    rather than from the id list alone, and that is the property being
    pinned.
    """
    engine, db = core
    notes = lineaged(engine)
    await engine.ensure(search_wait_s=0)

    mine = await source(db, tenant="a", text="mine")
    child, = await notes.derive({"t": "a", "text": "child"}, parents=[mine])
    # A row in another tenant that (impossibly, but assert it) claims mine.
    await db.notes.insert_one({"t": "b", "text": "theirs",
                               "lineage": [mine]})

    await notes.revoke({"t": "a", "_id": mine}, reason="scoped")
    theirs = await db.notes.find_one({"t": "b"})
    assert "forgotten" not in theirs, "propagation crossed the tenant boundary"
    assert (await db.notes.find_one({"_id": child}))["forgotten"] is not None


async def test_a_collection_without_lineage_is_untouched(core):
    """Opt-in: a collection of source facts has no lineage and should not
    pay a field, an index, or the extra query per revocation."""
    engine, db = core
    notes = engine.model("notes", tenant="t").forgettable()
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_many([{"t": "a", "doc_id": "d1"},
                                {"t": "a", "doc_id": "d2"}])

    assert await notes.revoke({"t": "a", "doc_id": "d1"}, reason="x") == 1
    assert len(await notes.find({"t": "a"})) == 1
    assert "lineage" not in await db.notes.find_one({"doc_id": "d2"})
