"""We erased document 7. What did we already say because of it?

That is the question an erasure request actually ends at, and until now this
package stopped one step short of it. ``Admission`` refuses the fact on the
next read. ``lineage`` carries the refusal to the rows written out of it. Both
of those live inside this database -- and the summary that went into a ticket,
the reply that was sent, the answer already sitting in somebody's inbox do
not. Nothing here can recall one. What ``ContextIndex`` does is make them
*findable*, which turns "we think that's contained" into a worklist with ids
in it.

The properties below are the ones that decide whether such a worklist can be
trusted, and most of them are about what the index **refuses** to do:

- it finds consequences one hop out and any number of hops out, because a
  consequence becomes a source the moment somebody works from it;
- it does not cross a tenant, because a use index that leaks is a map of one
  subject's data drawn for another;
- it records the same use twice as one record, because a retry after a
  timeout is the ordinary case and not a second thing that was said;
- it will not persist a record it cannot stand behind -- no read snapshot, no
  policy revision, no tenant, no named consequence -- because a record that
  looks like evidence and is not is worse than the absence it replaces;
- it stores ids and hashes and never text, because an index that quotes the
  paragraph it was asked to help forget is a new copy of that paragraph in a
  collection built to outlive the original;
- it fails loudly by default, because silence from this index is
  indistinguishable from "nothing was affected".
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from voyd.engine import (DIRECT, SOURCE, ContextIncomplete, ContextIndexSpec,
                         ContextUse, ScopeRequired)
from voyd.engine.context import ContextRef
from voyd.engine.time import now

RETAIN = timedelta(days=30)


async def _notes(engine, *, tenant="t", lineage=None, revision="v1",
                 best_effort=False, retain=RETAIN):
    """A handle that refuses, and an index that remembers what was said."""
    index = engine.context_index(
        ContextIndexSpec(retain=retain, tenant=tenant),
        best_effort=best_effort)
    notes = engine.model("notes", tenant=tenant).admitting(
        lineage_field=lineage, policy_revision=revision)
    notes.contextualized_by(index)
    await engine.ensure(search_wait_s=0)
    return notes, index


# ---- 1. the direct question --------------------------------------------

async def test_a_use_recorded_against_a_page_is_found_from_any_fact_on_it(core):
    """The whole point, in one test: read some facts, say something, and
    then ask -- from a fact -- what was said."""
    engine, db = core
    notes, index = await _notes(engine)
    await db.notes.insert_many([{"t": "a", "doc_id": "d1"},
                                {"t": "a", "doc_id": "d2"}])

    page = await notes.find({"t": "a"})
    use = await notes.record_use(
        page, consequence={"kind": "ticket", "id": "SUP-41"})
    assert use is not None

    source = str(page[0]["_id"])
    found = await notes.affected_by(source, tenant="a")
    assert [r["consequence"]["id"] for r in found] == ["SUP-41"]
    assert found[0]["depth"] == 0, "one hop from the fact to what it produced"


async def test_a_fact_that_produced_nothing_answers_with_nothing(core):
    """An empty worklist has to be an ordinary answer, or nobody will believe
    a non-empty one."""
    engine, db = core
    notes, _ = await _notes(engine)
    await db.notes.insert_one({"t": "a", "doc_id": "d1"})
    assert await notes.affected_by("no-such-id", tenant="a") == []


async def test_the_refs_say_whether_a_fact_was_read_or_merely_upstream(core):
    """``direct`` and ``source`` are different claims and the record keeps
    them apart: 'this was in the prompt' is what decides whether an answer
    has to be retracted."""
    engine, db = core
    notes, _ = await _notes(engine, lineage="lineage")
    await db.notes.insert_one({"t": "a", "doc_id": "parent"})
    parent = (await notes.find({"t": "a", "doc_id": "parent"}))[0]["_id"]
    child, = await notes.derive({"t": "a", "doc_id": "child"},
                                parents=[parent])

    page = await notes.find({"t": "a", "doc_id": "child"})
    receipt = await notes.receipt_for(page)
    kinds = {r["id"]: r["kind"] for r in receipt["refs"]}

    assert kinds[str(child)] == DIRECT, "the child was on the page"
    assert kinds[str(parent)] == SOURCE, \
        "the parent was not read here, and is still upstream of what was said"


async def test_erasing_a_source_finds_what_was_said_from_its_descendant(core):
    """The failure this package exists to prevent, one layer out. The
    erasure is honoured against the source, the summary is refused with it
    -- and the ticket that was already filed is the part nothing here can
    recall. It can at least be named."""
    engine, db = core
    notes, _ = await _notes(engine, lineage="lineage")
    await db.notes.insert_one({"t": "a", "doc_id": "parent"})
    parent = (await notes.find({"t": "a"}))[0]["_id"]
    await notes.derive({"t": "a", "doc_id": "child"}, parents=[parent])

    page = await notes.find({"t": "a", "doc_id": "child"})
    await notes.record_use(page, consequence={"kind": "email", "id": "m-9"})

    await notes.revoke({"t": "a", "doc_id": "parent"}, reason="erasure")
    assert await notes.find({"t": "a"}) == [], "both are unreachable now"

    worklist = await notes.affected_by(parent, tenant="a")
    assert [r["consequence"]["id"] for r in worklist] == ["m-9"]


# ---- 2. transitively, because a consequence becomes a source ------------

async def test_a_consequence_that_was_worked_from_is_itself_a_source(core):
    """An agent summarises a document into a ticket, then next week writes a
    reply after reading the ticket. Erasing the document has to reach the
    reply, and the reply names only the ticket."""
    engine, db = core
    notes, index = await _notes(engine)
    await db.notes.insert_one({"t": "a", "doc_id": "d1"})
    page = await notes.find({"t": "a"})
    fact = str(page[0]["_id"])

    await notes.record_use(page, consequence={"kind": "ticket", "id": "SUP-41"})
    # The ticket is worked from out there; the use is recorded against it
    # by whatever did the working.
    await index.record(ContextUse(
        collection="notes", consequence_kind="email", consequence_id="m-9",
        refs=(ContextRef(DIRECT, "SUP-41"),), policy_revision="v1",
        evaluated_at=now(), receipt="x" * 64, tenant="a"))

    found = await notes.affected_by(fact, tenant="a")
    by_id = {r["consequence"]["id"]: r["depth"] for r in found}
    assert by_id == {"SUP-41": 0, "m-9": 1}, \
        "the walk has to keep going where the ids keep going"


async def test_the_walk_stops_and_says_so_rather_than_hanging(core):
    """This index takes consequence ids from outside this database, so a
    cycle is a thing somebody can record. A truncated worklist beats an
    erasure request that never returns."""
    engine, db = core
    notes, index = await _notes(engine)
    await db.notes.insert_one({"t": "a", "doc_id": "d1"})
    page = await notes.find({"t": "a"})
    fact = str(page[0]["_id"])

    await notes.record_use(page, consequence={"kind": "ticket", "id": "A"})
    for src, dst in (("A", "B"), ("B", "A")):
        await index.record(ContextUse(
            collection="notes", consequence_kind="ticket", consequence_id=dst,
            refs=(ContextRef(DIRECT, src),), policy_revision="v1",
            evaluated_at=now(), receipt="x" * 64, tenant="a"))

    found = await notes.affected_by(fact, tenant="a", max_depth=3)
    assert {r["consequence"]["id"] for r in found} <= {"A", "B"}
    assert found, "a bounded walk still returns what it reached"


# ---- 3. the boundary ----------------------------------------------------

async def test_one_tenants_worklist_is_not_another_tenants(core):
    """A use index that leaks is a map of one subject's data drawn for
    somebody else -- and it is *durable*, which is worse than a leaked read."""
    engine, db = core
    notes, _ = await _notes(engine)
    await db.notes.insert_many([{"t": "a", "doc_id": "d1"},
                                {"t": "b", "doc_id": "d1"}])

    page_a = await notes.find({"t": "a"})
    await notes.record_use(page_a, consequence={"kind": "ticket", "id": "A-1"})
    fact_a = str(page_a[0]["_id"])

    assert await notes.affected_by(fact_a, tenant="a")
    assert await notes.affected_by(fact_a, tenant="b") == [], \
        "the same id asked for under another tenant finds nothing"


async def test_a_scoped_lookup_will_not_guess_the_tenant(core):
    """Answering "affected by what, for whom?" with a guess is how the
    worklist ends up being the wrong subject's."""
    engine, db = core
    notes, _ = await _notes(engine)
    await db.notes.insert_one({"t": "a", "doc_id": "d1"})
    with pytest.raises(ScopeRequired):
        await notes.affected_by("anything")


async def test_a_use_on_an_empty_page_cannot_name_its_tenant(core):
    """The handle knows the tenant field; only the rows know the value.
    Nothing was read, so there is nothing to read it off."""
    engine, _ = core
    notes, _ = await _notes(engine)
    page = await notes.find({"t": "a"})
    assert page == []
    with pytest.raises(ScopeRequired):
        await notes.record_use(page, consequence={"kind": "t", "id": "1"})


# ---- 4. recording the same thing twice is one thing --------------------

async def test_recording_the_same_use_twice_is_one_record(core):
    """A retry after a timeout is the ordinary case -- the write may well
    have landed. An index that counted it twice would answer "how many
    things did we say because of this" with a number that grows on network
    weather."""
    engine, db = core
    notes, index = await _notes(engine)
    await db.notes.insert_one({"t": "a", "doc_id": "d1"})
    page = await notes.find({"t": "a"})

    first = await notes.record_use(page, consequence={"kind": "t", "id": "1"})
    second = await notes.record_use(page, consequence={"kind": "t", "id": "1"})

    assert first.use_id == second.use_id
    assert index.recorded == 1 and index.duplicates == 1
    assert await db[index.collection].count_documents({}) == 1


async def test_the_identity_is_the_content_and_not_the_moment(core):
    """``recorded_at`` is when we wrote it down, not anything about the use.
    In the identity it would make every retry a new record, which is the
    whole failure the hash exists to prevent."""
    common = dict(collection="notes", consequence_kind="t",
                  consequence_id="1", refs=(ContextRef(DIRECT, "x"),),
                  policy_revision="v1", evaluated_at=now(),
                  receipt="h" * 64, tenant="a")
    early = ContextUse(**common, recorded_at=now())
    late = ContextUse(**common, recorded_at=now() + timedelta(hours=3))
    assert early.use_id == late.use_id

    other = ContextUse(**{**common, "consequence_id": "2"})
    assert other.use_id != early.use_id, \
        "a different consequence is a different record"


async def test_a_different_policy_is_a_different_use(core):
    """``over_budget`` does not say whether the budget was 100 or 10000. Two
    uses of the same facts under two rule sets are two facts about the
    deployment, and collapsing them loses the one an audit needs."""
    common = dict(collection="notes", consequence_kind="t",
                  consequence_id="1", refs=(ContextRef(DIRECT, "x"),),
                  evaluated_at=now(), receipt="h" * 64, tenant="a")
    assert ContextUse(**common, policy_revision="v1").use_id != \
        ContextUse(**common, policy_revision="v2").use_id


# ---- 5. a record it can stand behind, or none --------------------------

async def test_a_bare_list_is_not_a_page_and_cannot_be_recorded(core):
    """A plain list cannot say what instant it was admitted at. A use
    stamped with the wrong instant is worse than an absent one: it will
    exonerate a context nobody ever checked."""
    engine, db = core
    notes, _ = await _notes(engine)
    await db.notes.insert_one({"t": "a", "doc_id": "d1"})
    legacy = [d async for d in db.notes.find({"t": "a"})]

    with pytest.raises(ContextIncomplete) as caught:
        await notes.record_use(legacy, consequence={"kind": "t", "id": "1"})
    assert "a read snapshot" in caught.value.missing


async def test_a_page_read_through_the_handle_carries_its_own_snapshot(core):
    """The other half of the previous test: the check is satisfiable by
    reading normally, not by passing a flag."""
    engine, db = core
    notes, _ = await _notes(engine)
    await db.notes.insert_one({"t": "a", "doc_id": "d1"})
    page = await notes.find({"t": "a"})

    assert page.snapshot_complete is True
    assert page.policy_revision == "v1"
    assert page.evaluated_at is not None


async def test_every_hit_on_a_page_agrees_about_what_now_was(core):
    """Frozen once at the start of the read. A per-candidate clock would
    mean a page whose documents were admitted against different instants,
    and a receipt that committed to one of them arbitrarily."""
    engine, db = core
    notes, _ = await _notes(engine)
    await db.notes.insert_many([{"t": "a", "doc_id": f"d{i}"}
                                for i in range(5)])
    page = await notes.find({"t": "a"})
    receipt = await notes.receipt_for(page)
    assert receipt["at"] == page.evaluated_at.isoformat(), \
        "the receipt commits to the instant the page was admitted at, not to now()"


async def test_a_policy_without_a_revision_cannot_be_recorded(core):
    """A record naming no policy says a context was legitimate under rules
    nobody can name afterwards."""
    engine, db = core
    index = engine.context_index(ContextIndexSpec(retain=RETAIN, tenant="t"))
    notes = engine.model("notes", tenant="t").forgettable()
    notes.contextualized_by(index)
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_one({"t": "a", "doc_id": "d1"})

    with pytest.raises(ContextIncomplete) as caught:
        await notes.record_use(await notes.find({"t": "a"}),
                               consequence={"kind": "t", "id": "1"})
    assert "policy_revision" in caught.value.missing


@pytest.mark.parametrize("consequence", [
    None, {}, {"kind": "ticket"}, {"id": "SUP-41"}, {"kind": "", "id": "x"},
    {"kind": "ticket", "id": "  "},
])
async def test_a_consequence_that_names_nothing_is_refused(core, consequence):
    """"Something was produced" is not a worklist entry."""
    engine, db = core
    notes, _ = await _notes(engine)
    await db.notes.insert_one({"t": "a", "doc_id": "d1"})
    page = await notes.find({"t": "a"})
    with pytest.raises(ContextIncomplete) as caught:
        await notes.record_use(page, consequence=consequence)
    assert "a named consequence" in caught.value.missing


async def test_the_missing_pieces_are_reported_all_at_once(core):
    """Fixing these one raise at a time is three deploys."""
    engine, db = core
    index = engine.context_index(ContextIndexSpec(retain=RETAIN, tenant="t"))
    notes = engine.model("notes", tenant="t").forgettable()
    notes.contextualized_by(index)
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_one({"t": "a", "doc_id": "d1"})
    legacy = [d async for d in db.notes.find({})]

    with pytest.raises(ContextIncomplete) as caught:
        await notes.record_use(legacy, consequence={"kind": "", "id": ""})
    assert set(caught.value.missing) == {
        "a read snapshot", "policy_revision", "a named consequence"}


async def test_recording_a_use_with_no_index_is_an_error_not_a_shrug(core):
    """Silence from this path is indistinguishable from "nothing was
    affected", which is the one wrong answer it must never give."""
    engine, db = core
    notes = engine.model("notes", tenant="t").admitting(policy_revision="v1")
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_one({"t": "a", "doc_id": "d1"})

    with pytest.raises(ContextIncomplete):
        await notes.record_use(await notes.find({"t": "a"}),
                               consequence={"kind": "t", "id": "1"})
    with pytest.raises(ContextIncomplete):
        await notes.affected_by("anything", tenant="a")


# ---- 6. ids and hashes, never text -------------------------------------

async def test_nothing_the_document_said_is_in_the_record(core):
    """An index that quotes the paragraph it was asked to help forget is a
    new copy of that paragraph, in a collection built to outlive the
    original. The ledger's argument, one layer up."""
    engine, db = core
    notes, index = await _notes(engine)
    secret = "the patient's diagnosis is in this sentence"
    await db.notes.insert_one({"t": "a", "doc_id": "d1", "text": secret})

    await notes.record_use(await notes.find({"t": "a"}),
                           consequence={"kind": "ticket", "id": "SUP-41"})
    row = await db[index.collection].find_one({})
    assert secret not in repr(row)
    assert "text" not in row


@pytest.mark.parametrize("bad", [
    "a paragraph that is much too long to be an id " * 10,
    "line one\nline two",
])
async def test_a_consequence_id_that_is_really_content_is_refused(core, bad):
    """The convenient thing for a caller to pass is the answer itself. The
    guard is at the write, not in the docstring where it started."""
    engine, db = core
    notes, _ = await _notes(engine)
    await db.notes.insert_one({"t": "a", "doc_id": "d1"})
    page = await notes.find({"t": "a"})
    with pytest.raises(ValueError, match="not an id"):
        await notes.record_use(page, consequence={"kind": "answer", "id": bad})


async def test_a_ref_is_one_of_two_kinds(core):
    """"It was read" and "it is upstream of something that was read" are
    different claims, and a third kind would be a third claim nobody
    defined."""
    assert ContextRef(DIRECT, "x").as_dict() == {"kind": "direct", "id": "x"}
    with pytest.raises(ValueError, match="direct"):
        ContextRef("maybe", "x")
    with pytest.raises(TypeError):
        ContextRef.of("just-an-id")
    assert ContextRef.of({"kind": SOURCE, "id": "x"}) == ContextRef(SOURCE, "x")


# ---- 7. the receipt is what the record commits to ----------------------

async def test_the_record_carries_the_receipt_hash_of_the_context(core):
    """The use record says *these facts*; the receipt hash says *and this is
    the policy state that admitted them*. Without it a use is a claim about
    a page nobody can reconstruct."""
    engine, db = core
    notes, index = await _notes(engine)
    await db.notes.insert_one({"t": "a", "doc_id": "d1"})
    page = await notes.find({"t": "a"})

    receipt = await notes.receipt_for(page)
    use = await notes.record_use(page, consequence={"kind": "t", "id": "1"})
    assert use.receipt == receipt["hash"]

    row = await db[index.collection].find_one({"_id": use.use_id})
    assert row["receipt"] == receipt["hash"]
    assert row["policy_revision"] == "v1"


async def test_the_receipt_hash_is_still_recomputable_by_a_third_party(core):
    """Typed refs and a policy revision went into the body; the property
    that makes the receipt worth anything must survive them."""
    from voyd.engine.admission import _digest_of

    engine, db = core
    notes, _ = await _notes(engine)
    await db.notes.insert_one({"t": "a", "doc_id": "d1"})
    receipt = await notes.receipt_for(await notes.find({"t": "a"}))
    assert _digest_of({k: v for k, v in receipt.items() if k != "hash"}) \
        == receipt["hash"]


# ---- 8. retention is typed out -----------------------------------------

async def test_an_index_with_no_stated_retention_cannot_be_built():
    """A use index is most valuable when it is oldest, and it is a record of
    processing a subject can ask about. Neither argument obviously wins,
    which is exactly why this does not pick."""
    with pytest.raises(ValueError, match="retention decision"):
        ContextIndexSpec(retain=None)
    with pytest.raises(ValueError, match="positive timedelta"):
        ContextIndexSpec(retain=timedelta(0))


async def test_every_record_carries_the_deadline_it_was_declared_with(core):
    """The deadline is on the document, like everywhere else in this engine.
    One collection reasoning about retention differently is how the two
    drift."""
    engine, db = core
    notes, index = await _notes(engine, retain=timedelta(days=7))
    await db.notes.insert_one({"t": "a", "doc_id": "d1"})
    use = await notes.record_use(await notes.find({"t": "a"}),
                                 consequence={"kind": "t", "id": "1"})

    row = await db[index.collection].find_one({"_id": use.use_id})
    assert abs((row["expire_at"] - row["recorded_at"])
               - timedelta(days=7)) < timedelta(seconds=1)

    names = await db[index.collection].index_information()
    assert "context_retention" in names
    assert names["context_retention"]["expireAfterSeconds"] == 0


async def test_two_retentions_for_one_collection_collide_loudly(core):
    """Whichever was declared first would otherwise silently decide how long
    a subject's processing record is kept."""
    engine, _ = core
    engine.context_index(ContextIndexSpec(retain=timedelta(days=30)))
    with pytest.raises(ValueError, match="refusing to redeclare"):
        engine.context_index(ContextIndexSpec(retain=timedelta(days=1)))


# ---- 9. failing loudly, unless told otherwise --------------------------

async def test_an_index_that_cannot_write_raises_by_default(core):
    """A use that was not recorded is a consequence ``affected_by()`` will
    silently fail to name -- and silence reads exactly like "nothing was
    affected"."""
    engine, db = core
    notes, index = await _notes(engine)
    await db.notes.insert_one({"t": "a", "doc_id": "d1"})
    page = await notes.find({"t": "a"})

    class Broken:
        async def insert_one(self, row):
            raise RuntimeError("the index is down")

    index.db = {index.collection: Broken()}
    with pytest.raises(RuntimeError, match="the index is down"):
        await notes.record_use(page, consequence={"kind": "t", "id": "1"})
    assert index.dropped == 1


async def test_best_effort_is_available_and_counts_what_it_dropped(core):
    """A deployment may decide serving the request matters more than
    recording the use. It may not decide to do so invisibly."""
    engine, db = core
    notes, index = await _notes(engine, best_effort=True)
    await db.notes.insert_one({"t": "a", "doc_id": "d1"})
    page = await notes.find({"t": "a"})

    class Broken:
        async def insert_one(self, row):
            raise RuntimeError("the index is down")

    index.db = {index.collection: Broken()}
    assert await notes.record_use(
        page, consequence={"kind": "t", "id": "1"}) is None
    assert index.describe()["dropped"] == 1
    assert index.describe()["best_effort"] is True


async def test_a_dropped_use_is_visible_on_health(core):
    """The number worth an alert has to be somewhere a probe reads."""
    engine, _ = core
    _, index = await _notes(engine, best_effort=True)
    index.dropped = 3
    reported = engine.health()["context"]
    assert [r["dropped"] for r in reported] == [3]


# ---- 10. and it stays decoupled from revocation ------------------------

async def test_recording_a_use_revokes_nothing(core):
    """An index is not an enforcement point. If recording a use could
    withhold a fact, every agent that wrote a summary would be quietly
    shrinking its own future reads."""
    engine, db = core
    notes, _ = await _notes(engine)
    await db.notes.insert_many([{"t": "a", "doc_id": "d1"},
                                {"t": "a", "doc_id": "d2"}])
    page = await notes.find({"t": "a"})
    await notes.record_use(page, consequence={"kind": "t", "id": "1"})

    assert len(await notes.find({"t": "a"})) == 2
    assert notes.receipts()["revoked_total"] == 0


async def test_revoking_a_fact_writes_nothing_to_the_index(core):
    """The other direction, and the one with teeth: an erasure that had to
    update a use index could not complete while the index was down."""
    engine, db = core
    notes, index = await _notes(engine)
    await db.notes.insert_one({"t": "a", "doc_id": "d1"})
    page = await notes.find({"t": "a"})
    await notes.record_use(page, consequence={"kind": "t", "id": "1"})
    before = await db[index.collection].count_documents({})

    await notes.revoke({"t": "a", "doc_id": "d1"}, reason="erasure")

    assert await db[index.collection].count_documents({}) == before
    assert index.recorded == 1, "revocation is not a use"


async def test_the_worklist_survives_the_erasure_it_is_for(core):
    """The lookup has to answer about a document that has just been revoked
    -- if it applied the admission rules it would return nothing for exactly
    the fact somebody is investigating."""
    engine, db = core
    notes, _ = await _notes(engine)
    await db.notes.insert_one({"t": "a", "doc_id": "d1"})
    page = await notes.find({"t": "a"})
    fact = str(page[0]["_id"])
    await notes.record_use(page, consequence={"kind": "ticket", "id": "SUP-41"})

    await notes.revoke({"t": "a", "doc_id": "d1"}, reason="erasure")

    found = await notes.affected_by(fact, tenant="a")
    assert [r["consequence"]["id"] for r in found] == ["SUP-41"], \
        "this is the moment the index exists for"


async def test_the_index_is_installed_as_an_ordinary_trait(core):
    """Nothing special: it is declared, ``ensure()`` builds it, ``health()``
    reports it. A subsystem would be a second thing to operate."""
    engine, _ = core
    _, index = await _notes(engine)
    assert index.kind == "context"
    assert engine.installed("context") == {index.collection: index}
    assert engine.health()["declared"]["context"] == [index.collection]
