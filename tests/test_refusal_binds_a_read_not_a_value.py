"""Two questions about what refusal reaches, and the answers point opposite ways.

Both were asked as "what would it take to build this". Neither needed
building: one already works and nobody had shown it, and the other cannot
work, for a reason worth stating precisely rather than half-fixing.

**Answer-level revocation already works.** The mirror of admission is the
generation *leaving* the model: a cached answer, a summary, an embedding built
out of admitted context. Every RAG cache in production is a pile of derived
documents with no erasure story. Here, an answer written back with `derive()`
naming the context it was built from is unreachable the moment any of those
sources is revoked -- the same guarantee, one layer up, with no new machinery
at all. `examples/lineage.py` shows the mechanism on a summary; this pins it
on the artefact people actually keep, which is the answer.

**Session state cannot work, and the reason is structural.** A fact revoked at
turn 40 must not survive into turn 41 -- including in the part the agent
carried forward itself. It does survive, and `reachable()` is right to admit
it: refusal is a per-document check, and a value copied out before the mark
was written is a document *without* the mark. It is not the document; it is
what the document used to say.

That is not a gap to patch. It is the in-memory instance of a position this
package already takes in `voyd/engine/perimeter.py` -- who else holds a copy
is enumerated and audited, never enforced -- and an agent holding its own
context is a perimeter member nobody registered. Refusal binds a *read*. Once
a caller holds the fields, they have left the read path, and no per-document
check can reach a copy it is not shown.

The honest version of the feature is therefore not a smarter `reachable()`.
It is re-reading through the handle at the top of each turn, which already
works, or a store-backed liveness check -- new surface, and frozen. See
`docs/STATE.md`.
"""

from __future__ import annotations

from voyd.engine import Deadline, revoked

LEAK = "aws key AKIA-EXAMPLE-LEAKEDKEY-9c1f"


async def test_an_answer_built_from_revoked_context_is_unreachable(core):
    """The strongest unclaimed thing here, and it needed no code.

    The answer names the context it was built from, so revoking a source
    reaches the answer without the revoker knowing the answer exists -- which
    is the only version of this that works, because the person honouring an
    erasure request cannot be expected to enumerate every cache.
    """
    engine, db = core
    notes = engine.model("notes").admitting(
        Deadline(), revoked(), lineage_field="lineage")
    await engine.ensure(search_wait_s=0)

    source = (await db.notes.insert_one({"text": LEAK})).inserted_id
    unrelated = (await db.notes.insert_one({"text": "P0301"})).inserted_id

    context = await notes.find({})
    assert len(context) == 2, "both facts were admitted into the context"

    answer, = await notes.derive(
        {"kind": "answer", "text": f"The key is {LEAK}.", "served_at": "t0"},
        parents=[d["_id"] for d in context])

    await notes.revoke({"_id": source}, reason="credential leaked")

    reachable = {d["_id"] for d in await notes.find({})}
    assert source not in reachable, "the source itself"
    assert answer not in reachable, (
        "the cached answer built out of it -- this is the claim")
    assert unrelated in reachable, (
        "and a rule that took the whole collection would prove nothing")


async def test_a_value_carried_forward_is_not_the_document_it_came_from(core):
    """The limit, pinned so it is not rediscovered as a surprise.

    Asserted in both directions on purpose. A stale copy is admitted, which
    looks like a bug until you see the second half: the same document,
    refetched, is refused. The rule is working exactly as specified on
    whatever it is handed, and what it was handed was stale.
    """
    engine, db = core
    notes = engine.model("notes").admitting(Deadline(), revoked())
    await engine.ensure(search_wait_s=0)
    source = (await db.notes.insert_one({"text": LEAK})).inserted_id

    carried = await notes.find({})                  # turn 40: values copied out
    await notes.revoke({"_id": source}, reason="credential leaked")

    assert len(notes.reachable(carried)) == 1, (
        "the stale copy is admitted -- refusal binds a read, not a value")
    assert "forgotten" not in carried[0], (
        "and this is why: the copy predates the mark, so it does not carry it")

    refetched = [d async for d in db.notes.find({})]
    assert "forgotten" in refetched[0]
    assert notes.reachable(refetched) == [], (
        "the same document, read again, is refused. The boundary is correct; "
        "the caller's copy is what left the read path")


async def test_the_documented_workaround_actually_works(core):
    """A limit stated without a remedy is half a finding.

    Re-reading through the handle at the top of a turn is the whole fix, it
    needs nothing that does not ship, and it is what a long-lived agent
    should be doing anyway -- the context it carried is a cache, and this is
    the cache invalidating.
    """
    engine, db = core
    notes = engine.model("notes").admitting(Deadline(), revoked())
    await engine.ensure(search_wait_s=0)
    source = (await db.notes.insert_one({"text": LEAK})).inserted_id
    await db.notes.insert_one({"text": "P0301"})

    carried = await notes.find({})                  # turn 40
    await notes.revoke({"_id": source}, reason="credential leaked")

    turn_41 = await notes.find({"_id": {"$in": [d["_id"] for d in carried]}})
    assert [d["text"] for d in turn_41] == ["P0301"], (
        "re-reading the carried ids through the handle drops the revoked one")


async def test_which_answers_were_built_on_this_fact_is_already_one_query(core):
    """The consequence question, which `STATE.md` calls the most valuable
    feature on its list -- and it is an indexed find, today.

    `derive()` closes lineage transitively at write time, so a grandchild
    already names the grandparent. That was built so a revocation could reach
    a whole subtree in one update. The same field, read instead of written,
    answers the question from the other end: *which answers were built on this
    fact?*

    This narrows a gap the roadmap states more broadly than it is. The reverse
    index is still missing for an artefact that **left** -- a Slack message, a
    fine-tune, an answer you served and kept only a receipt for. For anything
    written back into the collection, which is what a RAG cache is, the
    archaeology project is a query and has been all along.
    """
    engine, db = core
    notes = engine.model("notes").admitting(
        Deadline(), revoked(), lineage_field="lineage")
    await engine.ensure(search_wait_s=0)

    source = (await db.notes.insert_one({"text": LEAK})).inserted_id
    unrelated = (await db.notes.insert_one({"text": "P0301"})).inserted_id

    summary, = await notes.derive({"kind": "summary"}, parents=[source])
    answer, = await notes.derive({"kind": "answer"}, parents=[summary])
    embedding, = await notes.derive({"kind": "embedding"}, parents=[answer])
    innocent, = await notes.derive({"kind": "answer"}, parents=[unrelated])

    fallout = [d async for d in db.notes.find({"lineage": source})]
    ids = {d["_id"] for d in fallout}

    assert ids == {summary, answer, embedding}, (
        "every consequence of the fact, at any depth, from one query")
    assert innocent not in ids, (
        "and nothing built from something else -- a rule that returned the "
        "collection would answer this question uselessly")

    # The three artefacts named in the pitch, and the third is the one people
    # forget: a vector is a lossy copy of the text that made it.
    assert sorted(d["kind"] for d in fallout) == ["answer", "embedding", "summary"]


async def test_the_consequences_go_unreachable_together(core):
    """And the other direction closes the loop.

    Asking *which answers were built on this* is only half a product. The half
    that matters is that honouring the erasure reaches all of them without the
    person honouring it having to read that list first.
    """
    engine, db = core
    notes = engine.model("notes").admitting(
        Deadline(), revoked(), lineage_field="lineage")
    await engine.ensure(search_wait_s=0)

    source = (await db.notes.insert_one({"text": LEAK})).inserted_id
    summary, = await notes.derive({"kind": "summary"}, parents=[source])
    answer, = await notes.derive({"kind": "answer"}, parents=[summary])
    embedding, = await notes.derive({"kind": "embedding"}, parents=[answer])

    marked = await notes.revoke({"_id": source}, reason="credential leaked")
    assert marked == 4, "the fact and the three things made out of it"
    assert await notes.find({}) == [], "none of them reachable on the next read"

    # Unreachable first, erased second: the rows are all still there.
    assert await db.notes.count_documents({}) == 4
