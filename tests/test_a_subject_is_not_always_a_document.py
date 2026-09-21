"""Every rule here reads top-level fields. The document model stopped agreeing.

`admission/` is built on an assumption that was true for so long nobody wrote
it down: **a fact is a document, and a document has an `_id`.** The mark goes
on the root. The deadline goes on the root. `lineage` is an array of `_id`s.
`_admit` is handed a document and asks the rules, and the rules read
`doc[at_field]` and `doc[mark_field]`.

Then the embedded-document pattern -- the one MongoDB recommends, and the one
nested vector embeddings now make the *retrieval* unit -- puts subjects inside
documents. A book with chapters. A ticket with comments. A case file with
notes, each about a different person, each with its own erasure request.

The first test below is the one that matters, and it was written before the
fix: a chapter carrying the exact mark ``revoke()`` writes reaches a prompt
with its parent, is counted in no tally, and ``receipt_for`` attests that
nothing was refused. That last part is the serious half. A miscount is a bug;
a hash-committed, third-party-verifiable receipt asserting a refusal that
never happened is the artifact an incident review trusts, and it is wrong.

**This is not a nested-index problem.** Every test here runs against an
ordinary ``find()``. Nested embeddings did not create the hole; they made the
shape that exposes it the recommended way to model data, and handed the query
layer a way to filter children that the per-document boundary cannot match.

The fix is to stop assuming. ``subjects=`` names the array whose elements are
subjects in their own right; refused elements are dropped from the document
and counted. The cost of *not* declaring it is unchanged behaviour, which is
deliberate -- this is opt-in because inventing subjects inside somebody's
documents would be a worse guess than the one being fixed.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from voyd.engine import SearchSpec, UnboundedForgetting, UnknownReason
from voyd.engine.admission import AdmissionSpec, quarantined, revoked
from voyd.engine.time import now

ERASED = {"at": None, "reason": "erasure"}


def _chapters():
    """One live chapter, one revoked, one expired. Marks on the subdocuments."""
    return [
        {"n": 1, "text": "ordinary"},
        {"n": 3, "text": "SUBJECT ERASURE REQUESTED",
         "forgotten": {"at": now(), "reason": "erasure"}},
        {"n": 4, "text": "EXPIRED AN HOUR AGO",
         "expire_at": now() - timedelta(hours=1)},
    ]


# ---- 1. the hole, with no nested index anywhere -------------------------

async def test_an_undeclared_subject_reaches_the_prompt_inside_its_parent(core):
    """The bug this file exists for, pinned as *current* behaviour.

    Not an aspiration and not a regression test -- a statement of what an
    undeclared collection still does, so that changing it is a decision
    somebody makes on purpose rather than a side effect. Every byte of the
    revoked chapter is in the returned document.
    """
    engine, db = core
    books = engine.model("books", tenant="t").admitting(policy_revision="v1")
    await engine.ensure(search_wait_s=0)
    await db.books.insert_one({"t": "a", "chapters": _chapters()})

    page = await books.find({"t": "a"})
    text = [c["text"] for c in page[0]["chapters"]]

    assert len(text) == 3
    assert "SUBJECT ERASURE REQUESTED" in text
    assert page.redacted == 0
    assert page.refused == {}


async def test_the_receipt_attests_a_refusal_that_did_not_happen(core):
    """The serious half. A miscount is a bug; a hash-committed receipt
    asserting that nothing was withheld is the artifact an incident review
    trusts, and on an undeclared collection it is confidently wrong."""
    engine, db = core
    books = engine.model("books", tenant="t").admitting(policy_revision="v1")
    await engine.ensure(search_wait_s=0)
    await db.books.insert_one({"t": "a", "chapters": _chapters()})

    page = await books.find({"t": "a"})
    receipt = await books.receipt_for(page)

    assert receipt["refused"] == {}
    assert len(receipt["admitted"]) == 1
    # And the document it committed to still carries the erased chapter.
    assert any(c.get("forgotten") for c in page[0]["chapters"])


# ---- 2. declaring the subject closes it ---------------------------------

async def test_a_declared_subject_is_refused_inside_its_parent(core):
    """The fix. The parent is admitted; the refused chapters are not in it."""
    engine, db = core
    books = engine.model("books", tenant="t").admitting(
        policy_revision="v1", subjects="chapters")
    await engine.ensure(search_wait_s=0)
    await db.books.insert_one({"t": "a", "chapters": _chapters()})

    page = await books.find({"t": "a"})

    assert len(page) == 1, "the book is still a legitimate answer"
    assert [c["n"] for c in page[0]["chapters"]] == [1]
    assert page.redacted == 2


async def test_each_redacted_subject_is_named_by_its_own_reason(core):
    """A chapter withheld for a deadline and one withheld by an erasure
    request are different events, and an operator needs to tell them apart
    for the same reason ``quarantined`` is not merged into ``deadline``."""
    engine, db = core
    books = engine.model("books", tenant="t").admitting(
        policy_revision="v1", subjects="chapters")
    await engine.ensure(search_wait_s=0)
    await db.books.insert_one({"t": "a", "chapters": _chapters()})

    await books.find({"t": "a"})

    assert books.receipts()["refused_by_reason"] == {"revoked": 1, "deadline": 1}


async def test_a_shortened_document_can_never_be_silent(core):
    """The fix must not reintroduce the bug in the other direction. A book
    that comes back with two chapters missing and no number saying so is the
    same lie told by a different mechanism."""
    engine, db = core
    books = engine.model("books", tenant="t").admitting(
        policy_revision="v1", subjects="chapters")
    await engine.ensure(search_wait_s=0)
    await db.books.insert_one({"t": "a", "chapters": _chapters()})

    page = await books.find({"t": "a"})
    assert page.redacted == 2
    assert page.as_dict()["redacted"] == 2


async def test_the_whole_parent_is_never_withheld_for_one_subject(core):
    """The other available guess, and why it is not the one taken: a single
    erased comment withholding an entire case file is correct, catastrophic,
    and not what anybody asked for."""
    engine, db = core
    books = engine.model("books", tenant="t").admitting(
        policy_revision="v1", subjects="chapters")
    await engine.ensure(search_wait_s=0)
    await db.books.insert_one({
        "t": "a", "title": "kept",
        "chapters": [{"n": 1, "forgotten": {"at": now(), "reason": "erasure"}}]})

    page = await books.find({"t": "a"})
    assert len(page) == 1 and page[0]["title"] == "kept"
    assert page[0]["chapters"] == []
    assert page.redacted == 1


async def test_a_refused_parent_is_still_refused_whole(core):
    """Redaction is what happens to an *admitted* document. A book that is
    itself revoked does not come back trimmed -- it does not come back."""
    engine, db = core
    books = engine.model("books", tenant="t").admitting(
        policy_revision="v1", subjects="chapters")
    await engine.ensure(search_wait_s=0)
    await db.books.insert_one({"t": "a", "doc_id": "b1",
                               "chapters": _chapters()})
    await books.revoke({"t": "a", "doc_id": "b1"}, reason="erasure")

    assert await books.find({"t": "a"}) == []


# ---- 3. the invariants the fix must not break ---------------------------

async def test_the_private_redaction_mark_never_reaches_a_caller(core):
    """``_redact`` has to return one value and say two things, so it stamps a
    private key and one place takes it off. A sentinel that escapes to a
    caller is a worse bug than the one it was added for."""
    engine, db = core
    books = engine.model("books", tenant="t").admitting(
        policy_revision="v1", subjects="chapters")
    await engine.ensure(search_wait_s=0)
    await db.books.insert_many([{"t": "a", "chapters": _chapters()}
                                for _ in range(3)])

    page = await books.find({"t": "a"})
    reachable = books.for_tenant("a").reachable(
        [d async for d in db.books.find({"t": "a"})])
    one = await books.find_one({"t": "a"})

    for source in (list(page), reachable, [one]):
        for doc in source:
            assert not any(k.startswith("__redacted") for k in doc), doc.keys()


async def test_an_undeclared_collection_pays_nothing(core):
    """Opt-in has to be free, or it is a tax on every collection that never
    had this shape."""
    engine, db = core
    notes = engine.model("notes", tenant="t").admitting(policy_revision="v1")
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_many([{"t": "a", "n": i} for i in range(5)])

    page = await notes.find({"t": "a"})
    assert len(page) == 5 and page.redacted == 0
    assert notes.spec.subjects is None


async def test_a_non_document_element_is_left_alone(core):
    """An array of strings is not an array of subjects. A rule cannot read a
    field off a string, and dropping it would be redaction with no reason to
    report."""
    engine, db = core
    books = engine.model("books", tenant="t").admitting(
        policy_revision="v1", subjects="tags")
    await engine.ensure(search_wait_s=0)
    await db.books.insert_one({"t": "a", "tags": ["red", "blue"]})

    page = await books.find({"t": "a"})
    assert page[0]["tags"] == ["red", "blue"]
    assert page.redacted == 0


async def test_the_document_on_disk_is_not_edited(core):
    """Refusal is a read-path guarantee. Redacting must not turn a read into
    a write -- the row stays whole, and the next policy change can restore
    what this read withheld."""
    engine, db = core
    books = engine.model("books", tenant="t").admitting(
        policy_revision="v1", subjects="chapters")
    await engine.ensure(search_wait_s=0)
    await db.books.insert_one({"t": "a", "chapters": _chapters()})

    await books.find({"t": "a"})

    raw = await db.books.find_one({"t": "a"})
    assert len(raw["chapters"]) == 3, "the row is untouched; only the answer was"


async def test_break_glass_sees_the_redacted_subjects(core):
    """Auditing what was withheld is the job ``including_refused()`` exists
    for, and a subject withheld inside a document is no different from one
    withheld as a document."""
    engine, db = core
    books = engine.model("books", tenant="t").admitting(
        policy_revision="v1", subjects="chapters")
    await engine.ensure(search_wait_s=0)
    await db.books.insert_one({"t": "a", "chapters": _chapters()})

    page = await books.including_refused().find({"t": "a"})
    assert len(page[0]["chapters"]) == 3
    assert page.redacted == 0


# ---- 4. what the declaration refuses to accept --------------------------

def test_a_dotted_subject_path_is_refused():
    """One level, deliberately. A redaction whose depth nobody can state is
    worse than one that refuses to start."""
    with pytest.raises(ValueError, match="dotted path"):
        AdmissionSpec("books", subjects="a.b").with_defaults()


def test_an_empty_subject_path_is_refused():
    with pytest.raises(ValueError, match="not an empty string"):
        AdmissionSpec("books", subjects="   ").with_defaults()


def test_the_declaration_says_so_out_loud():
    """``describe()`` is what ``health()`` prints. A collection enforcing a
    rule per subdocument and reporting the same sentence as one that does not
    is how the two get confused in an incident."""
    spec = AdmissionSpec("books", subjects="chapters").with_defaults()
    assert "per chapters[]" in spec.describe()
    assert "per" not in AdmissionSpec("notes").with_defaults().describe()


# ---- 5. the other contradiction: sealed, and embedded by the server -----

async def test_a_sealed_field_cannot_also_be_embedded_by_the_server(core):
    """``sealed()`` says the server never holds this plaintext. ``auto_embed``
    says the server reads it and ships it to an embedding endpoint. Declared
    on the same path those are not a trade-off, and both resolutions are bad
    -- vectors of noise, or plaintext egress no perimeter registered."""
    engine, _ = core
    engine.model("notes", tenant="t").sealed("text")
    engine.searchable(SearchSpec(
        collection="notes", text_paths=("text",), tenant_field="t",
        tenant_type="token", auto_embed="voyage-4"))

    with pytest.raises(ValueError, match="sealed and also declared"):
        await engine.ensure(search_wait_s=0)


async def test_sealing_one_field_and_embedding_another_is_allowed(core):
    """The guard must not forbid a coherent design. Sealing the body and
    embedding the title is lossy, not contradictory, and this has no
    business having an opinion about it."""
    engine, _ = core
    engine.model("notes", tenant="t").sealed("body")
    engine.searchable(SearchSpec(
        collection="notes", text_paths=("title",), tenant_field="t",
        tenant_type="token", auto_embed="voyage-4"))

    await engine.ensure(search_wait_s=0)     # does not raise


# ---- 6. a subject with a name can be addressed --------------------------
#
# ``subjects`` made embedded subjects visible to refusal. It left the harder
# half open: a subdocument has no ``_id``, so nothing could *target* one. An
# erasure request that says "forget chapter 3" had no verb.
#
# Position was the obvious name and it is the wrong one -- ``chapters.3``
# is stale the first time anybody removes an element, silently, on an
# erasure path. So the name is a field the application carries, and the
# thing that stops that being a convention is that it is enforced: an
# element without it is refused, not admitted.

def _keyed():
    return [{"cid": "c1", "text": "one"},
            {"cid": "c3", "text": "ERASE ME"},
            {"cid": "c9", "text": "nine"}]


async def _keyed_books(engine, db):
    books = engine.model("books", tenant="t").admitting(
        policy_revision="v1", subjects="chapters", subject_key="cid")
    await engine.ensure(search_wait_s=0)
    await db.books.insert_one({"t": "a", "doc_id": "b1", "chapters": _keyed()})
    return books


async def test_one_embedded_subject_can_be_erased_by_name(core):
    """The verb that was missing. "Forget chapter 3" and "forget the book"
    are different instructions, and only the second one could be said."""
    engine, db = core
    books = await _keyed_books(engine, db)

    modified = await books.revoke_subject(
        {"t": "a", "doc_id": "b1"}, key="c3", reason="erasure")

    assert modified == 1
    page = await books.find({"t": "a"})
    assert [c["cid"] for c in page[0]["chapters"]] == ["c1", "c9"]
    assert page.redacted == 1


async def test_erasing_a_subject_leaves_its_siblings_alone(core):
    """The whole reason not to reach for the document-level verb."""
    engine, db = core
    books = await _keyed_books(engine, db)
    await books.revoke_subject({"t": "a", "doc_id": "b1"}, key="c3",
                               reason="erasure")

    page = await books.find({"t": "a"})
    assert len(page) == 1, "the book is not withheld for one chapter"
    assert [c["text"] for c in page[0]["chapters"]] == ["one", "nine"]


async def test_the_name_travels_with_the_element_not_its_position(core):
    """Position was the other candidate. It is wrong the moment an element
    is removed -- every later index shifts, and the erasure lands on
    somebody else's paragraph. A key moves with the data."""
    engine, db = core
    books = await _keyed_books(engine, db)
    # c1 is pulled out from under it, so c3 is now at index 0.
    await db.books.update_one({"doc_id": "b1"},
                              {"$pull": {"chapters": {"cid": "c1"}}})

    await books.revoke_subject({"t": "a", "doc_id": "b1"}, key="c3",
                               reason="erasure")

    page = await books.find({"t": "a"})
    assert [c["cid"] for c in page[0]["chapters"]] == ["c9"], \
        "the right element was erased after the array moved"


async def test_an_erased_subject_is_unreachable_not_gone(core):
    """Say what actually happened. TTL collects documents, not array
    elements, so there is no deadline here for a reaper to act on: the
    element stays on disk, refused on every read, until its parent's own
    deadline. Implying the bytes are gone would be the overclaim this
    package spends whole files avoiding."""
    engine, db = core
    books = await _keyed_books(engine, db)
    await books.revoke_subject({"t": "a", "doc_id": "b1"}, key="c3",
                               reason="erasure")

    raw = await db.books.find_one({"doc_id": "b1"})
    assert len(raw["chapters"]) == 3
    assert raw["chapters"][1]["forgotten"]["reason"] == "erasure"


async def test_an_auditor_can_still_see_what_was_erased(core):
    """``including_refused()`` is the reason the bytes stay. A subject
    withheld inside a document is no different from one withheld as a
    document."""
    engine, db = core
    books = await _keyed_books(engine, db)
    await books.revoke_subject({"t": "a", "doc_id": "b1"}, key="c3",
                               reason="erasure")

    page = await books.including_refused().find({"t": "a"})
    assert [c["cid"] for c in page[0]["chapters"]] == ["c1", "c3", "c9"]


async def test_erasing_a_subject_is_counted_and_witnessed(core):
    """A revocation is an event. One that is invisible to the chain and the
    counters would make subject-level erasure the one write here nobody can
    audit."""
    engine, db = core
    chain = engine.ledger("refusals", tenant="t")
    books = engine.model("books", tenant="t").admitting(
        policy_revision="v1", subjects="chapters", subject_key="cid")
    books.witnessed_by(chain)
    await engine.ensure(search_wait_s=0)
    await db.books.insert_one({"t": "a", "doc_id": "b1", "chapters": _keyed()})

    await books.revoke_subject({"t": "a", "doc_id": "b1"}, key="c3",
                               reason="erasure")

    assert books.receipts()["revoked_total"] == 1
    entries = await chain.entries(tenant="a")
    assert entries[-1]["detail"]["subject"] == {"path": "chapters",
                                                "key": "c3"}


async def test_a_subject_that_cannot_be_named_is_refused(core):
    """The enforcement that keeps ``subject_key`` from being a convention.

    An element with no key cannot be the target of an erasure request, named
    in a lineage, or attested to in a receipt. Whether it happens to be
    expired today is a question about a thing nobody can talk about
    tomorrow, so it fails closed -- the same direction an unreadable
    deadline takes."""
    engine, db = core
    books = engine.model("books", tenant="t").admitting(
        policy_revision="v1", subjects="chapters", subject_key="cid")
    await engine.ensure(search_wait_s=0)
    await db.books.insert_one({
        "t": "a", "doc_id": "b2",
        "chapters": [{"cid": "ok", "text": "named"}, {"text": "anonymous"}]})

    page = await books.find({"t": "a"})

    assert [c["cid"] for c in page[0]["chapters"]] == ["ok"]
    assert page.redacted == 1
    assert books.receipts()["refused_by_reason"] == {"unnamed": 1}


async def test_an_unnamed_subject_is_counted_apart_from_a_forgotten_one(core):
    """It is a statement about the schema, not about the fact. Merging it
    into ``revoked`` would read as "the system is forgetting things" when
    the truth is "a writer is dropping a field"."""
    engine, db = core
    books = engine.model("books", tenant="t").admitting(
        policy_revision="v1", subjects="chapters", subject_key="cid")
    await engine.ensure(search_wait_s=0)
    await db.books.insert_one({"t": "a", "doc_id": "b3", "chapters": [
        {"text": "anonymous"},
        {"cid": "c2", "forgotten": {"at": now(), "reason": "erasure"}}]})

    await books.find({"t": "a"})

    assert books.receipts()["refused_by_reason"] == {"unnamed": 1, "revoked": 1}


async def test_addressing_a_subject_needs_both_declarations(core):
    """Two declarations have to be in place, and saying which one is missing
    is cheaper than letting a caller guess from an empty result."""
    engine, db = core
    anonymous = engine.model("books", tenant="t").admitting(
        policy_revision="v1", subjects="chapters")
    await engine.ensure(search_wait_s=0)

    with pytest.raises(UnknownReason, match="subject_key"):
        await anonymous.revoke_subject({"t": "a", "doc_id": "b1"},
                                       key="c3", reason="erasure")


async def test_a_flat_collection_says_so_rather_than_matching_nothing(core):
    engine, _ = core
    flat = engine.model("notes", tenant="t").admitting(policy_revision="v1")
    await engine.ensure(search_wait_s=0)

    with pytest.raises(UnknownReason, match="subjects="):
        await flat.revoke_subject({"t": "a", "doc_id": "n1"},
                                  key="x", reason="erasure")


async def test_erasing_a_subject_cannot_be_unbounded(core):
    """The same guard the document-level verb has. ``{"t": "a"}`` narrows
    nothing beyond the tenant, and a subject key is not a filter."""
    engine, db = core
    books = await _keyed_books(engine, db)

    with pytest.raises(UnboundedForgetting):
        await books.revoke_subject({"t": "a"}, key="c3", reason="erasure")


async def test_a_subject_inside_a_refused_parent_can_still_be_erased(core):
    """Revoking a chapter inside an expired book is a legitimate
    instruction, and a query that hid the parent would report "nothing
    matched" for a document that is plainly there."""
    engine, db = core
    books = await _keyed_books(engine, db)
    await db.books.update_one(
        {"doc_id": "b1"},
        {"$set": {"expire_at": now() - timedelta(hours=1)}})
    assert await books.find({"t": "a"}) == []

    modified = await books.revoke_subject(
        {"t": "a", "doc_id": "b1"}, key="c3", reason="erasure")
    assert modified == 1


def test_a_key_with_nothing_to_name_is_refused_at_declaration():
    with pytest.raises(ValueError, match="no subjects="):
        AdmissionSpec("books", subject_key="cid").with_defaults()


# ---- 7. the copy the database keeps for itself --------------------------
#
# ``derived_fields`` nulls a lossy encoding held *in the document*. With
# server-side embedding there is no such field: the vector lives in the
# search node's own storage, which no query here can write to. The purge
# that is actually available is to overwrite the field it was derived from,
# and that costs the source text its remaining deadline -- so it is a sink
# somebody registers, not a default.

def test_the_perimeter_has_a_name_for_a_copy_it_cannot_write_to():
    """It is not ``owned`` -- there is no endpoint and no acknowledgement.
    Not ``derived`` -- "cannot be recalled" is false here, and saying so
    would give up a purge that exists. Not ``sealed`` -- the whole point is
    that the server read the plaintext."""
    from voyd.engine import INTERNAL, Perimeter, derived_index

    perimeter = Perimeter().register(
        derived_index(None, "notes", field="text"))
    described = perimeter.describe()

    assert described["sinks"][INTERNAL] == ["notes.text-index"]
    assert "overwriting the field" in described["claims"][INTERNAL]


async def test_an_unwritable_derived_copy_is_purged_through_its_source(core):
    """The whole mechanism, end to end: revoking a document clears the field
    the search node embedded, so the vector goes with the fact instead of
    outliving it until the reaper runs."""
    from voyd.engine import Perimeter, derived_index

    engine, db = core
    notes = engine.model("notes", tenant="t").admitting(policy_revision="v1")
    notes.bounded_by(Perimeter().register(
        derived_index(db, "notes", field="text")))
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_one({"t": "a", "doc_id": "n1",
                               "text": "the sentence that was erased"})

    await notes.revoke({"t": "a", "doc_id": "n1"}, reason="erasure")

    raw = await db.notes.find_one({"doc_id": "n1"})
    assert raw["text"] is None, "the source of the derived copy is gone"
    assert "text" in raw, "and the document keeps its shape"


async def test_a_reversible_hold_destroys_nothing(core):
    """``Perimeter.forget`` runs on irreversible revocation only, and that
    is load-bearing here rather than incidental: a quarantine that is later
    lifted must not have destroyed the text in the meantime."""
    from voyd.engine import Perimeter, derived_index

    engine, db = core
    notes = engine.model("notes", tenant="t").admitting(
        quarantined(), revoked(), policy_revision="v1")
    notes.bounded_by(Perimeter().register(
        derived_index(db, "notes", field="text")))
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_one({"t": "a", "doc_id": "n1", "text": "held"})

    await notes.quarantine({"t": "a", "doc_id": "n1"}, reason="review")
    raw = await db.notes.find_one({"doc_id": "n1"})
    assert raw["text"] == "held", "a hold is not an erasure"

    await notes.lift("quarantined", {"t": "a", "doc_id": "n1"},
                     reason="cleared")
    assert (await notes.find({"t": "a"}))[0]["text"] == "held"


# ---- 8. the two declarations must agree about what a fact is ------------
#
# ``subjects`` closed the read path. It left one way to reach the same bug
# from the other side: index a nested path, so retrieval ranks a *child* and
# returns its *parent*, on a collection that never said its children were
# subjects. Nothing on the read path can detect that -- the boundary is
# handed a parent and has no reason to look inside it -- so it is caught
# where it belongs, at declaration.

async def test_a_nested_index_on_an_ungoverned_collection_is_refused(core):
    """Nested retrieval separates the unit of relevance from the unit of
    refusal. On a collection that refuses things, that separation is the
    whole bug -- so the boot fails rather than the erasure."""
    engine, _ = core
    engine.model("books", tenant="t").admitting(policy_revision="v1")
    engine.searchable(SearchSpec(
        collection="books", vector_path="chapters.embedding",
        text_paths=("title",), tenant_field="t", tenant_type="token"))

    with pytest.raises(ValueError, match="never declared subjects="):
        await engine.ensure(search_wait_s=0)


async def test_a_nested_index_is_allowed_once_the_subjects_are_named(core):
    """The guard must not forbid the design -- only the undeclared one."""
    engine, _ = core
    engine.model("books", tenant="t").admitting(
        policy_revision="v1", subjects="chapters")
    engine.searchable(SearchSpec(
        collection="books", vector_path="chapters.embedding",
        text_paths=("title",), tenant_field="t", tenant_type="token"))

    await engine.ensure(search_wait_s=0)      # does not raise


async def test_retrieval_and_refusal_may_not_govern_different_arrays(core):
    """Each declaration is defensible alone. Together they mean the search
    ranks elements of one array while refusal governs another, and neither
    is wrong on its own terms -- which is why nothing else would catch it."""
    engine, _ = core
    engine.model("books", tenant="t").admitting(
        policy_revision="v1", subjects="reviews")
    engine.searchable(SearchSpec(
        collection="books", vector_path="chapters.embedding",
        text_paths=("title",), tenant_field="t", tenant_type="token"))

    with pytest.raises(ValueError, match="but indexes chapters"):
        await engine.ensure(search_wait_s=0)


async def test_a_collection_with_no_admission_policy_is_not_policed(core):
    """This guard exists because refusal and retrieval disagreed. A
    collection that refuses nothing has no disagreement to have, and a
    library that forbade nesting there would be inventing a rule."""
    engine, _ = core
    engine.searchable(SearchSpec(
        collection="notes", vector_path="chunks.embedding",
        text_paths=("title",), tenant_field="t", tenant_type="token"))

    await engine.ensure(search_wait_s=0)      # does not raise
