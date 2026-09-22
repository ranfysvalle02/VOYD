"""A chapter can be forgotten without forgetting the book.

Every rule in this package reads *top-level* fields. That is the right
default and it is silently wrong for the document shape MongoDB
recommends and retrieval increasingly works over: a book with chapters, a
ticket with comments, a case file with notes. A chapter carrying the exact
mark `revoke()` writes is admitted with its parent, counted nowhere, and
attested by `receipt_for` as "nothing was refused".

`subjects` is the answer -- it says which thing is the subject instead of
assuming the document is -- and `_admit` redacts the refused elements from
the document it returns rather than refusing the parent whole, because a
book is not erased by one retracted chapter.

**The redaction was counted and not performed on the only read path the
proxy uses.** `reachable()` used `_admit` as a *predicate* and kept the
document it was handed, so a refused chapter was recorded in `receipts()`
and served anyway. `find()` was correct, because it keeps the returned
document. One read path redacting and another not is the failure this
project is named after, and the paths were the library one and the wire
one.

So these tests are written against `Guard.filter`, which is what the
boundary calls, and the first one fails against the predicate version.

Redaction must also never be *silent*: a document that came back shorter
than it is on disk must not look like a whole one, which is why the count
is separated from the refusal count and why the private mark is taken off
before anything leaves.

No database. The subject check is a pure function of a document.
"""

from __future__ import annotations

from datetime import timedelta

from voyd.engine import Deadline, revoked
from voyd.engine.admission import Admission, AdmissionSpec
from voyd.engine.time import now
from voyd.wire.policy import Guard

PAST = now() - timedelta(days=1)


def spec(**kw) -> AdmissionSpec:
    return AdmissionSpec("books", rules=(Deadline(), revoked()),
                         subjects="chapters", subject_key="title", **kw)


def book() -> dict:
    return {"_id": 1, "title": "a manual", "chapters": [
        {"title": "intro", "text": "fine"},
        {"title": "leaked", "text": "the credential",
         "forgotten": {"at": PAST, "reason": "leak"}},
        {"title": "stale", "text": "last year's", "expire_at": PAST},
        {"title": "outro", "text": "also fine"},
    ]}


# ---- through the boundary's own entry point ------------------------------

def test_the_refused_chapter_does_not_reach_the_caller():
    """The regression. `Guard.filter` is what the proxy calls on every
    batch, and it was counting this refusal while serving the chapter."""
    guard = Guard(spec())
    kept = guard.filter([book()])
    assert len(kept) == 1, "the book itself is not erased by a bad chapter"
    assert [c["title"] for c in kept[0]["chapters"]] == ["intro", "outro"]


def test_both_reasons_reach_the_receipts():
    """A revoked chapter and an expired one are different events and an
    operator needs to see which -- the same argument that keeps reasons
    unmerged for whole documents."""
    guard = Guard(spec())
    guard.filter([book()])
    assert guard.reasons() == {"revoked": 1, "deadline": 1}


def test_the_private_mark_does_not_leave_with_the_document():
    """`_admit` stamps the redacted document so the page can count it.
    That stamp is internal, and a caller receiving it would be handed a
    field this package invented."""
    kept = Guard(spec()).filter([book()])
    assert not [k for k in kept[0] if k.startswith("_voyd")], kept[0]
    for chapter in kept[0]["chapters"]:
        assert not [k for k in chapter if k.startswith("_voyd")]


def test_a_book_whose_every_chapter_is_refused_still_arrives_empty():
    """Redaction, not refusal: the parent survives with nothing in it.
    Refusing the book instead would erase a document nobody revoked."""
    all_bad = {"_id": 2, "chapters": [
        {"title": "a", "forgotten": {"at": PAST, "reason": "x"}},
        {"title": "b", "forgotten": {"at": PAST, "reason": "x"}},
    ]}
    kept = Guard(spec()).filter([all_bad])
    assert len(kept) == 1
    assert kept[0]["chapters"] == []


def test_a_refused_parent_is_still_refused_whole():
    """`subjects` adds a question, it does not replace one. A mark on the
    document itself refuses the document."""
    doc = {"_id": 3, "forgotten": {"at": PAST, "reason": "leak"},
           "chapters": [{"title": "fine"}]}
    assert Guard(spec()).filter([doc]) == []


def test_an_unnamed_subject_is_refused_rather_than_admitted():
    """With `subject_key` declared, an element that does not carry it is
    refused. That is what makes the key enforced rather than a convention
    -- and an anonymous subject can be refused on read and never
    *addressed*, so admitting one would be admitting something nothing can
    later revoke."""
    doc = {"_id": 4, "chapters": [{"title": "named"}, {"text": "nameless"}]}
    kept = Guard(spec()).filter([doc])
    assert [c.get("title") for c in kept[0]["chapters"]] == ["named"]


def test_the_unnamed_refusal_has_its_own_reason():
    guard = Guard(spec())
    guard.filter([{"_id": 5, "chapters": [{"text": "nameless"}]}])
    assert guard.reasons() == {"unnamed": 1}


# ---- and the collection that declared nothing pays nothing ---------------

def test_a_collection_with_no_subjects_is_untouched():
    """The gate is a field being `None`. An ordinary collection must not
    start paying for a question it never asked, and an array field on one
    of its documents is just an array."""
    plain = Guard(AdmissionSpec("books", rules=(Deadline(), revoked())))
    kept = plain.filter([book()])
    assert len(kept) == 1
    assert [c["title"] for c in kept[0]["chapters"]] == [
        "intro", "leaked", "stale", "outro"], (
        "a collection that declared no subjects had its array edited")


# ---- the same document through `find`'s path, for agreement --------------

def test_the_two_read_paths_agree_about_what_is_left():
    """`find` keeps `_admit`'s return and `reachable` now does too. This
    is the assertion that they cannot drift apart again: one boundary
    meaning two things depending on which method was called is what this
    file was written about."""
    handle = Admission(None, spec())
    through_reachable = handle.reachable([book()])
    # `_admit` is what `find` appends, so it is compared directly rather
    # than through a database this test does not need.
    admitted = handle._admit(book())
    assert admitted is not None
    left_via_admit = [c["title"] for c in admitted["chapters"]]
    assert [c["title"] for c in through_reachable[0]["chapters"]] == \
        left_via_admit
