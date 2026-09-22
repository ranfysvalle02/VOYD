"""Revoking a source reaches the summary somebody wrote out of it.

The read path already refuses any document carrying the mark. The failure
this closes is that the mark did not *travel*: a client deletes the source,
the boundary turns that into a revocation, and the summary an agent wrote
out of it keeps scoring well forever. The erasure request is honoured
against the document somebody named and defeated by the paragraph nobody
did -- which is this package's own failure arriving through the one door it
left open.

Three claims, and they are separable, so they are separated:

    the cascade reaches     a revoked source takes its children with it,
                            at any depth, because ancestry is closed
                            transitively when a child is written
    the order is chosen     children are marked *before* the source, so a
                            crash leaves a visible half-erasure the caller
                            can retry rather than a summary of an erased
                            fact still answering prompts
    the question inverts    `find({"lineage": id})` answers "what was made
                            out of this?" from the other end

`lineage_field` is opt-in, so this is the one part of the boundary that
opens a connection of its own on the read path's behalf -- a cascade is a
write the caller did not issue, and it must not go on the caller's session.
That is asserted here too: the client's own session sees nothing it did not
ask for.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pymongo import MongoClient

pytestmark = pytest.mark.needs_mongo

UTC = timezone.utc

# `on_delete="revoke"` plus `lineage_field`: the two halves that make a
# client's ordinary `deleteOne` reach a document it never named.
POLICY = """
from voyd import guard, deadline, revocable, tenant

@guard("notes", on_delete="revoke", lineage_field="lineage")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()
"""


def future() -> datetime:
    return datetime.now(UTC) + timedelta(days=1)


@pytest.fixture
def derived(boundary, database, direct):
    """A source, a summary of it, and an answer built on the summary."""
    wire = boundary(POLICY)
    client = MongoClient(wire.uri, serverSelectionTimeoutMS=20_000)
    notes = client[database].notes
    # Written *through* the boundary, because closing a document's
    # ancestry is something the boundary does on the way in. A fixture
    # that inserted these directly would be testing a cascade over
    # lineage the boundary never saw.
    notes.insert_one({"_id": "source", "tenant_id": "acme",
                      "expire_at": future(), "text": "the fault code"})
    notes.insert_one({"_id": "summary", "tenant_id": "acme",
                      "expire_at": future(), "lineage": ["source"],
                      "text": "a summary of the fault code"})
    notes.insert_one({"_id": "answer", "tenant_id": "acme",
                      "expire_at": future(), "lineage": ["summary"],
                      "text": "an answer quoting the summary"})
    try:
        yield client, notes
    finally:
        client.close()


def test_a_childs_ancestry_is_closed_when_it_is_written(derived, direct,
                                                        database):
    # The mechanism the cascade rests on: a child's lineage is its
    # parent's lineage plus the parent, so a grandchild already names the
    # grandparent. That is what makes one `$in` reach the whole subtree at
    # any depth instead of a recursive walk.
    stored = {d["_id"]: d.get("lineage") or []
              for d in direct[database].notes.find({})}
    assert stored["source"] == []
    assert stored["summary"] == ["source"]
    assert "summary" in stored["answer"]
    assert "source" in stored["answer"], (
        "the grandchild does not name the grandparent, so a cascade would "
        "have to walk the tree and would stop at the first level")


def test_revoking_a_source_reaches_the_summary_and_the_answer(derived, direct,
                                                              database):
    client, notes = derived
    assert len(list(notes.find({"tenant_id": "acme"}))) == 3

    # An ordinary delete. The client names one document and never hears
    # about the other two.
    notes.delete_one({"_id": "source", "tenant_id": "acme"})

    served = [d["_id"] for d in notes.find({"tenant_id": "acme"})]
    assert served == [], (
        f"a document made out of a revoked fact is still reachable: "
        f"{served}")

    # Nothing was deleted. Every row is on disk, marked, which is what
    # makes the erasure auditable rather than merely done.
    on_disk = list(direct[database].notes.find({}))
    assert len(on_disk) == 3
    assert all(d.get("forgotten") for d in on_disk), (
        "a row was made unreachable without recording that it was")


def test_the_children_are_marked_before_the_source_is(derived, direct,
                                                      database):
    """The order is chosen, because the boundary cannot have a transaction.

    A crash between marking the children and revoking the source leaves a
    visible half-erasure: the source still reachable, the derivations
    already gone, and a caller who re-runs an idempotent delete. The
    reverse order fails the other way -- the source refused and the
    summary of it still answering prompts, with nothing saying so.
    """
    client, notes = derived
    notes.delete_one({"_id": "source", "tenant_id": "acme"})

    marks = {d["_id"]: d["forgotten"]["at"]
             for d in direct[database].notes.find({})}
    assert marks["summary"] <= marks["source"], (
        "the source was revoked before its descendants; a crash there "
        "leaves a summary of an erased fact still answering prompts")
    assert marks["answer"] <= marks["source"]


def test_the_question_answers_from_the_other_end(derived, direct, database):
    # "What was made out of this?" is an ordinary query, which is the
    # point of storing ancestry rather than deriving it: an auditor does
    # not need a new verb.
    built_on_source = {d["_id"] for d in
                       direct[database].notes.find({"lineage": "source"})}
    assert built_on_source == {"summary", "answer"}


def test_a_cascade_does_not_go_on_the_callers_session(derived, direct,
                                                      database):
    # The cascade is the boundary's write, not the caller's: it is issued
    # because a policy file said so, at a moment the caller did not choose.
    # Putting it on their session would change what their *later* reads
    # see, which is a larger surprise than the one being fixed.
    client, notes = derived
    with client.start_session(causal_consistency=True) as s:
        notes.delete_one({"_id": "source", "tenant_id": "acme"}, session=s)
        # The session still works and still refuses, which is all the
        # caller should be able to notice.
        assert list(notes.find({"tenant_id": "acme"}, session=s)) == []
    assert direct[database].notes.count_documents({}) == 3


def test_an_unrelated_document_is_not_swept_up(boundary, database, direct):
    # A cascade that over-reached would be a cross-tenant write dressed up
    # as an erasure, and it would look exactly like this test passing for
    # the wrong reason if nothing else were in the collection.
    wire = boundary(POLICY)
    client = MongoClient(wire.uri, serverSelectionTimeoutMS=20_000)
    try:
        notes = client[database].notes
        notes.insert_one({"_id": "source", "tenant_id": "acme",
                          "expire_at": future()})
        notes.insert_one({"_id": "child", "tenant_id": "acme",
                          "expire_at": future(), "lineage": ["source"]})
        notes.insert_one({"_id": "stranger", "tenant_id": "acme",
                          "expire_at": future()})
        notes.delete_one({"_id": "source", "tenant_id": "acme"})

        assert [d["_id"] for d in notes.find({"tenant_id": "acme"})] == \
            ["stranger"]
        untouched = direct[database].notes.find_one({"_id": "stranger"})
        assert not untouched.get("forgotten")
    finally:
        client.close()
