"""Lineage, authority, and the scope errors -- the last three that mattered.

**Lineage** is the differentiator the wire enforces for free: revoke a source
and the summary, the answer and the embedding built out of it go with it. An
erasure that stops at the document somebody named is not an erasure, it is a
filing action -- and the person honouring an erasure request cannot be
expected to enumerate every cache.

**Authority** is the gate on the verbs that *change* reachability. Withholding
a fact and granting one back are not equally dangerous, and until this file
neither was checked.

**The scope errors** are pure functions with no database in them at all, and
they are where a tenant leak actually gets stopped: presence is not shape, and
`{"$ne": "nobody"}` passes a presence check and then matches everyone.
"""

from __future__ import annotations

import uuid

import pytest

from .conftest import MONGO_URI

pymongo = pytest.importorskip("pymongo")


@pytest.fixture
async def engine():
    from pymongo import AsyncMongoClient

    from voyd import Engine

    client = AsyncMongoClient(MONGO_URI)
    name = f"voyd_test_lin_{uuid.uuid4().hex[:8]}"
    eng = Engine(client, client[name])
    await eng.connect()
    try:
        yield eng
    finally:
        await client.drop_database(name)
        await client.close()


# ---- lineage -------------------------------------------------------------

async def test_revoking_a_source_reaches_what_was_made_of_it(engine):
    """Transitively, and in one write. A grandchild names the grandparent
    because closure happens at write time, which is why this is a query and
    not a walk."""
    from voyd.engine import Deadline, revoked

    notes = engine.model("notes").admitting(
        Deadline(), revoked(), lineage_field="lineage")
    await engine.ensure(search_wait_s=0)

    src = (await engine.db.notes.insert_one({"text": "the credential"})).inserted_id
    await engine.db.notes.insert_one({"text": "unrelated"})
    summary, = await notes.derive({"kind": "summary"}, parents=[src])
    answer, = await notes.derive({"kind": "answer"}, parents=[summary])
    await notes.derive({"kind": "embedding"}, parents=[answer])

    n = await notes.revoke({"_id": src}, reason="credential leaked")

    assert n == 4, "the fact and the three things made out of it"
    assert [d["text"] for d in await notes.find({})] == ["unrelated"]
    assert await engine.db.notes.count_documents({}) == 5


async def test_the_consequence_question_is_one_indexed_query(engine):
    """*Which answers were built on this fact?* -- the same field, read from
    the other end. For anything written back into the collection, which is
    what a RAG cache is, the archaeology project is a `find`."""
    from voyd.engine import Deadline, revoked

    notes = engine.model("notes").admitting(
        Deadline(), revoked(), lineage_field="lineage")
    await engine.ensure(search_wait_s=0)

    src = (await engine.db.notes.insert_one({"text": "source"})).inserted_id
    other = (await engine.db.notes.insert_one({"text": "other"})).inserted_id
    summary, = await notes.derive({"kind": "summary"}, parents=[src])
    answer, = await notes.derive({"kind": "answer"}, parents=[summary])
    innocent, = await notes.derive({"kind": "answer"}, parents=[other])

    fallout = {d["_id"] async for d in engine.db.notes.find({"lineage": src})}

    assert fallout == {summary, answer}
    assert innocent not in fallout


async def test_deriving_from_a_revoked_source_is_refused(engine):
    """The write-side race. An agent still holding the text and writing it
    back must be refused, not written-and-marked -- reaching here means
    something read a document it should not have been given."""
    from voyd.engine import Deadline, DerivationBroken, revoked

    notes = engine.model("notes").admitting(
        Deadline(), revoked(), lineage_field="lineage")
    await engine.ensure(search_wait_s=0)
    src = (await engine.db.notes.insert_one({"text": "gone"})).inserted_id
    await notes.revoke({"_id": src}, reason="erasure request")

    with pytest.raises(DerivationBroken):
        await notes.derive({"kind": "late summary"}, parents=[src])


# ---- authority -----------------------------------------------------------

async def test_a_verb_that_changes_reachability_can_be_gated(engine):
    """`Grants` reads a capability list off the caller's claims. Reading is
    not what it guards -- changing what is readable is."""
    from voyd.engine import Grants, NotAuthorised

    notes = engine.model("notes").forgettable().authorised_by(Grants())
    await engine.ensure(search_wait_s=0)
    await engine.db.notes.insert_one({"text": "a"})

    intern = notes.for_caller({"sub": "intern", "may": []})
    with pytest.raises(NotAuthorised):
        await intern.revoke({"text": "a"}, reason="oops")

    officer = notes.for_caller({"sub": "dana", "may": ["revoke"]})
    assert await officer.revoke({"text": "a"}, reason="erasure request") == 1


async def test_an_authority_cannot_verify_the_claims_it_is_handed():
    """Stated because it is the honest limit: claims come from whatever
    already authenticated the caller. An authorisation system whose only
    input is the attacker's would be worse than none."""
    from voyd.engine import Grants

    g = Grants()
    ok = g.permits("revoke", {"sub": "dana", "may": ["revoke"]},
                   collection="notes")
    assert ok is True
    assert g.permits("revoke", {"sub": "i", "may": []},
                     collection="notes") is False
    assert g.permits("revoke", None, collection="notes") is False, (
        "no caller is not a free pass")


# ---- the scope errors, with no database in sight -------------------------

@pytest.mark.parametrize("bad", [
    {"$ne": "nobody"}, {"$exists": True}, {"$gt": ""}, {"$nin": ["x"]},
], ids=lambda o: next(iter(o)))
def test_a_tenant_that_is_an_operator_is_refused(bad):
    """Presence is not shape. Every one of these passes a presence check and
    then matches every tenant -- and `$vectorSearch`'s filter accepts them,
    so presence-checking plus a vector index is a leak with a green suite."""
    from voyd.engine import ScopeInvalid
    from voyd.engine.errors import require_tenant

    with pytest.raises(ScopeInvalid):
        require_tenant("notes", "tenant_id", {"tenant_id": bad})


def test_a_missing_tenant_raises_rather_than_returning_everything():
    from voyd.engine import ScopeRequired
    from voyd.engine.errors import require_tenant

    with pytest.raises(ScopeRequired):
        require_tenant("notes", "tenant_id", {})
    with pytest.raises(ScopeRequired):
        require_tenant("notes", "tenant_id", {"tenant_id": None})


def test_an_unscoped_collection_is_left_alone():
    """The tenant rule must not invent a scope nobody declared."""
    from voyd.engine.errors import require_tenant

    assert require_tenant("notes", None, {"a": 1}) == {"a": 1}
