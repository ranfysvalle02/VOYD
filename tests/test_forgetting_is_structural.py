"""Refusal has to survive the developer who has not read the docstring.

Every other test in this suite proves a rule is enforced *where it was
written*. This file proves something harder and more useful: that the rule
holds in code written by somebody who did not know about it.

That is the actual bug. VOYD had the deadline check in ``Memory.recall`` and
in the void search path, correctly, from early on -- and still shipped six
read paths that went to MongoDB with a tenant filter and no deadline, because
a convention is only as good as the next person's memory. A rule you have to
remember to apply is not enforced, it is suggested.

So the central test here (``test_a_read_path_written_in_ignorance_is_safe``)
writes the naive thing on purpose -- a plain query, no deadline, no awareness
that forgetting exists -- through the handle, and asserts it is still safe.
If that test ever fails, the abstraction has stopped earning its place and is
just a longer way to spell ``find``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from voyd.engine import (DEADLINE, REVOKED, UNREADABLE, ScopeInvalid,
                         ScopeRequired, why_unreachable)
from voyd.engine.forgetting import ForgettingSpec

SPEC = ForgettingSpec("facts")


def at(**kw) -> datetime:
    return datetime.now(timezone.utc) + timedelta(**kw)


# ---- the rule, as pure logic ------------------------------------------

@pytest.mark.parametrize("doc, expected", [
    ({}, None),                                        # pinned: no field
    ({"expire_at": None}, None),                       # pinned: null
    ({"expire_at": at(hours=1)}, None),                # not yet due
    ({"expire_at": at(hours=-1)}, DEADLINE),
    ({"forgotten": {"at": at(), "reason": "erasure"}}, REVOKED),
    ({"expire_at": "next tuesday"}, UNREADABLE),
    ({"expire_at": 1_700_000_000}, UNREADABLE),
    ({"expire_at": []}, UNREADABLE),
])
def test_every_reason_a_fact_may_not_reach_a_prompt(doc, expected):
    assert why_unreachable(doc, SPEC) == expected


def test_revocation_beats_a_deadline_that_has_not_passed():
    """An erasure request does not wait for a TTL, and is not overridden by
    a generous one. Revoked is revoked."""
    doc = {"expire_at": at(days=3650), "forgotten": {"at": at(), "reason": "x"}}
    assert why_unreachable(doc, SPEC) == REVOKED


def test_an_unshiftable_deadline_fails_closed_rather_than_raising():
    """A datetime that cannot be moved to UTC is still unreadable, not an
    exception -- an exception inside a filter is how the filter gets skipped."""
    doc = {"expire_at": datetime.max.replace(
        tzinfo=timezone(timedelta(hours=-14)))}
    assert why_unreachable(doc, SPEC) == UNREADABLE


# ---- against a real database ------------------------------------------

@pytest.fixture
async def facts(core):
    """Four facts: pinned, live, expired, and revoked."""
    engine, db = core
    handle = engine.model("facts").forgettable()
    await engine.ensure(search_wait_s=0)

    await db.facts.insert_many([
        {"name": "pinned", "expire_at": None},
        {"name": "live", "expire_at": at(hours=1)},
        {"name": "expired", "expire_at": at(hours=-1)},
        {"name": "revoked", "expire_at": at(hours=1),
         "forgotten": {"at": at(), "reason": "subject request"}},
    ])
    return engine, db, handle


async def test_a_read_path_written_in_ignorance_is_safe(facts):
    """The test this whole module exists for.

    Below is what a developer writes when they have never heard of
    ``expire_at``: a query with their own filter and nothing else. Through the
    handle, it is still correct. There is no unfiltered ``find`` to reach for,
    so the naive thing and the safe thing are the same thing.
    """
    _, _, docs = facts

    # No deadline. No awareness one exists. Just "give me the facts".
    found = {d["name"] for d in await docs.find({})}

    assert found == {"pinned", "live"}, (
        f"a naive read returned {found - {'pinned', 'live'}} -- refusal is "
        f"back to being a convention")


async def test_the_same_naive_query_direct_on_the_collection_does_leak(facts):
    """The control. Without the handle this is exactly the old bug, which is
    what makes the test above meaningful rather than decorative."""
    _, db, _ = facts

    leaked = {d["name"] async for d in db.facts.find({})}

    assert leaked == {"pinned", "live", "expired", "revoked"}
    assert "expired" in leaked and "revoked" in leaked


async def test_find_one_refuses_a_forgotten_fact_by_name(facts):
    _, _, docs = facts
    assert await docs.find_one({"name": "live"}) is not None
    assert await docs.find_one({"name": "expired"}) is None
    assert await docs.find_one({"name": "revoked"}) is None
    assert await docs.find_one({"name": "pinned"}) is not None


async def test_count_and_find_cannot_disagree_about_what_exists(facts):
    """A count that includes what a read refuses is how "0 results" and
    "2 documents" end up on the same screen."""
    _, _, docs = facts
    assert await docs.count() == len(await docs.find({})) == 2


async def test_exists_is_reachability_not_storage(facts):
    _, _, docs = facts
    assert await docs.exists({"name": "revoked"}) is False
    assert await docs.exists({"name": "live"}) is True


# ---- the escape hatch has to work, and has to be named ----------------

async def test_including_forgotten_sees_everything(facts):
    """Audit and administration need the whole picture. The point is not that
    it is impossible -- it is that it is *spelled out*."""
    _, _, docs = facts
    everything = {d["name"] for d in await docs.including_forgotten().find({})}
    assert everything == {"pinned", "live", "expired", "revoked"}


async def test_the_escape_hatch_does_not_leak_into_the_original_handle(facts):
    """``including_forgotten()`` returns a new handle. If it mutated this one,
    a single audit call would silently disarm refusal for the rest of the
    process."""
    _, _, docs = facts
    await docs.including_forgotten().find({})
    assert {d["name"] for d in await docs.find({})} == {"pinned", "live"}


# ---- refusal for documents that never went through a query ------------

async def test_search_hits_are_refused_one_at_a_time(facts):
    """The case the query-side filter cannot cover.

    ``$vectorSearch`` hits never pass through ``_query`` -- the deadline is
    deliberately not in the vector index -- so they are admitted per document
    by ``reachable()``. This is the authoritative check, and the reason the
    query-side clause is an optimisation rather than the guarantee.
    """
    _, db, docs = facts
    # Straight from the collection, exactly as a search would hand them over.
    raw = [d async for d in db.facts.find({})]
    assert len(raw) == 4

    admitted = {d["name"] for d in docs.reachable(raw)}
    assert admitted == {"pinned", "live"}


async def test_reachable_accepts_an_explicit_instant(facts):
    """So a caller can ask "what was reachable at 09:00?" without a clock."""
    _, db, docs = facts
    raw = [d async for d in db.facts.find({})]
    long_ago = datetime(2020, 1, 1, tzinfo=timezone.utc)
    # At that instant the "expired" fact had not expired yet; revoked still is.
    names = {d["name"] for d in docs.reachable(raw, when=long_ago)}
    assert "expired" in names
    assert "revoked" not in names


# ---- revocation: unreachable now, erased later ------------------------

async def test_revoke_makes_a_fact_unreachable_without_deleting_it(facts):
    """The operation no vector database has.

    ``delete_many`` is a storage call whose effect on retrieval is
    "eventually". This is a retrieval call whose effect is "next read", and
    the row is still on disk to prove it.
    """
    _, db, docs = facts

    assert await docs.find_one({"name": "live"}) is not None
    n = await docs.revoke({"name": "live"}, reason="leaked secret")
    assert n == 1

    assert await docs.find_one({"name": "live"}) is None, \
        "revocation did not take effect on the next read"
    assert await db.facts.count_documents({"name": "live"}) == 1, \
        "the row should still be on disk -- that is the whole point"

    row = await db.facts.find_one({"name": "live"})
    assert row["forgotten"]["reason"] == "leaked secret"
    assert row["expire_at"] is not None, "revoked rows must still be collected"


async def test_revoking_something_already_forgotten_is_a_no_op(facts):
    """``revoke`` goes through the same refusing query, so it cannot resurrect
    a deadline on a fact that is already gone."""
    _, _, docs = facts
    assert await docs.revoke({"name": "expired"}) == 0


async def test_a_revoked_fact_can_be_kept_briefly_for_proof(facts):
    """``erase_after`` keeps the tombstone readable through the escape hatch,
    for the case where you have to show *when* something stopped being
    reachable."""
    _, _, docs = facts
    await docs.revoke({"name": "live"}, reason="audit",
                      erase_after=timedelta(days=7))

    assert await docs.find_one({"name": "live"}) is None
    kept = await docs.including_forgotten().find_one({"name": "live"})
    assert kept is not None
    assert kept["expire_at"] > datetime.now(timezone.utc) + timedelta(days=6)


async def test_pinning_is_the_absence_of_a_deadline(facts):
    _, db, docs = facts
    await docs.pin({"name": "live"})
    row = await db.facts.find_one({"name": "live"})
    assert row["expire_at"] is None
    assert await docs.find_one({"name": "live"}) is not None


# ---- proof --------------------------------------------------------------

async def test_a_query_side_refusal_is_not_counted_and_says_so(facts):
    """The honest limit of the audit trail.

    ``find()`` pushes the rule into the query, so MongoDB drops forgotten
    facts server-side and the handle never sees them. Counting those would
    mean issuing every read twice. ``refused_at_boundary`` is therefore a
    lower bound, and the field name says so -- an audit number that quietly
    undercounts would be worse than none.
    """
    _, _, docs = facts
    await docs.find({})                       # refuses two, server-side
    assert docs.receipts()["refused_at_boundary"] == 0


async def test_revocation_is_counted_exactly(facts):
    """Unlike refusals, this one is exact: it is counted when it happens."""
    _, _, docs = facts
    await docs.revoke({"name": "live"}, reason="erasure")
    r = docs.receipts()
    assert r["revoked_total"] == 1
    assert r["last_reason"] == "erasure"


async def test_receipts_count_refusals_by_reason(facts):
    """"It became unreachable at T" should be showable, not assertable."""
    _, db, docs = facts
    raw = [d async for d in db.facts.find({})]
    docs.reachable(raw)          # refuses one expired, one revoked

    r = docs.receipts()
    assert r["refused_by_reason"].get(DEADLINE) == 1
    assert r["refused_by_reason"].get(REVOKED) == 1
    assert r["refused_at_boundary"] == 2
    assert r["last_at"] is not None


async def test_refusals_show_up_on_engine_health(facts):
    """A guarantee nobody can observe is a guarantee nobody will notice
    breaking."""
    engine, db, docs = facts
    raw = [d async for d in db.facts.find({})]
    docs.reachable(raw)

    reported = engine.health()["forgetting"]
    assert len(reported) == 1
    assert reported[0]["collection"] == "facts"
    assert reported[0]["refused_at_boundary"] == 2


async def test_declaring_it_forgettable_also_declares_the_ttl(facts):
    """Refusing on read without ever collecting is a storage leak; collecting
    without refusing is the original bug. One declaration, both halves."""
    engine, _, _ = facts
    assert "facts" in [s.collection for s in engine.expiry.specs]


# ---- the boundary the handle also has to keep -------------------------

@pytest.fixture
async def tenanted(core):
    """Two tenants in one collection, behind a handle that declares one."""
    engine, db = core
    handle = engine.model("scoped", tenant="tenant").forgettable()
    await engine.ensure(search_wait_s=0)
    await db.scoped.insert_many([
        {"tenant": "acme", "text": "acme payroll"},
        {"tenant": "globex", "text": "globex merger terms"},
    ])
    return engine, db, handle


async def test_the_naive_read_is_tenant_safe_too(tenanted):
    """The defect this closes, and the reason it mattered.

    This module's promise is that the naive read is the safe read. For a
    while it was only half true: the handle refused forgotten facts and
    silently ignored the ``tenant`` it had been declared with, so
    ``model(tenant="t").forgettable().find({})`` returned every tenant's
    rows -- while ``engine.search`` on the *same model declaration* refused
    the same query. One declaration, two primitives, two answers, which is
    exactly the drift this module exists to remove, reappearing inside it.
    """
    _, _, docs = tenanted
    with pytest.raises(ScopeRequired):
        await docs.find({})


async def test_a_scoped_read_still_works_and_sees_only_its_tenant(tenanted):
    """Enforcing must not mean refusing everything."""
    _, _, docs = tenanted
    rows = await docs.find({"tenant": "acme"})
    assert [r["text"] for r in rows] == ["acme payroll"]


async def test_the_tenant_shape_check_is_inherited_not_reimplemented(tenanted):
    """An operator in the tenant position is refused here for the same
    reason and by the same code as on the search path -- one rule, not two
    that can drift."""
    _, _, docs = tenanted
    with pytest.raises(ScopeInvalid):
        await docs.find({"tenant": {"$ne": "nobody"}})


async def test_revoking_cannot_reach_another_tenant(tenanted):
    """The dangerous direction: forgetting is a write."""
    _, _, docs = tenanted
    with pytest.raises(ScopeRequired):
        await docs.revoke({}, reason="everything everywhere")

    assert await docs.revoke({"tenant": "acme"}, reason="scoped") == 1
    survivors = [r["text"] for r in await docs.find({"tenant": "globex"})]
    assert survivors == ["globex merger terms"]


async def test_audit_sees_forgotten_rows_but_not_foreign_ones(tenanted):
    """``including_forgotten`` sets aside the deadline, not the boundary.

    Seeing forgotten rows is an operational need. Seeing another tenant's
    forgotten rows is a breach with a nicer name.
    """
    _, _, docs = tenanted
    with pytest.raises(ScopeRequired):
        await docs.including_forgotten().find({})

    await docs.revoke({"tenant": "acme"}, reason="audit")
    seen = await docs.including_forgotten().find({"tenant": "acme"})
    assert [r["text"] for r in seen] == ["acme payroll"]


async def test_a_collection_with_no_tenant_is_unaffected(core):
    """Not every collection is multi-tenant, and declaring none must stay a
    valid choice rather than becoming an error."""
    engine, db = core
    free = engine.model("free").forgettable()
    await engine.ensure(search_wait_s=0)
    await db.free.insert_one({"text": "anyone can read this"})
    assert [r["text"] for r in await free.find({})] == ["anyone can read this"]
