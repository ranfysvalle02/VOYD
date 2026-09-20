"""`deleted=true` is the smallest member of a protocol, not a category apart.

The claim VOYD makes about its own abstraction is that "may this fact reach a
consumer?" is one predicate, and the everyday mechanisms teams hand-write --
soft-delete, TTL, feature flags, row-level security, token budgets -- are
reasons in it, not separate machinery. That is easy to assert and worth
pinning, so this expresses five of them as Rules on one handle and checks the
two things a claim like that has to earn:

1. they refuse the right document, each under its own name; and
2. the query half (``find``) and the per-document half (``reachable``) agree,
   which is exactly what a hand-written ``deleted=true`` filter does *not* buy
   you, because a ``$vectorSearch`` hit never passes through it.

The two custom rules are imported from ``examples/rosetta.py`` on purpose:
they are a stranger's code, written against the public contract, and pinning
them here means the demo cannot rot into a lie.
"""

from __future__ import annotations

from datetime import timedelta

from examples.rosetta import BehindFlag, SoftDeleted
from voyd.engine import Budget, Deadline, Restricted, now

SEED = [
    {"name": "live", "audience": ["support"]},
    {"name": "soft_deleted", "audience": ["support"], "deleted": True},
    {"name": "expired", "audience": ["support"]},              # expire_at set below
    {"name": "behind_gamma", "audience": ["support"], "feature": "gamma"},
    {"name": "wrong_audience", "audience": ["legal"]},
]


# ---- the two custom rules, as pure predicates (no database) ---------------

def test_soft_delete_is_the_smallest_possible_rule():
    r = SoftDeleted()
    assert r.refuses({"deleted": True}) is True
    assert r.refuses({"deleted": False}) is False
    assert r.refuses({}) is False, "absent is not deleted"
    assert r.clause() == {"deleted": {"$ne": True}}


def test_a_feature_flag_is_a_caller_aware_rule():
    r = BehindFlag()
    assert r.needs_caller is True
    assert r.refuses({"feature": "beta"}, caller={"flags": ["beta"]}) is False
    assert r.refuses({"feature": "gamma"}, caller={"flags": ["beta"]}) is True
    assert r.refuses({}, caller={"flags": []}) is False, "names no flag: public"
    assert r.refuses({"feature": "beta"}, caller={}) is True, "no claim, no access"
    assert r.clause() is None
    assert r.clause_for({"flags": ["beta"]})["$or"][-1] == {
        "feature": {"$in": ["beta"]}}


# ---- five reasons, one handle, both halves, against a real database -------

async def _catalog(core):
    engine, db = core
    docs = engine.model("catalog").admitting(
        SoftDeleted(), Deadline(), BehindFlag(), Restricted())
    await engine.ensure(search_wait_s=0)
    rows = [dict(r) for r in SEED]
    for r in rows:
        if r["name"] == "expired":
            r["expire_at"] = now() - timedelta(hours=1)
    await db.catalog.insert_many(rows)
    return engine, db, docs


async def test_one_handle_enforces_all_four_query_reasons_and_the_halves_agree(core):
    engine, db, docs = await _catalog(core)
    reader = docs.for_caller({"flags": ["beta"], "groups": ["support"]})

    queried = {d["name"] for d in await reader.find({})}
    raw = [d async for d in db.catalog.find({})]
    per_doc = {d["name"] for d in reader.reachable(raw)}

    assert len(raw) == 5, "all five rows are on disk"
    assert queried == {"live"}, "the query half admits only the clean document"
    assert per_doc == {"live"}, (
        "the query and per-document halves disagree -- one of the search tiers "
        "would leak")


async def test_each_mechanism_is_refused_under_its_own_name(core):
    engine, db, docs = await _catalog(core)
    reader = docs.for_caller({"flags": ["beta"], "groups": ["support"]})

    raw = [d async for d in db.catalog.find({})]
    reader.reachable(raw)                       # count on the per-document half
    reasons = reader.receipts()["refused_by_reason"]

    assert reasons.get("deleted") == 1
    assert reasons.get("deadline") == 1
    assert reasons.get("behind_flag") == 1
    assert reasons.get("not_cleared") == 1      # Restricted's reason
    assert sum(reasons.values()) == 4, "each of the four tripped exactly once"


async def test_soft_delete_as_a_rule_matches_the_adhoc_filter_then_holds_further(core):
    """The subsumption, stated directly: the rule's query half is byte-for-byte
    the filter a team would hand-write, and it *additionally* holds on the
    per-document half a hand-written filter cannot reach."""
    engine, db = core
    docs = engine.model("plain").admitting(SoftDeleted())
    await engine.ensure(search_wait_s=0)
    await db.plain.insert_many([
        {"name": "a"},
        {"name": "b", "deleted": True},
        {"name": "c", "deleted": False},
    ])

    handle_side = {d["name"] for d in await docs.find({})}
    adhoc_side = {d["name"] async for d in
                  db.plain.find({"deleted": {"$ne": True}})}
    assert handle_side == adhoc_side == {"a", "c"}, "the query halves match"

    raw = [d async for d in db.plain.find({})]
    assert {d["name"] for d in docs.reachable(raw)} == {"a", "c"}, (
        "and the same rule holds per document, which the ad-hoc filter never "
        "touches -- this is the half a $vectorSearch hit needs")


async def test_the_budget_is_the_reason_with_no_query_half(core):
    """Four of the five push down; the budget cannot, and that is the point.
    A running total is not a per-document property, let alone a boolean
    field, so it is enforced entirely on egress."""
    engine, db = core
    docs = engine.model("prompts").admitting(Deadline(), Budget(limit=100))
    await engine.ensure(search_wait_s=0)
    await db.prompts.insert_many(
        [{"name": f"c{i}", "tokens": 40} for i in range(4)])

    assert Budget(limit=100).clause() is None, "no query half, by nature"

    async def fetch(n: int) -> list[dict]:
        return [d async for d in db.prompts.find({}).sort("_id", 1).limit(n)]

    page = await docs.saturate(fetch, limit=5)
    assert len(page) == 2, "two 40-token chunks fit in a 100-token budget"
    assert page.spent == 80
    assert "over_budget" in page.refused
    assert page.starved is False, "budget-complete is complete, not starved"
