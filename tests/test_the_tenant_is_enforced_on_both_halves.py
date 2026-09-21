"""Tenancy, held to this package's own step 4 -- and it used to fail it.

`AHA.md` step 4 is the rule the whole design rests on: *any rule pushed into a
query or an index filter must also exist as a per-document check, or one read
path prunes correctly and another admits the same document.* Every reason in
`rules.py` obeys it. The tenant scope does not, and that is worth stating
plainly because tenancy is the constraint most users think they are buying.

`model("notes", tenant="tenant_id")` is excellent at the things it does: the
field becomes *required*, so an unscoped `find({})` raises instead of
returning every tenant, and the value must be a scalar id, so the
`{"$ne": "other"}` injection that passes a presence check and then matches
everything is refused. Both are tested below, and the second one is a real
breach this repository already measured -- `$vectorSearch`'s filter accepts
`$ne`, so presence-checking plus a vector index is a leak with a green suite.

What it was not, until the commit that renamed this file, was a check on the
way *out*. The scope contributed to the collection query and to the index
filter and was never asked about a document, so a batch handed to
`reachable()` -- which is exactly what a `$vectorSearch` hit is -- came back
holding every tenant. Not a leak on the handle's own paths, where the query
always carries the scope, but precisely the asymmetry step 4 forbids, sitting
on the constraint a reader is least likely to check.

It is now enforced on both halves from one value. `find`, `find_one` and
`search` bind the tenant their filters already require, so the per-document
check tests the same thing the query pushed down rather than trusting that it
worked. `reachable()` has no filters to read, so an unbound read on a scoped
collection **raises** -- the same refusal `find({})` has always made, because
they are the same mistake reached by different roads.
"""

from __future__ import annotations

import pytest

from voyd.engine import (Deadline, Restricted, ScopeInvalid, ScopeRequired,
                         revoked)

CORPUS = [
    {"tenant_id": "acme",   "text": "acme salary bands"},
    {"tenant_id": "acme",   "text": "acme roadmap"},
    {"tenant_id": "globex", "text": "globex merger memo"},
]


async def test_the_tenant_field_is_required_rather_than_remembered(core):
    """The part that works, and it is the part that matters most day to day.

    You do not have to remember the filter. You have to remember nothing:
    the unscoped read raises.
    """
    engine, db = core
    notes = engine.model("notes", tenant="tenant_id").forgettable()
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_many([dict(d) for d in CORPUS])

    with pytest.raises(ScopeRequired):
        await notes.find({})
    with pytest.raises(ScopeRequired):
        await notes.find({"tenant_id": None})

    assert {d["text"] for d in await notes.find({"tenant_id": "acme"})} == {
        "acme salary bands", "acme roadmap"}


@pytest.mark.parametrize("operator", [
    {"$ne": "globex"}, {"$exists": True}, {"$gt": ""}, {"$nin": ["nobody"]},
], ids=lambda o: next(iter(o)))
async def test_a_tenant_id_that_is_an_operator_is_refused(core, operator):
    """The breach that arrives as an answer.

    A presence check passes every one of these and then matches every tenant,
    because the value is interpolated straight into a filter that supports
    operators. Presence is not shape.
    """
    engine, db = core
    notes = engine.model("notes", tenant="tenant_id").forgettable()
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_many([dict(d) for d in CORPUS])

    with pytest.raises(ScopeInvalid):
        await notes.find({"tenant_id": operator})


async def test_an_unbound_batch_raises_rather_than_returning_every_tenant(core):
    """The hole, closed, asserted in the fail-closed direction.

    The old behaviour returned both tenants from this call. Returning the
    *caller's* tenant would have been a guess about which read this was;
    returning everything was the bug. Raising is the only answer that is not
    one of those two, and it matches what `find({})` has always done.
    """
    engine, db = core
    notes = engine.model("notes", tenant="tenant_id").forgettable()
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_many([dict(d) for d in CORPUS])

    batch = [d async for d in db.notes.find({})]
    with pytest.raises(ScopeRequired):
        notes.reachable(batch)


async def test_a_bound_batch_is_filtered_per_document(core):
    """And bound, it is the egress half the constraint was missing.

    `off_scope` is counted apart from `not_cleared` deliberately: a caller
    reaching above their clearance is somebody probing, while a document
    arriving from outside the read's scope means an index filter and a
    per-document check have disagreed, and exactly one of them is
    authoritative.
    """
    engine, db = core
    notes = engine.model("notes", tenant="tenant_id").forgettable()
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_many([dict(d) for d in CORPUS])
    batch = [d async for d in db.notes.find({})]

    assert {d["text"] for d in notes.for_tenant("acme").reachable(batch)} == {
        "acme salary bands", "acme roadmap"}
    assert {d["text"] for d in notes.for_tenant("globex").reachable(batch)} == {
        "globex merger memo"}
    assert notes.receipts()["refused_by_reason"]["off_scope"] == 3


async def test_binding_does_not_mutate_the_shared_handle(core):
    """Handles are deduplicated per collection, so a `for_tenant` that
    assigned to `self` would make the last request's tenant the current one,
    under concurrency, in the check that decides whose documents a caller
    sees. The same reason `for_caller` is a clone."""
    engine, db = core
    notes = engine.model("notes", tenant="tenant_id").forgettable()
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_many([dict(d) for d in CORPUS])
    batch = [d async for d in db.notes.find({})]

    acme = notes.for_tenant("acme")
    globex = notes.for_tenant("globex")
    assert acme is not notes and globex is not notes and acme is not globex
    assert len(acme.reachable(batch)) == 2, "globex's binding did not bleed in"
    with pytest.raises(ScopeRequired):
        notes.reachable(batch)          # the shared handle is still unbound


async def test_a_bound_handle_makes_an_empty_filter_complete(core):
    """`find({})` on a bound handle is no longer an error: the tenant is
    carried. A filter naming a *different* tenant is a contradiction rather
    than a narrowing, so it is refused rather than silently intersected."""
    engine, db = core
    notes = engine.model("notes", tenant="tenant_id").forgettable()
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_many([dict(d) for d in CORPUS])

    acme = notes.for_tenant("acme")
    assert {d["text"] for d in await acme.find({})} == {
        "acme salary bands", "acme roadmap"}
    with pytest.raises(ScopeInvalid):
        await acme.find({"tenant_id": "globex"})


async def test_restricted_still_composes_with_the_scope(core):
    """The old remedy, kept as a test rather than as advice.

    Before the fix, `Restricted(field="tenant_id", claim="tenant_id")` was how
    a careful user closed this themselves. It still works and still composes,
    which matters: somebody's code out there does this, and the built-in
    check must not double-refuse or conflict with it.
    """
    engine, db = core
    guarded = engine.model("memos", tenant="tenant_id").admitting(
        Deadline(), revoked(),
        Restricted(field="tenant_id", claim="tenant_id"))
    await engine.ensure(search_wait_s=0)
    await db.memos.insert_many([dict(d) for d in CORPUS])

    batch = [d async for d in db.memos.find({})]

    acme = guarded.for_caller({"tenant_id": "acme"}).for_tenant("acme")
    assert {d["text"] for d in acme.reachable(batch)} == {
        "acme salary bands", "acme roadmap"}, "the foreign row is refused"

    globex = guarded.for_caller({"tenant_id": "globex"}).for_tenant("globex")
    assert {d["text"] for d in globex.reachable(batch)} == {
        "globex merger memo"}, "and the boundary is per caller, not per process"

    refused = guarded.receipts()["refused_by_reason"]
    assert refused["off_scope"] + refused.get("not_cleared", 0) >= 3, (
        "the two checks agree; which one fires first is not a contract")


async def test_the_query_half_still_works_with_the_rule_installed(core):
    """Belt and braces must not become belt instead of braces.

    Adding the per-document rule must not weaken the scope: the unscoped read
    still raises, and a scoped read still returns only that tenant.
    """
    engine, db = core
    guarded = engine.model("memos", tenant="tenant_id").admitting(
        Deadline(), revoked(),
        Restricted(field="tenant_id", claim="tenant_id"))
    await engine.ensure(search_wait_s=0)
    await db.memos.insert_many([dict(d) for d in CORPUS])

    with pytest.raises(ScopeRequired):
        await guarded.for_caller({"tenant_id": "acme"}).find({})

    acme = guarded.for_caller({"tenant_id": "acme"})
    assert len(await acme.find({"tenant_id": "acme"})) == 2
