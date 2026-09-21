"""Tenancy, held to this package's own step 4.

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

What it is not is a `Rule`. It contributes to the collection query and to the
index filter; it is not asked about a document on the way out. So a batch
handed to `reachable()` -- which is exactly what a `$vectorSearch` hit is --
is not tenant-filtered. That is not a bug in the handle's own paths, where
the query always carries the scope. It is the asymmetry step 4 forbids, on
the one constraint where a user is least likely to notice.

The remedy is one line and ships today. This file pins the gap *and* the
remedy, because a limit stated without one is half a finding.
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


async def test_the_scope_alone_does_not_reach_the_egress_boundary(core):
    """The asymmetry, asserted rather than assumed.

    If this ever starts passing tenant-filtered, the remedy below became
    unnecessary and this file should say so instead of quietly inverting.
    """
    engine, db = core
    notes = engine.model("notes", tenant="tenant_id").forgettable()
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_many([dict(d) for d in CORPUS])

    batch = [d async for d in db.notes.find({})]
    kept = notes.reachable(batch)

    assert len({d["tenant_id"] for d in kept}) == 2, (
        "the scope is a query-half rule: a batch that did not come through "
        "the query is not tenant-filtered on the way out")


async def test_restricted_gives_the_tenant_its_missing_egress_half(core):
    """The remedy, in one line, using only what ships.

    `Restricted` is `needs_caller`, so it compares the document against who
    is asking -- which is what a tenant check is. Installed beside the scope,
    the constraint now exists on both halves and step 4 is satisfied.
    """
    engine, db = core
    guarded = engine.model("memos", tenant="tenant_id").admitting(
        Deadline(), revoked(),
        Restricted(field="tenant_id", claim="tenant_id"))
    await engine.ensure(search_wait_s=0)
    await db.memos.insert_many([dict(d) for d in CORPUS])

    batch = [d async for d in db.memos.find({})]

    acme = guarded.for_caller({"tenant_id": "acme"})
    assert {d["text"] for d in acme.reachable(batch)} == {
        "acme salary bands", "acme roadmap"}, "the foreign row is refused"

    globex = guarded.for_caller({"tenant_id": "globex"})
    assert {d["text"] for d in globex.reachable(batch)} == {
        "globex merger memo"}, "and the boundary is per caller, not per process"

    assert guarded.receipts()["refused_by_reason"]["not_cleared"] == 3


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
