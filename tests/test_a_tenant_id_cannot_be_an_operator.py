"""The tenant boundary holds against a tenant id that is a query operator.

``require_scope`` used to check that the declared tenant field was *present*
and not ``None``. Presence is not shape, and every tier interpolates a filter
value straight into a query:

- ``$vectorSearch``'s ``filter`` accepts ``$ne`` / ``$gt`` / ``$nin``,
- the cosine fallback is a plain ``find``,
- the lexical leg's ``equals`` rejects a non-scalar, which trips the
  degrade path and serves the same unbounded query through cosine instead.

So ``filters={"voyd_id": {"$ne": "nobody"}}`` passed the check and then
matched *every* tenant. Measured, before the fix, on Atlas Local 8.x: both
the vector-only leg and ``$rankFusion`` returned rows from two tenants for
all five payloads below.

This is the leak the README calls "a data breach that arrives as an answer",
so it is asserted on all three tiers rather than on the one a laptop happens
to pick. The pure-logic half needs no MongoDB and runs on an engine-only
install.
"""

from __future__ import annotations

import random
import uuid
from dataclasses import replace
from datetime import datetime, timezone

import pytest
from bson import ObjectId

from voyd.engine import FilterInvalid, ScopeError, ScopeInvalid, ScopeRequired
from voyd.engine.errors import require_scope

DIMS = 8

# Each of these is a *presence*-valid tenant id and a query operator. The
# first four are operators the vector leg genuinely supports -- which is what
# made them leak rather than error.
OPERATOR_PAYLOADS = [
    {"$ne": "nonexistent"},
    {"$gt": ""},
    {"$exists": True},
    {"$nin": []},
    {"$regex": ".*"},
]


def vec(seed: int) -> list[float]:
    random.seed(seed)
    return [random.random() for _ in range(DIMS)]


# ---- pure logic, no I/O ------------------------------------------------

def test_a_missing_tenant_is_still_refused():
    """The original guarantee, unchanged by the shape check."""
    with pytest.raises(ScopeRequired):
        require_scope("notes", "voyd_id", {})
    with pytest.raises(ScopeRequired):
        require_scope("notes", "voyd_id", {"voyd_id": None})
    with pytest.raises(ScopeRequired):
        require_scope("notes", "voyd_id", None)


@pytest.mark.parametrize("payload", OPERATOR_PAYLOADS)
def test_an_operator_in_the_tenant_position_is_refused(payload):
    with pytest.raises(ScopeInvalid) as caught:
        require_scope("notes", "voyd_id", {"voyd_id": payload})
    # The message has to name the field, or a caller cannot tell which of
    # several filters was the unsafe one.
    assert "voyd_id" in str(caught.value)
    assert caught.value.field == "voyd_id"


def test_a_list_tenant_is_refused_too():
    """A list is ``$in`` by another name on the ``find`` path."""
    with pytest.raises(ScopeInvalid):
        require_scope("notes", "voyd_id", {"voyd_id": ["tenant_a", "tenant_b"]})


def test_both_refusals_are_one_thing_to_the_query_path():
    """``query()`` counts and re-raises a single base class.

    If these were unrelated exception types, one of them would eventually be
    caught and the other not.
    """
    assert issubclass(ScopeRequired, ScopeError)
    assert issubclass(ScopeInvalid, ScopeError)
    assert issubclass(ScopeError, ValueError)


@pytest.mark.parametrize("ident", [
    "tenant_a",                                  # a slug or token
    ObjectId(),                                  # the default tenant_type
    uuid.uuid4(),                                # a session id
    42,                                          # an integer key
    datetime(2026, 1, 1, tzinfo=timezone.utc),   # unusual, but a scalar
])
def test_every_scalar_id_a_real_caller_uses_is_allowed(ident):
    """The fix must not narrow the legitimate surface.

    Over-restricting here would be the same bug in the other direction: a
    caller with ObjectId tenants discovering at runtime that only strings
    work.
    """
    assert require_scope("notes", "voyd_id", {"voyd_id": ident})["voyd_id"] == ident


def test_a_non_tenant_filter_cannot_smuggle_an_operator_either():
    """Not a tenant breach -- but it silently changes which tier answers.

    ``equals`` cannot express an operator, so the lexical leg would fail, the
    query would degrade to cosine, and the filter would then mean whatever
    the operator means. The three tiers must agree about which documents
    exist, so this is refused rather than degraded.
    """
    with pytest.raises(FilterInvalid) as caught:
        require_scope("notes", "voyd_id",
                      {"voyd_id": "tenant_a", "kind": {"$ne": "secret"}})
    assert caught.value.field == "kind"

    # A scalar in the same position is fine, and a None is simply ignored.
    ok = require_scope("notes", "voyd_id",
                       {"voyd_id": "tenant_a", "kind": "note", "other": None})
    assert ok["kind"] == "note"


def test_require_scope_does_not_mutate_the_callers_filters():
    original = {"voyd_id": "tenant_a"}
    out = require_scope("notes", "voyd_id", original)
    out["injected"] = True
    assert "injected" not in original


# ---- against the real query planner, on every tier --------------------

@pytest.fixture
async def two_tenants(core):
    """One collection, two tenants, indexed and confirmed queryable.

    ``ensure()`` waits for the index to be *queryable*, not for these rows to
    be *indexed* -- so the honest query is polled until it returns, or the
    containment assertions below would pass against an empty index and prove
    nothing.
    """
    import asyncio

    engine, db = core
    engine.model("notes", tenant="voyd_id").searchable(
        vector_path="vector", dimensions=DIMS, text_paths=("text",))
    await engine.ensure(search_wait_s=90)

    await db.notes.insert_many([
        {"voyd_id": "tenant_a", "text": "acme quarterly numbers", "vector": vec(1)},
        {"voyd_id": "tenant_b", "text": "globex quarterly numbers", "vector": vec(2)},
    ])

    # Loud, not skipped, and deliberately so. The repo's convention is that a
    # fixture may skip when the environment never got ready -- but these are
    # the tenant-boundary assertions, and a suite that goes green because
    # mongot was slow is worse than one that goes red. 120s because that is
    # the real ceiling on a loaded machine: this first timed out at 60s while
    # a second suite and a benchmark were contending for the same mongot.
    timeout = 120
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if await engine.search("notes", vec(1), filters={"voyd_id": "tenant_a"}):
            break
        await asyncio.sleep(0.5)
    else:
        pytest.fail(
            f"mongot did not index the fixture rows within {timeout}s, so the "
            f"containment assertions would have run against an empty index "
            f"and proved nothing. Run the suite alone -- a concurrent suite "
            f"or benchmark starves mongot.")

    return engine, db


def _force_cosine(engine):
    """Drop to the fallback tier. ``capabilities`` is frozen, so replace it."""
    se = engine.search_engine
    se.capabilities = replace(se.capabilities, search=False, rank_fusion=False)


@pytest.mark.parametrize("payload", OPERATOR_PAYLOADS)
async def test_the_vector_leg_refuses_an_operator_tenant(two_tenants, payload):
    engine, _ = two_tenants
    with pytest.raises(ScopeInvalid):
        await engine.search("notes", vec(1), filters={"voyd_id": payload})


@pytest.mark.parametrize("payload", OPERATOR_PAYLOADS)
async def test_the_hybrid_legs_refuse_an_operator_tenant(two_tenants, payload):
    """``text=`` is what routes to ``$rankFusion``.

    Both legs matter: a miss on either one leaks every tenant, and before the
    fix this path returned rows from both tenants for every payload.
    """
    engine, _ = two_tenants
    with pytest.raises(ScopeInvalid):
        await engine.search("notes", vec(1), text="quarterly",
                            filters={"voyd_id": payload})


@pytest.mark.parametrize("payload", OPERATOR_PAYLOADS)
async def test_the_cosine_fallback_refuses_an_operator_tenant(two_tenants, payload):
    """The degraded tier is where this would have been missed.

    It is a plain ``find``, so it interprets operators natively -- and it is
    the tier a deployment silently lands on when mongot is unhappy.
    """
    engine, _ = two_tenants
    _force_cosine(engine)
    with pytest.raises(ScopeInvalid):
        await engine.search("notes", vec(1), filters={"voyd_id": payload})


async def test_the_honest_query_still_works_on_all_three_tiers(two_tenants):
    """The containment tests above are worthless if search is simply broken."""
    engine, _ = two_tenants

    vector_only = await engine.search("notes", vec(1), filters={"voyd_id": "tenant_a"})
    hybrid = await engine.search("notes", vec(1), text="quarterly",
                                 filters={"voyd_id": "tenant_a"})
    _force_cosine(engine)
    fallback = await engine.search("notes", vec(1), filters={"voyd_id": "tenant_a"})

    for tier, hits in (("vector", vector_only), ("hybrid", hybrid),
                       ("cosine", fallback)):
        assert hits, f"{tier} returned nothing for a legitimate query"
        assert {h["voyd_id"] for h in hits} == {"tenant_a"}, \
            f"{tier} crossed the tenant boundary"


async def test_a_refused_scope_is_counted_and_observable(two_tenants):
    """A refusal nobody can see is a refusal nobody will notice being wrong.

    ``scope_refused`` is already on ``/healthz``; an operator tenant has to
    land there too, because a spike in it is the signal that something is
    probing the boundary.
    """
    engine, _ = two_tenants
    before = engine.health()["search"]["scope_refused"]

    with pytest.raises(ScopeInvalid):
        await engine.search("notes", vec(1), filters={"voyd_id": {"$ne": "x"}})
    with pytest.raises(ScopeRequired):
        await engine.search("notes", vec(1), filters={})

    assert engine.health()["search"]["scope_refused"] == before + 2
