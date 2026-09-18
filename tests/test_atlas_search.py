"""Proof that the Atlas path is the path -- not a branch nobody runs.

Before this, ``atlas`` was inferred from the connection string, so the bundled
dev database (a plain mongod) always answered False and the quickstart silently
ran an in-process cosine loop. ``$vectorSearch`` was effectively dead code in
every environment a developer actually used.

These tests run against the Atlas Local container from docker-compose, so the
default developer experience and the tested one are the same thing.

This is also where the product's central claim is proved: **the void is the
retrieval boundary**, and it is enforced inside mongot -- in both ``$rankFusion``
legs -- rather than filtered afterwards in Python.

Embeddings are written directly rather than earned from Voyage: these assert on
retrieval and ranking, which must not depend on a network call or an API key.
"""

from __future__ import annotations

import asyncio
import random

import pytest

# These assert on the HTTP service's store. Engine-only installs skip the module.
pytest.importorskip("fastapi")

from bson import ObjectId

# mongot indexes asynchronously, so a freshly written doc is not instantly
# searchable. Real code tolerates this; tests have to wait for it.
INDEX_LAG_TIMEOUT = 20.0


def vec(seed: int, dims: int) -> list[float]:
    random.seed(seed)
    return [random.random() for _ in range(dims)]


async def until_searchable(store, voyd_id, query_vec, *, expected: int):
    """Poll until mongot has caught up, or fail loudly rather than assert on an
    empty result that only means 'too early'."""
    deadline = asyncio.get_running_loop().time() + INDEX_LAG_TIMEOUT
    hits: list = []
    while asyncio.get_running_loop().time() < deadline:
        hits = await store.vector_search(voyd_id, query_vec, limit=10)
        if len(hits) >= expected:
            return hits
        await asyncio.sleep(0.5)
    pytest.fail(f"mongot did not index {expected} docs within {INDEX_LAG_TIMEOUT}s "
                f"(got {len(hits)})")


@pytest.fixture
async def dropped(app):
    """Three documents in one namespace -- two in one scope, one in another.

    The split matters: it is what makes "scoped to the namespace" and "scoped to
    the void" two different assertions rather than one.
    """
    dims = app.intelligence.config.dimensions
    voyd_id = ObjectId()
    docs = [
        ("brakes.md", "brake pad replacement and rotor resurfacing", 1, "alpha"),
        ("fault.md", "diagnostic scan for code P0301 misfire cylinder 1", 2, "alpha"),
        ("oil.md", "synthetic oil change with filter", 3, "beta"),
    ]
    await app.store.db.documents.insert_many([
        {"voyd_id": voyd_id, "token": token, "doc_id": name,
         "name": name, "text": text, "key": None, "mime": "text/plain",
         "indexed": True, "embedding": vec(seed, dims)}
        for name, text, seed, token in docs
    ])
    await until_searchable(app.store, voyd_id, vec(1, dims), expected=3)
    return {"voyd_id": voyd_id, "dims": dims}


# ---- the deployment is what we think it is -----------------------------

async def test_the_dev_database_really_is_search_capable(app):
    """The regression guard: if this fails, the quickstart has silently gone
    back to being a plain mongod and search is fake again."""
    store = app.store
    caps = store.engine.capabilities
    assert store.search, "Atlas Local should expose $listSearchIndexes"
    assert caps.rank_fusion, f"$rankFusion needs 8.1+, got {caps.version}"
    assert store.search_ready, "startup must block until indexes are queryable"
    assert store.search_tier == "hybrid"


async def test_capability_is_detected_not_guessed_from_the_uri(app):
    """Atlas Local is reached at mongodb://localhost -- the old URI heuristic
    called that 'not Atlas'. Capability and URI-shape must disagree here."""
    uri = app.store.config.uri.lower()
    assert not uri.startswith("mongodb+srv://") and "mongodb.net" not in uri, (
        "this test is only meaningful against a local-looking URI")
    assert app.store.search is True, "probed, not guessed"


# ---- retrieval ---------------------------------------------------------

async def test_vector_search_runs_on_the_server(app, dropped):
    hits = await app.store.vector_search(
        dropped["voyd_id"], vec(1, dropped["dims"]), limit=3)

    assert [h["name"] for h in hits][0] == "brakes.md", "nearest vector first"
    assert all("score" in h for h in hits)
    assert app.store.degraded_searches == 0, "must not have fallen back to cosine"


async def test_hybrid_beats_pure_vector_on_an_exact_code(app, dropped):
    """The reason hybrid exists. 'P0301' is a part/fault code: embeddings are
    weak at exact rare tokens, lexical search is exact. Fusion gets both, and
    the things people drop in a void are full of identifiers like this.

    The query vector is deliberately brakes.md's, so pure vector ranks the
    wrong doc first and only the lexical half can rescue it.
    """
    query_vec = vec(1, dropped["dims"])

    vector_only = await app.store.vector_search(
        dropped["voyd_id"], query_vec, limit=3)
    assert vector_only[0]["name"] == "brakes.md"

    # Poll the hybrid path: the lexical leg can lag the vector one, and a
    # vector-only ranking here would look like a wrong answer rather than an
    # index that is still catching up.
    deadline = asyncio.get_running_loop().time() + INDEX_LAG_TIMEOUT
    while asyncio.get_running_loop().time() < deadline:
        hybrid = await app.store.vector_search(
            dropped["voyd_id"], query_vec, limit=3, query_text="P0301")
        if hybrid and hybrid[0]["name"] == "fault.md":
            break
        await asyncio.sleep(0.5)

    assert hybrid[0]["name"] == "fault.md", (
        "lexical half should pull the exact code to the top: "
        f"{[h['name'] for h in hybrid]}")


async def test_rank_fusion_is_used_when_query_text_is_supplied(app, dropped):
    """Same inputs, different tier -- confirms query_text actually switches
    pipelines rather than being quietly dropped."""
    query_vec = vec(2, dropped["dims"])
    plain = await app.store.vector_search(dropped["voyd_id"], query_vec, limit=3)
    fused = await app.store.vector_search(
        dropped["voyd_id"], query_vec, limit=3, query_text="synthetic oil filter")

    assert [h["name"] for h in plain] != [h["name"] for h in fused]
    assert app.store.degraded_searches == 0


# ---- the boundary, enforced inside mongot ------------------------------

async def test_search_cannot_cross_a_namespace_boundary(app, dropped):
    """The isolation claim has to hold in the *search index* too, not only in
    the find() filters. This is the one place scoping is delegated to another
    process, which makes it the easiest place to get wrong."""
    other = await app.store.vector_search(
        ObjectId(), vec(1, dropped["dims"]), limit=10)
    assert other == []


async def test_hybrid_search_cannot_cross_a_namespace_boundary(app, dropped):
    """$rankFusion runs two pipelines; both need the filter. A $search leg
    without its compound filter would leak every namespace's documents."""
    leaked = await app.store.vector_search(
        ObjectId(), vec(1, dropped["dims"]), limit=10, query_text="P0301 brake oil")
    assert leaked == []


async def test_the_void_is_the_retrieval_boundary(app, dropped):
    """The product, in one assertion. Scoping to a void must narrow retrieval
    inside mongot -- a file in a sibling void is not a lower-ranked hit, it is
    not a hit."""
    hits = await app.store.vector_search(
        dropped["voyd_id"], vec(3, dropped["dims"]), token="alpha", limit=10)

    names = {h["name"] for h in hits}
    assert names == {"brakes.md", "fault.md"}
    assert "oil.md" not in names, "leaked across a void boundary"

    # oil.md is the nearest vector to seed 3 -- unscoped, it ranks first. So the
    # assertion above is about the filter, not about it being far away.
    unscoped = await app.store.vector_search(
        dropped["voyd_id"], vec(3, dropped["dims"]), limit=10)
    assert unscoped[0]["name"] == "oil.md"


async def test_the_void_boundary_holds_on_the_hybrid_path_too(app, dropped):
    """Both $rankFusion legs need the token filter, not just the vector one --
    otherwise a lexical match is the way around the boundary."""
    hits = await app.store.vector_search(
        dropped["voyd_id"], vec(1, dropped["dims"]), token="beta",
        query_text="P0301 brake pad rotor", limit=10)

    names = {h["name"] for h in hits}
    assert names <= {"oil.md"}, f"lexical leg leaked out of the void: {names}"


# ---- degradation is visible -------------------------------------------

async def test_an_unqueryable_index_falls_back_instead_of_reporting_nothing(
        app, dropped, caplog):
    """The subtle one. A missing or still-building vector index does not raise --
    $vectorSearch just returns zero rows, which looks exactly like "no matches".
    So an unready index must route to cosine, or the void silently appears
    empty and nothing anywhere says why."""
    search = app.store.engine.search_engine
    search.ready = False
    try:
        with caplog.at_level("WARNING", logger="engine.search"):
            hits = await app.store.vector_search(
                dropped["voyd_id"], vec(1, dropped["dims"]), limit=3)
    finally:
        search.ready = True

    assert hits, "must not report an empty void"
    assert hits[0]["name"] == "brakes.md", "fallback is still correctly ranked"
    assert app.store.degraded_searches >= 1
    assert "in-process cosine" in caplog.text


async def test_a_server_side_failure_is_counted_and_logged(app, dropped, caplog):
    """The other degradation path: the query itself errors (bad pipeline, index
    type mismatch). That one does raise, and must be counted, not swallowed."""
    import dataclasses

    search = app.store.engine.search_engine
    original = search.specs["documents"]
    # Point the lexical leg at the vector index: a type mismatch mongot rejects.
    search.specs["documents"] = dataclasses.replace(
        original, text_index=original.vector_index)
    try:
        with caplog.at_level("ERROR", logger="engine.search"):
            hits = await app.store.vector_search(
                dropped["voyd_id"], vec(1, dropped["dims"]), limit=3,
                query_text="P0301")
    finally:
        search.specs["documents"] = original

    assert app.store.degraded_searches >= 1
    assert "degrading to in-process cosine" in caplog.text
    assert hits[0]["name"] == "brakes.md"
