"""A search index that already exists is not automatically the right index.

``ensure_indexes`` used to skip any index whose *name* it recognised. So
changing a spec -- another ``text_path``, different ``dimensions``, a new
filter field -- left the old index in place and every subsequent query ran
against it. No error, no warning, just answers computed from a definition the
application no longer declares. That is the same shape as every other bug this
engine was built to remove: the failure arrives as a result.

The two halves are not symmetric, which is why this file exists:

- a ``search`` (lexical) definition can be updated in place, so drift is
  *corrected*;
- a ``vectorSearch`` definition cannot be. ``update_search_index`` validates
  whatever it receives as a lexical definition and fails with ``"mappings" is
  required``. Drift there can only be *reported*, so it is reported loudly and
  named on ``health()``.

The unit-level tests below pin the comparison itself, including the case that
makes naive equality useless: Atlas fills in ``indexOptions``, ``norms`` and
``store`` on a string field, so a definition read back never equals the one
sent. If that registered as drift, every start-up would rewrite its indexes.
"""

from __future__ import annotations

import asyncio

import pytest

from voyd.engine.search import SearchSpec, drifted

# ---- the comparison, no I/O -------------------------------------------

VECTOR = {"fields": [
    {"type": "vector", "path": "embedding",
     "numDimensions": 8, "similarity": "cosine"},
    {"type": "filter", "path": "tenant_id"},
]}

LEXICAL = {"mappings": {"dynamic": False, "fields": {
    "text": {"type": "string"},
    "tenant_id": {"type": "token"},
}}}

# What Atlas actually hands back for LEXICAL: three keys it added itself.
LEXICAL_AS_STORED = {"mappings": {"dynamic": False, "fields": {
    "text": {"type": "string", "indexOptions": "offsets",
             "norms": "include", "store": True},
    "tenant_id": {"type": "token"},
}}}


def test_atlas_filling_in_its_own_defaults_is_not_drift():
    """The test that keeps this feature from being worse than nothing: if
    normalisation read as drift, every process start would rewrite every
    index, forever."""
    assert drifted("search", LEXICAL, LEXICAL_AS_STORED) is False


def test_an_index_that_matches_its_spec_is_not_drift():
    assert drifted("vectorSearch", VECTOR, VECTOR) is False


def test_a_missing_index_is_not_drift():
    """Absent is a different state, handled by creating it."""
    assert drifted("search", LEXICAL, None) is False
    assert drifted("vectorSearch", VECTOR, None) is False


@pytest.mark.parametrize("change", [
    pytest.param({"fields": VECTOR["fields"] + [{"type": "filter",
                                                 "path": "expire_at"}]},
                 id="a filter field was added"),
    pytest.param({"fields": [{"type": "vector", "path": "embedding",
                              "numDimensions": 1024, "similarity": "cosine"}]},
                 id="dimensions changed"),
    pytest.param({"fields": [{"type": "vector", "path": "embedding",
                              "numDimensions": 8, "similarity": "dotProduct"}]},
                 id="similarity changed"),
])
def test_a_changed_vector_spec_is_drift(change):
    """Each of these silently changes what a query means."""
    assert drifted("vectorSearch", change, VECTOR) is True


@pytest.mark.parametrize("change", [
    pytest.param({"mappings": {"dynamic": False, "fields": {
        "text": {"type": "string"}, "tenant_id": {"type": "token"},
        "name": {"type": "string"}}}}, id="a text path was added"),
    pytest.param({"mappings": {"dynamic": False, "fields": {
        "text": {"type": "string"}}}}, id="the tenant field was dropped"),
    pytest.param({"mappings": {"dynamic": False, "fields": {
        "text": {"type": "string"},
        "tenant_id": {"type": "objectId"}}}}, id="the tenant type changed"),
    pytest.param({"mappings": {"dynamic": True, "fields": {
        "text": {"type": "string"},
        "tenant_id": {"type": "token"}}}}, id="dynamic was turned on"),
])
def test_a_changed_lexical_spec_is_drift(change):
    assert drifted("search", change, LEXICAL_AS_STORED) is True


# ---- against a real deployment ---------------------------------------

async def _wait(coll, name: str, predicate, timeout: float = 90.0) -> dict | None:
    """Poll one index until ``predicate`` holds. Bounded, never a bare sleep."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        for i in [x async for x in await coll.list_search_indexes()]:
            if i["name"] == name and predicate(i):
                return i
        await asyncio.sleep(1.0)
    return None


@pytest.fixture
async def searchable(core):
    """An engine with one searchable collection whose indexes are live."""
    engine, db = core
    if not engine.capabilities.search:
        pytest.skip("deployment has no Atlas Search")

    spec = SearchSpec(collection="docs", dimensions=8,
                      text_paths=("text",), tenant_field="tenant",
                      tenant_type="token")
    engine.searchable(spec)
    await db.docs.insert_one({"tenant": "A", "text": "seed",
                              "embedding": [1.0] * 8})
    if not await engine.search_engine.ensure_indexes(wait_s=90.0):
        # mongot builds every suite database's indexes at once, so under a
        # full run this can time out. That is the environment being busy, not
        # drift detection being wrong -- and this suite skips on environment,
        # never fails on it. Every assertion about drift below stays hard.
        pytest.skip("search indexes did not become queryable in 90s "
                    "(mongot is busy); nothing to reconcile against")
    return engine, db, spec


async def test_a_lexical_index_that_drifts_is_corrected_in_place(searchable):
    """Declare another text path, re-ensure, and the live index should follow."""
    engine, db, spec = searchable
    wider = SearchSpec(collection="docs", dimensions=8,
                       text_paths=("text", "name"), tenant_field="tenant",
                       tenant_type="token")
    engine.search_engine.specs["docs"] = wider

    await engine.search_engine.ensure_indexes(wait_s=90.0)

    live = await _wait(db.docs, spec.text_index,
                       lambda i: "name" in
                       i.get("latestDefinition", {})
                        .get("mappings", {}).get("fields", {}))
    assert live is not None, "the lexical index was not updated to match"
    assert f"docs.{spec.text_index}" not in engine.search_engine.stale, \
        "an index that was corrected must not be reported as stale"


async def test_a_drifted_vector_index_is_reported_and_not_silently_kept(
        searchable, caplog):
    """A vectorSearch definition cannot be updated in place, so the only
    honest options are to say so and to name it. Saying nothing -- the old
    behaviour -- means queries quietly use the previous definition."""
    engine, db, spec = searchable
    changed = SearchSpec(collection="docs", dimensions=8,
                         text_paths=("text",), tenant_field="tenant",
                         tenant_type="token",
                         filter_fields=("expire_at",))
    engine.search_engine.specs["docs"] = changed

    with caplog.at_level("ERROR", logger="engine.search"):
        await engine.search_engine.ensure_indexes(wait_s=15.0)

    ref = f"docs.{spec.vector_index}"
    assert ref in engine.search_engine.stale, \
        "a vector index that cannot be corrected must be named"
    assert ref in engine.health()["search"]["stale_indexes"], \
        "and a probe has to be able to see it"
    assert any("cannot be updated in place" in r.getMessage()
               for r in caplog.records), "the reason must be logged, not implied"


async def test_reconciling_an_unchanged_index_is_a_no_op(searchable, caplog):
    """Re-running ``ensure`` on a correct deployment must be silent. If this
    fails, every restart rewrites its indexes."""
    engine, _, _ = searchable
    with caplog.at_level("WARNING", logger="engine.search"):
        await engine.search_engine.ensure_indexes(wait_s=90.0)
    assert engine.search_engine.stale == []
    assert [r for r in caplog.records if "drift" in r.message.lower()] == []


# ---- the model is part of the definition -----------------------------

def test_drift_sees_the_embedding_model_change():
    """The semantics of an autoEmbed index *are* its model.

    Reducing the field to ``("autoEmbed", path)`` made voyage-4 and
    voyage-4-large identical signatures, so changing the declared model
    produced no drift, the index kept the old one, and every later query was
    embedded by a model the application no longer declared. Ordinary-looking
    results, wrong embeddings, no signal -- the exact failure drifted()
    exists to catch, hiding on the newest index type.
    """
    from voyd.engine.search import SearchSpec, drifted

    base = SearchSpec("docs", text_paths=("text",),
                      auto_embed="voyage-4").auto_embed_definition()
    other_model = SearchSpec("docs", text_paths=("text",),
                             auto_embed="voyage-4-large").auto_embed_definition()
    other_modality = SearchSpec("docs", text_paths=("text",),
                                auto_embed="voyage-4",
                                auto_embed_modality="image").auto_embed_definition()

    assert drifted("vectorSearch", other_model, base) is True
    assert drifted("vectorSearch", other_modality, base) is True
    assert drifted("vectorSearch", base, base) is False


def test_drift_still_sees_a_dimension_change_on_a_client_vector_index():
    """The control: the older index type must keep working the same way."""
    from voyd.engine.search import SearchSpec, drifted

    wide = SearchSpec("docs", dimensions=1024).vector_definition()
    narrow = SearchSpec("docs", dimensions=512).vector_definition()
    assert drifted("vectorSearch", narrow, wide) is True
