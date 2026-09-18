"""Declaring server-side embedding, on a deployment that cannot do it yet.

``SearchSpec.auto_embed`` asks mongot to produce the vectors: the index holds
text, the query is text, and nothing in this process ever computes an
embedding. On a deployment with the models registered that is a real
simplification -- the embedder and the index cannot disagree about the model,
because there is only one of them.

Atlas Local is not such a deployment. Measured against
``mongodb/mongodb-atlas-local:8.2`` (mongot 0.69.1, edition ``localDev``),
``autoEmbed`` validates field by field and then answers ``supported models
are: []``: the capability is absent rather than misconfigured, with no
credential to supply and no registration command to call. That finding is
written up in BUG.md.

So this file tests the half that is real here, which is the more important
half anyway: **declaring it must be safe on a deployment that cannot honour
it.** The spec says what it wants, the engine gets a refusal, and it falls
back to a client-supplied vector index -- loudly, counted, and visible on
``health()``, with no branch anywhere upstream. The day models are registered
the same code takes the other path.

What is *not* tested here, honestly: the happy path. No assertion below
proves mongot embeds correctly, because nothing local can. The pieces that
depend on a real cluster are the query shape and the write path, and they are
marked as such.
"""

from __future__ import annotations

import pytest

from voyd.engine.search import SearchSpec

MODEL = "voyage-3-large"


# ---- the declaration, as pure logic -----------------------------------

def test_the_two_index_shapes_are_different_requests():
    """One holds a vector the client computed; the other holds text the
    server will embed. They are not variations, they are different indexes."""
    spec = SearchSpec("docs", text_paths=("text",), auto_embed=MODEL,
                      tenant_field="tenant", tenant_type="token")

    auto = spec.auto_embed_definition()["fields"][0]
    assert auto["type"] == "autoEmbed"
    assert auto["path"] == "text", "the embedded path is the text field"
    assert auto["model"] == MODEL
    assert auto["modality"] == "text"
    assert "numDimensions" not in auto, \
        "dimensions belong to whoever computes the vector, and that is not us"

    plain = spec.vector_definition()["fields"][0]
    assert plain["type"] == "vector"
    assert plain["path"] == "embedding"
    assert plain["numDimensions"] == spec.dimensions


def test_the_tenant_filter_survives_either_shape():
    """The boundary is not negotiable. Whichever index is built, the tenant
    is a filter field inside it."""
    spec = SearchSpec("docs", auto_embed=MODEL, tenant_field="tenant",
                      tenant_type="token", filter_fields=("kind",))
    for definition in (spec.auto_embed_definition(), spec.vector_definition()):
        filters = {f["path"] for f in definition["fields"]
                   if f.get("type") == "filter"}
        assert filters == {"tenant", "kind"}


def test_not_declaring_it_changes_nothing():
    """The default has to stay exactly what it was."""
    spec = SearchSpec("docs")
    assert spec.auto_embed is None
    assert spec.vector_definition()["fields"][0]["type"] == "vector"


# ---- against the deployment we actually have --------------------------

@pytest.fixture
async def declared(core):
    """A collection that asks for server-side embedding and will not get it."""
    engine, db = core
    engine.model("docs", tenant="tenant").searchable(
        vector_path="embedding", dimensions=8, text_paths=("text",),
        auto_embed=MODEL)
    await engine.ensure(search_wait_s=60)
    return engine, db


async def test_a_deployment_that_cannot_embed_says_so_and_carries_on(declared):
    """The load-bearing test: asking is safe.

    If this failed, adopting ``auto_embed`` before every deployment supports
    it would be reckless, and the feature could not be declared until the
    last cluster caught up.
    """
    engine, _ = declared
    se = engine.search_engine

    assert "docs" in se.auto_embed_declined, (
        "Atlas Local registers no models, so this must have fallen back -- "
        "if it did not, either the image gained the capability (good news, "
        "update BUG.md) or the refusal was swallowed")
    assert "docs" not in se.auto_embed_active
    assert se.embeds_itself("docs") is False


async def test_the_fallback_builds_a_usable_vector_index(declared):
    """Falling back has to leave a working search, not a broken one."""
    engine, db = declared
    idx = {i["name"] async for i in await db.docs.list_search_indexes()}
    assert "docs_vector" in idx

    live = [i async for i in await db.docs.list_search_indexes()
            if i["name"] == "docs_vector"][0]
    kinds = {f.get("type") for f in
             (live.get("latestDefinition") or {}).get("fields", [])}
    assert "vector" in kinds, "the fallback must be a client-vector index"
    assert "autoEmbed" not in kinds


async def test_who_owns_the_embedding_is_on_health(declared):
    """A deployment difference this large must not be something you infer
    from results being worse."""
    engine, _ = declared
    owner = engine.health()["search"]["embedding_owner"]
    assert owner["client"] == ["docs"]
    assert owner["server"] == []


async def test_the_refusal_is_logged_loudly_enough_to_notice(core, caplog):
    """Silently dropping to client-side embedding would be the quiet
    degradation this codebase exists to refuse.

    Declared on a *fresh* collection, because the refusal happens when the
    index is created. A second ``ensure()`` on an existing index does not
    re-attempt it -- which is correct, and is what the next test covers.
    """
    engine, _ = core
    engine.model("fresh", tenant="tenant").searchable(
        vector_path="embedding", dimensions=8, text_paths=("text",),
        auto_embed=MODEL)

    with caplog.at_level("ERROR"):
        await engine.ensure(search_wait_s=30)

    said = [r.message for r in caplog.records if "fresh" in r.message]
    assert said, caplog.text
    message = said[0].lower()
    assert "cannot" in message and "falling back" in message
    # The operator has to be told what is now their problem.
    assert "must keep producing embeddings" in message


async def test_a_restart_does_not_flip_the_answer(declared):
    """The second boot reads the index that exists rather than re-asking.

    It matters that this still reports ``client``: if a restart silently
    marked the collection as server-embedded, the write path would stop
    supplying vectors against an index that needs them, and the collection
    would go quietly unsearchable.
    """
    engine, _ = declared
    before = engine.health()["search"]["embedding_owner"]

    await engine.ensure(search_wait_s=30)

    assert engine.health()["search"]["embedding_owner"] == before
    assert engine.search_engine.embeds_itself("docs") is False


async def test_search_still_works_on_the_fallback(declared):
    """The whole point of degrading rather than failing."""
    import asyncio
    import random

    engine, db = declared
    rng = random.Random(1)
    vec = [rng.random() for _ in range(8)]
    await db.docs.insert_one({"tenant": "t1", "text": "fault code P0301",
                              "embedding": vec})

    deadline = asyncio.get_running_loop().time() + 60
    while asyncio.get_running_loop().time() < deadline:
        hits = await engine.search("docs", vec, filters={"tenant": "t1"})
        if hits:
            assert hits[0]["text"] == "fault code P0301"
            return
        await asyncio.sleep(0.5)
    pytest.fail("the fallback index never served a query")


# ---- the shape the other path will take -------------------------------

def test_the_query_is_text_when_the_server_owns_the_embedding():
    """Unverifiable end to end here, so the *stage* is asserted directly.

    With ``autoEmbed`` there is no query vector: the index holds text and
    mongot embeds the query with the same model it used on write. Getting
    this wrong would be invisible until a real cluster, so the pipeline shape
    is pinned now rather than discovered later.
    """
    from voyd.engine.capabilities import Capabilities
    from voyd.engine.search import SearchEngine

    spec = SearchSpec("docs", text_paths=("text",), auto_embed=MODEL,
                      vector_index="docs_vector")
    se = SearchEngine(db=None, capabilities=Capabilities(search=True))
    se.specs["docs"] = spec

    se.auto_embed_active.append("docs")
    stage = se._vector_stage(spec, [0.1] * 8, "misfire", {"tenant": "t1"}, 5)
    vs = stage["$vectorSearch"]
    assert vs["query"] == "misfire"
    assert vs["path"] == "text"
    assert "queryVector" not in vs
    assert vs["filter"] == {"tenant": "t1"}, "the boundary still applies"

    se.auto_embed_active.remove("docs")
    stage = se._vector_stage(spec, [0.1] * 8, "misfire", {"tenant": "t1"}, 5)
    vs = stage["$vectorSearch"]
    assert vs["queryVector"] == [0.1] * 8
    assert vs["path"] == "embedding"
    assert "query" not in vs
