"""Server-side embedding, verified against a real cluster.

``auto_embed`` asks mongot to produce the vectors: the index holds text, the
query is text, and nothing in this process ever computes an embedding. The
companion file test_the_server_can_own_the_embedding.py proves that
*declaring* it is safe on a deployment that cannot honour it -- Atlas Local
registers no models at all, so it falls back, loudly (see docs/BUG.md).

This file is the other half, skipped unless handed a cluster:

    VOYD_ATLAS_URI="mongodb+srv://..." uv run pytest tests/test_atlas_autoembed.py

It was written before one was available, which is the point: three things
could not be checked locally, and all three were settled on 18 September 2026
against Atlas (mongod 9.0.1, model ``voyage-4``). All five tests passed.

  1. The ``autoEmbed`` definition is complete. Local validation stopped at
     the model check, so a required field could have been hiding behind it.
     None is.
  2. Writes need nothing extra. Rows go in as text and come back with no
     ``embedding`` field -- the application genuinely never holds a vector.
  3. Retrieval works, and so do the guarantees that matter more than it: the
     tenant boundary holds on this index shape, and ``revoke()`` still
     refuses a document whose vector this process never computed.

Two shapes were confirmed earlier by the server itself, without a cluster,
and both proved correct: ``autoEmbed`` requires ``model`` and
``modality``, and ``$vectorSearch`` takes ``query`` for text, mutually
exclusive with ``queryVector`` ("Exactly one and only one of query and
queryVector can be present").

These stay as tests rather than becoming a changelog entry: they are the only
thing that will notice when a model is retired or the index shape changes.
"""

from __future__ import annotations

import asyncio
import os
import uuid

import pytest

ATLAS_URI = os.environ.get("VOYD_ATLAS_URI")
# Verified against Atlas (mongod 9.0.1) on 18 Sep 2026. The cluster reports:
#   voyage-4, voyage-4-large, voyage-4-lite, voyage-code-4, voyage-code-3
# The voyage-3 family is *not* offered for autoEmbed, which is worth knowing
# because it is what the documentation era suggests and it fails closed.
MODEL = os.environ.get("VOYD_ATLAS_EMBED_MODEL", "voyage-4")

pytestmark = pytest.mark.skipif(
    not ATLAS_URI,
    reason="set VOYD_ATLAS_URI to a cluster with an embedding model registered")

INDEXED_TEXT = "the fault code is P0301, a misfire on cylinder one"
OTHER_TEXT = "the user's name is Dana and she prefers concise answers"


@pytest.fixture
async def atlas():
    """An Engine on a throwaway database on a real cluster."""
    from pymongo import AsyncMongoClient

    from voyd.engine import Engine

    client = AsyncMongoClient(ATLAS_URI)
    name = f"voyd_autoembed_{uuid.uuid4().hex[:10]}"
    engine = Engine(client, client[name])
    await engine.connect()
    try:
        yield engine
    finally:
        await client.drop_database(name)
        await client.close()


@pytest.fixture
async def embedded(atlas):
    """A collection the *server* embeds, with two documents and no vectors."""
    engine = atlas
    engine.model("notes", tenant="tenant").searchable(
        text_paths=("text",), auto_embed=MODEL)
    await engine.ensure(search_wait_s=300)

    if not engine.search_engine.embeds_itself("notes"):
        pytest.fail(
            f"the cluster refused autoEmbed with model {MODEL!r}. Either the "
            f"model is not registered on this deployment (try "
            f"VOYD_ATLAS_EMBED_MODEL), or the index definition this engine "
            f"builds is incomplete -- which is the thing this file exists to "
            f"find out. Check the ERROR log for mongot's own words.")

    await engine.db.notes.insert_many([
        {"tenant": "t1", "text": INDEXED_TEXT},
        {"tenant": "t1", "text": OTHER_TEXT},
    ])
    return engine


async def test_the_application_never_computes_a_vector(embedded):
    """The claim that makes this worth adopting.

    Rows go in with text and nothing else. If an ``embedding`` field appears,
    something in this process is still embedding and the simplification is
    imaginary.
    """
    engine = embedded
    row = await engine.db.notes.find_one({"text": INDEXED_TEXT})
    assert "embedding" not in row, \
        "a vector was stored client-side; the server was supposed to own this"


async def test_a_text_query_finds_the_right_document(embedded):
    """The end-to-end question. No vector is supplied at any point."""
    engine = embedded

    deadline = asyncio.get_running_loop().time() + 300
    hits: list = []
    while asyncio.get_running_loop().time() < deadline:
        hits = await engine.search("notes", [], text="engine misfire",
                                   filters={"tenant": "t1"}, limit=2)
        if hits:
            break
        await asyncio.sleep(2)

    assert hits, (
        "no hits. Either mongot never embedded the rows, or the $vectorSearch "
        "stage shape is wrong. The stage sends `query` (text) with no "
        "`queryVector`, which the server confirmed is the correct "
        "alternative -- so suspect the write path or index definition first.")
    assert hits[0]["text"] == INDEXED_TEXT, (
        f"the semantically closer document did not rank first: {hits[0]['text']!r}. "
        f"Retrieval works but the model is not doing what we assumed.")


async def test_the_tenant_boundary_still_holds_when_the_server_embeds(embedded):
    """The filter is declared inside the autoEmbed index. If it were dropped
    in that shape, every tenant would leak -- the same breach the ordinary
    index is tested for, on a code path that builds a different index."""
    engine = embedded
    await engine.db.notes.insert_one(
        {"tenant": "t2", "text": "globex confidential merger terms"})

    deadline = asyncio.get_running_loop().time() + 120
    while asyncio.get_running_loop().time() < deadline:
        hits = await engine.search("notes", [], text="confidential merger",
                                   filters={"tenant": "t1"}, limit=10)
        if hits:
            break
        await asyncio.sleep(2)

    assert all(h["tenant"] == "t1" for h in hits), \
        f"cross-tenant leak on the autoEmbed index: {[h['tenant'] for h in hits]}"


async def test_health_reports_the_server_as_the_owner(embedded):
    engine = embedded
    owner = engine.health()["search"]["embedding_owner"]
    assert owner["server"] == ["notes"]
    assert owner["client"] == []


async def test_forgetting_still_works_when_the_server_owns_the_vector(embedded):
    """The thesis has to survive the new index shape.

    A revoked document must stop being reachable even though the vector now
    lives somewhere this process never touched. If refusal only worked on
    client-computed vectors it would be a coincidence, not a guarantee.
    """
    engine = embedded
    notes = engine.admission("notes")

    deadline = asyncio.get_running_loop().time() + 300
    while asyncio.get_running_loop().time() < deadline:
        if await engine.search("notes", [], text="engine misfire",
                               filters={"tenant": "t1"}):
            break
        await asyncio.sleep(2)

    await notes.revoke({"text": INDEXED_TEXT}, reason="atlas check")

    hits = await engine.search("notes", [], text="engine misfire",
                               filters={"tenant": "t1"}, limit=5)
    assert all(h["text"] != INDEXED_TEXT for h in notes.reachable(hits)), \
        "a revoked document came back from a server-embedded index"
    assert await engine.db.notes.count_documents({"text": INDEXED_TEXT}) == 1, \
        "forget must still not delete"
