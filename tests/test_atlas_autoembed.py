"""The half that cannot be checked without a real cluster.

Everything else about ``auto_embed`` is asserted in
``test_the_server_can_own_the_embedding.py``, against Atlas Local, which
refuses the feature. That file proves *declaring* it is safe. It cannot prove
the feature works, because nothing local can: mongot on the ``localDev``
edition registers no models at all (see BUG.md).

This file is the other half, and it is skipped unless you hand it a cluster:

    VOYD_ATLAS_URI="mongodb+srv://..." uv run pytest tests/test_atlas_autoembed.py -v

Point it at a deployment with an embedding model registered and it answers
the question the local suite cannot: does the server actually embed, and does
a text query actually come back with the right document?

**Read the failures carefully.** Several assertions below encode beliefs that
were derived from error messages rather than from a working system, and the
useful outcome of a failure here is usually "the design was wrong", not "the
cluster is broken". Each one says which is which.

What was already confirmed by the server, without a cluster, and so is *not*
in doubt:

- ``autoEmbed`` requires ``model`` and ``modality`` -- mongot demanded each
  by name during validation.
- ``$vectorSearch`` takes ``query`` for text, and it is mutually exclusive
  with ``queryVector``: "Exactly one and only one of query and queryVector
  can be present". The engine sends exactly one.

What remains genuinely unknown, and is what this file exists to settle:

- whether the ``autoEmbed`` field definition is *complete*, or whether more
  required fields sit behind the model check that local validation never
  reached,
- whether writes need anything the application is not doing,
- whether retrieval actually returns the document.
"""

from __future__ import annotations

import asyncio
import os
import uuid

import pytest

ATLAS_URI = os.environ.get("VOYD_ATLAS_URI")
MODEL = os.environ.get("VOYD_ATLAS_EMBED_MODEL", "voyage-3-large")

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
    notes = engine.forgetting("notes")

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
