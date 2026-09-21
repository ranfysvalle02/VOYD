"""`search.py` -- 586 lines, and the read path the whole argument is about.

A `find` goes through a collection query, so the database can drop forgotten
rows server-side. A `$vectorSearch` hit does not: it arrives from an index
that ranked it, having passed through nothing. That asymmetry is the reason
this project exists, so it is the one that most needs a test against a real
`mongot` rather than a mock -- a fake index would only prove the fake was
filtered.

Also here because it is the other feature kept through the trim:
**server-side embedding**. When the index owns the vector, a client-side
embedder cannot drift from it -- and asking such an index for a vector it
never computed has to be an error rather than a plausible ranking.
"""

from __future__ import annotations

import asyncio
import random
import uuid
from datetime import timedelta

import pytest

from voyd.engine.time import now

from .conftest import MONGO_URI

pymongo = pytest.importorskip("pymongo")
DIMS = 8
PAST = now() - timedelta(days=1)


def vec(seed: int) -> list[float]:
    rng = random.Random(seed)
    return [rng.random() for _ in range(DIMS)]


@pytest.fixture
async def searchable():
    """A real vector index on a real mongot, with one expired document."""
    from pymongo import AsyncMongoClient

    from voyd import Engine

    client = AsyncMongoClient(MONGO_URI)
    name = f"voyd_test_search_{uuid.uuid4().hex[:8]}"
    engine = Engine(client, client[name])
    await engine.connect()
    try:
        model = engine.model("notes")
        model.searchable(vector_path="embedding", text_paths=("text",),
                         dimensions=DIMS)
        notes = model.forgettable()
        await engine.ensure()
        await engine.db.notes.insert_many([
            {"text": "the fault code is P0301", "embedding": vec(1)},
            {"text": "last year's pricing", "embedding": vec(2),
             "expire_at": PAST},
        ])
        yield engine, notes
    finally:
        await client.drop_database(name)
        await client.close()


async def _until_indexed(engine, want: int, tries: int = 24) -> int:
    """mongot indexes asynchronously; poll rather than sleep a constant."""
    import asyncio
    for _ in range(tries):
        cur = await engine.db.notes.aggregate([{"$vectorSearch": {
            "index": "notes_vector", "path": "embedding",
            "queryVector": vec(1), "numCandidates": 50, "limit": 10}}])
        hits = [d async for d in cur]
        if len(hits) >= want:
            return len(hits)
        await asyncio.sleep(5)
    return 0


async def test_the_index_ranks_the_expired_document(searchable):
    """The premise. If mongot ever stopped returning it, everything below
    would pass for the wrong reason -- the boundary would be credited for
    something the index did."""
    engine, _ = searchable
    assert await _until_indexed(engine, 2) == 2, (
        "the index never became queryable; the rest of this file is vacuous")


async def test_the_search_path_refuses_what_the_index_ranked(searchable):
    """The whole argument, executed: the hit arrives having passed through
    no query, and is refused on the way out."""
    engine, notes = searchable
    assert await _until_indexed(engine, 2) == 2

    page = await notes.search(vec(1), limit=10)

    assert [d["text"] for d in page] == ["the fault code is P0301"]
    assert notes.receipts()["refused_by_reason"].get("deadline") == 1


async def test_a_short_page_is_not_silently_short(searchable):
    """A caller asking for five and getting one cannot tell "only one
    matched" from "the rest were forgotten and nobody went back". `starved`
    is the difference, and it is the field worth an alert."""
    engine, notes = searchable
    assert await _until_indexed(engine, 2) == 2

    page = await notes.search(vec(1), limit=10)
    assert page.starved is False, (
        "candidates were exhausted, so the short page is complete")


async def test_the_server_embeds_and_refusal_still_holds(atlas):
    """Server-side embedding, against a live Atlas cluster.

    This one cannot be faked and cannot run locally: Atlas Local registers no
    models, so it *declines* an `auto_embed` declaration and falls back to a
    client-supplied vector. A test that accepted the fallback would be
    asserting the opposite of what it claims.

    What it proves is the strongest version of the thesis. The application
    never computes a vector -- there is no `embedding` field on any document
    -- so the index owns the encoding entirely, `$vectorSearch` ranks by it,
    and the expired hit is still refused on the way out. The one path where
    nothing the application holds could have filtered it.
    """
    from pymongo import AsyncMongoClient

    from voyd import Engine

    uri, name = atlas
    client = AsyncMongoClient(uri)
    engine = Engine(client, client[name])
    await engine.connect()
    try:
        model = engine.model("notes")
        # `voyage-3` is what this project's `.env` still names and Atlas has
        # since dropped it; the supported set is reported by the server in
        # the error, which is how this was found.
        model.searchable(text_paths=("text",), auto_embed="voyage-4",
                         dimensions=1024)
        notes = model.forgettable()
        await engine.ensure(search_wait_s=120)

        assert engine.search_engine.embeds_itself("notes") is True, (
            "the deployment declined auto_embed; this test would otherwise "
            "pass against a client-supplied vector and prove nothing")

        await engine.db.notes.insert_many([
            {"text": "the fault code is P0301 on cylinder one"},
            {"text": "last year's pricing for the enterprise tier",
             "expire_at": PAST},
        ])

        # mongot indexes asynchronously, and `ensure` returning means the
        # *index* is queryable, not that these two documents are in it. Poll
        # rather than sleep a constant -- and poll generously, because this
        # is a shared cluster and the budget was tight enough to flake once
        # when another index was building beside it.
        page = []
        for _ in range(60):
            page = await notes.search(None, text="engine fault code", limit=10)
            if page:
                break
            await asyncio.sleep(5)

        assert page, (
            "nothing was indexed within five minutes. That is an environment "
            "problem rather than a refusal problem, but it is reported as a "
            "failure because a silent skip here would hide a real regression "
            "in exactly the path this file exists to check")
        assert [d["text"] for d in page] == [
            "the fault code is P0301 on cylinder one"]
        assert notes.receipts()["refused_by_reason"].get("deadline") == 1

        stored = [d async for d in engine.db.notes.find({})]
        assert not any("embedding" in d for d in stored), (
            "the index owns the vector; a client-side one would be a second "
            "encoding to keep in step, which is the drift this removes")

        # And the other direction, asserted here rather than in its own test
        # because it needs this same index to be live and that costs two
        # minutes to build. Handing a server-embedded index a vector it never
        # computed is an error, not a plausible ranking -- results that look
        # ordinary and mean nothing are the failure this project is named for.
        with pytest.raises(ValueError, match="embedded by the server"):
            await notes.search(vec(1), limit=5)
    finally:
        await client.drop_database(name)
        await client.close()
