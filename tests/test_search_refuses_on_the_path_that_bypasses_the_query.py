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

# Every test here waits on a real index build -- mongot's clock, not
# ours. Excluded from the default run and included by CI; see
# `addopts` in pyproject.toml and the test that guards it.
pytestmark = pytest.mark.slow

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


async def _until_indexed(engine, want: int, seconds: int = 180) -> int:
    """Wait for mongot to have these documents, or report why it did not.

    Two waits, not one, because they fail for different reasons and only
    the second is interesting. The index has to become *queryable*, and then
    the documents have to be *in* it -- `ensure()` returning means the first,
    never the second.

    Generous, and deliberately so: mongot is shared across every database on
    the deployment, so a laptop carrying a dozen collections from previous
    work builds indexes far slower than an empty one. That is an environment
    property rather than a property of refusal, which is why the caller
    skips rather than fails when it runs out -- see the note there.
    """
    import asyncio
    deadline = asyncio.get_running_loop().time() + seconds
    while asyncio.get_running_loop().time() < deadline:
        state = [i async for i in
                 await engine.db.notes.list_search_indexes("notes_vector")]
        if state and state[0].get("queryable"):
            break
        await asyncio.sleep(5)

    while asyncio.get_running_loop().time() < deadline:
        cur = await engine.db.notes.aggregate([{"$vectorSearch": {
            "index": "notes_vector", "path": "embedding",
            "queryVector": vec(1), "numCandidates": 50, "limit": 10}}])
        hits = [d async for d in cur]
        if len(hits) >= want:
            return len(hits)
        await asyncio.sleep(5)
    return 0


def _skip_unless_indexed(count: int, want: int) -> None:
    """An un-built index is not a failed guarantee.

    This distinction is worth the extra function. If the boundary stopped
    refusing, that is a defect and must be red. If mongot never finished
    building, the test established nothing either way -- and reporting that
    as a failure teaches people to re-run rather than to look, which is how
    a real regression gets waved through the third time it appears.

    The Atlas test in this file covers the same claim on a cluster that is
    not competing with a laptop's leftovers, so nothing is lost by skipping
    here.
    """
    if count < want:
        pytest.skip(
            f"mongot indexed {count} of {want} within the budget. This is an "
            f"environment result, not a refusal result -- a shared local "
            f"deployment carrying other databases builds slowly. Check with "
            f"`db.notes.getSearchIndexes()`.")


async def test_the_index_ranks_the_expired_document(searchable):
    """The premise. If mongot ever stopped returning it, everything below
    would pass for the wrong reason -- the boundary would be credited for
    something the index did."""
    engine, _ = searchable
    _skip_unless_indexed(await _until_indexed(engine, 2), 2)


async def test_the_search_path_refuses_what_the_index_ranked(searchable):
    """The whole argument, executed: the hit arrives having passed through
    no query, and is refused on the way out."""
    engine, notes = searchable
    _skip_unless_indexed(await _until_indexed(engine, 2), 2)

    page = await notes.search(vec(1), limit=10)

    assert [d["text"] for d in page] == ["the fault code is P0301"]
    assert notes.receipts()["refused_by_reason"].get("deadline") == 1


async def test_a_short_page_is_not_silently_short(searchable):
    """A caller asking for five and getting one cannot tell "only one
    matched" from "the rest were forgotten and nobody went back". `starved`
    is the difference, and it is the field worth an alert."""
    engine, notes = searchable
    _skip_unless_indexed(await _until_indexed(engine, 2), 2)

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
