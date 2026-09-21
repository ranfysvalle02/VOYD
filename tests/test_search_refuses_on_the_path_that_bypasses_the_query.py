"""The read path the whole argument is about, through the connection string.

A `find` goes through a collection query, so the database can drop forgotten
rows server-side. A `$vectorSearch` hit does not: it arrives from an index
that ranked it, having passed through nothing. That asymmetry is the reason
this project exists, so it is the one that most needs a test against a real
`mongot` rather than a mock -- a fake index would only prove the fake was
filtered.

**And it is driven through the proxy**, because the claim is that a
ranked hit is refused before it reaches an application that never heard of
this package. The index is still built with `SearchEngine.ensure_indexes`,
the same call `voyd-wire --ensure` makes: provisioning is an operator step,
not an application one.

Also here because it is the other feature kept through the trim:
**server-side embedding**. When the index owns the vector, a client-side
embedder cannot drift from it -- and asking such an index for a vector it
never computed has to be an error rather than a plausible ranking. On the
wire that error is the boundary's, issued before the query reaches mongot.
"""

from __future__ import annotations

import random
import socket
import subprocess
import sys
import time
import uuid
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path

import pytest

from voyd.engine.time import now

from .conftest import MONGO_URI, free_port, mongo_host

pymongo = pytest.importorskip("pymongo")
ROOT = Path(__file__).resolve().parents[1]

# Every test here waits on a real index build -- mongot's clock, not
# ours. Excluded from the default run and included by CI; see
# `addopts` in pyproject.toml and the test that guards it.
pytestmark = pytest.mark.slow

DIMS = 8
PAST = now() - timedelta(days=1)

POLICY = """
from voyd import guard, deadline, revocable

@guard("notes")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
"""

AUTO_POLICY = """
from voyd import guard, deadline, revocable, auto_embed

@guard("notes")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    text = auto_embed("voyage-4")
"""


def vec(seed: int) -> list[float]:
    rng = random.Random(seed)
    return [rng.random() for _ in range(DIMS)]


@contextmanager
def _wire(tmp_path, policy: str, target: str, *extra):
    """A `voyd-wire` on a free port, from a policy file. Yields the port."""
    path = tmp_path / "voydfile.py"
    path.write_text(policy)
    port = free_port()
    proc = subprocess.Popen(
        [sys.executable, "tools/voyd_wire.py", "--config", str(path),
         "--listen", str(port), "--target", target, *extra],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        until = time.monotonic() + 180
        while time.monotonic() < until:
            if proc.poll() is not None:
                pytest.fail(f"voyd-wire exited early:\n{proc.stdout.read()}")
            try:
                with socket.create_connection(("127.0.0.1", port), 0.2):
                    break
            except OSError:
                time.sleep(0.2)
        else:
            pytest.fail("voyd-wire never started listening")
        yield port
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


async def _provision(db, **kw):
    """Build the vector index, the way an operator does.

    `SearchEngine.ensure_indexes` is what `voyd-wire --ensure` calls. It is
    used directly here rather than through the flag because the local
    deployment needs an ordinary client-vector index, and the policy file's
    vocabulary only declares the server-embedded kind -- which Atlas Local
    declines. The Atlas test below goes through the flag.
    """
    from voyd.engine.capabilities import detect
    from voyd.engine.search import SearchEngine, SearchSpec

    caps = await detect(db.client, db)
    if not caps.search:
        pytest.skip("no Atlas Search on this deployment")
    engine = SearchEngine(db=db, capabilities=caps)
    engine.register(SearchSpec("notes", vector_index="notes_vector", **kw))
    await engine.ensure_indexes(wait_s=180)
    engine.ready = True
    return engine


@pytest.fixture
async def indexed():
    """A real vector index on a real mongot, with one expired document.

    Yields the database, because the control assertions have to be able to
    ask what mongot is actually ranking. If the *direct* connection ever
    stops returning the expired row, everything below passes for the wrong
    reason and the boundary is being credited for something the index did.
    """
    from pymongo import AsyncMongoClient

    client = AsyncMongoClient(MONGO_URI)
    name = f"voyd_test_search_{uuid.uuid4().hex[:8]}"
    db = client[name]
    try:
        await db.notes.insert_many([
            {"text": "the fault code is P0301", "embedding": vec(1)},
            {"text": "last year's pricing", "embedding": vec(2),
             "expire_at": PAST},
        ])
        await _provision(db, vector_path="embedding", text_paths=("text",),
                         dimensions=DIMS)
        yield db
    finally:
        await client.drop_database(name)
        await client.close()


def _ranked(collection, want: int, seconds: int = 180) -> list:
    """Wait for mongot to be ranking these documents, then return the hits.

    Poll for the state the test *asserts*, not a weaker one. An earlier
    version of this file broke out of its wait as soon as the live row was
    indexed and then asserted that a refusal had happened -- with the
    expired row still on mongot's queue, ranked by nothing and refused by
    nothing. It read as a regression in refusal and was a race in the wait.
    """
    deadline = time.monotonic() + seconds
    hits: list = []
    while time.monotonic() < deadline:
        hits = list(collection.aggregate([{"$vectorSearch": {
            "index": "notes_vector", "path": "embedding",
            "queryVector": vec(1), "numCandidates": 50, "limit": 10}}]))
        if len(hits) >= want:
            return hits
        time.sleep(5)
    return hits


def _skip_unless_indexed(hits: list, want: int) -> None:
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
    if len(hits) < want:
        pytest.skip(
            f"mongot ranked {len(hits)} of {want} within the budget. This is "
            f"an environment result, not a refusal result -- a shared local "
            f"deployment carrying other databases builds slowly. Check with "
            f"`db.notes.getSearchIndexes()`.")


def test_the_index_ranks_the_expired_document(indexed, tmp_path):
    """The premise, asserted on the *direct* connection. If mongot ever
    stopped returning the expired row, everything below would pass for the
    wrong reason -- the boundary would be credited for something the index
    did."""
    direct = pymongo.MongoClient(MONGO_URI)[indexed.name]
    try:
        hits = _ranked(direct.notes, 2)
        _skip_unless_indexed(hits, 2)
        assert "last year's pricing" in {d["text"] for d in hits}, (
            "the index is not ranking the expired row, so there is nothing "
            "here for the boundary to refuse")
    finally:
        direct.client.close()


def test_the_search_path_refuses_what_the_index_ranked(indexed, tmp_path):
    """The whole argument, executed through a plain driver: the hit arrives
    from an index having passed through no query, and is refused on the way
    out of the proxy."""
    direct = pymongo.MongoClient(MONGO_URI)[indexed.name]
    try:
        _skip_unless_indexed(_ranked(direct.notes, 2), 2)
    finally:
        direct.client.close()

    with _wire(tmp_path, POLICY, mongo_host()) as port:
        client = pymongo.MongoClient(
            f"mongodb://localhost:{port}/?directConnection=true",
            serverSelectionTimeoutMS=8000)
        try:
            hits = list(client[indexed.name].notes.aggregate([
                {"$vectorSearch": {
                    "index": "notes_vector", "path": "embedding",
                    "queryVector": vec(1), "numCandidates": 50,
                    "limit": 10}}]))
        finally:
            client.close()

    assert [d["text"] for d in hits] == ["the fault code is P0301"], (
        "the expired row was ranked by mongot and reached the application")


def test_a_client_vector_on_a_server_embedded_index_is_refused(tmp_path, db):
    """The other direction, and it needs no index at all.

    Handing a server-embedded index a vector it never computed is an error,
    not a plausible ranking -- results that look ordinary and mean nothing
    are the failure this project is named for. The boundary answers it
    itself, before the query reaches mongot, which is why this does not
    have to wait two minutes for a build.
    """
    with _wire(tmp_path, AUTO_POLICY, mongo_host()) as port:
        client = pymongo.MongoClient(
            f"mongodb://localhost:{port}/?directConnection=true",
            serverSelectionTimeoutMS=8000)
        try:
            with pytest.raises(pymongo.errors.PyMongoError) as caught:
                list(client[db.name].notes.aggregate([
                    {"$vectorSearch": {
                        "index": "notes_vector", "path": "embedding",
                        "queryVector": vec(1), "numCandidates": 50,
                        "limit": 10}}]))
        finally:
            client.close()
    assert "voyd" in str(caught.value).lower() or "embed" in str(caught.value).lower()


def _creds(uri: str) -> str:
    """The `user:pass@` prefix from a connection string, or empty."""
    from urllib.parse import urlsplit

    parsed = urlsplit(uri)
    if not parsed.username:
        return ""
    return f"{parsed.username}:{parsed.password}@"


def test_the_server_embeds_and_refusal_still_holds(atlas, tmp_path):
    """Server-side embedding, against a live Atlas cluster, through the proxy.

    This one cannot be faked and cannot run locally: Atlas Local registers no
    models, so it *declines* an `auto_embed` declaration and falls back to a
    client-supplied vector. A test that accepted the fallback would be
    asserting the opposite of what it claims.

    What it proves is the strongest version of the thesis. The application
    never computes a vector -- there is no `embedding` field on any document
    -- so the index owns the encoding entirely, `$vectorSearch` ranks by it,
    and the expired hit is still refused on the way out. The one path where
    nothing the application holds could have filtered it, reached by a
    driver that imported nothing.
    """
    from voyd.engine.search import SearchSpec

    # The index name comes from the spec `voyd-wire --ensure` builds, not
    # from a literal. `tools/voyd_ensure.py` does not override
    # `vector_index`, so it is the `SearchSpec` default -- and a literal
    # here was wrong on the first run, which reads as "mongot indexed
    # nothing" rather than as "you asked for an index that does not exist".
    index = SearchSpec("notes").vector_index

    uri, name = atlas
    direct = pymongo.MongoClient(uri)
    try:
        # The refusable row is **revoked, not expired**, and that is not a
        # style choice. `--ensure` builds the TTL index behind `deadline()`,
        # this test waits minutes for a server-side index build, and
        # MongoDB's TTL monitor runs about once a minute -- so a row
        # inserted already a day past its deadline is reaped long before
        # mongot is asked about it. The first run of this version polled
        # for five minutes and found one hit, which reads as "the index is
        # slow" and was the reaper doing exactly what this project says it
        # does. A revocation with no deadline is pinned, refused by the
        # boundary, and cannot race a sweeper.
        direct[name].notes.insert_many([
            {"text": "the fault code is P0301 on cylinder one"},
            {"text": "last year's pricing for the enterprise tier",
             "forgotten": {"at": PAST, "reason": "retracted"}},
        ])
        with _wire(tmp_path, AUTO_POLICY, uri,
                   "--ensure", name, "--ensure-wait", "180") as port:
            # The credentials go to the *proxy*, which forwards the SCRAM
            # exchange upstream. Atlas requires authentication and the
            # boundary has none of its own to lend -- it deliberately does
            # not authenticate on a caller's behalf, because an identity
            # the caller did not prove is one the boundary invented. So a
            # client with no credentials gets `Unauthorized` from Atlas,
            # through the proxy, which is the correct answer and was the
            # second thing this rewrite found.
            client = pymongo.MongoClient(
                f"mongodb://{_creds(uri)}localhost:{port}/"
                f"?directConnection=true&authSource=admin",
                serverSelectionTimeoutMS=60000, connectTimeoutMS=60000,
                socketTimeoutMS=120000)
            try:
                notes = client[name].notes
                # Poll for the state this test asserts: both rows ranked by
                # mongot on the *direct* connection, so there is genuinely
                # something to refuse, and only then ask the boundary.
                deadline = time.monotonic() + 300
                ranked: list = []
                while time.monotonic() < deadline:
                    ranked = list(direct[name].notes.aggregate([
                        {"$vectorSearch": {
                            "index": index, "path": "text",
                            "query": "engine fault code",
                            "numCandidates": 50, "limit": 10}}]))
                    if len(ranked) >= 2:
                        break
                    time.sleep(5)

                assert len(ranked) >= 2, (
                    "the live row was indexed and the revoked one was not, "
                    "so nothing was ever offered to be refused. An "
                    "environment result -- but reported as a failure, "
                    "because a pass here would be this file asserting "
                    "refusal on a corpus with nothing to refuse")

                hits = list(notes.aggregate([
                    {"$vectorSearch": {
                        "index": index, "path": "text",
                        "query": "engine fault code",
                        "numCandidates": 50, "limit": 10}}]))
                assert [d["text"] for d in hits] == [
                    "the fault code is P0301 on cylinder one"]

                stored = list(direct[name].notes.find({}))
                assert not any("embedding" in d for d in stored), (
                    "the index owns the vector; a client-side one would be "
                    "a second encoding to keep in step, which is the drift "
                    "this removes")

                with pytest.raises(pymongo.errors.PyMongoError):
                    list(notes.aggregate([{"$vectorSearch": {
                        "index": index, "path": "text",
                        "queryVector": [0.0] * 1024,
                        "numCandidates": 50, "limit": 5}}]))
            finally:
                client.close()
    finally:
        direct.close()
