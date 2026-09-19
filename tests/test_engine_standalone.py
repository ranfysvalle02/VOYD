"""Does the engine work without VOYD?

The honest way to answer is to use it for something that has nothing to
do with VOYD -- no voyds, no voids, no owners, no guards. If a
recipes app can get hybrid search, a job queue and change-stream handlers
out of it, the seam is real.

If these tests ever need to import something from ``voyd`` other than
``voyd.engine``, the boundary has leaked.
"""

from __future__ import annotations

import asyncio
import random

import pytest
from bson import ObjectId

from voyd.engine import JobQueue, PermanentFailure, SearchSpec
from voyd.engine.jobs import backoff

DIMS = 8


def vec(seed: int) -> list[float]:
    random.seed(seed)
    return [random.random() for _ in range(DIMS)]


async def search_when_indexed(app, collection, vector, *, timeout=25.0,
                              until=None, **kw):
    """mongot indexes asynchronously, so a fresh write is not instantly
    searchable. Poll rather than sleep a guessed interval.

    ``until`` is the condition the *caller* is waiting for. The default --
    "any hits at all" -- is wrong for a hybrid query: the vector leg is
    typically ready before the lexical one, so polling for non-empty results
    returns a vector-only ranking and the test reads a race as a wrong answer.
    """
    until = until or bool
    deadline = asyncio.get_running_loop().time() + timeout
    hits: list = []
    while asyncio.get_running_loop().time() < deadline:
        hits = await app.search(collection, vector, **kw)
        if until(hits):
            return hits
        await asyncio.sleep(0.5)
    pytest.fail(f"mongot did not index {collection} within {timeout}s "
                f"(last result: {[h.get('title') for h in hits]})")


# ``core`` -- a bare Engine on a vanilla client -- comes from ``conftest``. This
# whole file is the boundary check: nothing but ``voyd.engine``, and the live
# handle is the throwaway Engine any stranger gets, not the HTTP service's store.


@pytest.fixture
async def recipes(core):
    """``core`` plus built search indexes. Separate because building them
    costs seconds, and only the search tests need them."""
    app, db = core
    app.searchable(SearchSpec(
        collection="recipes",
        vector_path="vector",
        dimensions=DIMS,
        text_paths=("title", "body"),
        tenant_field="kitchen_id",
        vector_index="recipes_vec",
        text_index="recipes_text",
    ))
    await app.ensure(search_wait_s=60)
    return app, db


async def test_a_different_app_gets_hybrid_search_for_free(recipes):
    app, db = recipes
    kitchen = ObjectId()
    await db.recipes.insert_many([
        {"kitchen_id": kitchen, "title": "Carbonara",
         "body": "guanciale pecorino egg", "vector": vec(1)},
        {"kitchen_id": kitchen, "title": "Cacio e Pepe",
         "body": "pecorino black pepper E332 emulsifier", "vector": vec(2)},
    ])

    async def search(**kw):
        return await search_when_indexed(
            app, "recipes", vec(1), filters={"kitchen_id": kitchen}, **kw)

    assert app.search_tier == "hybrid"
    assert (await search())[0]["title"] == "Carbonara", "nearest vector"

    # Same query vector, but the exact additive code should win via the
    # lexical leg -- the whole reason hybrid exists, in an app that has never
    # heard of VOYD.
    # Wait for the *lexical* leg specifically: until the exact token ranks
    # first, all we know is that $vectorSearch is ready.
    fused = await search(text="E332",
                         until=lambda h: h and h[0]["title"] == "Cacio e Pepe")
    assert fused[0]["title"] == "Cacio e Pepe", [h["title"] for h in fused]


async def test_tenant_isolation_holds_for_any_app(recipes):
    """The tenant field is configuration, not a hardcoded ``voyd_id``."""
    app, db = recipes
    kitchen = ObjectId()
    await db.recipes.insert_one({"kitchen_id": kitchen, "title": "Secret Sauce",
                                 "body": "classified", "vector": vec(3)})

    mine = await search_when_indexed(app, "recipes", vec(3),
                                     filters={"kitchen_id": kitchen})
    theirs = await app.search("recipes", vec(3), filters={"kitchen_id": ObjectId()})
    assert [h["title"] for h in mine] == ["Secret Sauce"]
    assert theirs == []


async def test_the_job_queue_needs_no_app_vocabulary(core):
    """``indexed``/``embed_attempts`` were VOYD's field names. They are now
    parameters, so an app picks its own."""
    app, db = core
    await db.imports.insert_one({"state": False, "url": "http://example.com/a"})

    q = JobQueue(db=db, collection="imports", when={"state": False},
                 status_field="state", attempts_field="tries", max_attempts=3)

    job = await q.claim()
    assert job["url"].endswith("/a")
    assert await q.claim() is None, "claimed jobs are not handed out twice"

    await q.fail(job, RuntimeError("rate limited"))
    again = await q.claim()
    assert again["tries"] == 1, "retryable failure returns the job, counted"

    await q.complete(again, {"title": "fetched"})
    doc = await db.imports.find_one({"_id": job["_id"]})
    assert doc["state"] is True and doc["title"] == "fetched"


async def test_permanent_failure_skips_the_retries(core):
    """A handler can say 'this document is the problem' and stop the cycle."""
    app, db = core
    await db.imports.insert_one({"state": False, "url": "not-a-url"})
    q = JobQueue(db=db, collection="imports", when={"state": False},
                 status_field="state", attempts_field="tries")

    job = await q.claim()
    assert await q.fail(job, PermanentFailure("unparseable")) is True
    assert (await db.imports.find_one({"_id": job["_id"]}))["state"] == "error"
    assert await q.claim() is None


async def test_health_reports_the_tier_for_any_app(recipes):
    app, _ = recipes
    health = app.health()
    assert health["search"]["tier"] == "hybrid"
    assert health["search"]["indexes_ready"] is True
    assert health["change_streams"] is True
    assert health["time"] == {"tz": "UTC", "aware": True}
    assert "voyd" not in str(health).lower(), "no app vocabulary leaked into the engine"


def test_backoff_is_bounded_and_gentle_at_first():
    assert backoff(0, base=2.0) == 2.0
    assert backoff(2, base=2.0) == 2.0
    assert backoff(5, base=2.0) > 2.0
    assert backoff(99, base=2.0) == 60.0


def test_engine_is_the_public_import():
    import voyd
    from voyd import Engine, PermanentFailure
    from voyd.engine import Engine as Inner, PermanentFailure as InnerFail

    assert Engine is Inner
    assert PermanentFailure is InnerFail
    assert voyd.__all__[0] == "Engine"


def test_importing_engine_does_not_load_the_app_extra():
    """Engine is the core. FastAPI, R2 and Voyage are optional extras."""
    import os
    import subprocess
    import sys
    from pathlib import Path

    root = str(Path(__file__).resolve().parents[1])
    env = os.environ.copy()
    env["PYTHONPATH"] = root + os.pathsep + env.get("PYTHONPATH", "")
    code = (
        "import sys\n"
        "from voyd import Engine, PermanentFailure\n"
        "assert 'voyd.app' not in sys.modules\n"
        "assert 'fastapi' not in sys.modules\n"
        "assert Engine.__name__ == 'Engine'\n"
    )
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, env=env, cwd=root)
    assert r.returncode == 0, r.stderr


def test_the_test_harness_does_not_smuggle_in_the_app_extra():
    """The import graph is only half the boundary. If ``conftest`` imports the
    HTTP service at module load, an engine-only install cannot even collect the
    engine suite -- so the ``core`` fixture and the service must be lazy, not
    top-level."""
    from pathlib import Path

    src = (Path(__file__).resolve().parents[1] / "tests" / "conftest.py").read_text()
    top_level = [
        line for line in src.splitlines()
        if line[:1] not in (" ", "\t", "#", "")  # module-scope statements only
    ]
    joined = "\n".join(top_level)
    assert "fastapi" not in joined, (
        "conftest must not import the HTTP service at module scope")
    assert "voyd.web" not in joined
    assert "import Voyd" not in joined, (
        "the HTTP service is imported inside the fixture")


def test_engine_source_has_no_app_vocabulary_and_no_vendor():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / "voyd" / "engine"
    banned = ("voyd", "openai", "voyage", "cohere", "pinecone", "langchain")
    for path in root.glob("*.py"):
        text = path.read_text().lower()
        for word in banned:
            assert word not in text, f"{path.name} names {word!r}"


def test_examples_are_the_engine_not_the_service():
    """``agent.py`` and ``worker.py`` are what people copy. They must run on the
    bare install -- Engine and a driver -- never the HTTP service."""
    from pathlib import Path

    examples = Path(__file__).resolve().parents[1] / "examples"
    for name in ("agent.py", "worker.py"):
        src = (examples / name).read_text()
        assert "from voyd import Engine" in src, name
        assert "PermanentFailure" in src, name
        assert "Voyd(" not in src, f"{name} pulls the HTTP service"
        assert "Intelligence" not in src, f"{name} names a vendor"
        assert "import fastapi" not in src and "from fastapi" not in src, name
