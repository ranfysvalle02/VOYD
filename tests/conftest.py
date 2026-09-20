"""Shared fixtures.

Two audiences, two fixtures:

- ``core`` -- a bare ``Engine`` on a throwaway database, built from a *vanilla*
  ``AsyncMongoClient``. That is the caller an agent actually is: no
  FastAPI, no ``tz_aware`` handed in, no app extra. Engine tests take this, so the
  boundary is honest at the harness and not only in the import graph. Nothing in
  this fixture imports the HTTP service.
- ``app`` / ``client`` -- the VOYD HTTP service (FastAPI) on its own database.
  Only the service tests need these; those modules
  ``pytest.importorskip('fastapi')`` so a ``pip install voyd[dev]`` without the
  ``app`` extra still runs the engine suite. The service is imported lazily
  *inside* the fixture for the same reason.

The integration tests need a real MongoDB, because the properties worth proving
-- tenant isolation, ownership checks, forgetting on a deadline -- are properties
of the *queries*; a fake store would prove only that the fake is filtered. They
skip cleanly when no MongoDB is reachable. Point them elsewhere with
``VOYD_TEST_MONGO_URI``.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from contextlib import asynccontextmanager

import pytest

# docker-compose publishes Atlas Local on 27018. directConnection is required
# from the host: the deployment advertises its in-network hostname ("mongo"),
# which does not resolve out here, so a topology-discovering client times out.
TEST_MONGO_URI = os.environ.get(
    "VOYD_TEST_MONGO_URI", "mongodb://localhost:27018/?directConnection=true"
)

_available: bool | None = None

# Fixtures drop their own database, but an interrupted run (Ctrl-C, a timeout,
# a killed CI job) never reaches teardown. Those leftovers are not inert: each
# one keeps its Atlas Search indexes, and mongot goes on maintaining all of
# them. Enough of them and every later run slows to a crawl for no visible
# reason -- which is exactly the kind of "it got mysteriously slow" that costs
# an afternoon. So the session sweeps them first.
# Every database a test creates must start with one of these, or the sweep
# below will not find it and it will keep its mongot indexes forever.
#
# ``bench_`` is deliberately NOT here. It was, briefly, on the reasoning that
# bench/measure.py leaves 1024-dimension indexes behind and somebody should
# collect them. The result was that starting the suite dropped a *running*
# benchmark's database out from under it:
#
#   WriteError: Cannot create collection bench_d7e8144356.ttlbench
#   - database is in the process of being dropped.
#
# A sweep that destroys a concurrent tool's data is worse than an orphaned
# index. bench/measure.py collects its own leftovers instead, where the
# knowledge that no other benchmark is running actually lives.
_TEST_DB_PREFIXES = ("voyd_test_", "core_")

# Two footguns, both of which surface as a *different* test failing:
#
# 1. The sweep below drops every database matching the prefixes above, so two
#    concurrent pytest runs delete each other's data mid-test.
# 2. The reaper test in test_the_deadline_is_enforced_twice.py turns
#    ``ttlMonitorSleepSecs`` down and restores it, and so do
#    examples/forget.py and examples/why_this_belongs_in_the_database.py. It
#    is a server-global, so running a demo during the suite makes each restore
#    the other's temporary value.
#
# In both cases the symptom is an unrelated assertion about a row count. Run
# the suite alone.
#
# ``ttl_reaper_disarmed`` below is deliberately *not* a third entry on that
# list, and the reason is written up there: it needs the reaper to leave one
# database's rows alone, which is a per-database question, so it answers it
# per database instead of reaching for the server-global switch that would
# have fought footgun 2 directly. The nearest thing to a rule this file has
# learned is that a fixture protecting one test's data should not be writing
# state every other test can see.


async def _mongo_available(uri: str) -> bool:
    """Probed once per session -- otherwise every test pays the timeout to skip."""
    global _available
    if _available is not None:
        return _available

    from pymongo import AsyncMongoClient

    client = AsyncMongoClient(uri, serverSelectionTimeoutMS=1500)
    try:
        await client.admin.command("ping")
        _available = True
    except Exception:
        _available = False
    finally:
        await client.close()
    return _available


@pytest.fixture(scope="session", autouse=True)
def _sweep_leaked_test_databases():
    """Drop databases left behind by interrupted runs, before anything else.

    Deliberately a *sync* fixture driving its own loop: a session-scoped async
    fixture binds to whatever event loop the asyncio plugin gives session
    scope, and that contract has changed across pytest-asyncio releases. This
    is housekeeping, not a test -- it should not be the thing that decides
    which plugin version the suite collects under.
    """
    asyncio.run(_sweep())


async def _sweep():
    if not await _mongo_available(TEST_MONGO_URI):
        return

    from pymongo import AsyncMongoClient

    client = AsyncMongoClient(TEST_MONGO_URI)
    try:
        names = await client.list_database_names()
        stale = [n for n in names if n.startswith(_TEST_DB_PREFIXES)]
        for name in stale:
            await client.drop_database(name)
        if stale:
            print(f"\nswept {len(stale)} leaked test database(s) from a "
                  f"previous interrupted run")
    except Exception as exc:  # never fail the suite over housekeeping
        print(f"\ncould not sweep leaked test databases: {exc}")
    finally:
        await client.close()



@asynccontextmanager
async def ttl_reaper_disarmed(db):
    """Take the TTL indexes off *this* database, so an expired row stays put.

    Several tests assert the pair that is the product's entire thesis: a
    document is **past its deadline** and **still physically on disk**, and the
    read path refuses it anyway. Both halves have to be true at the same
    instant or the test proves nothing -- if the row is gone, the refusal might
    just be an empty collection, which is the ordinary behaviour of every
    database and not a claim worth shipping.

    MongoDB's TTL monitor is what breaks the pair. It sweeps every 60s, and a
    test that waits on anything slow -- mongot building an index, say -- can
    cross a sweep boundary and lose the row mid-test. That is not a flaky
    assertion; it is the fixture and the server racing over the same document,
    with the winner decided by how warm the machine is.

    **Why the index and not the monitor.** The obvious lever is
    ``setParameter: {ttlMonitorEnabled: false}``, and it works, and it is the
    wrong lever for three reasons -- all of which come from it being *global
    state on a shared server* while the thing it protects is one test's rows:

    1. It does not compose. Two concurrent pausers (pytest-xdist, or simply
       two developers pointed at the same mongod) and the first one to finish
       restores the monitor while the second is still running -- which does
       not fail, it just silently reinstates the race the pause existed to
       remove. A guard that quietly stops guarding is worse than no guard.
    2. It does not survive a crash. A ``kill -9`` between pause and restore
       leaves the monitor off on a shared deployment indefinitely, and nothing
       in a later run would notice or put it back.
    3. It needs admin. Managed Atlas refuses ``setParameter``, so the tests
       that most need this would have skipped there -- and a skip that is
       always a skip is a test nobody has ever run, which is the complaint
       this repository makes about everybody else's suite.

    Dropping the TTL indexes has none of those properties, because the scope
    is already right: ``app`` gives every test its own ``voyd_test_<uuid>``
    database, the reaper can only reach these rows *through indexes in that
    database*, and the database is dropped at teardown. No admin command, no
    shared state, nothing to restore, and two of these can run at once on one
    server without knowing about each other.

    Nothing here touches ``ttlMonitorSleepSecs``: speeding the reaper up would
    be the opposite mistake, a test passing because deletion happened to be
    quick. The monitor still runs, on its own clock, for every other database
    on the server. It simply has nothing to find in this one.
    """
    disarmed = []
    for name in await db.list_collection_names():
        async for index in await db[name].list_indexes():
            if "expireAfterSeconds" in index:
                await db[name].drop_index(index["name"])
                disarmed.append(f"{name}.{index['name']}")

    # A disarm that silently found nothing would turn every caller into the
    # race this exists to remove, and they would still look green most of the
    # time -- which is worse than the race, because nobody would go looking.
    # This is what fails if the schema stops declaring a deadline, or renames
    # the field one is on.
    assert disarmed, (
        f"{db.name} declares no TTL index, so this fixture protected nothing. "
        f"Either the schema changed and these tests are now racing the "
        f"reaper, or they no longer need to be here")

    # Deliberately not restored. The database is thrown away at teardown, so
    # putting the indexes back would be ceremony -- and ceremony in a teardown
    # is where "it only leaks when the test fails" comes from.
    yield disarmed


@pytest.fixture
async def reaper_disarmed(app):
    """``ttl_reaper_disarmed`` on the service's database, for autouse modules.

    Takes ``app`` so it is ordered after the schema exists -- there is nothing
    to take off a database whose indexes have not been created yet, and the
    assertion inside would be the thing that told you so.
    """
    async with ttl_reaper_disarmed(app.store.db) as disarmed:
        yield disarmed


@pytest.fixture
async def core():
    """A bare ``Engine`` on a throwaway db, from a vanilla client.

    A default ``AsyncMongoClient`` is *not* ``tz_aware`` -- which is precisely
    the caller an agent runtime is, and precisely the caller that made a
    forgotten memory crash recall. Building ``Engine`` from it here, rather than
    from the HTTP service's pre-configured store, is what keeps "``engine.db``
    pins its own UTC codecs" a tested property instead of a lucky inheritance.

    Yields ``(engine, engine.db)``. The db handle is the engine's UTC-aware one,
    so direct writes in a test round-trip the same way the engine's do.
    """
    if not await _mongo_available(TEST_MONGO_URI):
        pytest.skip(f"no MongoDB at {TEST_MONGO_URI}")

    from pymongo import AsyncMongoClient

    from voyd.engine import Engine

    client = AsyncMongoClient(TEST_MONGO_URI)
    name = f"core_{uuid.uuid4().hex[:12]}"
    engine = Engine(client, client[name])
    await engine.connect()
    try:
        yield engine, engine.db
    finally:
        await client.drop_database(name)
        await client.close()


@pytest.fixture
async def app():
    """The VOYD HTTP service on a throwaway database, dropped afterwards.

    This is the full service: FastAPI, the store, embeddings. Imported
    lazily so ``conftest`` itself does not pull the ``app`` extra -- an engine-only
    install can still collect and run the engine tests.

    The Ops background workers are left off: these tests exercise request
    handling, not the embed loop. The vault's passcode limiter is
    process-global, so it is cleared here (not autouse, so engine tests never
    import the service to do it) -- otherwise one test's wrong guesses would
    429 the next test's good ones.
    """
    if not await _mongo_available(TEST_MONGO_URI):
        pytest.skip(f"no MongoDB at {TEST_MONGO_URI}")

    from voyd import Intelligence, Store, Voyd
    from voyd.web.vault import _passcode_limiter

    _passcode_limiter.clear()
    db_name = f"voyd_test_{uuid.uuid4().hex[:12]}"
    voyd = Voyd(
        domain="voyd.test",
        store=Store.Mongo(TEST_MONGO_URI, db_name=db_name),
        intelligence=Intelligence.Voyage(api_key="vy-test"),
    )
    await voyd.store.connect()
    await voyd.store.ensure_schema(
        vector_dimensions=voyd.intelligence.config.dimensions)
    try:
        yield voyd
    finally:
        await voyd.store.client.drop_database(db_name)
        await voyd.store.close()
        _passcode_limiter.clear()


@pytest.fixture
async def client(app):
    """An HTTP client speaking to the service in-process.

    Requests carry ``X-Voyd`` to choose a namespace (see ``voyd.host``), which is
    the documented escape hatch for exactly this: no wildcard DNS needed.
    """
    import httpx

    transport = httpx.ASGITransport(app=app.api)
    async with httpx.AsyncClient(transport=transport,
                                 base_url="http://voyd.test") as c:
        yield c
