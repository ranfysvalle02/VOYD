"""A void that is over must read as gone, before the reaper agrees.

MongoDB's TTL monitor runs about once a minute. For that window a void and its
documents are still on disk, and every path that can reach them has to say no
anyway -- otherwise VOYD ships the exact failure it exists to remove: a
document past its deadline, still answering queries, with nothing anywhere
wrong enough to page you.

These tests never wait for the reaper and never touch ``ttlMonitorSleepSecs``.
They open a void with a *negative* TTL, which is expired the moment it exists,
then assert the row is still physically present and the API refuses it anyway.
That separation is the whole point: if a test passed only because the reaper
happened to run, it would prove nothing about the query.

They also **stop** the reaper, which they did not used to, and the reason is
worth keeping. The claim being made is a pair -- *past its deadline* and
*still on disk* -- and both halves have to hold at the same instant. Not
waiting for the reaper is not the same as the reaper not running: the monitor
sweeps on its own 60s clock, and ``indexed_namespace`` below waits up to 60s
for mongot to build an index. On a cold index those two windows overlap, the
sweep takes the expired row out from under the fixture, and the final
assertion -- that it really was still there to be found -- fails. Nothing
about VOYD was wrong on those runs; the test was racing the server for the
document it was about to make a claim about, and the winner was decided by how
warm the machine happened to be.

So ``reaper_paused`` below removes MongoDB's cleanup from the experiment. That
makes the claim stronger rather than weaker: with nothing deleting anything,
a document that does not come back came back from nowhere except the filter.
"""

from __future__ import annotations

import asyncio

import pytest

# This module drives the HTTP service (FastAPI). An engine-only install skips it whole.
pytest.importorskip("fastapi")

from voyd.auth import new_api_key
from voyd.web.deps import hash_api_key

EXPIRED = {"ttl_seconds": -1}      # over before the response is written
LIVE = {"ttl_seconds": 3600}
PERMANENT: dict = {}               # no deadline at all


async def _fixed_vector(dims: int) -> list[float]:
    """Stands in for the embedding provider: every document below is
    written with this same vector, so every one of them is a hit."""
    return [1.0] * dims


async def owner_on(app, slug: str, email: str) -> dict:
    key = new_api_key()
    owner_id = await app.store.create_owner(email, hash_api_key(key))
    await app.store.create_voyd(slug, owner_id, {}, name=slug)
    return {"X-Voyd": slug, "Authorization": f"Bearer {key}"}


@pytest.fixture(autouse=True)
async def _the_row_must_stay_on_disk(reaper_paused):
    """Every test in this module needs an expired row to stay on disk.

    Autouse rather than named per test, because the requirement is a property
    of the whole file: each test here opens something already past its
    deadline and then asserts the row survived long enough to be refused. One
    that forgot to ask for this would not fail -- it would pass until the
    machine got slow, which is the failure mode this module is about.

    The body is ``reaper_paused`` in conftest.py; this exists only to make it
    unconditional here.
    """
    yield


@pytest.fixture
async def dead_void(client, app):
    """An expired void whose row is confirmed to still be on disk.

    The confirmation is load-bearing. Without it a passing test below could
    just mean the reaper was quick, which is the opposite of the claim.
    """
    headers = await owner_on(app, "acme", "expired@example.com")
    r = await client.post("/v1/voids", json=EXPIRED, headers=headers)
    assert r.status_code == 200, r.text
    token = r.json()["token"]

    on_disk = await app.store.db.voids.count_documents({"token": token})
    assert on_disk == 1, "the reaper got there first; this test proves nothing"
    return {"headers": headers, "token": token}


# ---- the void surface --------------------------------------------------

async def test_an_expired_void_cannot_be_described(client, dead_void):
    """``GET /v1/voids/{token}`` is the read that every other one funnels
    through, so it is the one that must 404 first."""
    r = await client.get(f"/v1/voids/{dead_void['token']}",
                         headers=dead_void["headers"])
    assert r.status_code == 404, r.text


async def test_an_expired_void_cannot_be_searched(client, dead_void):
    """The headline failure. A scope past its deadline answering a query is
    the bug class this product is named after."""
    r = await client.post(f"/v1/voids/{dead_void['token']}/search",
                          json={"query": "anything"},
                          headers=dead_void["headers"])
    assert r.status_code == 404, r.text


async def test_an_expired_void_cannot_be_added_to(client, dead_void):
    """Ingest into a dead scope would create rows that are already garbage --
    and briefly searchable ones, since they inherit the past deadline."""
    r = await client.post(f"/v1/voids/{dead_void['token']}/documents",
                          json={"text": "too late"},
                          headers=dead_void["headers"])
    assert r.status_code == 404, r.text


async def test_an_expired_void_is_not_listed(client, app, dead_void):
    """``GET /v1/voids`` claims to list living voids. Expired ones are gone,
    not hidden -- including while their rows are still on disk."""
    live = await client.post("/v1/voids", json=LIVE,
                             headers=dead_void["headers"])
    live_token = live.json()["token"]

    r = await client.get("/v1/voids", headers=dead_void["headers"])
    assert r.status_code == 200, r.text
    listed = {v["token"] for v in r.json()["voids"]}
    assert live_token in listed
    assert dead_void["token"] not in listed

    # Still on disk, still not listed. That is the claim.
    assert await app.store.db.voids.count_documents(
        {"token": dead_void["token"]}) == 1


async def test_a_void_with_no_deadline_is_not_mistaken_for_expired(client, app):
    """The deadline filter treats null/absent ``expire_at`` as permanent. Get
    that backwards and every permanent void disappears instead -- the same bug
    pointed the other way, and the property that makes pinning work."""
    headers = await owner_on(app, "forever", "forever@example.com")
    r = await client.post("/v1/voids", json=PERMANENT, headers=headers)
    token = r.json()["token"]
    assert r.json()["expires"] == "never"

    assert (await client.get(f"/v1/voids/{token}",
                             headers=headers)).status_code == 200
    listed = {v["token"] for v in
              (await client.get("/v1/voids", headers=headers)).json()["voids"]}
    assert token in listed


# ---- the namespace-wide path -------------------------------------------

@pytest.fixture
async def indexed_namespace(client, app, dead_void):
    """One expired void and one live one, both with a searchable document.

    The wait for mongot lives *here*, in a precondition, rather than inside the
    test. A `skip` in the middle of a test body abandons that test's own claim
    and still reports green -- so on a busy machine the assertion below would
    quietly stop being checked. As a fixture, a skip means "the environment
    never got ready", which is a different and honest statement.
    """
    headers = dead_void["headers"]
    # The query has to be embedded to be searched, and these tests carry no
    # real Voyage key. The vector is irrelevant here: the claim is about which
    # rows the filter admits, not about ranking.
    dims = app.intelligence.config.dimensions
    app.intelligence.embed_query = lambda text: _fixed_vector(dims)

    live = await client.post("/v1/voids", json=LIVE, headers=headers)
    live_token = live.json()["token"]

    voyd = await app.store.get_voyd_by_slug("acme")
    for token, name in ((dead_void["token"], "expired.md"),
                        (live_token, "current.md")):
        void = await app.store.db.voids.find_one({"token": token})
        await app.store.db.documents.insert_one({
            "voyd_id": voyd["_id"], "token": token, "doc_id": f"d-{name}",
            "name": name, "text": "the launch date is March 3",
            "embedding": [1.0] * dims, "indexed": True,
            "expire_at": void["expire_at"],
        })

    async def search() -> set[str]:
        r = await client.post("/v1/search", json={"query": "launch date"},
                              headers=headers)
        assert r.status_code == 200, r.text
        return {m["name"] for m in r.json()["matches"]}

    # Wait for the *live* document, so "the expired one is absent" can never
    # pass merely because the index was cold.
    for _ in range(60):
        names = await search()
        if "current.md" in names:
            return names
        await asyncio.sleep(1)
    pytest.skip("mongot did not index the live document in 60s; "
                "there is nothing to prove the filter against")


async def test_namespace_search_does_not_reach_into_an_expired_void(
        app, dead_void, indexed_namespace):
    """``POST /v1/search`` spans every void the owner has, so it reaches
    documents directly rather than resolving one void first. It needs its own
    deadline check, and this is the test that says so.
    """
    names = indexed_namespace
    assert "current.md" in names
    assert "expired.md" not in names, (
        "a document past its deadline was returned by namespace-wide search")
    # And it really was still there to be found.
    assert await app.store.db.documents.count_documents(
        {"name": "expired.md"}) == 1
