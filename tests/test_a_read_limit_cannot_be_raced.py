"""A read limit that can be exceeded under concurrency is not a limit.

``max_downloads`` is one of the three primitives the README sells -- "a
passcode and a read limit on the scope". It was enforced by reading
``download_count``, comparing it to the limit in Python, and then
incrementing: a TOCTOU. Two concurrent readers both see ``limit - 1``, both
pass the guard, and both increment.

Measured before the fix, against Atlas Local: a void with
``max_downloads: 3`` and twelve concurrent readers served **four**. Only four
rather than twelve because ``asyncio`` interleaves at the ``await``, which is
exactly what makes this the kind of bug that never shows up on a laptop and
shows up immediately behind two replicas.

The limit now lives in the *filter* of a ``find_one_and_update``, so the
increment only happens for a request that held a slot.
"""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("fastapi")

from tests.test_scope import owner_on

LIMIT = 3
CONCURRENT = 12
PASSCODE = "hunter2"


@pytest.fixture
async def limited(app):
    """A void with a read allowance, created through the store.

    The store, not the HTTP route, because the race is in the store's
    contract and this has to be able to hammer it concurrently without
    12 presign round trips.
    """
    owner_id = await app.store.create_owner("limit@example.com", "keyhash")
    voyd = await app.store.create_voyd("limited", owner_id, {}, name="limited")
    await app.store.create_void(voyd_id=voyd["_id"], token="tok123",
                               policy={"max_downloads": LIMIT}, expire_at=None)
    return app, voyd["_id"], "tok123"


async def _count(app, voyd_id, token) -> int:
    void = await app.store.get_void(voyd_id, token)
    return void.get("download_count", 0)


async def test_concurrent_readers_cannot_exceed_the_limit(limited):
    """The assertion the old code failed."""
    app, voyd_id, token = limited

    results = await asyncio.gather(*[
        app.store.claim_download(voyd_id, token, LIMIT)
        for _ in range(CONCURRENT)
    ])

    assert sum(results) == LIMIT, (
        f"{sum(results)} readers were served against a limit of {LIMIT}; "
        f"the claim is not atomic"
    )
    assert await _count(app, voyd_id, token) == LIMIT, (
        "the counter ran past the limit, so a later honest read would be "
        "refused for the wrong reason"
    )


async def test_the_allowance_is_spent_not_merely_rationed(limited):
    """Once exhausted, it stays exhausted -- including for a serial caller."""
    app, voyd_id, token = limited

    for i in range(LIMIT):
        assert await app.store.claim_download(voyd_id, token, LIMIT) is True, \
            f"read {i + 1} of {LIMIT} was refused while the allowance remained"
    assert await app.store.claim_download(voyd_id, token, LIMIT) is False


async def test_an_unlimited_void_is_still_counted(app):
    """No limit means no ceiling, but the count is still the audit trail."""
    owner_id = await app.store.create_owner("open@example.com", "keyhash")
    voyd = await app.store.create_voyd("openvoid", owner_id, {}, name="open")
    await app.store.create_void(voyd_id=voyd["_id"], token="tok", policy={},
                                expire_at=None)

    results = await asyncio.gather(*[
        app.store.claim_download(voyd["_id"], "tok", None) for _ in range(5)
    ])
    assert all(results)
    assert await _count(app, voyd["_id"], "tok") == 5


async def test_a_void_with_no_counter_field_is_not_immortal(limited):
    """A void created before ``download_count`` existed must not read as zero
    downloads forever -- ``$lt`` does not match a missing field, so the filter
    has to admit it explicitly and let ``$inc`` create it."""
    app, voyd_id, token = limited
    await app.store.db.voids.update_one(
        {"voyd_id": voyd_id, "token": token},
        {"$unset": {"download_count": ""}})

    assert await app.store.claim_download(voyd_id, token, 1) is True
    assert await _count(app, voyd_id, token) == 1
    assert await app.store.claim_download(voyd_id, token, 1) is False


async def test_a_wrong_passcode_does_not_spend_the_allowance(client, app):
    """Ordering, not just atomicity.

    If the slot were claimed before the credential was checked, anyone with
    the link could burn a legitimate reader's downloads without ever knowing
    the passcode. So the 401 has to come first and cost nothing.
    """
    headers = await owner_on(app, "ordering", "order@example.com")
    r = await client.post("/v1/voids",
                          json={"passcode": PASSCODE, "max_downloads": LIMIT},
                          headers=headers)
    assert r.status_code == 200, r.text
    token = r.json()["token"]
    voyd_id = (await app.store.get_voyd_by_slug("ordering"))["_id"]

    # A real file, or the route 404s before it ever reaches the gate and this
    # test passes without testing anything.
    await app.store.create_file(voyd_id, token, "doc1", name="f.bin",
                                key="ordering/tok/doc1", mime="application/octet-stream",
                                expire_at=None)

    bad = await client.get(f"/v1/voids/{token}/files/doc1",
                           headers={"X-Voyd": "ordering", "X-Passcode": "wrong"})
    assert bad.status_code == 401, \
        f"expected the credential check first, got {bad.status_code}: {bad.text}"
    assert await _count(app, voyd_id, token) == 0, \
        "a wrong passcode spent part of the allowance"

    # And the right passcode does consume exactly one.
    good = await client.get(f"/v1/voids/{token}/files/doc1",
                            headers={"X-Voyd": "ordering", "X-Passcode": PASSCODE})
    assert good.status_code == 200, good.text
    assert await _count(app, voyd_id, token) == 1
