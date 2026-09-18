"""The request layer's bounds, including the ones that were not there.

`vault.py` opens by claiming that request bodies are Pydantic models "so a
malformed call is refused before any row is written rather than half-way
through the batch". That was true of the fields somebody thought to bound. A
second adversarial pass found two that nobody had:

- ``ttl_seconds`` was unbounded above. A deadline becomes a ``datetime``, so
  ``now() + timedelta(seconds=10**15)`` raised ``OverflowError`` straight out
  of the route as a 500. The realistic way to hit this is not an attacker, it
  is a caller passing milliseconds.

- ``metadata`` was unbounded, which made ``MAX_DOCUMENT_CHARS`` decorative.
  Measured: 8MB of metadata accepted, 9.4MB on disk -- ~47x the text cap on
  the same row -- and 17MB raised ``DocumentTooLarge`` from the driver as
  another uncaught 500.

Neither is a breach. Both are a 500 where a 422 belongs, or a documented
bound that did not hold, which is the same class of "true in the place we
tested" the rest of this suite exists to catch.

A third, ``max_downloads`` accepting 0 and negatives over HTTP while the
library refused them, went away with the byte path it bounded.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from tests.test_scope import owner_on
from voyd.web.vault import (MAX_DOCUMENT_CHARS, MAX_METADATA_BYTES,
                            MAX_TTL_SECONDS)


@pytest.fixture
async def ns(client, app):
    return await owner_on(app, "edges", "edges@example.com")


# ---- ttl_seconds ------------------------------------------------------

@pytest.mark.parametrize("ttl", [3600, 0, -1, -86400, MAX_TTL_SECONDS])
async def test_a_legitimate_ttl_is_still_accepted(client, ns, ttl):
    """Including the negatives, which are deliberately allowed: a scope that
    is already over is valid and must collect rather than linger."""
    r = await client.post("/v1/voids", json={"ttl_seconds": ttl}, headers=ns)
    assert r.status_code == 200, r.text


@pytest.mark.parametrize("ttl", [
    MAX_TTL_SECONDS + 1,
    10 ** 15,            # the value that used to raise OverflowError
    10 ** 18,
    2 ** 63,             # past a C int entirely
])
async def test_an_unrepresentable_ttl_is_refused_not_a_500(client, ns, ttl):
    r = await client.post("/v1/voids", json={"ttl_seconds": ttl}, headers=ns)
    assert r.status_code == 422, f"expected a refusal, got {r.status_code}"
    assert "ttl_seconds" in r.text


# ---- metadata ---------------------------------------------------------

async def test_metadata_cannot_carry_a_document_past_the_text_cap(client, ns):
    """The cap on `text` only means something if the row cannot route around
    it."""
    r = await client.post("/v1/voids", json={"ttl_seconds": 3600}, headers=ns)
    token = r.json()["token"]

    big = await client.post(
        f"/v1/voids/{token}/documents",
        json={"documents": [{"text": "x", "metadata": {"pad": "y" * 100_000}}]},
        headers=ns)
    assert big.status_code == 422, big.text
    assert "metadata" in big.text

    # And nothing was written -- the batch is refused whole.
    described = await client.get(f"/v1/voids/{token}", headers=ns)
    assert described.json()["index"]["total"] == 0


async def test_metadata_that_annotates_is_still_welcome(client, ns):
    """The fix must not break the feature. Metadata is for labels."""
    r = await client.post("/v1/voids", json={"ttl_seconds": 3600}, headers=ns)
    token = r.json()["token"]

    ok = await client.post(
        f"/v1/voids/{token}/documents",
        json={"documents": [{
            "text": "fault code P0301",
            "metadata": {"vin": "1HGCM82633A004352", "source": "scan",
                         "tags": ["misfire", "cylinder-1"]},
        }]},
        headers=ns)
    assert ok.status_code == 200, ok.text


async def test_a_metadata_value_at_the_limit_is_measured_in_bytes(client, ns):
    """The bound is serialised bytes, not key count -- one key is enough to
    blow it."""
    r = await client.post("/v1/voids", json={"ttl_seconds": 3600}, headers=ns)
    token = r.json()["token"]

    over = await client.post(
        f"/v1/voids/{token}/documents",
        json={"documents": [{"text": "x",
                             "metadata": {"k": "y" * (MAX_METADATA_BYTES + 100)}}]},
        headers=ns)
    assert over.status_code == 422, over.text


async def test_unserialisable_metadata_is_refused_rather_than_stored(client, ns):
    """Measuring the size requires serialising it, so a value that cannot be
    serialised has to fail as a validation error and not as a TypeError."""
    r = await client.post("/v1/voids", json={"ttl_seconds": 3600}, headers=ns)
    token = r.json()["token"]

    # Deeply self-referential structures cannot arrive over JSON, but a
    # non-dict can, and the documented behaviour is to drop it silently.
    dropped = await client.post(
        f"/v1/voids/{token}/documents",
        json={"documents": [{"text": "x", "metadata": "not an object"}]},
        headers=ns)
    assert dropped.status_code == 200, dropped.text


# ---- the bounds that already existed, kept honest --------------------

async def test_the_batch_and_text_bounds_still_hold(client, ns):
    """Regression cover for the two that were already right, so a later
    refactor of this model cannot quietly drop them."""
    r = await client.post("/v1/voids", json={"ttl_seconds": 3600}, headers=ns)
    token = r.json()["token"]

    too_many = await client.post(
        f"/v1/voids/{token}/documents",
        json={"documents": [{"text": "x"} for _ in range(101)]}, headers=ns)
    assert too_many.status_code == 422

    empty = await client.post(f"/v1/voids/{token}/documents",
                              json={"documents": []}, headers=ns)
    assert empty.status_code == 422

    too_long = await client.post(
        f"/v1/voids/{token}/documents",
        json={"documents": [{"text": "x" * (MAX_DOCUMENT_CHARS + 1)}]},
        headers=ns)
    assert too_long.status_code == 422
