"""The two things the vault's request layer owes a caller: a bounded gate and
a declared shape.

Argon2 makes one passcode guess expensive, which is a cost ceiling, not a
bound -- an attacker runs guesses in parallel. So the *rate* of guessing is
capped on both read paths, and only on voids that are actually gated. The
bodies are Pydantic models, so a malformed call is refused before any row is
written rather than half-way through the batch.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from tests.test_scope import owner_on

PASSCODE = "hunter2"


@pytest.fixture
async def gated(client, app, monkeypatch):
    """A passcode-gated scope, with embeddings stubbed so a *successful* search
    never reaches Voyage."""
    monkeypatch.setattr(
        app.intelligence, "embed_query",
        lambda text: _zeros(app.intelligence.config.dimensions))
    headers = await owner_on(app, "gate", "gate@example.com")
    r = await client.post("/v1/voids", json={"passcode": PASSCODE},
                          headers=headers)
    assert r.status_code == 200, r.text
    # The namespace header alone: reading a gated void needs no API key, which
    # is the point of a shareable link.
    return {"headers": headers, "ns": {"X-Voyd": "gate"},
            "token": r.json()["token"]}


async def _zeros(dims: int) -> list[float]:
    return [0.0] * dims


@pytest.fixture
async def public(client, app, monkeypatch):
    """The same scope with no guard at all."""
    monkeypatch.setattr(
        app.intelligence, "embed_query",
        lambda text: _zeros(app.intelligence.config.dimensions))
    headers = await owner_on(app, "open", "open@example.com")
    r = await client.post("/v1/voids", json={}, headers=headers)
    return {"headers": headers, "ns": {"X-Voyd": "open"},
            "token": r.json()["token"]}


# ---- the gate is bounded, not just expensive ---------------------------

async def test_guessing_the_passcode_is_rate_limited_not_merely_slow(
        client, gated):
    """Ten wrong guesses are 401. The eleventh is refused without a verify --
    otherwise the only cost of a brute force is CPU the attacker does not pay.
    """
    url = f"/v1/voids/{gated['token']}/search"
    for i in range(10):
        r = await client.post(url, json={"query": "x", "passcode": f"no-{i}"},
                              headers=gated["ns"])
        assert r.status_code == 401, i

    r = await client.post(url, json={"query": "x", "passcode": "no-10"},
                          headers=gated["ns"])
    assert r.status_code == 429
    assert "attempts" in r.json()["detail"].lower()

    # And the lockout is not bypassed by finally getting it right.
    r = await client.post(url, json={"query": "x", "passcode": PASSCODE},
                          headers=gated["ns"])
    assert r.status_code == 429


async def test_the_right_passcode_clears_the_count(client, gated):
    """A legitimate reader must not be locked out by someone else's guessing
    from the same address."""
    url = f"/v1/voids/{gated['token']}/search"
    for i in range(9):
        assert (await client.post(
            url, json={"query": "x", "passcode": f"no-{i}"},
            headers=gated["ns"])).status_code == 401

    ok = await client.post(url, json={"query": "x", "passcode": PASSCODE},
                           headers=gated["ns"])
    assert ok.status_code == 200, ok.text

    # Counters reset, so the next nine wrong guesses are 401 again, not 429.
    for i in range(9):
        assert (await client.post(
            url, json={"query": "x", "passcode": f"nope-{i}"},
            headers=gated["ns"])).status_code == 401


async def test_the_download_path_shares_the_same_bound(client, gated):
    """Search and download are the same boundary, so one of them cannot be the
    unmetered way in."""
    f = await client.post(f"/v1/voids/{gated['token']}/files",
                          json={"name": "invoice.txt", "mime": "text/plain"},
                          headers=gated["headers"])
    url = f"/v1/voids/{gated['token']}/files/{f.json()['doc_id']}"

    for _ in range(10):
        assert (await client.get(
            url, headers={**gated["ns"], "X-Passcode": "wrong"})).status_code == 401
    assert (await client.get(
        url, headers={**gated["ns"], "X-Passcode": "wrong"})).status_code == 429


async def test_an_ungated_void_is_never_rate_limited(client, public):
    """Throttling public traffic would buy no security and cost availability."""
    url = f"/v1/voids/{public['token']}/search"
    for i in range(25):
        r = await client.post(url, json={"query": "anything"},
                              headers=public["ns"])
        assert r.status_code == 200, (i, r.text)


# ---- the declared shape ------------------------------------------------

async def test_the_single_document_shorthand_still_normalises(client, app):
    """``{"text": ...}`` and ``{"documents": [...]}`` are the same call."""
    headers = await owner_on(app, "short", "short@example.com")
    token = (await client.post("/v1/voids", json={}, headers=headers)).json()["token"]

    r = await client.post(f"/v1/voids/{token}/documents",
                          json={"text": " one ", "name": " one.md ",
                                "metadata": "not-an-object"},
                          headers=headers)
    assert r.status_code == 200, r.text
    assert len(r.json()["added"]) == 1
    assert r.json()["added"][0]["name"] == "one.md", "name was not stripped"

    doc = await app.store.db.documents.find_one({"token": token})
    assert doc["text"] == "one", "text was not stripped"
    assert not doc["metadata"], "non-object metadata was kept"


@pytest.mark.parametrize("body", [
    {},                                        # neither form
    {"documents": []},                         # empty list
    {"documents": None},                       # explicitly nothing
    {"documents": [{"name": "no text.md"}]},   # text is required
    {"documents": ["just a string"]},          # not an object
    {"documents": [{"text": "ok"}] * 101},     # over MAX_BATCH
])
async def test_a_malformed_batch_is_refused_before_anything_is_written(
        client, app, body):
    headers = await owner_on(app, "bad", "bad@example.com")
    token = (await client.post("/v1/voids", json={}, headers=headers)).json()["token"]

    r = await client.post(f"/v1/voids/{token}/documents", json=body,
                          headers=headers)
    assert r.status_code == 422, r.text
    assert await app.store.db.documents.count_documents({"token": token}) == 0


async def test_ttl_seconds_must_be_an_integer(client, app):
    headers = await owner_on(app, "ttl", "ttl@example.com")
    r = await client.post("/v1/voids", json={"ttl_seconds": "soon"},
                          headers=headers)
    assert r.status_code == 422
