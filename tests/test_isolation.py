"""The claims that need a real database to be worth anything.

Two claims an attacker tests first, so they are tested here against real
queries rather than asserted in prose:

- a void is a boundary -- another namespace's key cannot reach through it, and
  the ``voyd_id`` filter makes a foreign token *invisible*, not merely forbidden
- a namespace URL can never expose the control plane

The guard is tested here too, because "a passcode and a download limit" is a
claim about what happens on the byte path, not a field on a document.
"""

from __future__ import annotations

import pytest

# This module drives the HTTP service (FastAPI). An engine-only install skips it whole,
# rather than failing collection on the import below.
pytest.importorskip("fastapi")

from voyd.auth import new_api_key
from voyd.web.deps import hash_api_key


async def make_owner(engine, email: str) -> tuple[dict, str]:
    """An owner plus their plaintext API key (only the hash is ever stored)."""
    key = new_api_key()
    owner_id = await engine.store.create_owner(email, hash_api_key(key))
    return {"_id": owner_id, "email": email}, key


async def make_voyd(engine, owner, slug: str) -> dict:
    return await engine.store.create_voyd(slug, owner["_id"], {}, name=slug)


def auth(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


def on(slug: str, key: str | None = None) -> dict:
    """Headers addressing a voyd host, optionally as an authenticated owner."""
    headers = {"X-Voyd": slug}
    if key:
        headers.update(auth(key))
    return headers


@pytest.fixture
async def two_namespaces(client, app):
    """Two owners, two namespaces, one void each -- the isolation fixture."""
    alice, alice_key = await make_owner(app, "alice@example.com")
    bob, bob_key = await make_owner(app, "bob@example.com")
    await make_voyd(app, alice, "alpha")
    await make_voyd(app, bob, "bravo")

    alpha = await client.post("/v1/voids", json={}, headers=on("alpha", alice_key))
    bravo = await client.post("/v1/voids", json={}, headers=on("bravo", bob_key))
    return {
        "alice_key": alice_key, "bob_key": bob_key,
        "alpha_token": alpha.json()["token"],
        "bravo_token": bravo.json()["token"],
    }


# ---- the void is a boundary --------------------------------------------

async def test_a_token_from_another_namespace_is_invisible(client, two_namespaces):
    """The token is real and the caller owns *a* namespace, but not the one it
    belongs to -- so the ``voyd_id`` filter must make it 404, not 403."""
    r = await client.get(f"/v1/voids/{two_namespaces['bravo_token']}",
                         headers=on("alpha", two_namespaces["alice_key"]))
    assert r.status_code == 404

    # And it is still perfectly visible on its own host.
    r = await client.get(f"/v1/voids/{two_namespaces['bravo_token']}",
                         headers=on("bravo", two_namespaces["bob_key"]))
    assert r.status_code == 200


async def test_an_owner_cannot_open_a_void_in_another_namespace(client, two_namespaces):
    """Bob holds a valid key -- it is simply not valid *here*. 403, not 401."""
    r = await client.post("/v1/voids", json={},
                          headers=on("alpha", two_namespaces["bob_key"]))
    assert r.status_code == 403


async def test_a_document_cannot_be_added_to_a_foreign_scope(client, two_namespaces):
    """Both ingest paths -- inline text and the blob handshake -- have to hold
    the same boundary, or one of them is the way in."""
    inline = await client.post(
        f"/v1/voids/{two_namespaces['bravo_token']}/documents",
        json={"text": "trespass"},
        headers=on("alpha", two_namespaces["alice_key"]),
    )
    assert inline.status_code == 404

    blob = await client.post(
        f"/v1/voids/{two_namespaces['bravo_token']}/files",
        json={"name": "secret.txt", "mime": "text/plain"},
        headers=on("alpha", two_namespaces["alice_key"]),
    )
    assert blob.status_code == 404


# ---- the guard ---------------------------------------------------------

@pytest.fixture
async def guarded(client, two_namespaces):
    """A passcode-protected scope with one blob-backed document, two reads."""
    r = await client.post("/v1/voids",
                          json={"passcode": "hunter2", "max_downloads": 2},
                          headers=on("alpha", two_namespaces["alice_key"]))
    token = r.json()["token"]
    f = await client.post(f"/v1/voids/{token}/files",
                          json={"name": "invoice.txt", "mime": "text/plain"},
                          headers=on("alpha", two_namespaces["alice_key"]))
    return {"token": token, "doc_id": f.json()["doc_id"], **two_namespaces}


async def test_a_download_without_the_passcode_is_refused(client, guarded):
    """The link is shareable, so the guard is the only thing between a stranger
    and the bytes. No key is required here -- that is the point."""
    r = await client.get(
        f"/v1/voids/{guarded['token']}/files/{guarded['doc_id']}",
        headers=on("alpha"))
    assert r.status_code == 401


async def test_the_passcode_also_gates_search_inside_the_boundary(client, guarded):
    """A void is a retrieval boundary, so reading it by query must be gated the
    same way as reading it by download. Otherwise search is the way around."""
    r = await client.post(f"/v1/voids/{guarded['token']}/search",
                          json={"query": "invoice"}, headers=on("alpha"))
    assert r.status_code == 401


async def test_the_download_limit_is_enforced_on_the_byte_path(client, guarded):
    """``max_downloads`` is a promise about the bytes, not a display field."""
    headers = {**on("alpha"), "X-Passcode": "hunter2"}
    url = f"/v1/voids/{guarded['token']}/files/{guarded['doc_id']}"

    assert (await client.get(url, headers=headers)).status_code == 200
    assert (await client.get(url, headers=headers)).status_code == 200
    # 410 Gone, not 403: the allowance is spent, and no credential brings it back.
    assert (await client.get(url, headers=headers)).status_code == 410, "spent"


async def test_the_passcode_hash_never_leaves_the_process(client, guarded):
    r = await client.get(f"/v1/voids/{guarded['token']}",
                         headers=on("alpha", guarded["alice_key"]))
    assert "passcode_hash" not in str(r.json()), "serialised a credential"


# ---- auth boundaries ---------------------------------------------------

@pytest.mark.parametrize("headers, expected", [
    ({}, 401),                                   # no credentials
    ({"Authorization": "Bearer nope"}, 401),     # not a key
    ({"Authorization": "Basic abc"}, 401),       # wrong scheme
])
async def test_owner_routes_reject_bad_credentials(client, two_namespaces, headers, expected):
    r = await client.post("/v1/voids", json={},
                          headers={"X-Voyd": "alpha", **headers})
    assert r.status_code == expected


# ---- the two planes ----------------------------------------------------

# ---- the two planes ----------------------------------------------------

async def test_namespace_management_is_apex_only(client, two_namespaces):
    key = two_namespaces["alice_key"]
    assert (await client.get("/v1/voyds", headers=auth(key))).status_code == 200
    assert (await client.get("/v1/voyds", headers=on("alpha", key))).status_code == 404



async def test_cors_is_open_on_the_api_only(client, two_namespaces):
    """The wildcard belongs to the public JSON API and nowhere else.

    There is no browser surface left to protect, which is precisely why the
    scoping stays: a future page must not inherit a wildcard nobody
    reconsidered.
    """
    api = await client.get(f"/v1/voids/{two_namespaces['alpha_token']}",
                           headers={"X-Voyd": "alpha",
                                    "Origin": "https://evil.example",
                                    **auth(two_namespaces["alice_key"])})
    other = await client.get("/healthz", headers={"Origin": "https://evil.example"})

    assert api.headers.get("access-control-allow-origin") == "*"
    assert "access-control-allow-origin" not in other.headers


async def test_there_is_no_browser_surface_left(client, two_namespaces):
    """The console is gone: one credential, and it is an API key.

    Asserted rather than assumed, because a stray router re-added later would
    bring sessions and cookies back with it.
    """
    for path in ("/", "/login", "/signup", "/new", "/keys"):
        for headers in ({}, on("alpha")):
            r = await client.get(path, headers=headers)
            assert r.status_code == 404, f"{path} still answers: {r.status_code}"
