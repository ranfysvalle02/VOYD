"""The product, end to end: open a scope, put text in it, query it, forget it.

These drive the HTTP API the MCP tools call, because that is the surface an
agent actually reaches. Embeddings are stubbed -- these assert on the *scope*
(what goes in, what comes back, what expires), not on Voyage.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from voyd.auth import new_api_key
from voyd.engine.time import now
from voyd.web.deps import hash_api_key


async def owner_on(app, slug: str, email: str) -> dict:
    key = new_api_key()
    owner_id = await app.store.create_owner(email, hash_api_key(key))
    await app.store.create_voyd(slug, owner_id, {}, name=slug)
    return {"X-Voyd": slug, "Authorization": f"Bearer {key}"}


@pytest.fixture
async def scope(client, app):
    """An open scope on a fresh namespace, plus its auth headers."""
    headers = await owner_on(app, "acme", "scope@example.com")
    r = await client.post("/v1/voids", json={"ttl_seconds": 3600}, headers=headers)
    assert r.status_code == 200, r.text
    return {"headers": headers, "token": r.json()["token"], "body": r.json()}


# ---- opening a scope ---------------------------------------------------

async def test_a_scope_is_created_with_a_deadline(scope):
    """The deadline is the product, so it is in the response, not buried."""
    assert scope["body"]["expire_at"] is not None
    assert scope["body"]["expires"] != "never"


async def test_a_scope_without_a_ttl_is_permanent_and_says_so(client, app):
    """Not every scope should expire -- but the default must never be a silent
    'forever', which is exactly how vector namespaces leak."""
    headers = await owner_on(app, "perm", "perm@example.com")
    r = await client.post("/v1/voids", json={}, headers=headers)
    assert r.json()["expires"] == "never"


# ---- text straight in --------------------------------------------------

async def test_documents_go_in_without_touching_object_storage(client, scope):
    """The whole point of the inline path: no presign, no PUT, no round trip.

    ``app.storage`` in tests points at an unroutable endpoint, so if this ever
    reached R2 the test would fail rather than quietly pass.
    """
    r = await client.post(
        f"/v1/voids/{scope['token']}/documents",
        json={"documents": [
            {"text": "the brake pads are worn", "name": "a.md"},
            {"text": "fault code P0301 on cylinder 1", "name": "b.md",
             "metadata": {"source": "scan"}},
        ]},
        headers=scope["headers"])

    assert r.status_code == 200, r.text
    assert len(r.json()["added"]) == 2
    assert r.json()["index"]["total"] == 2


async def test_a_single_document_needs_no_list(client, scope):
    """The shorthand exists because an agent adding one note should not have
    to know about batching."""
    r = await client.post(f"/v1/voids/{scope['token']}/documents",
                          json={"text": "just one", "name": "one.md"},
                          headers=scope["headers"])
    assert r.status_code == 200
    assert len(r.json()["added"]) == 1


async def test_documents_inherit_the_scope_deadline(client, app, scope):
    """The claim that makes the deadline trustworthy: the caller sets one TTL,
    on the scope, and every row inside it carries the same one. Nothing can be
    left behind holding a vector."""
    await client.post(f"/v1/voids/{scope['token']}/documents",
                      json={"text": "inherits", "name": "x.md"},
                      headers=scope["headers"])

    void = await app.store.db.voids.find_one({"token": scope["token"]})
    doc = await app.store.db.documents.find_one({"token": scope["token"]})
    assert doc["expire_at"] == void["expire_at"] is not None


async def test_an_empty_document_is_refused_rather_than_queued(client, scope):
    """Embedding whitespace costs an API call to learn nothing."""
    r = await client.post(f"/v1/voids/{scope['token']}/documents",
                          json={"documents": [{"text": "   "}]},
                          headers=scope["headers"])
    assert r.status_code == 422


async def test_a_rejected_batch_writes_nothing(client, scope):
    """Partial writes are worse than refusals: the caller gets a scope with
    some of its documents in it and no way to tell which half landed."""
    r = await client.post(
        f"/v1/voids/{scope['token']}/documents",
        json={"documents": [
            {"text": "good one"}, {"text": "good two"}, {"text": "  "},
        ]},
        headers=scope["headers"])
    assert r.status_code == 422

    body = (await client.get(f"/v1/voids/{scope['token']}",
                             headers=scope["headers"])).json()
    assert body["index"]["total"] == 0, "the two valid documents were written anyway"


async def test_one_enormous_document_is_refused(client, scope):
    """It has to fit a BSON document alongside its vector, and anything this
    size should have been chunked by the caller."""
    r = await client.post(f"/v1/voids/{scope['token']}/documents",
                          json={"text": "x" * 200_001},
                          headers=scope["headers"])
    assert r.status_code == 422


async def test_a_batch_is_bounded(client, scope):
    """One call must not be able to queue unbounded embedding work."""
    r = await client.post(
        f"/v1/voids/{scope['token']}/documents",
        json={"documents": [{"text": f"doc {i}"} for i in range(101)]},
        headers=scope["headers"])
    assert r.status_code == 422


async def test_documents_cannot_be_added_to_a_foreign_scope(client, app, scope):
    """Same boundary as everything else: a real token, the wrong namespace."""
    other = await owner_on(app, "rival", "rival@example.com")
    r = await client.post(f"/v1/voids/{scope['token']}/documents",
                          json={"text": "trespass"}, headers=other)
    assert r.status_code == 404


# ---- knowing what is queryable ----------------------------------------

async def test_the_scope_counts_what_is_in_it(client, app, scope):
    """``doc_count`` is initialised on the void and incremented on write. If
    those two ever name different fields the counter silently stays zero."""
    await client.post(f"/v1/voids/{scope['token']}/documents",
                      json={"documents": [{"text": "a"}, {"text": "b"}]},
                      headers=scope["headers"])

    void = await app.store.db.voids.find_one({"token": scope["token"]})
    assert void["doc_count"] == 2


async def test_describe_separates_added_from_searchable(client, scope):
    """Embedding is asynchronous. A caller about to search needs to know the
    difference between 'I added 50' and '50 are queryable', or it will read an
    incomplete index as an empty answer."""
    await client.post(f"/v1/voids/{scope['token']}/documents",
                      json={"documents": [{"text": "a"}, {"text": "b"}]},
                      headers=scope["headers"])

    body = (await client.get(f"/v1/voids/{scope['token']}",
                             headers=scope["headers"])).json()
    assert body["index"]["total"] == 2
    assert body["index"]["pending"] == 2, "nothing embedded yet: no worker running"
    assert body["index"]["indexed"] == 0
    assert len(body["documents"]) == 2


async def test_the_scope_reports_its_own_expiry(client, scope):
    body = (await client.get(f"/v1/voids/{scope['token']}",
                             headers=scope["headers"])).json()
    assert body["void"]["expire_at"] is not None


# ---- the deadline actually collects ------------------------------------

async def test_an_expired_scope_takes_its_documents_and_vectors_with_it(
        client, app, scope):
    """The drift bug this exists to make impossible.

    Split across services, the vector outlives the document and the bytes
    outlive both. Here one TTL index covers the scope and its rows: the same
    ``expire_at``, so MongoDB's reaper cannot collect one without the other.
    """
    await client.post(f"/v1/voids/{scope['token']}/documents",
                      json={"documents": [{"text": "doomed", "name": "d.md"}]},
                      headers=scope["headers"])

    # TTL granularity is ~60s, so assert on the *declaration* rather than
    # sleeping: both collections expire on the same field, with no grace.
    for coll in ("voids", "documents"):
        idx = await app.store.db[coll].index_information()
        assert idx["expire_at_1"]["expireAfterSeconds"] == 0, coll

    # And the rows agree on the deadline, which is what makes one index enough.
    void = await app.store.db.voids.find_one({"token": scope["token"]})
    async for doc in app.store.db.documents.find({"token": scope["token"]}):
        assert doc["expire_at"] == void["expire_at"]


async def test_a_past_deadline_is_accepted_and_simply_collects(
        client, app, scope, reaper_disarmed):
    """A zero/negative TTL is not an error -- it is a scope that is already
    over. It must not linger just because the reaper has not run yet.

    ``reaper_disarmed`` because the row this reads back is expired the instant
    it is written, so the TTL monitor is entitled to delete it between the
    POST and the ``find_one`` -- a narrow window, but one that turns a real
    assertion into a ``NoneType`` traceback roughly whenever a sweep lands
    there. The claim is about what the *API* did with a past deadline, so the
    reaper is noise in it either way.
    """
    r = await client.post("/v1/voids", json={"ttl_seconds": -1},
                          headers=scope["headers"])
    assert r.status_code == 200
    void = await app.store.db.voids.find_one({"token": r.json()["token"]})
    assert void["expire_at"] < now(), "already past due"
