"""The headline capability has to exist on the surface people actually use.

For a while it did not. ``revoke()`` lived on the engine, the README led with
it, and a caller holding an API key -- or an agent holding the tools --
had no way to reach it. The story and the product disagreed, which is a worse
failure than a missing feature: it is a promise the thing cannot keep.

``POST /v1/voids/{token}/forget`` closes that, and the tests below are mostly
about what it must *not* do. It is the only destructive-sounding verb in the
API and it is deliberately not destructive: nothing is removed, nothing is
scheduled, and the caller is handed no follow-up obligation. The rows stay on
disk and stop being reachable; the scope's deadline still owns erasure.

Which is the design collapsing into one field rather than growing a second
mechanism. Forgetting a fact is giving it a deadline in the past -- the same
``expire_at`` the scope already runs on -- so a subject erasure request and an
ordinary expiry are collected by the same TTL index and reclaimed by the same
change-stream event. There is no erasure subsystem here because an erasure
request *is* a deadline that has already passed.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from tests.test_scope import owner_on


@pytest.fixture
async def scope_with_docs(client, app):
    """A scope holding three documents, through the real HTTP surface."""
    headers = await owner_on(app, "forget", "forget@example.com")
    r = await client.post("/v1/voids", json={"ttl_seconds": 3600},
                          headers=headers)
    assert r.status_code == 200, r.text
    token = r.json()["token"]

    added = await client.post(
        f"/v1/voids/{token}/documents",
        json={"documents": [{"text": "the admin password is hunter2"},
                            {"text": "fault code P0301"},
                            {"text": "the user's name is Dana"}]},
        headers=headers)
    assert added.status_code == 200, added.text
    doc_ids = [d["doc_id"] for d in added.json()["added"]]
    return headers, token, doc_ids


async def _count(client, token, headers) -> int:
    r = await client.get(f"/v1/voids/{token}", headers=headers)
    return r.json()["index"]["total"]


async def test_a_caller_with_an_api_key_can_forget_one_document(
        scope_with_docs, client):
    headers, token, doc_ids = scope_with_docs

    r = await client.post(f"/v1/voids/{token}/forget",
                          json={"doc_ids": [doc_ids[0]],
                                "reason": "credential leaked"},
                          headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["forgotten"] == 1
    assert body["reason"] == "credential leaked"
    # The timestamp somebody will have to defend is the one refusal began,
    # not the one the sweeper writes later.
    assert body["unreachable_since"]

    assert await _count(client, token, headers) == 2


async def test_the_forgotten_document_is_gone_from_the_scope_immediately(
        scope_with_docs, client, app):
    """No sweeper has run. The row is still on disk. It is already
    unreachable through every read the product offers."""
    headers, token, doc_ids = scope_with_docs

    await client.post(f"/v1/voids/{token}/forget",
                      json={"doc_ids": [doc_ids[0]]}, headers=headers)

    # describe() no longer counts it...
    assert await _count(client, token, headers) == 2
    # ...and the row is still physically present, which is the point.
    on_disk = await app.store.db.documents.count_documents(
        {"doc_id": doc_ids[0]})
    assert on_disk == 1, "forget must not delete -- erasure is the deadline's job"


async def test_forgetting_the_whole_scope_needs_no_document_list(
        scope_with_docs, client):
    headers, token, _ = scope_with_docs

    r = await client.post(f"/v1/voids/{token}/forget", json={},
                          headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["forgotten"] == 3
    assert await _count(client, token, headers) == 0


async def test_an_empty_body_is_accepted_as_forget_everything(
        scope_with_docs, client):
    """An agent calling this with no arguments means "forget it all", and
    should not be met with a 422 about a missing field."""
    headers, token, _ = scope_with_docs
    r = await client.post(f"/v1/voids/{token}/forget", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["forgotten"] == 3


async def test_forgetting_twice_is_not_an_error_and_not_double_counted(
        scope_with_docs, client):
    """Idempotent, because an agent that retries on a timeout must not be
    told it forgot six things when there were three."""
    headers, token, _ = scope_with_docs

    first = await client.post(f"/v1/voids/{token}/forget", json={},
                              headers=headers)
    second = await client.post(f"/v1/voids/{token}/forget", json={},
                               headers=headers)
    assert first.json()["forgotten"] == 3
    assert second.json()["forgotten"] == 0
    assert second.status_code == 200


async def test_the_reason_is_recorded_on_the_row_for_an_audit(
        scope_with_docs, client, app):
    headers, token, doc_ids = scope_with_docs
    await client.post(f"/v1/voids/{token}/forget",
                      json={"doc_ids": [doc_ids[1]], "reason": "user retracted"},
                      headers=headers)

    row = await app.store.db.documents.find_one({"doc_id": doc_ids[1]})
    assert row["forgotten"]["reason"] == "user retracted"
    assert row["forgotten"]["at"] is not None


async def test_an_erasure_request_is_just_a_deadline_that_already_passed(
        scope_with_docs, client, app):
    """The design claim, asserted rather than narrated.

    If forgetting used a second mechanism, this row would need a second
    cleanup path. It does not: it carries the same ``expire_at`` the scope's
    TTL index already collects, so the reaper takes it with everything else
    and the change stream reclaims its bytes the same way.
    """
    headers, token, doc_ids = scope_with_docs
    await client.post(f"/v1/voids/{token}/forget",
                      json={"doc_ids": [doc_ids[0]]}, headers=headers)

    row = await app.store.db.documents.find_one({"doc_id": doc_ids[0]})
    assert row["expire_at"] is not None, \
        "a forgotten row with no deadline would never be collected"
    # Already due, so the existing TTL index collects it on the next sweep.
    from voyd.engine.time import aware, now
    assert aware(row["expire_at"]) <= now()


async def test_forgetting_needs_ownership(scope_with_docs, client, app):
    """Reachability is not something a bearer of the void token alone may
    change -- otherwise a shared read link could erase the scope."""
    headers, token, _ = scope_with_docs
    stranger = await owner_on(app, "stranger", "stranger@example.com")

    # The namespace header alone, with no key at all.
    anon = await client.post(f"/v1/voids/{token}/forget", json={},
                             headers={"X-Voyd": "forget"})
    assert anon.status_code == 401, anon.text

    # A real key, but for a different namespace.
    other = await client.post(f"/v1/voids/{token}/forget", json={},
                              headers=stranger)
    assert other.status_code == 404, other.text


async def test_forgetting_an_unknown_scope_is_a_404_not_a_silent_zero(
        scope_with_docs, client):
    headers, _, _ = scope_with_docs
    r = await client.post("/v1/voids/nosuchtoken/forget", json={},
                          headers=headers)
    assert r.status_code == 404
