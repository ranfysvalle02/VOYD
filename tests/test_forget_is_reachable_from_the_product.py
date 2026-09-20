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
    TTL index already collects, so the reaper takes it with everything else --
    and there is nothing else to reclaim, because the text is a field on the
    row rather than an object somewhere holding its own deadline.
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


# --------------------------------------------------------------------------
# and it can be proven afterwards
# --------------------------------------------------------------------------

async def test_forget_hands_back_a_receipt(client, scope_with_docs):
    """The one piece of the audit trail that does not live here.

    A hash chain is evidence against somebody who cannot rewrite it. The
    operator of this database can. So the caller who asked for the erasure
    leaves holding a hash computed before any dispute existed -- and a chain
    that later does not contain it is falsified by a record the auditee never
    had.
    """
    headers, token, doc_ids = scope_with_docs

    r = await client.post(f"/v1/voids/{token}/forget",
                          json={"doc_ids": doc_ids[:1],
                                "reason": "credential leaked"},
                          headers=headers)
    assert r.status_code == 200, r.text
    receipt = r.json()["receipt"]
    assert len(receipt["hash"]) == 64
    assert receipt["seq"] == 0
    assert receipt["prev"] == "0" * 64, "the first link points at genesis"


async def test_proof_verifies_the_chain_and_states_its_limits(client, scope_with_docs):
    """``forget`` is a promise; this is the evidence, with the boundaries on it.

    The claims block is not decoration. A proof that is quoted as proving
    more than it does is worse than no proof, and the thing this one most
    invites is "you deleted it" -- which it does not say, because nothing
    here deletes anything on request.
    """
    headers, token, doc_ids = scope_with_docs

    first = await client.post(f"/v1/voids/{token}/forget",
                              json={"doc_ids": doc_ids[:1], "reason": "leaked"},
                              headers=headers)
    second = await client.post(f"/v1/voids/{token}/forget",
                               json={"doc_ids": doc_ids[1:2],
                                     "reason": "user retracted it"},
                               headers=headers)
    assert second.status_code == 200, second.text

    r = await client.get(f"/v1/voids/{token}/proof", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()

    assert body["chain"]["intact"] is True
    assert body["chain"]["entries"] == 2
    assert [e["reason"] for e in body["entries"]] == ["leaked",
                                                      "user retracted it"]
    # Each entry commits to its predecessor, and the caller's receipt is in it.
    assert body["entries"][0]["hash"] == first.json()["receipt"]["hash"]
    assert body["entries"][1]["prev"] == body["entries"][0]["hash"]

    deleted = " ".join(body["claims"]["does_not_prove"])
    assert "deleted" in deleted, (
        "the one thing a reader will assume this proves is erasure; it must "
        "be denied in the response, not only in the docs")
    assert body["chain"]["signed"] is False, "no key configured: say so"


async def test_a_chain_entry_does_not_carry_the_text_it_forgot(client,
                                                               scope_with_docs):
    """The record must not become an exempt copy of the secret.

    The chain is the one collection here with no deadline on it. A document
    quoted into it would outlive every mechanism built to forget it -- so the
    entry holds ids and a reason, and this is the test that keeps it that way.
    """
    headers, token, doc_ids = scope_with_docs

    await client.post(f"/v1/voids/{token}/forget",
                      json={"doc_ids": doc_ids[:1], "reason": "leaked"},
                      headers=headers)

    body = (await client.get(f"/v1/voids/{token}/proof", headers=headers)).json()
    assert "hunter2" not in str(body), \
        "the forgotten text is in the audit record, which never expires"


async def test_proof_is_scoped_to_its_owner(client, app, scope_with_docs):
    """One namespace's refusal history is not another's to read."""
    from tests.test_scope import owner_on

    headers, token, doc_ids = scope_with_docs
    await client.post(f"/v1/voids/{token}/forget",
                      json={"doc_ids": doc_ids[:1], "reason": "leaked"},
                      headers=headers)

    stranger = await owner_on(app, "nosy", "nosy@example.com")
    r = await client.get(f"/v1/voids/{token}/proof", headers=stranger)
    assert r.status_code in (403, 404), (
        f"another owner read this namespace's refusal chain: {r.status_code}")


# --------------------------------------------------------------------------
# refusal is part of the answer, not a silent subtraction
# --------------------------------------------------------------------------
#
# These go through the store rather than POST /search, for the same reason
# the rest of the search suite does: embedding a query needs a real Voyage
# key, and the claim being tested is about the boundary, not the vendor.


async def test_search_reports_what_it_refused(client, app, scope_with_docs):
    """A short result and an empty scope must not look the same.

    The caller of this API is usually a model. Hand it two hits where there
    were three and it will describe what it got as what exists; tell it a
    matching fact was forgotten and it can say so, or ask. The information is
    free -- the read path already counted the refusals on the way out -- and
    withholding it is what turns a correct filter into a confident wrong
    answer downstream.
    """
    headers, token, doc_ids = scope_with_docs
    voyd = await app.store.get_voyd_by_slug("forget")

    await client.post(f"/v1/voids/{token}/forget",
                      json={"doc_ids": doc_ids, "reason": "leaked"},
                      headers=headers)

    page = await app.store.vector_search(
        voyd["_id"], [0.1] * app.store.engine.search_engine.specs[
            "documents"].dimensions, token=token, limit=5)

    assert list(page) == [], "a revoked document must not be a hit"
    reported = page.as_dict()
    assert reported["refused_total"] >= 0
    assert "starved" in reported and "refused" in reported, (
        "the answer cannot distinguish 'nothing matched' from 'everything "
        "matching was forgotten'")


def test_the_response_shape_is_the_same_whether_anything_was_refused():
    """The field is present and empty rather than absent, so it can be trusted.

    A key that only appears when something was refused makes every caller
    write the same ``if "admission" in body`` branch, and the ones who forget
    it get the old ambiguity back. A plain list -- which is what a caller
    that filters the matches first will hand over -- must degrade to "no
    claim", not to a 500.
    """
    from voyd.engine.admission import Page
    from voyd.web.vault import _admission_of

    clean = _admission_of(Page([{"doc_id": "d1"}], examined=1))
    assert clean == {"refused": [], "refused_total": 0, "examined": 1,
                     "spent": 0, "redacted": 0, "starved": False}

    # ``redacted`` obeys the same rule as the rest, and has to: a document
    # returned with an embedded subject removed is shorter than the row on
    # disk, and a caller told only "1 match" has been quietly edited. Present
    # and zero, or the API reintroduces at its own boundary the silence that
    # ``subjects`` was added to end.
    trimmed = _admission_of(Page([{"doc_id": "d1"}], examined=1, redacted=2))
    assert trimmed["redacted"] == 2

    refused = _admission_of(Page([], refused={"quarantined": 3}, examined=3,
                                 starved=True))
    assert refused["refused"] == [{"reason": "quarantined", "count": 3}]
    assert refused["refused_total"] == 3
    assert refused["starved"] is True

    assert set(_admission_of([{"doc_id": "d1"}])) >= {"refused", "starved"}, \
        "a plain list must produce the same keys, claiming nothing"
