"""The README's claim, made testable: *"R2 is only needed for the blob path --
inline text needs no object storage at all."*

It used to be false twice over. ``voyd.app`` hard-imported ``aioboto3`` (the
optional ``r2`` extra), so ``pip install 'voyd[app]'`` could not boot the
service at all; and ``build_app`` always constructed ``Storage.R2`` with
placeholder credentials, so an unconfigured deployment handed out presigned
URLs against a bucket that does not exist -- a dead link at the client instead
of an error at the server.

So: the import graph is checked in a subprocess with the extra made
unimportable, and the inline path is exercised end to end against
``NullStorage``.
"""

from __future__ import annotations

import random
import subprocess
import sys
import uuid

import pytest

pytest.importorskip("fastapi")

from tests.test_atlas_search import until_searchable
from tests.test_scope import owner_on
from voyd.storage import NullStorage, Storage
from voyd.storage.base import NoObjectStorage, ObjectStorage

# The status the blob endpoints answer with when there is no bucket. 501, not
# 409: no change to the void's state makes the call work, because it is the
# *server* that does not implement the byte path here.
NO_BYTE_PATH = 501


# ---- fixtures: the same service, with no object storage ----------------

@pytest.fixture
async def null_app():
    """The HTTP service on ``NullStorage`` -- the deployment the README describes.

    Deliberately not ``monkeypatch``-ing the shared ``app`` fixture's storage:
    this asserts that a service *composed* with no object storage works, which is
    what ``build_app`` now does.
    """
    from tests.conftest import TEST_MONGO_URI, _mongo_available

    if not await _mongo_available(TEST_MONGO_URI):
        pytest.skip(f"no MongoDB at {TEST_MONGO_URI}")

    from voyd import Intelligence, Store, Voyd
    from voyd.web.console import _credential_limiter
    from voyd.web.vault import _passcode_limiter

    _credential_limiter.clear()
    _passcode_limiter.clear()
    db_name = f"voyd_test_{uuid.uuid4().hex[:12]}"
    voyd = Voyd(
        domain="voyd.test",
        store=Store.Mongo(TEST_MONGO_URI, db_name=db_name),
        storage=Storage.Null(),
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
        _credential_limiter.clear()
        _passcode_limiter.clear()


@pytest.fixture
async def null_client(null_app):
    import httpx

    transport = httpx.ASGITransport(app=null_app.api)
    async with httpx.AsyncClient(transport=transport,
                                 base_url="http://voyd.test") as c:
        yield c


def vec(seed: int, dims: int) -> list[float]:
    random.seed(seed)
    return [random.random() for _ in range(dims)]


@pytest.fixture
async def null_scope(null_client, null_app, monkeypatch):
    """A void on the storage-less Host, with query embedding stubbed.

    ``embed_query`` is stubbed because these assert on retrieval and on the
    storage boundary, not on Voyage.
    """
    dims = null_app.intelligence.config.dimensions

    async def _fixed_query_vector(text: str) -> list[float]:
        return vec(1, dims)

    monkeypatch.setattr(null_app.intelligence, "embed_query",
                        _fixed_query_vector)
    headers = await owner_on(null_app, "nobucket", "null@example.com")
    r = await null_client.post("/v1/voids", json={"ttl_seconds": 3600},
                               headers=headers)
    assert r.status_code == 200, r.text
    return {"headers": headers, "token": r.json()["token"], "dims": dims}


# ---- the import graph --------------------------------------------------

def test_the_service_imports_without_the_r2_extra():
    """``pip install 'voyd[app]'`` has no aioboto3, and must still boot.

    Run in a subprocess with a meta-path finder that raises
    ``ModuleNotFoundError`` for the ``r2`` extra's modules: the package *is*
    installed in this venv, so hiding it is the only honest check. A failure
    here is the original bug.
    """
    code = """
import sys
class Absent:
    BLOCKED = ("aioboto3", "botocore")
    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in self.BLOCKED:
            # What a real absent module raises, so the guards under test see
            # exactly what they would see on a `voyd[app]`-only install.
            raise ModuleNotFoundError(f"No module named {name!r}", name=name)
        return None
sys.meta_path.insert(0, Absent())

import voyd.app
import voyd.ops
import voyd.settings
import voyd.web.owner
import voyd.web.vault
from voyd.storage import Storage
assert not Storage.Null().offers_bytes
assert "aioboto3" not in sys.modules and "botocore" not in sys.modules
print("ok")
"""
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True,
                          text=True)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip().endswith("ok")


def test_asking_for_r2_without_the_extra_names_the_fix():
    """A missing extra should be an instruction, not a ModuleNotFoundError
    three imports deep -- same contract as ``python -m voyd``."""
    code = """
import sys
class Absent:
    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in ("aioboto3", "botocore"):
            raise ModuleNotFoundError(f"No module named {name!r}", name=name)
        return None
sys.meta_path.insert(0, Absent())
from voyd.storage import Storage
try:
    Storage.R2(endpoint="https://x", key_id="k", secret_key="s", bucket="b")
except ModuleNotFoundError as exc:
    assert "voyd[r2]" in str(exc), str(exc)
    print("ok")
else:
    raise AssertionError("expected ModuleNotFoundError")
"""
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True,
                          text=True)
    assert proc.returncode == 0, proc.stderr


def test_null_storage_satisfies_the_storage_interface():
    """The app depends on the Protocol, so both backends must satisfy it --
    otherwise "no object storage" is a fork of the code, not a configuration."""
    assert isinstance(NullStorage(), ObjectStorage)


# ---- configuration is honest -------------------------------------------

def test_unset_r2_settings_select_null_storage(caplog):
    from voyd.settings import VoydSettings, build_storage

    s = VoydSettings(_env_file=None)
    with caplog.at_level("INFO", logger="voyd.settings"):
        storage = build_storage(s)
    assert isinstance(storage, NullStorage)
    # One clear line, or an operator finds out from a dead download link.
    assert any("blob path is disabled" in r.message for r in caplog.records)


def test_configured_r2_settings_still_select_r2():
    """The existing deployment shape must be untouched."""
    pytest.importorskip("aioboto3")
    from voyd.settings import VoydSettings, build_storage
    from voyd.storage import R2Storage

    s = VoydSettings(_env_file=None, r2_endpoint="https://example.invalid",
                     r2_key_id="k", r2_secret="s", r2_bucket="b")
    assert isinstance(build_storage(s), R2Storage)


def test_half_configured_storage_is_refused_not_degraded():
    """Three of four set is a typo, not a deployment shape: presigning with a
    missing bucket fails at the client, where nobody is watching."""
    from voyd.settings import VoydSettings, build_storage

    s = VoydSettings(_env_file=None, r2_endpoint="https://example.invalid",
                     r2_key_id="k", r2_secret="s")
    with pytest.raises(ValueError, match="VOYD_R2_BUCKET"):
        build_storage(s)


# ---- the inline path works in full -------------------------------------

async def test_inline_documents_and_search_work_with_no_object_storage(
        null_client, null_app, null_scope):
    """The claim, end to end: text in, hit out, no bucket anywhere."""
    token, dims = null_scope["token"], null_scope["dims"]
    r = await null_client.post(
        f"/v1/voids/{token}/documents",
        json={"documents": [{"text": "brake pad replacement", "name": "brakes.md"},
                            {"text": "synthetic oil change", "name": "oil.md"}]},
        headers=null_scope["headers"],
    )
    assert r.status_code == 200, r.text
    assert len(r.json()["added"]) == 2

    described = await null_client.get(f"/v1/voids/{token}",
                                      headers=null_scope["headers"])
    assert described.status_code == 200
    assert described.json()["index"]["total"] == 2

    # Embeddings written directly: the assertion is about retrieval without a
    # bucket, and must not depend on Voyage.
    voyd = await null_app.store.get_voyd_by_slug("nobucket")
    await null_app.store.db.documents.update_many(
        {"voyd_id": voyd["_id"], "token": token},
        {"$set": {"embedding": vec(1, dims), "indexed": True}},
    )
    await until_searchable(null_app.store, voyd["_id"], vec(1, dims), expected=2)

    hits = await null_client.post(f"/v1/voids/{token}/search",
                                  json={"query": "brakes"},
                                  headers=null_scope["headers"])
    assert hits.status_code == 200, hits.text
    matches = hits.json()["matches"]
    assert matches, "inline text must be retrievable with no object storage"
    assert all("text" in m for m in matches)
    assert not any("download_url" in m for m in matches)

    # Namespace-wide search is the same path, so it is asserted too.
    wide = await null_client.post("/v1/search", json={"query": "oil"},
                                  headers=null_scope["headers"])
    assert wide.status_code == 200, wide.text
    assert wide.json()["matches"]


async def test_a_blob_backed_hit_does_not_break_a_search(
        null_client, null_app, null_scope):
    """A row carrying a ``key`` cannot be created through this API -- but it can
    survive storage being reconfigured away. ``_present_matches`` presigns for
    any such hit, so this is the line that would 500 a whole search response.
    """
    token, dims = null_scope["token"], null_scope["dims"]
    voyd = await null_app.store.get_voyd_by_slug("nobucket")
    await null_app.store.db.documents.insert_one({
        "voyd_id": voyd["_id"], "token": token, "doc_id": "legacy",
        "name": "invoice.txt", "text": "invoice for brake pads",
        "key": f"voyds/nobucket/voids/{token}/legacy", "mime": "text/plain",
        "indexed": True, "embedding": vec(1, dims),
    })
    await until_searchable(null_app.store, voyd["_id"], vec(1, dims), expected=1)

    r = await null_client.post(f"/v1/voids/{token}/search",
                               json={"query": "invoice"},
                               headers=null_scope["headers"])
    assert r.status_code == 200, r.text
    hit = next(m for m in r.json()["matches"] if m["doc_id"] == "legacy")
    # The hit is served -- text and all -- just without a URL we cannot mint.
    assert hit["text"].startswith("invoice")
    assert "download_url" not in hit


# ---- the byte path refuses, clearly ------------------------------------

async def test_the_blob_endpoints_say_not_implemented(null_client, null_scope):
    """501 on all three, and the message points at the inline path. The old
    behaviour was a 200 carrying a presigned URL to nowhere."""
    token, headers = null_scope["token"], null_scope["headers"]

    presign = await null_client.post(f"/v1/voids/{token}/files",
                                     json={"name": "invoice.txt",
                                           "mime": "text/plain"},
                                     headers=headers)
    assert presign.status_code == NO_BYTE_PATH, presign.text
    assert "documents" in presign.json()["detail"]

    complete = await null_client.post(
        f"/v1/voids/{token}/files/whatever/complete", json={}, headers=headers)
    assert complete.status_code == NO_BYTE_PATH

    download = await null_client.get(
        f"/v1/voids/{token}/files/whatever", headers=headers)
    assert download.status_code == NO_BYTE_PATH


async def test_nothing_is_written_when_the_byte_path_is_refused(
        null_client, null_app, null_scope):
    """The refusal comes before the insert, or a void fills with rows whose
    bytes can never arrive."""
    token = null_scope["token"]
    await null_client.post(f"/v1/voids/{token}/files",
                           json={"name": "invoice.txt", "mime": "text/plain"},
                           headers=null_scope["headers"])
    body = (await null_client.get(f"/v1/voids/{token}",
                                  headers=null_scope["headers"])).json()
    assert body["documents"] == []


# ---- the backend itself ------------------------------------------------

async def test_null_storage_fails_loudly_on_bytes_and_quietly_on_cleanup():
    """The split that matters: a missing capability is an error; a torn-down
    void must not error, because there is nothing left to reclaim."""
    storage = NullStorage()

    for call in (storage.presign_put("k"), storage.presign_get("k"),
                 storage.head("k"), storage.get_text_window("k", max_bytes=10)):
        with pytest.raises(NoObjectStorage):
            await call

    assert await storage.delete_prefix("voyds/x/") == 0
    assert await storage.delete_key("voyds/x/y") is None


async def test_the_embed_worker_parks_a_document_it_can_never_read(null_app):
    """A blob-backed row with no storage is permanently unembeddable. Retrying
    it forever would hold the queue's back-off open for nothing."""
    from voyd.ops import Ops

    voyd_id = (await null_app.store.create_voyd(
        "parked", (await null_app.store.db.owners.insert_one(
            {"email": "p@example.com"})).inserted_id, {}, name="parked"))["_id"]
    doc = await null_app.store.db.documents.insert_one({
        "voyd_id": voyd_id, "token": "t", "doc_id": "d", "name": "n",
        "text": None, "key": "voyds/parked/voids/t/d", "mime": "text/plain",
        "indexed": False,
    })

    ops = Ops(null_app.store, null_app.storage, null_app.intelligence)
    await ops._embed_document(
        await null_app.store.db.documents.find_one({"_id": doc.inserted_id}))

    row = await null_app.store.db.documents.find_one({"_id": doc.inserted_id})
    # ``"error"`` is this store's terminal state for "will never embed" --
    # not ``False``, which the queue would hand out again on the next tick.
    assert row["indexed"] == "error", "parked, not left pending forever"
    assert row.get("embedding") is None
