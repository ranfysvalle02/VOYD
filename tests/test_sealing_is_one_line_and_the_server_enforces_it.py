"""Encryption you cannot forget to use, and cannot bypass by accident.

The mechanism shipped before the ergonomics did, and the gap between them
was the whole risk. To seal a collection you had to: build a keyring, call
``ensure()``, remember ``key_for(scope)`` before every new scope, construct
a *second* MongoClient with the right options, remember which of your two
clients was the encrypting one, set a ``key_scope`` field on every document
by hand, and pass a keyring plus a field list to ``unseal()`` at every read
site.

Seven things to remember, and the cost of forgetting the fourth one is a
plaintext write that raises nothing and is in a backup before anybody
notices. That is not an encryption feature, it is a trap with a key vault
attached.

So it is one line now:

    notes = engine.model("notes", tenant="tenant").sealed("text")

and the two halves that make it safe are both structural rather than
remembered:

  * the **scope is the tenant**, so there is no second field, no second
    lookup, and per-tenant erasure falls out of a declaration the model
    already made;
  * the **server rejects a plaintext write**, via a ``binData`` validator,
    so the writer that skips all of this -- a migration, a shell, another
    service -- fails loudly instead of silently succeeding.
"""

from __future__ import annotations

import pytest

from tests.conftest import TEST_MONGO_URI
from voyd.engine import UNRECOVERABLE, Engine, LocalFile
from voyd.engine.keyring import ENCRYPTED, available

_ok, _why = available()
pytestmark = pytest.mark.skipif(not _ok, reason=f"no automatic encryption: {_why}")

SECRET = "alice was treated for a stress fracture in March"
OTHER = "the fault code is P0301"


async def seeded(core, tmp_path, **kw):
    engine, db = core
    notes = engine.model("notes", tenant="tenant").sealed(
        "text", custody=LocalFile(path=tmp_path / "master.key"), **kw)
    await engine.ensure(search_wait_s=0)
    await notes.seal([{"tenant": "alice", "text": SECRET},
                      {"tenant": "bob", "text": OTHER}])
    return notes


# ---- the one line does the whole thing --------------------------------

async def test_declaring_sealed_encrypts_writes_and_decrypts_reads(
        core, tmp_path):
    """No second client, no manual key minting, no field to set by hand."""
    engine, db = core
    notes = await seeded(core, tmp_path)
    try:
        assert [d["text"] for d in await notes.find({"tenant": "alice"})] \
            == [SECRET]

        raw = await db.notes.find_one({"tenant": "alice"})
        assert raw["text"].subtype == ENCRYPTED
        assert SECRET.encode() not in bytes(raw["text"])
    finally:
        await engine.aclose()


async def test_the_scope_is_the_tenant_so_there_is_no_second_field(
        core, tmp_path):
    """The design decision the ergonomics rest on.

    A per-scope key needs a field naming the key, and a multi-tenant
    collection already has one. Tying them together means nothing to keep
    in step -- and per-tenant crypto erasure becomes a property of a
    declaration the model already made.
    """
    engine, db = core
    notes = await seeded(core, tmp_path)
    try:
        row = await db.notes.find_one({"tenant": "alice"})
        assert set(row) == {"_id", "tenant", "text"}, \
            "sealing must not add bookkeeping fields to the document"
        assert notes.sealing.scope_field == "tenant"
    finally:
        await engine.aclose()


async def test_shredding_a_tenant_leaves_every_other_tenant_alone(
        core, tmp_path):
    """And the erasure is counted as ``unrecoverable``, not as an error."""
    engine, db = core
    notes = await seeded(core, tmp_path)
    try:
        assert await notes.shred("alice") == 1

        assert await notes.find({"tenant": "alice"}) == []
        assert [d["text"] for d in await notes.find({"tenant": "bob"})] \
            == [OTHER]
        assert notes.receipts()["refused_by_reason"][UNRECOVERABLE] == 1

        assert await db.notes.count_documents({"tenant": "alice"}) == 1, \
            "the row survives; it is noise now, which is the claim"
    finally:
        await engine.aclose()


# ---- the half the server enforces --------------------------------------

async def test_a_plaintext_write_is_rejected_by_mongodb(core, tmp_path):
    """The failure that made the old ergonomics dangerous.

    A writer that does not go through the encrypting client -- a
    migration, a shell, a second service, this application holding the
    plain handle by accident -- used to succeed and store plaintext.
    Silent, permanent, and in a backup before anyone could notice.

    Now the collection carries a ``binData`` validator, so it is refused
    by the database rather than by a code review. Same move as
    ``Admission`` having no unfiltered ``find``, one layer down.
    """
    from pymongo.errors import WriteError

    engine, db = core
    await seeded(core, tmp_path)
    try:
        with pytest.raises(WriteError):
            await db.notes.insert_one({"tenant": "alice", "text": "plain"})
        assert await db.notes.count_documents({"text": "plain"}) == 0
    finally:
        await engine.aclose()


async def test_the_validator_is_applied_to_a_collection_that_already_exists(
        core, tmp_path):
    """First boot creates it; every boot after that modifies it. A
    ``collMod`` on a missing collection is an error and a first boot is
    exactly when it is missing, so both paths converge."""
    engine, db = core
    await db.create_collection("notes")
    await db.notes.insert_one({"tenant": "pre-existing", "other": 1})

    notes = engine.model("notes", tenant="tenant").sealed(
        "text", custody=LocalFile(path=tmp_path / "m.key"))
    await engine.ensure(search_wait_s=0)
    try:
        cursor = await db.list_collections(filter={"name": "notes"})
        info = await cursor.to_list(1)
        rule = info[0]["options"]["validator"]["$jsonSchema"]
        assert rule["properties"]["text"]["bsonType"] == "binData"

        await notes.seal({"tenant": "alice", "text": SECRET})
        assert [d["text"] for d in await notes.find({"tenant": "alice"})] \
            == [SECRET]
    finally:
        await engine.aclose()


# ---- it composes with everything else ----------------------------------

async def test_a_revoked_document_is_refused_before_anything_is_decrypted(
        core, tmp_path):
    """Sealing is something a collection *has*, so the refusal machinery
    keeps working -- and the ordering is the efficient one: a document
    refused by its mark never costs a key lookup, which matters because on
    a live scope the refusal rate is most of the page."""
    engine, db = core
    notes = await seeded(core, tmp_path)
    try:
        await notes.revoke({"tenant": "alice"}, reason="erasure request",
                           everything=True)
        assert await notes.find({"tenant": "alice"}) == []
        assert notes.receipts()["revoked_total"] == 1
        assert UNRECOVERABLE not in notes.receipts()["refused_by_reason"], \
            "the mark refused it, so no key was ever fetched"
    finally:
        await engine.aclose()


# ---- the declaration refuses to guess ----------------------------------

def test_sealing_without_a_scope_refuses_rather_than_defaulting(core):
    """Defaulting would put every document under one key, and then one
    erasure request erases everybody. There is no safe default here, so
    there is no default."""
    engine, _ = core
    with pytest.raises(ValueError, match="erases everybody"):
        engine.model("loose").sealed("text")


def test_sealing_no_fields_refuses(core):
    engine, _ = core
    with pytest.raises(ValueError, match="at least one field"):
        engine.model("notes", tenant="t").sealed()


def test_two_sealed_collections_share_one_vault(core):
    """A scope's key must not depend on which handle asked for it, so
    declaring a second sealed collection merges rather than replacing."""
    engine, _ = core
    engine.model("notes", tenant="t").sealed("text")
    engine.model("files", tenant="t").sealed("body")
    rings = engine._installed["keyring"]
    assert len(rings) == 1
    assert set(next(iter(rings.values())).spec.protect) == {"notes", "files"}


async def test_the_engine_closes_the_client_it_opened(core, tmp_path):
    """The keyring owning the writer is only a convenience if there is a
    way to put it down. A library that opens a connection you cannot close
    has traded one chore for a worse one."""
    engine, db = core
    notes = engine.model("notes", tenant="tenant").sealed(
        "text", custody=LocalFile(path=tmp_path / "m.key"))
    await engine.ensure(search_wait_s=0)
    await notes.seal({"tenant": "alice", "text": SECRET})

    ring = next(iter(engine._installed["keyring"].values()))
    assert ring._writer is not None
    await engine.aclose()
    assert ring._writer is None


async def test_the_keyring_dials_the_deployment_it_belongs_to(core):
    """Asking the caller for the URI a second time is a way to point them
    at two different deployments, and the failure would read as 'the keys
    are missing' rather than as a misconfiguration."""
    engine, _ = core
    ring = engine.keyring()
    host, port = TEST_MONGO_URI.split("//")[1].split("/")[0].split(":")
    assert f"{host}:{port}" in ring._uri


async def test_seal_mints_the_key_for_a_scope_it_has_not_seen(core, tmp_path):
    """Requiring ``key_for()`` first makes 'wrote a document, forgot the
    key' a reachable state. The driver's answer to that state is an
    exception on the write -- safe, and still a step a caller can only get
    wrong."""
    engine, db = core
    notes = await seeded(core, tmp_path)
    try:
        ring = notes.sealing.keyring
        assert await db[ring.collection].count_documents(
            {"keyAltNames": "carol"}) == 0

        await notes.seal({"tenant": "carol", "text": "a third tenant"})

        assert await db[ring.collection].count_documents(
            {"keyAltNames": "carol"}) == 1
        assert [d["text"] for d in await notes.find({"tenant": "carol"})] \
            == ["a third tenant"]
    finally:
        await engine.aclose()


async def test_sealing_a_document_with_no_scope_value_raises(core, tmp_path):
    from voyd.engine import ScopeRequired

    engine, _ = core
    notes = engine.model("notes", tenant="tenant").sealed(
        "text", custody=LocalFile(path=tmp_path / "m.key"))
    await engine.ensure(search_wait_s=0)
    try:
        with pytest.raises(ScopeRequired):
            await notes.seal({"text": "no tenant on this one"})
    finally:
        await engine.aclose()


async def test_seal_on_an_unsealed_collection_says_what_to_declare(core):
    """The error names the declaration, because the caller is one word
    away from the thing they wanted and should not have to go and read
    this module to find out which one."""
    from voyd.engine import UnknownReason

    engine, _ = core
    plain = engine.model("plain", tenant="t").forgettable()
    assert plain.seals is False

    with pytest.raises(UnknownReason, match=r"\.sealed\("):
        await plain.seal({"t": "a", "text": "x"})
    with pytest.raises(UnknownReason, match=r"\.sealed\("):
        await plain.shred("a")


async def test_survives_a_restart_when_custody_is_durable(core, tmp_path):
    """The rung most proofs of concept should be on, proven rather than
    documented: a second engine, a new keyring, the same key file, and
    yesterday's ciphertext still reads."""
    engine, db = core
    key = tmp_path / "durable.key"
    notes = engine.model("notes", tenant="tenant").sealed(
        "text", custody=LocalFile(path=key))
    await engine.ensure(search_wait_s=0)
    await notes.seal({"tenant": "alice", "text": SECRET})
    await engine.aclose()

    reborn = Engine(db.client, db)
    await reborn.connect()
    again = reborn.model("notes", tenant="tenant").sealed(
        "text", custody=LocalFile(path=key))
    await reborn.ensure(search_wait_s=0)
    try:
        assert [d["text"] for d in await again.find({"tenant": "alice"})] \
            == [SECRET]
    finally:
        await reborn.aclose()
