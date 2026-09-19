"""Refusal answers "may this reach a prompt". This answers "and the backups?"

That is the question a security reviewer asks four minutes in, and refusal
has nothing to say to it: refusal is a property of *this application's read
path*, and a restored snapshot does not run this application's read path. So
the plaintext being deliberately still on disk is proof to an engineer and a
**finding** to a reviewer, and the finding is correct.

Crypto-shredding closes it. A key per scope, sensitive fields as ciphertext
at rest, and destroying the key makes every copy unreadable at once -- the
row, the replica, the snapshot, the export somebody took in March -- without
any of them being visited.

These tests pin the three things that make it real rather than a slide:

  * the plaintext genuinely never reaches the disk, checked by reading the
    collection with a client that has no key;
  * destroying one scope's key erases that scope and **only** that scope,
    because the schema resolves the key through a JSON pointer rather than
    binding one key to the whole collection;
  * a destroyed key is a *refusal*, not an exception -- one crypto-erased
    document must not turn a page of fifty into a 500.

Skipped where the encryption stack is absent, and the skip names what is
missing, because "silently did not test the encryption" and "tested the
encryption" must not look the same in a CI log.
"""

from __future__ import annotations

import uuid

import pytest

from tests.conftest import TEST_MONGO_URI
from voyd.engine import (UNRECOVERABLE, Keyring, KeyringSpec, Sealed,
                         Unrecoverable)
from voyd.engine.keyring import ENCRYPTED, available

_ok, _why = available()
pytestmark = pytest.mark.skipif(not _ok, reason=f"no automatic encryption: {_why}")

SECRET = "alice was treated for a stress fracture in March"
OTHER = "the fault code is P0301"


async def sealed(core, *, collection="notes"):
    """A keyring, and a client that encrypts ``text`` on the way in."""
    from pymongo import AsyncMongoClient

    engine, db = core
    ring = Keyring(db, KeyringSpec(protect={collection: Sealed(("text",))}))
    await ring.ensure()
    await ring.key_for("scope-a")
    await ring.key_for("scope-b")
    writer = AsyncMongoClient(TEST_MONGO_URI,
                              auto_encryption_opts=await ring.client_options())
    return ring, writer[db.name][collection]


async def test_the_plaintext_never_reaches_the_disk(core):
    """Checked by reading with a client that holds no key, which is the
    only check that means anything -- asking the encrypting client whether
    it encrypted is asking the wrong process."""
    engine, db = core
    ring, writer = await sealed(core)
    try:
        await writer.insert_one({"key_scope": "scope-a", "text": SECRET})

        raw = await db.notes.find_one({"key_scope": "scope-a"})
        assert raw["text"].subtype == ENCRYPTED, \
            "a client with no key must see ciphertext, not text"
        assert SECRET.encode() not in bytes(raw["text"])

        back = await writer.find_one({"key_scope": "scope-a"})
        assert back["text"] == SECRET, "and the encrypting client reads it"
    finally:
        await writer.database.client.close()


async def test_destroying_a_key_erases_one_scope_and_only_one(core):
    """The reason ``keyId`` is a JSON pointer rather than a key id.

    A literal id in the schema binds one key to the whole collection, so a
    single erasure request would take out every other tenant. That is not a
    tradeoff, it is a different product.
    """
    from pymongo import AsyncMongoClient

    engine, db = core
    ring, writer = await sealed(core)
    try:
        await writer.insert_many([
            {"key_scope": "scope-a", "text": SECRET},
            {"key_scope": "scope-b", "text": OTHER},
        ])
        assert await ring.shred("scope-a") == 1

        # A cold client: the shredding process may still hold a cached key,
        # which is the measured caveat, not the guarantee.
        cold = AsyncMongoClient(TEST_MONGO_URI,
                                auto_encryption_opts=await ring.client_options())
        try:
            with pytest.raises(Exception):
                await cold[db.name].notes.find_one({"key_scope": "scope-a"})
            survived = await cold[db.name].notes.find_one(
                {"key_scope": "scope-b"})
            assert survived["text"] == OTHER, \
                "erasing one subject must not erase everybody else"
        finally:
            await cold.close()

        row = await db.notes.find_one({"key_scope": "scope-a"})
        assert row is not None and row["text"].subtype == ENCRYPTED, \
            "the row is still on disk -- and now it is noise, everywhere"
    finally:
        await writer.database.client.close()


async def test_an_unrecoverable_document_is_refused_not_an_exception(core):
    """One crypto-erased document must not 500 a page of fifty.

    Automatic *decryption* raises ``EncryptionError`` for the whole batch
    when any key is missing, and a crypto-erased document is a normal,
    expected state -- it is the feature working. So the read side is
    explicit, and a missing key is a refusal with a name beside the
    deadline and the revocation.
    """
    engine, db = core
    ring, writer = await sealed(core)
    try:
        await writer.insert_many([
            {"key_scope": "scope-a", "text": SECRET},
            {"key_scope": "scope-b", "text": OTHER},
        ])
        await ring.shred("scope-a")

        notes = engine.model("notes").forgettable()
        rows = [d async for d in db.notes.find({})]
        ce = await ring.encryption()
        try:
            page = await notes.unseal(rows, fields=("text",), keyring=ring,
                                      encryption=ce)
        finally:
            await ce.close()

        assert [d["text"] for d in page] == [OTHER]
        assert page.refused == {UNRECOVERABLE: 1}
        assert notes.receipts()["refused_by_reason"][UNRECOVERABLE] == 1
    finally:
        await writer.database.client.close()


async def test_the_key_carries_the_same_deadline_the_documents_do(core):
    """One owner, applied to the thing that enforces the guarantee.

    The key vault is an ordinary collection, so the key expires by the same
    TTL index as everything else -- no second scheduler, no cron keeping two
    clocks in agreement. And a key's deadline moves earlier or not at all,
    for the reason a document's does: renewing a key extends the
    readability of everything it protects.
    """
    from datetime import timedelta

    from voyd.engine import now

    engine, db = core
    ring = Keyring(db, KeyringSpec(collection=f"k_{uuid.uuid4().hex[:6]}"))
    await ring.ensure()

    indexes = await (await db[ring.collection].list_indexes()).to_list(None)
    ttl = [i for i in indexes if i.get("expireAfterSeconds") == 0]
    assert ttl, "the key must expire by the same mechanism as the documents"

    soon, late = now() + timedelta(hours=1), now() + timedelta(days=30)
    key_id = await ring.key_for("scope-a", expire_at=late)
    await ring.key_for("scope-a", expire_at=soon)
    kept = (await db[ring.collection].find_one({"_id": key_id}))["expire_at"]
    assert kept < now() + timedelta(days=1), "the earlier deadline wins"

    await ring.key_for("scope-a", expire_at=late)
    again = (await db[ring.collection].find_one({"_id": key_id}))["expire_at"]
    assert again == kept, "a key's deadline never moves later"


def test_the_rule_catches_ciphertext_that_reached_a_read_path_unsealed():
    """A safety net, not the mechanism. A sealed document arriving at a
    path that never called ``unseal()`` must be a refusal with a name,
    rather than a ``Binary`` serialised into a prompt as if it were text."""
    from bson.binary import Binary

    from voyd.engine import why_refused
    from voyd.engine.admission import AdmissionSpec

    spec = AdmissionSpec("notes", rules=(Unrecoverable("text"),))
    blob = Binary(b"not really ciphertext", ENCRYPTED)
    assert why_refused({"text": blob}, spec) == UNRECOVERABLE
    assert why_refused({"text": "ordinary"}, spec) is None


def test_the_capability_probe_says_why_when_it_says_no():
    """``capabilities.py``'s rule, applied here: ask, report, never pretend.

    A deployment that silently skipped encryption would look exactly like
    one that had it, which is the failure mode this package is named after.
    """
    ok, why = available()
    assert isinstance(ok, bool) and why
    if not ok:
        assert "pymongocrypt" in why or "crypt_shared" in why


# ---- rotation: the half that makes destruction credible ---------------

async def test_rotating_the_master_key_leaves_every_document_readable(core):
    """A key that cannot be re-wrapped is a key that gets copied instead.

    And a copied key cannot be destroyed, so "we shredded it" quietly stops
    being true without anybody doing anything wrong. Rotation re-encrypts
    the *data keys* under a new master -- the DEK itself does not change,
    so not one document is rewritten and everything stays readable. That
    asymmetry is why rotating a CMK is cheap and re-encrypting a collection
    is not.
    """
    from pymongo import AsyncMongoClient

    from voyd.engine import Ephemeral

    engine, db = core
    ring, writer = await sealed(core)
    try:
        await writer.insert_one({"key_scope": "scope-a", "text": SECRET})
        wrapped_before = (await db[ring.collection].find_one(
            {"keyAltNames": "scope-a"}))["keyMaterial"]

        assert await ring.rotate() >= 1

        after = await db[ring.collection].find_one({"keyAltNames": "scope-a"})
        assert after["keyMaterial"] != wrapped_before, \
            "the data key must be wrapped by something new"

        cold = AsyncMongoClient(
            TEST_MONGO_URI, auto_encryption_opts=await ring.client_options())
        try:
            back = await cold[db.name].notes.find_one({"key_scope": "scope-a"})
            assert back["text"] == SECRET, \
                "rotation must not cost a single document its readability"
        finally:
            await cold.close()

        # And a rotation cannot quietly downgrade custody: rewrapping under
        # a *different* master is an explicit argument, not a default.
        assert await ring.rotate(scope="scope-a", custody=Ephemeral()) == 1
    finally:
        await writer.database.client.close()


async def test_a_keyring_refuses_two_answers_about_who_holds_the_key(core):
    """``custody=`` and ``kms_providers=`` together is the one question
    that must have exactly one answer, so it raises rather than picking."""
    from voyd.engine import Ephemeral

    engine, db = core
    with pytest.raises(ValueError, match="not both"):
        Keyring(db, custody=Ephemeral(), kms_providers={"local": {"key": b""}})


async def test_a_raw_provider_dict_reports_unknown_custody_not_safe_custody(
        core, caplog):
    """Supported, because the driver's vocabulary is the real interface --
    and reported as unknown rather than assumed, because a dict cannot say
    whether the key behind it is in an HSM or in a variable two frames up.
    """
    import logging
    import os

    engine, db = core
    ring = Keyring(db, kms_providers={"local": {"key": os.urandom(96)}})
    assert ring.describe()["custody"]["audited"] is False
    with caplog.at_level(logging.WARNING):
        ring.custody.warn_if_weak("keyring x")
    assert "cannot report where the master key lives" in caplog.text
