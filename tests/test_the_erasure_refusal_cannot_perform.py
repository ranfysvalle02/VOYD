"""Destroying the key, which is the one claim refusal cannot make.

Refusal binds *this* read path, so it has nothing to say about a replica, a
snapshot, or the backup somebody restores next year -- none of those run it.
That gap is the whole reason `sealed()` and `--key-vault` exist, and it is
the strongest claim in the README: destroy a key and every copy of the
ciphertext becomes unreadable at once, without visiting any of them.

A claim that strong is worth testing as three separate statements, because
they fail in different places and only the middle one is about cryptography:

    custody      *who* holds the master key, and whether this deployment is
                 honest about how weak that answer is
    the keyring  a key per scope, minted on first use, with a deadline that
                 may move earlier and never later
    the shred    the ciphertext on disk is noise afterwards, and the *other*
                 scopes are untouched -- one key per collection would take
                 every other tenant with the subject who asked to be
                 forgotten

The live half needs `pymongocrypt` and either `crypt_shared` or
`mongocryptd`, neither of which is on PyPI. `available()` is asked rather
than assumed, and the tests skip by name when the answer is no -- because a
suite that silently passed without encryption would be testing nothing while
reporting on the feature that matters most.
"""

from __future__ import annotations

import base64
import os
from datetime import datetime, timedelta, timezone

import pytest

from voyd.engine.custody import (LOCAL_KEY_BYTES, Aws, Azure, Ephemeral, Gcp,
                                 Kmip, LocalFile, from_env)
from voyd.engine.keyring import (KeyringSpec, Queryable, Sealed,
                                 available)

UTC = timezone.utc


# ---- who holds the master key -----------------------------------------

def test_the_default_rung_is_the_weakest_one_and_says_so():
    # A default that quietly worked in production would be worse than one
    # that visibly does not.
    custody = Ephemeral()
    assert custody.provider == "local"
    assert custody.durable is False and custody.audited is False
    assert len(custody.credentials()["key"]) == LOCAL_KEY_BYTES
    assert custody.master_key() is None
    assert "memory" in custody.detail()


def test_two_ephemeral_keys_are_two_keys():
    # Regenerated per process is the documented weakness; a shared
    # constant would make it a fake.
    assert Ephemeral().credentials()["key"] != Ephemeral().credentials()["key"]


def test_a_weak_rung_warns_and_a_strong_one_does_not(caplog):
    import logging

    with caplog.at_level(logging.WARNING):
        Ephemeral().warn_if_weak("test")
    assert "regenerated on restart" in caplog.text

    caplog.clear()
    with caplog.at_level(logging.WARNING):
        Aws(key="arn:aws:kms:us-east-1:1:key/abc",
            region="us-east-1").warn_if_weak("test")
    # Durable and audited: nothing to say.
    assert caplog.text == ""


def test_a_durable_but_unaudited_rung_says_which_half_it_has(caplog, tmp_path):
    import logging

    with caplog.at_level(logging.WARNING):
        LocalFile(path=tmp_path / "master.key").warn_if_weak("test")
    # The mechanism is real; custody is a file permission, so "the key was
    # destroyed" is your word for it.
    assert "your word for it" in caplog.text


def test_a_local_key_file_is_created_once_and_read_back_exactly(tmp_path):
    path = tmp_path / "master.key"
    custody = LocalFile(path=path)
    first = custody.credentials()["key"]
    assert len(first) == LOCAL_KEY_BYTES
    assert path.stat().st_mode & 0o777 == 0o600
    # Read back, not regenerated -- the difference between a durable rung
    # and an ephemeral one pretending to be durable.
    assert LocalFile(path=path).credentials()["key"] == first


def test_a_key_file_is_never_stripped_before_it_is_read(tmp_path):
    # ~4.8% of 96-byte keys begin or end with a byte `strip()` treats as
    # whitespace. Stripping first makes one file in twenty read back short,
    # which presents as a deployment that can no longer decrypt anything
    # it wrote, intermittently, with no cause at the point of failure.
    material = b"\n" + os.urandom(LOCAL_KEY_BYTES - 2) + b"\t"
    assert len(material) == LOCAL_KEY_BYTES
    path = tmp_path / "whitespacey.key"
    path.write_bytes(material)
    assert LocalFile(path=path).credentials()["key"] == material


def test_a_key_that_has_been_through_a_shell_arrives_base64(tmp_path):
    material = os.urandom(LOCAL_KEY_BYTES)
    path = tmp_path / "encoded.key"
    # The whitespace around base64 is punctuation, not key material.
    path.write_bytes(b"  " + base64.b64encode(material) + b"\n")
    assert LocalFile(path=path).credentials()["key"] == material


def test_a_key_file_of_the_wrong_size_refuses_to_be_guessed_at(tmp_path):
    # A wrong key is not an error, it is every document becoming
    # unreadable -- so this fails loudly at startup instead.
    path = tmp_path / "short.key"
    path.write_bytes(b"not ninety six bytes")
    with pytest.raises(ValueError, match="Refusing to guess"):
        LocalFile(path=path).credentials()


def test_a_kms_rung_is_durable_audited_and_carries_its_own_master_key():
    aws = Aws(key="arn:aws:kms:eu-west-1:123:key/abc", region="eu-west-1")
    assert aws.provider == "aws" and aws.durable and aws.audited
    assert aws.master_key()["key"] == "arn:aws:kms:eu-west-1:123:key/abc"
    assert "aws" in aws.providers()
    for rung in (Azure(key_name="k", key_vault_endpoint="v", tenant_id="t",
                       client_id="c", client_secret="s"),
                 Gcp(project_id="p", location="l", key_ring="r", key_name="k"),
                 Kmip(endpoint="host:5696")):
        assert rung.durable and rung.audited, rung
        assert rung.providers()


def test_the_region_is_taken_from_the_arn_so_the_two_cannot_disagree():
    aws = Aws(key="arn:aws:kms:ap-south-1:123:key/abc")
    assert aws.master_key()["region"] == "ap-south-1"


def test_an_unset_environment_is_a_demo_and_never_claims_to_be_audited(
        monkeypatch):
    for name in list(os.environ):
        if name.startswith("VOYDTEST_"):
            monkeypatch.delenv(name)
    custody = from_env("VOYDTEST")
    assert isinstance(custody, Ephemeral)
    assert not custody.audited and not custody.durable


def test_the_environment_selects_the_rung_it_names(monkeypatch, tmp_path):
    monkeypatch.setenv("VOYDTEST_PROVIDER", "aws")
    monkeypatch.setenv("VOYDTEST_KEY", "arn:aws:kms:eu-west-1:1:key/a")
    monkeypatch.setenv("VOYDTEST_REGION", "eu-west-1")
    assert isinstance(from_env("VOYDTEST"), Aws)

    monkeypatch.setenv("VOYDTEST_PROVIDER", "local")
    monkeypatch.setenv("VOYDTEST_KEY_PATH", str(tmp_path / "m.key"))
    assert isinstance(from_env("VOYDTEST"), LocalFile)
    # `local` with no path is still a demo, not a silent file somewhere.
    monkeypatch.delenv("VOYDTEST_KEY_PATH")
    assert isinstance(from_env("VOYDTEST"), Ephemeral)


# ---- the keyring's own declarations ------------------------------------

def test_the_key_is_resolved_per_document_and_not_per_collection():
    # `pointer_field` is what makes the driver resolve a *different* key
    # per document. A static keyId would give one key per collection,
    # which makes shredding all-or-nothing: erase one subject and every
    # other tenant goes with them.
    spec = KeyringSpec()
    assert spec.pointer_field and spec.collection and spec.at_field


def test_the_two_encryption_modes_differ_in_what_a_shred_reaches():
    # Sealed erases one subject; Queryable erases a field for everybody,
    # because QE rejects a pointer keyId. Chosen deliberately or not at
    # all, so the difference is declared rather than discovered.
    assert Sealed().shred_granularity == "scope"
    assert Sealed().queryable is False
    assert Queryable(fields=("email",)).shred_granularity == "collection"
    assert Queryable(fields=("email",)).queryable is True


def test_a_spec_sorts_its_collections_by_how_they_are_protected():
    spec = KeyringSpec(protect={"notes": Sealed(fields=("text",)),
                                "people": Queryable(fields=("email",))})
    assert set(spec.sealed_collections()) == {"notes"}
    assert set(spec.queryable_collections()) == {"people"}


def test_this_deployment_says_which_half_of_encryption_it_is_missing():
    # Asked, reported, never pretended: a deployment that silently skipped
    # encryption would look exactly like one that had it.
    ok, why = available()
    assert isinstance(ok, bool) and isinstance(why, str) and why
    if not ok:
        assert "pymongocrypt" in why or "crypt_shared" in why


# ---- destroying a key, against a real deployment -----------------------

crypto = pytest.mark.skipif(not available()[0],
                            reason=f"automatic encryption: {available()[1]}")


@pytest.fixture
async def keyring(direct, database):
    """A real key vault, in the throwaway database rather than beside it.

    The conventional home is `encryption.__keyVault`, which is the one
    thing here that would survive the `drop_database` every other fixture
    relies on -- so the vault is named *inside* the database under test
    and goes with it.

    An async fixture because `AsyncMongoClient` binds to the event loop it
    was created on, and a client built on the fixture's loop and used on
    the test's is a `RuntimeError` that reads like a driver bug.
    """
    from pymongo import AsyncMongoClient

    from voyd.engine.keyring import Keyring

    host, port = direct.address
    made = []

    async def build(custody=None):
        client = AsyncMongoClient(
            f"mongodb://{host}:{port}/?directConnection=true")
        made.append(client)
        ring = Keyring(client[database], KeyringSpec(collection="__keys"),
                       custody=custody or Ephemeral())
        await ring.ensure()
        return ring

    try:
        yield build
    finally:
        for client in made:
            await client.close()


@crypto
@pytest.mark.needs_mongo
async def test_a_key_is_minted_once_per_scope_and_reused(keyring, direct,
                                                         database):
    ring = await keyring()
    first = await ring.key_for("alice")
    again = await ring.key_for("alice")
    assert first == again, "a second key for one scope splits the erasure"
    bob = await ring.key_for("bob")
    assert bob != first, "one key for two tenants is all-or-nothing erasure"
    assert direct[database]["__keys"].count_documents({}) == 2


@crypto
@pytest.mark.needs_mongo
async def test_a_keys_deadline_moves_earlier_and_never_later(keyring, direct,
                                                             database):
    # The same invariant `revoke()` holds for a document, and for the same
    # reason: extending a key's life extends the readability of everything
    # it protects. "We renewed the key so the erasure took a week longer"
    # is not a sentence anybody wants to write down.
    ring = await keyring()
    soon = datetime.now(UTC) + timedelta(hours=1)
    later = datetime.now(UTC) + timedelta(days=30)
    sooner = datetime.now(UTC) + timedelta(minutes=5)

    key_id = await ring.key_for("alice", expire_at=later)
    await ring.key_for("alice", expire_at=soon)
    doc = direct[database]["__keys"].find_one({"_id": key_id})
    assert doc[ring.spec.at_field].replace(tzinfo=UTC) <= soon

    await ring.key_for("alice", expire_at=later)
    doc = direct[database]["__keys"].find_one({"_id": key_id})
    assert doc[ring.spec.at_field].replace(tzinfo=UTC) <= soon, \
        "a key's deadline was extended"

    await ring.key_for("alice", expire_at=sooner)
    doc = direct[database]["__keys"].find_one({"_id": key_id})
    assert doc[ring.spec.at_field].replace(tzinfo=UTC) <= sooner


@crypto
@pytest.mark.needs_mongo
async def test_shredding_a_scope_leaves_the_ciphertext_and_takes_the_key(
        keyring, direct, database):
    ring = await keyring()
    await ring.key_for("alice")
    await ring.key_for("bob")

    assert await ring.shred("alice") == 1
    assert direct[database]["__keys"].count_documents(
        {"keyAltNames": "alice"}) == 0
    # The other scope is untouched, which is the entire argument for a key
    # per tenant rather than one per collection.
    assert direct[database]["__keys"].count_documents(
        {"keyAltNames": "bob"}) == 1
    # Shredding what is already gone is a normal answer, not an error: an
    # erasure request that arrives twice must not fail the second time.
    assert await ring.shred("alice") == 0
    assert await ring.shred("nobody-by-that-name") == 0


@crypto
@pytest.mark.needs_mongo
async def test_the_bytes_on_disk_are_noise_once_the_key_is_destroyed(
        keyring, direct, database):
    """The claim refusal cannot make, made against real bytes.

    What a DBA, a replica and a backup all are, is a reader without this
    process's read path. So the assertion is made on the stored document
    read *around* every boundary: the plaintext is not in it, and after the
    shred there is no key anywhere that could recover it.
    """
    secret = "the diagnosis is in this sentence"
    ring = await keyring()
    key_id = await ring.key_for("alice")

    encryption, owned = await ring._encryption()
    try:
        from voyd.engine.keyring import RANDOM

        sealed = await encryption.encrypt(secret, RANDOM, key_id=key_id)
        direct[database].notes.insert_one({"tenant_id": "alice",
                                           "text": sealed})

        on_disk = direct[database].notes.find_one({"tenant_id": "alice"})
        assert on_disk["text"].subtype == 6, "not stored as ciphertext"
        assert secret.encode() not in bytes(on_disk["text"])
        # With the key, it comes back.
        assert await encryption.decrypt(on_disk["text"]) == secret

        assert await ring.shred("alice") == 1
    finally:
        if owned:
            await encryption.aclose() if hasattr(encryption, "aclose") \
                else await encryption.close()

    # A reader that never had the key cached -- which is what a restored
    # backup is -- cannot produce the plaintext at all. Named precisely,
    # because `raises(Exception)` here would pass just as happily on a
    # closed socket, and this is the assertion the whole feature rests on.
    from pymongo.errors import EncryptionError

    fresh, owned = await ring._encryption()
    try:
        with pytest.raises(EncryptionError) as refused:
            await fresh.decrypt(on_disk["text"])
        assert "keys requested were satisfied" in str(refused.value), (
            f"decryption failed for some other reason: {refused.value}")
    finally:
        if owned:
            await fresh.aclose() if hasattr(fresh, "aclose") \
                else await fresh.close()

    # And the ciphertext is still sitting there, which is the point: no
    # backup had to be visited for it to stop being readable.
    assert direct[database].notes.count_documents({"tenant_id": "alice"}) == 1
