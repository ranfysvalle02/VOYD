"""Queryable Encryption buys a searchable ciphertext and sells per-subject erasure.

Two protection modes, and choosing between them is a real engineering
decision rather than a preference -- so the decision is pinned here, with
the constraint that forces it measured against a live server rather than
recalled from a doc page.

``Sealed`` (CSFLE) resolves ``keyId`` through a **JSON pointer**, so the
driver picks a different key per document. That is what makes per-scope
shredding possible: erase one subject and nobody else's key is touched. The
price is that the field cannot be queried, which costs nothing in this
package -- retrieval matches on the embedding, and the embedding is not the
sensitive field.

``Queryable`` indexes the ciphertext, so equality (7.0+) and range (8.0+)
work against it. The price is structural and is the point of this file: QE
**rejects a pointer keyId**, so one key covers one field across the whole
collection. Shredding it erases that field for everybody.

Wanting both means a collection per subject, which is a sharding decision
wearing an encryption costume.
"""

from __future__ import annotations

import uuid

import pytest

from tests.conftest import TEST_MONGO_URI
from voyd.engine import Keyring, KeyringSpec, Queryable, Sealed
from voyd.engine.keyring import ENCRYPTED, available

_ok, _why = available()
pytestmark = pytest.mark.skipif(not _ok, reason=f"no automatic encryption: {_why}")

SSN = "123-45-6789"
OTHER = "999-99-9999"


async def qe_ring(db, collection="people"):
    from pymongo import AsyncMongoClient

    ring = Keyring(db, KeyringSpec(
        collection=f"k_{uuid.uuid4().hex[:6]}",
        protect={collection: Queryable(("ssn",), query_type="equality")}))
    await ring.ensure()
    client = AsyncMongoClient(TEST_MONGO_URI,
                              auto_encryption_opts=await ring.client_options())
    return ring, client


async def test_the_ciphertext_itself_is_queryable(core):
    """The thing ``Sealed`` cannot do, and the only reason to pay QE's price."""
    engine, db = core
    ring, client = await qe_ring(db)
    try:
        await ring.create_queryable(client, "people")
        await client[db.name].people.insert_many([
            {"name": "alice", "ssn": SSN}, {"name": "bob", "ssn": OTHER}])

        hit = await client[db.name].people.find_one({"ssn": SSN})
        assert hit["name"] == "alice", "equality against ciphertext"

        raw = await db.people.find_one({"name": "alice"})
        assert raw["ssn"].subtype == ENCRYPTED
        assert SSN.encode() not in bytes(raw["ssn"])
    finally:
        await client.close()


async def test_queryable_encryption_needs_its_metadata_collections(core):
    """A QE namespace cannot be created by inserting into it, and the
    failure is the dangerous kind: writing to one that was never created
    this way does not raise, it writes plaintext."""
    engine, db = core
    ring, client = await qe_ring(db)
    try:
        await ring.create_queryable(client, "people")
        names = await db.list_collection_names()
        assert {"enxcol_.people.esc", "enxcol_.people.ecoc"} <= set(names)
    finally:
        await client.close()


async def test_creating_an_undeclared_collection_as_queryable_raises(core):
    engine, db = core
    ring, client = await qe_ring(db)
    try:
        with pytest.raises(ValueError, match="not declared Queryable"):
            await ring.create_queryable(client, "somewhere_else")
    finally:
        await client.close()


async def test_a_queryable_key_is_per_field_not_per_scope(core):
    """The measured constraint, asserted rather than trusted.

    QE rejects ``keyId`` as a string pointer -- *BSON field
    'create.encryptedFields.fields.keyId' is the wrong type 'string'* -- so
    the map this keyring produces must carry real key ids, one per field,
    fixed at collection creation.
    """
    engine, db = core
    ring, client = await qe_ring(db)
    try:
        fields = await ring.encrypted_fields_map()
        spec = fields[f"{db.name}.people"]["fields"][0]
        assert not isinstance(spec["keyId"], str), \
            "QE cannot take a pointer; a string here would fail at create"
        assert spec["queries"] == {"queryType": "equality"}

        # And the key is named for the field, so an operator asked to
        # destroy `people.ssn` does not have to work out which UUID it is.
        named = await db[ring.collection].find_one(
            {"keyAltNames": "people.ssn"})
        assert named is not None and named["_id"] == spec["keyId"]
    finally:
        await client.close()


async def test_shredding_a_queryable_key_takes_the_whole_collection(core):
    """The cost, demonstrated rather than asserted in prose.

    This is the test that would tempt somebody to "fix" QE into per-subject
    erasure. It cannot be fixed; it is what the mode is. Erasing alice here
    also erases bob, which is why ``Sealed`` is the default and why
    ``describe()`` reports the granularity out loud.
    """
    from pymongo import AsyncMongoClient

    engine, db = core
    ring, client = await qe_ring(db)
    cold = None
    try:
        await ring.create_queryable(client, "people")
        await client[db.name].people.insert_many([
            {"name": "alice", "ssn": SSN}, {"name": "bob", "ssn": OTHER}])

        assert await ring.shred("people.ssn") == 1

        cold = AsyncMongoClient(
            TEST_MONGO_URI,
            auto_encryption_opts=await ring.client_options())
        for who in ("alice", "bob"):
            with pytest.raises(Exception):
                await cold[db.name].people.find_one({"name": who})
    finally:
        await client.close()
        if cold is not None:
            await cold.close()


def test_the_two_modes_report_their_granularity(core):
    """Said out loud in ``describe()``, because this is the tradeoff people
    make once and misremember forever."""
    engine, db = core
    both = Keyring(db, KeyringSpec(protect={
        "notes": Sealed(("text",)),
        "people": Queryable(("ssn",)),
    }))
    described = both.describe()
    assert described["shred_granularity"] == {"sealed": "scope",
                                              "queryable": "collection"}
    assert described["sealed"] == {"notes": ["text"]}
    assert described["queryable"] == {"people": ["ssn"]}
    assert described["custody"]["audited"] is False


async def test_a_keyring_can_hold_both_modes_at_once(core):
    """They are not alternatives at the deployment level -- one collection
    needs a searchable ciphertext and another needs per-subject erasure, and
    both schemas go to the same client."""
    engine, db = core
    ring = Keyring(db, KeyringSpec(
        collection=f"k_{uuid.uuid4().hex[:6]}",
        protect={"notes": Sealed(("text",)), "people": Queryable(("ssn",))}))
    await ring.ensure()
    opts = await ring.client_options()

    assert f"{db.name}.notes" in opts._schema_map
    assert f"{db.name}.people" in opts._encrypted_fields_map
    assert opts._schema_map[f"{db.name}.notes"]["properties"]["text"][
        "encrypt"]["keyId"] == "/key_scope"
