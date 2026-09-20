"""Custody, proven against a key server this process does not control.

For a long time this was the project's one honestly-unmet standard. Every
other claim here is checked against real infrastructure -- the suite runs
against real `mongot` rather than a mock, because these properties are only
true if the *queries* are right -- and the custody ladder's external rungs
were unit-tested shapes. "Constructs the right `master_key` document" and
"works against a key server" are different claims, and only the first was
proven.

The gap was carried on a wrong assumption: that closing it needed a cloud
account and CI secrets. **Enterprise custody is not a synonym for one
vendor's managed service.** KMIP is the open standard the category actually
runs on -- Thales, Fortanix, Entrust, HSM appliances -- and a large share of
deployments choose it *because* they will not put keys in a public cloud.
It is also runnable: a conformant server starts in a subprocess in eight
seconds.

So this is not a mock and not a shape check. A real server, over TLS, holds
a key this process cannot produce, and every claim the ladder makes about
an external rung is exercised against it:

  * the data key is **wrapped by a key held elsewhere**, and the stored
    document names that provider;
  * rotation re-wraps under the same external master without rewriting a
    document -- previously untested against anything that could refuse;
  * shredding makes the ciphertext unreadable, and a cold client agrees.
"""

from __future__ import annotations

import uuid

import pytest

pytest.importorskip("kmip", reason="pykmip is not installed")
pytest.importorskip("pymongocrypt", reason="the crypto extra is not installed")

from tests.support import kmip as kmip_server  # noqa: E402
from voyd.engine import Kmip  # noqa: E402
from voyd.engine.keyring import Keyring, KeyringSpec, Sealed  # noqa: E402

SECRET = "alice was treated for a stress fracture in March"


@pytest.fixture(scope="session")
def kms(tmp_path_factory):
    """One server for the session. Real TLS, real key storage, real refusals."""
    into = tmp_path_factory.mktemp("kmip")
    proc, endpoint, tls = kmip_server.start(into)
    try:
        yield Kmip(endpoint=endpoint, tls=tls)
    finally:
        proc.terminate()
        proc.wait(timeout=10)


async def ring_on(core, kms, **kw):
    engine, db = core
    ring = Keyring(db, KeyringSpec(collection=f"k_{uuid.uuid4().hex[:6]}",
                                   protect={"notes": Sealed(("text",))}),
                   custody=kms, **kw)
    await ring.ensure()
    return ring


# ---- the key is somewhere else ----------------------------------------

async def test_the_data_key_is_wrapped_by_a_key_this_process_does_not_hold(
        core, kms):
    """The difference between demonstration-grade and audited custody, and
    the thing a unit test cannot show: the wrapping key lives on a server,
    and the stored document says so."""
    engine, db = core
    ring = await ring_on(core, kms)

    key_id = await ring.key_for("alice")
    stored = await db[ring.collection].find_one({"keyAltNames": "alice"})

    assert stored["_id"] == key_id
    assert stored["masterKey"]["provider"] == "kmip", \
        "the master key must be recorded as external, not local"
    assert stored["masterKey"].get("keyId"), \
        "and it must name the key the server generated"
    assert ring.custody.audited is True and ring.custody.durable is True


async def test_a_round_trip_through_the_external_master(core, kms):
    engine, db = core
    ring = await ring_on(core, kms)
    key_id = await ring.key_for("alice")

    encryption = await ring.encryption()
    try:
        from pymongo.encryption import Algorithm
        sealed = await encryption.encrypt(SECRET, Algorithm.UNINDEXED,
                                          key_id=key_id)
        assert sealed.subtype == 6
        assert SECRET.encode() not in bytes(sealed)
        assert await encryption.decrypt(sealed) == SECRET
    finally:
        await encryption.close()


# ---- the operations that were only ever shapes ------------------------

async def test_rotation_re_wraps_under_the_external_master(core, kms):
    """`rewrap_many_data_key` had never run against anything that could
    say no. A key that cannot be re-wrapped is one that gets copied
    instead, and a copied key cannot be destroyed -- so "we shredded it"
    stops being true with nobody doing anything wrong."""
    engine, db = core
    ring = await ring_on(core, kms)
    key_id = await ring.key_for("alice")
    before = (await db[ring.collection].find_one({"_id": key_id}))["keyMaterial"]

    assert await ring.rotate() >= 1

    after = await db[ring.collection].find_one({"_id": key_id})
    assert after["keyMaterial"] != before, "the wrapping must be new"
    assert after["masterKey"]["provider"] == "kmip"


async def test_shredding_against_a_real_server(core, kms):
    """The claim the whole ladder exists for, with the master key held by
    something that is not this process."""
    engine, db = core
    ring = await ring_on(core, kms)
    key_id = await ring.key_for("alice")

    encryption = await ring.encryption()
    try:
        from pymongo.encryption import Algorithm
        sealed = await encryption.encrypt(SECRET, Algorithm.UNINDEXED,
                                          key_id=key_id)
    finally:
        await encryption.close()

    assert await ring.shred("alice") == 1

    cold = await ring.encryption()
    try:
        with pytest.raises(Exception):
            await cold.decrypt(sealed)
    finally:
        await cold.close()


async def test_shredding_one_scope_leaves_its_neighbour_readable(core, kms):
    engine, db = core
    ring = await ring_on(core, kms)
    mine = await ring.key_for("alice")
    theirs = await ring.key_for("bob")

    encryption = await ring.encryption()
    try:
        from pymongo.encryption import Algorithm
        a = await encryption.encrypt(SECRET, Algorithm.UNINDEXED, key_id=mine)
        b = await encryption.encrypt("the fault code is P0301",
                                     Algorithm.UNINDEXED, key_id=theirs)
    finally:
        await encryption.close()

    await ring.shred("alice")

    cold = await ring.encryption()
    try:
        with pytest.raises(Exception):
            await cold.decrypt(a)
        assert await cold.decrypt(b) == "the fault code is P0301"
    finally:
        await cold.close()


# ---- and the ladder reports itself honestly ---------------------------

def test_an_external_rung_does_not_warn_about_custody(kms, caplog):
    """`Ephemeral` and `LocalFile` warn because their custody is this
    process or a file permission. A KMS rung has nothing to apologise
    for, and saying so is how the warning stays worth reading."""
    import logging

    with caplog.at_level(logging.WARNING):
        kms.warn_if_weak("keyring test.__keys")
    assert caplog.text == ""


def test_the_tls_options_reach_the_driver(kms):
    """A KMIP appliance without mutual TLS is a key server on the open
    network. The options have to survive the trip from custody to the
    driver, and nothing checked that they did."""
    assert kms.tls_options()["kmip"]["tlsCAFile"].endswith("ca.pem")
    assert kms.providers()["kmip"]["endpoint"] == kms.endpoint
