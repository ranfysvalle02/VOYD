"""Automatic encryption: 1,177 lines that survived the trim with no tests.

Refusal answers *may this fact reach a prompt* on this read path. It does not
answer *and your backups?* -- a restored snapshot does not run it, and neither
does a DBA with a shell. `keyring.py` is the answer to that one: a key per
scope, ciphertext at rest, and the scope's deadline destroying the key so
every copy becomes unreadable at once.

That is the strongest claim in this repository and it was, until this file,
entirely unverified. Four things have to be true or the claim is worse than
absent:

1. what is on disk is not the plaintext -- checked by reading the raw bytes,
   not by trusting the driver;
2. the handle still returns a string, or the encryption is a bug;
3. destroying the key makes it unreadable, and that shows up as a *refusal
   with a name* rather than an exception or an empty page;
4. shredding one tenant does not touch another, which is the only reason
   per-subject erasure is meaningful.

Skips cleanly without the encryption stack, and says which half is missing --
`crypt_shared`/`mongocryptd` is an Enterprise download and not on PyPI.
"""

from __future__ import annotations

import uuid

import pytest

from voyd.engine.keyring import available

from .conftest import MONGO_URI

pymongo = pytest.importorskip("pymongo")

_ok, _why = available()
pytestmark = pytest.mark.skipif(not _ok, reason=f"no encryption stack: {_why}")

SECRET = "alice was treated for a stress fracture in March"
KEPT = "the fault code is P0301"


@pytest.fixture
async def sealed():
    """A sealed, tenant-scoped collection with two patients' rows."""
    from pymongo import AsyncMongoClient

    from voyd.engine import Deadline, revoked
    from voyd.engine.admission import Admission, AdmissionSpec
    from voyd.engine.custody import Ephemeral
    from voyd.engine.keyring import Keyring, KeyringSpec, Sealed, Sealing

    client = AsyncMongoClient(MONGO_URI)
    name = f"voyd_test_seal_{uuid.uuid4().hex[:8]}"
    db = client[name]
    try:
        # Sealing is a keyring, a spec, and a trait on the admission
        # handle. Assembled here rather than behind a helper so the three
        # pieces the guarantee rests on are visible in the test that
        # asserts it.
        keyring = Keyring(db, KeyringSpec(
            pointer_field="patient",
            protect={"notes": Sealed(("text",))}),
            custody=Ephemeral(), uri=MONGO_URI)
        await keyring.ensure()
        notes = Admission(db, AdmissionSpec(
            "notes", tenant="patient",
            rules=(Deadline(), revoked())).with_defaults()).sealed_by(
                Sealing(keyring, ("text",), "patient"))
        await notes.seal([{"patient": "alice", "text": SECRET},
                          {"patient": "bob", "text": KEPT}])
        yield db, notes
    finally:
        await client.drop_database(name)
        await client.close()


async def test_the_plaintext_is_not_on_disk(sealed):
    """Read the way a DBA, a replica and a backup all read: without us."""
    db, _ = sealed
    raw = await db.notes.find_one({"patient": "alice"})
    assert raw is not None
    assert not isinstance(raw["text"], str), "the field is still a string"
    assert SECRET.encode() not in bytes(raw["text"]), (
        "the plaintext is in the bytes on disk; the encryption is decorative")


async def test_the_handle_still_returns_a_string(sealed):
    """Encryption nobody can read through is not a feature."""
    _, notes = sealed
    got = await notes.find({"patient": "alice"})
    assert [d["text"] for d in got] == [SECRET]


async def test_destroying_the_key_refuses_by_name(sealed):
    """Not an exception and not an empty page.

    `unrecoverable` is reported apart from `revoked` because it is a strictly
    stronger statement: revoked says this application will not serve it,
    unrecoverable says nobody can -- not a replica, not a backup restored
    next year.
    """
    _, notes = sealed
    await notes.shred("alice")

    assert await notes.find({"patient": "alice"}) == []
    assert notes.receipts()["refused_by_reason"].get("unrecoverable") == 1


async def test_shredding_one_tenant_leaves_the_others_readable(sealed):
    """The only reason a per-subject erasure means anything. A key per scope
    is what makes this a destruction rather than a filter."""
    _, notes = sealed
    await notes.shred("alice")

    assert [d["text"] for d in await notes.find({"patient": "bob"})] == [KEPT]


async def test_the_row_survives_the_shred(sealed):
    """Unreachable first, erased second. The ciphertext stays until the
    deadline collects it -- destroying the key is what makes the bytes
    worthless everywhere at once, including where this process cannot reach."""
    db, notes = sealed
    await notes.shred("alice")

    assert await db.notes.count_documents({"patient": "alice"}) == 1


async def test_custody_says_what_it_is_rather_than_implying_it(sealed):
    """`Ephemeral` is demo-grade and has to admit it. A custody ladder whose
    bottom rung looks like its top rung is worse than no ladder."""
    from voyd.engine.custody import Ephemeral, LocalFile

    demo = Ephemeral().describe()
    assert demo["durable"] is False
    assert demo["audited"] is False

    onfile = LocalFile(path="/tmp/does-not-need-to-exist.key").describe()
    assert onfile["durable"] is True, (
        "a key on disk outlives the process; saying otherwise would make the "
        "ladder meaningless")
