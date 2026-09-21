"""End to end, against a real MongoDB, driven by a client that never heard of
this package.

Every assertion below is made through a plain `pymongo.MongoClient`. That is
deliberate and it is the whole architectural claim: if these hold for pymongo
they hold for the Node driver, for Compass and for a notebook, because all of
them put the same bytes on the wire.

The control assertion matters as much as the claim. The *direct* connection
must keep serving the expired and revoked rows -- if it ever stops, these
tests pass for the wrong reason and the boundary is being credited for
something the database did.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time
from datetime import timedelta
from pathlib import Path

import pytest

from voyd.engine.time import now

from .conftest import MONGO_URI, free_port, mongo_host

pymongo = pytest.importorskip("pymongo")
ROOT = Path(__file__).resolve().parents[1]
PAST = now() - timedelta(days=1)

POLICY = """
from voyd import guard, deadline, revocable, tenant

@guard("notes", on_delete="revoke")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()
"""


@pytest.fixture
def seeded(db):
    db.notes.insert_many([
        {"tenant_id": "acme", "text": "live"},
        {"tenant_id": "acme", "text": "expired", "expire_at": PAST},
        {"tenant_id": "acme", "text": "revoked",
         "forgotten": {"at": PAST, "reason": "leak"}},
        {"tenant_id": "acme", "text": "doomed"},
        {"tenant_id": "globex", "text": "someone else's"},
    ])
    return db


@pytest.fixture
def boundary(tmp_path):
    """A `voyd-wire` on a free port, from a policy file. Yields its URI."""
    policy = tmp_path / "voydfile.py"
    policy.write_text(POLICY)
    port = free_port()
    proc = subprocess.Popen(
        [sys.executable, "tools/voyd_wire.py", "--config", str(policy),
         "--listen", str(port), "--target", mongo_host()],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        until = time.monotonic() + 15
        while time.monotonic() < until:
            if proc.poll() is not None:
                pytest.fail(f"voyd-wire exited early:\n{proc.stdout.read()}")
            try:
                with socket.create_connection(("127.0.0.1", port), 0.2):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            pytest.fail("voyd-wire never started listening")
        yield f"mongodb://localhost:{port}/?directConnection=true"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def texts(uri, name, flt):
    client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=8000)
    try:
        return sorted(d["text"] for d in client[name].notes.find(flt))
    finally:
        client.close()


def test_the_unguarded_connection_still_leaks(seeded):
    """The control. If this fails, everything below proves nothing."""
    assert texts(MONGO_URI, seeded.name, {}) == [
        "doomed", "expired", "live", "revoked", "someone else's"]


def test_a_plain_driver_through_the_boundary_cannot_read_a_forgotten_fact(
        seeded, boundary):
    assert texts(boundary, seeded.name, {"tenant_id": "acme"}) == [
        "doomed", "live"]


def test_a_delete_becomes_a_revocation(seeded, boundary):
    """The verb already in their code, given the better meaning."""
    client = pymongo.MongoClient(boundary, serverSelectionTimeoutMS=8000)
    try:
        res = client[seeded.name].notes.delete_one({"text": "doomed"})
    finally:
        client.close()

    assert res.deleted_count == 1, "the driver is entitled to its own reply"
    assert texts(boundary, seeded.name, {"tenant_id": "acme"}) == ["live"]
    assert seeded.notes.count_documents({}) == 5, (
        "nothing may be destroyed: a delete that really deleted is not a "
        "refusal, and the row is the investigation")

    row = seeded.notes.find_one({"text": "doomed"})
    assert row["forgotten"]["reason"] == "deleted via voyd-wire"
    assert row["expire_at"] is not None, (
        "the bytes still go, on the deadline they already had")


def test_the_wire_and_the_library_write_the_same_document(seeded, boundary):
    """Two spellings that produced different rows would be the drift this
    package is about, arriving through its own front door."""
    client = pymongo.MongoClient(boundary, serverSelectionTimeoutMS=8000)
    try:
        client[seeded.name].notes.delete_one({"text": "doomed"})
    finally:
        client.close()
    through_wire = seeded.notes.find_one({"text": "doomed"})

    assert set(through_wire["forgotten"]) == {"at", "reason"}
    assert through_wire["expire_at"] is not None
    assert through_wire["embedding"] is None, (
        "the derived encoding goes too -- a vector beside an erased document "
        "is a copy of it in a coat")


def test_an_undeclared_collection_is_forwarded_untouched(seeded, boundary):
    """It refuses what it was told to refuse, and says so rather than
    implying it."""
    seeded.other.insert_many([{"text": "a"},
                              {"text": "b", "expire_at": PAST}])
    client = pymongo.MongoClient(boundary, serverSelectionTimeoutMS=8000)
    try:
        assert client[seeded.name].other.count_documents({}) == 2
    finally:
        client.close()


def test_the_boundary_refuses_to_run_as_a_plain_relay():
    """No policy and no `--guard` would be a TCP pipe wearing the name of a
    boundary, which is the one thing this must never be."""
    proc = subprocess.run([sys.executable, "tools/voyd_wire.py"],
                          cwd=ROOT, capture_output=True, text=True, timeout=30)
    assert proc.returncode == 2
    assert "pretending to be a boundary" in proc.stderr


# --------------------------------------------------------------------------
# Every way a client can make a guarded fact stop being reachable. Covering
# three of four is the silent hole this project is named after, and it was
# real: `deleteOne` left the row on disk while `findOneAndDelete` destroyed
# it, under the same policy, in the same process.
# --------------------------------------------------------------------------

def test_find_one_and_delete_also_becomes_a_revocation(seeded, boundary):
    """A different wire command (`findAndModify`), so a separate rewrite.

    The verb's whole point is that the caller gets the document back, and
    that still happens -- `remove: true` becomes an update pipeline, not a
    refusal.
    """
    client = pymongo.MongoClient(boundary, serverSelectionTimeoutMS=8000)
    try:
        got = client[seeded.name].notes.find_one_and_delete({"text": "doomed"})
    finally:
        client.close()

    assert got is not None and got["text"] == "doomed", (
        "the caller asked for the document back and is entitled to it")
    assert texts(boundary, seeded.name, {"tenant_id": "acme"}) == ["live"]
    assert seeded.notes.count_documents({}) == 5, "nothing destroyed"
    row = seeded.notes.find_one({"text": "doomed"})
    assert row["forgotten"]["reason"] == "findOneAndDelete via voyd-wire"


def test_both_delete_verbs_produce_the_same_document(seeded, boundary):
    """Two spellings that left different rows would be the drift this
    package is about, arriving through its own front door."""
    client = pymongo.MongoClient(boundary, serverSelectionTimeoutMS=8000)
    try:
        client[seeded.name].notes.delete_one({"text": "doomed"})
        client[seeded.name].notes.find_one_and_delete({"text": "live"})
    finally:
        client.close()

    a = seeded.notes.find_one({"text": "doomed"})
    b = seeded.notes.find_one({"text": "live"})
    assert set(a["forgotten"]) == set(b["forgotten"]) == {"at", "reason"}
    assert a["expire_at"] is not None and b["expire_at"] is not None
    assert a["embedding"] is None and b["embedding"] is None


def test_dropping_a_guarded_collection_is_refused(seeded, boundary):
    """The verb that cannot be a revocation, so it is a loud error instead.

    A collection that declared `on_delete="revoke"` has said deletes here
    become revocations. Honouring that for `deleteOne` and letting `drop`
    through would be the boundary lying by omission -- and a drop takes the
    marks with it, so there would not even be evidence afterwards.
    """
    client = pymongo.MongoClient(boundary, serverSelectionTimeoutMS=8000)
    try:
        with pytest.raises(pymongo.errors.OperationFailure, match="voyd-wire refuses"):
            client[seeded.name].notes.drop()
    finally:
        client.close()

    assert seeded.notes.count_documents({}) == 5, "the collection survived"


def test_an_undeclared_collection_can_still_be_dropped(seeded, boundary):
    """It refuses what it was told to refuse. A proxy that guarded every
    collection would be a different and much more surprising product."""
    seeded.other.insert_one({"text": "a"})
    client = pymongo.MongoClient(boundary, serverSelectionTimeoutMS=8000)
    try:
        client[seeded.name].other.drop()
    finally:
        client.close()
    assert seeded.other.count_documents({}) == 0


def test_an_aggregation_cannot_copy_refused_documents_elsewhere(seeded, boundary):
    """The sharpest hole a read-path boundary can have, because it does not
    look destructive.

    `$out` and `$merge` write inside the server. The documents never come
    back to the client, so nothing on the read path is ever handed one to
    refuse. Measured before this was closed: a connection that had just
    declined to show `revoked` copied it into another collection anyway.

    A proxy cannot make these safe -- it is never given the document -- so
    the only honest answer is the one `drop` gets.
    """
    client = pymongo.MongoClient(boundary, serverSelectionTimeoutMS=8000)
    try:
        for stage in ({"$out": "copied"}, {"$merge": {"into": "copied"}}):
            with pytest.raises(pymongo.errors.OperationFailure,
                               match="voyd-wire refuses"):
                client[seeded.name].notes.aggregate(
                    [{"$match": {"tenant_id": "acme"}}, stage])
    finally:
        client.close()

    assert seeded.copied.count_documents({}) == 0, (
        "a refused document escaped into an unguarded collection")


def test_an_ordinary_aggregation_is_untouched(seeded, boundary):
    """The refusal must be about writing elsewhere, not about aggregating.
    A boundary that broke `$group` would be swapped out within a day."""
    client = pymongo.MongoClient(boundary, serverSelectionTimeoutMS=8000)
    try:
        got = list(client[seeded.name].notes.aggregate(
            [{"$match": {"tenant_id": "acme"}}, {"$sort": {"text": 1}}]))
    finally:
        client.close()
    assert [d["text"] for d in got] == ["doomed", "live"], (
        "the expired and revoked rows are refused; the rest aggregates")
