"""Lineage, authority, and the scope errors -- the last three that mattered.

**Lineage** is the differentiator, and this file drives it *through the
proxy*: revoke a source and the summary, the answer and the embedding built
out of it go with it, for a client that never heard of this package. An
erasure that stops at the document somebody named is not an erasure, it is a
filing action -- and the person honouring an erasure request cannot be
expected to enumerate every cache.

The two halves are tested separately because they fail separately. A cascade
that reaches children and not grandchildren looks like it works. It is the
*insert* path that makes depth work: the boundary closes a document's
ancestry transitively when it is written, which is the only reason
propagation is one `$in` rather than a recursive walk. So the deep case here
is not a redundant version of the shallow one, it is the assertion that the
write side happened at all.

**Authority** is the gate on the verbs that *change* reachability. Withholding
a fact and granting one back are not equally dangerous, and until this file
neither was checked.

**The scope errors** are pure functions with no database in them at all, and
they are where a tenant leak actually gets stopped: presence is not shape, and
`{"$ne": "nobody"}` passes a presence check and then matches everyone.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

from .conftest import free_port, mongo_host

pymongo = pytest.importorskip("pymongo")
ROOT = Path(__file__).resolve().parents[1]

POLICY = """
from voyd import guard, deadline, revocable

@guard("notes", on_delete="revoke", lineage_field="lineage")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
"""


@contextmanager
def _wire(tmp_path, policy: str):
    """A `voyd-wire` on a free port, from a policy file. Yields the port."""
    path = tmp_path / "voydfile.py"
    path.write_text(policy)
    port = free_port()
    proc = subprocess.Popen(
        [sys.executable, "tools/voyd_wire.py", "--config", str(path),
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
        yield port
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.fixture
def boundary(tmp_path):
    """The boundary, guarding a collection that tracks derivation."""
    with _wire(tmp_path, POLICY) as port:
        yield f"mongodb://localhost:{port}/?directConnection=true"


@pytest.fixture
def notes(boundary, db):
    """A plain pymongo handle onto the guarded collection, through the proxy.

    `db` is the throwaway database and the *direct* connection; it is kept
    so the control assertions below can ask what is actually on disk. If
    those ever stop finding the rows, these tests pass for the wrong reason
    and the boundary is being credited for a delete.
    """
    client = pymongo.MongoClient(boundary, serverSelectionTimeoutMS=8000)
    try:
        yield client[db.name].notes, db
    finally:
        client.close()


# ---- lineage, through the connection string the README recommends --------

def test_revoking_a_source_reaches_what_was_made_of_it(notes):
    """A delete of the source, by a client that imported nothing, reaches
    the summary, the answer and the embedding built out of it -- and leaves
    every byte on disk."""
    through, direct = notes
    src = through.insert_one({"text": "the credential"}).inserted_id
    through.insert_one({"text": "unrelated"})
    summary = through.insert_one(
        {"kind": "summary", "lineage": [src]}).inserted_id
    answer = through.insert_one(
        {"kind": "answer", "lineage": [summary]}).inserted_id
    through.insert_one({"kind": "embedding", "lineage": [answer]})

    through.delete_one({"_id": src})

    survivors = list(through.find({}))
    assert [d.get("text") for d in survivors] == ["unrelated"], (
        "the fact and the three things made out of it are all unreachable")
    # The control: nothing was deleted. Five rows, four of them marked.
    assert direct.notes.count_documents({}) == 5
    assert direct.notes.count_documents({"forgotten": {"$exists": True}}) == 4


def test_the_boundary_closes_the_ancestry_so_the_cascade_reaches_depth(notes):
    """The write-side half, asserted on its own because it is what makes the
    read-side half work at depth.

    The client named *one* parent. The grandchild stored on disk names the
    grandparent too, because the boundary closed the ancestry on the way in
    -- and that is the only reason revoking the source is one query rather
    than a walk."""
    through, direct = notes
    src = through.insert_one({"text": "source"}).inserted_id
    summary = through.insert_one(
        {"kind": "summary", "lineage": [src]}).inserted_id
    answer = through.insert_one(
        {"kind": "answer", "lineage": [summary]}).inserted_id

    stored = direct.notes.find_one({"_id": answer})
    assert stored is not None
    assert set(stored["lineage"]) == {src, summary}, (
        "the client named only its parent; the boundary added the grandparent")


def test_the_consequence_question_is_one_indexed_query(notes):
    """*Which answers were built on this fact?* -- the same field, read from
    the other end. For anything written back into the collection, which is
    what a RAG cache is, the archaeology project is a `find`."""
    through, direct = notes
    src = through.insert_one({"text": "source"}).inserted_id
    other = through.insert_one({"text": "other"}).inserted_id
    summary = through.insert_one(
        {"kind": "summary", "lineage": [src]}).inserted_id
    answer = through.insert_one(
        {"kind": "answer", "lineage": [summary]}).inserted_id
    innocent = through.insert_one(
        {"kind": "answer", "lineage": [other]}).inserted_id

    fallout = {d["_id"] for d in direct.notes.find({"lineage": src})}

    assert fallout == {summary, answer}
    assert innocent not in fallout


def test_deriving_from_a_revoked_source_is_refused(notes):
    """The write-side race, at the boundary. An agent still holding the text
    and writing it back must be refused, not written-and-marked -- reaching
    here means something read a document it should not have been given."""
    through, direct = notes
    src = through.insert_one({"text": "gone"}).inserted_id
    through.delete_one({"_id": src})

    with pytest.raises(pymongo.errors.PyMongoError):
        through.insert_one({"kind": "late summary", "lineage": [src]})

    assert direct.notes.count_documents({"kind": "late summary"}) == 0, (
        "refused means not written, not written-and-marked")


def test_a_delete_that_names_one_of_many_cascades_from_that_one(notes):
    """`deleteOne` asks the server to pick and does not say which, so the
    boundary resolves the id once and pins both halves to it. Without that,
    the children of a document the server did not revoke get marked."""
    through, direct = notes
    a = through.insert_one({"text": "twin", "pick": "a"}).inserted_id
    b = through.insert_one({"text": "twin", "pick": "b"}).inserted_id
    child_a = through.insert_one({"of": "a", "lineage": [a]}).inserted_id
    child_b = through.insert_one({"of": "b", "lineage": [b]}).inserted_id

    through.delete_one({"text": "twin"})

    marked = {d["_id"] for d in
              direct.notes.find({"forgotten": {"$exists": True}})}
    assert marked in ({a, child_a}, {b, child_b}), (
        f"the cascade and the revocation landed on different rows: {marked}")
    assert len(marked) == 2
    assert {a, b} & marked and {child_a, child_b} & marked


def test_an_ordinary_collection_pays_nothing_for_lineage(tmp_path, db):
    """The gate is a field being `None`. A policy that declares no
    `lineage_field` must behave exactly as it did before this existed --
    including the delete still becoming a revocation."""
    plain = POLICY.replace(', lineage_field="lineage"', "")
    with _wire(tmp_path, plain) as port:
        client = pymongo.MongoClient(
            f"mongodb://localhost:{port}/?directConnection=true",
            serverSelectionTimeoutMS=8000)
        try:
            through = client[db.name].notes
            src = through.insert_one({"text": "a"}).inserted_id
            through.insert_one({"text": "b", "lineage": [src]})
            through.delete_one({"_id": src})
            assert [d["text"] for d in through.find({})] == ["b"]
            assert db.notes.count_documents({}) == 2
        finally:
            client.close()


# ---- authority -----------------------------------------------------------

def test_an_authority_cannot_verify_the_claims_it_is_handed():
    """Stated because it is the honest limit: claims come from whatever
    already authenticated the caller. An authorisation system whose only
    input is the attacker's would be worse than none."""
    from voyd.engine import Grants

    g = Grants()
    ok = g.permits("revoke", {"sub": "dana", "may": ["revoke"]},
                   collection="notes")
    assert ok is True
    assert g.permits("revoke", {"sub": "i", "may": []},
                     collection="notes") is False
    assert g.permits("revoke", None, collection="notes") is False, (
        "no caller is not a free pass")


# ---- the scope errors, with no database in sight -------------------------

@pytest.mark.parametrize("bad", [
    {"$ne": "nobody"}, {"$exists": True}, {"$gt": ""}, {"$nin": ["x"]},
], ids=lambda o: next(iter(o)))
def test_a_tenant_that_is_an_operator_is_refused(bad):
    """Presence is not shape. Every one of these passes a presence check and
    then matches every tenant -- and `$vectorSearch`'s filter accepts them,
    so presence-checking plus a vector index is a leak with a green suite."""
    from voyd.engine import ScopeInvalid
    from voyd.engine.errors import require_tenant

    with pytest.raises(ScopeInvalid):
        require_tenant("notes", "tenant_id", {"tenant_id": bad})


def test_a_missing_tenant_raises_rather_than_returning_everything():
    from voyd.engine import ScopeRequired
    from voyd.engine.errors import require_tenant

    with pytest.raises(ScopeRequired):
        require_tenant("notes", "tenant_id", {})
    with pytest.raises(ScopeRequired):
        require_tenant("notes", "tenant_id", {"tenant_id": None})


def test_an_unscoped_collection_is_left_alone():
    """The tenant rule must not invent a scope nobody declared."""
    from voyd.engine.errors import require_tenant

    assert require_tenant("notes", None, {"a": 1}) == {"a": 1}
