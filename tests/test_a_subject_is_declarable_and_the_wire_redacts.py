"""A chapter can be forgotten without forgetting the book, from a policy file.

`test_an_embedded_subject_is_refused_without_its_parent.py` holds the
verdict: given a spec that declares `subjects`, the refused elements are
removed and the parent is served without them. This file holds the two
things that made that verdict unreachable in the product.

**It was not declarable.** `AdmissionSpec` took `subjects` and
`subject_key`, `_admit` redacted, and `declare.py` exposed neither -- so on
the wire `spec.subjects` was always `None` and a book with a revoked
chapter went out whole. `subjects(key=...)` closes that, and `key` is
required here where the engine leaves it optional: an anonymous subject is
refusable on read and can never be *addressed*, and an erasure request
names a thing.

**And redaction was a no-op on the only read path the boundary uses.**
Two causes, both the same mistake -- an optimisation that assumed a
document only ever comes back whole or not at all:

- `_redact` tested elements with `isinstance(element, dict)`. The proxy
  decodes replies with a lazy codec, so an element arrives as a
  `RawBSONDocument`: a `Mapping`, not a `dict` subclass. Every real
  chapter fell through the "a scalar in an array of scalars" branch and
  was kept. The feature worked in every test that built its documents by
  hand and did nothing at all in production.
- `enforce` forwarded the original bytes whenever `len(kept) ==
  len(batch)`, which is the right test for refusing a document and the
  wrong one for editing it.

The third cause is the interesting one, and it is the reason the blinding
projection is *refused* here rather than rewritten. Everywhere else a
projection that hides the marks has a remedy: put the rule in the filter
and the server drops the refused documents before the projection can hide
anything. No query removes an array element, so for a subject there is no
remedy and the read is refused with a message saying what to ask for
instead.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path

import pytest

from voyd.declare import load
from voyd.engine.time import now

from .conftest import free_port, mongo_host

pymongo = pytest.importorskip("pymongo")
ROOT = Path(__file__).resolve().parents[1]
PAST = now() - timedelta(days=1)

POLICY = """
from voyd import guard, deadline, revocable, subjects

@guard("books")
class Books:
    expire_at = deadline()
    forgotten = revocable()
    chapters = subjects(key="title")
"""

SECRET = "the admin password is hunter2"


def _load(tmp_path, body: str):
    path = tmp_path / "voydfile.py"
    path.write_text(body)
    return load(str(path))


# ---- the declaration, and what it refuses to compile --------------------

def test_a_policy_file_can_declare_a_subject_array(tmp_path):
    spec = _load(tmp_path, POLICY)["books"]
    assert spec.subjects == "chapters"
    assert spec.subject_key == "title"


def test_a_subject_array_without_a_key_is_a_load_error(tmp_path):
    """The engine allows anonymous subjects and says they are honest but
    limited. A policy file does not, because the limit is that nothing can
    ever revoke one -- and an erasure request names a thing."""
    with pytest.raises(TypeError):
        _load(tmp_path, POLICY.replace('subjects(key="title")', "subjects()"))


def test_an_empty_key_is_a_load_error(tmp_path):
    with pytest.raises(ValueError, match="needs key="):
        _load(tmp_path, POLICY.replace('key="title"', 'key="  "'))


def test_two_subject_arrays_are_a_load_error(tmp_path):
    """A document has one shape. Two answers to "which thing is the
    subject" is no answer."""
    body = POLICY.replace('    chapters = subjects(key="title")',
                          '    chapters = subjects(key="title")\n'
                          '    notes = subjects(key="id")')
    with pytest.raises(ValueError, match="two subject arrays"):
        _load(tmp_path, body)


def test_subjects_with_nothing_to_refuse_them_is_a_load_error(tmp_path):
    """Declaring the array makes refusal able to *see* the elements.
    Something still has to refuse one."""
    body = """
from voyd import guard, subjects, tenant

@guard("books")
class Books:
    tenant_id = tenant()
    chapters = subjects(key="title")
"""
    with pytest.raises(ValueError, match="no reason to refuse"):
        _load(tmp_path, body)


# ---- and the boundary redacts, for a driver that imported nothing -------

@contextmanager
def _wire(policy: str):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "voydfile.py"
        path.write_text(policy)
        port = free_port()
        proc = subprocess.Popen(
            [sys.executable, "-m", "voyd.wire", "--config", str(path),
             "--listen", str(port), "--target", mongo_host()],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True)
        try:
            until = time.monotonic() + 15
            while time.monotonic() < until:
                if proc.poll() is not None:
                    pytest.fail(f"exited early:\n{proc.stdout.read()}")
                try:
                    with socket.create_connection(("127.0.0.1", port), 0.2):
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                pytest.fail("never started listening")
            yield port, proc
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


@pytest.fixture
def library(db):
    db.books.insert_one({"_id": 1, "title": "a manual", "chapters": [
        {"title": "intro", "text": "fine"},
        {"title": "leaked", "text": SECRET,
         "forgotten": {"at": PAST, "reason": "credential leaked"}},
        {"title": "stale", "text": "last year's", "expire_at": PAST},
        {"title": "outro", "text": "also fine"},
    ]})
    return db


def test_the_refused_chapters_do_not_reach_a_plain_driver(library):
    """The product claim, and the one that was false in three separate
    ways an hour ago."""
    with _wire(POLICY) as (port, _proc):
        client = pymongo.MongoClient(
            f"mongodb://localhost:{port}/?directConnection=true",
            serverSelectionTimeoutMS=8000)
        try:
            book = client[library.name].books.find_one({"_id": 1})
        finally:
            client.close()

    assert [c["title"] for c in book["chapters"]] == ["intro", "outro"]
    assert SECRET not in str(book), (
        "the revoked chapter's text reached the client")
    on_disk = library.books.find_one({"_id": 1})
    assert len(on_disk["chapters"]) == 4, (
        "the control: nothing was deleted, so redaction is what happened")


def test_a_projection_that_hides_a_chapters_marks_is_refused(library):
    """Everywhere else a blinding projection is rewritten -- the rule goes
    into the filter and the server drops the refused documents. No query
    removes an array element, so here there is no remedy and the read is
    refused rather than served unjudged."""
    with _wire(POLICY) as (port, _proc):
        client = pymongo.MongoClient(
            f"mongodb://localhost:{port}/?directConnection=true",
            serverSelectionTimeoutMS=8000)
        try:
            with pytest.raises(pymongo.errors.PyMongoError) as caught:
                list(client[library.name].books.find({}, {"chapters.text": 1}))
        finally:
            client.close()
    assert "chapters" in str(caught.value)


def test_asking_for_the_marks_too_is_served(library):
    """The refusal has to be escapable by asking correctly, or it is a
    boundary that refuses a shape rather than protecting a guarantee."""
    with _wire(POLICY) as (port, _proc):
        client = pymongo.MongoClient(
            f"mongodb://localhost:{port}/?directConnection=true",
            serverSelectionTimeoutMS=8000)
        try:
            got = list(client[library.name].books.find({}, {
                "chapters.text": 1, "chapters.title": 1,
                "chapters.forgotten": 1, "chapters.expire_at": 1,
                "forgotten": 1, "expire_at": 1}))
        finally:
            client.close()
    assert [c["title"] for c in got[0]["chapters"]] == ["intro", "outro"]


def test_the_boundary_says_at_boot_that_it_judges_elements(library):
    """An operator seeing fewer chapters than the database holds should
    find the reason in the startup output, not in a stack trace."""
    with _wire(POLICY) as (_port, proc):
        proc.terminate()
        out = proc.stdout.read() if proc.stdout else ""
    assert "judges each element of 'chapters'" in out
    assert "no erasure request can reach" in out
