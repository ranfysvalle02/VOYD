"""A rule nobody here wrote, enforced on the wire, from a policy file.

`rules.py` has always said a third-party rule is the same kind of object as
a builtin one with no privileged path. That was true of the *engine* and
false of the *policy file*, which is the only artifact an application
actually has: the vocabulary is a fixed set of helpers, so a stranger's
rule had nowhere to be written and could not reach the boundary at all.

**It was worse than missing.** A rule object in a class body was simply not
a `_Field`, so the loader skipped it -- and the proxy came up announcing
`refuses on [deadline, revoked]` while serving every document the rule was
written to refuse. No error, no warning, and a policy file that looked
exactly like a working one. This project's own named failure, in the loader
that reads the file the whole product is.

So the assertions here come in pairs: the rule is installed *and* the half
-written version cannot be installed in silence. The second is the one
worth having, because the first fails loudly the moment somebody reads
their own metrics and the second never fails at all.

The rule below is deliberately about something this package has no word
for. `Jurisdiction` is not a deadline, not a revocation, not a clearance
and not a budget; it refuses a document whose region is not the one the
policy allows. Nothing in `voyd/` knows what a region is, which is the
point -- the boundary is extensible without the boundary being edited.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

from voyd.declare import load

from .conftest import free_port, mongo_host

pymongo = pytest.importorskip("pymongo")
ROOT = Path(__file__).resolve().parents[1]

# The stranger's rule, written against the documented protocol and nothing
# else. It is a string because a policy file is a file, and the whole claim
# is that this is all somebody has to write.
JURISDICTION = '''
from dataclasses import dataclass

@dataclass(frozen=True)
class Jurisdiction:
    """A document may not leave its region."""
    allowed: str
    field: str = "region"
    reason: str = "wrong_region"

    def refuses(self, doc, *, when=None):
        return doc.get(self.field) != self.allowed

    def clause(self):
        return {self.field: self.allowed}
'''

POLICY = JURISDICTION + '''
from voyd import guard, deadline, revocable

@guard("notes")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    region = Jurisdiction(allowed="eu")
'''


def _load(tmp_path, body: str):
    path = tmp_path / "voydfile.py"
    path.write_text(body)
    return load(str(path))


# ---- it installs, and it binds the attribute name ------------------------

def test_a_rule_written_elsewhere_is_installed(tmp_path):
    spec = _load(tmp_path, POLICY)["notes"]
    assert [type(r).__name__ for r in spec.rules] == [
        "Deadline", "Marked", "Jurisdiction"]


def test_the_attribute_name_is_the_field_it_reads(tmp_path):
    """`region = Jurisdiction(allowed="eu")` reads `region`, without saying
    so twice. Every other line in a policy file binds the name that way,
    and a rule that had to repeat its own would be the one exception."""
    spec = _load(tmp_path, POLICY.replace("region = Jurisdiction",
                                          "locale = Jurisdiction"))["notes"]
    theirs = next(r for r in spec.rules if type(r).__name__ == "Jurisdiction")
    assert theirs.field == "locale"


def test_a_rule_that_names_its_own_field_is_still_honoured(tmp_path):
    """Not every rule is a dataclass, and one that cannot be rebuilt with a
    new field is installed as written rather than rejected -- naming its own
    field is untidy, not wrong."""
    body = '''
from voyd import guard, deadline, revocable

class PlainRule:
    """An ordinary class. Nothing here is a dataclass."""
    reason = "wrong_region"

    def __init__(self, allowed):
        self.allowed = allowed
        self.field = "region"

    def refuses(self, doc, *, when=None):
        return doc.get(self.field) != self.allowed

    def clause(self):
        return {self.field: self.allowed}

@guard("notes")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    anything = PlainRule("eu")
'''
    spec = _load(tmp_path, body)["notes"]
    theirs = next(r for r in spec.rules if type(r).__name__ == "PlainRule")
    assert theirs.field == "region"


# ---- and half a rule cannot be installed in silence ----------------------

@pytest.mark.parametrize("drop", ["reason", "refuses", "clause"])
def test_a_rule_missing_a_member_of_the_protocol_fails_at_load(tmp_path, drop):
    """The assertion that matters. Without it each of these loads cleanly,
    announces the rules it *did* understand, and serves everything the
    missing one is there to refuse."""
    body = JURISDICTION
    if drop == "reason":
        body = body.replace('    reason: str = "wrong_region"\n', "")
    elif drop == "refuses":
        body = body.replace("    def refuses(self, doc, *, when=None):\n"
                            "        return doc.get(self.field) != self.allowed\n",
                            "")
    else:
        body = body.replace("    def clause(self):\n"
                            "        return {self.field: self.allowed}\n", "")
    body += '''
from voyd import guard, deadline, revocable

@guard("notes")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    region = Jurisdiction(allowed="eu")
'''
    with pytest.raises(ValueError, match="missing"):
        _load(tmp_path, body)


def test_a_reason_that_is_not_a_name_fails_at_load(tmp_path):
    """`reason` is what the refusal is counted and reported under, so a
    number or an object there is a series nobody can alert on."""
    body = JURISDICTION.replace('    reason: str = "wrong_region"',
                                "    reason: int = 7") + '''
from voyd import guard, deadline, revocable

@guard("notes")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    region = Jurisdiction(allowed="eu")
'''
    with pytest.raises(ValueError, match="not a string"):
        _load(tmp_path, body)


def test_an_ordinary_constant_in_the_class_body_is_left_alone(tmp_path):
    """The check must not turn a policy file into a place you cannot keep a
    helper. Only something that is *half* a rule is an error."""
    body = '''
from voyd import guard, deadline, revocable

REGIONS = ("eu", "us")

@guard("notes")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    note = "written by the platform team"
'''
    spec = _load(tmp_path, body)["notes"]
    assert [type(r).__name__ for r in spec.rules] == ["Deadline", "Marked"]


# ---- through the boundary, which is the only claim that counts -----------

@contextmanager
def _wire(policy: str):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "voydfile.py"
        path.write_text(policy)
        port = free_port()
        proc = subprocess.Popen(
            [sys.executable, "-m", "voyd.wire.proxy", "--config", str(path),
             "--listen", str(port), "--target", mongo_host()],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True)
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
            yield port, proc
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


@pytest.fixture
def regions(db):
    db.notes.insert_many([
        {"text": "a paris invoice", "region": "eu"},
        {"text": "a texas invoice", "region": "us"},
        {"text": "an unlabelled invoice"},
    ])
    return db


def test_the_boundary_enforces_a_rule_it_has_never_heard_of(regions):
    """The product claim. Twelve lines in a policy file, and a driver that
    imported nothing is refused by a word this package does not know."""
    with _wire(POLICY) as (port, _proc):
        client = pymongo.MongoClient(
            f"mongodb://localhost:{port}/?directConnection=true",
            serverSelectionTimeoutMS=8000)
        try:
            got = sorted(d["text"] for d in client[regions.name].notes.find({}))
        finally:
            client.close()

    assert got == ["a paris invoice"]
    assert regions.notes.count_documents({}) == 3, (
        "the control: nothing was deleted, so refusal is what happened")


def test_it_is_announced_at_boot_and_counted_by_its_own_reason(regions):
    """A rule the operator cannot see in the startup line or on the
    counters is one they cannot tell is running, which is the state this
    whole file exists to keep the loader out of."""
    with _wire(POLICY) as (port, proc):
        client = pymongo.MongoClient(
            f"mongodb://localhost:{port}/?directConnection=true",
            serverSelectionTimeoutMS=8000)
        try:
            list(client[regions.name].notes.find({}))
        finally:
            client.close()
        proc.terminate()
        out = proc.stdout.read() if proc.stdout else ""

    assert "wrong_region" in out, (
        "the stranger's reason never reached the operator's output")
    assert "refuses on [deadline, revoked, wrong_region]" in out, (
        "the boot line did not name the rule it is enforcing")
