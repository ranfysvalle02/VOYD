"""The guarantee, enforced for a client that has never heard of this package.

Everything else here binds a *handle*. `docs.find(...)` refuses and
`db.notes.find(...)` does not, which is why this repository also ships a
raw-read guard, a source scanner, and a CI gate asserting no module reaches
past the handle. All of that is machinery for stopping people doing the easy
thing.

`tools/voyd_wire.py` moves the boundary to the wire, so the guarantee binds
the *connection*. This test is the evidence, and it is deliberately written
with a plain `pymongo.MongoClient` and no VOYD import in the read path: if
the assertions below hold, they hold for the Node driver, for Compass, and
for a notebook, because all of them send the same bytes.

It is an integration test of a demonstration tool, not of the package, and it
is worth the seconds it costs for one reason: this is the only test in the
suite where the thing being refused arrives at a client the package cannot
see, which is the whole architectural claim.
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

from .conftest import TEST_MONGO_URI

pymongo = pytest.importorskip("pymongo")
ROOT = Path(__file__).resolve().parents[1]
DB = "voyd_example_wire_test"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _target() -> str:
    """host:port of the suite's MongoDB, as the proxy wants it."""
    hostport = TEST_MONGO_URI.split("//", 1)[1].split("/", 1)[0]
    return hostport if ":" in hostport else f"{hostport}:27017"


@pytest.fixture
def proxied():
    """A `voyd-wire` fronting the test database, guarding `notes`."""
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, "tools/voyd_wire.py", "--listen", str(port),
         "--target", _target(), "--guard", "notes"],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
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


@pytest.fixture
def seeded():
    """Three documents: one live, one expired, one revoked. Written raw."""
    client = pymongo.MongoClient(TEST_MONGO_URI)
    client.drop_database(DB)
    past = now() - timedelta(days=1)
    client[DB].notes.insert_many([
        {"text": "live fact"},
        {"text": "expired fact", "expire_at": past},
        {"text": "revoked fact",
         "forgotten": {"at": past, "reason": "credential leaked"}},
    ])
    try:
        yield client
    finally:
        client.drop_database(DB)
        client.close()


def _texts(uri: str) -> list[str]:
    client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=8000)
    try:
        return sorted(d["text"] for d in client[DB].notes.find({}))
    finally:
        client.close()


def test_a_driver_that_never_heard_of_voyd_still_cannot_read_a_forgotten_fact(
        seeded, proxied):
    """The claim, in two lines.

    The direct read is the control, and it has to keep leaking: if the raw
    path ever stopped serving the expired and revoked rows, this test would
    pass for the wrong reason and prove nothing about the proxy.
    """
    assert _texts(TEST_MONGO_URI) == [
        "expired fact", "live fact", "revoked fact"], (
        "the unguarded connection must still serve all three, or the proxy "
        "below is being credited for something the database did")

    assert _texts(proxied) == ["live fact"]


def test_the_rows_are_all_still_on_disk(seeded, proxied):
    """Unreachable first, erased second. The proxy refuses; it never deletes,
    and it has no write path at all."""
    assert _texts(proxied) == ["live fact"]
    assert seeded[DB].notes.count_documents({}) == 3


def test_an_unguarded_collection_is_forwarded_untouched(seeded, proxied):
    """It refuses what it was told to refuse, and says so rather than
    implying it. A proxy that silently guarded everything would be a
    different and much more surprising product."""
    seeded[DB].other.insert_many([
        {"text": "a"}, {"text": "b", "expire_at": now() - timedelta(days=1)}])
    client = pymongo.MongoClient(proxied, serverSelectionTimeoutMS=8000)
    try:
        assert client[DB].other.count_documents({}) == 2
    finally:
        client.close()


def test_the_proxy_refuses_to_run_as_a_plain_relay():
    """`--guard` with nothing named would be a TCP relay wearing the name of
    a boundary, which is the one thing this tool must not be."""
    proc = subprocess.run(
        [sys.executable, "tools/voyd_wire.py", "--listen", "0"],
        cwd=ROOT, capture_output=True, text=True, timeout=30)
    assert proc.returncode == 2
    assert "pretending to be a boundary" in proc.stderr


# --------------------------------------------------------------------------
# The policy file. The whole of what a team writes, and it is not in their
# application: no import added, no handle wrapping a collection, no read path
# rewritten. So it has to be exactly as hard to get wrong as their code would
# have been, and fail at load rather than at the first query.
# --------------------------------------------------------------------------

VOYDFILE = '''
from voyd import guard, deadline, revocable, tenant

@guard("notes")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()
'''


def test_a_policy_file_declares_the_same_boundary_the_flags_do(tmp_path, seeded):
    """The declarative form is a spelling, not a second mechanism.

    It compiles to the same `AdmissionSpec` the hand-written form builds, so
    there is no cliff between "declare it" and "drop to the protocol" -- which
    is the property that lets the file stay small without becoming a ceiling.
    """
    from voyd.declare import load

    path = tmp_path / "voydfile.py"
    path.write_text(VOYDFILE)
    specs = load(str(path))

    assert set(specs) == {"notes"}
    spec = specs["notes"]
    assert spec.tenant == "tenant_id"
    assert [type(r).__name__ for r in spec.rules] == ["Deadline", "Marked"]
    assert spec.rules[0].at_field == "expire_at"
    assert spec.rules[1].field == "forgotten"
    assert spec.rules[1].reversible is False, "a revocation is not a hypothesis"


@pytest.mark.parametrize("body,because", [
    ("@guard('notes')\nclass N:\n    pass",
     "a guard that refuses nothing is a slower read"),
    ("from voyd import deadline\n@guard('notes')\nclass N:\n"
     "    a = deadline()\n    b = deadline()",
     "two clocks is the drift this exists to remove"),
    ("from voyd import tenant\n@guard('notes')\nclass N:\n"
     "    a = tenant()\n    b = tenant()",
     "a scope with two keys is not a scope"),
], ids=["no rules", "two deadlines", "two tenants"])
def test_a_policy_file_that_is_wrong_fails_at_load(tmp_path, body, because):
    """Not at the first query.

    This is the one file where an error must surface immediately: a proxy
    started from a broken declaration is a door standing ajar, and the
    symptom is rows, not an exception.
    """
    from voyd.declare import load

    path = tmp_path / "voydfile.py"
    path.write_text("from voyd import guard\n" + body)
    with pytest.raises(ValueError):
        load(str(path))


def test_an_empty_policy_file_is_refused(tmp_path):
    """A file with no `@guard` in it would start a boundary that refuses
    nothing, silently -- which is this project's one unforgivable failure,
    committed by its own front door."""
    from voyd.declare import load

    path = tmp_path / "voydfile.py"
    path.write_text("x = 1\n")
    with pytest.raises(ValueError, match="declared no collections"):
        load(str(path))


def test_the_proxy_runs_from_a_policy_file(seeded, tmp_path):
    """End to end: the file is the configuration, and the client is plain."""
    path = tmp_path / "voydfile.py"
    path.write_text(VOYDFILE)

    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, "tools/voyd_wire.py", "--config", str(path),
         "--listen", str(port), "--target", _target()],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        deadline_at = time.monotonic() + 15
        while time.monotonic() < deadline_at:
            if proc.poll() is not None:
                pytest.fail(f"voyd-wire exited early:\n{proc.stdout.read()}")
            try:
                with socket.create_connection(("127.0.0.1", port), 0.2):
                    break
            except OSError:
                time.sleep(0.1)
        client = pymongo.MongoClient(f"mongodb://localhost:{port}/"
                                     "?directConnection=true",
                                     serverSelectionTimeoutMS=8000)
        try:
            got = sorted(d["text"] for d in client[DB].notes.find({}))
        finally:
            client.close()
        assert got == ["live fact"]
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
