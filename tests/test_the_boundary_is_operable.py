"""Correct is not the same as operable, and these were the difference.

Three complaints, one cause: the upstream was a `(host, port, tls)` tuple
resolved once at startup. It could not be re-resolved, so an election meant a
restart; the listener could not be TLS, so the boundary had to sit beside the
application; and connections were unbounded, so a busy minute was an outage.

`Upstream` is that tuple given a lifecycle -- resolved lazily, cached, and
**invalidated by the server's own error**. That last part is the whole design.
A health check is a guess about the future; `NotWritablePrimary` is the server
telling you about the present, on the very message that proves it, which the
client was going to receive anyway.
"""

from __future__ import annotations

import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import voyd_wire as w  # noqa: E402

from .conftest import free_port, mongo_host  # noqa: E402

pymongo = pytest.importorskip("pymongo")
ROOT = Path(__file__).resolve().parents[1]


# ---- the failover signal, which cannot be caused on demand --------------

@pytest.mark.parametrize("reply,expected", [
    ({"ok": 0.0, "code": 10107, "codeName": "NotWritablePrimary"}, True),
    ({"ok": 0.0, "code": 189, "codeName": "PrimarySteppedDown"}, True),
    ({"ok": 1.0, "n": 1, "writeErrors": [{"code": 10107}]}, True),
    ({"ok": 1.0, "n": 1}, False),
    ({"ok": 0.0, "code": 11000, "codeName": "DuplicateKey"}, False),
], ids=["not-primary", "stepped-down", "nested-write-error", "fine", "other"])
def test_a_stepped_down_primary_is_recognised(reply, expected):
    """The nested case matters most: a write error inside a batch is where
    this hides on exactly the command -- a delete -- that this boundary
    rewrites, and a top-level-only check would miss it."""
    assert bool(w.stepped_down(reply)) is expected


def test_an_invalidated_upstream_re_resolves():
    """Cached until the server says otherwise, then resolved again."""
    up = w.Upstream("localhost:27017", verbose=False)
    first = up.address()
    assert up.address() is first or up.address() == first, "cached"
    assert up.generation == 0

    up.invalidate("NotWritablePrimary")
    assert up.generation == 1
    assert up.address() == first, "same target still resolves the same way"


def test_invalidating_an_unresolved_upstream_is_a_no_op():
    """A connection can fail before anything was resolved. Counting that as
    an election would make the generation number meaningless."""
    up = w.Upstream("localhost:27017", verbose=False)
    up.invalidate("ConnectionRefused")
    assert up.generation == 0


def test_a_bare_host_needs_no_dns_and_no_tls():
    assert w.Upstream("db:27020", verbose=False).address() == ("db", 27020, False)
    assert w.Upstream("db", verbose=False).address() == ("db", 27017, False)


# ---- the listener --------------------------------------------------------

def test_without_a_certificate_it_binds_loopback_only():
    """A decision, not a default. A plaintext boundary reachable from the
    network would carry in the clear every document it just refused."""
    port = free_port()
    sock = w.listener(port, None, None)
    try:
        assert sock.getsockname()[0] == "127.0.0.1"
    finally:
        sock.close()


def test_with_a_certificate_it_terminates_tls_and_binds_outward(tmp_path):
    port = free_port()
    cert, key = _self_signed(tmp_path)
    sock = w.listener(port, str(cert), str(key))
    try:
        assert sock.getsockname()[0] == "0.0.0.0"
        assert isinstance(sock, ssl.SSLSocket)
    finally:
        sock.close()


def _self_signed(tmp_path):
    crypto = pytest.importorskip("cryptography")  # noqa: F841
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName(
                [x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256()))
    c, k = tmp_path / "c.pem", tmp_path / "k.pem"
    c.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    k.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    return c, k


# ---- and the whole thing, running ---------------------------------------

def _wait(port, proc, seconds=15):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if proc.poll() is not None:
            pytest.fail(f"voyd-wire exited:\n{proc.stdout.read()}")
        try:
            with socket.create_connection(("127.0.0.1", port), 0.2):
                return
        except OSError:
            time.sleep(0.1)
    pytest.fail("voyd-wire never listened")


def test_a_tls_client_gets_the_same_refusal(db, tmp_path):
    """The point of terminating TLS: the boundary can be reached across a
    network without giving back in the clear what it just refused."""
    from datetime import timedelta

    from voyd.engine.time import now

    db.notes.insert_many([
        {"tenant_id": "acme", "text": "live"},
        {"tenant_id": "acme", "text": "gone", "expire_at": now() - timedelta(days=1)},
    ])
    cert, key = _self_signed(tmp_path)
    policy = tmp_path / "voydfile.py"
    policy.write_text("from voyd import guard, deadline, revocable, tenant\n"
                      "@guard('notes')\n"
                      "class N:\n"
                      "    expire_at = deadline()\n"
                      "    forgotten = revocable()\n"
                      "    tenant_id = tenant()\n")
    port = free_port()
    proc = subprocess.Popen(
        [sys.executable, "tools/voyd_wire.py", "--config", str(policy),
         "--listen", str(port), "--target", mongo_host(),
         "--tls-cert", str(cert), "--tls-key", str(key)],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        _wait(port, proc)
        client = pymongo.MongoClient(
            f"mongodb://localhost:{port}/?directConnection=true&tls=true"
            "&tlsAllowInvalidCertificates=true",
            serverSelectionTimeoutMS=10000)
        try:
            got = sorted(d["text"] for d in
                         client[db.name].notes.find({"tenant_id": "acme"}))
        finally:
            client.close()
        assert got == ["live"]
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def test_connections_past_the_limit_are_closed_rather_than_queued(db, tmp_path):
    """A driver retries; an unbounded backlog turns a busy minute into an
    outage. Closing is the honest answer and it has to actually happen."""
    policy = tmp_path / "voydfile.py"
    policy.write_text("from voyd import guard, deadline\n"
                      "@guard('notes')\n"
                      "class N:\n    expire_at = deadline()\n")
    port = free_port()
    proc = subprocess.Popen(
        [sys.executable, "tools/voyd_wire.py", "--config", str(policy),
         "--listen", str(port), "--target", mongo_host(),
         "--max-connections", "2"],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        _wait(port, proc)
        held, alive = [], 0
        for _ in range(5):
            s = socket.socket()
            s.settimeout(3)
            s.connect(("127.0.0.1", port))
            held.append(s)
            time.sleep(0.2)
        for s in held:
            # A refused connection is *closed* by the boundary, and a closed
            # socket reads as b"". An idle accepted one blocks until the
            # timeout. Those are the two outcomes, and conflating them is
            # how this test first passed while proving nothing.
            try:
                s.settimeout(0.4)
                alive += 0 if s.recv(1) == b"" else 1
            except socket.timeout:
                alive += 1          # open and idle
            except OSError:
                pass
            finally:
                s.close()
        assert alive == 2, f"expected 2 within the limit, got {alive}"
    finally:
        proc.terminate()
        proc.wait(timeout=5)
