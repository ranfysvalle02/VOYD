"""The things an operator needs on the first day, and the ones that lied.

`LIMITS.md` is honest that nobody has run this in production. That is not
an argument for leaving the production surfaces untested -- it is the
reason to, because there is no user to discover them for us.

Three of them were wrong in the same direction: **confidently ready**.

**A readiness probe on the listen port reports ready while the deployment
behind it is unreachable.** Measured: pointed at a dead port, the boundary
starts, prints its banner, accepts connections and fails every read. A
`SIGTERM`-and-roll deploy would route traffic to it. `/health` goes one
hop further, to the thing this process cannot work without.

**The metrics surface bound loopback with no flag**, which is correct on a
host and unreachable in Kubernetes, where the scrape comes from another
pod. So the exposition existed and could not be read exactly where it
mattered. `--metrics-bind` is an opt-in with the reason in its help text,
and `/health` is separate because one bit describes no corpus.

**`--version` did not exist**, which is the first thing anybody asks when
a deployment is behaving unlike the last one.

The container is built and smoke-tested in CI rather than here: a test
that needs a Docker daemon is a test that skips on somebody's laptop and
then rots.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path

import pytest

from voyd import __version__
from voyd.wire.health import main as health_main

from .conftest import free_port, mongo_host

pymongo = pytest.importorskip("pymongo")
ROOT = Path(__file__).resolve().parents[1]

POLICY = """
from voyd import guard, deadline, revocable

@guard("notes")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
"""


@contextmanager
def _wire(target: str, *extra: str):
    """A boundary with metrics on, pointed wherever the caller says."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "voydfile.py"
        path.write_text(POLICY)
        listen, metrics = free_port(), free_port()
        proc = subprocess.Popen(
            [sys.executable, "-m", "voyd.wire", "--config", str(path),
             "--listen", str(listen), "--target", target,
             "--metrics", str(metrics), "--quiet", *extra],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True)
        try:
            until = time.monotonic() + 15
            while time.monotonic() < until:
                if proc.poll() is not None:
                    pytest.fail(f"exited early:\n{proc.stdout.read()}")
                try:
                    with socket.create_connection(("127.0.0.1", listen), 0.2):
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                pytest.fail("never started listening")
            yield listen, metrics
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


def _health(port: int) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health",
                                    timeout=8) as reply:
            return reply.status, reply.read().decode().strip()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode().strip()


def _tcp(port: int) -> bool:
    """The naive readiness check, kept as the control."""
    try:
        socket.create_connection(("127.0.0.1", port), 1.0).close()
        return True
    except OSError:
        return False


# ---- readiness that tells the truth --------------------------------------

def test_health_is_ok_when_the_upstream_is_reachable(db):
    with _wire(mongo_host()) as (_listen, metrics):
        assert _health(metrics) == (200, "ok")


def test_health_is_unavailable_when_the_upstream_is_not():
    """The regression, and the reason `/health` exists rather than a TCP
    check: both boundaries accept connections, and only one of them can
    serve a read."""
    with _wire("127.0.0.1:1") as (listen, metrics):
        code, body = _health(metrics)
        assert _tcp(listen) is True, (
            "the control: the listen port is open either way, which is "
            "exactly why probing it is not a readiness check")
        assert code == 503
        assert "cannot reach" in body


def test_the_probe_recovers_rather_than_remembering_a_failure(db):
    """A boundary that cached "unhealthy" would never come back into
    service after its deployment did."""
    with _wire(mongo_host()) as (_listen, metrics):
        assert _health(metrics)[0] == 200
        assert _health(metrics)[0] == 200


def test_health_carries_no_numbers(db):
    """It is the endpoint chosen for being reachable, so it must not leak
    what the exposition deliberately keeps on loopback: a refusal count
    broken down by reason describes a corpus."""
    with _wire(mongo_host()) as (_listen, metrics):
        _code, body = _health(metrics)
        assert body == "ok"
        assert "refused" not in body and "voyd_" not in body


# ---- the command a container's HEALTHCHECK runs --------------------------

def test_the_health_command_agrees_with_the_endpoint(db):
    with _wire(mongo_host()) as (_listen, metrics):
        assert health_main(["--port", str(metrics)]) == 0


def test_the_health_command_fails_when_the_upstream_is_gone():
    with _wire("127.0.0.1:1") as (_listen, metrics):
        assert health_main(["--port", str(metrics)]) == 1


def test_the_health_command_fails_when_nothing_is_listening():
    """A slim image has no curl, so this is what the HEALTHCHECK runs. It
    has to exit non-zero rather than raise: a checker that crashes is
    reported as the checker being broken, not the thing it checks."""
    assert health_main(["--port", str(free_port())]) == 1


# ---- and the operator's other first questions ----------------------------

def test_the_version_is_answerable_without_starting_anything():
    out = subprocess.run([sys.executable, "-m", "voyd.wire", "--version"],
                         cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert out.returncode == 0
    assert __version__ in out.stdout

def test_the_help_names_the_command_and_not_the_file():
    """argparse defaults `prog` to `sys.argv[0]`, so `--help` named
    `__main__.py` under `-m` and an absolute path under a systemd unit. A
    usage line somebody copies should be the command they typed."""
    out = subprocess.run([sys.executable, "-m", "voyd.wire", "--help"],
                         cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert out.stdout.startswith("usage: voyd-wire")


def test_the_module_form_does_not_warn():
    """An import of `main` in `voyd/wire/__init__.py` makes `-m
    voyd.wire.proxy` load the package and then re-execute the module, and
    Python says so on stderr -- the first line of every container's log,
    read by somebody who is already worried. So there are no imports in
    that file at all."""
    for form in ("voyd.wire", "voyd.wire.proxy"):
        out = subprocess.run([sys.executable, "-m", form, "--version"],
                             cwd=ROOT, capture_output=True, text=True,
                             timeout=60)
        assert out.returncode == 0, form
        assert "RuntimeWarning" not in out.stderr, form
        assert out.stderr.strip() == "", f"{form} wrote {out.stderr!r}"
