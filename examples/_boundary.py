"""Start the boundary, hand back a plain driver. Used by every example.

Not an example itself -- running it does nothing, which is deliberate, since
CI runs `examples/*.py` and this file has to be safe in that glob.

It exists because every example below now tells the same story and the
bootstrap is the least interesting part of it: write a policy file, start
`voyd-wire` against the deployment, point an ordinary `pymongo.MongoClient`
at the proxy. The client each example goes on to use imports `MongoClient`
and nothing else, which is the entire claim -- everything demonstrated is
equally true of the Node driver, of Compass, and of a notebook, because they
all send the same bytes.

The *direct* connection is handed back too, and every example uses it. An
assertion that a fact is unreachable through the boundary is worth little
without the one beside it saying the row is still on disk; together they are
the difference between a refusal and a delete.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# The examples all read the same variable, so one export points every one of
# them at Atlas instead of the local container.
URI = os.getenv("VOYD_MONGO_URI",
                "mongodb://localhost:27018/?directConnection=true")


def target() -> str:
    """What `--target` should be, from whatever `VOYD_MONGO_URI` says."""
    return URI if URI.startswith("mongodb+srv://") else \
        URI.split("//", 1)[1].split("/", 1)[0]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def database(slug: str) -> str:
    return f"voyd_example_{slug}_{uuid.uuid4().hex[:8]}"


@contextmanager
def boundary(policy: str, *extra: str, wait_s: float = 30.0):
    """Serve `policy` in front of the deployment. Yields a proxy URI.

    The policy file is written to a temporary directory rather than into
    the repository, because an example that leaves a `voydfile.py` behind
    teaches the wrong thing about where policy lives.
    """
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "voydfile.py"
        path.write_text(policy)
        port = free_port()
        proc = subprocess.Popen(
            [sys.executable, "-m", "voyd.wire", "--config", str(path),
             "--listen", str(port), "--target", target(), *extra],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True)
        try:
            until = time.monotonic() + wait_s
            while time.monotonic() < until:
                if proc.poll() is not None:
                    raise SystemExit(
                        f"voyd-wire exited before it listened:\n"
                        f"{proc.stdout.read() if proc.stdout else ''}")
                try:
                    with socket.create_connection(("127.0.0.1", port), 0.2):
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                raise SystemExit("voyd-wire never started listening")
            yield f"mongodb://localhost:{port}/?directConnection=true"
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


@contextmanager
def deployment(slug: str):
    """A throwaway database and a direct client, dropped afterwards."""
    from pymongo import MongoClient

    direct = MongoClient(URI)
    name = database(slug)
    try:
        yield direct, name
    finally:
        direct.drop_database(name)
        direct.close()


if __name__ == "__main__":
    print("examples/_boundary.py is a helper, not an example. "
          "Run one of the others.")
