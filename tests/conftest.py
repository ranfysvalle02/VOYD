"""One fixture, and a small suite on purpose.

The previous suite ran 817 checks and is in `git log`. This is not that. It
is the foundation the rewrite stands on: the smallest set of claims that, if
any one of them broke, would make everything above it a lie.

Three of the four files here need no MongoDB at all, which is the point --
the per-document check and the wire codec are pure, and a boundary whose core
cannot be tested without a database is a boundary that will not move to
another one.
"""

from __future__ import annotations

import os
import pathlib
import socket
import uuid

import pytest

def _load_dotenv() -> None:
    """Read `.env` if it is there, without overriding the real environment.

    Not a convenience. Server-side embedding only exists on a real Atlas
    cluster -- Atlas Local registers no models -- so the one test that can
    prove `auto_embed` needs a live URI, and the place this project keeps one
    is `.env`. It is gitignored; nothing here ever prints a value.
    """
    path = pathlib.Path(__file__).resolve().parents[1] / ".env"
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


_load_dotenv()

# Everything runs against this. Atlas Local by default; point it at a real
# cluster and the whole suite goes with it.
MONGO_URI = os.environ.get(
    "VOYD_TEST_MONGO_URI", "mongodb://localhost:27018/?directConnection=true")

# A real Atlas cluster, when one is configured. Only the server-side
# embedding test requires it, because that feature does not exist anywhere
# else -- and a test that silently fell back to a client-supplied vector
# would be asserting the opposite of what it claims.
ATLAS_URI = os.environ.get("VOYD_ATLAS_URI")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def mongo_host() -> str:
    """``host:port`` out of the test URI, as ``--target`` wants it."""
    hostport = MONGO_URI.split("//", 1)[1].split("/", 1)[0]
    return hostport if ":" in hostport else f"{hostport}:27017"


@pytest.fixture
def db():
    """A throwaway database, dropped afterwards. Skips if nothing is there."""
    pymongo = pytest.importorskip("pymongo")
    client = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)
    try:
        client.admin.command("ping")
    except Exception:
        pytest.skip(f"no MongoDB at {MONGO_URI}")
    name = f"voyd_test_{uuid.uuid4().hex[:10]}"
    try:
        yield client[name]
    finally:
        client.drop_database(name)
        client.close()


@pytest.fixture
def atlas():
    """A throwaway database on a real Atlas cluster, dropped afterwards."""
    if not ATLAS_URI:
        pytest.skip("set VOYD_ATLAS_URI (or put it in .env) for the "
                    "server-side embedding test")
    pymongo = pytest.importorskip("pymongo")
    client = pymongo.MongoClient(ATLAS_URI, serverSelectionTimeoutMS=15000)
    try:
        client.admin.command("ping")
    except Exception as exc:
        pytest.skip(f"Atlas unreachable: {type(exc).__name__}")
    name = f"voyd_test_{uuid.uuid4().hex[:10]}"
    try:
        yield ATLAS_URI, name
    finally:
        client.drop_database(name)
        client.close()
