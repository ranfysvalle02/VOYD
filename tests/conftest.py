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
import socket
import uuid

import pytest

MONGO_URI = os.environ.get(
    "VOYD_TEST_MONGO_URI", "mongodb://localhost:27018/?directConnection=true")


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
