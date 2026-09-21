"""One fixture, a sweeper, and a small suite on purpose.

The previous suite ran 817 checks and is in `git log`. This is not that. It
is the foundation the rewrite stands on: the smallest set of claims that, if
any one of them broke, would make everything above it a lie.

Most of the files here need no MongoDB at all, which is the point -- the
per-document check and the wire codec are pure, and a boundary whose core
cannot be tested without a database is a boundary that will not move to
another one.
"""

from __future__ import annotations

import os
import pathlib
import re
import socket
import time
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

# A real three-node replica set (`docker compose up rs`). Fan-out is the one
# claim the default deployment cannot test: Atlas Local is a single-node set,
# so it has a primary and nothing to fan out to, and every routing assertion
# against it would pass by having nowhere else to go.
#
# It authenticates, and that is load-bearing rather than tidy: fan-out has
# to open a connection of its own to a secondary and prove an identity on
# it, so a rig without `--auth` would exercise the one path that needs no
# SCRAM at all.
RS_URI = os.environ.get(
    "VOYD_TEST_RS_URI",
    "mongodb://voyd:voyd@localhost:27021,localhost:27022,localhost:27023"
    "/?replicaSet=voydrs&authSource=admin")

# ---------------------------------------------------------------------------
# Leaked databases, and why this exists.
#
# A search index is not free. `mongot` is shared across every database on a
# deployment, so a laptop carrying a dozen abandoned test databases builds
# new indexes slowly enough that a healthy test times out -- which is how
# this got written: nine leftover databases, 24 search indexes, and an index
# test that failed for a reason that had nothing to do with refusal.
#
# The previous suite had a sweeper for exactly this and the rewrite deleted
# it. Restoring it, with the one subtlety that version had already learned
# the hard way.
# ---------------------------------------------------------------------------

# The suite's own databases. Timestamped so the sweep can tell a run that is
# *happening* from one that was abandoned.
TEST_PREFIX = "voyd_test_"
# The examples' databases. Not timestamped -- they are standalone teaching
# files and a clock in the name would be noise -- so they are only ever swept
# at session start, before any example in this session could have created
# one. Sweeping those mid-run is precisely the bug that once deleted a
# running demo's data out from under it.
EXAMPLE_PREFIX = "voyd_example_"
ABANDONED_AFTER = 15 * 60


def throwaway_name() -> str:
    """A database name a sweep can reason about.

    The timestamp is the whole point. Without it the only way to decide
    whether a database is abandoned is to guess, and the guess that seems
    obvious -- "I do not recognise this, drop it" -- deletes the data of a
    second test run happening at the same time.
    """
    return f"{TEST_PREFIX}{int(time.time())}_{uuid.uuid4().hex[:8]}"


def _abandoned(name: str, *, now: float) -> bool:
    match = re.fullmatch(rf"{TEST_PREFIX}(\d+)_[0-9a-f]+", name)
    if not match:
        return False            # not ours, or not a shape we can date: leave it
    return (now - int(match.group(1))) > ABANDONED_AFTER


@pytest.fixture(scope="session", autouse=True)
def _sweep_leaked_databases():
    """Drop what previous runs left behind, then report what this one does.

    Two sweeps with different rules, because "might be in use right now" is
    true of one prefix and cannot be true of the other.
    """
    pymongo = pytest.importorskip("pymongo")
    try:
        client = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)
        client.admin.command("ping")
    except Exception:
        yield                   # no database: nothing to sweep, nothing to leak
        return

    now = time.time()
    swept = [n for n in client.list_database_names()
             if _abandoned(n, now=now) or n.startswith(EXAMPLE_PREFIX)]
    for name in swept:
        client.drop_database(name)
    if swept:
        print(f"\nswept {len(swept)} leaked database(s) from earlier runs")

    yield

    # Not a failure -- a report. A leak is worth knowing about and is not
    # worth turning somebody's green run red, and the next session's sweep
    # will collect it anyway.
    left = [n for n in client.list_database_names()
            if n.startswith((TEST_PREFIX, EXAMPLE_PREFIX))]
    if left:
        print(f"\n{len(left)} test database(s) survived this run: "
              f"{', '.join(sorted(left)[:5])}"
              f"{' …' if len(left) > 5 else ''}")
    client.close()


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
    name = throwaway_name()
    try:
        yield client[name]
    finally:
        client.drop_database(name)
        client.close()


@pytest.fixture(scope="session")
def replica_set():
    """The three-node set, or a skip. Yields the URI.

    Session-scoped because electing a replica set costs seconds and nothing
    in these tests mutates the topology permanently.
    """
    pymongo = pytest.importorskip("pymongo")
    client = pymongo.MongoClient(RS_URI, serverSelectionTimeoutMS=4000)
    try:
        client.admin.command("ping")
        if len(client.secondaries) < 2:
            pytest.skip("the replica set has no secondaries to rank on")
    except Exception:
        pytest.skip(f"no replica set at {RS_URI} -- `docker compose up -d rs`")
    finally:
        client.close()
    return RS_URI


@pytest.fixture
def rs_db(replica_set):
    """A throwaway database on the replica set, dropped afterwards."""
    pymongo = pytest.importorskip("pymongo")
    client = pymongo.MongoClient(replica_set, serverSelectionTimeoutMS=8000)
    name = throwaway_name()
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
    name = throwaway_name()
    try:
        yield ATLAS_URI, name
    finally:
        client.drop_database(name)
        client.close()
