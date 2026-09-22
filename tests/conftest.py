"""What the live tests connect to, and the promise that they leave nothing.

Two jobs, and the second is the one worth reading.

**Finding a cluster.** The integration half needs a real deployment -- a real
`mongod`, a real `mongot`, a real search index -- because its claims are
about queries and bytes, and a mock would only prove the mock was filtered.
The URI comes from the environment, and from a `.env` beside the compose file
if there is one, so that running the suite is the same gesture as running the
examples. No cluster, no guessing: the tests skip, loudly, by name.

**Leaving nothing behind.** Every live test runs in a database named for this
run and drops it when it ends, whatever happened -- and "whatever happened"
includes the interesting cases, because a test that only cleans up when it
passes stops cleaning up exactly when it starts failing. Search indexes go
with the database, TTL and tenant indexes go with the collections, the proxy
is terminated and then killed if it will not go, and the temporary policy
file goes with pytest's own `tmp_path`.

Nothing here touches a database the caller already had. The throwaway name
carries a uuid, so two runs on one cluster -- a laptop and CI against the
same Atlas project -- cannot collide or clean up after each other, and an
epoch, which is what lets a later run identify a database an *earlier* one
abandoned. That second half is not decoration: `kill -9`, a closed laptop
and a reclaimed CI runner all run no finaliser, and without a timestamp the
wreckage is indistinguishable from a suite that is running right now.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[1]

# In the order a deployment means them: the variable set for the suite, then
# the one the examples read, then a plain Atlas string. `VOYD_TEST_MONGO_URI`
# wins so that pointing the examples at a scratch cluster does not silently
# move the tests too.
URI_VARS = ("VOYD_TEST_MONGO_URI", "VOYD_MONGO_URI", "VOYD_ATLAS_URI",
            "MONGODB_URI")

# The cluster that can embed. `auto_embed` means mongot owns the encoding,
# and only a real Atlas deployment registers a model -- Atlas Local
# *declines* the declaration, which is a different outcome and not a
# weaker one, so the test that needs it says so rather than accepting the
# fallback and asserting the opposite of what it claims.
ATLAS_VAR = "VOYD_ATLAS_URI"

# The model the server is asked to embed with. Read from the environment
# because it is a property of the cluster's Atlas project, not of this
# repository: a deployment that has not registered `voyage-4` needs the
# name it did register, and hard-coding one would make this file the
# thing to edit.
MODEL = os.environ.get("VOYAGE_MODEL") or "voyage-4"

# How long a throwaway database has to have been abandoned before this
# suite will clean it up. Test databases carry the epoch second they were
# created in, so a crashed or killed run leaves one behind and the next
# run sweeps it -- while a suite running *concurrently* on the same
# cluster is never inside the window and is never touched.
STALE_AFTER_S = 2 * 60 * 60


def _load_dotenv() -> None:
    """Read `.env` into the environment without overriding what is set.

    Deliberately not a dependency. A four-line parser that understands
    `KEY=value`, `export KEY=value`, comments and quotes is the whole of
    what this file needs, and an already-exported variable still wins --
    so `VOYD_TEST_MONGO_URI=... pytest` points at another cluster without
    editing anything.
    """
    path = ROOT / ".env"
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        line = line.removeprefix("export ").strip()
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key, value = key.strip(), value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


_load_dotenv()


def mongo_uri() -> str | None:
    for var in URI_VARS:
        value = os.environ.get(var, "").strip()
        if value.startswith("mongodb://") or value.startswith("mongodb+srv://"):
            return value
    return None


def _reachable(candidate: str) -> str | None:
    """`candidate`, or a direct-connection form of it, or None.

    A single-host URI carrying `replicaSet=` is the one configuration that
    fails for a reason that has nothing to do with this suite: the set
    name in somebody's `.env` outlives the container that had it, and
    pymongo then refuses to select a server that is up and answering. The
    boundary itself dials `directConnection`, so the fallback is the
    connection the product makes rather than a special case invented here
    -- and it is a *fallback*, tried only after the URI as written.
    """
    from pymongo import MongoClient

    forms = [candidate]
    single = "," not in urlsplit(candidate).netloc
    if single and not candidate.startswith("mongodb+srv://"):
        base = candidate.split("?", 1)[0]
        forms.append(f"{base}?directConnection=true")
    for form in forms:
        client = MongoClient(form, serverSelectionTimeoutMS=8000)
        try:
            client.admin.command("ping")
            return form
        except Exception:                                      # noqa: BLE001
            continue
        finally:
            client.close()
    return None


@pytest.fixture(scope="session")
def uri() -> str:
    found = mongo_uri()
    if not found:
        pytest.skip(f"no cluster: set one of {', '.join(URI_VARS)} "
                    f"(or run `docker compose up -d mongo`)")
    usable = _reachable(found)
    if not usable:
        pytest.skip("cluster unreachable")
    return usable


@pytest.fixture(scope="session")
def atlas_uri() -> str:
    """A cluster with a mongot that will embed. Skipped, never faked."""
    found = os.environ.get(ATLAS_VAR, "").strip()
    if not found.startswith(("mongodb://", "mongodb+srv://")):
        pytest.skip(f"{ATLAS_VAR} is not set: server-side embedding needs a "
                    f"real Atlas cluster with a registered model")
    usable = _reachable(found)
    if not usable:
        pytest.skip(f"{ATLAS_VAR} is set but the cluster is unreachable")
    return usable


@pytest.fixture(scope="session")
def direct(uri):
    """A client straight at the deployment, around the boundary.

    Every assertion about refusal needs this one as well as the guarded
    one: "the row is still on disk" and "the boundary refused it" are two
    statements, and only the unguarded client can make the first.
    """
    from pymongo import MongoClient

    client = MongoClient(uri, serverSelectionTimeoutMS=10_000)
    try:
        client.admin.command("ping")
    except Exception as exc:                                   # noqa: BLE001
        client.close()
        pytest.skip(f"cluster unreachable: {type(exc).__name__}")
    # Pay off the previous run's debts before making any of this run's.
    # Attached to the client rather than run as an autouse fixture, so a
    # pure-test session -- the one CI runs with no `services:` at all --
    # never opens a socket to do it.
    try:
        for name in sweep(client):
            print(f"swept an abandoned test database: {name}")
    except Exception as exc:                                   # noqa: BLE001
        # Housekeeping must never be the reason a run fails: that would
        # make a stranger's first `pytest` red for a permission this
        # suite does not actually need.
        print(f"could not sweep ({type(exc).__name__}: {exc})")
    try:
        yield client
    finally:
        client.close()


def scratch_name() -> str:
    """`voyd_test_<epoch>_<uuid>`. Both halves earn their place.

    The uuid is what makes two runs against one Atlas project unable to
    collide -- with a fixed name the second run's cleanup would delete the
    first run's data mid-test. The epoch is what makes an *abandoned*
    database identifiable later: a `kill -9` runs no finaliser, and
    without a timestamp the leftovers are indistinguishable from a suite
    that is running right now.
    """
    return f"voyd_test_{int(time.time())}_{uuid.uuid4().hex[:8]}"


def sweep(client, *, now: float | None = None) -> list[str]:
    """Drop test databases abandoned by an earlier run. Returns what went.

    This is the half a `finally` block cannot do. Everything below cleans
    up after itself on every exit path the interpreter is given a chance
    to take -- and `kill -9`, a laptop lid, and a CI runner reclaimed
    mid-job are not among them. So each run also pays off the previous
    one's debts, bounded by `STALE_AFTER_S` so it can never reach a
    database a concurrent run is still using.
    """
    cutoff = (now or time.time()) - STALE_AFTER_S
    dropped = []
    for name in client.list_database_names():
        parts = name.split("_")
        if len(parts) != 4 or not name.startswith("voyd_test_"):
            continue
        try:
            stamp = int(parts[2])
        except ValueError:
            continue
        if stamp < cutoff:
            client.drop_database(name)
            dropped.append(name)
    return dropped


@pytest.fixture
def database(direct) -> str:
    """A database named for this test, dropped when it ends."""
    name = scratch_name()
    try:
        yield name
    finally:
        # Unconditional, and it must stay that way: a cleanup that only runs
        # on the happy path stops running exactly when a failing test starts
        # leaving rows behind. Search indexes and TTL indexes are dropped
        # with the database they live in.
        direct.drop_database(name)


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class Boundary:
    """A real `voyd-wire` on a real port, with a client pointed at it."""

    def __init__(self, port: int, database: str, auth: str = ""):
        self.port = port
        self.database = database
        # The credentials the *caller* presents, which are the caller's and
        # not the boundary's. `voyd-wire` does not authenticate on anybody's
        # behalf -- it forwards the handshake and then asks the deployment
        # who authenticated, because a rule that believed a claim the client
        # asserted would be an authorisation system whose only input is the
        # attacker's. A deployment with `--auth` on therefore needs the
        # client to carry credentials to the boundary exactly as it would
        # carry them to the cluster.
        self.auth = auth

    @property
    def uri(self) -> str:
        source = f"{self.auth}@" if self.auth else ""
        extra = "&authSource=admin" if self.auth else ""
        return (f"mongodb://{source}127.0.0.1:{self.port}/"
                f"?directConnection=true{extra}")


@pytest.fixture
def boundary(uri, database, tmp_path):
    """Start `voyd-wire` in front of the cluster with a given policy.

    A subprocess rather than an in-process call, because the claim is that
    any driver in any language reaches this through a socket -- and an
    in-process boundary would be a different thing wearing the same name.

    Returns a factory: a test writes its policy, gets a `Boundary`, and the
    process is terminated (then killed) and the policy file removed on the
    way out no matter how the test ended.
    """
    started: list[subprocess.Popen] = []

    def start(policy: str, *extra: str, ensure: bool = False,
              target: str | None = None, db: str | None = None) -> Boundary:
        # `target` and `db` default to the session's cluster and this
        # test's throwaway database. They are arguments rather than
        # fixtures because one test needs a *different* cluster -- the
        # Atlas one that can embed -- and a boundary pointed at one
        # deployment while its driver writes to another is a failure that
        # reads exactly like a broken index.
        path = tmp_path / f"voydfile_{uuid.uuid4().hex[:6]}.py"
        path.write_text(policy)
        port = free_port()
        dialed = target or uri
        dialed = dialed if "://" in dialed else f"mongodb://{dialed}"
        # Lifted from the target rather than configured again: the identity
        # the tests use is the deployment's, and two places to write it is
        # one place for them to disagree.
        netloc = urlsplit(dialed).netloc
        auth = netloc.rsplit("@", 1)[0] if "@" in netloc else ""
        argv = [sys.executable, "-m", "voyd.wire",
                "--config", str(path), "--listen", str(port),
                "--target", dialed, "--quiet", *extra]
        if ensure:
            argv += ["--ensure", db or database]
        proc = subprocess.Popen(argv, cwd=ROOT, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True)
        started.append(proc)

        # `--ensure` builds indexes before it binds anything, and a
        # server-embedded index on a real Atlas cluster is minutes of
        # mongot's time, not ours. An ordinary boundary that has not
        # listened in a minute is broken, so the two waits are different
        # numbers rather than one pessimistic one.
        until = time.monotonic() + (420 if ensure else 60)
        while time.monotonic() < until:
            if proc.poll() is not None:
                raise AssertionError(
                    f"voyd-wire exited {proc.returncode} before listening:\n"
                    f"{(proc.stdout.read() if proc.stdout else '')[-2000:]}")
            try:
                with socket.create_connection(("127.0.0.1", port), 0.2):
                    return Boundary(port, db or database, auth)
            except OSError:
                time.sleep(0.1)
        raise AssertionError("voyd-wire never listened")

    try:
        yield start
    finally:
        for proc in started:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
