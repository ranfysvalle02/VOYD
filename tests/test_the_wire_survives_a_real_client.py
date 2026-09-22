"""What a driver keeps when its connection string points here instead.

The README claims one connection string is the whole integration. That
sentence is only true if the *stateful* parts of the protocol survive the
crossing -- and they are the parts a boundary is most likely to break,
because each one binds to a connection rather than to a message:

    sessions       an `lsid` the server tracks, and causal consistency
                   built on operation times the client echoes back
    transactions   several messages that are one atomic unit, with the
                   commit on a different message from the writes
    cursors        a `getMore` is a second request whose meaning depends
                   entirely on what the first one returned
    failover       the address the boundary forwards to is a lifecycle,
                   not a value

A per-message check that quietly dropped a session id, resolved a cursor
against the wrong connection, or cached a primary forever would pass every
test in the rest of this suite. Each of these needs a real server, a real
driver and a real replica set, because the failure is the interaction.

`stepped_down` is asked as a pure function at the bottom: it reads the
reply a client was getting anyway, and the nested case is the one that
matters, so it is worth checking without a cluster in the way.
"""

from __future__ import annotations

import os
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, OperationFailure

from tests.conftest import _reachable, scratch_name

UTC = timezone.utc

POLICY = """
from voyd import guard, deadline, revocable, tenant

@guard("notes", on_delete="revoke")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()
"""

# The three-node set from docker-compose, which exists for the one claim
# Atlas Local cannot make: it is a single node, so every failover assertion
# against it would pass by having nowhere else to go. It also runs with
# `--auth`, which is the other half -- a deployment where nobody
# authenticated answers every caller-identity question the same way.
RS_URI = ("mongodb://voyd:voyd@localhost:27021,localhost:27022,"
          "localhost:27023/?authSource=admin&replicaSet=voydrs")


def past() -> datetime:
    return datetime.now(UTC) - timedelta(hours=1)


def future() -> datetime:
    return datetime.now(UTC) + timedelta(days=1)


@pytest.fixture
def guarded(boundary, database):
    wire = boundary(POLICY)
    client = MongoClient(wire.uri, serverSelectionTimeoutMS=15_000)
    try:
        yield client, client[database].notes
    finally:
        client.close()


# ---- sessions ----------------------------------------------------------

@pytest.mark.needs_mongo
def test_a_session_crosses_the_boundary_and_reads_its_own_write(guarded):
    # An `lsid` the boundary dropped or rewrote would not error -- the
    # server would simply treat every operation as its own session, and
    # causal consistency would quietly stop holding.
    client, notes = guarded
    with client.start_session(causal_consistency=True) as s:
        notes.insert_one({"_id": "n1", "tenant_id": "acme",
                          "expire_at": future()}, session=s)
        got = notes.find_one({"tenant_id": "acme"}, session=s)
        assert got is not None and got["_id"] == "n1"
        # The session has an operation time now, which is the evidence the
        # server tracked it rather than the boundary inventing a reply.
        assert s.operation_time is not None
        assert s.cluster_time is not None


@pytest.mark.needs_mongo
def test_refusal_holds_inside_a_session_as_well_as_outside_one(guarded):
    client, notes = guarded
    notes.insert_many([
        {"_id": "live", "tenant_id": "acme", "expire_at": future()},
        {"_id": "gone", "tenant_id": "acme", "expire_at": past()},
    ])
    with client.start_session(causal_consistency=True) as s:
        served = [d["_id"] for d in notes.find({"tenant_id": "acme"},
                                               session=s)]
    assert served == ["live"], "a session was a way around the boundary"


@pytest.mark.needs_mongo
def test_two_sessions_on_one_connection_do_not_become_one(guarded):
    # The boundary keeps per-connection state (the caller's identity, the
    # ids whose refusal was pushed down). Keyed by the wrong thing, two
    # sessions sharing a socket would read each other's.
    client, notes = guarded
    notes.insert_many([
        {"_id": "a", "tenant_id": "acme", "expire_at": future()},
        {"_id": "b", "tenant_id": "globex", "expire_at": future()},
    ])
    with client.start_session() as first, client.start_session() as second:
        assert first.session_id != second.session_id
        mine = [d["_id"] for d in notes.find({"tenant_id": "acme"},
                                             session=first)]
        theirs = [d["_id"] for d in notes.find({"tenant_id": "globex"},
                                               session=second)]
    assert mine == ["a"] and theirs == ["b"]


# ---- transactions ------------------------------------------------------

@pytest.mark.needs_mongo
def test_a_transaction_commits_through_the_boundary_as_one_unit(
        guarded, direct, database):
    # The commit is a *different message* from the writes, on the same
    # connection, and it is the one a boundary is most likely to mangle.
    client, notes = guarded
    with client.start_session() as s:
        with s.start_transaction():
            notes.insert_one({"_id": "t1", "tenant_id": "acme",
                              "expire_at": future()}, session=s)
            notes.insert_one({"_id": "t2", "tenant_id": "acme",
                              "expire_at": future()}, session=s)
            # Uncommitted, so nobody outside the transaction sees them --
            # including a client that goes around the boundary entirely.
            assert direct[database].notes.count_documents({}) == 0
    assert direct[database].notes.count_documents({}) == 2
    assert sorted(d["_id"] for d in notes.find({"tenant_id": "acme"})) \
        == ["t1", "t2"]


@pytest.mark.needs_mongo
def test_an_aborted_transaction_leaves_nothing_behind(guarded, direct,
                                                      database):
    client, notes = guarded
    with client.start_session() as s:
        s.start_transaction()
        notes.insert_one({"_id": "t1", "tenant_id": "acme",
                          "expire_at": future()}, session=s)
        s.abort_transaction()
    assert direct[database].notes.count_documents({}) == 0


@pytest.mark.needs_mongo
def test_a_read_inside_a_transaction_still_refuses(guarded, direct,
                                                   database):
    # A transaction is a place a per-message check can lose its place: the
    # reads carry the same `lsid` and a `txnNumber`, and the refusal has to
    # apply to them exactly as it does outside.
    client, notes = guarded
    direct[database].notes.insert_many([
        {"_id": "live", "tenant_id": "acme", "expire_at": future()},
        {"_id": "gone", "tenant_id": "acme", "expire_at": past()},
        {"_id": "revoked", "tenant_id": "acme", "expire_at": future(),
         "forgotten": {"at": past()}},
    ])
    with client.start_session() as s:
        with s.start_transaction():
            served = [d["_id"] for d in notes.find({"tenant_id": "acme"},
                                                   session=s)]
    assert served == ["live"]


# ---- cursors, and more than one at a time ------------------------------

@pytest.mark.needs_mongo
def test_several_cursors_interleave_on_one_connection_without_crossing(
        guarded, direct, database):
    # A `getMore` means nothing on its own: its meaning is the cursor the
    # first reply opened. Three cursors advanced round-robin on one socket
    # is how a boundary that keyed anything by connection instead of by
    # cursor id gets caught.
    client, notes = guarded
    rows = []
    for tenant in ("acme", "globex", "initech"):
        rows += [{"_id": f"{tenant}{i}", "tenant_id": tenant,
                  "expire_at": future() if i % 2 else past()}
                 for i in range(40)]
    direct[database].notes.insert_many(rows)

    cursors = {t: notes.find({"tenant_id": t}, batch_size=3).sort("_id")
               for t in ("acme", "globex", "initech")}
    seen: dict[str, list] = {t: [] for t in cursors}
    alive = dict(cursors)
    while alive:
        for tenant, cursor in list(alive.items()):
            try:
                seen[tenant].append(next(cursor))
            except StopIteration:
                alive.pop(tenant)
    for tenant, docs in seen.items():
        # Its own tenant, and only the live half of it -- named exactly,
        # across every batch, with two other cursors advancing in between.
        # `i % 2` put the deadline in the future for the odd ones.
        assert {d["tenant_id"] for d in docs} == {tenant}
        assert sorted(d["_id"] for d in docs) == sorted(
            f"{tenant}{i}" for i in range(40) if i % 2)
    for cursor in cursors.values():
        cursor.close()


@pytest.mark.needs_mongo
def test_many_clients_page_at_once_and_none_sees_anothers_rows(
        boundary, direct, database):
    # One upstream connection per client is the design; this is the
    # assertion that pays for it. Sharing one would hand a cursor to
    # whoever asked second, and the symptom would be exactly this test's
    # failure mode -- another tenant's row in your page.
    wire = boundary(POLICY)
    tenants = [f"t{i}" for i in range(8)]
    rows = []
    for tenant in tenants:
        rows += [{"_id": f"{tenant}_{i}", "tenant_id": tenant,
                  "expire_at": future() if i % 2 else past()}
                 for i in range(60)]
    direct[database].notes.insert_many(rows)

    results: dict[str, list] = {}
    errors: list[BaseException] = []

    def page(tenant: str) -> None:
        client = MongoClient(wire.uri, serverSelectionTimeoutMS=20_000)
        try:
            got = [d["_id"] for d in
                   client[database].notes.find({"tenant_id": tenant},
                                               batch_size=4).sort("_id")]
            results[tenant] = got
        except BaseException as exc:                       # noqa: BLE001
            errors.append(exc)
        finally:
            client.close()

    threads = [threading.Thread(target=page, args=(t,)) for t in tenants]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)

    assert not errors, f"a concurrent client failed: {errors[:2]}"
    assert set(results) == set(tenants)
    for tenant, ids in results.items():
        assert len(ids) == 30, f"{tenant} got {len(ids)} rows, not 30"
        assert all(i.startswith(f"{tenant}_") for i in ids), \
            "a client was served another tenant's rows"


@pytest.mark.needs_mongo
def test_a_cursor_survives_being_left_open_and_closed_by_the_client(
        guarded, direct, database):
    # `killCursors` is its own command, and a boundary that lost it leaks
    # a cursor on the server for every abandoned page.
    client, notes = guarded
    direct[database].notes.insert_many(
        [{"_id": f"n{i}", "tenant_id": "acme", "expire_at": future()}
         for i in range(50)])
    cursor = notes.find({"tenant_id": "acme"}, batch_size=5)
    assert next(cursor)["tenant_id"] == "acme"
    cursor.close()
    # And the connection is still usable afterwards, which is the part a
    # mishandled `killCursors` reply breaks.
    assert notes.count_documents({"tenant_id": "acme"}) == 50


# ---- failover ----------------------------------------------------------

def _rs_available() -> str | None:
    if os.environ.get("VOYD_SKIP_RS"):
        return None
    return _reachable(RS_URI)


@pytest.mark.needs_mongo
@pytest.mark.slow
def test_the_boundary_follows_an_election_without_being_restarted(boundary):
    """An address is a lifecycle, not a value.

    Resolved once at startup, a failover means a restart -- which is the
    operability complaint `Upstream` exists to answer. The claim is that
    the server's own error invalidates the cache and the *next* connection
    re-resolves, so this causes a real election rather than waiting for
    one, and then asks a fresh client to work.
    """
    usable = _rs_available()
    if not usable:
        pytest.skip("the three-node replica set is not up "
                    "(docker compose up -d rs)")

    admin = MongoClient(usable, serverSelectionTimeoutMS=15_000)
    database = scratch_name()
    try:
        # `ping` first. A driver connects lazily, so `.primary` on an
        # undiscovered topology is `None` -- the same trap `Upstream._resolve`
        # documents, and this test fell into it before the comment was read.
        admin.admin.command("ping")
        was = admin.primary
        assert was is not None, "no primary to step down"
        wire = boundary(POLICY, target=usable, db=database)

        client = MongoClient(wire.uri, serverSelectionTimeoutMS=20_000)
        try:
            notes = client[database].notes
            notes.insert_one({"_id": "before", "tenant_id": "acme",
                              "expire_at": future()})
            assert notes.find_one({"tenant_id": "acme"})["_id"] == "before"
        finally:
            client.close()

        # Cause the election. `force` because a stepdown otherwise waits
        # for a secondary to catch up, and an outage you have to wait for
        # is one you are reasoning about rather than measuring.
        try:
            admin.admin.command("replSetStepDown", 30, force=True)
        except (OperationFailure, ConnectionFailure):
            pass                     # the command kills its own connection

        until = time.monotonic() + 90
        now = None
        while time.monotonic() < until:
            try:
                admin.admin.command("ping")
                now = admin.primary
                if now is not None and now != was:
                    break
            except (OperationFailure, ConnectionFailure):
                pass
            time.sleep(1)
        assert now is not None and now != was, (
            f"no election happened: primary is still {was}")

        # The boundary still has the old primary cached. Its first attempt
        # gets the server's own `NotWritablePrimary`, which is what
        # invalidates it -- so what is asserted is convergence within a
        # few fresh connections, not that the first one is lucky.
        deadline = time.monotonic() + 90
        wrote = False
        attempts = 0
        while time.monotonic() < deadline and not wrote:
            attempts += 1
            probe = MongoClient(wire.uri, serverSelectionTimeoutMS=10_000)
            try:
                probe[database].notes.insert_one(
                    {"_id": f"after{attempts}", "tenant_id": "acme",
                     "expire_at": future()})
                wrote = True
            except (OperationFailure, ConnectionFailure):
                time.sleep(2)
            finally:
                probe.close()
        assert wrote, (f"the boundary never followed the election "
                       f"({attempts} attempts); it would need a restart")

        # And it is still a boundary, not just a pipe: the new primary's
        # reads refuse exactly as the old one's did.
        after = MongoClient(wire.uri, serverSelectionTimeoutMS=20_000)
        try:
            notes = after[database].notes
            notes.insert_one({"_id": "expired", "tenant_id": "acme",
                              "expire_at": past()})
            served = [d["_id"] for d in notes.find({"tenant_id": "acme"})]
            assert "expired" not in served
            assert "before" in served
        finally:
            after.close()
    finally:
        try:
            admin.drop_database(database)
        finally:
            admin.close()


# ---- the reply that causes all of the above, read as a pure function ---

def test_a_stepdown_is_recognised_wherever_the_server_puts_it():
    from voyd.wire.upstream import STEPPED_DOWN, stepped_down

    assert stepped_down({"ok": 1}) is None
    assert stepped_down({"ok": 0, "code": 10107,
                         "codeName": "NotWritablePrimary"}) \
        == "NotWritablePrimary"
    # Nested inside a batch is where this hides on exactly the command
    # the boundary rewrites -- a delete -- and reading only the top level
    # is how a boundary keeps forwarding to a node that cannot write.
    assert stepped_down({"ok": 1, "n": 0, "writeErrors": [
        {"index": 0, "code": 11602,
         "errmsg": "interrupted"}]}) == "11602"
    # Every code this treats as an election, so adding one is deliberate.
    assert STEPPED_DOWN == {10107, 13435, 13436, 11602, 189, 91}


def test_an_ordinary_write_error_is_not_read_as_an_election():
    from voyd.wire.upstream import stepped_down

    # A duplicate key must not invalidate the upstream: re-resolving on
    # every application-level error would mean a topology scan per bad
    # insert, and the boundary would be slowest exactly when a client is
    # retrying hardest.
    assert stepped_down({"ok": 1, "writeErrors": [
        {"index": 0, "code": 11000, "errmsg": "duplicate key"}]}) is None
    assert stepped_down({"ok": 0, "code": 13, "codeName": "Unauthorized"}) \
        is None
    assert stepped_down({"writeErrors": "not a list of dicts"}) is None
