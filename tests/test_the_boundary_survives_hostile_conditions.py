"""The failures tests are worst at finding, caused on purpose.

Everything else in this suite drives the boundary the way a well-behaved
client does. This file is for the other kind: a client that stops reading,
one that vanishes mid-reply, one that half closes; a worker that dies, one
that is alive but wedged; and an upstream that holds an election under
load.

Four real bugs came out of writing it, and each test below names the one
it pins. That is the point of the file -- a concurrency bug that has been
reproduced once and never again is a bug that is still there.
"""

from __future__ import annotations

import asyncio
import os
import signal
import socket
import struct
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

from voyd.wire import codec

from .conftest import MONGO_URI, free_port, mongo_host  # noqa: E402

pymongo = pytest.importorskip("pymongo")

POLICY = ("from voyd import guard, deadline, revocable\n"
          "@guard('bench', on_delete='revoke')\n"
          "class B:\n"
          "    expire_at = deadline()\n"
          "    forgotten = revocable()\n")

ASK = None          # built lazily; encoding needs the proxy imported


def ask() -> bytes:
    global ASK
    if ASK is None:
        ASK = codec.encode_sections(1, 0, 0, {"find": "bench", "$db": "benchdb"})
    return ASK


def read_one(sock: socket.socket) -> bytes:
    hdr = codec.read_exact(sock, codec.HEADER)
    length, _rid, _rt, _op = codec.frame(hdr)
    return hdr + codec.read_exact(sock, length - codec.HEADER)


def listening(port: int, proc, seconds: float = 20.0) -> None:
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if proc.poll() is not None:
            pytest.fail("process exited before it listened")
        try:
            with socket.create_connection(("127.0.0.1", port), 0.2):
                return
        except OSError:
            time.sleep(0.05)
    pytest.fail(f"nothing listened on {port}")


@pytest.fixture
def wired(tmp_path):
    """A boundary in front of a synthetic upstream.

    Deliberately not `mongod`: these tests are about the transport, and a
    real database makes them slower, flakier, and no more truthful about
    sockets. `voyd.wire.bench`'s upstream answers every request with one
    pre-encoded batch.
    """
    started = []

    def go(*extra, docs=200, pad=1000):
        up_port, listen = free_port(), free_port()
        upstream = subprocess.Popen(
            [sys.executable, "-m", "voyd.wire.bench", "--role", "upstream",
             "--port", str(up_port), "--docs", str(docs),
             "--refuse-every", "10", "--pad", str(pad),
             "--upstream-procs", "1"],
            cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        started.append(upstream)
        listening(up_port, upstream)

        policy = tmp_path / "voydfile.py"
        policy.write_text(POLICY)
        proxy = subprocess.Popen(
            [sys.executable, "-m", "voyd.wire.proxy", "--config", str(policy),
             "--listen", str(listen), "--target", f"127.0.0.1:{up_port}",
             "--quiet", *extra],
            cwd=ROOT, start_new_session=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        started.append(proxy)
        listening(listen, proxy)
        return listen, proxy

    yield go
    for proc in reversed(started):
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                proc.kill()


# --------------------------------------------------------------------------
# A half close is "no more requests", not "abandon my reply".
# --------------------------------------------------------------------------

async def test_a_clean_eof_is_a_different_event_from_a_truncated_message():
    """The distinction the half-close fix rests on. Nothing where a header
    should start is a peer finishing on a boundary; bytes and then nothing
    is a broken stream, and conflating them either drops replies or
    forwards garbage."""
    left, right = socket.socketpair()
    left.close()
    reader, writer = await asyncio.open_connection(sock=right)
    with pytest.raises(codec.Hangup):
        await codec.read_message_async(reader)
    writer.close()

    left, right = socket.socketpair()
    left.sendall(struct.pack("<iiiI", 400, 1, 0, codec.OP_MSG) + b"only a bit")
    left.close()
    reader, writer = await asyncio.open_connection(sock=right)
    with pytest.raises(ConnectionError) as blew:
        await codec.read_message_async(reader)
    assert not isinstance(blew.value, codec.Hangup), \
        "a truncated message is not a polite goodbye"
    writer.close()


def test_a_half_closed_client_still_receives_the_reply_it_asked_for(wired):
    """A client that calls `shutdown(SHUT_WR)` is still reading.

    This failed before: the request direction hitting EOF tore the reply
    direction down with it, so the caller lost its last answer. It was
    never a regression from the event loop -- the threaded version did
    the same thing -- which is why no test caught it.
    """
    listen, _proxy = wired()
    sock = socket.create_connection(("127.0.0.1", listen), 10)
    sock.settimeout(15)
    try:
        sock.sendall(ask())
        sock.shutdown(socket.SHUT_WR)
        reply = read_one(sock)
        assert len(reply) > codec.HEADER
    finally:
        sock.close()


def test_a_half_close_with_several_replies_outstanding_loses_none(wired):
    listen, _proxy = wired(docs=20, pad=100)
    sock = socket.create_connection(("127.0.0.1", listen), 10)
    sock.settimeout(15)
    try:
        for _ in range(25):
            sock.sendall(ask())
        sock.shutdown(socket.SHUT_WR)
        assert sum(1 for _ in range(25) if read_one(sock)) == 25
    finally:
        sock.close()


# --------------------------------------------------------------------------
# Clients that misbehave must cost one connection, never the listener.
# --------------------------------------------------------------------------

def test_a_client_that_stops_reading_does_not_grow_the_boundary(wired):
    """Backpressure. `drain()` is what stops a fast upstream and a slow
    client from buffering the difference in this process -- the shape of
    an outage that looks like a memory leak."""
    listen, proxy = wired(docs=500, pad=2000)     # ~1MB per reply

    def rss() -> float:
        out = subprocess.run(["ps", "-o", "rss=", "-p", str(proxy.pid)],
                             capture_output=True, text=True).stdout.strip()
        return int(out) / 1024 if out else 0.0

    before = rss()
    stalled = []
    try:
        for _ in range(20):
            sock = socket.create_connection(("127.0.0.1", listen), 10)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            for _ in range(200):          # 4,000 replies asked for, none read
                sock.sendall(ask())
            stalled.append(sock)
        time.sleep(5)
        grew = rss() - before
    finally:
        for sock in stalled:
            sock.close()
    assert grew < 400, (
        f"grew {grew:.0f}MB; 4,000 unread replies of ~1MB is ~4GB "
        f"if nothing is pushing back")


def test_a_storm_of_resets_costs_connections_and_not_the_listener(wired):
    """`ssl.SSLError` subclasses `OSError`, so a handshake failure caught in
    the shutdown branch takes the listener down for everybody. Same shape,
    ruder: fifty clients that vanish mid-reply."""
    listen, proxy = wired(docs=200, pad=500)
    for _ in range(50):
        sock = socket.create_connection(("127.0.0.1", listen), 10)
        for _ in range(20):
            sock.sendall(ask())
        # SO_LINGER 0 makes close() an RST rather than a FIN.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                        struct.pack("ii", 1, 0))
        sock.close()
    time.sleep(1)
    assert proxy.poll() is None, "the proxy died"

    survivor = socket.create_connection(("127.0.0.1", listen), 10)
    survivor.settimeout(15)
    try:
        survivor.sendall(ask())
        assert len(read_one(survivor)) > codec.HEADER
    finally:
        survivor.close()


def test_garbage_costs_one_connection(wired):
    listen, proxy = wired()
    junk = socket.create_connection(("127.0.0.1", listen), 10)
    junk.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n" * 8)
    time.sleep(0.5)
    junk.close()
    assert proxy.poll() is None

    good = socket.create_connection(("127.0.0.1", listen), 10)
    good.settimeout(15)
    try:
        good.sendall(ask())
        assert len(read_one(good)) > codec.HEADER
    finally:
        good.close()


# --------------------------------------------------------------------------
# Workers: the ones that die, and the worse ones that do not.
# --------------------------------------------------------------------------

def scrape(port: int) -> dict[str, float]:
    body = urllib.request.urlopen(
        f"http://127.0.0.1:{port}/metrics", timeout=5).read().decode()
    out = {}
    for line in body.splitlines():
        if line and not line.startswith("#"):
            name, _sp, value = line.partition(" ")
            out[name] = float(value)
    return out


def children_of(pid: int) -> list[int]:
    listing = subprocess.run(["ps", "-o", "pid=,ppid=", "-ax"],
                             capture_output=True, text=True).stdout
    out = []
    for line in listing.splitlines():
        bits = line.split()
        if len(bits) >= 2 and int(bits[1]) == pid:
            out.append(int(bits[0]))
    return out


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs fork()")
def test_a_killed_worker_is_replaced_exactly_once_and_counted(wired):
    """Before this, the parent never noticed. Capacity dropped by a third,
    `voyd_workers` went on reporting the number asked for, and nothing
    said anything.

    "Exactly once" is the load-bearing word. The first version of the
    supervisor closed the listening socket in the parent, so every
    replacement inherited a closed fd and died at once -- one `SIGKILL`
    produced four restarts in two seconds, a crash loop manufactured by
    the thing that was supposed to be recovering from one.
    """
    metrics = free_port()
    listen, proxy = wired("--workers", "3", "--metrics", str(metrics),
                          docs=20, pad=100)
    time.sleep(1.5)
    workers = children_of(proxy.pid)
    assert len(workers) == 3, workers

    before = scrape(metrics)
    assert before["voyd_workers_configured"] == 3
    assert before["voyd_worker_restarts_total"] == 0

    os.kill(workers[0], signal.SIGKILL)
    time.sleep(3)

    after = scrape(metrics)
    assert after["voyd_worker_restarts_total"] == 1, \
        f"one kill, one restart: {after['voyd_worker_restarts_total']}"
    assert after["voyd_workers_live"] == 3, "capacity came back"
    assert len(children_of(proxy.pid)) == 3

    sock = socket.create_connection(("127.0.0.1", listen), 10)
    sock.settimeout(15)
    try:
        sock.sendall(ask())
        assert len(read_one(sock)) > codec.HEADER, "still serving after a restart"
    finally:
        sock.close()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs fork()")
def test_a_wedged_worker_is_visible_even_though_it_is_alive(wired):
    """The failure a restart cannot catch, and the one the metrics used to
    hide completely.

    `voyd_metrics_age_seconds` reported the *freshest* worker's flush, so
    seven healthy workers held it near zero while the eighth was frozen.
    Measured: a `SIGKILL`ed worker left it reading 0.095. It is the
    stalest now, and every slot is published separately.

    `SIGSTOP` is the honest simulation -- the process is alive, so no
    supervisor will replace it, and its loop is simply not running.
    """
    metrics = free_port()
    _listen, proxy = wired("--workers", "3", "--metrics", str(metrics),
                           docs=20, pad=100)
    time.sleep(1.5)
    workers = children_of(proxy.pid)
    assert len(workers) == 3

    os.kill(workers[0], signal.SIGSTOP)
    try:
        time.sleep(4)
        got = scrape(metrics)
        ages = {int(k.split('"')[1]): v for k, v in got.items()
                if k.startswith("voyd_worker_flush_age_seconds")}
        assert len(ages) == 3
        wedged = max(ages.values())
        healthy = sorted(ages.values())[:-1]
        assert wedged > 3, f"the frozen worker should look frozen: {ages}"
        assert all(age < 2 for age in healthy), f"the others are fine: {ages}"
        assert got["voyd_metrics_age_seconds"] == pytest.approx(wedged,
                                                                abs=0.5), \
            "the headline age is the worst worker, not the best"
        assert got["voyd_worker_restarts_total"] == 0, \
            "a stopped process is not a dead one; do not replace it"
    finally:
        os.kill(workers[0], signal.SIGCONT)


# --------------------------------------------------------------------------
# An election, caused on purpose.
# --------------------------------------------------------------------------

def test_the_failover_signal_fires_on_a_real_election(tmp_path):
    """`LIMITS.md` called this "the failover signal, which cannot be caused
    on demand", and the only tests for it fed synthetic reply documents to
    `stepped_down`. It can be caused: `replSetStepDown` with `force` on
    the single-node replica set Atlas Local already is.

    So this is the whole path, for real -- an election, the server's own
    `NotWritablePrimary` read off the reply the client was getting anyway,
    the cached upstream invalidated, and the boundary still refusing
    afterwards without anybody restarting it.
    """
    admin = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=8000)
    hello = admin.admin.command("hello")
    if not hello.get("setName"):
        pytest.skip("not a replica set; there is no election to hold")

    name = f"voyd_failover_{os.getpid()}"
    source = admin[name]
    source.notes.insert_many([{"t": "a"}, {"t": "b"},
                              {"t": "gone", "forgotten": True}])

    policy = tmp_path / "voydfile.py"
    policy.write_text("from voyd import guard, deadline, revocable\n"
                      "@guard('notes', on_delete='revoke')\n"
                      "class N:\n"
                      "    expire_at = deadline()\n"
                      "    forgotten = revocable()\n")
    listen = free_port()
    proxy = subprocess.Popen(
        [sys.executable, "-m", "voyd.wire.proxy", "--config", str(policy),
         "--listen", str(listen), "--target", mongo_host()],
        cwd=ROOT, start_new_session=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        listening(listen, proxy)
        client = pymongo.MongoClient(
            f"mongodb://localhost:{listen}/?directConnection=true",
            serverSelectionTimeoutMS=10000)
        try:
            assert len(list(client[name].notes.find({}))) == 2, \
                "refusing before the election"

            try:
                admin.admin.command("replSetStepDown", 5, force=True)
            except pymongo.errors.PyMongoError:
                pass              # the connection dies with the primary

            # The driver retries; what matters is that it converges.
            done = None
            for _ in range(12):
                try:
                    done = client[name].notes.delete_one({"t": "a"})
                    break
                except pymongo.errors.PyMongoError:
                    time.sleep(2)
            assert done is not None, "never recovered after the election"

            assert len(list(client[name].notes.find({}))) == 1, \
                "still refusing after the election"
        finally:
            client.close()

        # Nothing was destroyed, across an election.
        assert source.notes.count_documents({}) == 3
        assert source.notes.find_one({"t": "a"})["forgotten"]["reason"] == \
            "deleted via voyd-wire"
    finally:
        proxy.terminate()
        said = proxy.communicate(timeout=30)[0]
        admin.drop_database(name)
        # Leave the cluster writable for whatever runs next.
        for _ in range(30):
            try:
                if admin.admin.command("hello").get("isWritablePrimary"):
                    break
            except pymongo.errors.PyMongoError:
                pass
            time.sleep(1)
        admin.close()

    assert "no longer writable" in said, (
        "the boundary should have read the server's own election error:\n"
        + said[-800:])
