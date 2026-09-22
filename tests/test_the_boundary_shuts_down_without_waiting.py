"""A deploy is a `SIGTERM`, and this one used to be a `SIGKILL`.

Draining exists so a rolling restart is a non-event: requests already in
flight finish, and the client sees answers rather than resets. That is the
claim `voyd-wire`'s shutdown path has always made. It was false in the
most complete way available -- **a `SIGTERM` with a single connected
client never returned at all**, so every deploy waited out its grace
period and took the kill it was trying to avoid, which is the exact
failure the feature was added for.

Two causes, both the same shape. Since Python 3.12, `Server.wait_closed()`
waits for every *handler* to finish, not only for the listening socket to
shut -- and `async with server:` awaits it on the way out. So the block
that was supposed to end at `stopping.wait()` never ended, and the bounded
drain underneath it was unreachable. The timeout that was meant to cap
this could not run.

The second is the interesting one, because fixing the first only turned
"never" into "the full drain window, every time". A client sitting idle
between requests is not work in flight; it is a keepalive socket, and
every other proxy hangs up on those at once. Being blocked on *read the
next request* is the definition of idle, so the read is raced against the
shutdown. A connection mid-request is not blocked there -- it is waiting
on a reply -- and still gets the whole drain.

Measured on this laptop, one connected and idle `pymongo` client:

    before   never exited (still alive at 60s)
    after    0.07s

The numbers below are asserted as ceilings rather than equalities, because
this is a timing test and the thing worth failing on is a regression to
tens of seconds, not a slow CI box taking three.
"""

from __future__ import annotations

import asyncio
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from voyd.wire.codec import Hangup
from voyd.wire.proxy import _next_message

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


def _start(tmp_path, *extra: str):
    path = tmp_path / "voydfile.py"
    path.write_text(POLICY)
    port = free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "voyd.wire.proxy", "--config", str(path),
         "--listen", str(port), "--target", mongo_host(), *extra],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    until = time.monotonic() + 15
    while time.monotonic() < until:
        if proc.poll() is not None:
            pytest.fail(f"voyd-wire exited early:\n{proc.stdout.read()}")
        try:
            with socket.create_connection(("127.0.0.1", port), 0.2):
                return proc, port
        except OSError:
            time.sleep(0.1)
    proc.kill()
    pytest.fail("voyd-wire never started listening")


def _client(port: int):
    """A driver pointed at the boundary, with a short selection timeout.

    Short because these tests outlive the process they are talking to. A
    `MongoClient.close()` whose server has vanished blocks for
    `serverSelectionTimeoutMS` while its monitor tries to reconnect -- so
    the default 8s turned five idle clients into forty seconds of
    *teardown*, measuring pymongo's patience rather than this boundary's
    shutdown. The thing under test is what the proxy does with a SIGTERM,
    and it has already happened by then.
    """
    return pymongo.MongoClient(
        f"mongodb://localhost:{port}/?directConnection=true",
        serverSelectionTimeoutMS=2000)


def _terminate(proc, limit: float) -> float:
    started = time.monotonic()
    proc.terminate()
    try:
        proc.wait(timeout=limit)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
        pytest.fail(
            f"voyd-wire did not exit within {limit}s of SIGTERM. A deploy "
            f"would wait out its grace period and SIGKILL it, dropping "
            f"whatever was in the air -- which is what draining exists to "
            f"prevent")
    return time.monotonic() - started


# ---- the end to end claim ------------------------------------------------

def test_an_idle_boundary_exits_immediately(tmp_path):
    """The control. If this one ever gets slow, the others are measuring
    something other than what they name."""
    proc, _port = _start(tmp_path)
    assert _terminate(proc, 10) < 3


def test_a_connected_but_idle_client_does_not_hold_a_deploy(tmp_path, db):
    """The regression. One client, authenticated, connected, doing
    nothing -- which is what every pooled application looks like between
    requests, and what the whole fleet looks like at 3am."""
    proc, port = _start(tmp_path)
    client = _client(port)
    try:
        client[db.name].notes.find_one({})       # a real, finished request
        assert _terminate(proc, 30) < 5, (
            "an idle connection waited out the drain window; being blocked "
            "on the next request is not work in flight")
    finally:
        client.close()


def test_several_idle_clients_do_not_add_up(tmp_path, db):
    """Because the drain is per connection, not per process: five idle
    sockets must cost what one does."""
    proc, port = _start(tmp_path)
    clients = [_client(port) for _ in range(5)]
    try:
        for c in clients:
            c[db.name].notes.find_one({})
        assert _terminate(proc, 30) < 5
    finally:
        for c in clients:
            c.close()


def test_the_drain_window_is_reachable_from_the_command_line(tmp_path):
    """It was a parameter with a default and no flag, so an operator could
    not set it at all -- a knob documented in a docstring and wired to
    nothing."""
    out = subprocess.run(
        [sys.executable, "-m", "voyd.wire.proxy", "--help"],
        cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert "--drain" in out.stdout
    proc, _port = _start(tmp_path, "--drain", "1")
    assert _terminate(proc, 10) < 3


# ---- and the decision itself, with no process in sight -------------------

def test_a_message_that_arrives_wins_over_a_drain_that_has_not():
    """The ordinary case: not draining, so the read is simply awaited."""
    async def go():
        reader = asyncio.StreamReader()
        reader.feed_data(_a_message())
        got = await _next_message(reader, None)
        assert got[2] == 7                       # req_id survived

    asyncio.run(go())


def test_a_drain_that_is_already_set_does_not_wait_for_a_message():
    """A connection that comes back round the loop after the shutdown has
    been signalled, with nothing buffered, is idle by definition."""
    async def go():
        reader = asyncio.StreamReader()          # nothing will ever arrive
        reader.feed_eof()
        draining = asyncio.Event()
        draining.set()
        with pytest.raises(Hangup):
            await _next_message(reader, draining)

    asyncio.run(go())


def test_a_drain_that_arrives_while_waiting_ends_the_wait():
    """The race, which is the whole mechanism. Without it this await never
    returns for a client that sends nothing more."""
    async def go():
        reader = asyncio.StreamReader()
        draining = asyncio.Event()
        loop = asyncio.get_running_loop()
        loop.call_later(0.05, draining.set)
        started = loop.time()
        with pytest.raises(Hangup):
            await _next_message(reader, draining)
        assert loop.time() - started < 2

    asyncio.run(go())


def test_a_request_already_arrived_is_served_even_while_draining():
    """The half that must *not* be fast. A message waiting in the buffer
    is work the client is owed, and a shutdown racing it has to lose --
    otherwise draining would drop requests instead of finishing them."""
    async def go():
        reader = asyncio.StreamReader()
        reader.feed_data(_a_message())
        draining = asyncio.Event()
        draining.set()                           # the shutdown got here first
        got = await _next_message(reader, draining)
        assert got[2] == 7, (
            "a request the client had already sent was dropped by the "
            "shutdown that was supposed to let it finish")

    asyncio.run(go())


def _a_message() -> bytes:
    """A minimal, well-framed OP_MSG with request id 7."""
    import struct

    import bson

    body = b"\x00\x00\x00\x00" + b"\x00" + bson.encode({"ping": 1})
    return struct.pack("<iiii", 16 + len(body), 7, 0, 2013) + body
