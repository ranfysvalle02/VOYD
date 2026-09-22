"""The transport got cheaper. The counting must not get looser.

Moving off two OS threads per connection and onto an event loop, then
across worker processes, changes nothing a user can see -- which is
precisely why it needs tests. Two things could silently break and both are
the kind of failure this project is named after:

1. A boundary that *appears* to scale because it stopped enforcing. Many
   connections at once must each still be refused correctly, not merely
   accepted quickly.
2. A boundary that scales and then undercounts. With `--workers` the
   counters live in N address spaces, and a refusal tally summed wrong is a
   tool lying about the one number it exists to report.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

from voyd.wire import codec
from voyd.wire import policy
from voyd.wire import proxy as w

from .conftest import free_port, mongo_host  # noqa: E402

pymongo = pytest.importorskip("pymongo")


POLICY = ("from voyd import guard, deadline, revocable, tenant\n"
          "@guard('notes')\n"
          "class N:\n"
          "    expire_at = deadline()\n"
          "    forgotten = revocable()\n")


def _wait(port, proc, seconds=20):
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


# --------------------------------------------------------------------------
# One length rule, two readers.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("length", [-1, 2_000_000_000, 4, codec.MAX_MESSAGE + 1],
                         ids=["negative", "huge", "undersized", "just-over"])
def test_both_readers_obey_the_same_cap(length):
    """The cap is the security property; the socket is a detail.

    A sync reader and an async one each carrying their own copy of the
    bound is how one of them drifts, and the one that drifts is the one
    nobody tested. They share `frame`, and this is what says so.
    """
    hdr = struct.pack("<i", length) + struct.pack("<iiI", 1, 0, 2013)
    with pytest.raises(codec.ProtocolError):
        codec.frame(hdr)


def test_the_async_reader_reads_what_the_sync_one_reads():
    import asyncio

    raw = codec.encode_sections(7, 0, 0, {"find": "notes"})

    async def go():
        a, b = socket.socketpair()
        a.sendall(raw)
        reader, writer = await asyncio.open_connection(sock=b)
        try:
            return await codec.read_message_async(reader)
        finally:
            writer.close()
            a.close()

    got, _len, req_id, _resp_to, opcode = asyncio.run(go())
    assert got == raw and req_id == 7 and opcode == codec.OP_MSG


def test_a_peer_that_vanishes_mid_message_is_a_disconnect():
    """`IncompleteReadError` and an empty `recv` mean the same thing, and
    `pump` must have one disconnect to catch rather than two."""
    import asyncio

    async def go():
        a, b = socket.socketpair()
        a.sendall(struct.pack("<iiiI", 64, 1, 0, 2013))   # header, no body
        a.close()
        reader, writer = await asyncio.open_connection(sock=b)
        try:
            with pytest.raises(ConnectionError):
                await codec.read_message_async(reader)
        finally:
            writer.close()

    asyncio.run(go())


# --------------------------------------------------------------------------
# Counting across processes.
# --------------------------------------------------------------------------

def test_merge_adds_up_every_worker_including_reasons():
    total = w.merge([
        {"served": 3, "refused": 2, "revoked": 1, "cascaded": 7,
         "reasons": {"expired": 2}},
        # A worker that predates a counter, or simply never touched a
        # lineage collection, omits the key. Summing must treat that as
        # zero rather than dropping the column, because an undercount is
        # the one direction this number must never be wrong in.
        {"served": 4, "refused": 5, "revoked": 0,
         "reasons": {"expired": 1, "revoked": 4}},
    ])
    assert total == {"served": 7, "refused": 7, "revoked": 1, "cascaded": 7,
                     "reasons": {"expired": 3, "revoked": 4}}


def test_a_tally_survives_the_pipe_it_is_sent_through():
    """Workers report through `json` over a pipe, so a tally that is not
    JSON-serialisable would be dropped -- and a dropped tally is an
    undercount, which is the one direction this number must never be
    wrong in."""
    guard = policy.Guard.defaults("notes", at_field="expire_at",
                             mark_field="forgotten")
    guard.filter([{"forgotten": True}, {"text": "fine"}])
    counts = w.tally({"notes": guard})
    assert json.loads(json.dumps(counts)) == counts
    assert counts["refused"] == 1 and counts["served"] == 1


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs fork()")
def test_workers_share_one_socket_and_report_one_total(db, tmp_path):
    """Four clients across two workers, and *one* summary at the end.

    The failure this guards is subtle and would look like success: each
    worker printing its own summary reads exactly like the real thing
    while reporting a fraction of the traffic. The assertion that there is
    a single summary line matters as much as the number in it.
    """
    db.notes.insert_many([{"text": "a"}, {"text": "b"},
                          {"text": "gone", "forgotten": True}])
    policy = tmp_path / "voydfile.py"
    policy.write_text(POLICY)
    port = free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "voyd.wire.proxy", "--config", str(policy),
         "--listen", str(port), "--target", mongo_host(), "--workers", "2"],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        _wait(port, proc)
        for _ in range(4):
            client = pymongo.MongoClient(
                f"mongodb://localhost:{port}/?directConnection=true",
                serverSelectionTimeoutMS=8000)
            try:
                got = list(client[db.name].notes.find({}))
                assert len(got) == 2, "the revoked one is refused, per worker"
            finally:
                client.close()

        proc.send_signal(signal.SIGTERM)
        out = proc.communicate(timeout=40)[0]
    finally:
        if proc.poll() is None:
            proc.kill()

    assert out.count("documents deleted by this process: 0") == 1, \
        f"one summary, not one per worker:\n{out}"
    assert "served 8" in out, f"4 clients x 2 admitted, summed:\n{out[-600:]}"
    assert "refused 4" in out, f"4 clients x 1 refused, summed:\n{out[-600:]}"


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs fork()")
def test_ctrl_c_does_not_cost_the_workers_their_tallies(db, tmp_path):
    """What a terminal does is signal the whole process group.

    Workers that stayed in the parent's group got `SIGINT` twice -- once
    from the tty, once forwarded by the parent -- and the second signal is
    the one that means "they mean it" and exits at once. Both workers died
    mid-drain without reporting, and the total silently undercounted by
    everything they had served. This is that, measured, so it stays fixed.
    """
    db.notes.insert_many([{"text": "a"}, {"text": "b"},
                          {"text": "gone", "forgotten": True}])
    policy = tmp_path / "voydfile.py"
    policy.write_text(POLICY)
    port = free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "voyd.wire.proxy", "--config", str(policy),
         "--listen", str(port), "--target", mongo_host(), "--workers", "2"],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        start_new_session=True)
    try:
        _wait(port, proc)
        client = pymongo.MongoClient(
            f"mongodb://localhost:{port}/?directConnection=true",
            serverSelectionTimeoutMS=8000)
        try:
            assert len(list(client[db.name].notes.find({}))) == 2
        finally:
            client.close()

        os.killpg(os.getpgid(proc.pid), signal.SIGINT)
        out = proc.communicate(timeout=40)[0]
    finally:
        if proc.poll() is None:
            proc.kill()

    assert "without a tally" not in out, \
        f"a worker was signalled twice and lost its counts:\n{out}"
    assert "served 2" in out, f"the tally survived the interrupt:\n{out[-600:]}"


# --------------------------------------------------------------------------
# Many at once, still refusing.
# --------------------------------------------------------------------------

def test_many_concurrent_connections_are_each_still_refused(db, tmp_path):
    """The point of the event loop, and the trap in it.

    120 simultaneous clients is well past what two OS threads apiece made
    comfortable. Scaling is only worth anything if every one of them is
    still refused correctly -- a boundary that got fast by getting
    permissive is the exact failure this repository is about.

    The limit is 600 rather than 120 because a `MongoClient` is not one
    socket: it opens a monitor connection beside its pool, so this is
    nearer 360 concurrent connections than 120. Sizing it at 120 was the
    first draft, and the boundary correctly closed the overflow -- which
    is `test_connections_past_the_limit_are_closed_rather_than_queued`
    passing in a test that meant to measure something else.
    """
    db.notes.insert_many([{"text": "a"}, {"text": "b"},
                          {"text": "gone", "forgotten": True}])
    policy = tmp_path / "voydfile.py"
    policy.write_text(POLICY)
    port = free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "voyd.wire.proxy", "--config", str(policy),
         "--listen", str(port), "--target", mongo_host(),
         "--max-connections", "600", "--quiet"],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    clients = []
    try:
        _wait(port, proc)
        for _ in range(120):
            clients.append(pymongo.MongoClient(
                f"mongodb://localhost:{port}/?directConnection=true",
                serverSelectionTimeoutMS=15000, maxPoolSize=1))
        for client in clients:
            got = [d["text"] for d in client[db.name].notes.find({})]
            assert "gone" not in got, "refusal held under concurrency"
            assert len(got) == 2
    finally:
        for client in clients:
            client.close()
        proc.terminate()
        proc.wait(timeout=20)
