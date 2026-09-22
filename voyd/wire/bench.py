#!/usr/bin/env python3
"""How much does refusal cost, and does it scale? Measured, not asserted.

    voyd-bench                  # the whole sweep
    voyd-bench --workers 1,4    # just these
    voyd-bench --seconds 20     # longer, less noise

Every performance number this project states comes from here, so it is in the
repository rather than in a gist: a benchmark nobody else can run is an
anecdote, and this project's whole argument is that a claim you cannot
check is worth nothing.

**Why not `mongod` and `pymongo`.** The first attempt at this measured a
real driver against Atlas Local and reported that `--workers 4` bought
1.42x. That number was about the laptop, not the boundary: `mongod` and
the load generator were competing for the same cores as the proxy, so the
proxy was never the bottleneck and the experiment could not see what it
claimed to measure. An earlier attempt was worse -- 1.18x -- because the
load generator was Python threads and spent the run holding the GIL
against itself.

So both ends are replaced with the cheapest thing that still speaks the
protocol:

- **The upstream** is a socket that answers every request with one
  pre-encoded reply, patching four bytes of `responseTo`. It does no BSON
  work at all. A real `mongod` does much more, which is exactly why it
  cannot be in the loop when the question is about the proxy.
- **The clients** are raw sockets sending a pre-encoded `find` and reading
  the reply back without decoding it. No driver, no handshake, no BSON.

What is left in the middle is the only thing doing real work: `enforce`
decodes a cursor batch, runs admission per document, and re-encodes the
ones that survived. That is the cost this measures.

**The control matters more than the result.** `--workers 0` runs the
clients straight at the upstream with no proxy in the path. If that number
is not far above every proxy number below it, the harness is the bottleneck
and the whole sweep is measuring itself. It is printed first, every time,
for that reason.
"""

from __future__ import annotations

import argparse
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import time
import pathlib
from pathlib import Path
from typing import Any

from . import codec
from . import proxy as w

ROOT = Path(__file__).resolve().parents[2]

COLLECTION = "bench"
NAMESPACE = f"benchdb.{COLLECTION}"


# ---------------------------------------------------------------------------
# The two pre-encoded messages. Built once; neither end pays to make them.
# ---------------------------------------------------------------------------

def request() -> bytes:
    """A `find` the proxy will forward and the upstream will answer."""
    return w.encode_sections(1, 0, 0, {"find": COLLECTION, "$db": "benchdb"})


def reply(docs: int, refuse_every: int, pad: int, dims: int = 0) -> bytes:
    """One cursor batch, some of it refusable.

    `refuse_every` is not decoration. `enforce` returns the original bytes
    untouched when nothing was refused, so a batch that is entirely
    admissible measures the decode and skips the re-encode -- half the
    work, and the cheaper half. A batch with refusals in it exercises the
    path a real guarded collection takes.

    `dims` is not decoration either, and for longer than it should have been
    this function could not express it. **The shape of the document is a
    claim about the workload.** A batch of `{_id, i, text}` is cheap to
    decode in a way a retrieval corpus is not: the thing this boundary sits
    in front of returns vectors, and a 1536-float array costs more to
    materialise than every other field in the document put together. A
    proxy benchmarked only on short documents is being asked the easy
    question. Default 0 so the older numbers on this page stay comparable.
    """
    vector = [0.1] * dims if dims else None
    batch = []
    for i in range(docs):
        doc: dict = {"_id": i, "i": i, "text": "x" * pad}
        if vector is not None:
            # Same list object in every document: this is BSON-encoded once
            # into a canned reply, so there is nothing to alias and nothing
            # downstream that could mutate it.
            doc["embedding"] = vector
        if refuse_every and i % refuse_every == 0:
            doc["forgotten"] = True
        batch.append(doc)
    return codec.encode_op_msg(1, 1, 0, {
        "cursor": {"id": 0, "ns": NAMESPACE, "firstBatch": batch},
        "ok": 1.0})


# ---------------------------------------------------------------------------
# The synthetic upstream.
# ---------------------------------------------------------------------------

def be_upstream(port: int, docs: int, refuse_every: int, pad: int,
                procs: int, dims: int = 0) -> None:
    """Answer everything with the same batch, as fast as a socket allows."""
    import threading

    canned = reply(docs, refuse_every, pad, dims)
    head, tail = canned[:8], canned[12:]

    listen = socket.socket()
    listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen.bind(("127.0.0.1", port))
    listen.listen(512)

    # Fork, then make sure the forks die with us. An earlier version did
    # not, and the orphans kept the inherited stdout open forever -- so a
    # `... | tail` around the whole benchmark hung after printing every
    # result, which reads exactly like the benchmark itself deadlocking.
    # It took a probe to see that the numbers were already correct and it
    # was only the teardown that was broken.
    kids: list[int] = []
    mine = False
    for _ in range(procs - 1):
        pid = os.fork()
        if pid == 0:
            kids, mine = [], True
            break
        kids.append(pid)

    def stop(*_a):
        for kid in kids:
            try:
                os.kill(kid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        os._exit(0)

    if not mine:
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)

    def serve_one(conn: socket.socket) -> None:
        try:
            while True:
                hdr = codec.read_exact(conn, codec.HEADER)
                msg_len, req_id, _resp_to, _op = codec.frame(hdr)
                codec.read_exact(conn, msg_len - codec.HEADER)
                # Four bytes of `responseTo` is the whole of the work. A
                # driver would care about more; this is deliberately not a
                # driver.
                conn.sendall(head + struct.pack("<i", req_id) + tail)
        except (OSError, ConnectionError, w.ProtocolError):
            pass
        finally:
            conn.close()

    while True:
        try:
            conn, _ = listen.accept()
        except OSError:
            break
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        threading.Thread(target=serve_one, args=(conn,), daemon=True).start()


# ---------------------------------------------------------------------------
# The load generator.
# ---------------------------------------------------------------------------

def be_client(port: int, seconds: float, pipeline: int, out_fd: int) -> None:
    """Send `find`, read the reply, do not decode it, repeat.

    Pipelining is what keeps this from measuring round-trip latency
    instead of throughput: with one request in flight the number you get
    is the speed of light down a loopback, not the cost of admission.
    """
    msg = request()
    conn = socket.create_connection(("127.0.0.1", port), 10)
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    replies = 0
    try:
        conn.sendall(msg * pipeline)
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            hdr = codec.read_exact(conn, codec.HEADER)
            msg_len, _rid, _rt, _op = codec.frame(hdr)
            codec.read_exact(conn, msg_len - codec.HEADER)
            replies += 1
            conn.sendall(msg)
    except (OSError, ConnectionError, w.ProtocolError):
        pass
    finally:
        conn.close()
        with os.fdopen(out_fd, "w") as report:
            report.write(str(replies))


# ---------------------------------------------------------------------------
# CPU accounting.
# ---------------------------------------------------------------------------

def cpu_seconds(pids: list[int]) -> float:
    """Cumulative CPU time of a process tree, in seconds.

    Sampled rather than instantaneous: `pcpu` is an average over the
    process lifetime on some platforms and an instant on others, and
    neither is what "how much CPU did this run cost" means. Two readings
    of cumulative time and a subtraction is unambiguous.
    """
    if not pids:
        return 0.0
    out = subprocess.run(["ps", "-o", "cputime=", "-p",
                          ",".join(str(p) for p in pids)],
                         capture_output=True, text=True).stdout
    total = 0.0
    for line in out.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        # "MM:SS.ss" or "HH:MM:SS.ss"
        parts = line.split(":")
        secs = float(parts[-1])
        if len(parts) > 1:
            secs += int(parts[-2]) * 60
        if len(parts) > 2:
            secs += int(parts[-3]) * 3600
        total += secs
    return total


def descendants(pid: int) -> list[int]:
    """A pid and everything forked from it, so `--workers N` is counted."""
    out = subprocess.run(["ps", "-o", "pid=,ppid=", "-ax"],
                         capture_output=True, text=True).stdout
    kids: dict[int, list[int]] = {}
    for line in out.strip().splitlines():
        bits = line.split()
        if len(bits) >= 2:
            kids.setdefault(int(bits[1]), []).append(int(bits[0]))
    seen, stack = [], [pid]
    while stack:
        current = stack.pop()
        seen.append(current)
        stack.extend(kids.get(current, []))
    return seen


def wait_for(port: int, timeout: float = 20.0) -> None:
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            return
        except OSError:
            time.sleep(0.05)
    raise SystemExit(f"nothing came up on {port}")


# ---------------------------------------------------------------------------
# One measurement.
# ---------------------------------------------------------------------------

def measure(port: int, clients: int, seconds: float, pipeline: int,
            docs: int, proxy_pid: int | None) -> dict:
    """Run the clients, and attribute the CPU the proxy spent doing it."""
    pids = descendants(proxy_pid) if proxy_pid else []
    before = cpu_seconds(pids)

    kids = []
    for _ in range(clients):
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            try:
                be_client(port, seconds, pipeline, write_fd)
            finally:
                os._exit(0)
        os.close(write_fd)
        kids.append((pid, read_fd))

    started = time.monotonic()
    total = 0
    for pid, read_fd in kids:
        with os.fdopen(read_fd) as report:
            blob = report.read().strip()
        total += int(blob) if blob.isdigit() else 0
        os.waitpid(pid, 0)
    elapsed = time.monotonic() - started

    after = cpu_seconds(pids)
    burned = max(after - before, 0.0)
    checked = total * docs
    return {"replies": total, "elapsed": elapsed,
            "qps": total / elapsed if elapsed else 0.0,
            "docs_per_sec": checked / elapsed if elapsed else 0.0,
            "cpu": burned,
            "cores": burned / elapsed if elapsed else 0.0,
            "us_per_doc": (burned / checked * 1e6) if checked else 0.0}


def run(args) -> int:
    policy = Path(args.policy or (ROOT / ".voyd_bench_policy.py"))
    policy.write_text(
        "from voyd import guard, deadline, revocable\n"
        f"@guard('{COLLECTION}')\n"
        "class Bench:\n"
        "    expire_at = deadline()\n"
        "    forgotten = revocable()\n")

    up_port = args.port
    upstream = subprocess.Popen(
        [sys.executable, "-m", "voyd.wire.bench",
         "--role", "upstream", "--port", str(up_port),
         "--docs", str(args.docs), "--refuse-every", str(args.refuse_every),
         "--pad", str(args.pad), "--dims", str(args.dims),
         "--upstream-procs", str(args.upstream_procs)],
        cwd=ROOT)
    rows = []
    try:
        wait_for(up_port)

        print(f"\nvoyd-bench: {args.clients} clients x {args.pipeline} in "
              f"flight, {args.docs} docs/batch "
              f"({args.docs // max(args.refuse_every, 1)} refusable), "
              f"{args.seconds}s each, {os.cpu_count()} cores\n")
        header = (f"{'':14} {'q/s':>9} {'docs/s':>11} {'cores':>7} "
                  f"{'us/doc':>8} {'vs 1':>6}  enforcing")
        print(header)
        print("-" * len(header))

        base = None
        for workers in args.workers:
            if workers == 0:
                got = measure(up_port, args.clients, args.seconds,
                              args.pipeline, args.docs, None)
                print(f"{'no proxy':14} {got['qps']:9.0f} "
                      f"{got['docs_per_sec']:11.0f} {'':>7} {'':>8} {'':>6}"
                      "   <- the control: the harness's own ceiling")
                rows.append(("no proxy", got))
                continue

            listen = _free_port()
            proxy = subprocess.Popen(
                [sys.executable, "-m", "voyd.wire", "--config", str(policy),
                 "--listen", str(listen), "--target", f"127.0.0.1:{up_port}",
                 "--max-connections", str(max(args.clients * 4, 64)),
                 "--workers", str(workers), "--quiet"]
                + (["--metrics", str(_free_port())] if args.with_metrics
                   else []),
                cwd=ROOT, start_new_session=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            try:
                wait_for(listen)
                time.sleep(0.5)
                got = measure(listen, args.clients, args.seconds,
                              args.pipeline, args.docs, proxy.pid)
            finally:
                proxy.terminate()
                try:
                    said = proxy.communicate(timeout=30)[0]
                except subprocess.TimeoutExpired:
                    proxy.kill()
                    said = ""
            got["enforced"] = _enforced(said, args.refuse_every)
            if base is None:
                base = got["docs_per_sec"]
            label = f"workers={workers}"
            print(f"{label:14} {got['qps']:9.0f} {got['docs_per_sec']:11.0f} "
                  f"{got['cores']:7.2f} {got['us_per_doc']:8.2f} "
                  f"{got['docs_per_sec'] / base:6.2f}x  "
                  f"{got['enforced']}")
            rows.append((label, got))
    finally:
        upstream.terminate()
        try:
            upstream.wait(timeout=10)
        except subprocess.TimeoutExpired:
            upstream.kill()
        if not args.policy:
            policy.unlink(missing_ok=True)

    _verdict(rows)
    return 0


def _enforced(said: str, refuse_every: int) -> str:
    """Did the boundary actually refuse, at speed?

    A proxy that got fast by quietly forwarding everything would post the
    best numbers on this page, so throughput alone is not a result. The
    worker summary says how many documents it served and how many it
    refused; with one document in `refuse_every` revoked, the refused
    share has to come out at 1/refuse_every or the run measured a
    boundary that had stopped being one.
    """
    found = re.search(r"served (\d+), refused (\d+)", said)
    if not found:
        return "?? no summary"
    served, refused = int(found.group(1)), int(found.group(2))
    total = served + refused
    if not total:
        return "?? nothing served"
    share = refused / total
    want = 1.0 / refuse_every if refuse_every else 0.0
    ok = abs(share - want) < 0.005
    return f"{'refused' if ok else 'LEAKED'} {share:.1%}"


def _verdict(rows: list[tuple[str, dict]]) -> None:
    """Say what the numbers mean, including when they mean nothing.

    A benchmark that prints a table and stops invites the reader to take
    the biggest number home. The two ways this sweep is invalid -- a
    saturated harness, and a worker count that never used a second core --
    are checked here so they cannot be skipped.
    """
    control = dict(rows).get("no proxy")
    proxied = [(name, got) for name, got in rows if name != "no proxy"]
    if not proxied:
        return
    print()
    best = max(got["docs_per_sec"] for _, got in proxied)
    if control:
        headroom = control["docs_per_sec"] / best if best else 0.0
        verdict = ("the harness had room" if headroom >= 1.5 else
                   "SUSPECT: the harness may be the bottleneck")
        print(f"control is {headroom:.1f}x the best proxied result -- "
              f"{verdict}")
    leaked = [name for name, got in proxied
              if not str(got.get("enforced", "")).startswith("refused")]
    if leaked:
        print(f"  FAILED: {', '.join(leaked)} did not refuse the expected "
              f"share -- these numbers are for a boundary that stopped "
              f"being one, and mean nothing")
    one = dict(proxied).get("workers=1")
    if one:
        print(f"one worker used {one['cores']:.2f} cores, "
              f"{one['us_per_doc']:.2f}us of CPU per document admitted")
        if one["cores"] < 0.85:
            print("  SUSPECT: a single worker never saturated a core, so "
                  "this run cannot say what workers buy")


def seal_cost(uri: str, docs: int, pad: int, runs: int) -> int:
    """What sealing costs per document, measured rather than hedged.

    Separate from the sweep above and deliberately not part of it. That one
    measures a *proxy* -- sockets, BSON, the event loop -- against a fake
    upstream. This measures the two crypto operations on their own, because
    they are the only new per-document cost `--key-vault` adds and mixing
    them into a throughput number would make neither legible.

    It needs a real key vault, since the whole point is that the cost is
    libmongocrypt's and not a stand-in's. Nothing is written to the
    collection: the documents are sealed in memory and unsealed again, which
    is exactly the work the boundary does on the write and read paths.

    The number worth carrying away is the decrypt one. A read pays it per
    document on top of refusal's ~2.3us; a write pays the encrypt once.
    """
    import asyncio
    import statistics

    from voyd.engine.custody import Ephemeral

    from . import seal

    database = f"voyd_bench_seal_{os.getpid()}"

    # `list[float]` per direction, not a single figure each: this returned
    # two floats until the spread was added, and the annotation kept saying
    # so afterwards -- which is how a function that reports a median and a
    # range was documented as returning one number. Every `min`/`max`/
    # `median` call below is a type error against the old signature.
    async def go() -> tuple[list[float], list[float]]:
        vault = seal.Vault(uri, database=database,
                                sealed={"notes": (("text",), "tenant_id")},
                                custody=Ephemeral())
        await vault.open()
        try:
            body = "x" * pad
            plain = [{"_id": i, "tenant_id": "acme", "text": body}
                     for i in range(docs)]

            # Both directions are run `runs` times and reported as a
            # median with its spread, because a single pass is not a
            # measurement. Encryption in particular moves around by a
            # factor of two between passes -- key-cache warm-up and the
            # allocator, not anything this boundary controls -- and
            # printing one draw of that as "21.0us" would be this file
            # inventing a precision it does not have.
            written = []
            sealed = plain
            for _ in range(runs):
                start = time.perf_counter()
                sealed = [await vault._seal_document(
                    d, ("text",), "tenant_id", where="bench") for d in plain]
                written.append((time.perf_counter() - start) / docs * 1e6)

            read = []
            for _ in range(runs):
                start = time.perf_counter()
                kept, tally = await vault.unseal(sealed, "notes")
                read.append((time.perf_counter() - start) / docs * 1e6)
                if len(kept) != docs or tally:
                    raise SystemExit(
                        "seal bench: a document was refused during a run "
                        "with no erasure in it; this measured the wrong path")
                if kept[0]["text"] != body:
                    raise SystemExit(
                        "seal bench: the round trip did not return the "
                        "plaintext, so this measured nothing useful")
            return written, read
        finally:
            await vault.aclose()
            from pymongo import AsyncMongoClient
            scratch: AsyncMongoClient = AsyncMongoClient(uri)
            await scratch.drop_database(database)
            await scratch.close()

    written, read = asyncio.run(go())
    encrypt, decrypt = statistics.median(written), statistics.median(read)
    print(f"\nsealing, per document ({docs} docs x {pad}B, {runs} runs each "
          f"way,\nreal key vault, libmongocrypt):\n")
    print(f"  encrypt (write path)   {encrypt:6.2f}us   "
          f"(min {min(written):.2f}, max {max(written):.2f})")
    print(f"  decrypt (read path)    {decrypt:6.2f}us   "
          f"(min {min(read):.2f}, max {max(read):.2f})")
    print(f"\n  refusal alone          {REFUSAL_US:6.2f}us   "
          f"(the pure path, unchanged for unsealed collections)")
    print(f"  a sealed read          {REFUSAL_US + decrypt:6.2f}us   "
          f"= refusal + decrypt, {(REFUSAL_US + decrypt) / REFUSAL_US:.1f}x")
    print("\nThe read number is the one to carry away, and it is the stable "
          "one: a\ndocument is sealed once and served many times. Encryption "
          "moves around\nbetween passes by enough that quoting it to two "
          "decimal places would be\nfiction -- the spread above is the "
          "honest form of it.")
    return 0


# Refusal's own per-document cost, from the sweep above. Stated as a
# constant here so the comparison below is against this file's own measured
# number rather than a figure recalled from the README.
REFUSAL_US = 2.3


def cascade_cost(uri: str, parents: int, children: int, runs: int) -> int:
    """What making a refusal travel costs, measured rather than assumed.

    `lineage_field` buys the thing an erasure request actually needs: a
    revocation reaching the summary somebody wrote out of the fact. It
    buys it with round trips the boundary does not otherwise make, and
    "one extra round trip" had been a sentence in a docstring rather than
    a number -- in a repository whose whole argument is the difference.

    Two operations pay, and they pay differently:

    **A delete** resolves the ids its filter matched, marks every
    descendant of them, and only then forwards the revocation. Two extra
    commands, whatever the filter matched, so the cost per *erasure
    request* is flat and the cost per document falls as the subtree grows.

    **An insert naming a parent** reads its ancestors so the child's
    lineage can be closed transitively. One extra command per insert,
    which is the one to watch: it is on the ordinary write path of any
    application that records derivation, not on an erasure path somebody
    runs occasionally.

    Measured against a real deployment through a real proxy, twice: once
    with a policy declaring `lineage_field` and once with the same policy
    without it. The second is the control, and it is what makes the number
    a difference rather than a latency.
    """
    import statistics
    import tempfile

    try:
        import pymongo
    except ImportError:
        raise SystemExit("pip install pymongo   (--cascade needs a driver)")

    LINEAGE = """
from voyd import guard, deadline, revocable

@guard("notes", on_delete="revoke", lineage_field="lineage")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
"""
    PLAIN = LINEAGE.replace(', lineage_field="lineage"', "")

    def timed(policy_text: str, label: str) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "voydfile.py"
            path.write_text(policy_text)
            listen = _free_port()
            host = uri.split("//", 1)[1].split("/", 1)[0]
            proxy = subprocess.Popen(
                [sys.executable, "-m", "voyd.wire", "--config",
                 str(path), "--listen", str(listen), "--target", host,
                 "--quiet"])
            try:
                wait_for(listen)
                name = f"voyd_bench_casc_{os.getpid()}"
                direct: Any = pymongo.MongoClient(uri)
                through: Any = pymongo.MongoClient(
                    f"mongodb://localhost:{listen}/?directConnection=true",
                    serverSelectionTimeoutMS=8000)
                inserts: list[float] = []
                deletes: list[float] = []
                try:
                    notes = through[name].notes
                    for _ in range(runs):
                        direct.drop_database(name)
                        roots = [notes.insert_one({"n": i}).inserted_id
                                 for i in range(parents)]
                        # One insert naming a parent, timed on its own.
                        start = time.perf_counter()
                        for i in range(children):
                            notes.insert_one(
                                {"c": i, "lineage": [roots[i % parents]]})
                        inserts.append(
                            (time.perf_counter() - start) / children * 1e6)
                        # One erasure request, cascading over the subtree.
                        start = time.perf_counter()
                        notes.delete_one({"_id": roots[0]})
                        deletes.append((time.perf_counter() - start) * 1e3)
                finally:
                    direct.drop_database(name)
                    through.close()
                    direct.close()
            finally:
                proxy.terminate()
                proxy.wait(timeout=10)
        return {"label": label,
                "insert_us": statistics.median(inserts),
                "delete_ms": statistics.median(deletes)}

    with_lineage = timed(LINEAGE, "lineage_field declared")
    without = timed(PLAIN, "the same policy without it")

    print(f"\n  {parents} parents, {children} derived documents, "
          f"{runs} runs, through a real proxy\n")
    head = f"  {'policy':30} {'insert':>12} {'delete':>12}"
    print(head)
    print("  " + "-" * (len(head) - 2))
    for row in (without, with_lineage):
        print(f"  {row['label']:30} {row['insert_us']:9.0f}us "
              f"{row['delete_ms']:9.2f}ms")

    d_insert = with_lineage["insert_us"] - without["insert_us"]
    d_delete = with_lineage["delete_ms"] - without["delete_ms"]
    print(f"\n  the cascade costs {d_insert:+.0f}us per derived insert and "
          f"{d_delete:+.2f}ms per erasure request.")
    print(f"  Per document the delete reached, that is "
          f"{d_delete * 1000 / max(children, 1):+.0f}us -- and it falls as "
          f"the subtree grows,")
    print("  because resolving the ids and marking the descendants is two "
          "commands")
    print("  whatever they matched. The insert figure is the one to watch: "
          "it is on")
    print("  an ordinary write path, not on an erasure path somebody runs "
          "twice a year.")
    return 0


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--role", choices=["upstream", "client"])
    ap.add_argument("--port", type=int, default=29500)
    ap.add_argument("--workers", default="0,1,2,4,8",
                    help="worker counts to sweep; 0 means no proxy at all, "
                         "which is the control")
    ap.add_argument("--clients", type=int, default=8)
    ap.add_argument("--pipeline", type=int, default=8,
                    help="requests in flight per client. With one, this "
                         "measures loopback latency rather than throughput")
    ap.add_argument("--seconds", type=float, default=8.0)
    ap.add_argument("--docs", type=int, default=100,
                    help="documents per cursor batch -- the unit of work")
    ap.add_argument("--refuse-every", type=int, default=10,
                    help="one document in N is revoked. Zero refusals skips "
                         "the re-encode, which is half the work")
    ap.add_argument("--pad", type=int, default=200)
    ap.add_argument("--dims", type=int, default=0,
                    help="give every document an embedding of N floats. The "
                         "retrieval-shaped workload: 1536 is OpenAI's and "
                         "Voyage's common width. Default 0 keeps the short "
                         "documents the earlier rows on this page used")
    ap.add_argument("--upstream-procs", type=int, default=4)
    ap.add_argument("--with-metrics", action="store_true",
                    help="run with --metrics on, to show that flushing "
                         "counters on a timer costs the message path "
                         "nothing measurable")
    ap.add_argument("--policy", help="keep the generated voydfile here")
    ap.add_argument("--cascade", action="store_true",
                    help="measure what `lineage_field` costs: the round "
                         "trips a cascading erasure and a derived insert "
                         "add, against the same policy without it. Needs a "
                         "real deployment")
    ap.add_argument("--cascade-parents", type=int, default=4)
    ap.add_argument("--cascade-children", type=int, default=40)
    ap.add_argument("--seal", action="store_true",
                    help="instead of the sweep, measure what --key-vault "
                         "costs per document: one encrypt and one decrypt "
                         "against a real key vault. Needs a reachable "
                         "MongoDB and the crypto extra")
    ap.add_argument("--seal-uri",
                    default=os.getenv(
                        "VOYD_TEST_MONGO_URI",
                        "mongodb://localhost:27018/?directConnection=true"),
                    help="the deployment --seal builds its key vault in")
    ap.add_argument("--seal-runs", type=int, default=5)
    args = ap.parse_args(argv)

    if args.cascade:
        return cascade_cost(args.seal_uri, args.cascade_parents,
                            args.cascade_children, args.seal_runs)

    if args.seal:
        return seal_cost(args.seal_uri, args.docs * 5, args.pad,
                         args.seal_runs)

    if args.role == "upstream":
        signal.signal(signal.SIGTERM, lambda *_: os._exit(0))
        be_upstream(args.port, args.docs, args.refuse_every, args.pad,
                    args.upstream_procs, args.dims)
        return 0

    args.workers = [int(x) for x in str(args.workers).split(",") if x != ""]
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
