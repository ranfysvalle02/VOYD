#!/usr/bin/env python3
"""What the boundary refused, while it is still running.

Counters printed on shutdown answer "what did that process do?" after it
is too late to do anything. An operator needs the other question --
*what is it doing now?* -- and `LIMITS.md` has said for a while that this
is the first thing anybody running it would ask for.

**The shape of the problem is `--workers`.** Counters live in N address
spaces. Three ways to put them back together, and only one of them is
right here:

- *A port per worker.* Pushes the aggregation onto whoever is scraping,
  and their sum is only as correct as their service discovery.
- *Workers push to the parent over a pipe.* An IPC round trip on a
  reporting path, and a worker blocked writing to a full pipe is a worker
  not serving traffic. Reporting must never be able to stall refusal.
- *A slab of shared memory, one slot per worker.* Each worker is the
  only writer to its own slot, so there are no locks and no coordination
  at all; the reader sums N slots. This is that.

**Counters are flushed on a timer, not per document.** Refusal costs
about 2.3us per document and a write to shared memory on that path would
be a measurable tax on the thing being measured. The loop copies its
in-process integers into the slab once a second, which is finer than any
scrape interval anybody will configure, and the hot path stays arithmetic
on a Python int. The staleness is real and is stated in the exposition
itself as `voyd_metrics_age_seconds`.

**It binds loopback, always.** There is no flag to change that, for the
same reason the proxy refuses to serve plaintext off-loopback: a refusal
count broken down by reason is a description of what a corpus contains
and who has been probing it. `deadline` climbing is the system working;
`not_cleared` climbing is somebody trying doors. That second series is
not something to hand to the network because it was convenient.
"""

from __future__ import annotations

import mmap
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from voyd.engine.admission import reasons as R

# The reason vocabulary, fixed here on purpose. `reasons.py` calls these
# "stable strings ... renaming one is a breaking change to somebody's
# alert", and a metrics surface that discovered its own label values at
# runtime would turn that breaking change into a silent one: the old
# series would simply stop, which on most dashboards renders as a healthy
# flat line rather than as an error. Listing them makes a rename fail
# here, loudly, at import.
REASONS: tuple[str, ...] = (
    R.DEADLINE, R.REVOKED, R.UNREADABLE, R.QUARANTINED, R.WRONG_MODEL,
    R.NOT_CLEARED, R.UNRECOVERABLE, R.OFF_SCOPE, R.OVER_BUDGET,
    R.UNCOSTED, R.REDUNDANT, R.KEY_UNAVAILABLE, R.UNNAMED,
)
# Anything the engine reports that is not above. It exists so a new reason
# is undercounted in its own series rather than dropped from the totals --
# a number that is quietly missing is worse than one that is quietly
# lumped, because only the second one adds up.
OTHER = "other"

# Per-worker fields that are not per-collection.
GLOBAL = (
    "connections_open",
    "connections_total",
    "connections_refused_total",
    "upstream_reresolve_total",
    "messages_from_client_total",
    "messages_from_upstream_total",
    "worker_flushes_total",
)


class Layout:
    """Where each number lives inside one worker's slot.

    Fixed at startup from the collections the policy declared, which is
    the same reason the reason list is fixed: a slot whose shape depended
    on traffic could not be summed across workers that had seen different
    traffic.
    """

    def __init__(self, collections: tuple[str, ...]):
        self.collections = tuple(sorted(collections))
        self.names: list[tuple[str, str | None, str | None]] = []
        for field in GLOBAL:
            self.names.append((field, None, None))
        for collection in self.collections:
            for field in ("admitted_total", "refused_total", "revoked_total"):
                self.names.append((field, collection, None))
            for reason in (*REASONS, OTHER):
                self.names.append(("refused_by_reason_total", collection,
                                   reason))
        self.size = len(self.names)

    def index(self, field: str, collection: str | None = None,
              reason: str | None = None) -> int:
        return self.names.index((field, collection, reason))


# The supervisor's own numbers, written by the parent and never by a
# worker. They live in a header ahead of the slots for the same reason the
# slots are per worker: exactly one process writes each word.
HEADER = ("workers_configured", "workers_live", "worker_restarts_total")


class Slab:
    """One shared page per worker, plus a header the parent owns.

    Anonymous `mmap` created before the fork, so every worker inherits the
    same pages. A worker only ever writes its own slot, and the reader
    only ever sums, so the strongest thing a racing reader can see is a
    slot that is half a second old -- never a torn total, because each
    counter is a single aligned 64-bit store.
    """

    def __init__(self, workers: int, layout: Layout):
        self.workers = max(workers, 1)
        self.layout = layout
        self.stride = layout.size + 1            # +1 for the flush timestamp
        self.head = len(HEADER)
        self.buf = mmap.mmap(
            -1, (self.head + self.stride * self.workers) * 8)
        self.set_header(workers_configured=self.workers,
                        workers_live=self.workers)

    # -- the header, written by the supervisor ----------------------------

    def set_header(self, **fields: int) -> None:
        for name, value in fields.items():
            struct.pack_into("<q", self.buf, HEADER.index(name) * 8,
                             int(value))

    def header(self) -> dict[str, int]:
        return {name: struct.unpack_from("<q", self.buf, i * 8)[0]
                for i, name in enumerate(HEADER)}

    def bump(self, name: str, by: int = 1) -> None:
        self.set_header(**{name: self.header()[name] + by})

    # -- the slots, written by the workers --------------------------------

    def _base(self, slot: int) -> int:
        return (self.head + slot * self.stride) * 8

    def write(self, slot: int, values: list[int], at: float) -> None:
        base = self._base(slot)
        struct.pack_into(f"<{self.layout.size}q", self.buf, base, *values)
        struct.pack_into("<q", self.buf, base + self.layout.size * 8,
                         int(at * 1000))

    def clear(self, slot: int) -> None:
        """Forget a slot entirely. Used when a worker is replaced.

        Its counters go with it. That is a real loss and the alternative
        is worse: leaving them means a restarted worker's fresh counts are
        added to a dead worker's, and a counter that double counts across
        a restart is one an operator cannot reason about at all.
        `worker_restarts_total` is what marks the discontinuity.
        """
        base = self._base(slot)
        self.buf[base:base + self.stride * 8] = b"\x00" * (self.stride * 8)

    def ages(self) -> list[float]:
        """How long since each slot was written. -1 for never."""
        out = []
        now = time.time()
        for slot in range(self.workers):
            stamp = struct.unpack_from(
                "<q", self.buf,
                self._base(slot) + self.layout.size * 8)[0]
            out.append(-1.0 if stamp == 0 else now - stamp / 1000)
        return out

    def read(self) -> tuple[list[int], float]:
        """Every slot, summed, with the age of the *stalest* live one.

        Stalest, not freshest, and the difference is the whole point. An
        earlier version reported the freshest, which meant one wedged
        worker among eight was completely invisible: the other seven kept
        the number at zero while a third of the traffic went unrefused by
        a loop that had stopped flushing. Measured -- a `SIGKILL`ed worker
        left `voyd_metrics_age_seconds` reading 0.095.

        A staleness number that only reports the healthiest worker is a
        liveness check that cannot fail.
        """
        totals = [0] * self.layout.size
        for slot in range(self.workers):
            base = self._base(slot)
            got = struct.unpack_from(f"<{self.layout.size}q", self.buf, base)
            stamp = struct.unpack_from("<q", self.buf,
                                       base + self.layout.size * 8)[0]
            if stamp == 0:
                continue                 # a worker that has not flushed yet
            for i, value in enumerate(got):
                totals[i] += value
        seen = [age for age in self.ages() if age >= 0]
        return totals, (max(seen) if seen else -1.0)


class Meter:
    """One worker's counters, incremented in process and flushed on a timer.

    Plain integer attributes rather than anything clever: this is touched
    on the message path, and the whole argument for flushing on a timer is
    that the message path should not pay for reporting.
    """

    def __init__(self, layout: Layout, slab: Slab, slot: int):
        self.layout = layout
        self.slab = slab
        self.slot = slot
        self.connections_open = 0
        self.connections_total = 0
        self.connections_refused_total = 0
        self.upstream_reresolve_total = 0
        self.messages_from_client_total = 0
        self.messages_from_upstream_total = 0
        self.worker_flushes_total = 0

    def flush(self, guards: dict) -> None:
        self.worker_flushes_total += 1
        values = [0] * self.layout.size
        for field in GLOBAL:
            values[self.layout.index(field)] = getattr(self, field)
        for name, guard in guards.items():
            if name not in self.layout.collections:
                continue
            values[self.layout.index("admitted_total", name)] = guard.admitted
            values[self.layout.index("refused_total", name)] = guard.refused
            values[self.layout.index("revoked_total", name)] = guard.revoked
            spare = 0
            for reason, count in guard.reasons().items():
                if reason in REASONS:
                    values[self.layout.index("refused_by_reason_total",
                                             name, reason)] = count
                else:
                    spare += count
            values[self.layout.index("refused_by_reason_total", name,
                                     OTHER)] = spare
        self.slab.write(self.slot, values, time.time())


# ---------------------------------------------------------------------------
# Exposition.
# ---------------------------------------------------------------------------

HELP = {
    "connections_open": ("gauge", "Client connections currently open."),
    "connections_total": ("counter", "Client connections accepted."),
    "connections_refused_total": (
        "counter", "Connections closed at the limit rather than queued."),
    "upstream_reresolve_total": (
        "counter",
        "Times the upstream was invalidated by the server's own error. "
        "Climbing means elections, not a problem with this process."),
    "messages_from_client_total": ("counter", "Wire messages from clients."),
    "messages_from_upstream_total": ("counter", "Wire messages from upstream."),
    "worker_flushes_total": (
        "counter",
        "Flushes summed over every worker. For liveness use "
        "voyd_worker_flush_age_seconds instead: this total keeps climbing "
        "while one worker is wedged, because the healthy ones carry it."),
    "admitted_total": ("counter", "Documents a prompt was allowed to see."),
    "refused_total": ("counter", "Documents refused on the read path."),
    "revoked_total": ("counter", "Deletes rewritten as revocations."),
    "refused_by_reason_total": (
        "counter",
        "Refusals by reason. `deadline` climbing is the system working; "
        "`not_cleared` or `off_scope` climbing is worth a page."),
}


def render(slab: Slab) -> bytes:
    """Prometheus text exposition, version 0.0.4."""
    totals, age = slab.read()
    layout = slab.layout
    lines: list[str] = []

    head = slab.header()
    lines.append("# HELP voyd_metrics_age_seconds Age of the STALEST worker "
                 "flush -- the worst one, so a single wedged worker among "
                 "many is visible. Counters flush on a timer so the message "
                 "path does not pay for reporting; -1 means none has flushed.")
    lines.append("# TYPE voyd_metrics_age_seconds gauge")
    lines.append(f"voyd_metrics_age_seconds {age:.3f}")

    lines.append("# HELP voyd_worker_flush_age_seconds Age of each worker's "
                 "last flush, by slot. This is the liveness signal: a slot "
                 "climbing while the others stay flat is one wedged or dead "
                 "worker, which no aggregate can show you.")
    lines.append("# TYPE voyd_worker_flush_age_seconds gauge")
    for slot, each in enumerate(slab.ages()):
        lines.append(f'voyd_worker_flush_age_seconds{{worker="{slot}"}} '
                     f"{each:.3f}")

    lines.append("# HELP voyd_workers_configured Workers asked for.")
    lines.append("# TYPE voyd_workers_configured gauge")
    lines.append(f"voyd_workers_configured {head['workers_configured']}")
    lines.append("# HELP voyd_workers_live Workers the supervisor can still "
                 "see. Below configured means one died; alert on the "
                 "difference, not on either number alone.")
    lines.append("# TYPE voyd_workers_live gauge")
    lines.append(f"voyd_workers_live {head['workers_live']}")
    lines.append("# HELP voyd_worker_restarts_total Workers replaced after "
                 "dying. Any value above zero is a crash that happened; a "
                 "climbing one is a crash loop.")
    lines.append("# TYPE voyd_worker_restarts_total counter")
    lines.append(f"voyd_worker_restarts_total {head['worker_restarts_total']}")

    grouped: dict[str, list[tuple[dict, int]]] = {}
    for (field, collection, reason), value in zip(layout.names, totals):
        labels = {}
        if collection:
            labels["collection"] = collection
        if reason:
            labels["reason"] = reason
        grouped.setdefault(field, []).append((labels, value))

    for field, series in grouped.items():
        kind, text = HELP.get(field, ("counter", ""))
        lines.append(f"# HELP voyd_{field} {text}")
        lines.append(f"# TYPE voyd_{field} {kind}")
        for labels, value in series:
            tags = ",".join(f'{k}="{_escape(v)}"' for k, v in labels.items())
            lines.append(f"voyd_{field}{{{tags}}} {value}" if tags
                         else f"voyd_{field} {value}")
    return ("\n".join(lines) + "\n").encode()


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "")


class _Handler(BaseHTTPRequestHandler):
    slab: Slab

    def do_GET(self) -> None:          # noqa: N802 - http.server's spelling
        if self.path.split("?")[0] not in ("/metrics", "/"):
            self.send_error(404)
            return
        body = render(self.slab)
        self.send_response(200)
        self.send_header("Content-Type",
                         "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:
        """Silent. A scrape every fifteen seconds would otherwise be the
        only thing in the log, and a log that is all heartbeat is a log
        nobody reads the real lines in."""


def serve(port: int, slab: Slab) -> ThreadingHTTPServer:
    """Start the exposition on loopback, in a daemon thread.

    A thread rather than a route on the event loop, deliberately: reading
    the slab touches no asyncio state, so a scrape cannot interleave with
    a connection's teardown, and a scraper that hangs mid-response cannot
    occupy the loop that is supposed to be refusing documents.
    """
    handler = type("Handler", (_Handler,), {"slab": slab})
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True,
                     name="voyd-metrics").start()
    return httpd
