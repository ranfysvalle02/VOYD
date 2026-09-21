"""Counters on shutdown answer "what did that process do?" too late.

`LIMITS.md` carried "no metrics endpoint" as the first thing anybody
operating this would ask for, and that was true for as long as the only
way to read a refusal count was to kill the process. These are the tests
for the surface that closed it.

The interesting ones are not about HTTP. They are about the two ways a
metrics surface lies: a number that is quietly missing because nobody
mapped it, and a label that silently stopped being emitted because
somebody renamed the thing behind it. Both render on a dashboard as a
healthy flat line.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import voyd_metrics as m  # noqa: E402

from voyd.engine.admission import reasons as R  # noqa: E402

from .conftest import free_port, mongo_host  # noqa: E402

pymongo = pytest.importorskip("pymongo")


# --------------------------------------------------------------------------
# The vocabulary. A renamed reason must break here, not on a dashboard.
# --------------------------------------------------------------------------

# Names in `reasons.py` that are deliberately not refusal reasons.
NOT_A_REASON = {"REACHABLE", "REFUSED", "UNKNOWN", "LIFTED", "LIFT_BATCH"}


def test_every_refusal_reason_in_the_engine_has_a_series():
    """`reasons.py` says renaming one of these is a breaking change to
    somebody's alert. A reason added there and not here would be counted
    into `other` and vanish from its own series -- which on most
    dashboards is a flat line, not an error."""
    declared = {name for name in dir(R)
                if name.isupper() and name not in NOT_A_REASON
                and isinstance(getattr(R, name), str)}
    exported = {getattr(R, name) for name in declared}
    missing = exported - set(m.REASONS)
    assert not missing, (
        f"reasons.py declares {sorted(missing)} with no series in "
        f"voyd_metrics.REASONS; add them or add them to NOT_A_REASON")


def test_no_series_survives_its_reason_being_renamed():
    for reason in m.REASONS:
        assert isinstance(reason, str) and reason


# --------------------------------------------------------------------------
# The slab: one writer per slot, summed by the reader.
# --------------------------------------------------------------------------

def test_slots_are_summed_across_workers():
    layout = m.Layout(("notes",))
    slab = m.Slab(3, layout)
    for slot in range(3):
        meter = m.Meter(layout, slab, slot)
        meter.connections_total = 10 + slot
        meter.flush({})
    totals, age = slab.read()
    assert totals[layout.index("connections_total")] == 33
    assert 0 <= age < 5


def test_a_worker_that_never_flushed_is_not_counted_as_zero_age():
    """An unflushed slot is absence, not a fresh reading of nothing."""
    layout = m.Layout(("notes",))
    slab = m.Slab(4, layout)
    meter = m.Meter(layout, slab, 0)
    meter.connections_total = 7
    meter.flush({})
    totals, age = slab.read()
    assert totals[layout.index("connections_total")] == 7
    assert age >= 0, "one worker did flush, so there is an age"

    fresh = m.Slab(2, m.Layout(("notes",)))
    assert fresh.read()[1] == -1.0, "nothing flushed at all"


def test_an_unknown_reason_is_bucketed_rather_than_dropped():
    """A number quietly missing is worse than one quietly lumped, because
    only the second one still adds up."""
    layout = m.Layout(("notes",))
    slab = m.Slab(1, layout)
    meter = m.Meter(layout, slab, 0)

    class Fake:
        admitted, refused, revoked = 5, 3, 0

        def reasons(self):
            return {R.DEADLINE: 1, "a_reason_from_the_future": 2}

    meter.flush({"notes": Fake()})
    totals, _age = slab.read()
    at = layout.index("refused_by_reason_total", "notes", R.DEADLINE)
    other = layout.index("refused_by_reason_total", "notes", m.OTHER)
    assert totals[at] == 1 and totals[other] == 2
    assert totals[layout.index("refused_total", "notes")] == 3


def test_a_collection_with_no_guard_is_not_written_into_a_neighbours_slot():
    layout = m.Layout(("notes",))
    slab = m.Slab(1, layout)
    meter = m.Meter(layout, slab, 0)

    class Fake:
        admitted, refused, revoked = 1, 1, 1

        def reasons(self):
            return {}

    meter.flush({"notes": Fake(), "undeclared": Fake()})
    totals, _ = slab.read()
    assert totals[layout.index("admitted_total", "notes")] == 1


# --------------------------------------------------------------------------
# Exposition.
# --------------------------------------------------------------------------

def test_the_exposition_parses_as_prometheus_text():
    layout = m.Layout(("notes", "tickets"))
    slab = m.Slab(1, layout)
    m.Meter(layout, slab, 0).flush({})
    body = m.render(slab).decode()

    seen_help, seen_type = set(), set()
    for line in body.splitlines():
        if line.startswith("# HELP "):
            seen_help.add(line.split()[2])
        elif line.startswith("# TYPE "):
            name, kind = line.split()[2:4]
            assert kind in ("counter", "gauge"), line
            seen_type.add(name)
        elif line:
            metric, _space, value = line.partition(" ")
            float(value)                      # raises if it is not a number
            assert metric.startswith("voyd_"), line
    assert seen_help == seen_type, "every series is documented and typed"
    assert 'collection="tickets"' in body


def test_staleness_is_published_rather_than_assumed():
    """Counters flush on a timer so the message path stays cheap. That is
    a real tradeoff, so the age is in the exposition instead of being
    something an operator has to know."""
    slab = m.Slab(1, m.Layout(("notes",)))
    assert "voyd_metrics_age_seconds -1" in m.render(slab).decode()


# --------------------------------------------------------------------------
# The whole thing, running.
# --------------------------------------------------------------------------

def _wait(port, proc, seconds=20):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if proc.poll() is not None:
            pytest.fail("voyd-wire exited")
        try:
            with socket.create_connection(("127.0.0.1", port), 0.2):
                return
        except OSError:
            time.sleep(0.1)
    pytest.fail("voyd-wire never listened")


def _scrape(port: int) -> str:
    return urllib.request.urlopen(
        f"http://127.0.0.1:{port}/metrics", timeout=5).read().decode()


def test_metrics_are_summed_across_workers_while_it_runs(db, tmp_path):
    """The point of the whole shared-memory arrangement: three workers,
    one set of numbers, available before the process dies."""
    db.notes.insert_many([{"t": "a"}, {"t": "b"},
                          {"t": "gone", "forgotten": True}])
    policy = tmp_path / "voydfile.py"
    policy.write_text("from voyd import guard, deadline, revocable\n"
                      "@guard('notes')\n"
                      "class N:\n"
                      "    expire_at = deadline()\n"
                      "    forgotten = revocable()\n")
    port, metrics = free_port(), free_port()
    proc = subprocess.Popen(
        [sys.executable, "tools/voyd_wire.py", "--config", str(policy),
         "--listen", str(port), "--target", mongo_host(),
         "--workers", "3", "--metrics", str(metrics), "--quiet"],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
        start_new_session=True)
    try:
        _wait(port, proc)
        for _ in range(5):
            client = pymongo.MongoClient(
                f"mongodb://localhost:{port}/?directConnection=true",
                serverSelectionTimeoutMS=8000)
            try:
                assert len(list(client[db.name].notes.find({}))) == 2
            finally:
                client.close()
        time.sleep(1.5)                  # a flush interval, plus slack
        body = _scrape(metrics)
    finally:
        proc.terminate()
        proc.wait(timeout=30)

    assert "voyd_workers 3" in body
    assert 'voyd_admitted_total{collection="notes"} 10' in body, body
    assert 'voyd_refused_total{collection="notes"} 5' in body, body
    assert ('voyd_refused_by_reason_total{collection="notes",'
            'reason="revoked"} 5') in body, body
    age = float([ln for ln in body.splitlines()
                 if ln.startswith("voyd_metrics_age_seconds ")][0].split()[1])
    assert 0 <= age < 5, f"counters are stale: {age}s"


def test_the_metrics_port_is_loopback_only():
    """A refusal count broken down by reason describes what a corpus holds
    and who has been probing it. There is no flag to put that on a
    network, and this is what says so.

    Asserted on the bound address rather than by failing to reach it from
    outside: a host with no routable address of its own would make that
    version pass for the wrong reason, which is the kind of test that
    reports green on a laptop and proves nothing on a server.
    """
    slab = m.Slab(1, m.Layout(("notes",)))
    httpd = m.serve(free_port(), slab)
    try:
        assert httpd.server_address[0] == "127.0.0.1"
    finally:
        httpd.shutdown()
        httpd.server_close()

    # And there is no way to ask for anything else.
    source = (ROOT / "tools" / "voyd_metrics.py").read_text()
    assert source.count("0.0.0.0") == 0, \
        "voyd_metrics must not be able to bind outward"
    helptext = subprocess.run(
        [sys.executable, "tools/voyd_wire.py", "--help"],
        cwd=ROOT, capture_output=True, text=True).stdout
    assert "--metrics PORT" in helptext
    assert "--metrics-host" not in helptext and "--metrics-bind" not in helptext


def test_a_scrape_of_something_that_is_not_metrics_is_a_404():
    slab = m.Slab(1, m.Layout(("notes",)))
    port = free_port()
    httpd = m.serve(port, slab)
    try:
        with pytest.raises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/debug", timeout=5)
        assert caught.value.code == 404
    finally:
        httpd.shutdown()
        httpd.server_close()
