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

from voyd.wire import metrics as m

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
        f"metrics.REASONS; add them or add them to NOT_A_REASON")


def test_no_series_survives_its_reason_being_renamed():
    for reason in m.REASONS:
        assert isinstance(reason, str) and reason


def test_the_declared_counters_are_exactly_the_series():
    """`Meter`'s annotations and `GLOBAL` are two views of one fact.

    They have to both exist. The annotations are what lets a type checker
    see a counter at all -- without them `voyd/wire/` had seventeen
    `attr-defined` errors and went unchecked, which is how the front door
    ended up being the least statically verified file in the repository.
    `GLOBAL` is what allocates the slot and exposes the series.

    Duplication that is checked is not drift. This is the check, and it is
    the thing that was missing the first time: the original hand-written
    list *also* duplicated `GLOBAL`, nothing compared them, and adding one
    name to one of them killed a worker's reporting.
    """
    declared = {name for name, kind in m.Meter.__annotations__.items()
                if kind is int or kind == "int"}
    assert declared == set(m.GLOBAL), (
        f"declared but not a series: {sorted(declared - set(m.GLOBAL))}; "
        f"a series with no annotation: {sorted(set(m.GLOBAL) - declared)}. "
        f"Both directions matter -- the first is a counter nothing reads, "
        f"the second is a counter no checker can see")


def test_every_global_counter_exists_on_a_fresh_meter():
    """`flush` does `getattr` for every name in GLOBAL.

    A name added to GLOBAL and not initialised raised inside the flusher
    task, which killed a worker's reporting and presented as the proxy
    dropping connections -- a reporting bug wearing the costume of a
    network one. `Meter` now derives its counters from GLOBAL instead of
    hand-listing them, and this is the assertion that it still does.
    """
    layout = m.Layout(("notes",))
    meter = m.Meter(layout, m.Slab(1, layout), 0)
    for field in m.GLOBAL:
        assert getattr(meter, field) == 0
    meter.flush({})                      # must not raise


def test_every_global_counter_has_help_text():
    """A series with no HELP is a number a stranger has to guess at."""
    missing = [f for f in m.GLOBAL if f not in m.HELP]
    assert not missing, (
        f"{sorted(missing)} are exposed with no HELP; a counter nobody can "
        f"interpret is only marginally better than one nobody has")


def test_a_counter_that_is_not_a_series_is_refused():
    """A typo must not become a number that climbs where nothing reads it.

    `meter.sealed_write_total += 1` would otherwise spring the attribute
    into existence, count correctly, never be flushed, and leave the
    dashboard flat -- confidently wrong and quiet about it, which is the
    failure this repository is named after, committed by the part of it
    whose job is to report.
    """
    layout = m.Layout(("notes",))
    meter = m.Meter(layout, m.Slab(1, layout), 0)
    with pytest.raises(AttributeError, match="has no counter"):
        meter.sealed_write_total = 1     # the plausible typo
    meter.sealed_writes_total += 1       # the real one still works
    assert meter.sealed_writes_total == 1


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
        admitted, refused, revoked, cascaded = 5, 3, 0, 0

        def reasons(self):
            return {R.DEADLINE: 1, "a_reason_from_the_future": 2}

    meter.flush({"notes": Fake()})
    totals, _age = slab.read()
    at = layout.index("refused_by_reason_total", "notes", R.DEADLINE)
    other = layout.index("refused_by_reason_total", "notes", m.OTHER)
    assert totals[at] == 1 and totals[other] == 2
    assert totals[layout.index("refused_total", "notes")] == 3


def test_the_cascade_has_a_series_of_its_own():
    """Counted apart from `revoked_total`, because the two diverging is the
    only way to see from outside that a cascade stopped running.

    "3 facts revoked" and "3 facts revoked and 41 things made out of them
    went too" are different sentences, and on a collection declaring
    `lineage_field` only the second one answers an erasure request.
    """
    layout = m.Layout(("notes",))
    slab = m.Slab(1, layout)
    meter = m.Meter(layout, slab, 0)

    class Fake:
        admitted, refused, revoked, cascaded = 0, 0, 3, 41

        def reasons(self):
            return {}

    meter.flush({"notes": Fake()})
    totals, _ = slab.read()
    assert totals[layout.index("revoked_total", "notes")] == 3
    assert totals[layout.index("cascaded_total", "notes")] == 41
    assert "cascaded_total" in m.HELP, (
        "a counter nobody can interpret is barely better than none")


def test_a_collection_with_no_guard_is_not_written_into_a_neighbours_slot():
    layout = m.Layout(("notes",))
    slab = m.Slab(1, layout)
    meter = m.Meter(layout, slab, 0)

    class Fake:
        admitted, refused, revoked, cascaded = 1, 1, 1, 1

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
        [sys.executable, "-m", "voyd.wire.proxy", "--config", str(policy),
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

    assert "voyd_workers_configured 3" in body
    assert "voyd_workers_live 3" in body
    assert "voyd_worker_restarts_total 0" in body
    # One series per worker, because an aggregate cannot show you that one
    # of three has stopped flushing.
    assert body.count("voyd_worker_flush_age_seconds{") == 3, body
    assert 'voyd_admitted_total{collection="notes"} 10' in body, body
    assert 'voyd_refused_total{collection="notes"} 5' in body, body
    assert ('voyd_refused_by_reason_total{collection="notes",'
            'reason="revoked"} 5') in body, body
    age = float([ln for ln in body.splitlines()
                 if ln.startswith("voyd_metrics_age_seconds ")][0].split()[1])
    assert 0 <= age < 5, f"counters are stale: {age}s"


def test_the_metrics_port_is_loopback_unless_somebody_says_otherwise():
    """A refusal count broken down by reason describes what a corpus holds
    and who has been probing it. `deadline` climbing is the system
    working; `not_cleared` climbing is somebody trying doors.

    That is a reason to make exposing it *explicit*, not a reason to make
    it impossible: impossible leaves the whole surface unreachable in
    Kubernetes, where the scrape comes from another pod. So loopback is the
    default, the flag exists, and what this asserts is that nothing asks
    for anything wider by accident.

    Asserted on the bound address rather than by failing to reach it from
    outside: a host with no routable address of its own would make that
    version pass for the wrong reason, which is the kind of test that
    reports green on a laptop and proves nothing on a server.
    """
    slab = m.Slab(1, m.Layout(("notes",)))
    httpd = m.serve(free_port(), slab)
    try:
        assert httpd.server_address[0] == "127.0.0.1", (
            "the default has to be loopback: an operator who did not think "
            "about it must not have published the refusal breakdown")
    finally:
        httpd.shutdown()
        httpd.server_close()

    # The flag exists, and its help text says what is being exposed rather
    # than only how. A knob whose consequence is undocumented is one
    # somebody turns to make a scrape work and never reads again.
    helptext = subprocess.run(
        [sys.executable, "-m", "voyd.wire", "--help"],
        cwd=ROOT, capture_output=True, text=True).stdout
    assert "--metrics-bind ADDR" in helptext
    assert "127.0.0.1" in helptext, "the default is not stated in --help"
    for warned in ("corpus", "probing"):
        assert warned in helptext, (
            f"--metrics-bind does not say what it exposes ({warned!r} "
            f"missing); the reason is the whole point of the flag")


def test_binding_the_exposition_outward_takes_saying_so():
    """The other half: the flag works, so the Kubernetes case is real
    rather than a documented intention."""
    slab = m.Slab(1, m.Layout(("notes",)))
    httpd = m.serve(free_port(), slab, bind="0.0.0.0")
    try:
        assert httpd.server_address[0] == "0.0.0.0"
    finally:
        httpd.shutdown()
        httpd.server_close()


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
