"""The numbers in LIMITS come from a script, so the script is load-bearing.

A benchmark that quietly stops measuring the right thing is worse than no
benchmark, because its output still looks like evidence. These are fast
and check the two properties that make the sweep mean anything: the
harness has to be faster than the thing it measures, and the thing it
measures has to still be refusing while it is measured.

Nothing here asserts a throughput number. Those depend on the machine, and
a test that pins them would fail on every laptop that is not this one --
which is how a suite teaches people to ignore it.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import voyd_bench as b  # noqa: E402
import voyd_wire as w  # noqa: E402


def test_the_canned_reply_is_a_cursor_batch_the_boundary_will_admit():
    """If `enforce` does not recognise this as a guarded batch it forwards
    it untouched -- and the benchmark would be timing a plain TCP relay
    while reporting it as the cost of refusal."""
    raw = b.reply(docs=10, refuse_every=5, pad=8)
    decoded = w.decode_op_msg(raw)
    assert decoded is not None
    _flags, body = decoded
    assert body["cursor"]["ns"] == b.NAMESPACE
    assert len(body["cursor"]["firstBatch"]) == 10
    assert w._collection_of(body) == b.COLLECTION


def test_the_batch_actually_contains_refusable_documents():
    """`enforce` returns the original bytes when nothing was refused, so a
    fully admissible batch measures the decode and skips the re-encode --
    half the work, and the cheaper half."""
    batch = w.decode_op_msg(b.reply(100, 10, 8))[1]["cursor"]["firstBatch"]
    revoked = [d for d in batch if d.get("forgotten")]
    assert len(revoked) == 10, "one in ten, which is what the sweep reports"


def test_the_guard_refuses_exactly_the_share_the_sweep_checks_for():
    """The whole enforcement check in the benchmark rests on this ratio."""
    guard = w.Guard.defaults(b.COLLECTION, at_field="expire_at",
                             mark_field="forgotten")
    batch = w.decode_op_msg(b.reply(100, 10, 8))[1]["cursor"]["firstBatch"]
    kept = guard.filter(batch)
    assert len(kept) == 90 and guard.refused == 10


@pytest.mark.parametrize("said,expected", [
    ("voyd-wire: served 900, refused 100 {}", "refused 10.0%"),
    ("voyd-wire: served 1000, refused 0 {}", "LEAKED 0.0%"),
    ("nothing at all", "?? no summary"),
])
def test_a_boundary_that_stopped_refusing_is_reported_as_a_failure(
        said, expected):
    """A proxy that got fast by forwarding everything would post the best
    numbers in the table. That has to read as a failure, not a record."""
    assert b._enforced(said, refuse_every=10) == expected


def test_the_sweep_runs_end_to_end_and_the_control_beats_the_proxy():
    """One short real sweep. Not for the numbers -- for the invariant that
    the harness is not what is being measured."""
    out = subprocess.run(
        [sys.executable, "tools/voyd_bench.py", "--workers", "0,1",
         "--seconds", "1.5", "--clients", "2", "--docs", "20"],
        cwd=ROOT, capture_output=True, text=True, timeout=180)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "the harness had room" in out.stdout, out.stdout
    assert "refused 10.0%" in out.stdout, out.stdout
    assert "LEAKED" not in out.stdout, out.stdout
