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

from voyd.wire import bench as b
from voyd.wire import codec
from voyd.wire import policy


def test_the_canned_reply_is_a_cursor_batch_the_boundary_will_admit():
    """If `enforce` does not recognise this as a guarded batch it forwards
    it untouched -- and the benchmark would be timing a plain TCP relay
    while reporting it as the cost of refusal."""
    raw = b.reply(docs=10, refuse_every=5, pad=8)
    decoded = codec.decode_op_msg(raw)
    assert decoded is not None
    _flags, body = decoded
    assert body["cursor"]["ns"] == b.NAMESPACE
    assert len(body["cursor"]["firstBatch"]) == 10
    assert policy._collection_of(body) == b.COLLECTION


def test_the_batch_actually_contains_refusable_documents():
    """`enforce` returns the original bytes when nothing was refused, so a
    fully admissible batch measures the decode and skips the re-encode --
    half the work, and the cheaper half."""
    batch = codec.decode_op_msg(b.reply(100, 10, 8))[1]["cursor"]["firstBatch"]
    revoked = [d for d in batch if d.get("forgotten")]
    assert len(revoked) == 10, "one in ten, which is what the sweep reports"


def test_the_guard_refuses_exactly_the_share_the_sweep_checks_for():
    """The whole enforcement check in the benchmark rests on this ratio."""
    guard = policy.Guard.defaults(b.COLLECTION, at_field="expire_at",
                             mark_field="forgotten")
    batch = codec.decode_op_msg(b.reply(100, 10, 8))[1]["cursor"]["firstBatch"]
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
        [sys.executable, "-m", "voyd.wire.bench", "--workers", "0,1",
         "--seconds", "1.5", "--clients", "2", "--docs", "20"],
        cwd=ROOT, capture_output=True, text=True, timeout=180)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "the harness had room" in out.stdout, out.stdout
    assert "refused 10.0%" in out.stdout, out.stdout
    assert "LEAKED" not in out.stdout, out.stdout


# --------------------------------------------------------------------------
# The shape of the document is a claim about the workload.
#
# For a long time this harness could only build `{_id, i, text}` with a short
# pad, and every throughput number on LIMITS.md was therefore an answer about
# documents this boundary does not exist to protect. A retrieval corpus
# returns vectors, and a 1536-float array costs more to materialise than
# every other field in the document put together -- which is the entire cost
# `enforce` was optimised against. A benchmark that cannot express the
# expensive case will report that the expensive case is cheap.
# --------------------------------------------------------------------------

def test_the_batch_can_carry_embeddings_because_the_workload_does():
    raw = b.reply(docs=4, refuse_every=0, pad=10, dims=8)
    batch = codec.decode_op_msg(raw)[1]["cursor"]["firstBatch"]
    assert len(batch) == 4
    assert all(len(d["embedding"]) == 8 for d in batch), (
        "a proxy benchmarked only on short documents is being asked the "
        "easy question")


def test_no_dimensions_is_the_old_shape_so_the_old_rows_stay_comparable():
    """`--dims 0` must not quietly become `--dims 0.0` or an empty array.

    The earlier numbers on LIMITS.md were measured without this flag. If the
    default changed their shape, they would have to be deleted rather than
    compared against -- so the default is pinned, not assumed.
    """
    batch = codec.decode_op_msg(b.reply(docs=3, refuse_every=0, pad=10))[1]
    for doc in batch["cursor"]["firstBatch"]:
        assert "embedding" not in doc


def test_embeddings_do_not_disturb_which_documents_are_refusable():
    """The vector is payload; the verdict must still come from the mark."""
    plain = codec.decode_op_msg(b.reply(docs=20, refuse_every=5, pad=10))[1]
    fat = codec.decode_op_msg(b.reply(docs=20, refuse_every=5, pad=10, dims=4))[1]
    marked = [[d["_id"] for d in r["cursor"]["firstBatch"] if d.get("forgotten")]
              for r in (plain, fat)]
    assert marked[0] == marked[1] == [0, 5, 10, 15]
