"""The wire codec, which is where the one silent bug lived.

`decode_op_msg` reads a kind-0 body by slicing to the end of the payload.
On a message that carries a **kind-1 document sequence** after the body --
which every write command does -- the trailing bytes land inside the BSON and
it fails, returning `None`. The detection above it read that `None` as
"not a delete", so every delete was forwarded and really deleted, the driver
was told `deleted_count=1`, and nothing anywhere said otherwise.

That is exactly the failure this project exists to make impossible: an
instrument that is wrong and quiet. So the codec is tested first and tested
alone, with no database anywhere near it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
bson = pytest.importorskip("bson")
import voyd_wire as w  # noqa: E402

BODY = {"delete": "notes", "ordered": True, "$db": "app"}
DELETES = [{"q": {"_id": 1}, "limit": 1}, {"q": {"tag": "x"}, "limit": 0}]


def test_a_body_only_message_round_trips():
    raw = w.encode_sections(7, 0, 0, BODY)
    flags, body, ident, docs = w.decode_sections(raw)
    assert (body, ident, docs) == (BODY, None, [])
    assert flags == 0


def test_a_message_with_a_document_sequence_round_trips():
    """The case that was broken, and the reason this file is first."""
    raw = w.encode_sections(7, 0, 0, BODY, "deletes", DELETES)
    flags, body, ident, docs = w.decode_sections(raw)
    assert body == BODY
    assert ident == "deletes"
    assert docs == DELETES


def test_the_header_length_matches_the_bytes():
    """A wrong length desynchronises the stream and every later message is
    garbage -- a failure that looks like the database going away."""
    import struct
    raw = w.encode_sections(7, 0, 0, BODY, "deletes", DELETES)
    assert struct.unpack("<i", raw[:4])[0] == len(raw)


def test_the_kind_zero_reader_is_honest_about_a_sequence_it_cannot_read():
    """`decode_op_msg` may return `None` -- it may not return a *wrong body*.

    Returning `None` is fine and is what it does; the bug was never here, it
    was in a caller treating `None` as a decision rather than as an absence.
    This pins the guarantee that caller is entitled to rely on.
    """
    raw = w.encode_sections(7, 0, 0, BODY, "deletes", DELETES)
    got = w.decode_op_msg(raw)
    assert got is None or got[1] == BODY, (
        "a partial read that returned a plausible-but-wrong body would be "
        "undetectable downstream")


def test_the_checksum_bit_is_cleared_when_a_message_is_rewritten():
    """A stale CRC over a body we just changed is worse than no CRC. The
    protocol makes the checksum optional; a wrong one is not optional."""
    raw = w.encode_sections(7, 0, w.FLAG_CHECKSUM, BODY)
    flags, body, _, _ = w.decode_sections(raw)
    assert not flags & w.FLAG_CHECKSUM
    assert body == BODY


# --------------------------------------------------------------------------
# Reading lazily must not read differently.
#
# `enforce` decodes a reply with `LAZY` so that a batch nobody guards costs
# four field reads instead of a Python float per dimension per document. That
# is a speed change hiding inside the enforcement path, which is the most
# dangerous place to put one: a decoder that disagrees with the old decoder
# about a deadline does not get slower, it gets *wrong*, quietly, in the
# direction of admitting something. So the two are pinned against each other
# rather than trusted to agree.
# --------------------------------------------------------------------------

from datetime import datetime, timedelta, timezone  # noqa: E402

from voyd.engine.admission.rules import Deadline, revoked  # noqa: E402
from voyd.engine.admission.spec import AdmissionSpec  # noqa: E402

_NOW = datetime.now(timezone.utc)
BATCH = [
    {"_id": 1, "t": "live", "expire_at": _NOW + timedelta(days=1)},
    {"_id": 2, "t": "expired", "expire_at": _NOW - timedelta(days=1)},
    {"_id": 3, "t": "revoked", "expire_at": _NOW + timedelta(days=1),
     "forgotten": _NOW},
    {"_id": 4, "t": "no deadline at all"},
]
SPEC = AdmissionSpec("notes", rules=(Deadline(at_field="expire_at"),
                                     revoked("forgotten")))


def _reply(docs, ns="app.notes"):
    return w.encode_op_msg(7, 7, 0, {"ok": 1.0,
                                     "cursor": {"id": 0, "ns": ns,
                                                "firstBatch": docs}})


def _kept(raw):
    """The ids that came back out, however the reply was encoded."""
    flags, reply = w.decode_op_msg(raw)
    return [d["_id"] for d in reply["cursor"]["firstBatch"]]


def test_the_lazy_decoder_reads_the_same_values_as_the_eager_one():
    raw = _reply(BATCH)
    eager = w.decode_op_msg(raw)[1]
    lazy = w.decode_op_msg(raw, w.LAZY)[1]
    assert [dict(d) for d in lazy["cursor"]["firstBatch"]] == \
           eager["cursor"]["firstBatch"]


def test_a_deadline_is_not_tz_aware_in_either_decoder():
    """Pinned because it is the difference that would not raise.

    Neither decoder attaches a timezone -- `bson` is configured that way on
    both paths, and `voyd.engine.time.aware` reads naive as UTC because that
    is what BSON stored. If somebody turns `tz_aware` on for one of them, the
    comparison does not fail loudly, it just starts answering a slightly
    different question about the boundary between yesterday and today.
    """
    raw = _reply(BATCH)
    for opts in (None, w.LAZY):
        doc = w.decode_op_msg(raw, opts)[1]["cursor"]["firstBatch"][0]
        assert doc["expire_at"].tzinfo is None


def test_lazy_reading_does_not_change_one_verdict():
    raw = _reply(BATCH)
    guards = {"notes": w.Guard(SPEC)}
    assert _kept(w.enforce(raw, 7, 7, guards, False)) == [1, 4], (
        "the expired and the revoked are refused; a document with no "
        "deadline was never given one and is not a refusal")


def test_an_unguarded_batch_is_returned_as_the_identical_bytes():
    """The whole point of the lazy read: this path must not rebuild anything."""
    raw = _reply(BATCH, ns="app.somewhere_else")
    assert w.enforce(raw, 7, 7, {"notes": w.Guard(SPEC)}, False) is raw


def test_a_batch_with_nothing_to_refuse_is_also_untouched():
    raw = _reply([BATCH[0]])
    assert w.enforce(raw, 7, 7, {"notes": w.Guard(SPEC)}, False) is raw


def test_a_refused_batch_re_encodes_every_surviving_field():
    """Documents are spliced back from their original bytes, not rebuilt.

    A document that survives must arrive whole. This is the failure that a
    faster decoder invites: keeping the verdict correct while quietly
    dropping a field nobody wrote a test for.
    """
    fat = [dict(BATCH[0], embedding=[0.5] * 64, nested={"a": [1, {"b": 2}]}),
           BATCH[1]]
    raw = _reply(fat)
    # The comparison is against the *round trip*, not against the Python
    # dict: BSON keeps milliseconds and no timezone, so the original object
    # is not what any correct decoder would hand back.
    survivor = w.decode_op_msg(raw)[1]["cursor"]["firstBatch"][0]
    out = w.enforce(raw, 7, 7, {"notes": w.Guard(SPEC)}, False)
    got = w.decode_op_msg(out)[1]["cursor"]["firstBatch"]
    assert len(got) == 1 and dict(got[0]) == survivor
