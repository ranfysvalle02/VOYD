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
