"""Bytes on a wire, before any policy reads them.

Everything this boundary enforces rests on being able to read the traffic and
put it back. A framing bug here does not produce a wrong verdict -- it
produces a proxy that forwards half of one message and the tail of another,
or one that cannot see what it is supposed to refuse, which is the failure
this project exists to remove wearing a different hat.

So the properties asserted are the ones the proxy assumes and never rechecks:
a length field from the wire cannot make this process allocate, a message
survives a decode/encode round trip byte-identically in the shape the driver
sent it, a write's kind-1 document sequence is not lost when a body is
rewritten, and a rewritten message never carries the checksum of the body it
used to be.
"""

from __future__ import annotations

import asyncio
import struct
import zlib

import bson
import pytest

from voyd.wire.codec import (FLAG_CHECKSUM, HEADER, MAX_MESSAGE, OP_COMPRESSED,
                             OP_MSG, LAZY, Hangup, ProtocolError,
                             decode_op_msg, decode_sections, encode_op_msg,
                             encode_sections, frame, read_message_async,
                             uncompress_message)


def header_of(raw: bytes):
    return struct.unpack("<iiiI", raw[:16])


async def reader_over(payload: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(payload)
    reader.feed_eof()
    return reader


# ---- framing: a length from the wire is attacker-controlled ------------

def test_the_header_is_parsed_and_its_parts_come_back_in_order():
    raw = encode_op_msg(7, 3, 0, {"ping": 1})
    msg_len, req_id, resp_to, opcode = frame(raw[:HEADER])
    assert (msg_len, req_id, resp_to, opcode) == (len(raw), 7, 3, OP_MSG)


def test_a_length_that_would_be_a_memory_blowup_is_refused():
    for bad in (MAX_MESSAGE + 1, 2_000_000_000):
        with pytest.raises(ProtocolError):
            frame(struct.pack("<iiiI", bad, 1, 0, OP_MSG))


def test_a_length_below_the_header_is_refused_rather_than_desynchronising():
    # A negative or short length silently skips the read loop and turns the
    # stream into garbage that looks like the database going away.
    for bad in (-1, 0, HEADER - 1):
        with pytest.raises(ProtocolError):
            frame(struct.pack("<iiiI", bad, 1, 0, OP_MSG))
    assert frame(struct.pack("<iiiI", HEADER, 1, 0, OP_MSG))[0] == HEADER


def test_a_peer_that_stops_on_a_boundary_is_not_the_same_event_as_a_truncation():
    async def run():
        # Nothing at all where a header should start: the peer is finished,
        # and its already-issued replies are still owed to it.
        with pytest.raises(Hangup):
            await read_message_async(await reader_over(b""))
        # Bytes and then nothing is a broken stream.
        with pytest.raises(ConnectionError) as short_header:
            await read_message_async(await reader_over(b"\x01\x02\x03"))
        assert not isinstance(short_header.value, Hangup)

        raw = encode_op_msg(1, 0, 0, {"ping": 1})
        with pytest.raises(ConnectionError) as truncated:
            await read_message_async(await reader_over(raw[:-4]))
        assert not isinstance(truncated.value, Hangup)

    asyncio.run(run())


def test_one_message_is_read_off_a_stream_carrying_two():
    async def run():
        first = encode_op_msg(1, 0, 0, {"ping": 1})
        second = encode_op_msg(2, 0, 0, {"hello": 1})
        reader = await reader_over(first + second)
        raw, msg_len, req_id, _, opcode = await read_message_async(reader)
        assert raw == first and msg_len == len(first)
        assert req_id == 1 and opcode == OP_MSG
        raw2, _, req_id2, _, _ = await read_message_async(reader)
        assert raw2 == second and req_id2 == 2

    asyncio.run(run())


def test_the_async_reader_obeys_the_same_cap_as_the_sync_one():
    async def run():
        bogus = struct.pack("<iiiI", MAX_MESSAGE + 1, 1, 0, OP_MSG)
        with pytest.raises(ProtocolError):
            await read_message_async(await reader_over(bogus + b"\x00" * 64))

    asyncio.run(run())


# ---- OP_MSG: decode, rewrite, re-encode --------------------------------

def test_a_body_survives_the_round_trip_with_its_ids_and_flags():
    body = {"find": "notes", "filter": {"owner": "a"}, "batchSize": 10}
    raw = encode_op_msg(11, 22, 0, body)
    flags, decoded = decode_op_msg(raw)
    assert flags == 0 and dict(decoded) == body
    msg_len, req_id, resp_to, opcode = header_of(raw)
    assert (msg_len, req_id, resp_to, opcode) == (len(raw), 11, 22, OP_MSG)
    assert encode_op_msg(11, 22, 0, decoded) == raw


def test_a_rewritten_message_never_carries_the_checksum_of_what_it_was():
    # A stale CRC32C over a body we just changed is worse than none, and
    # the trailer is optional in the protocol.
    raw = encode_op_msg(1, 0, FLAG_CHECKSUM, {"ping": 1})
    flags, body = decode_op_msg(raw)
    assert not flags & FLAG_CHECKSUM
    assert dict(body) == {"ping": 1}

    sections = encode_sections(1, 0, FLAG_CHECKSUM, {"delete": "notes"},
                               "deletes", [{"q": {}, "limit": 1}])
    assert not struct.unpack("<I", sections[16:20])[0] & FLAG_CHECKSUM


def test_a_body_that_arrived_with_a_checksum_trailer_is_still_read():
    inner = bson.encode({"ping": 1})
    payload = (struct.pack("<I", FLAG_CHECKSUM) + b"\x00" + inner
               + struct.pack("<I", zlib.crc32(inner)))
    raw = struct.pack("<iiiI", 16 + len(payload), 1, 0, OP_MSG) + payload
    flags, body = decode_op_msg(raw)
    # The trailer is not mistaken for part of the document.
    assert flags & FLAG_CHECKSUM and dict(body) == {"ping": 1}


def test_the_lazy_codec_reads_the_same_fields_without_materialising_them():
    # Why the proxy costs microseconds: a vector never becomes a list of
    # Python floats unless a rule actually reads it.
    doc = {"cursor": {"ns": "db.notes"}, "embedding": [0.1] * 1024}
    raw = encode_op_msg(1, 0, 0, doc)
    _, lazy = decode_op_msg(raw, LAZY)
    assert lazy["cursor"]["ns"] == "db.notes"
    assert bytes(lazy.raw) == bson.encode(doc)
    # And the two decoders must not disagree about a verdict's input.
    _, eager = decode_op_msg(raw)
    assert eager["cursor"]["ns"] == lazy["cursor"]["ns"]


def test_anything_that_is_not_a_kind_zero_body_is_left_alone():
    # Forwarded untouched rather than half-parsed: a reply carrying a
    # cursor batch is always kind 0, so this costs nothing real.
    with_sequence = encode_sections(1, 0, 0, {"delete": "notes"},
                                    "deletes", [{"q": {}, "limit": 1}])
    assert decode_op_msg(with_sequence) is None
    assert decode_op_msg(b"\x00" * 18) is None
    junk = struct.pack("<iiiI", 24, 1, 0, OP_MSG) + struct.pack("<I", 0) + b"\x00garb"
    assert decode_op_msg(junk) is None


# ---- the kind-1 sequence every hand-rolled parser gets wrong -----------

def test_a_writes_documents_travel_beside_the_body_and_come_back():
    body = {"delete": "notes", "$db": "app"}
    docs = [{"q": {"_id": 1}, "limit": 1}, {"q": {"_id": 2}, "limit": 0}]
    raw = encode_sections(5, 0, 0, body, "deletes", docs)
    flags, got_body, ident, got_docs = decode_sections(raw)
    assert flags == 0 and got_body == body
    assert ident == "deletes" and got_docs == docs
    assert encode_sections(5, 0, 0, got_body, ident, got_docs) == raw


def test_a_body_with_no_sequence_decodes_with_an_empty_one():
    raw = encode_op_msg(1, 0, 0, {"find": "notes"})
    flags, body, ident, docs = decode_sections(raw)
    assert body == {"find": "notes"} and ident is None and docs == []


def test_rewriting_a_delete_into_an_update_keeps_the_sequence_intact():
    # The boundary's on_delete="revoke" is exactly this rewrite, so losing
    # a document out of the sequence would silently drop a revocation.
    raw = encode_sections(9, 0, 0, {"delete": "notes", "$db": "app"},
                          "deletes", [{"q": {"_id": i}, "limit": 1}
                                      for i in range(3)])
    _, body, ident, docs = decode_sections(raw)
    rewritten = encode_sections(
        9, 0, 0, {"update": body["delete"], "$db": body["$db"]}, "updates",
        [{"q": d["q"], "u": {"$set": {"forgotten": {}}}} for d in docs])
    _, new_body, new_ident, new_docs = decode_sections(rewritten)
    assert new_body["update"] == "notes" and new_ident == "updates"
    assert [d["q"] for d in new_docs] == [d["q"] for d in docs]


def test_a_section_kind_this_codec_does_not_know_is_not_guessed_at():
    payload = struct.pack("<I", 0) + b"\x09" + struct.pack("<i", 5)
    raw = struct.pack("<iiiI", 16 + len(payload), 1, 0, OP_MSG) + payload
    assert decode_sections(raw) is None
    assert decode_sections(b"\x00" * 18) is None


# ---- compression: a boundary that cannot read the traffic enforces nothing

def test_a_message_that_arrives_compressed_anyway_is_inflated_not_forwarded():
    # Compression is negotiated away at the handshake. A proxy that
    # forwarded what it could not read would be a boundary that says
    # nothing because it saw nothing.
    inner = encode_op_msg(4, 0, 0, {"find": "notes"})
    body = inner[16:]
    squashed = zlib.compress(body)
    payload = struct.pack("<iiB", OP_MSG, len(body), 2) + squashed
    raw = struct.pack("<iiiI", 16 + len(payload), 4, 0, OP_COMPRESSED) + payload

    restored = uncompress_message(raw)
    assert restored == inner
    assert header_of(restored)[3] == OP_MSG
    assert dict(decode_op_msg(restored)[1]) == {"find": "notes"}


def test_an_uncompressed_noop_compressor_is_passed_through():
    inner = encode_op_msg(4, 0, 0, {"ping": 1})
    body = inner[16:]
    payload = struct.pack("<iiB", OP_MSG, len(body), 0) + body
    raw = struct.pack("<iiiI", 16 + len(payload), 4, 0, OP_COMPRESSED) + payload
    assert uncompress_message(raw) == inner


def test_a_compressor_this_process_cannot_read_says_so_rather_than_guessing():
    payload = struct.pack("<iiB", OP_MSG, 4, 99) + b"junk"
    raw = struct.pack("<iiiI", 16 + len(payload), 1, 0, OP_COMPRESSED) + payload
    assert uncompress_message(raw) is None
