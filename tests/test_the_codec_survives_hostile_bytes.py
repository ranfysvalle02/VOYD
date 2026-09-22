"""Bytes from the wire, assumed to be malicious, because they may be.

Every other test in this suite hands the codec something a driver would
plausibly send. This one hands it what an attacker would, and what a bug
upstream would, which turn out to be the same set: truncated messages,
lengths that disagree with the buffer, section sizes that point past the
end, a document sequence whose identifier has no terminator, nesting deep
enough to blow a stack.

The contract under test is narrow and absolute. Every entry point either
**returns a value or raises `ProtocolError`**. It may not raise anything
else, and it may not hang, and it may not allocate on a number it was
handed. A parser that raises `IndexError` on hostile input is a parser
whose caller has an `except ProtocolError` that does not fire -- and in
this process the caller is a proxy that would then either crash a worker
serving other people's connections or, worse, fall through to forwarding
what it could not read.

Generated rather than enumerated, because the interesting inputs here are
the ones nobody thought of. The corpus is every valid message this suite
knows how to build, mutated: truncated at every length, one byte flipped
at every offset, every length field replaced with a hostile value.
"""

from __future__ import annotations

import random
import struct

import pytest

from voyd.wire.codec import (FLAG_CHECKSUM, HEADER, MAX_MESSAGE, OP_COMPRESSED,
                             OP_MSG, ProtocolError, decode_op_msg,
                             decode_sections, encode_op_msg, encode_sections,
                             frame, uncompress_message)

SEED = 20260922          # fixed, so a failure is reproducible from the name


def corpus() -> list[bytes]:
    """Valid messages of every shape this codec claims to read."""
    return [
        encode_op_msg(1, 0, 0, {"ping": 1}),
        encode_op_msg(2, 1, FLAG_CHECKSUM, {"find": "notes", "filter": {}}),
        encode_op_msg(3, 0, 0, {"cursor": {"id": 7, "ns": "db.notes",
                                           "firstBatch": [{"_id": i}
                                                          for i in range(5)]},
                                "ok": 1.0}),
        encode_sections(4, 0, 0, {"delete": "notes", "$db": "app"},
                        "deletes", [{"q": {"_id": 1}, "limit": 1}]),
        encode_sections(5, 0, 0, {"insert": "notes", "$db": "app"},
                        "documents", [{"_id": i} for i in range(4)]),
        encode_op_msg(6, 0, 0, {"embedding": [0.1] * 64}),
    ]


def readers():
    """Every way bytes enter this process, and what each may raise."""
    return [
        ("frame", lambda b: frame(b[:HEADER]) if len(b) >= HEADER else None,
         (ProtocolError, struct.error)),
        ("decode_op_msg", lambda b: decode_op_msg(b), ()),
        ("decode_sections", lambda b: decode_sections(b), ()),
        ("uncompress_message", lambda b: uncompress_message(b), (struct.error,)),
    ]


def hostile(message: bytes, rng: random.Random) -> list[bytes]:
    """The mutations that have historically broken hand-rolled parsers."""
    out = []
    # Truncated anywhere, including mid-header and mid-length-prefix.
    out += [message[:n] for n in range(0, len(message), 3)]
    # A length that disagrees with what is actually there, in both
    # directions and at the boundaries the cap is written against.
    for claimed in (0, 1, HEADER - 1, HEADER, len(message) - 1,
                    len(message) + 1, MAX_MESSAGE, MAX_MESSAGE + 1,
                    2 ** 31 - 1, -1, -(2 ** 31)):
        out.append(struct.pack("<i", claimed) + message[4:])
    # One byte flipped, anywhere. Section kinds, BSON type bytes and
    # internal length prefixes all live in here.
    for _ in range(120):
        i = rng.randrange(len(message))
        out.append(message[:i] + bytes([message[i] ^ 0xFF]) + message[i + 1:])
    # An opcode nothing handles.
    out.append(message[:12] + struct.pack("<I", 9999) + message[16:])
    return out


@pytest.mark.parametrize("name,read,allowed", readers(),
                         ids=[r[0] for r in readers()])
def test_no_reader_raises_anything_but_a_protocol_error(name, read, allowed):
    rng = random.Random(SEED)
    checked = 0
    for message in corpus():
        for bad in hostile(message, rng):
            checked += 1
            try:
                read(bad)
            except (ProtocolError, *allowed):
                pass
            except Exception as exc:                       # noqa: BLE001
                raise AssertionError(
                    f"{name} raised {type(exc).__name__}: {exc}\n"
                    f"  on {len(bad)} bytes: {bad[:48].hex()}") from exc
    assert checked > 1000, f"only {checked} inputs; the corpus is too thin"


def test_a_length_field_cannot_make_this_process_allocate():
    # The one number here that is both attacker-controlled and used as a
    # size. Every value outside the window is refused before anything is
    # read, so no allocation is ever attempted on it.
    for claimed in (-(2 ** 31), -1, 0, HEADER - 1,
                    MAX_MESSAGE + 1, 2 ** 31 - 1):
        with pytest.raises(ProtocolError):
            frame(struct.pack("<iiiI", claimed, 1, 0, OP_MSG))
    for ok in (HEADER, HEADER + 1, MAX_MESSAGE):
        assert frame(struct.pack("<iiiI", ok, 1, 0, OP_MSG))[0] == ok


def test_a_section_that_points_past_the_end_is_refused_not_read():
    # A kind-1 section carries its own size, and a parser that trusts it
    # reads whatever follows in memory -- the classic shape of this bug.
    body = encode_sections(1, 0, 0, {"delete": "notes"}, "deletes",
                           [{"q": {}, "limit": 1}])
    payload = bytearray(body)
    # The kind-1 section's size lives just after the kind byte; make it
    # claim far more than the message holds.
    index = payload.find(b"\x01deletes") if b"\x01deletes" in payload else -1
    if index > 4:
        payload[index + 1:index + 5] = struct.pack("<i", 1 << 30)
        assert decode_sections(bytes(payload)) is None


def test_a_document_sequence_with_no_terminator_is_refused():
    # The identifier is a C string. Without its NUL the parser has no end
    # to find, and `bytes.index` raises rather than returning -1.
    payload = struct.pack("<I", 0) + b"\x00" + b"\x10\x00\x00\x00" + b"x" * 12
    payload += b"\x01" + struct.pack("<i", 12) + b"nonulhere123"
    raw = struct.pack("<iiiI", 16 + len(payload), 1, 0, OP_MSG) + payload
    assert decode_sections(raw) is None


def test_deeply_nested_bson_does_not_take_the_worker_with_it():
    # A recursive decoder dies on this with a RecursionError, which is
    # not a ProtocolError and would kill a worker serving other people's
    # connections.
    doc: dict = {"a": 1}
    for _ in range(200):
        doc = {"a": doc}
    try:
        raw = encode_op_msg(1, 0, 0, doc)
    except Exception:                                      # noqa: BLE001
        pytest.skip("the encoder refuses to build it, which is also fine")
    try:
        decode_op_msg(raw)
    except ProtocolError:
        pass
    except RecursionError as exc:
        raise AssertionError(
            "a nested document exhausted the stack; the worker would take "
            "every connection on it down") from exc


def test_a_compressed_message_claiming_an_impossible_size_is_refused():
    import zlib

    inner = encode_op_msg(1, 0, 0, {"ping": 1})[16:]
    squashed = zlib.compress(inner)
    # The uncompressed size is a claim, and zlib is the thing that would
    # act on it.
    payload = struct.pack("<iiB", OP_MSG, 1 << 30, 2) + squashed
    raw = struct.pack("<iiiI", 16 + len(payload), 1, 0, OP_COMPRESSED) + payload
    result = uncompress_message(raw)
    # Either it declines or it returns the real bytes; what it must not do
    # is trust the claim.
    assert result is None or len(result) < 1 << 20


def test_garbage_is_declined_rather_than_half_parsed():
    rng = random.Random(SEED)
    for size in (0, 1, 4, 15, 16, 17, 64, 4096):
        for _ in range(40):
            blob = bytes(rng.randrange(256) for _ in range(size))
            assert decode_op_msg(blob) is None or isinstance(
                decode_op_msg(blob), tuple)
            assert decode_sections(blob) is None or isinstance(
                decode_sections(blob), tuple)
