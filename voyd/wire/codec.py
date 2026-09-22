"""The wire, as bytes. No policy lives here.

MongoDB speaks a length-prefixed binary protocol over one socket: a 16-byte
header, then a body whose shape depends on an opcode. This module is the
whole of reading and writing that, and it is separate from the enforcement
decisions on purpose -- "can this boundary be bypassed?" should be
answerable by reading the file that decides, not by reading a framing bug
first.

Three jobs:

**Frame.** Read exactly one message off a stream, refusing a length that
would be a memory blowup or a desynchronisation.

**Uncompress.** A client that negotiated compression sends bodies this
process cannot read, and a boundary that cannot read the traffic cannot
enforce anything. Compression is negotiated away at the handshake, but a
message that arrives compressed anyway is inflated rather than forwarded
blind.

**Encode and decode `OP_MSG`.** Including the kind-1 document sequence that
carries a write's documents outside the body, which is the part every
hand-rolled parser gets wrong -- and the *lazy* codec, which is what keeps
an unguarded reply cheap: it is decoded into raw BSON views, so a reply
this boundary only inspects and forwards never materialises its documents
at all.

Be precise about what that does and does not buy, because the tempting
version of this sentence is false. `RawBSONDocument` inflates the **whole
document** on the first field read -- measured: touching `tenant_id`
turns a 1024-float `embedding` in the same document into a Python list.
So the saving is per *document nobody judges*, not per field nobody
reads: a `find` on a collection no policy declared costs four reads of
the reply envelope and never touches a document, while a guarded batch
pays full decode for every document in it. Laziness here is a filter on
which documents become real, not on which fields do.

The framing -- header layout, `OP_MSG` sections, `OP_COMPRESSED` -- is
lifted from `tools/wire_proxy.py` in the author's `mdb-embedded`
repository, MIT to MIT. That file logs traffic; this one hands it to
something that rewrites it.
"""

from __future__ import annotations

import asyncio
import socket
import struct
from typing import Mapping

try:
    import bson
    from bson.codec_options import CodecOptions
    from bson.raw_bson import RawBSONDocument
except ImportError:  # pragma: no cover - the one dependency, and it is pymongo's
    import sys
    sys.exit("pip install pymongo   (for the bson library)")

OP_MSG = 2013
OP_COMPRESSED = 2012

# OP_MSG flagBits. Bit 0 says a CRC32C trailer follows the sections; we clear
# it when we rewrite a message rather than recomputing a checksum over a body
# we just changed. The checksum is optional in the protocol and drivers accept
# its absence -- and a *stale* checksum would be worse than none.
FLAG_CHECKSUM = 1 << 0

# MongoDB's own ceiling (`maxMessageSizeBytes`). A length field arrives from
# the wire and this process allocates on it, so it is attacker-controlled
# input in the most literal sense: without a cap, one malformed header asking
# for two gigabytes is a memory blowup, and a *negative* one silently skips
# the read loop and desynchronises the stream into garbage that looks like
# the database going away.
MAX_MESSAGE = 48_000_000
HEADER = 16


class Hangup(ConnectionError):
    """The peer stopped sending, cleanly, on a message boundary.

    Distinguished from every other disconnect because a client that half
    closes is *not* abandoning the replies it already asked for -- it is
    saying "no more requests". Treating the two the same costs the caller
    its last answer on every `shutdown(SHUT_WR)`.
    """


class ProtocolError(Exception):
    """The framing is wrong. Close the connection rather than guess.

    A proxy that tries to resynchronise a broken stream is a proxy that will
    eventually forward half of one message and the tail of another, which is
    a far worse failure than hanging up.
    """


def frame(hdr: bytes) -> tuple[int, int, int, int]:
    """The header, validated. One rule, and both readers below obey it.

    This is deliberately separate from the reading: the cap is the security
    property and the socket is an implementation detail, so a sync reader
    and an async one must not each carry their own copy of the bound. They
    would drift, and the one that drifted would be the one nobody tested.
    """
    msg_len, req_id, resp_to, opcode = struct.unpack("<iiiI", hdr)
    if not HEADER <= msg_len <= MAX_MESSAGE:
        raise ProtocolError(
            f"message length {msg_len} outside [{HEADER}, {MAX_MESSAGE}]")
    return msg_len, req_id, resp_to, opcode


def read_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("disconnected")
        buf += chunk
    return bytes(buf)


def read_message(sock: socket.socket) -> tuple[bytes, int, int, int, int]:
    """Blocking read of one message. Kept for tests and for anything that
    wants the codec without an event loop; the proxy itself uses the async
    reader below."""
    hdr = read_exact(sock, HEADER)
    msg_len, req_id, resp_to, opcode = frame(hdr)
    return hdr + read_exact(sock, msg_len - HEADER), msg_len, req_id, resp_to, opcode


async def read_message_async(
        reader: asyncio.StreamReader) -> tuple[bytes, int, int, int, int]:
    """The same message, the same cap, without holding a thread.

    `IncompleteReadError` is how a StreamReader spells the disconnect that
    `read_exact` spells as an empty `recv`, and both mean the same thing:
    the peer went away mid-message. It is translated here rather than at the
    call site so `pump` has one disconnect to catch, not two.
    """
    try:
        hdr = await reader.readexactly(HEADER)
    except asyncio.IncompleteReadError as exc:
        # Nothing at all where a header should start is the peer saying it
        # is finished, on a boundary. Bytes and then nothing is a truncated
        # message, which is a broken stream and not the same event.
        if not exc.partial:
            raise Hangup("peer stopped sending") from exc
        raise ConnectionError("disconnected mid-header") from exc
    msg_len, req_id, resp_to, opcode = frame(hdr)
    try:
        body = await reader.readexactly(msg_len - HEADER)
    except asyncio.IncompleteReadError as exc:
        raise ConnectionError("disconnected mid-message") from exc
    return hdr + body, msg_len, req_id, resp_to, opcode


def _decompress(compressor_id: int, data: bytes) -> bytes | None:
    if compressor_id == 0:
        return data
    if compressor_id == 2:
        import zlib
        return zlib.decompress(data)
    if compressor_id == 1:
        try:
            import snappy
            return snappy.uncompress(data)
        except Exception:
            return None
    if compressor_id == 3:
        try:
            import zstandard
            return zstandard.ZstdDecompressor().decompress(data)
        except Exception:
            return None
    return None


def uncompress_message(raw: bytes) -> bytes | None:
    """An OP_COMPRESSED message, re-expressed as the message it wraps.

    We strip compression from the handshake so this should not arrive, but a
    proxy that silently forwarded something it could not read would be exactly
    the failure this project is about: a boundary that says nothing because it
    saw nothing.
    """
    _, req_id, resp_to, _ = struct.unpack("<iiiI", raw[:16])
    original_op, _size, comp_id = struct.unpack("<iiB", raw[16:25])
    body = _decompress(comp_id, raw[25:])
    if body is None:
        return None
    return struct.pack("<iiiI", 16 + len(body), req_id, resp_to,
                       original_op) + body


def decode_sections(raw: bytes) -> tuple[int, dict, str | None, list] | None:
    """Flags, the body document, and the document sequence beside it.

    Write commands put their payload in a **kind-1 section**: the body says
    ``{"delete": "notes", ...}`` and a separate section identified as
    ``deletes`` carries ``[{"q": ..., "limit": 1}]``. Reads do not, which is
    why the read path above only ever needed kind 0 -- and why rewriting a
    write needs this.
    """
    payload = raw[16:]
    if len(payload) < 5:
        return None
    flags = struct.unpack("<I", payload[:4])[0]
    end = len(payload) - (4 if flags & FLAG_CHECKSUM else 0)
    i, body, ident, docs = 4, None, None, []
    try:
        while i < end:
            kind = payload[i]
            i += 1
            size = struct.unpack("<i", payload[i:i + 4])[0]
            if kind == 0:
                body = bson.decode(payload[i:i + size])
                i += size
            elif kind == 1:
                seg = payload[i + 4:i + size]
                nul = seg.index(b"\x00")
                ident = seg[:nul].decode()
                rest, j = seg[nul + 1:], 0
                while j < len(rest):
                    n = struct.unpack("<i", rest[j:j + 4])[0]
                    docs.append(bson.decode(rest[j:j + n]))
                    j += n
                i += size
            else:
                return None
    except Exception:
        return None
    return (flags, body, ident, docs) if body is not None else None


def encode_sections(req_id: int, resp_to: int, flags: int, body: dict,
                    ident: str | None = None,
                    docs: list | None = None) -> bytes:
    payload = struct.pack("<I", flags & ~FLAG_CHECKSUM)
    payload += b"\x00" + bson.encode(body)
    if ident is not None:
        blob = ident.encode() + b"\x00" + b"".join(bson.encode(d) for d in (docs or []))
        payload += b"\x01" + struct.pack("<i", 4 + len(blob)) + blob
    return struct.pack("<iiiI", 16 + len(payload), req_id, resp_to,
                       OP_MSG) + payload


# Decode a body without building Python objects for the fields nobody reads.
# `RawBSONDocument` keeps the original bytes and walks them on `[]`/`.get()`,
# which is the difference between reading `cursor.ns` and materialising a
# thousand floats per document to reach it. Immutable by design, which suits
# this file: nothing on the read path may edit a document in place anyway.
# `tz_aware` is left at its default, which is *off*, because that is what the
# eager `bson.decode` above this used and a verdict must not depend on which
# decoder read the document. Naive means UTC here anyway: `voyd.engine.time.
# aware` coerces on the way into a rule, "because that is what BSON stored".
# Turning it on would be more correct in the abstract and a silent change of
# behaviour in practice, which is the trade this file always refuses.
LAZY = CodecOptions(document_class=RawBSONDocument, tz_aware=False)


def decode_op_msg(raw: bytes, opts: CodecOptions | None = None
                  ) -> tuple[int, Mapping] | None:
    """The flags and the body document of a kind-0 OP_MSG.

    Returns ``None`` for anything else -- a document sequence (kind 1), a
    body we cannot parse. Those are forwarded untouched, which is safe here
    because a *reply* carrying a cursor batch is always a kind-0 body.

    ``opts=LAZY`` returns a ``RawBSONDocument`` instead of a ``dict``: the
    same fields, read on demand. Use it where the body is *inspected* and
    usually forwarded; use the default where it is taken apart and rebuilt.
    """
    payload = raw[16:]
    if len(payload) < 5:
        return None
    flags = struct.unpack("<I", payload[:4])[0]
    if payload[4] != 0:
        return None
    end = len(payload) - (4 if flags & FLAG_CHECKSUM else 0)
    try:
        return flags, bson.decode(payload[5:end], opts)
    except Exception:
        return None


def encode_op_msg(req_id: int, resp_to: int, flags: int,
                  doc: Mapping) -> bytes:
    """Re-frame a body document as an OP_MSG, checksum bit cleared."""
    body = bson.encode(doc)
    payload = struct.pack("<I", flags & ~FLAG_CHECKSUM) + b"\x00" + body
    return struct.pack("<iiiI", 16 + len(payload), req_id, resp_to,
                       OP_MSG) + payload
