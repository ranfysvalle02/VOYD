#!/usr/bin/env python3
"""A MongoDB connection that cannot serve a fact you have forgotten.

    # terminal 1 -- rules in a file that is not your application
    python tools/voyd_wire.py --config voydfile.py --target localhost:27018

    # terminal 2 -- any driver, any language
    mongosh mongodb://localhost:27099/demo

Everything else in this repository binds a *handle*: `docs.find(...)` refuses
and `db.notes.find(...)` does not, which is why there is a raw-read guard, a
scanner, and a CI gate asserting no module reaches past the handle. All of
that is machinery for stopping your own team from doing the easy thing.

This moves the boundary to the wire. It speaks the MongoDB protocol, sits
between any client and any `mongod`, and applies the same per-document check
to every document on the way back. The guarantee then binds the *connection*,
so there is no raw read to guard -- not from Node, not from Compass, not from
a data scientist's notebook, not from a shell that has never heard of VOYD.

**It holds no database connection of its own.** `reachable()` is pure: it is
handed documents and returns the ones a prompt may see. So this process needs
no credentials beyond forwarding yours, and adds no round trip. That is the
same property that makes shadow mode three lines.

**What this is and is not.** It is a demonstration that the boundary is
portable, and it is deliberately outside `voyd/` -- nothing here is importable
package surface. It terminates TLS, follows a failover, drains on `SIGTERM`,
and runs one coroutine pair per connection across `--workers` processes. What
it still is not: a driver. It does not pool upstream connections -- that one
deliberately, because
a MongoDB connection carries authentication, sessions, cursors and
transactions, and sharing one would hand a cursor to whoever asked second.

What does survive the crossing, measured rather than assumed: read preference
is honoured against a topology of one (the `*Preferred` modes served by the
primary, strict `secondary` a client-side error rather than a quiet primary
read), retryable writes stay armed because `rewrite_topology` keeps
`setName`, and sessions and transactions are forwarded intact. `--fan-out`
ranks reads on secondaries and re-reads their marks from the primary before
releasing them -- see `voyd_fanout.py` for why the obvious version of that
is unsafe.

**Concurrency is the transport's problem, not the boundary's.** Every
function that rewrites bytes here -- `enforce`, `refuse_unrewritable`,
`revoke_instead_of_delete`, `rewrite_topology`, `delete_reply` -- is
`bytes -> bytes` and touches no socket, because `reachable()` is pure. That
is what made moving this from two OS threads per connection to one coroutine
pair a change to the shell and nothing else, and it is why the ceiling is now
upstream sockets rather than thread stacks.

The wire framing -- header layout, OP_MSG sections, OP_COMPRESSED -- is lifted
from `tools/wire_proxy.py` in the author's `mdb-embedded` repository, MIT to
MIT. That file logs traffic; this one rewrites it.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import socket
import ssl
import struct
import sys
import threading
import time
import traceback
from typing import Mapping

try:
    import bson
    from bson.codec_options import CodecOptions
    from bson.raw_bson import RawBSONDocument
except ImportError:  # pragma: no cover - the one dependency, and it is pymongo's
    sys.exit("pip install pymongo   (for the bson library)")

import voyd_fanout
import voyd_metrics
from voyd.declare import OPTIONS, load
from voyd.engine import Deadline, revoked
from voyd.engine.time import now
from voyd.engine.admission import Admission, AdmissionSpec

OP_MSG = 2013
OP_COMPRESSED = 2012

# OP_MSG flagBits. Bit 0 says a CRC32C trailer follows the sections; we clear
# it when we rewrite a message rather than recomputing a checksum over a body
# we just changed. The checksum is optional in the protocol and drivers accept
# its absence -- and a *stale* checksum would be worse than none.
FLAG_CHECKSUM = 1 << 0


class Guard:
    """One collection's admission handle, and the tally it has refused.

    Built with ``db=None`` on purpose: this object never queries anything. It
    is the same construction the unit tests use, which is the evidence that
    the per-document check does not depend on a database at all -- the thing
    that makes it movable to a wire in the first place.
    """

    def __init__(self, spec: AdmissionSpec, *, on_delete: str = "forward"):
        self.collection = spec.collection
        self.spec = spec
        self.on_delete = on_delete
        self.handle = Admission(None, spec)
        self.refused = 0
        self.admitted = 0
        self.revoked = 0

    @classmethod
    def defaults(cls, collection: str, *, at_field: str, mark_field: str):
        """A guard for a collection nobody wrote a policy for.

        The two rules every collection with a deadline wants, so
        ``--guard notes`` is still a complete thing to type. A policy file
        says more; this says the obvious part.
        """
        return cls(AdmissionSpec(collection,
                                 rules=(Deadline(at_field=at_field),
                                        revoked(mark_field))))

    def filter(self, docs: list[dict]) -> list[dict]:
        handle = self.handle
        if self.spec.tenant:
            # A declared tenant is enforced per document, and the proxy has
            # no filters to read it from -- so it takes the scope from the
            # batch itself. Every document in a cursor batch came from one
            # query, so they share a tenant; a batch that does not is already
            # the leak, and `off_scope` is what names it.
            scopes = {d.get(self.spec.tenant) for d in docs}
            handle = handle.for_tenant(scopes.pop() if len(scopes) == 1
                                       else object())
        kept = handle.reachable(docs)
        self.refused += len(docs) - len(kept)
        self.admitted += len(kept)
        return kept

    def reasons(self) -> dict:
        return self.handle.receipts().get("refused_by_reason", {})


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
    saying "no more requests". Treating the two the same is why a
    `shutdown(SHUT_WR)` used to cost the caller its last answer.
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


# --------------------------------------------------------------------------
# The two legs. Only one of them rewrites anything.
# --------------------------------------------------------------------------

def _collection_of(reply: Mapping) -> str | None:
    """Which collection this cursor batch came from.

    ``cursor.ns`` is ``"db.collection"``, and it is the only place a reply
    names what it is. A reply without one is not a cursor batch.
    """
    ns = (reply.get("cursor") or {}).get("ns")
    if not isinstance(ns, str) or "." not in ns:
        return None
    return ns.split(".", 1)[1]


def revoke_instead_of_delete(raw: bytes, req_id: int, resp_to: int,
                             guard: Guard, verbose: bool) -> bytes | None:
    """Turn a client's ``delete`` into the revocation it should have been.

    This is the half of the story the read path could not tell. A boundary
    that refuses forgotten facts is worth little if the only way to forget
    one is to import a library -- so the verb a caller already has is given
    the better meaning:

        db.notes.deleteOne({"_id": x})   # what they wrote
        -> the row is marked, unreachable on the next read, still on disk,
           and its deadline is pulled in so the reaper collects it

    Which is the whole thesis applied to somebody else's code without
    editing it. Delete is a wish -- eventually, best effort, unprovable.
    Refuse is a contract. They asked for the wish and got the contract, and
    the bytes still go, on the deadline they already had.

    **Only when the policy file says so.** `@guard(..., on_delete="revoke")`
    is opt-in because silently redefining `delete` for an operator who did
    not ask is precisely the kind of surprise this project exists to remove.
    Left alone, a delete is forwarded and really deletes.

    The update emitted here is the same pipeline ``Admission.revoke()``
    writes -- the literal mark, the deadline moved *earlier only*, and the
    derived encodings nulled -- so a fact forgotten through the wire and one
    forgotten through the library are the same document afterwards. Two
    spellings that produced different rows would be the drift this whole
    package is about.
    """
    decoded = decode_sections(raw)
    if decoded is None:
        return None
    flags, body, ident, docs = decoded
    if body.get("delete") != guard.collection or ident != "deletes":
        return None

    pipeline = _forget_pipeline(guard.spec, "deleted via voyd-wire")
    if not pipeline:
        return None          # nothing to mark with; forward the real delete

    updates = [{
        "q": d.get("q", {}),
        # `limit: 1` means deleteOne; anything else is deleteMany.
        "multi": d.get("limit", 0) == 0,
        "u": pipeline,
    } for d in docs]

    new_body = {("update" if k == "delete" else k): v for k, v in body.items()}
    if verbose:
        print(f"  voyd: {guard.collection}: delete -> revoke "
              f"({len(updates)} clause(s)); the rows stay on disk",
              flush=True)
    guard.revoked += len(updates)
    return encode_sections(req_id, resp_to, flags, new_body, "updates", updates)


def _forget_pipeline(spec, reason: str) -> list:
    """The update `Admission.revoke()` writes, as a pipeline.

    One definition, used by every verb this boundary rewrites, because two
    spellings that produced different rows would be the drift this package
    is about arriving through its own front door.
    """
    mark_field = next((r.field for r in spec.rules
                       if getattr(r, "reversible", None) is False), None)
    if mark_field is None:
        return []
    stamp = now()
    at = spec.at_field
    return [{"$set": {
        mark_field: {"$literal": {"at": stamp, "reason": reason}},
        # A missing deadline is a *pinned* row, not an early one, so the two
        # cases are separated -- `$min` against null would pin an erased
        # fact forever.
        at: {"$cond": [{"$eq": [{"$type": f"${at}"}, "date"]},
                       {"$min": [f"${at}", stamp]}, stamp]},
        **{name: None for name in spec.derived_fields},
    }}]


def revoke_instead_of_find_and_delete(raw: bytes, req_id: int, resp_to: int,
                                      guard: Guard, verbose: bool) -> bytes | None:
    """`findOneAndDelete`, which is a different command and was a real hole.

    `delete` and `findAndModify` are separate wire commands, so intercepting
    the first and not the second gave a team the guarantee for one delete
    verb and silently not for the other -- measured: `deleteOne` left the row
    on disk and `findOneAndDelete` destroyed it, under the same policy, in
    the same process. Partial enforcement that looks complete is the exact
    failure this project exists to forbid, so it was worth more than a
    footnote.

    `remove: true` becomes `update: <the forget pipeline>`, which keeps the
    verb's whole point -- the caller still gets the document back.
    """
    decoded = decode_op_msg(raw)
    if decoded is None:
        return None
    flags, body = decoded
    if body.get("findAndModify") != guard.collection or not body.get("remove"):
        return None

    pipeline = _forget_pipeline(guard.spec, "findOneAndDelete via voyd-wire")
    if not pipeline:
        return None

    body = {k: v for k, v in body.items() if k != "remove"}
    body["update"] = pipeline
    # `new: false` is what a delete means here: the caller asked for the
    # document as it was, which is also the only version that still reads.
    body.setdefault("new", False)
    if verbose:
        print(f"  voyd: {guard.collection}: findOneAndDelete -> revoke; "
              f"the row stays on disk", flush=True)
    guard.revoked += 1
    return encode_op_msg(req_id, resp_to, flags, body)


# Commands that can make a guarded fact unreachable and that this boundary
# cannot turn into a revocation. Refusing them is the whole point: a
# guarantee that covers three verbs out of four is the silent hole this
# package is named after, and the operator asked for `on_delete="revoke"`.
UNREWRITABLE = {
    "drop": "drops the whole collection, marks and all",
    "dropDatabase": "drops the database",
    "renameCollection": "moves the collection out from under the policy",
}

# Aggregation stages that write somewhere else. These are the sharpest hole
# this boundary can have, because they do not *look* destructive: the
# documents never come back to the client, so nothing on the read path ever
# sees them. Measured before it was closed --
#
#     through the boundary:  ['live']
#     after $out to another collection:  ['SECRET', 'live']
#
# -- a refused document copied itself out of the policy's reach, server-
# side, through a connection that had just declined to show it. That is
# exactly the silence this package is named after, arriving through its own
# front door.
#
# A proxy cannot make these safe. The copy happens inside the server and
# the boundary is never handed a document to refuse, so the only honest
# answer is the same one `drop` gets: say no, out loud, with a reason.
EXFILTRATING_STAGES = ("$out", "$merge")


def writes_elsewhere(body: dict) -> str | None:
    """Does this aggregation end by writing somewhere the policy is not?"""
    pipeline = body.get("pipeline")
    if not isinstance(pipeline, list):
        return None
    for stage in pipeline:
        if not isinstance(stage, dict):
            continue
        for name in EXFILTRATING_STAGES:
            if name in stage:
                return name
    return None


def refuse_unrewritable(raw: bytes, req_id: int, resp_to: int,
                        guards: dict[str, Guard]) -> bytes | None:
    """Answer the client with an error rather than let the fact be destroyed.

    Only on a collection somebody declared `on_delete="revoke"` for. That
    declaration is a statement that deletes here are supposed to become
    revocations, and honouring it for `deleteOne` while passing `drop`
    through would be the boundary lying by omission.
    """
    decoded = decode_op_msg(raw)
    if decoded is None:
        return None
    _flags, body = decoded

    guard = guards.get(body.get("aggregate"))
    stage = writes_elsewhere(body) if guard is not None else None
    if stage is not None:
        print(f"  voyd: REFUSED {stage} on {guard.collection}: it copies "
              f"documents server-side, past the boundary", flush=True)
        return encode_op_msg(req_id, resp_to, 0, {
            "ok": 0.0, "code": 8000, "codeName": "AtlasError",
            "errmsg": (f"voyd-wire refuses {stage} on {guard.collection!r}: "
                       f"it writes documents to another collection inside "
                       f"the server, where this boundary never sees them and "
                       f"the policy does not follow. Read through the "
                       f"boundary and write the results back instead."),
        })

    for command, why in UNREWRITABLE.items():
        target = body.get(command)
        named = (target if isinstance(target, str)
                 else next(iter(guards), None) if command == "dropDatabase"
                 else None)
        guard = guards.get(named) if named else None
        if command not in body or guard is None or guard.on_delete != "revoke":
            continue
        print(f"  voyd: REFUSED {command} on {guard.collection}: {why}, and "
              f"this collection declared on_delete='revoke'", flush=True)
        return encode_op_msg(req_id, resp_to, 0, {
            "ok": 0.0, "code": 8000, "codeName": "AtlasError",
            "errmsg": (f"voyd-wire refuses {command} on "
                       f"{guard.collection!r}: it {why}, which cannot be "
                       f"expressed as a revocation. This collection declared "
                       f"on_delete='revoke'; drop it through a direct "
                       f"connection if you mean it."),
        })
    return None


# Fields in a `hello` reply that name *other machines*. A driver reads these
# and connects to them directly, which is the whole of how a replica set
# works and the whole of how a boundary gets walked past.
TOPOLOGY_FIELDS = ("hosts", "passives", "arbiters")


def rewrite_topology(raw: bytes, req_id: int, resp_to: int,
                     advertise: str) -> bytes | None:
    """Answer `hello` with this boundary's address instead of the cluster's.

    Until this existed the boundary depended on the client passing
    `directConnection=true` -- which is *client configuration*, not
    enforcement. A driver without it reads the `hosts` array and connects to
    the real nodes, straight past the policy. Measured against a local
    deployment it does not even fail safe: the client reads the container's
    internal hostname, cannot resolve it, and gives up. Against Atlas those
    hosts resolve perfectly, so the same bug is a silent bypass rather than
    an error.

    **What is rewritten, and what is deliberately not.** This is where a
    topology rewrite goes wrong, so each field is a decision:

    - ``hosts``, ``me``, ``primary`` -> this boundary. That is the lie that
      makes the client stay.
    - ``passives``, ``arbiters`` -> emptied. They name other machines.
    - ``setName`` -> **kept**. Stripping it makes a driver treat the target
      as a standalone, which silently disables retryable writes -- a
      correctness regression handed over as a topology tidy-up.
    - ``isWritablePrimary`` / ``secondary`` -> **passed through untouched**.
      Forcing these true is the tempting version and it is the dangerous
      one: that flag is exactly the signal a driver uses to notice a
      failover, so masking it means the client keeps writing happily to a
      boundary whose upstream is now a secondary, and nothing anywhere
      notices. A boundary that lies about writability has made itself the
      outage.
    """
    decoded = decode_op_msg(raw)
    if decoded is None:
        return None
    flags, reply = decoded

    # A `hello` reply is the one that describes a server to a driver. This
    # check is a fast path and a statement of intent, *not* the safety
    # property -- deleting it changes no behaviour, which a sabotage run
    # proved rather than a reviewer guessing. The guarantee that an
    # unrelated message is forwarded byte for byte is the `out == reply`
    # comparison at the bottom: nothing is re-encoded unless a field
    # actually changed.
    if "maxWireVersion" not in reply or not (
            set(reply) & {"isWritablePrimary", "ismaster", "hosts", "me"}):
        return None

    out = dict(reply)
    for field in TOPOLOGY_FIELDS:
        if field in out:
            out[field] = [advertise] if field == "hosts" else []
    if "me" in out:
        out["me"] = advertise
    if "primary" in out:
        # Only meaningful if the upstream still believes it has one. Saying
        # "the primary is me" while the upstream says there is none would be
        # the same lie as forcing writability.
        out["primary"] = advertise
    if out == reply:
        return None
    return encode_op_msg(req_id, resp_to, flags, out)


def delete_reply(raw: bytes, req_id: int, resp_to: int) -> bytes:
    """Make an ``update`` reply look like the ``delete`` reply it answers.

    The driver issued a delete and is entitled to a delete's shape. An
    update reply carries ``nModified`` beside ``n``; a delete's does not, and
    a client that sees a field its command never produces is being told
    something true about the proxy and confusing about its own call.
    """
    decoded = decode_op_msg(raw)
    if decoded is None:
        return raw
    flags, reply = decoded
    if "nModified" not in reply:
        return raw
    reply = {k: v for k, v in reply.items() if k != "nModified"}
    return encode_op_msg(req_id, resp_to, flags, reply)


def strip_compression(raw: bytes, req_id: int, resp_to: int) -> bytes:
    """Remove ``compression`` from a handshake so replies arrive readable.

    A boundary that cannot read the traffic cannot enforce anything, and
    negotiating compression away is cheaper and far less fragile than
    recompressing every batch we rewrite. The cost is bandwidth on a demo.
    """
    decoded = decode_op_msg(raw)
    if decoded is None:
        return raw
    flags, doc = decoded
    if not ({"hello", "ismaster", "isMaster"} & set(doc)) or "compression" not in doc:
        return raw
    doc = dict(doc)
    doc["compression"] = []
    return encode_op_msg(req_id, resp_to, flags, doc)


def enforce(raw: bytes, req_id: int, resp_to: int, guards: dict[str, Guard],
            verbose: bool) -> bytes:
    """Apply admission to a cursor batch on its way back to the client.

    Everything that is not a guarded cursor batch is forwarded byte for byte.
    That is deliberate: a proxy that re-encoded every message would be a new
    source of protocol bugs in exchange for nothing, and the only thing worth
    touching is the one array of documents that is about to become context.

    **Nothing is decoded until it is about to be judged.** Every reply on the
    connection arrives here, and all but a few are forwarded -- so the body is
    read lazily and the questions are asked cheapest-first: is there a cursor,
    what collection is it, is that collection guarded. A `find` on a
    collection nobody declared costs four field reads, not a Python object per
    float in every embedding it happens to carry. The documents become real
    only at ``guard.filter``, which is the first line that needs their values.
    """
    decoded = decode_op_msg(raw, LAZY)
    if decoded is None:
        return raw
    flags, reply = decoded
    cursor = reply.get("cursor")
    if not isinstance(cursor, Mapping):
        return raw
    key = "firstBatch" if "firstBatch" in cursor else (
        "nextBatch" if "nextBatch" in cursor else None)
    if key is None:
        return raw

    collection = _collection_of(reply)
    guard = guards.get(collection) if collection else None
    if guard is None:
        return raw

    batch = cursor[key]
    if not isinstance(batch, list) or not batch:
        return raw

    # The first read of the documents themselves, and only on a batch that a
    # declared guard is about to judge. Still lazy: the rules name a handful
    # of top-level fields, so a vector never becomes a list of floats -- and a
    # document that survives is re-encoded from the bytes it arrived in.
    kept = guard.filter(batch)
    if len(kept) == len(batch):
        return raw                      # nothing refused: do not touch the bytes

    reply = dict(reply)
    reply["cursor"] = dict(cursor)
    reply["cursor"][key] = kept
    # `reply` is now a plain dict of raw values; `bson.encode` splices the
    # untouched ones back in as bytes rather than re-serialising them.
    if verbose:
        print(f"  voyd: {collection}: refused {len(batch) - len(kept)} of "
              f"{len(batch)}  {guard.reasons()}", flush=True)
    return encode_op_msg(req_id, resp_to, flags, reply)


async def pump(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
               back: asyncio.StreamWriter, *, to_server: bool,
               guards: dict[str, Guard], verbose: bool,
               rewritten: set[int],
               upstream: Upstream | None = None,
               advertise: str | None = None,
               meter: "voyd_metrics.Meter | None" = None) -> str:
    """One direction of one connection.

    ``rewritten`` is shared between the two directions and is the only state
    they share: a request id whose ``delete`` was turned into an ``update``
    has to be recognised again when its reply comes back the other way. It is
    per-connection, because request ids are.

    It needs no lock. Both directions of a connection run on the same event
    loop, so the set is only ever touched between awaits -- and the previous
    version's `threading.Lock` was protecting against a preemption that can
    no longer happen. Deleting it is not an optimisation; it removes a piece
    of shared mutable state from a program whose entire argument is about
    being careful with those.

    ``back`` is the writer pointing the way we came, used to answer a
    refusal without troubling the server.
    """

    async def send(sock_writer: asyncio.StreamWriter, payload: bytes) -> None:
        # `drain` is not optional. Without it a fast upstream and a slow
        # client buffer the difference in this process's memory, which is
        # the shape of an outage that looks like a leak.
        sock_writer.write(payload)
        await sock_writer.drain()

    try:
        while True:
            raw, _len, req_id, resp_to, opcode = await read_message_async(reader)
            if meter is not None:
                # One integer add per *message*, not per document. The
                # per-document path is 2.3us and stays untouched.
                if to_server:
                    meter.messages_from_client_total += 1
                else:
                    meter.messages_from_upstream_total += 1
            if opcode == OP_COMPRESSED:
                expanded = uncompress_message(raw)
                if expanded is None:
                    # Unreadable rather than empty. Say so and forward: a
                    # silent pass-through would be a boundary reporting
                    # nothing because it saw nothing, which is the exact
                    # failure this tool exists to make impossible.
                    print("  voyd: WARNING: compressed message this proxy "
                          "cannot read, forwarded unchecked", flush=True)
                    await send(writer, raw)
                    continue
                raw, opcode = expanded, OP_MSG
            if opcode == OP_MSG and to_server:
                raw = strip_compression(raw, req_id, resp_to)
                # `decode_sections`, not `decode_op_msg`: a write command
                # carries a kind-1 document sequence after its body, and the
                # kind-0-only reader treats those trailing bytes as part of
                # the body's BSON and fails. It failed silently, which meant
                # every delete was forwarded and the rewrite below looked
                # like it was not implemented.
                head = decode_sections(raw)
                body = head[1] if head else {}

                # A destructive verb this boundary cannot express as a
                # revocation is answered here rather than forwarded: the
                # reply goes straight back and the server never sees it.
                refusal = refuse_unrewritable(raw, req_id, req_id, guards)
                if refusal is not None:
                    await send(back, refusal)
                    continue

                target = guards.get(body.get("delete"))
                if target is not None and target.on_delete == "revoke":
                    swapped = revoke_instead_of_delete(
                        raw, req_id, resp_to, target, verbose)
                    if swapped is not None:
                        raw = swapped
                        rewritten.add(req_id)

                # `findOneAndDelete` is a *different command*, and
                # intercepting one and not the other gave a team the
                # guarantee for one delete verb and silently not the other.
                fam = guards.get(body.get("findAndModify"))
                if fam is not None and fam.on_delete == "revoke":
                    swapped = revoke_instead_of_find_and_delete(
                        raw, req_id, resp_to, fam, verbose)
                    if swapped is not None:
                        raw = swapped
            elif opcode == OP_MSG:
                if advertise:
                    rebuilt = rewrite_topology(raw, req_id, resp_to, advertise)
                    if rebuilt is not None:
                        await send(writer, rebuilt)
                        continue
                was_delete = resp_to in rewritten
                rewritten.discard(resp_to)

                # The failover signal, read off the reply the client was
                # getting anyway. No health check, no timer: the server is
                # already telling us, on the one message that proves it.
                if upstream is not None:
                    head = decode_op_msg(raw)
                    if head is not None:
                        why = stepped_down(head[1])
                        if why:
                            upstream.invalidate(why)

                raw = (delete_reply(raw, req_id, resp_to) if was_delete
                       else enforce(raw, req_id, resp_to, guards, verbose))
            await send(writer, raw)
    except Hangup:
        # Not an error, and the one disconnect the caller may still be
        # owed something for.
        return "hangup"
    except ProtocolError as exc:
        print(f"  voyd: dropped a connection: {exc}", flush=True)
    except (ConnectionError, OSError):
        # A closed socket is how a client disconnects, and both directions
        # notice. `OSError` is here beside `ConnectionError` because the
        # *other* pump closing these sockets first surfaces as EBADF, not as
        # a connection error -- which printed a stack trace on every clean
        # exit and made a working proxy look broken.
        pass
    except asyncio.CancelledError:
        # The sibling direction ended and `session` is tearing this one
        # down. Not an error, and re-raising is how a cancelled task is
        # supposed to behave -- swallowing it would make shutdown hang.
        raise
    except Exception:
        traceback.print_exc()
    return "closed"


# What a replica set says when the node you are talking to is no longer the
# one that may write. The boundary learns from these rather than polling: a
# health check is a guess about the future, and this is the server telling
# you about the present.
STEPPED_DOWN = {
    10107,   # NotWritablePrimary
    13435,   # NotPrimaryNoSecondaryOk
    13436,   # NotPrimaryOrSecondary
    11602,   # InterruptedDueToReplStateChange
    189,     # PrimarySteppedDown
    91,      # ShutdownInProgress
}


class Upstream:
    """Where the boundary forwards to, and how it stays right.

    This used to be a ``(host, port, tls)`` tuple resolved once at startup,
    and all three of the operability complaints against this proxy were the
    same complaint about that tuple: it could not be re-resolved, so a
    failover meant a restart.

    A connection is a *lifecycle*, not an address:

    - **resolved lazily**, so startup does not block on DNS and a cluster
      that is briefly unreachable does not prevent the boundary from
      listening;
    - **cached**, because resolving a `mongodb+srv` URI costs a DNS round
      trip and a topology scan, and doing that per connection would put the
      driver's startup cost on every client;
    - **invalidated by the server's own error**. When a reply carries
      `NotWritablePrimary` -- or any of the codes above -- the cached
      address is wrong *now*, and the next connection re-resolves. That is
      how a driver learns about an election, and it is strictly better than
      a timer: no window where the boundary knows and has not acted, and no
      polling a healthy cluster forever to find out about an event that may
      never happen.

    What it still is not: a driver. It picks one node and forwards bytes; it
    does not load-balance reads, follow read preference, or retry a write
    the client already saw fail. A client should reach it with
    ``directConnection=true`` so it does not chase the hosts the cluster
    advertises straight past the boundary.
    """

    def __init__(self, target: str, *, verbose: bool = True,
                 meter: "voyd_metrics.Meter | None" = None):
        self.target = target
        self.verbose = verbose
        self.meter = meter
        self._addr: tuple[str, int, bool] | None = None
        self._lock = threading.Lock()
        # Resolution is serialised so a burst of clients arriving after an
        # election causes one topology scan rather than one each. The
        # threading lock above still guards the cache itself, because
        # `_resolve` runs in an executor thread.
        self._resolving = asyncio.Lock()
        self.generation = 0

    def address(self) -> tuple[str, int, bool]:
        with self._lock:
            if self._addr is None:
                self._addr = self._resolve()
            return self._addr

    def invalidate(self, why: str) -> None:
        """Forget where the primary was. The next connection finds out."""
        with self._lock:
            if self._addr is None:
                return
            host, port, _ = self._addr
            self._addr = None
            self.generation += 1
            if self.meter is not None:
                self.meter.upstream_reresolve_total += 1
        print(f"voyd-wire: {host}:{port} is no longer writable ({why}); "
              f"re-resolving on the next connection", flush=True)

    def _resolve(self) -> tuple[str, int, bool]:
        """A bare `host:port`, or a URI resolved the way a driver would.

        Atlas is `mongodb+srv`, which means three things a raw TCP dial
        cannot do: the hosts live in DNS SRV records, the connection must be
        TLS, and the port is not in the string.
        """
        target = self.target
        if "://" not in target:
            host, _, port = target.partition(":")
            return host, int(port or 27017), False

        from pymongo.uri_parser import parse_uri
        parsed = parse_uri(target)
        tls = bool(parsed["options"].get("tls",
                                         target.startswith("mongodb+srv")))
        try:
            from pymongo import MongoClient
            with MongoClient(target, serverSelectionTimeoutMS=15000) as probe:
                # `ping` first: the driver connects lazily, and `.primary` on
                # an undiscovered topology is `None` -- which silently
                # selected the first DNS node and looked exactly like this
                # not working.
                probe.admin.command("ping")
                primary = probe.primary
            if primary:
                if self.verbose:
                    print(f"voyd-wire: primary is {primary[0]}:{primary[1]}",
                          flush=True)
                return primary[0], primary[1], tls
        except Exception as exc:
            print(f"voyd-wire: could not find the primary "
                  f"({type(exc).__name__}); using the first node DNS "
                  f"returned. Writes may come back `not primary`.", flush=True)

        host, port = parsed["nodelist"][0]
        return host, port, tls

    def connect(self) -> socket.socket:
        host, port, tls = self.address()
        sock = socket.create_connection((host, port), timeout=20)
        # No *read* timeout, deliberately. A MongoDB connection legitimately
        # idles for minutes -- an awaitData cursor, a change stream, a client
        # between requests -- so a read deadline would kill healthy
        # connections and look like the cluster flapping. TCP keepalive is
        # the right tool: it notices a peer that went away without
        # penalising one that is merely quiet.
        keepalive(sock)
        sock.settimeout(None)
        if not tls:
            return sock
        ctx = ssl.create_default_context()
        # `server_hostname` is what makes certificate validation mean
        # anything against a named cluster; without it this is an encrypted
        # channel to whoever answered.
        return ctx.wrap_socket(sock, server_hostname=host)

    async def open(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """The same upstream connection, without holding a thread.

        `_resolve` stays blocking -- it is a DNS round trip and a pymongo
        topology scan -- so it goes to an executor. Doing it inline would
        stall every other connection on this loop for the length of a
        cluster handshake, which is exactly the failure an event loop is
        supposed to remove.
        """
        async with self._resolving:
            loop = asyncio.get_running_loop()
            host, port, tls = await loop.run_in_executor(None, self.address)

        ssl_ctx = None
        server_hostname = None
        if tls:
            ssl_ctx = ssl.create_default_context()
            server_hostname = host
        reader, writer = await asyncio.open_connection(
            host, port, ssl=ssl_ctx, server_hostname=server_hostname)

        # No *read* timeout, deliberately -- see `connect` above. Keepalive
        # is the tool that notices a peer that vanished without penalising
        # one that is merely idle, and it has to be set on the socket under
        # the stream rather than on the stream.
        raw_sock = writer.get_extra_info("socket")
        if raw_sock is not None:
            keepalive(raw_sock)
        return reader, writer


class Secondaries:
    """The nodes a read may be ranked on, and the credential to reach them.

    Separate from `Upstream` because it answers a different question and
    fails differently. `Upstream` must be right or nothing works; this may
    be empty, stale, or unreachable and the only consequence is that reads
    stay on the primary -- which is the behaviour of every version of this
    proxy before fan-out existed. Degrading to "correct but not spread" is
    the only acceptable failure mode for an optimisation that sits in front
    of a guarantee.

    **It carries its own credential, and that is a real change.** Every
    other upstream connection in this file is the client's: the proxy holds
    no credentials and forwards the client's handshake. A secondary
    connection cannot work that way. Authentication is per connection and
    SCRAM is a challenge-response bound to a nonce, so the client's
    handshake cannot be replayed onto a second socket -- the proxy would
    have to know the password, and it deliberately does not.

    So fan-out takes a URI of its own, and reads served from a secondary run
    as *that* identity rather than the caller's. Where the two differ, that
    is a privilege change, which is why `Conversation` refuses to fan out on
    any connection whose client authenticated as a different user. See
    LIMITS.md §3.
    """

    def __init__(self, uri: str, *, verbose: bool = True,
                 meter: "voyd_metrics.Meter | None" = None,
                 give_up: float = 1.0):
        self.uri = uri
        # Shared across every connection this worker serves. A per
        # connection sample would be a handful of reads on a short-lived
        # client, which is not enough to withdraw a collection on.
        self.payoff = voyd_fanout.Payoff(ratio=give_up)
        self.verbose = verbose
        self.meter = meter
        self._nodes: list[tuple[str, int, bool]] = []
        self._next = 0
        self._lock = threading.Lock()
        self._resolving = asyncio.Lock()
        self._resolved = False

    def identity(self) -> tuple[str, str] | None:
        """``(auth database, username)`` from the fan-out URI.

        A *pair*, because a username on its own does not name anybody.
        ``alice`` in ``admin`` and ``alice`` in ``reports`` are two
        different principals with two different sets of privileges, and an
        identity check that compared only the name would hand the first
        one's connection to the second. That was a real hole in this check
        for one commit, documented rather than found.
        """
        try:
            from pymongo.uri_parser import parse_uri
            parsed = parse_uri(self.uri)
        except Exception:
            return None
        username = parsed.get("username")
        if not username:
            return None
        options = parsed.get("options") or {}
        source = options.get("authSource") or parsed.get("database") or "admin"
        return str(source), str(username)

    @property
    def user(self) -> str | None:
        """Just the name, for log lines. Never for the check."""
        found = self.identity()
        return found[1] if found else None

    def _resolve(self) -> list[tuple[str, int, bool]]:
        from pymongo.uri_parser import parse_uri
        parsed = parse_uri(self.uri)
        tls = bool(parsed["options"].get("tls",
                                         self.uri.startswith("mongodb+srv")))
        try:
            from pymongo import MongoClient
            with MongoClient(self.uri, serverSelectionTimeoutMS=15000) as probe:
                probe.admin.command("ping")
                found = sorted(probe.secondaries)
        except Exception as exc:
            print(f"voyd-wire: cannot enumerate secondaries "
                  f"({type(exc).__name__}); reads stay on the primary",
                  flush=True)
            return []
        if self.verbose:
            where = ", ".join(f"{h}:{p}" for h, p in found) or "none"
            print(f"voyd-wire: ranking reads on {where}", flush=True)
        return [(h, p, tls) for h, p in found]

    async def pick(self) -> tuple[str, int, bool] | None:
        """The next secondary, round robin, or `None` if there are none."""
        async with self._resolving:
            if not self._resolved:
                loop = asyncio.get_running_loop()
                nodes = await loop.run_in_executor(None, self._resolve)
                with self._lock:
                    self._nodes, self._resolved = nodes, True
        with self._lock:
            if not self._nodes:
                return None
            node = self._nodes[self._next % len(self._nodes)]
            self._next += 1
            return node

    def forget(self) -> None:
        """A secondary that would not answer is not one to keep offering."""
        with self._lock:
            self._resolved = False
            self._nodes = []

    async def open(self) -> tuple[asyncio.StreamReader,
                                  asyncio.StreamWriter] | None:
        node = await self.pick()
        if node is None:
            return None
        host, port, tls = node
        ssl_ctx = ssl.create_default_context() if tls else None
        try:
            reader, writer = await asyncio.open_connection(
                host, port, ssl=ssl_ctx,
                server_hostname=host if tls else None)
        except (OSError, asyncio.TimeoutError, ssl.SSLError) as exc:
            print(f"voyd-wire: secondary {host}:{port} unreachable "
                  f"({type(exc).__name__}); reads stay on the primary",
                  flush=True)
            self.forget()
            return None
        raw_sock = writer.get_extra_info("socket")
        if raw_sock is not None:
            keepalive(raw_sock)
        if not await self._identify(reader, writer):
            await close(writer)
            self.forget()
            return None
        return reader, writer

    async def _identify(self, reader: asyncio.StreamReader,
                        writer: asyncio.StreamWriter) -> bool:
        """Run the handshake and SCRAM over this stream pair.

        `authenticate` is pymongo's synchronous code driven through a shim,
        so it runs in a worker thread; every round trip it asks for is
        marshalled back here. Nothing else is on the connection yet -- the
        reply pump does not start until this returns -- so reading the next
        message is unambiguous rather than a race with a client's traffic.
        """
        loop = asyncio.get_running_loop()
        counter = [0]

        async def round_trip(body: dict) -> dict:
            from pymongo.errors import OperationFailure
            counter[0] += 1
            req_id = counter[0]
            writer.write(encode_op_msg(req_id, 0, 0, body))
            await writer.drain()
            raw, _len, _rid, _resp, opcode = await read_message_async(reader)
            if opcode == OP_COMPRESSED:
                expanded = uncompress_message(raw)
                if expanded is None:
                    raise OperationFailure("unreadable compressed reply")
                raw = expanded
            decoded = decode_op_msg(raw)
            if decoded is None:
                raise OperationFailure("unreadable reply while authenticating")
            reply = dict(decoded[1])
            if not reply.get("ok"):
                raise OperationFailure(
                    reply.get("errmsg", "authentication failed"),
                    reply.get("code"), reply)
            return reply

        def exchange(body: dict) -> dict:
            return asyncio.run_coroutine_threadsafe(
                round_trip(body), loop).result(30)

        try:
            return await loop.run_in_executor(
                None, authenticate, exchange, self.uri)
        except Exception as exc:
            print(f"voyd-wire: secondary handshake failed "
                  f"({type(exc).__name__}); reads stay on the primary",
                  flush=True)
            return False


class _AuthShim:
    """Just enough of a pymongo ``Connection`` for its SCRAM code to run.

    SCRAM is a salted challenge-response over two round trips, and the
    earlier version of this declined to implement it with the note that a
    security primitive should not be written by somebody who did not have
    to. That reasoning was right and the conclusion was wrong: the choice
    was never "write SCRAM or skip authentication", it was "write SCRAM or
    *drive the implementation already installed*".

    ``_authenticate_scram`` touches exactly two things on the connection it
    is handed -- ``auth_ctx`` and ``command`` -- which is little enough that
    this is a transport rather than a reimplementation. The client proof,
    the salted password, the iteration count and the server-signature check
    that stops a man in the middle finishing the exchange all stay in
    pymongo. What is supplied here is a way to send a document and get one
    back.
    """

    auth_ctx = None

    def __init__(self, exchange):
        self._exchange = exchange

    def command(self, dbname: str, spec: Mapping, *args, **kwargs) -> dict:
        body = dict(spec)
        body["$db"] = dbname
        return self._exchange(body)


def authenticate(exchange, uri: str) -> bool:
    """Hand this proxy's own secondary connection its identity.

    ``exchange`` is a *blocking* callable taking a command document and
    returning the reply. This function therefore runs in a worker thread,
    and the callable marshals each round trip back to the event loop -- the
    only arrangement that works for both a plain socket and a TLS one,
    because an already-wrapped `SSLSocket` cannot be handed to asyncio and
    a TLS handshake cannot happen after authentication.

    Returns False rather than raising on every failure path. A secondary
    this proxy cannot authenticate to is not an outage; it is a deployment
    where reads stay on the primary, which is what every version of this
    file did before fan-out existed.
    """
    from pymongo.auth_shared import _build_credentials_tuple
    from pymongo.uri_parser import parse_uri

    parsed = parse_uri(uri)
    username, password = parsed.get("username"), parsed.get("password")
    options = parsed.get("options") or {}
    source = (options.get("authSource") or parsed.get("database") or "admin")

    # The handshake proper. Every MongoDB connection owes the server one of
    # these before anything else, and `saslSupportedMechs` is how the server
    # is *asked* which mechanisms this user has rather than told which one
    # this proxy guessed -- the difference between working on a SCRAM-SHA-1
    # deployment and failing on one.
    shim = _AuthShim(exchange)
    hello: dict = {"hello": 1, "client": {
        "driver": {"name": "voyd-wire", "version": "0"},
        "os": {"type": sys.platform}}}
    if username:
        hello["saslSupportedMechs"] = f"{source}.{username}"
    try:
        reply = shim.command("admin", hello)
    except Exception as exc:
        print(f"voyd-wire: secondary handshake failed "
              f"({type(exc).__name__}); reads stay on the primary", flush=True)
        return False
    if not username:
        return True                      # an unauthenticated deployment

    offered = reply.get("saslSupportedMechs") or []
    mechanism = ("SCRAM-SHA-256" if "SCRAM-SHA-256" in offered
                 else "SCRAM-SHA-1" if "SCRAM-SHA-1" in offered else None)
    if mechanism is None:
        print(f"voyd-wire: the secondary offers {list(offered) or 'nothing'} "
              f"for {username!r}, and fan-out speaks only SCRAM; reads stay "
              f"on the primary", flush=True)
        return False

    try:
        from pymongo.synchronous.auth import _authenticate_scram
    except ImportError:                  # pymongo < 4.9 laid it out flat
        from pymongo.auth import _authenticate_scram  # type: ignore[no-redef]
    credentials = _build_credentials_tuple(
        mechanism, source, username, password, {}, source)
    try:
        _authenticate_scram(credentials, shim, mechanism)
    except Exception as exc:
        # Deliberately not the server's message: an authentication failure
        # reply can carry the mechanism and the user, and this line goes to
        # an operator's log.
        print(f"voyd-wire: could not authenticate to the secondary as "
              f"{username!r} ({type(exc).__name__}); reads stay on the "
              f"primary", flush=True)
        return False
    return True


def stepped_down(reply: dict) -> str | None:
    """Did the server just say this node may not write?

    Read from the reply the client was going to get anyway. A write error
    inside a batch is nested under ``writeErrors``, which is where this
    hides on exactly the command -- a delete -- that matters most here.
    """
    if reply.get("code") in STEPPED_DOWN:
        return str(reply.get("codeName") or reply.get("code"))
    for err in reply.get("writeErrors") or ():
        if isinstance(err, dict) and err.get("code") in STEPPED_DOWN:
            return str(err.get("codeName") or err.get("code"))
    return None


def keepalive(sock: socket.socket) -> None:
    """Notice a peer that vanished, without punishing one that is idle."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        for opt, value in (("TCP_KEEPIDLE", 60), ("TCP_KEEPINTVL", 15),
                           ("TCP_KEEPCNT", 4)):
            if hasattr(socket, opt):        # Linux; macOS spells one of them
                sock.setsockopt(socket.IPPROTO_TCP, getattr(socket, opt), value)
    except OSError:
        pass                                 # best effort, never fatal


def listener(port: int, certfile: str | None, keyfile: str | None,
             *, backlog: int = 512) -> tuple[socket.socket, "ssl.SSLContext | None"]:
    """The socket clients reach, and the TLS context to wrap them in.

    Without a certificate this binds loopback only, and that is a decision
    rather than a default: a plaintext boundary reachable from the network
    would carry every document it just refused to serve, in the clear, to
    anybody on the path. With a certificate it binds all interfaces,
    because then it can be one.

    The context is returned *beside* the socket rather than wrapped around
    it. A wrapped listening socket hands back an already-negotiated
    `SSLSocket` from `accept()`, which means the handshake happens on the
    accept path -- one slow or hostile client stalls every other pending
    connection. `asyncio.start_server(ssl=...)` negotiates per connection
    instead, so a handshake that never completes costs one coroutine.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0" if certfile else "127.0.0.1", port))
    # A deeper backlog than the old 64: with workers sharing this socket the
    # kernel queue absorbs an accept burst that would otherwise be refused
    # connections the client reads as the boundary being down.
    sock.listen(backlog)
    sock.setblocking(False)
    if not certfile:
        return sock, None
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile, keyfile)
    return sock, ctx


class Live:
    """How many client connections are open right now.

    Its own object rather than a semaphore read, because "is anybody still
    connected?" and "may another connect?" are different questions and
    answering the first by interrogating the second is what broke shutdown.
    """

    def __init__(self) -> None:
        self.count = 0
        self.total = 0
        self._lock = threading.Lock()

    def __enter__(self):
        with self._lock:
            self.count += 1
            self.total += 1
        return self

    def __exit__(self, *_exc) -> None:
        with self._lock:
            self.count -= 1


async def session(client_r: asyncio.StreamReader, client_w: asyncio.StreamWriter,
                  upstream: Upstream, guards: dict[str, Guard], verbose: bool,
                  live: Live, advertise: str | None = None,
                  meter: "voyd_metrics.Meter | None" = None,
                  half_close_seconds: float = 10.0) -> None:
    """One client connection, start to finish, as one coroutine pair.

    A MongoDB connection is stateful -- authentication, sessions, cursors
    and transactions all bind to it -- so an upstream connection is *per
    client* rather than pooled. Sharing one would hand a cursor to whoever
    asked second, which is the concurrency bug this whole package exists to
    be careful about, committed by its own plumbing. That is unchanged by
    the move off threads; what changed is that a connection now costs a
    coroutine and a socket rather than two 8MB thread stacks.

    What is bounded instead is how many there are at once. `live` is
    entered and exited exactly once, here, so a client that disconnects
    mid-handshake cannot leak a slot.
    """
    with live:
        try:
            up_r, up_w = await upstream.open()
        except (OSError, asyncio.TimeoutError) as exc:
            host, port, _ = upstream.address()
            print(f"voyd-wire: cannot reach {host}:{port}: {exc}", flush=True)
            # A connection failure is as good a reason to re-resolve as an
            # election: the node may simply be gone.
            upstream.invalidate(type(exc).__name__)
            await close(client_w)
            return

        rewritten: set[int] = set()
        common = {"guards": guards, "verbose": verbose,
                  "rewritten": rewritten, "upstream": upstream,
                  "advertise": advertise, "meter": meter}
        forward = asyncio.ensure_future(pump(client_r, up_w, client_w,
                                             to_server=True, **common))
        back = asyncio.ensure_future(pump(up_r, client_w, up_w,
                                          to_server=False, **common))
        tasks = [forward, back]
        try:
            # Either direction ending ends the connection: an upstream that
            # closed has nothing more to say, and a client that vanished
            # has no reply to receive. Waiting for both unconditionally
            # would hold a slot open on a half-dead socket until keepalive
            # noticed, which is minutes.
            #
            # With one exception, and it is the whole reason these two
            # futures have names. A client that called `shutdown(SHUT_WR)`
            # is saying "no more requests" -- it is still reading, and it
            # is still owed the answers it already asked for. Tearing the
            # reply direction down on that is how a half close used to
            # cost the caller its last answer.
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            if (forward.done() and not forward.cancelled()
                    and not forward.exception()
                    and forward.result() == "hangup" and not back.done()):
                # Pass the half close through, so the server finishes its
                # replies and closes rather than waiting for a request
                # that is never coming.
                try:
                    if up_w.can_write_eof():
                        up_w.write_eof()
                except (OSError, ConnectionError, ssl.SSLError):
                    pass
                # Bounded, because a client that half closes and then
                # never reads must not hold a slot forever.
                await asyncio.wait([back], timeout=half_close_seconds)
        finally:
            for task in tasks:
                task.cancel()
            # Both have to actually finish before the slot is released, or
            # a burst of short-lived clients reports a connection count
            # with nothing to do with the sockets actually open.
            await asyncio.gather(*tasks, return_exceptions=True)
            await close(up_w)
            await close(client_w)


# Request ids this proxy invents for its own permission lookups. High and
# fixed so they cannot collide with a driver's, which start near zero and
# count up: a collision would mean a client's reply being resolved into a
# mark lookup's future and never reaching it.
ASKED_BASE = 0x7F00_0000


class Conversation:
    """One client, one primary connection, and at most one secondary.

    The fan-out path is a separate object from the plain one on purpose.
    Every other version of this proxy is a byte pipe with two coroutines and
    no routing decision to get wrong, and that path is untouched by this
    class -- `session` still runs it whenever `--fan-out` is absent. A
    boundary that made its simplest configuration go through its most
    complicated code to get there would be trading the property that matters
    for one that does not.

    State worth naming, because all of it is the kind that goes wrong:

    - ``home`` -- which upstream issued each cursor id. A `getMore` follows
      its cursor or it is asking a server about a cursor it never opened.
    - ``asked`` -- the futures for this proxy's own mark lookups, sent on the
      client's primary connection so they run as the client's identity and
      cost no extra socket.
    - ``client_lock`` -- two reply pumps now write to one client. Without it
      a secondary's batch and a primary's acknowledgement interleave into
      bytes no driver can frame.
    """

    def __init__(self, client_w, primary_w, guards, verbose, meter):
        self.client_w = client_w
        self.primary_w = primary_w
        self.guards = guards
        self.verbose = verbose
        self.meter = meter
        self.secondary_r = None
        self.secondary_w = None
        self.home: dict[int, str] = {}
        self.asked: dict[int, asyncio.Future] = {}
        self._next_ask = ASKED_BASE
        self.client_lock = asyncio.Lock()
        self.primary_lock = asyncio.Lock()
        self.payoff = None
        self.sent_at: dict[int, float] = {}
        # Starts *off* wherever the secondaries need a credential, and is
        # turned on only by a client proving the same identity. The other
        # way round -- on until somebody is caught -- is fail-open, and it
        # failed open for exactly as long as this file only looked for a
        # standalone `saslStart`.
        self.fan_out_ok = True

    async def to_client(self, payload: bytes) -> None:
        async with self.client_lock:
            self.client_w.write(payload)
            await self.client_w.drain()

    async def ask_primary(self, command: dict, timeout: float = 20.0) -> dict | None:
        """Run one command on the client's own primary connection.

        This is the only place the boundary speaks rather than forwards, and
        it is worth being precise about why that is still not "a connection
        of its own": the socket, the authentication and the identity are all
        the client's. What is borrowed is a gap between its requests.
        """
        self._next_ask += 1
        req_id = self._next_ask
        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()
        self.asked[req_id] = future
        try:
            async with self.primary_lock:
                self.primary_w.write(encode_op_msg(req_id, 0, 0, command))
                await self.primary_w.drain()
            raw = await asyncio.wait_for(future, timeout)
        except (asyncio.TimeoutError, ConnectionError, OSError):
            return None
        finally:
            self.asked.pop(req_id, None)
        decoded = decode_op_msg(raw)
        return dict(decoded[1]) if decoded else None

    async def authoritative(self, db: str, collection: str, ids: list,
                            fields: set | None) -> dict | None:
        """The marks the primary holds for these ids, drained to the end.

        ``None`` means the question could not be answered -- a timeout, a
        dead primary, an error reply. The caller refuses the batch on
        ``None``, because the alternative is serving documents whose
        permission nobody established, which is the failure this exists to
        prevent rather than a degraded version of preventing it.
        """
        command: dict = {"find": collection, "filter": {"_id": {"$in": ids}},
                         "batchSize": len(ids), "$db": db}
        if fields is not None:
            command["projection"] = {f: 1 for f in sorted(fields)}
        reply = await self.ask_primary(command)
        if not reply or not reply.get("ok"):
            return None
        cursor = reply.get("cursor") or {}
        docs = list(cursor.get("firstBatch") or [])
        cursor_id = cursor.get("id", 0)
        # A whole-document fetch can exceed one reply. Draining is not an
        # edge case to skip: a truncated answer would look exactly like
        # documents the primary does not have, and those get refused.
        while cursor_id:
            more = await self.ask_primary(
                {"getMore": cursor_id, "collection": collection,
                 "batchSize": len(ids), "$db": db})
            if not more or not more.get("ok"):
                return None
            nxt = more.get("cursor") or {}
            docs.extend(nxt.get("nextBatch") or [])
            cursor_id = nxt.get("id", 0)
        out = {}
        for doc in docs:
            try:
                out[doc["_id"]] = doc
            except TypeError:
                return None              # an unhashable _id cannot be matched
        return out

    async def permit(self, raw: bytes, req_id: int, resp_to: int) -> bytes:
        """Take the verdict on a secondary's batch from the primary's marks.

        The shape mirrors `enforce`, and the difference is the whole feature:
        `enforce` judges the documents it was handed, which is correct when
        they came from the primary and is a stale-mark bug when they did not.
        """
        decoded = decode_op_msg(raw, LAZY)
        if decoded is None:
            return raw
        flags, reply = decoded
        cursor = reply.get("cursor")
        if not isinstance(cursor, Mapping):
            return raw
        key = ("firstBatch" if "firstBatch" in cursor
               else "nextBatch" if "nextBatch" in cursor else None)
        if key is None:
            return raw
        ns = (cursor.get("ns") or "")
        db, _, collection = ns.partition(".")
        guard = self.guards.get(collection)
        if guard is None:
            return raw                   # nothing declared: nothing to verify
        batch = cursor[key]
        if not isinstance(batch, list) or not batch:
            return raw

        ids = voyd_fanout.needed_ids(batch)
        fields = voyd_fanout.verdict_fields(guard)
        began = time.monotonic()
        # How long the secondary took, measured from the moment `route`
        # sent the command. A *duration*, which is worth saying because the
        # first version of this passed the stored timestamp straight
        # through as if it were one -- the ratio was then a monotonic clock
        # against a few milliseconds, no collection ever looked unprofitable,
        # and the whole mechanism silently never fired.
        sent = self.sent_at.pop(resp_to, None)
        ranked_in = None if sent is None else began - sent
        fresh = (await self.authoritative(db, collection, ids, fields)
                 if ids is not None else None)
        verified_in = time.monotonic() - began
        if (self.payoff is not None and ranked_in is not None
                and fresh is not None):
            why = self.payoff.record(collection, ranked_in, verified_in)
            if why is not None:
                print(f"voyd-wire: no longer ranking {collection} on a "
                      f"secondary -- {why}", flush=True)
                if self.meter is not None:
                    self.meter.fanout_withdrawn_total += 1
        if fresh is None:
            # Unverifiable. Refuse the page rather than serve it: a batch
            # ranked on a replica whose marks could not be checked is
            # exactly the confidently-wrong answer this repository is named
            # after, and "the primary was briefly slow" is not a reason to
            # produce one.
            if self.meter is not None:
                self.meter.fanout_unverified_total += 1
            print(f"  voyd: {collection}: refused {len(batch)} of "
                  f"{len(batch)} -- the primary could not confirm their "
                  f"marks", flush=True)
            kept: list = []
        else:
            judgeable, originals = voyd_fanout.merge_marks(batch, fresh, fields)
            allowed = guard.filter(judgeable)
            try:
                permitted = {d["_id"] for d in allowed}
                kept = [o for o in originals if o["_id"] in permitted]
            except TypeError:
                keep_ids = [id(d) for d in allowed]
                kept = [o for o, j in zip(originals, judgeable)
                        if id(j) in keep_ids]
            if self.meter is not None:
                self.meter.fanout_verified_total += 1
            if self.verbose and len(kept) != len(batch):
                print(f"  voyd: {collection}: refused {len(batch) - len(kept)}"
                      f" of {len(batch)} on the primary's marks  "
                      f"{guard.reasons()}", flush=True)
        if len(kept) == len(batch):
            return raw
        reply = dict(reply)
        reply["cursor"] = dict(cursor)
        reply["cursor"][key] = kept
        return encode_op_msg(req_id, resp_to, flags, reply)


def _cursor_id(reply: Mapping) -> int | None:
    cursor = reply.get("cursor")
    if isinstance(cursor, Mapping):
        got = cursor.get("id")
        if isinstance(got, int) and got:
            return got
    return None


def authenticating(body: Mapping) -> tuple[bool, tuple[str, str] | None]:
    """Is this an authentication attempt, and as whom?

    Two shapes, and missing the second one was a real bug rather than a
    theoretical gap. A driver may send `saslStart` as its own command, but
    pymongo -- and every other modern driver -- folds the first round into
    the handshake as `speculativeAuthenticate` to save a round trip. A
    check that only looked for `saslStart` therefore never fired against a
    real driver, and fan-out stayed on for a client authenticated as
    somebody else. The test that found it is
    `test_a_client_arriving_as_somebody_else_is_not_served_over_this_identity`.

    The username comes off the SCRAM first message, `n,,n=<user>,r=<nonce>`,
    which is in the clear -- the *proof* is what is protected, not the
    identity -- so reading it needs no credential.

    Returns ``(attempted, identity)`` where identity is
    ``(auth database, username)``. ``(True, None)`` is the important case:
    an authentication this function does not understand, X.509 or AWS or
    OIDC, where the answer to "as whom" is unknown and the caller must
    treat it as "not us".

    The auth database is half the answer and was missing for a commit.
    ``alice`` authenticated against ``admin`` and ``alice`` authenticated
    against ``reports`` are different principals; comparing names alone
    would have let the second be served over the first's connection.
    """
    inner = body.get("speculativeAuthenticate")
    if isinstance(inner, Mapping):
        # A speculative round names its database in `db`; the enclosing
        # `hello` is always on `admin` and says nothing about the user.
        source = inner.get("db")
        body = inner
    elif {"saslStart", "authenticate"} & set(body):
        source = body.get("$db")
    else:
        return False, None
    if not isinstance(source, str):
        return True, None
    payload = body.get("payload")
    raw = getattr(payload, "value", payload)
    if not isinstance(raw, (bytes, bytearray)):
        return True, None
    try:
        for part in raw.decode("utf8", "replace").split(","):
            if part.startswith("n="):
                name = part[2:].replace("=2C", ",").replace("=3D", "=")
                return True, (source, name)
    except Exception:
        return True, None
    return True, None


async def route(client_r: asyncio.StreamReader, conv: Conversation,
                upstream: Upstream, secondaries: Secondaries,
                guards: dict[str, Guard], verbose: bool,
                rewritten: set[int],
                meter: "voyd_metrics.Meter | None") -> str:
    """client -> upstream, choosing which upstream each message goes to.

    Every write rewrite here is the same call the single-upstream pump
    makes, in the same order, and that is not duplication worth removing:
    the two paths must agree about what a `delete` means, and the way to be
    sure of that is that both call `revoke_instead_of_delete` rather than
    that one of them calls the other.
    """
    async def send_primary(payload: bytes) -> None:
        async with conv.primary_lock:
            conv.primary_w.write(payload)
            await conv.primary_w.drain()

    try:
        while True:
            raw, _len, req_id, resp_to, opcode = await read_message_async(client_r)
            if meter is not None:
                meter.messages_from_client_total += 1
            if opcode == OP_COMPRESSED:
                expanded = uncompress_message(raw)
                if expanded is None:
                    print("  voyd: WARNING: compressed message this proxy "
                          "cannot read, forwarded unchecked", flush=True)
                    await send_primary(raw)
                    continue
                raw, opcode = expanded, OP_MSG
            if opcode != OP_MSG:
                await send_primary(raw)
                continue

            raw = strip_compression(raw, req_id, resp_to)
            head = decode_sections(raw)
            body = head[1] if head else {}

            refusal = refuse_unrewritable(raw, req_id, req_id, guards)
            if refusal is not None:
                await conv.to_client(refusal)
                continue

            target = guards.get(body.get("delete"))
            if target is not None and target.on_delete == "revoke":
                swapped = revoke_instead_of_delete(
                    raw, req_id, resp_to, target, verbose)
                if swapped is not None:
                    raw = swapped
                    rewritten.add(req_id)
            fam = guards.get(body.get("findAndModify"))
            if fam is not None and fam.on_delete == "revoke":
                swapped = revoke_instead_of_find_and_delete(
                    raw, req_id, resp_to, fam, verbose)
                if swapped is not None:
                    raw = swapped

            # ---- the identity check -------------------------------------
            #
            # The secondary connection is this proxy's, not the client's. If
            # the client is authenticating as somebody, serving its reads
            # over a connection authenticated as somebody else is a
            # privilege change wearing the shape of an optimisation. So
            # fan-out is switched off for this connection unless the two
            # identities are the same name.
            attempted, who = authenticating(body)
            if attempted:
                mine = secondaries.identity()
                matched = who is not None and who == mine
                if verbose and not matched:
                    shown = f"{who[0]}.{who[1]}" if who else "a mechanism "\
                        "this boundary cannot read"
                    theirs = f"{mine[0]}.{mine[1]}" if mine else "nobody"
                    print(f"  voyd: client authenticated as {shown}; "
                          f"fan-out is off for this connection (secondaries "
                          f"are reached as {theirs})", flush=True)
                conv.fan_out_ok = matched

            # ---- the routing decision -----------------------------------
            dest = "primary"
            if conv.fan_out_ok:
                more = body.get("getMore")
                if isinstance(more, int):
                    dest = conv.home.get(more, "primary")
                elif voyd_fanout.routes_to_secondary(
                        body, guards, secondaries.payoff.withdrawn()):
                    if conv.secondary_w is None:
                        opened = await secondaries.open()
                        if opened is not None:
                            conv.secondary_r, conv.secondary_w = opened
                        else:
                            conv.fan_out_ok = False
                    if conv.secondary_w is not None:
                        dest = "secondary"
                        # A secondary refuses an ordinary read: the command
                        # has to say it accepts a non-primary. The client
                        # sees one node and cannot have asked for this, so
                        # the boundary asks on its behalf -- which is the
                        # whole of what `--fan-out` opts into.
                        if head is not None and voyd_fanout.read_preference_of(
                                body) is None:
                            patched = dict(body)
                            patched["$readPreference"] = {
                                "mode": "secondaryPreferred"}
                            raw = encode_sections(req_id, resp_to, head[0],
                                                  patched, head[2], head[3])
                        conv.sent_at[req_id] = time.monotonic()
                        if meter is not None:
                            meter.fanout_reads_total += 1

            if dest == "secondary" and conv.secondary_w is not None:
                conv.secondary_w.write(raw)
                await conv.secondary_w.drain()
            else:
                await send_primary(raw)
    except Hangup:
        return "hangup"
    except ProtocolError as exc:
        print(f"  voyd: dropped a connection: {exc}", flush=True)
    except asyncio.CancelledError:
        raise
    except (ConnectionError, OSError):
        pass
    except Exception:
        traceback.print_exc()
    return "closed"


async def replies(reader: asyncio.StreamReader, conv: Conversation, *,
                  source: str, guards: dict[str, Guard], verbose: bool,
                  rewritten: set[int], upstream: Upstream | None,
                  advertise: str | None,
                  meter: "voyd_metrics.Meter | None") -> str:
    """One upstream -> the client, with the verdict taken on the way.

    Two of these run per fanned-out connection and they write to the same
    client, which is what `conv.to_client` serialises. The `source` is not
    cosmetic: it decides whether a batch is judged on the documents it
    arrived with or on marks fetched from the primary, and getting that
    backwards is the whole bug this feature could have been.
    """
    try:
        while True:
            raw, _len, req_id, resp_to, opcode = await read_message_async(reader)
            if meter is not None:
                meter.messages_from_upstream_total += 1
            if opcode == OP_COMPRESSED:
                expanded = uncompress_message(raw)
                if expanded is None:
                    print("  voyd: WARNING: compressed message this proxy "
                          "cannot read, forwarded unchecked", flush=True)
                    await conv.to_client(raw)
                    continue
                raw, opcode = expanded, OP_MSG
            if opcode != OP_MSG:
                await conv.to_client(raw)
                continue

            # This proxy's own mark lookup, answered. It is not the
            # client's reply and must never reach it.
            if source == "primary" and resp_to in conv.asked:
                future = conv.asked.get(resp_to)
                if future is not None and not future.done():
                    future.set_result(raw)
                continue

            if advertise and source == "primary":
                rebuilt = rewrite_topology(raw, req_id, resp_to, advertise)
                if rebuilt is not None:
                    await conv.to_client(rebuilt)
                    continue

            peek = decode_op_msg(raw, LAZY)
            if peek is not None:
                if upstream is not None and source == "primary":
                    why = stepped_down(dict(peek[1]))
                    if why:
                        upstream.invalidate(why)
                # Cursor affinity, recorded from the reply that opens the
                # cursor. A `getMore` sent anywhere else is asking a server
                # about a cursor it has never heard of.
                open_cursor = _cursor_id(peek[1])
                if open_cursor is not None:
                    conv.home[open_cursor] = source

            if source == "secondary":
                raw = await conv.permit(raw, req_id, resp_to)
                conv.sent_at.pop(resp_to, None)
            else:
                was_delete = resp_to in rewritten
                rewritten.discard(resp_to)
                raw = (delete_reply(raw, req_id, resp_to) if was_delete
                       else enforce(raw, req_id, resp_to, guards, verbose))
            await conv.to_client(raw)
    except Hangup:
        return "hangup"
    except ProtocolError as exc:
        print(f"  voyd: dropped a connection: {exc}", flush=True)
    except asyncio.CancelledError:
        raise
    except (ConnectionError, OSError):
        pass
    except Exception:
        traceback.print_exc()
    return "closed"


async def fanned_session(client_r, client_w, upstream: Upstream,
                         secondaries: Secondaries, guards, verbose: bool,
                         live: Live, advertise, meter) -> None:
    """One client connection when `--fan-out` is on.

    Deliberately a sibling of `session` rather than a mode inside it. The
    plain path is the one every deployment runs and the one the guarantee
    is argued from; it does not grow a routing table so that this can exist.
    """
    with live:
        try:
            up_r, up_w = await upstream.open()
        except (OSError, asyncio.TimeoutError) as exc:
            host, port, _ = upstream.address()
            print(f"voyd-wire: cannot reach {host}:{port}: {exc}", flush=True)
            upstream.invalidate(type(exc).__name__)
            await close(client_w)
            return

        conv = Conversation(client_w, up_w, guards, verbose, meter)
        conv.payoff = secondaries.payoff
        conv.fan_out_ok = secondaries.identity() is None
        rewritten: set[int] = set()
        tasks = [
            asyncio.ensure_future(route(client_r, conv, upstream, secondaries,
                                        guards, verbose, rewritten, meter)),
            asyncio.ensure_future(replies(up_r, conv, source="primary",
                                          guards=guards, verbose=verbose,
                                          rewritten=rewritten,
                                          upstream=upstream,
                                          advertise=advertise, meter=meter)),
        ]
        secondary_task = None
        try:
            while True:
                done, _ = await asyncio.wait(
                    tasks + ([secondary_task] if secondary_task else []),
                    return_when=asyncio.FIRST_COMPLETED, timeout=0.05)
                # The secondary is opened lazily by `route`, so its reply
                # pump cannot be started up front. Noticing it here keeps
                # the ownership of every task in one place, which is what
                # makes the teardown below complete.
                if secondary_task is None and conv.secondary_r is not None:
                    secondary_task = asyncio.ensure_future(
                        replies(conv.secondary_r, conv, source="secondary",
                                guards=guards, verbose=verbose,
                                rewritten=rewritten, upstream=None,
                                advertise=None, meter=meter))
                    continue
                if done:
                    break
        finally:
            everything = tasks + ([secondary_task] if secondary_task else [])
            for task in everything:
                task.cancel()
            await asyncio.gather(*everything, return_exceptions=True)
            if conv.secondary_w is not None:
                await close(conv.secondary_w)
            await close(up_w)
            await close(client_w)


async def close(writer: asyncio.StreamWriter) -> None:
    """Close a stream and do not care how it goes.

    A peer that already vanished makes this raise, and a teardown path that
    raises is how a clean disconnect ends up printing a stack trace and
    making a working proxy look broken.
    """
    try:
        writer.close()
        await writer.wait_closed()
    except (OSError, ConnectionError, ssl.SSLError):
        pass


def tally(guards: dict[str, Guard]) -> dict:
    """What one process actually did, as data rather than as a print.

    Separated from the printing because with `--workers` the counters live
    in N address spaces and the number a human should read is the sum. A
    summary printed per worker is not a summary, it is N partial ones that
    each look like the whole -- and undercounting a refusal tally is the
    specific way this tool would lie about the thing it exists to prove.
    """
    reasons: dict[str, int] = {}
    for g in guards.values():
        for reason, n in g.reasons().items():
            reasons[reason] = reasons.get(reason, 0) + n
    return {"served": sum(g.admitted for g in guards.values()),
            "refused": sum(g.refused for g in guards.values()),
            "revoked": sum(g.revoked for g in guards.values()),
            "reasons": reasons}


def merge(tallies: list[dict]) -> dict:
    """N workers' counts, added up."""
    total = {"served": 0, "refused": 0, "revoked": 0, "reasons": {}}
    for one in tallies:
        for key in ("served", "refused", "revoked"):
            total[key] += one.get(key, 0)
        for reason, n in (one.get("reasons") or {}).items():
            total["reasons"][reason] = total["reasons"].get(reason, 0) + n
    return total


def summarise(counts: dict | dict[str, Guard]) -> None:
    """What this boundary actually did. A guarantee nobody counted is a
    claim about one."""
    if counts and all(isinstance(v, Guard) for v in counts.values()):
        counts = tally(counts)          # type: ignore[arg-type]
    served = counts.get("served", 0)
    refused = counts.get("refused", 0)
    revoked = counts.get("revoked", 0)
    reasons = counts.get("reasons") or {}
    print(f"voyd-wire: served {served}, refused {refused} {reasons or '{}'}, "
          f"turned {revoked} delete(s) into revocations", flush=True)
    print("voyd-wire: documents deleted by this process: 0", flush=True)


def serve(listen_port: int, target: str, guards: dict[str, Guard],
          verbose: bool, *, certfile: str | None = None,
          keyfile: str | None = None, max_connections: int = 200,
          drain_seconds: float = 20.0, advertise: str | None = None,
          workers: int = 1, metrics_port: int | None = None,
          fan_out: str | None = None, give_up: float = 1.0) -> None:
    """Bind, announce, then run the boundary -- in this process or N of them.

    The listening socket is bound *here*, once, before any fork. That is
    what makes a port already in use an error at startup rather than N
    identical errors from children a moment later, and it is what lets the
    workers share one accept queue without `SO_REUSEPORT`: the kernel hands
    each connection to exactly one of them.
    """
    sock, ssl_ctx = listener(listen_port, certfile, keyfile)

    where = "0.0.0.0" if certfile else "127.0.0.1"
    print(f"voyd-wire: listening on {where}:{listen_port}"
          + (" (TLS)" if certfile else " (plaintext, loopback only)")
          + f" -> {target.split('@')[-1].split('/')[0]}", flush=True)
    for name, g in sorted(guards.items()):
        print(f"voyd-wire: guarding {name}: {g.spec.describe()}"
              + (", delete -> revoke" if g.on_delete == "revoke" else ""),
              flush=True)
    print(f"voyd-wire: up to {max_connections} concurrent connections"
          + (f" per worker, {workers} workers "
             f"({max_connections * workers} total)" if workers > 1 else ""),
          flush=True)
    if advertise:
        print(f"voyd-wire: advertising itself as {advertise}; clients stay "
              f"here rather than following the cluster's own host list",
              flush=True)
    else:
        print("voyd-wire: NOT rewriting topology -- clients must pass "
              "directConnection=true or they will walk past this boundary",
              flush=True)
    print("voyd-wire: connect any driver to "
          f"mongodb{'+tls' if certfile else ''}://localhost:{listen_port}/"
          "?directConnection=true\n", flush=True)

    # The slab is allocated *before* the fork so every worker inherits the
    # same pages. There is no way to add one afterwards, which is why this
    # happens here and not lazily on the first scrape.
    slab = meters = None
    if metrics_port is not None:
        layout = voyd_metrics.Layout(tuple(guards))
        slab = voyd_metrics.Slab(workers, layout)
        meters = [voyd_metrics.Meter(layout, slab, i) for i in range(workers)]
        print(f"voyd-wire: metrics on http://127.0.0.1:{metrics_port}/metrics"
              f" (loopback only, always)", flush=True)

    if workers > 1:
        supervise(sock, workers, target, guards, verbose,
                  ssl_ctx=ssl_ctx, max_connections=max_connections,
                  drain_seconds=drain_seconds, advertise=advertise,
                  slab=slab, meters=meters, metrics_port=metrics_port,
                  fan_out=fan_out, give_up=give_up)
        return

    if slab is not None and metrics_port is not None:
        voyd_metrics.serve(metrics_port, slab)
    counts = asyncio.run(_run(sock, ssl_ctx, target, guards, verbose,
                              max_connections=max_connections,
                              drain_seconds=drain_seconds,
                              advertise=advertise, fan_out=fan_out,
                              give_up=give_up,
                              meter=meters[0] if meters else None))
    summarise(counts)


async def _run(sock: socket.socket, ssl_ctx: "ssl.SSLContext | None",
               target: str, guards: dict[str, Guard], verbose: bool, *,
               max_connections: int, drain_seconds: float,
               advertise: str | None, fan_out: str | None = None,
               give_up: float = 1.0,
               meter: "voyd_metrics.Meter | None" = None) -> dict:
    """One worker: accept, serve, drain, and report what it counted."""
    upstream = Upstream(target, verbose=verbose, meter=meter)
    secondaries = (Secondaries(fan_out, verbose=verbose, meter=meter,
                               give_up=give_up)
                   if fan_out else None)
    live = Live()
    stopping = asyncio.Event()

    async def flushing() -> None:
        """Copy this worker's counters into shared memory, once a second.

        On the timer rather than on the message path: refusal costs about
        2.3us per document and a shared-memory write per document would be
        a measurable tax on the number being reported. One second is finer
        than any scrape interval anybody configures, and the exposition
        publishes its own staleness so the tradeoff is visible rather than
        assumed.
        """
        while not stopping.is_set():
            meter.connections_open = live.count
            meter.connections_total = live.total
            meter.flush(guards)
            try:
                await asyncio.wait_for(stopping.wait(), timeout=1.0)
            except asyncio.TimeoutError:
                pass
        meter.connections_open = live.count
        meter.connections_total = live.total
        meter.flush(guards)          # a last one, so a drain is visible

    flusher = (asyncio.ensure_future(flushing()) if meter is not None
               else None)

    async def handle(reader: asyncio.StreamReader,
                     writer: asyncio.StreamWriter) -> None:
        raw_sock = writer.get_extra_info("socket")
        if raw_sock is not None:
            keepalive(raw_sock)
        if live.count >= max_connections:
            # Closing beats queueing: a driver retries, and an unbounded
            # backlog is how a proxy turns a busy minute into an outage.
            print("voyd-wire: at the connection limit; refused one",
                  flush=True)
            if meter is not None:
                meter.connections_refused_total += 1
            await close(writer)
            return
        if secondaries is not None:
            await fanned_session(reader, writer, upstream, secondaries,
                                 guards, verbose, live, advertise, meter)
        else:
            await session(reader, writer, upstream, guards, verbose, live,
                          advertise, meter)

    # A failed TLS handshake, a port scan, a plain-TCP probe against a TLS
    # listener: one client's problem, never the listener's. An earlier
    # version caught `ssl.SSLError` -- which subclasses `OSError` -- in the
    # shutdown branch and re-raised, killing the listener for everybody
    # because one client spoke the wrong protocol. `start_server` isolates
    # this per connection, and the handler below keeps it that way.
    def mishap(loop, context):
        exc = context.get("exception")
        if isinstance(exc, (ssl.SSLError, ConnectionError, OSError)):
            print(f"voyd-wire: rejected a connection: "
                  f"{type(exc).__name__}: {exc}", flush=True)
            return
        loop.default_exception_handler(context)

    loop = asyncio.get_running_loop()
    loop.set_exception_handler(mishap)

    server = await asyncio.start_server(handle, sock=sock, ssl=ssl_ctx)

    def drain() -> None:
        """Stop accepting, let existing connections finish, then report.

        A proxy killed mid-flight drops whatever was in the air, and the
        client sees a connection reset rather than an answer. Draining
        costs a few seconds and turns a deploy into a non-event.
        """
        if stopping.is_set():
            os._exit(1)                  # second signal: they mean it
        stopping.set()
        print("\nvoyd-wire: draining; not accepting new connections",
              flush=True)

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, drain)
        except (ValueError, NotImplementedError):
            pass                         # not the main thread, or not POSIX

    async with server:
        await stopping.wait()

    server.close()
    try:
        await server.wait_closed()
    except (OSError, ConnectionError):
        pass

    # Wait for the connections that were already open. Bounded, because a
    # client holding a cursor open forever must not hold up a deploy.
    #
    # A plain counter rather than draining a semaphore: acquiring N slots
    # to prove nobody holds one leaks every slot acquired before the first
    # failure, so the check could never succeed and every shutdown burned
    # the full timeout looking patient.
    deadline = time.monotonic() + drain_seconds
    while time.monotonic() < deadline and live.count:
        await asyncio.sleep(0.05)
    if live.count:
        print(f"voyd-wire: {live.count} connection(s) still open after "
              f"{drain_seconds}s; closing anyway", flush=True)
    if flusher is not None:
        await asyncio.gather(flusher, return_exceptions=True)
    return tally(guards)


def supervise(sock: socket.socket, workers: int, target: str,
              guards: dict[str, Guard], verbose: bool, *,
              ssl_ctx: "ssl.SSLContext | None", max_connections: int,
              drain_seconds: float, advertise: str | None,
              slab: "voyd_metrics.Slab | None" = None,
              meters: "list[voyd_metrics.Meter] | None" = None,
              metrics_port: int | None = None,
              fan_out: str | None = None, give_up: float = 1.0) -> None:
    """N worker processes over one listening socket, and one honest total.

    Why processes at all, when the loop already removed the thread stacks:
    the per-connection CPU here is BSON decode in `decode_sections` and
    `enforce`, and that is the one cost an event loop cannot spread. A
    single loop saturates one core and then queues. Workers are how the
    other cores get used.

    Why `fork` and not `multiprocessing`: the guards are live `Admission`
    handles built from a policy file, and the default start method on macOS
    is spawn, which would pickle them or re-read the file. Forking inherits
    the objects that were already validated at startup, so every worker is
    enforcing provably the same policy rather than its own re-parse of it.

    Each child writes its tally back through a pipe before exiting. The
    parent adds them up and prints once -- see `tally` for why N partial
    summaries would be worse than none.
    """
    stopping = False
    slots: dict[int, tuple[int, int]] = {}       # index -> (pid, read fd)
    tallies: list[dict] = []

    def spawn(index: int) -> None:
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            # Leave the parent's process group. A terminal sends `SIGINT`
            # to the whole foreground group, so a child that stayed in it
            # got the interrupt twice -- once from the tty and once
            # forwarded by the parent -- and the second signal is the one
            # that means "they mean it" and exits immediately. Both
            # workers therefore died mid-drain without reporting, and the
            # totals silently undercounted by everything they had served.
            # Measured, not theorised: Ctrl-C lost both tallies.
            #
            # One signal path, from the parent, is the fix. It is also
            # what containers already do -- `docker stop` and Kubernetes
            # signal PID 1 alone, never the group.
            try:
                os.setpgrp()
            except OSError:
                pass
            code = 0
            try:
                counts = asyncio.run(_run(
                    sock, ssl_ctx, target, guards, verbose,
                    max_connections=max_connections,
                    drain_seconds=drain_seconds, advertise=advertise,
                    fan_out=fan_out, give_up=give_up,
                    meter=meters[index] if meters else None))
            except BaseException:
                traceback.print_exc()
                counts, code = tally(guards), 1
            try:
                with os.fdopen(write_fd, "w") as out:
                    json.dump(counts, out)
            except OSError:
                pass
            # `_exit`, not `sys.exit`: a forked child must not run the
            # parent's atexit handlers or flush its buffers a second time.
            os._exit(code)
        os.close(write_fd)
        slots[index] = (pid, read_fd)

    def collect(index: int) -> bool:
        """Read a dead worker's tally. True if it managed to leave one."""
        _pid, read_fd = slots.pop(index)
        try:
            with os.fdopen(read_fd) as incoming:
                blob = incoming.read()
            tallies.append(json.loads(blob))
            return True
        except (ValueError, OSError):
            return False

    for index in range(workers):
        spawn(index)

    # The parent keeps the listening socket open, and must. An earlier
    # version closed it here on the reasoning that a process which never
    # calls `accept` has no business holding a listener -- which is wrong
    # twice. A listening socket's accept queue belongs to the socket, not
    # to a process, so holding the fd steals nothing from the workers.
    # And closing it meant every *replacement* worker inherited a closed
    # fd and died at once: one `SIGKILL` produced four restarts in two
    # seconds, a crash loop manufactured by the supervisor that was
    # supposed to be recovering from one. Found by killing a worker and
    # reading `voyd_worker_restarts_total`, which said 4 where it should
    # have said 1.

    # Metrics are served from the parent, which is the only process that
    # can see every worker's slot. It is also the process with no event
    # loop and nothing else to do, so a slow scrape costs nothing that was
    # going to refuse a document.
    if slab is not None and metrics_port is not None:
        voyd_metrics.serve(metrics_port, slab)

    def forward(signum, _frame):
        nonlocal stopping
        stopping = True
        for pid, _fd in list(slots.values()):
            try:
                os.kill(pid, signum)
            except ProcessLookupError:
                pass

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, forward)
        except ValueError:
            pass

    # ------------------------------------------------------------------
    # Supervision. Without this the parent slept until shutdown, and a
    # worker killed mid-run was simply gone: capacity dropped by its
    # share, `voyd_workers` went on reporting the number asked for, and
    # nothing anywhere said so. Measured -- `SIGKILL` on one of three left
    # two serving, the metric still reading 3, and no log line at all.
    # ------------------------------------------------------------------
    started = dict.fromkeys(slots, time.monotonic())
    backoff = 0.0
    while not stopping and slots:
        try:
            dead, status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            break
        if dead == 0:
            time.sleep(0.2)
            continue
        index = next((i for i, (pid, _fd) in slots.items() if pid == dead),
                     None)
        if index is None:
            continue
        left_a_tally = collect(index)
        if slab is not None:
            slab.set_header(workers_live=len(slots))
        why = (f"signal {os.WTERMSIG(status)}" if os.WIFSIGNALED(status)
               else f"status {os.WEXITSTATUS(status)}")
        if stopping:
            break
        print(f"voyd-wire: worker {dead} (slot {index}) died with {why}"
              + ("" if left_a_tally else ", losing its counts")
              + "; replacing it", flush=True)
        if slab is not None:
            # Its counters go with it. Leaving them would add a dead
            # worker's totals to its replacement's, and a counter that
            # double counts across a restart is one nobody can reason
            # about. `worker_restarts_total` marks the discontinuity.
            slab.clear(index)
            slab.bump("worker_restarts_total")
        # A worker that dies immediately is a crash loop, and respawning
        # it flat out would spin a core producing log lines. Back off, but
        # never give up: the other workers are still serving, and a
        # boundary that shuts itself down because one worker is unhappy
        # has turned a degradation into an outage.
        if time.monotonic() - started.get(index, 0) < 1.0:
            backoff = min(backoff * 2 or 0.25, 5.0)
            time.sleep(backoff)
        else:
            backoff = 0.0
        spawn(index)
        started[index] = time.monotonic()
        if slab is not None:
            slab.set_header(workers_live=len(slots))

    # Shutdown. Everything still alive was signalled by `forward`.
    for index in list(slots):
        pid, _fd = slots[index]
        collect(index)
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
    if slab is not None:
        slab.set_header(workers_live=0)
    missing = workers - len(tallies)
    if missing > 0:
        # A worker that died without reporting is worth saying out loud:
        # the total below is missing its share, and a silently low refusal
        # count is the one number here that must never be quietly wrong.
        print(f"voyd-wire: {missing} worker(s) exited without a tally; the "
              f"totals below undercount by their share", flush=True)
    summarise(merge(tallies))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--listen", type=int, default=27099, help="local port")
    ap.add_argument("--target", default="localhost:27017",
                    help="the database this fronts: `host:port`, or a full "
                         "MongoDB URI. A `mongodb+srv://` URI is resolved "
                         "through DNS and connected over TLS, which is what "
                         "Atlas requires")
    ap.add_argument("--config", metavar="VOYDFILE",
                    help="a policy file declaring the rules per collection "
                         "(see voyd.declare). This is the whole of what you "
                         "write, and it is not in your application")
    ap.add_argument("--guard", action="append", default=[], metavar="COLLECTION",
                    help="a collection whose reads are admitted; repeatable. "
                         "Collections not named here are forwarded untouched, "
                         "which is stated rather than implied: this refuses "
                         "what it was told to refuse")
    ap.add_argument("--at-field", default="expire_at")
    ap.add_argument("--mark-field", default="forgotten")
    ap.add_argument("--tls-cert", metavar="PEM",
                    help="terminate TLS from clients with this certificate. "
                         "Without it the listener binds loopback only, "
                         "because a plaintext boundary reachable from the "
                         "network would carry in the clear every document it "
                         "just refused to serve")
    ap.add_argument("--tls-key", metavar="PEM",
                    help="the private key for --tls-cert, if it is not in "
                         "the same file")
    ap.add_argument("--advertise", metavar="HOST:PORT", default=None,
                    help="rewrite `hello` so clients see this address "
                         "instead of the cluster's own hosts. Without it a "
                         "driver that does not pass directConnection=true "
                         "reads the real host list and connects past this "
                         "boundary entirely. Defaults to localhost:<listen> "
                         "when --advertise-self is given")
    ap.add_argument("--fan-out", metavar="URI", default=None,
                    help="rank reads on this deployment's secondaries "
                         "instead of the primary, re-reading each guarded "
                         "batch's marks from the primary before releasing "
                         "it. Takes a URI of its own because a secondary "
                         "connection cannot replay the client's "
                         "authentication; reads served this way run as that "
                         "URI's identity, and fan-out switches itself off "
                         "for any connection whose client authenticated as "
                         "somebody else. See LIMITS.md \u00a73")
    ap.add_argument("--fan-out-give-up", metavar="RATIO", type=float,
                    default=1.0,
                    help="stop ranking a collection on a secondary once "
                         "confirming its marks on the primary costs this "
                         "much of what the ranking saved (default 1.0: "
                         "give up when the check costs as much as the read "
                         "it was checking). 0 never gives up -- the "
                         "measurement still runs and still reports")
    ap.add_argument("--advertise-self", action="store_true",
                    help="shorthand for --advertise localhost:<listen>")
    ap.add_argument("--max-connections", type=int, default=200, metavar="N",
                    help="concurrent client connections; further ones are "
                         "closed rather than queued, because a driver "
                         "retries and an unbounded backlog turns a busy "
                         "minute into an outage")
    ap.add_argument("--workers", type=int, default=1, metavar="N",
                    help="worker processes sharing the listening socket. "
                         "The event loop makes a connection cheap but "
                         "cannot spread BSON decoding across cores, so "
                         "this is the knob that does. Counters are summed "
                         "across workers and reported once on shutdown")
    ap.add_argument("--metrics", type=int, metavar="PORT", default=None,
                    help="serve Prometheus metrics on this port. Always "
                         "loopback, with no flag to change it: a refusal "
                         "count broken down by reason describes what a "
                         "corpus holds and who has been probing it")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    if not args.config and not args.guard:
        print("voyd-wire: give it --config voydfile.py, or --guard naming at "
              "least one collection. With neither, this process is a plain "
              "TCP relay pretending to be a boundary", file=sys.stderr)
        return 2

    guards: dict[str, Guard] = {}
    if args.config:
        try:
            for collection, spec in load(args.config).items():
                guards[collection] = Guard(
                    spec, **OPTIONS.get(collection, {}))
        except Exception as exc:
            # A policy file that is wrong must fail here, loudly, rather than
            # at the first query. Starting a boundary from a broken
            # declaration is how you get a door that is ajar.
            print(f"voyd-wire: {args.config}: {exc}", file=sys.stderr)
            return 2
    for c in args.guard:
        guards.setdefault(c, Guard.defaults(
            c, at_field=args.at_field, mark_field=args.mark_field))
    try:
        if args.tls_key and not args.tls_cert:
            print("voyd-wire: --tls-key needs --tls-cert", file=sys.stderr)
            return 2
        advertise = args.advertise
        if args.advertise_self and not advertise:
            advertise = f"localhost:{args.listen}"
        if args.workers < 1:
            print("voyd-wire: --workers must be at least 1", file=sys.stderr)
            return 2
        if args.workers > 1 and not hasattr(os, "fork"):
            print("voyd-wire: --workers needs fork(); this platform has "
                  "none, so run one process per port behind a balancer",
                  file=sys.stderr)
            return 2
        serve(args.listen, args.target, guards, not args.quiet,
              certfile=args.tls_cert, keyfile=args.tls_key,
              max_connections=args.max_connections, advertise=advertise,
              workers=args.workers, metrics_port=args.metrics,
              fan_out=args.fan_out, give_up=args.fan_out_give_up)
    except KeyboardInterrupt:
        summarise(guards)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
