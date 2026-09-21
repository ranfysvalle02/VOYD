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
it still is not: a driver. It does not load-balance reads, honour read
preference, retry a write the client already saw fail, or pool upstream
connections -- that last one deliberately, because a MongoDB connection
carries authentication, sessions, cursors and transactions, and sharing one
would hand a cursor to whoever asked second.

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

try:
    import bson
except ImportError:  # pragma: no cover - the one dependency, and it is pymongo's
    sys.exit("pip install pymongo   (for the bson library)")

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
        msg_len, req_id, resp_to, opcode = frame(hdr)
        body = await reader.readexactly(msg_len - HEADER)
    except asyncio.IncompleteReadError as exc:
        raise ConnectionError("disconnected") from exc
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


def decode_op_msg(raw: bytes) -> tuple[int, dict] | None:
    """The flags and the body document of a kind-0 OP_MSG.

    Returns ``None`` for anything else -- a document sequence (kind 1), a
    body we cannot parse. Those are forwarded untouched, which is safe here
    because a *reply* carrying a cursor batch is always a kind-0 body.
    """
    payload = raw[16:]
    if len(payload) < 5:
        return None
    flags = struct.unpack("<I", payload[:4])[0]
    if payload[4] != 0:
        return None
    end = len(payload) - (4 if flags & FLAG_CHECKSUM else 0)
    try:
        return flags, bson.decode(payload[5:end])
    except Exception:
        return None


def encode_op_msg(req_id: int, resp_to: int, flags: int, doc: dict) -> bytes:
    """Re-frame a body document as an OP_MSG, checksum bit cleared."""
    body = bson.encode(doc)
    payload = struct.pack("<I", flags & ~FLAG_CHECKSUM) + b"\x00" + body
    return struct.pack("<iiiI", 16 + len(payload), req_id, resp_to,
                       OP_MSG) + payload


# --------------------------------------------------------------------------
# The two legs. Only one of them rewrites anything.
# --------------------------------------------------------------------------

def _collection_of(reply: dict) -> str | None:
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
    """
    decoded = decode_op_msg(raw)
    if decoded is None:
        return raw
    flags, reply = decoded
    cursor = reply.get("cursor")
    if not isinstance(cursor, dict):
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

    kept = guard.filter(batch)
    if len(kept) == len(batch):
        return raw                      # nothing refused: do not touch the bytes

    reply = dict(reply)
    reply["cursor"] = dict(cursor)
    reply["cursor"][key] = kept
    if verbose:
        print(f"  voyd: {collection}: refused {len(batch) - len(kept)} of "
              f"{len(batch)}  {guard.reasons()}", flush=True)
    return encode_op_msg(req_id, resp_to, flags, reply)


async def pump(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
               back: asyncio.StreamWriter, *, to_server: bool,
               guards: dict[str, Guard], verbose: bool,
               rewritten: set[int],
               upstream: Upstream | None = None,
               advertise: str | None = None) -> None:
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

    def __init__(self, target: str, *, verbose: bool = True):
        self.target = target
        self.verbose = verbose
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
        self._lock = threading.Lock()

    def __enter__(self):
        with self._lock:
            self.count += 1
        return self

    def __exit__(self, *_exc) -> None:
        with self._lock:
            self.count -= 1


async def session(client_r: asyncio.StreamReader, client_w: asyncio.StreamWriter,
                  upstream: Upstream, guards: dict[str, Guard], verbose: bool,
                  live: Live, advertise: str | None = None) -> None:
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
                  "advertise": advertise}
        tasks = [
            asyncio.ensure_future(pump(client_r, up_w, client_w,
                                       to_server=True, **common)),
            asyncio.ensure_future(pump(up_r, client_w, up_w,
                                       to_server=False, **common)),
        ]
        try:
            # Either direction ending ends the connection: a client that
            # hung up has no reply to receive, and an upstream that closed
            # has nothing more to say. Waiting for both instead would hold
            # a slot open on the half-closed socket until keepalive
            # noticed, which is minutes.
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in tasks:
                task.cancel()
            # Both have to actually finish before the slot is released, or
            # a burst of short-lived clients reports a connection count
            # with nothing to do with the sockets actually open.
            await asyncio.gather(*tasks, return_exceptions=True)
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
          workers: int = 1) -> None:
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

    if workers > 1:
        supervise(sock, workers, target, guards, verbose,
                  ssl_ctx=ssl_ctx, max_connections=max_connections,
                  drain_seconds=drain_seconds, advertise=advertise)
        return

    counts = asyncio.run(_run(sock, ssl_ctx, target, guards, verbose,
                              max_connections=max_connections,
                              drain_seconds=drain_seconds,
                              advertise=advertise))
    summarise(counts)


async def _run(sock: socket.socket, ssl_ctx: "ssl.SSLContext | None",
               target: str, guards: dict[str, Guard], verbose: bool, *,
               max_connections: int, drain_seconds: float,
               advertise: str | None) -> dict:
    """One worker: accept, serve, drain, and report what it counted."""
    upstream = Upstream(target, verbose=verbose)
    live = Live()
    stopping = asyncio.Event()

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
            await close(writer)
            return
        await session(reader, writer, upstream, guards, verbose, live,
                      advertise)

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
    return tally(guards)


def supervise(sock: socket.socket, workers: int, target: str,
              guards: dict[str, Guard], verbose: bool, *,
              ssl_ctx: "ssl.SSLContext | None", max_connections: int,
              drain_seconds: float, advertise: str | None) -> None:
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
    children: list[tuple[int, int]] = []          # (pid, read fd)
    for _ in range(workers):
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
                    drain_seconds=drain_seconds, advertise=advertise))
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
        children.append((pid, read_fd))

    # The parent holds no connections, so it must not hold the socket
    # either -- an accept queue with a listener that never accepts is a
    # client hanging for no reason.
    sock.close()

    def forward(signum, _frame):
        for pid, _fd in children:
            try:
                os.kill(pid, signum)
            except ProcessLookupError:
                pass

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, forward)
        except ValueError:
            pass

    tallies: list[dict] = []
    for pid, read_fd in children:
        with os.fdopen(read_fd) as incoming:
            blob = incoming.read()
        try:
            tallies.append(json.loads(blob))
        except ValueError:
            # A worker that died without reporting is worth saying out
            # loud: the total below is now missing its share, and a
            # silently low refusal count is the one number here that must
            # never be quietly wrong.
            print(f"voyd-wire: worker {pid} exited without a tally; the "
                  f"totals below undercount by its share", flush=True)
        os.waitpid(pid, 0)
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
              workers=args.workers)
    except KeyboardInterrupt:
        summarise(guards)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
