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
package surface. It is not a production proxy: no TLS termination, no
connection pooling, no auth passthrough beyond what the client sends, one
thread per direction, and receipts shared across connections. A real one is a
different project and probably not written in Python. The point it makes is
architectural, and it makes it in about three hundred lines.

The wire framing -- header layout, OP_MSG sections, OP_COMPRESSED -- is lifted
from `tools/wire_proxy.py` in the author's `mdb-embedded` repository, MIT to
MIT. That file logs traffic; this one rewrites it.
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
import threading
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


def read_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("disconnected")
        buf += chunk
    return buf


def read_message(sock: socket.socket) -> tuple[bytes, int, int, int, int]:
    hdr = read_exact(sock, 16)
    msg_len, req_id, resp_to, opcode = struct.unpack("<iiiI", hdr)
    return hdr + read_exact(sock, msg_len - 16), msg_len, req_id, resp_to, opcode


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


def pump(src: socket.socket, dst: socket.socket, *, to_server: bool,
         guards: dict[str, Guard], verbose: bool,
         rewritten: set[int], lock: threading.Lock,
         upstream: Upstream | None = None,
         finished: threading.Semaphore | None = None) -> None:
    """One direction of one connection.

    ``rewritten`` is shared between the two directions and is the only state
    they share: a request id whose ``delete`` was turned into an ``update``
    has to be recognised again when its reply comes back the other way. It is
    per-connection, because request ids are.
    """
    try:
        while True:
            raw, _len, req_id, resp_to, opcode = read_message(src)
            if opcode == OP_COMPRESSED:
                expanded = uncompress_message(raw)
                if expanded is None:
                    # Unreadable rather than empty. Say so and forward: a
                    # silent pass-through would be a boundary reporting
                    # nothing because it saw nothing, which is the exact
                    # failure this tool exists to make impossible.
                    print("  voyd: WARNING: compressed message this proxy "
                          "cannot read, forwarded unchecked", flush=True)
                    dst.sendall(raw)
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
                    src.sendall(refusal)
                    continue

                target = guards.get(body.get("delete"))
                if target is not None and target.on_delete == "revoke":
                    swapped = revoke_instead_of_delete(
                        raw, req_id, resp_to, target, verbose)
                    if swapped is not None:
                        raw = swapped
                        with lock:
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
                with lock:
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
            dst.sendall(raw)
    except (ConnectionError, OSError):
        # A closed socket is how a client disconnects, and both directions
        # notice. `OSError` is here beside `ConnectionError` because the
        # *other* pump closing these sockets first surfaces as EBADF, not as
        # a connection error -- which printed a stack trace on every clean
        # exit and made a working proxy look broken.
        pass
    except Exception:
        traceback.print_exc()
    finally:
        for sock in (src, dst):
            try:
                sock.close()
            except OSError:
                pass
        if finished is not None:
            finished.release()


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
        sock.settimeout(None)
        if not tls:
            return sock
        import ssl
        ctx = ssl.create_default_context()
        # `server_hostname` is what makes certificate validation mean
        # anything against a named cluster; without it this is an encrypted
        # channel to whoever answered.
        return ctx.wrap_socket(sock, server_hostname=host)


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


def listener(port: int, certfile: str | None,
             keyfile: str | None) -> socket.socket:
    """The socket clients reach, TLS-terminated when a certificate is given.

    Without one this binds loopback only, and that is a decision rather than
    a default: a plaintext boundary reachable from the network would carry
    every document it just refused to refuse, in the clear, to anybody on
    the path. With a certificate it binds all interfaces, because then it
    can be one.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0" if certfile else "127.0.0.1", port))
    sock.listen(64)
    if not certfile:
        return sock
    import ssl
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile, keyfile)
    return ctx.wrap_socket(sock, server_side=True)


def session(client: socket.socket, upstream: Upstream,
            guards: dict[str, Guard], verbose: bool,
            done: threading.Semaphore) -> None:
    """One client connection, start to finish, on one thread pair.

    A MongoDB connection is stateful -- authentication, sessions, cursors
    and transactions all bind to it -- so an upstream connection is *per
    client* rather than pooled. Sharing one would hand a cursor to whoever
    asked second, which is the concurrency bug this whole package exists to
    be careful about, committed by its own plumbing.

    What is bounded instead is how many there are at once. The semaphore is
    released exactly once, here, so a client that disconnects mid-handshake
    cannot leak a slot.
    """
    up = None
    try:
        up = upstream.connect()
    except OSError as exc:
        host, port, _ = upstream.address()
        print(f"voyd-wire: cannot reach {host}:{port}: {exc}", flush=True)
        # A connection failure is as good a reason to re-resolve as an
        # election: the node may simply be gone.
        upstream.invalidate(type(exc).__name__)
        client.close()
        done.release()
        return

    rewritten: set[int] = set()
    lock = threading.Lock()
    finished = threading.Semaphore(0)
    for src, dst, to_server in ((client, up, True), (up, client, False)):
        threading.Thread(
            target=pump, args=(src, dst),
            kwargs={"to_server": to_server, "guards": guards,
                    "verbose": verbose, "rewritten": rewritten, "lock": lock,
                    "upstream": upstream, "finished": finished},
            daemon=True).start()

    # Both directions have to end before the slot is free, or a burst of
    # short-lived clients would report a connection count that has nothing
    # to do with the sockets actually open.
    finished.acquire()
    finished.acquire()
    done.release()


def serve(listen_port: int, target: str, guards: dict[str, Guard],
          verbose: bool, *, certfile: str | None = None,
          keyfile: str | None = None, max_connections: int = 200) -> None:
    upstream = Upstream(target, verbose=verbose)
    server = listener(listen_port, certfile, keyfile)

    where = "0.0.0.0" if certfile else "127.0.0.1"
    print(f"voyd-wire: listening on {where}:{listen_port}"
          + (" (TLS)" if certfile else " (plaintext, loopback only)")
          + f" -> {target.split('@')[-1].split('/')[0]}", flush=True)
    for name, g in sorted(guards.items()):
        print(f"voyd-wire: guarding {name}: {g.spec.describe()}"
              + (", delete -> revoke" if g.on_delete == "revoke" else ""),
              flush=True)
    print(f"voyd-wire: up to {max_connections} concurrent connections",
          flush=True)
    print("voyd-wire: connect any driver to "
          f"mongodb{'+tls' if certfile else ''}://localhost:{listen_port}/"
          "?directConnection=true\n", flush=True)

    slots = threading.Semaphore(max_connections)
    while True:
        try:
            client, _ = server.accept()
        except OSError as exc:
            # A failed TLS handshake is one client's problem, not the
            # listener's. Refusing to keep serving because somebody sent
            # garbage would make this trivially deniable.
            print(f"voyd-wire: rejected a connection: {exc}", flush=True)
            continue
        if not slots.acquire(blocking=False):
            # Closing beats queueing: a driver retries, and an unbounded
            # backlog is how a proxy turns a busy minute into an outage.
            print("voyd-wire: at the connection limit; refused one",
                  flush=True)
            client.close()
            continue
        threading.Thread(target=session,
                         args=(client, upstream, guards, verbose, slots),
                         daemon=True).start()


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
    ap.add_argument("--max-connections", type=int, default=200, metavar="N",
                    help="concurrent client connections; further ones are "
                         "closed rather than queued, because a driver "
                         "retries and an unbounded backlog turns a busy "
                         "minute into an outage")
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
        serve(args.listen, args.target, guards, not args.quiet,
              certfile=args.tls_cert, keyfile=args.tls_key,
              max_connections=args.max_connections)
    except KeyboardInterrupt:
        refused = sum(g.refused for g in guards.values())
        revoked = sum(g.revoked for g in guards.values())
        served = sum(g.admitted for g in guards.values())
        print(f"\nvoyd-wire: {served} document(s) served, {refused} refused, "
              f"{revoked} delete(s) turned into revocations.")
        print("voyd-wire: documents deleted by this process: 0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
