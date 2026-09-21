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

from voyd.declare import load
from voyd.engine import Deadline, revoked
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

    def __init__(self, spec: AdmissionSpec):
        self.collection = spec.collection
        self.spec = spec
        self.handle = Admission(None, spec)
        self.refused = 0
        self.admitted = 0

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
         guards: dict[str, Guard], verbose: bool) -> None:
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
            if opcode == OP_MSG:
                raw = (strip_compression(raw, req_id, resp_to) if to_server
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


def serve(listen_port: int, target: str, guards: dict[str, Guard],
          verbose: bool) -> None:
    host, _, port = target.partition(":")
    target_addr = (host, int(port or 27017))

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", listen_port))
    server.listen(64)
    print(f"voyd-wire: listening on 127.0.0.1:{listen_port} -> "
          f"{target_addr[0]}:{target_addr[1]}")
    print(f"voyd-wire: guarding {', '.join(sorted(guards)) or '(nothing)'}")
    print("voyd-wire: connect any driver to "
          f"mongodb://localhost:{listen_port}/\n")

    while True:
        client, _ = server.accept()
        upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            upstream.connect(target_addr)
        except OSError as exc:
            print(f"voyd-wire: cannot reach {target}: {exc}")
            client.close()
            continue
        for src, dst, to_server in ((client, upstream, True),
                                    (upstream, client, False)):
            threading.Thread(target=pump, args=(src, dst),
                             kwargs={"to_server": to_server, "guards": guards,
                                     "verbose": verbose},
                             daemon=True).start()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--listen", type=int, default=27099, help="local port")
    ap.add_argument("--target", default="localhost:27017",
                    help="the mongod/Atlas this fronts (host:port)")
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
                guards[collection] = Guard(spec)
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
        serve(args.listen, args.target, guards, not args.quiet)
    except KeyboardInterrupt:
        total = sum(g.refused for g in guards.values())
        print(f"\nvoyd-wire: refused {total} document(s) this run")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
