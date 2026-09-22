#!/usr/bin/env python3
"""Transport and dispatch: sockets, connections, workers, and the CLI.

    # terminal 1 -- rules in a file that is not your application
    voyd-wire --config voydfile.py --target localhost:27018

    # terminal 2 -- any driver, any language
    mongosh mongodb://localhost:27099/demo

This file moves bytes and decides *where* they go. It decides nothing about
what a message is allowed to mean -- that is `policy.py`, all of it, so
"can this be bypassed?" is a question about one file. Framing and BSON are
`codec.py`. What is left here is the shell: accept a connection, open one
upstream, pump both directions, fork workers, drain on `SIGTERM`, parse the
arguments.

The boundary binds the **connection**, not a handle. There is no raw read
to guard -- not from Node, not from Compass, not from a notebook, not from
a shell that has never heard of VOYD -- because there is nothing to reach
past.

**Four connections of its own, named here rather than discovered.**
`--fan-out` opens secondary connections; `--key-vault` holds the vault;
`--ensure` connects with your credentials to *create* what the policy
declares, then closes before the listener binds; and a policy declaring
`lineage_field` opens one so a revocation can reach what was derived from
the fact. Everything else forwards your credentials and adds no round
trip, because the per-document check is pure. A property with an exception
nobody wrote down is not a property, which is this package's whole
complaint, so they are written down.

**What this is not: a driver.** It does not pool upstream connections, and
that one is deliberate -- a MongoDB connection carries authentication,
sessions, cursors and transactions, and sharing one would hand a cursor to
whoever asked second.

What does survive the crossing, measured rather than assumed: read
preference is honoured against a topology of one (the `*Preferred` modes
served by the primary, strict `secondary` a client-side error rather than
a quiet primary read), retryable writes stay armed because
`rewrite_topology` keeps `setName`, and sessions and transactions are
forwarded intact. `--fan-out` ranks reads on secondaries and re-reads
their marks from the primary before releasing them -- see `fanout.py` for
why the obvious version of that is unsafe.

**Concurrency is this file's problem and nobody else's.** Every function
in `policy.py` that rewrites bytes is `bytes -> bytes` and touches no
socket, because the check underneath it is pure. That is what made moving
from two OS threads per connection to one coroutine pair a change to the
shell and nothing else, and it is why the ceiling is upstream sockets
rather than thread stacks.

"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import socket
import ssl
import sys
import threading
import time
import traceback
from typing import Mapping, TypedDict


from . import cascade
from . import ensure
from . import fanout
from . import preflight
from . import seal
from . import metrics
from voyd.declare import OPTIONS, load
from .policy import (Budgets, Guard, _wants_a_caller, _was_reduced,
                     cascade_first, cascade_first_for_one, delete_reply,
                     derive_on_insert, erase_first, guard_for, judge,
                     refuse_client_vector, refuse_unrewritable,
                     revoke_instead_of_delete,
                     revoke_instead_of_find_and_delete, rewrite_derived_read,
                     rewrite_topology, seal_refusal, strip_compression,
                     unsuppliable_claims)

from .codec import (LAZY, OP_COMPRESSED, OP_MSG, Hangup, ProtocolError,
                    decode_op_msg, decode_sections, encode_op_msg,
                    encode_sections, read_message_async, uncompress_message)


async def _next_message(reader: asyncio.StreamReader,
                        draining: "asyncio.Event | None"):
    """The next message, or the shutdown that arrived while we waited.

    Racing the read against the drain is what makes a connection sitting
    idle between requests close *now* rather than in `drain_seconds`.
    Being blocked here is the definition of idle: nothing has been read,
    so nothing is half-forwarded, and closing costs the client nothing it
    was owed. A connection mid-request is not blocked here -- it is
    downstream waiting for a reply -- so it still gets the full drain.

    That distinction is the whole of a graceful shutdown, and it is the
    one every other proxy makes: finish what is in flight, hang up on
    what is idle. Without it a single connected `mongosh` held a deploy
    for the entire drain window, doing nothing.

    Racing means cancelling the loser. If the drain wins, the read may
    have consumed a partial header -- which does not matter, because the
    only thing that happens next is this connection closing.

    **A message already in the buffer wins even once the drain has
    fired**, which is why this races rather than checking `is_set()`
    first. The cheap version short-circuits on a set event and drops a
    request the client had already sent -- turning a graceful shutdown
    into a dropped request, in the function whose entire job is the
    opposite.
    """
    if draining is None:
        return await read_message_async(reader)
    read = asyncio.ensure_future(read_message_async(reader))
    stop = asyncio.ensure_future(draining.wait())
    try:
        done, _pending = await asyncio.wait(
            {read, stop}, return_when=asyncio.FIRST_COMPLETED)
        if read in done:
            return read.result()        # a real request wins a tie
        raise Hangup("drained while idle between requests")
    finally:
        for task in (read, stop):
            if not task.done():
                task.cancel()


class _Pump(TypedDict):
    """The state both directions of one connection share.

    Exists so `session` can hand `pump` the same eight things twice without
    the splat erasing their types. `total=True`: every key is required,
    which is the property worth having -- a direction started with one of
    these missing would enforce a different policy from its sibling, on the
    same connection, and nothing downstream would say so.
    """

    guards: dict[str, Guard]
    verbose: bool
    rewritten: set[int]
    upstream: "Upstream | None"
    advertise: str | None
    vault: "seal.Vault | None"
    embeds: Mapping | None
    meter: "metrics.Meter | None"
    # Shared by both directions, like `rewritten` and for the same reason:
    # the request side asks who this connection is, and the reply side is
    # the one that sees the answer come back. Not named `back` -- `pump`'s
    # third positional argument already is, and the splat would collide.
    back_channel: "Backchannel"
    who: "CallerIdentity"
    # Request ids whose refusal was pushed into the query, and the cursors
    # those requests opened. See `reduced` in `pump` for why a reply has to
    # remember this.
    reduced: set[int]
    reduced_cursors: set[int]
    budgets: Budgets
    draining: "asyncio.Event | None"


async def pump(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
               back: asyncio.StreamWriter, *, to_server: bool,
               guards: dict[str, Guard], verbose: bool,
               rewritten: set[int],
               upstream: Upstream | None = None,
               advertise: str | None = None,
               vault: "seal.Vault | None" = None,
               embeds: Mapping | None = None,
               meter: "metrics.Meter | None" = None,
               back_channel: "Backchannel | None" = None,
               who: "CallerIdentity | None" = None,
               reduced: set[int] | None = None,
               reduced_cursors: set[int] | None = None,
               budgets: "Budgets | None" = None,
               draining: "asyncio.Event | None" = None) -> str:
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
            raw, _len, req_id, resp_to, opcode = await _next_message(
                reader, draining if to_server else None)
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

                # Who is asking, established *before* the command goes
                # upstream, because the reply arrives on the other
                # direction and `enforce` is synchronous when it gets
                # there. Resolving it there would mean either blocking a
                # reply pump on a round trip or judging a batch without
                # the claims -- and the second one silently admits.
                #
                # Lazily, and only for a collection whose rules actually
                # ask: a policy with no caller-aware rule never pays the
                # round trip, and it is paid once per connection because
                # an authenticated connection cannot become somebody else.
                #
                # First, and that ordering is a bug this had: the
                # push-down below builds its `$match` out of these
                # claims, so resolving afterwards left every
                # caller-scoped reduction refused for want of an
                # identity the boundary already had the means to ask
                # for.
                if who is not None and _wants_a_caller(guards, body):
                    await who.resolve(verbose)

                # A destructive verb this boundary cannot express as a
                # revocation is answered here rather than forwarded: the
                # reply goes straight back and the server never sees it.
                refusal = refuse_unrewritable(raw, req_id, req_id, guards)
                if refusal is None and embeds:
                    refusal = refuse_client_vector(raw, req_id, req_id, embeds)
                if refusal is None:
                    # A reduction gets the refusal pushed into its query, or
                    # it gets an error. Never neither: see the note above
                    # `rewrite_derived_read` for why one call answers both.
                    pushed, refusal = rewrite_derived_read(
                        raw, req_id, resp_to, guards, verbose,
                        who.claims if who else None)
                    if pushed is not None:
                        raw = pushed
                        head = decode_sections(raw)
                        body = head[1] if head else body
                        # The rows were filtered by the server, and what
                        # comes back is a *reduction over* them -- a count,
                        # a group, a projection. Judging that reply per
                        # document would be asking the rules about
                        # documents that no longer exist, and one rule
                        # answers badly: `Restricted` refuses a document
                        # with no audience, because untagged is not public.
                        # A `$group` result has no audience, so the
                        # boundary filtered correctly server-side and then
                        # threw its own answer away. Measured as
                        # `count_documents() == 0` on a collection the same
                        # caller could `find()` two rows in.
                        if reduced is not None:
                            reduced.add(req_id)

                # A `getMore` continuing a reduced read is the same read.
                # Matched on the request, where the cursor id is still in
                # the message -- the reply that drains a cursor reports
                # `id: 0` and carries nothing to recognise it by.
                more = body.get("getMore")
                if (reduced is not None and reduced_cursors is not None
                        and isinstance(more, int)):
                    if more in reduced_cursors:
                        reduced.add(req_id)
                    # A client may also abandon it; `killCursors` is the
                    # other way this entry stops being needed.
                    if body.get("batchSize") == 0:
                        reduced_cursors.discard(more)
                # A cursor the client gives up on will never report `id: 0`,
                # so its running total would sit in `Budgets` for the life
                # of the connection. This is the other end of that lifecycle.
                if budgets is not None and "killCursors" in body:
                    budgets.forget(body.get("cursors"))
                if refusal is not None:
                    await send(back, refusal)
                    continue

                target = guard_for(guards, body, "delete")
                if target is not None and target.on_delete == "revoke":
                    # Children first. See `cascade_first` for why this
                    # order and not a transaction.
                    pins = await cascade_first(
                        raw, target, body.get("$db", ""), verbose)
                    swapped = revoke_instead_of_delete(
                        raw, req_id, resp_to, target, verbose, pins)
                    if swapped is not None:
                        raw = swapped
                        rewritten.add(req_id)

                # `findOneAndDelete` is a *different command*, and
                # intercepting one and not the other gave a team the
                # guarantee for one delete verb and silently not the other.
                fam = guard_for(guards, body, "findAndModify")
                if fam is not None and fam.on_delete == "revoke":
                    pin = await cascade_first_for_one(
                        raw, fam, body.get("$db", ""), verbose)
                    swapped = revoke_instead_of_find_and_delete(
                        raw, req_id, resp_to, fam, verbose, pin)
                    if swapped is not None:
                        raw = swapped

                # The write-side half of lineage. Before sealing, because
                # it rewrites the same documents the vault would encrypt
                # and reading a stale parse is the bug that combination
                # invites.
                raw, refused = await derive_on_insert(
                    raw, req_id, resp_to, guards, verbose)
                if refused is not None:
                    await send(back, refused)
                    continue

                # Sealing is last, and after a re-decode rather than on
                # the `head` above, because the two rewrites before it may
                # have replaced the message. Reading a stale parse here
                # would seal a command that is no longer the one being
                # sent, which is the kind of bug that only shows up on the
                # combination nobody ran.
                await erase_first(body, head[3] if head else [],
                                  guards, vault, verbose, meter)

                if vault is not None and vault.targets(body):
                    again = decode_sections(raw)
                    if again is not None:
                        before = vault.sealed_writes
                        try:
                            resealed = await vault.seal_command(
                                dict(again[1]), again[2], again[3])
                        except seal.SealError as exc:
                            if meter is not None:
                                meter.seal_refused_writes_total += 1
                            await send(back, seal_refusal(
                                req_id, req_id, str(exc)))
                            continue
                        if resealed is not None:
                            raw = encode_sections(req_id, resp_to, again[0],
                                                  *resealed)
                        if meter is not None:
                            meter.sealed_writes_total += (
                                vault.sealed_writes - before)
            elif opcode == OP_MSG:
                # This proxy's own question, answered. It is not the
                # client's reply and must never reach it -- forwarding one
                # hands a driver a response to a command it never sent,
                # which desynchronises the stream exactly like a wrong
                # `responseTo` does. First, so nothing below can rewrite,
                # judge or count a message the client is not owed.
                if back_channel is not None and back_channel.answer(resp_to,
                                                                    raw):
                    continue
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
                    # `reply`, not `head`: twenty lines up `head` holds a
                    # `decode_sections` 4-tuple and here it held a
                    # `decode_op_msg` 2-tuple. One name for two shapes in
                    # one function, distinguished only by which branch the
                    # reader is in -- and `head[1]` means the body in both,
                    # which is exactly the coincidence that keeps a reuse
                    # like this alive until the shapes diverge.
                    reply = decode_op_msg(raw)
                    if reply is not None:
                        why = stepped_down(reply[1])
                        if why:
                            upstream.invalidate(why)

                already = _was_reduced(raw, resp_to, reduced,
                                       reduced_cursors)
                if was_delete:
                    raw = delete_reply(raw, req_id, resp_to)
                elif not already:
                    raw = await judge(raw, req_id, resp_to, guards,
                                      verbose, vault, meter,
                                      who.claims if who else None, budgets)
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
        # Broad on purpose: a defect on one connection must not take the
        # listener with it. But a traceback goes to a log nobody alerts
        # on, so it is *counted* -- a proxy shedding one connection a
        # second otherwise looks healthy from outside, which is this
        # package's own complaint aimed at itself.
        if meter is not None:
            meter.connections_failed_total += 1
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
                 meter: "metrics.Meter | None" = None):
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
            probe: MongoClient = MongoClient(
                target, serverSelectionTimeoutMS=15000)
            with probe:
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
                 meter: "metrics.Meter | None" = None,
                 give_up: float = 1.0):
        self.uri = uri
        # Shared across every connection this worker serves. A per
        # connection sample would be a handful of reads on a short-lived
        # client, which is not enough to withdraw a collection on.
        self.payoff = fanout.Payoff(ratio=give_up)
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
            probe: MongoClient = MongoClient(
                self.uri, serverSelectionTimeoutMS=15000)
            with probe:
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
        # `p is not None` is not defensive noise: pymongo's address type is
        # `(host, port | None)`, and an entry with no port is not something
        # this proxy can open a socket to. Dropped and counted out of the
        # list rather than carried as a tuple that fails later, further
        # away, as a connection error.
        return [(h, p, tls) for h, p in found if p is not None]

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
        from pymongo.auth import (  # type: ignore[attr-defined,no-redef]
            _authenticate_scram)
    credentials = _build_credentials_tuple(
        mechanism, source, username, password, {}, source)
    try:
        # `shim` is not a pymongo `Connection` and is not pretending to be
        # one beyond the two methods SCRAM calls on it. That is the whole
        # design -- see `_AuthShim`: the client proof, the salting and the
        # server-signature check stay in the library, and what this file
        # supplies is a way to send a document and get one back. Ignored
        # rather than satisfied, because satisfying it means constructing a
        # real `Connection`, which means a real socket pool, which is the
        # thing being avoided.
        _authenticate_scram(credentials, shim, mechanism)  # type: ignore[arg-type]
    except Exception as exc:
        # Deliberately not the server's message: an authentication failure
        # reply can carry the mechanism and the user, and this line goes to
        # an operator's log.
        print(f"voyd-wire: could not authenticate to the secondary as "
              f"{username!r} ({type(exc).__name__}); reads stay on the "
              f"primary", flush=True)
        return False
    return True


def stepped_down(reply: Mapping) -> str | None:
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
                  vault: "seal.Vault | None" = None,
                  embeds: Mapping | None = None,
                  meter: "metrics.Meter | None" = None,
                  half_close_seconds: float = 10.0,
                  draining: "asyncio.Event | None" = None) -> None:
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
        # Annotated, because an unannotated dict splatted into `**kwargs`
        # is inferred as `dict[str, object]` and every one of `pump`'s eight
        # keyword arguments then fails to type-check -- sixteen of the
        # errors that kept this file unchecked came from these four lines.
        # A `TypedDict` costs one declaration and makes the splat as
        # checked as writing the arguments out twice would be, without
        # writing them out twice: the two directions of this connection must
        # be handed *identical* state or the boundary means different things
        # depending on which way a message is travelling.
        channel = Backchannel(up_w)
        common: _Pump = {"guards": guards, "verbose": verbose,
                         "rewritten": rewritten, "upstream": upstream,
                         "advertise": advertise, "vault": vault,
                         "embeds": embeds, "meter": meter,
                         "back_channel": channel,
                         "who": CallerIdentity(channel),
                         "reduced": set(), "reduced_cursors": set(),
                         "budgets": Budgets(), "draining": draining}
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



class Backchannel:
    """The boundary's own questions, asked on the client's own connection.

    Extracted from `Conversation`, which had the only copy, because the
    plain path -- the default, and the one most connections take -- needed
    the same primitive and a second spelling of "send a command and match
    its reply" is the drift this file keeps finding in itself.

    Why it is still not "a connection of its own": the socket, the
    authentication and the identity are all the client's. What is borrowed
    is a gap between its requests, which is also why every question asked
    here has to be one the client's own credentials are allowed to ask.
    """

    def __init__(self, primary_w: asyncio.StreamWriter | None = None):
        self.primary_w = primary_w
        self.asked: dict[int, asyncio.Future] = {}
        self._next = ASKED_BASE
        self.lock = asyncio.Lock()

    def answer(self, resp_to: int, raw: bytes) -> bool:
        """Resolve a pending question. True when the reply was *ours*.

        The return value is load-bearing: a caller that forwards on a
        `True` has just handed the client a reply to a command it never
        sent, which desynchronises the driver as surely as a wrong
        `responseTo` does.
        """
        future = self.asked.get(resp_to)
        if future is None:
            return False
        if not future.done():
            future.set_result(raw)
        return True

    async def ask(self, command: dict, timeout: float = 20.0) -> dict | None:
        """Run one command on the client's connection. `None` on any failure.

        `None` rather than an exception, and every caller treats it as "the
        question could not be answered" rather than as an answer. On the
        permission path that distinction is the whole guarantee: not
        knowing who is asking has to refuse, never admit.
        """
        if self.primary_w is None:
            return None
        self._next += 1
        req_id = self._next
        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()
        self.asked[req_id] = future
        try:
            async with self.lock:
                # One `write` per whole message, and that is load-bearing
                # rather than tidy. Two coroutines share this writer now --
                # the request pump forwarding the client, and this asking
                # its own question -- and what keeps their bytes from
                # interleaving is that each appends a complete message to
                # the buffer with no await inside. The `drain` below may
                # yield; by then the bytes are already ordered. Splitting
                # either write in two would corrupt the stream in a way
                # that looks like a driver bug.
                self.primary_w.write(encode_op_msg(req_id, 0, 0, command))
                await self.primary_w.drain()
            raw = await asyncio.wait_for(future, timeout)
        except (asyncio.TimeoutError, ConnectionError, OSError):
            return None
        finally:
            self.asked.pop(req_id, None)
        decoded = decode_op_msg(raw)
        return dict(decoded[1]) if decoded else None


class CallerIdentity:
    """Who the server says this connection authenticated as.

    **The claims come from the server, never from the client**, and that is
    not a preference. `for_caller` in `admission/core.py` says it outright:
    a handle that believed ``{"clearance": "secret"}`` because it was
    passed one "would be an authorisation system whose only input is the
    attacker's". A proxy is in an even worse position to trust the client,
    because the client is the only thing talking to it.

    So the question is put to the deployment. ``connectionStatus`` answered
    on this connection returns ``authenticatedUsers`` and
    ``authenticatedUserRoles`` -- the server's own account of who
    authenticated here, which the client cannot forge without forging the
    authentication itself.

    Asked once and cached, because it cannot change: a MongoDB connection
    authenticates and stays that identity. Asked *lazily*, on the first
    read against a collection whose rules need a caller, so a deployment
    that declares no such rule pays nothing at all.

    ``None`` claims mean the question could not be answered, and that is
    kept distinct from ``{}`` -- "nobody is authenticated", which is a real
    answer on a deployment without auth. The rules refuse either way; the
    difference is what an operator is told.
    """

    def __init__(self, back: Backchannel):
        self.back = back
        self.claims: dict | None = None
        self.asked = False
        self.why: str | None = None

    async def resolve(self, verbose: bool = False) -> dict | None:
        if self.asked:
            return self.claims
        self.asked = True
        reply = await self.back.ask({"connectionStatus": 1, "$db": "admin"})
        if reply is None or not reply.get("ok"):
            self.why = ("the deployment did not answer connectionStatus, so "
                        "who is asking is unknown")
            if verbose:
                print(f"  voyd: {self.why}", flush=True)
            return None
        self.claims = claims_from(reply)
        if verbose:
            who = self.claims.get("user") or "nobody"
            groups = ",".join(self.claims.get("groups") or []) or "none"
            print(f"  voyd: this connection is {who!r} to the server; "
                  f"groups={groups}", flush=True)
        return self.claims


def claims_from(status: Mapping) -> dict:
    """`connectionStatus` as the claims a rule reads.

    The mapping is deliberately thin. A role *is* a group -- that is what
    `db.createRole({role: "legal"})` makes -- so `restricted_to("groups")`
    against a document listing ``["legal", "deal-desk"]`` works with no
    further declaration, which is the case this is for.

    Bare role names only, not ``db.role``. Qualified names would also match
    a document that happened to spell them that way, and being generous is
    the wrong direction in a check that decides who sees what: a name this
    does not produce fails closed.
    """
    info = status.get("authInfo")
    info = info if isinstance(info, Mapping) else {}
    users = info.get("authenticatedUsers") or []
    roles = info.get("authenticatedUserRoles") or []
    first = users[0] if users and isinstance(users[0], Mapping) else {}
    groups = sorted({str(r["role"]) for r in roles
                     if isinstance(r, Mapping)
                     and isinstance(r.get("role"), str)})
    return {
        "user": first.get("user"),
        "db": first.get("db"),
        "groups": groups,
        # The same list under the name the deployment calls it, so a policy
        # can say `restricted_to("roles")` if that reads better to the
        # person writing it. One source, two spellings of the question.
        "roles": groups,
    }


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
        # One implementation of "ask on the client's own connection",
        # shared with the plain path. This class had the only copy and the
        # default path needed the same primitive; two spellings of
        # request-id matching is the drift this file keeps finding in
        # itself, so the copy moved out rather than being duplicated.
        self.back = Backchannel(primary_w)
        self.who = CallerIdentity(self.back)
        self.client_lock = asyncio.Lock()
        # One running total per cursor, for the same reason the plain path
        # has one: a cumulative rule spans a read, and a client picks how
        # many batches a read arrives in.
        self.budgets = Budgets()
        self.payoff = None
        # request id -> (sent at, shape). The shape travels with the
        # timing so the routing decision and the accounting cannot end up
        # holding two different ideas of what the read was.
        self.sent_at: dict[int, tuple[float, tuple]] = {}
        # The original bytes of each fanned-out read, kept until its reply
        # arrives. A secondary that answers with an error must not turn a
        # read the primary would have served into a failure the client
        # sees -- the boundary chose that route, so the boundary owns the
        # retry. Reads only, so re-running one is free of consequence.
        self.retry: dict[int, bytes] = {}
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

    async def ask_primary(self, command: dict,
                          timeout: float = 20.0) -> dict | None:
        """Run one command on the client's own primary connection.

        Kept as a name because `authoritative` and the mark lookups read
        better for it; the implementation is `Backchannel.ask`, which the
        plain path uses too.
        """
        return await self.back.ask(command, timeout)

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

        self.retry.pop(resp_to, None)
        ids = fanout.needed_ids(batch)
        fields = fanout.verdict_fields(guard)
        began = time.monotonic()
        # How long the secondary took, measured from the moment `route`
        # sent the command. A *duration*, which is worth saying because the
        # first version of this passed the stored timestamp straight
        # through as if it were one -- the ratio was then a monotonic clock
        # against a few milliseconds, no collection ever looked unprofitable,
        # and the whole mechanism silently never fired.
        sent = self.sent_at.pop(resp_to, None)
        ranked_in = None if sent is None else began - sent[0]
        fresh = (await self.authoritative(db, collection, ids, fields)
                 if ids is not None else None)
        verified_in = time.monotonic() - began
        # `sent is not None` rather than `ranked_in is not None`, which is
        # the same condition by construction one line up -- and being the
        # same condition *by construction* is the problem: a reader has to
        # derive it, and a checker cannot. Test the value being indexed.
        if (self.payoff is not None and sent is not None
                and ranked_in is not None and fresh is not None):
            why = self.payoff.record(sent[1], ranked_in, verified_in)
            if why is not None:
                where, kind, size = sent[1]
                asked = f" asking for up to {size}" if size else ""
                print(f"voyd-wire: no longer ranking {kind} on {where}"
                      f"{asked} on a secondary -- {why}", flush=True)
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
            judgeable, originals = fanout.merge_marks(batch, fresh, fields)
            allowed = guard.filter(judgeable, self.who.claims)
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
                rewritten: set[int], vault: "seal.Vault | None",
                embeds: Mapping | None,
                meter: "metrics.Meter | None",
                draining: "asyncio.Event | None" = None) -> str:
    """client -> upstream, choosing which upstream each message goes to.

    Every write rewrite here is the same call the single-upstream pump
    makes, in the same order, and that is not duplication worth removing:
    the two paths must agree about what a `delete` means, and the way to be
    sure of that is that both call `revoke_instead_of_delete` rather than
    that one of them calls the other.
    """
    async def send_primary(payload: bytes) -> None:
        async with conv.back.lock:
            conv.primary_w.write(payload)
            await conv.primary_w.drain()

    try:
        while True:
            raw, _len, req_id, resp_to, opcode = await _next_message(
                client_r, draining)
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
            original = raw

            # Who is asking, on this path too. Before the push-down below,
            # which builds its `$match` out of these claims -- resolving
            # afterwards leaves every caller-scoped reduction refused for
            # want of an identity already available.
            if _wants_a_caller(guards, body):
                await conv.who.resolve(verbose)

            refusal = refuse_unrewritable(raw, req_id, req_id, guards)
            if refusal is None and embeds:
                refusal = refuse_client_vector(raw, req_id, req_id, embeds)
            if refusal is None:
                pushed, refusal = rewrite_derived_read(
                    raw, req_id, resp_to, guards, verbose, conv.who.claims)
                if pushed is not None:
                    raw = pushed
                    original = raw
                    head = decode_sections(raw)
                    body = head[1] if head else body
            if refusal is not None:
                await conv.to_client(refusal)
                continue

            target = guard_for(guards, body, "delete")
            if target is not None and target.on_delete == "revoke":
                pins = await cascade_first(
                    raw, target, body.get("$db", ""), verbose)
                swapped = revoke_instead_of_delete(
                    raw, req_id, resp_to, target, verbose, pins)
                if swapped is not None:
                    raw = swapped
                    rewritten.add(req_id)
            fam = guard_for(guards, body, "findAndModify")
            if fam is not None and fam.on_delete == "revoke":
                pin = await cascade_first_for_one(
                    raw, fam, body.get("$db", ""), verbose)
                swapped = revoke_instead_of_find_and_delete(
                    raw, req_id, resp_to, fam, verbose, pin)
                if swapped is not None:
                    raw = swapped

            raw, refused = await derive_on_insert(
                raw, req_id, resp_to, guards, verbose)
            if refused is not None:
                await conv.to_client(refused)
                continue

            # The other end of a cursor's lifecycle; see `Budgets`.
            if "killCursors" in body:
                conv.budgets.forget(body.get("cursors"))

            # The same call the single-upstream pump makes, for the same
            # reason the delete rewrites above are duplicated rather than
            # factored: the two paths must agree about what a sealed write
            # means, and the way to be sure of that is that both call
            # `vault.seal_command` -- not that one of them calls the other.
            # A write is never fanned out, so this is only ever on the
            # primary leg.
            await erase_first(body, head[3] if head else [],
                              guards, vault, verbose, meter)

            if vault is not None and vault.targets(body):
                again = decode_sections(raw)
                if again is not None:
                    before = vault.sealed_writes
                    try:
                        resealed = await vault.seal_command(
                            dict(again[1]), again[2], again[3])
                    except seal.SealError as exc:
                        if meter is not None:
                            meter.seal_refused_writes_total += 1
                        await conv.to_client(
                            seal_refusal(req_id, req_id, str(exc)))
                        continue
                    if resealed is not None:
                        raw = encode_sections(req_id, resp_to, again[0],
                                              *resealed)
                        original = raw
                    if meter is not None:
                        meter.sealed_writes_total += (
                            vault.sealed_writes - before)

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
                elif (shape := fanout.routes_to_secondary(
                        body, guards, secondaries.payoff.withdrawn(),
                        frozenset(vault.sealed) if vault else frozenset())):
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
                        if head is not None and fanout.read_preference_of(
                                body) is None:
                            patched = dict(body)
                            patched["$readPreference"] = {
                                "mode": "secondaryPreferred"}
                            raw = encode_sections(req_id, resp_to, head[0],
                                                  patched, head[2], head[3])
                        conv.sent_at[req_id] = (time.monotonic(), shape)
                        conv.retry[req_id] = original
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
        # Broad on purpose: a defect on one connection must not take the
        # listener with it. But a traceback goes to a log nobody alerts
        # on, so it is *counted* -- a proxy shedding one connection a
        # second otherwise looks healthy from outside, which is this
        # package's own complaint aimed at itself.
        if meter is not None:
            meter.connections_failed_total += 1
        traceback.print_exc()
    return "closed"


async def replies(reader: asyncio.StreamReader, conv: Conversation, *,
                  source: str, guards: dict[str, Guard], verbose: bool,
                  rewritten: set[int], upstream: Upstream | None,
                  advertise: str | None, vault: "seal.Vault | None",
                  meter: "metrics.Meter | None") -> str:
    """One upstream -> the client, with the verdict taken on the way.

    Two of these run per fanned-out connection and they write to the same
    client, which is what `conv.to_client` serialises. The `source` is not
    cosmetic: it decides whether a batch is judged on the documents it
    arrived with or on marks fetched from the primary, and getting that
    backwards is the whole bug this feature could have been.
    """
    try:
        while True:
            raw, _len, req_id, resp_to, opcode = await read_message_async(
                reader)
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
            if source == "primary" and conv.back.answer(resp_to, raw):
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
                again = conv.retry.pop(resp_to, None)
                if again is not None and peek is not None and not (
                        peek[1].get("ok")):
                    # The secondary refused to answer. Send the same read to
                    # the primary and say nothing to the client, which is
                    # still waiting for its one reply and is entitled to the
                    # answer the deployment can give. Fan-out goes off for
                    # this connection: a secondary that just failed is not
                    # one to keep choosing.
                    conv.fan_out_ok = False
                    conv.sent_at.pop(resp_to, None)
                    if meter is not None:
                        meter.fanout_retried_on_primary_total += 1
                    if verbose:
                        print(f"  voyd: a secondary refused a read "
                              f"({peek[1].get('errmsg', 'no reason given')}"
                              f"); retrying it on the primary", flush=True)
                    async with conv.back.lock:
                        conv.primary_w.write(again)
                        await conv.primary_w.drain()
                    continue
                raw = await conv.permit(raw, req_id, resp_to)
                conv.sent_at.pop(resp_to, None)
            else:
                was_delete = resp_to in rewritten
                rewritten.discard(resp_to)
                raw = (delete_reply(raw, req_id, resp_to) if was_delete
                       else await judge(raw, req_id, resp_to, guards,
                                        verbose, vault, meter,
                                        conv.who.claims, conv.budgets))
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
        # Broad on purpose: a defect on one connection must not take the
        # listener with it. But a traceback goes to a log nobody alerts
        # on, so it is *counted* -- a proxy shedding one connection a
        # second otherwise looks healthy from outside, which is this
        # package's own complaint aimed at itself.
        if meter is not None:
            meter.connections_failed_total += 1
        traceback.print_exc()
    return "closed"


async def fanned_session(client_r, client_w, upstream: Upstream,
                         secondaries: Secondaries, guards, verbose: bool,
                         live: Live, advertise, vault, embeds, meter,
                         draining: "asyncio.Event | None" = None) -> None:
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
                                        guards, verbose, rewritten, vault,
                                        embeds, meter, draining)),
            asyncio.ensure_future(replies(up_r, conv, source="primary",
                                          guards=guards, verbose=verbose,
                                          rewritten=rewritten,
                                          upstream=upstream,
                                          advertise=advertise, vault=vault,
                                          meter=meter)),
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
                                advertise=None, vault=vault, meter=meter))
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


def tally(guards: dict[str, Guard],
          vault: "seal.Vault | None" = None) -> dict:
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
    counts = {"served": sum(g.admitted for g in guards.values()),
              "refused": sum(g.refused for g in guards.values()),
              "revoked": sum(g.revoked for g in guards.values()),
              "cascaded": sum(g.cascaded for g in guards.values()),
              "reasons": reasons}
    if vault is not None:
        counts["sealed"] = vault.sealed_writes
        counts["unsealed"] = vault.unsealed_reads
        counts["erased"] = vault.erasures
    return counts


def merge(tallies: list[dict]) -> dict:
    """N workers' counts, added up."""
    # Counts and reasons kept apart while summing, then joined on the way
    # out. One dict holding both an `int` and a `dict[str, int]` is what
    # made the reason accumulator untypeable -- and it is also why
    # `total[key] += ...` and `total["reasons"][reason] = ...` read as the
    # same kind of operation when they are not.
    counts = {"served": 0, "refused": 0, "revoked": 0, "cascaded": 0}
    reasons: dict[str, int] = {}
    for one in tallies:
        for key in counts:
            counts[key] += one.get(key, 0)
        for reason, n in (one.get("reasons") or {}).items():
            reasons[reason] = reasons.get(reason, 0) + n
    return {**counts, "reasons": reasons}


def summarise(counts: dict | dict[str, Guard]) -> None:
    """What this boundary actually did. A guarantee nobody counted is a
    claim about one."""
    if counts and all(isinstance(v, Guard) for v in counts.values()):
        counts = tally(counts)
    served = counts.get("served", 0)
    refused = counts.get("refused", 0)
    revoked = counts.get("revoked", 0)
    reasons = counts.get("reasons") or {}
    print(f"voyd-wire: served {served}, refused {refused} {reasons or '{}'}, "
          f"turned {revoked} delete(s) into revocations", flush=True)
    cascaded = counts.get("cascaded", 0)
    if cascaded:
        # Said separately from `revoked` on purpose. "3 facts revoked" and
        # "3 facts revoked and 41 things made out of them went too" are
        # different sentences, and the second one is the only one that
        # answers an erasure request honestly.
        print(f"voyd-wire: the refusal travelled to {cascaded} document(s) "
              f"derived from those facts, marked before the source was",
              flush=True)
    sealed = counts.get("sealed")
    if sealed is not None:
        print(f"voyd-wire: sealed {sealed} document(s) on the way in, "
              f"unsealed {counts.get('unsealed', 0)} on the way out, "
              f"sequenced {counts.get('erased', 0)} erasure(s)", flush=True)
        # The old line said this unconditionally, and with `--key-vault` it
        # would have been a half-truth: the boundary still deletes no
        # documents, but it does forward a key's destruction, and a key is
        # the one thing here whose deletion is the point. Saying both is
        # cheaper than letting a reader reconcile them.
        print(f"voyd-wire: documents deleted by this process: 0 "
              f"(key deletions forwarded: {counts.get('erased', 0)} -- the "
              f"one deletion this tool argues for)", flush=True)
    else:
        print("voyd-wire: documents deleted by this process: 0", flush=True)


def serve(listen_port: int, target: str, guards: dict[str, Guard],
          verbose: bool, *, certfile: str | None = None,
          keyfile: str | None = None, max_connections: int = 200,
          drain_seconds: float = 20.0, advertise: str | None = None,
          workers: int = 1, metrics_port: int | None = None,
          fan_out: str | None = None, give_up: float = 1.0,
          vault_spec: dict | None = None,
          auto_embed: dict | None = None) -> None:
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
        if g.spec.lineage_field:
            # Worth its own line: this is the only declaration that makes
            # the boundary write to documents the caller never named, and
            # an operator who finds extra rows marked should find the
            # reason in the startup output rather than in a stack trace.
            print(f"voyd-wire: {name} tracks derivation in "
                  f"{g.spec.lineage_field!r}: an insert naming a parent has "
                  f"its ancestry closed and is refused if that parent is "
                  f"already refused"
                  + ("; a delete marks the derivations first, then the "
                     "source" if g.on_delete == "revoke" else
                     ". Deletes here are FORWARDED and really delete, so "
                     "nothing cascades -- add on_delete='revoke' if that "
                     "is not what you meant"), flush=True)
        for claim in unsuppliable_claims(g):
            # Said at boot, loudly, because the alternative is correct and
            # useless: a rule whose claim this boundary cannot fill gets
            # no claim, "no claim is the lowest, not the highest", and the
            # collection refuses every document to everybody. That is
            # fail-closed, which is the right direction and the wrong
            # outcome -- and it presents as "VOYD broke my reads", with
            # nothing anywhere connecting it to a line in the policy file.
            print(f"voyd-wire: WARNING: {name} declares a rule needing the "
                  f"claim {claim!r}, and the wire can only supply 'user', "
                  f"'db', 'groups' and 'roles' -- the server's answer to "
                  f"connectionStatus. Every read of {name} will be refused. "
                  f"Use restricted_to('groups') against your MongoDB "
                  f"roles, which is the same question asked of an answer "
                  f"the deployment will vouch for",
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
    if vault_spec:
        for line in seal.announce(vault_spec):
            print(line, flush=True)
    for name, model in sorted((auto_embed or {}).items()):
        # Worth a line of its own: this is the only declaration that makes
        # the boundary refuse a *query* rather than a document, and an
        # operator debugging "why is my $vectorSearch an error" should find
        # the answer in the startup output.
        print(f"voyd-wire: {name} is embedded by the server "
              f"(auto_embed={model!r}); a client-supplied queryVector on it "
              f"is refused, because a vector from anywhere else is a hit in "
              f"a different space", flush=True)
    print("voyd-wire: connect any driver to "
          f"mongodb{'+tls' if certfile else ''}://localhost:{listen_port}/"
          "?directConnection=true\n", flush=True)

    # The slab is allocated *before* the fork so every worker inherits the
    # same pages. There is no way to add one afterwards, which is why this
    # happens here and not lazily on the first scrape.
    slab = meters = None
    if metrics_port is not None:
        layout = metrics.Layout(tuple(guards))
        slab = metrics.Slab(workers, layout)
        meters = [metrics.Meter(layout, slab, i) for i in range(workers)]
        print(f"voyd-wire: metrics on http://127.0.0.1:{metrics_port}/metrics"
              f" (loopback only, always)", flush=True)

    if workers > 1:
        supervise(sock, workers, target, guards, verbose,
                  ssl_ctx=ssl_ctx, max_connections=max_connections,
                  drain_seconds=drain_seconds, advertise=advertise,
                  slab=slab, meters=meters, metrics_port=metrics_port,
                  fan_out=fan_out, give_up=give_up, vault_spec=vault_spec,
                  auto_embed=auto_embed)
        return

    if slab is not None and metrics_port is not None:
        metrics.serve(metrics_port, slab)
    counts = asyncio.run(_run(sock, ssl_ctx, target, guards, verbose,
                              max_connections=max_connections,
                              drain_seconds=drain_seconds,
                              advertise=advertise, fan_out=fan_out,
                              give_up=give_up, vault_spec=vault_spec,
                              auto_embed=auto_embed,
                              meter=meters[0] if meters else None))
    summarise(counts)


async def _run(sock: socket.socket, ssl_ctx: "ssl.SSLContext | None",
               target: str, guards: dict[str, Guard], verbose: bool, *,
               max_connections: int, drain_seconds: float,
               advertise: str | None, fan_out: str | None = None,
               give_up: float = 1.0, vault_spec: dict | None = None,
               auto_embed: dict | None = None,
               meter: "metrics.Meter | None" = None) -> dict:
    """One worker: accept, serve, drain, and report what it counted."""
    upstream = Upstream(target, verbose=verbose, meter=meter)
    # Built per worker, after the fork, because an encrypting handle owns
    # sockets and an event loop and neither survives one. The *custody* is
    # built before the fork and inherited, which is the part that has to be
    # shared: an `Ephemeral` master key minted per worker would give each
    # of them a different key for the same tenant, and a document written
    # through one worker would be unreadable through the next.
    embeds = dict(auto_embed or {})
    vault = seal.Vault(**vault_spec) if vault_spec else None
    if vault is not None:
        await vault.open()
    # Per worker, after the fork, for the same reason the vault is: it owns
    # sockets and an event loop and neither survives one. Attached to the
    # guards rather than threaded through a dozen signatures because it is
    # a property of a *collection that declares lineage*, and every site
    # that needs it already has that collection's guard in hand.
    lineage = None
    if cascade.Cascade.wanted(guards):
        lineage = cascade.Cascade(_vault_uri(target), verbose=verbose)
        await lineage.open()
        for g in guards.values():
            if g.spec.lineage_field:
                g.cascade = lineage
    secondaries = (Secondaries(fan_out, verbose=verbose, meter=meter,
                               give_up=give_up)
                   if fan_out else None)
    live = Live()
    stopping = asyncio.Event()

    async def flushing(meter: "metrics.Meter") -> None:
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

    # Started only when there is a meter, and `flushing` closes over the
    # narrowed local rather than the optional parameter: a closure cannot
    # carry a narrowing from its enclosing scope, so six `Meter | None`
    # errors lived in a function that is only ever called when it is not
    # None. The local makes the precondition part of the code instead of a
    # fact about the call site.
    flusher = (asyncio.ensure_future(flushing(meter)) if meter is not None
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
                                 guards, verbose, live, advertise, vault,
                                 embeds, meter, stopping)
        else:
            await session(reader, writer, upstream, guards, verbose, live,
                          advertise, vault, embeds, meter, draining=stopping)

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

    await stopping.wait()

    # `server.close()` rather than `async with server`, and the difference
    # is not style. Since Python 3.12 `Server.__aexit__` awaits
    # `wait_closed()`, which waits for every *handler* to finish -- so the
    # context manager blocked forever on a single idle client and the
    # bounded drain below was never reached.
    server.close()

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

    # **Bounded, and that is the whole point of this line.** Since Python
    # 3.12 `Server.wait_closed()` waits for every *handler* to finish, not
    # only for the listening socket to shut. An unbounded await here meant
    # a `SIGTERM` with one idle client attached never returned at all --
    # measured: an idle proxy exited in 0.02s and a proxy with a single
    # connected `mongosh` was still alive after 60 seconds, having printed
    # "draining" and nothing since. The bounded drain above it was never
    # reached, so the timeout that was supposed to cap this could not.
    #
    # In production that is every rolling deploy waiting out its grace
    # period and then taking a `SIGKILL`, which is precisely the
    # connection reset draining exists to avoid -- the feature failing in
    # the shape of the problem it was added for.
    try:
        await asyncio.wait_for(server.wait_closed(), timeout=1.0)
    except (asyncio.TimeoutError, OSError, ConnectionError):
        pass
    if flusher is not None:
        await asyncio.gather(flusher, return_exceptions=True)
    counted = tally(guards, vault)
    if vault is not None:
        # The one connection this process opened on its own behalf, put
        # down on the way out. A boundary that argues at length about
        # holding a handle you cannot close should not leave one open.
        await vault.aclose()
    if lineage is not None:
        await lineage.aclose()
    return counted


def supervise(sock: socket.socket, workers: int, target: str,
              guards: dict[str, Guard], verbose: bool, *,
              ssl_ctx: "ssl.SSLContext | None", max_connections: int,
              drain_seconds: float, advertise: str | None,
              slab: "metrics.Slab | None" = None,
              meters: "list[metrics.Meter] | None" = None,
              metrics_port: int | None = None,
              fan_out: str | None = None, give_up: float = 1.0,
              vault_spec: dict | None = None,
              auto_embed: dict | None = None) -> None:
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
                    vault_spec=vault_spec, auto_embed=auto_embed,
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
        metrics.serve(metrics_port, slab)

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
        found = next((i for i, (pid, _fd) in slots.items() if pid == dead),
                     None)
        if found is None:
            continue
        index = found
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


def _custody(spec: str):
    """`local`, `local:/path`, or `env:PREFIX`. Never a guess.

    Built here, in the parent, *before* any fork -- so every worker
    inherits the same master key. An `Ephemeral` custody constructed per
    worker would mint a different key each, and a tenant written through
    one worker would be undecryptable through the next: a data-loss bug
    that only appears with `--workers 2` and looks like corruption.
    """
    from voyd.engine.custody import Ephemeral, LocalFile, from_env

    if spec == "local":
        return Ephemeral()
    if spec.startswith("local:"):
        return LocalFile(path=spec.split(":", 1)[1])
    if spec.startswith("env:"):
        return from_env(spec.split(":", 1)[1])
    raise ValueError(
        f"--kms {spec!r}: expected `local`, `local:/path/to/master.key`, or "
        f"`env:PREFIX`. Custody is the whole of the erasure claim, so this "
        f"refuses to guess at it")


def _vault_from(args) -> dict | int:
    """The vault configuration, or an exit code and a reason on stderr.

    Three ways to be wrong, and all three are startup errors rather than
    surprises later:

    - a policy declares `sealed()` and nobody passed `--key-vault`. The
      boundary would read ciphertext it could not decrypt and refuse every
      sealed document under `unrecoverable` -- fail-closed, but a
      deployment reporting a total erasure it never asked for.
    - `--key-vault` with no `sealed()` anywhere. Holding keys buys nothing
      and costs a credential, so it is a mistake worth naming.
    - a `--kms` this cannot parse.
    """
    declared = seal.sealed_from(OPTIONS)
    if declared and not args.key_vault:
        print("voyd-wire: this policy declares sealed() on "
              + ", ".join(sorted(declared))
              + " but no --key-vault was given. Without one this boundary "
                "holds no keys, so it cannot decrypt those fields and would "
                "refuse every document in them as unrecoverable -- a total "
                "erasure nobody asked for, reported as if it were working. "
                "Pass --key-vault DB, or drop sealed() from the policy",
              file=sys.stderr)
        return 2
    if args.key_vault and not declared:
        print("voyd-wire: --key-vault was given but no collection declares "
              "sealed(). Holding a master key buys nothing here and costs "
              "this process a credential it does not need", file=sys.stderr)
        return 2
    if not declared:
        return {}
    database, _, collection = args.key_vault.partition(".")
    try:
        custody = _custody(args.kms)
    except ValueError as exc:
        print(f"voyd-wire: {exc}", file=sys.stderr)
        return 2
    return {"uri": _vault_uri(args.target), "database": database,
            "sealed": declared, "custody": custody,
            "collection": collection or "__keys"}


def _ensure(args, guards: dict[str, Guard]) -> int:
    """Build what the policy declares, before serving. 0 to continue.

    Deliberately in front of `_preflight` in `main`, so the ordinary first
    run is `--ensure app --verify app`: create it, then have a separately
    written checker refuse to agree it is there. One of those alone is a
    boot step; the pair is evidence.
    """
    try:
        lines = asyncio.run(ensure.provision(
            _vault_uri(args.target), args.ensure, guards, OPTIONS,
            wait_s=args.ensure_wait))
    except Exception as exc:                                  # noqa: BLE001
        print(f"voyd-wire: --ensure could not build the policy's schema "
              f"({type(exc).__name__}: {exc}). Nothing was served, because "
              f"a boundary enforcing a policy whose indexes do not exist "
              f"refuses correctly and ranks badly, one query at a time",
              file=sys.stderr)
        return 4
    for line in lines:
        print(line, flush=True)
    print(flush=True)
    return 0


def _preflight(args, guards: dict[str, Guard]) -> int:
    """Ask before serving. Returns an exit code, 0 to continue.

    Synchronous and finished before `serve` binds anything, which is the
    whole point: the answer belongs in the same screen of output as the
    guarantees the boundary is about to start making, not in a metric
    somebody reads afterwards.
    """
    found, why = asyncio.run(preflight.inspect(
        _vault_uri(args.target), args.verify,
        preflight.declarations(guards, OPTIONS)))
    for line in preflight.report(found, why):
        print(line, flush=True)
    if preflight.fatal(found) and not args.verify_only:
        print("voyd-wire: refusing to start. The boundary would enforce a "
              "policy this cluster cannot satisfy, and it would do it one "
              "query at a time -- which is a worse way to find out than "
              "this. Fix the line above, or drop --verify to start anyway",
              file=sys.stderr)
        return 3
    if preflight.fatal(found):
        return 3
    print(flush=True)
    return 0


def _embeds_from(options: Mapping) -> dict:
    """Collection -> the model the server embeds it with.

    Flattened from the policy file's `OPTIONS`, because the boundary's
    question is per collection: *does this collection's index hold text
    the server encoded?* Which field it is declared on matters to the
    index and not to the refusal -- a client vector is wrong for the
    collection however many paths it embeds.
    """
    out = {}
    for name, opt in options.items():
        declared = opt.get("auto_embed") or {}
        if declared:
            out[name] = next(iter(declared.values()))
    return out


def _vault_uri(target: str) -> str:
    """The connection string the vault dials, from `--target`.

    The same deployment the boundary forwards to, by construction rather
    than by a second flag somebody could point elsewhere. A key vault on a
    different cluster than the ciphertext is a failure that looks like
    "the keys are missing" rather than like a misconfiguration.
    """
    if "://" in target:
        return target
    return f"mongodb://{target}/?directConnection=true"


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
    ap.add_argument("--drain", type=float, default=20.0, metavar="SECONDS",
                    help="on SIGTERM, how long to let requests already in "
                         "flight finish. Connections sitting idle between "
                         "requests are closed at once and do not wait this "
                         "out. 0 hangs up on everything immediately")
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
    ap.add_argument("--key-vault", metavar="DB[.COLLECTION]", default=None,
                    help="hold the keys for the fields a policy file "
                         "declared sealed(), encrypting them on the way in "
                         "and decrypting them on the way out. This is the "
                         "one flag that costs this boundary its purity: it "
                         "opens a database connection of its own, holds KMS "
                         "credentials, and makes a sealed read cost a "
                         "decrypt rather than 2.3us. What it buys is the "
                         "erasure refusal cannot perform -- destroying a "
                         "key makes every copy of that tenant's ciphertext "
                         "unreadable, in every replica, snapshot and "
                         "backup, without visiting any of them. See "
                         "LIMITS.md \u00a75")
    ap.add_argument("--kms", metavar="SPEC", default="local",
                    help="who holds the master key: `local` (ephemeral, "
                         "demo-grade, gone on restart), "
                         "`local:/path/to/master.key` (durable; custody is "
                         "a file permission), or `env:PREFIX` to read a "
                         "provider out of the environment the way "
                         "voyd.engine.custody.from_env does -- which is the "
                         "rung that gets you aws/azure/gcp/kmip, where "
                         "destroying the master key is somebody else's "
                         "audited operation")
    ap.add_argument("--ensure", metavar="DB", default=None,
                    help="before serving, create what the policy file "
                         "declares in this database: the collection, a TTL "
                         "index behind every deadline(), an index leading "
                         "with every tenant(), and a vector index the "
                         "server embeds for every auto_embed(). The one "
                         "mode that writes -- it uses your credentials and "
                         "closes its connection before the listener binds. "
                         "Idempotent, so it is safe on every boot. Pair it "
                         "with --verify, which is the same declaration read "
                         "by different code that creates nothing")
    ap.add_argument("--ensure-wait", metavar="SECONDS", type=float,
                    default=90.0,
                    help="how long --ensure waits for a search index to "
                         "become queryable. mongot builds asynchronously "
                         "and a query against a half-built index returns "
                         "no rows rather than an error, so the wait is the "
                         "difference between a clean first run and a "
                         "confusing one (default: 90)")
    ap.add_argument("--ensure-only", action="store_true",
                    help="run --ensure and exit without serving, for a "
                         "deploy step that is not the process that serves")
    ap.add_argument("--verify", metavar="DB", default=None,
                    help="before serving, ask the cluster whether it "
                         "matches the policy file: a TTL index behind every "
                         "deadline(), an index leading with every tenant(), "
                         "an autoEmbed field naming the model auto_embed() "
                         "declares, a binData validator behind every "
                         "sealed(). Read-only -- it issues listIndexes, "
                         "$listSearchIndexes and listCollections, creates "
                         "nothing, and closes its connection before the "
                         "listener accepts anything. A contradiction (the "
                         "index embeds with a different model than the "
                         "policy names) refuses to start; a missing layer "
                         "underneath refusal (no TTL index) is a warning. "
                         "Needs a database because a policy file names "
                         "collections and the *client* names the database, "
                         "so this process genuinely cannot know it")
    ap.add_argument("--verify-only", action="store_true",
                    help="run --verify and exit without binding a port. "
                         "The form a deploy gate wants: exit 0 if the "
                         "cluster matches the policy, 3 if it contradicts "
                         "it, and print the warnings either way")
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
                    spec,
                    on_delete=OPTIONS.get(collection, {}).get(
                        "on_delete", "forward"))
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
        vault_spec = _vault_from(args)
        if isinstance(vault_spec, int):
            return vault_spec
        if args.ensure_only and not args.ensure:
            print("voyd-wire: --ensure-only needs --ensure DB naming the "
                  "database to build", file=sys.stderr)
            return 2
        if args.ensure:
            code = _ensure(args, guards)
            if code:
                return code
            if args.ensure_only and not args.verify:
                return 0
        if args.verify_only and not args.verify:
            print("voyd-wire: --verify-only needs --verify DB naming the "
                  "database to check", file=sys.stderr)
            return 2
        if args.verify:
            code = _preflight(args, guards)
            if code or args.verify_only or args.ensure_only:
                return code
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
              drain_seconds=args.drain,
              workers=args.workers, metrics_port=args.metrics,
              fan_out=args.fan_out, give_up=args.fan_out_give_up,
              vault_spec=vault_spec, auto_embed=_embeds_from(OPTIONS))
    except KeyboardInterrupt:
        summarise(guards)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
