#!/usr/bin/env python3
"""Transport: sockets, connections, workers, and the shutdown.

    # terminal 1 -- rules in a file that is not your application
    voyd-wire --config voydfile.py --target localhost:27018

    # terminal 2 -- any driver, any language
    mongosh mongodb://localhost:27099/demo

This file moves bytes and decides *when* they move. It decides nothing
about what a message is allowed to mean -- that is `policy.py`, all of it,
so "can this be bypassed?" is a question about one file. Framing and BSON
are `codec.py`. What is left here is the shell: accept a connection, open
one upstream, pump both directions, fork workers, drain on `SIGTERM`.

Four questions a reader arrives with are four files beside this one,
because each is a different question and only one of them is "how do the
bytes move":

    upstream.py   *where* it forwards, and how an election is followed
    identity.py   *who* the server says this connection authenticated as
    report.py     *what* it refused, summed across workers
    cli.py        the flags, and what runs before the listener binds

None of them imports this file except `cli`, which composes them. The
direction matters: "what does it do with a message" stays answerable
without reading an argument parser.

The boundary binds the **connection**, not a handle. There is no raw read
to guard -- not from Node, not from Compass, not from a notebook, not from
a shell that has never heard of VOYD -- because there is nothing to reach
past.

**Three connections of its own, named here rather than discovered.**
`--key-vault` holds the vault; `--ensure` connects with your credentials
to *create* what the policy declares, then closes before the listener
binds; and a policy declaring `lineage_field` opens one so a revocation
can reach what was derived from the fact. Everything else forwards your
credentials and adds no round trip, because the per-document check is
pure. A property with an exception nobody wrote down is not a property,
which is this package's whole complaint, so they are written down.

**What this is not: a driver.** It does not pool upstream connections, and
that one is deliberate -- a MongoDB connection carries authentication,
sessions, cursors and transactions, and sharing one would hand a cursor to
whoever asked second.

What does survive the crossing, measured rather than assumed: read
preference is honoured against a topology of one (the `*Preferred` modes
served by the primary, strict `secondary` a client-side error rather than
a quiet primary read), retryable writes stay armed because
`rewrite_topology` keeps `setName`, and sessions and transactions are
forwarded intact.

**One upstream per client, and one request loop.** A read is served by the
deployment the client was pointed at. There is no second path that routes
some reads elsewhere, and `LIMITS.md` section 8 says why ranking on a
replica is not one.

**Concurrency is this file's problem and nobody else's.** Every function
in `policy.py` that rewrites bytes is `bytes -> bytes` and touches no
socket, because the check underneath it is pure. That is what made moving
from two OS threads per connection to one coroutine pair a change to the
shell and nothing else, and it is why the ceiling is upstream sockets
rather than thread stacks.

"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import socket
import ssl
import threading
import time
import traceback
from typing import Mapping, TypedDict


from . import cascade
from . import seal
from . import metrics
from .policy import (Budgets, Guard, _wants_a_caller, _was_reduced,
                     cascade_first, cascade_first_for_one, delete_reply,
                     derive_on_insert, erase_first, guard_for, judge,
                     refuse_client_vector, refuse_unrewritable,
                     revoke_instead_of_delete,
                     revoke_instead_of_find_and_delete, rewrite_derived_read,
                     rewrite_topology, seal_refusal, strip_compression,
                     unsuppliable_claims)

from .codec import (OP_COMPRESSED, OP_MSG, Hangup, ProtocolError,
                    decode_op_msg, decode_sections, encode_sections,
                    read_message_async, uncompress_message)
from .identity import Backchannel, CallerIdentity
from .report import merge, summarise, tally
from .upstream import (Upstream, keepalive, stepped_down,
                       upstream_ready, vault_uri)


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


def serve(listen_port: int, target: str, guards: dict[str, Guard],
          verbose: bool, *, certfile: str | None = None,
          keyfile: str | None = None, max_connections: int = 200,
          drain_seconds: float = 20.0, advertise: str | None = None,
          workers: int = 1, metrics_port: int | None = None,
          metrics_bind: str = "127.0.0.1",
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
        if g.spec.subjects:
            # Its own line because it changes what a *document* is here.
            # An operator seeing fewer chapters than the database holds
            # should find the reason in the startup output.
            print(f"voyd-wire: {name} judges each element of "
                  f"{g.spec.subjects!r} on its own, named by "
                  f"{g.spec.subject_key!r}: a refused element is removed and "
                  f"the document served without it. An element with no "
                  f"{g.spec.subject_key!r} is refused, because a subject "
                  f"nothing can name is one no erasure request can reach",
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
        where_metrics = ("127.0.0.1" if metrics_bind in ("", "0.0.0.0")
                         else metrics_bind)
        print(f"voyd-wire: metrics on "
              f"http://{where_metrics}:{metrics_port}/metrics, readiness on "
              f"/health"
              + ("" if metrics_bind == "127.0.0.1" else
                 f"  -- bound {metrics_bind}, so the refusal breakdown is "
                 f"reachable from the network"), flush=True)

    if workers > 1:
        supervise(sock, workers, target, guards, verbose,
                  ssl_ctx=ssl_ctx, max_connections=max_connections,
                  drain_seconds=drain_seconds, advertise=advertise,
                  slab=slab, meters=meters, metrics_port=metrics_port,
                  metrics_bind=metrics_bind, vault_spec=vault_spec,
                  auto_embed=auto_embed)
        return

    if slab is not None and metrics_port is not None:
        metrics.serve(metrics_port, slab, bind=metrics_bind,
                      ready=upstream_ready(target))
    counts = asyncio.run(_run(sock, ssl_ctx, target, guards, verbose,
                              max_connections=max_connections,
                              drain_seconds=drain_seconds,
                              advertise=advertise, vault_spec=vault_spec,
                              auto_embed=auto_embed,
                              meter=meters[0] if meters else None))
    summarise(counts)


async def _run(sock: socket.socket, ssl_ctx: "ssl.SSLContext | None",
               target: str, guards: dict[str, Guard], verbose: bool, *,
               max_connections: int, drain_seconds: float,
               advertise: str | None, vault_spec: dict | None = None,
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
        lineage = cascade.Cascade(vault_uri(target), verbose=verbose)
        await lineage.open()
        for g in guards.values():
            if g.spec.lineage_field:
                g.cascade = lineage
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
              metrics_bind: str = "127.0.0.1",
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
        metrics.serve(metrics_port, slab, bind=metrics_bind,
                      ready=upstream_ready(target))

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
