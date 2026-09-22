"""Who the server says this connection is, asked on the client's own socket.

Two objects and a translation, and the reason they are one module is that
they answer one question: *who is asking?* -- which the boundary is in the
worst possible position to take the client's word for, because the client
is the only thing talking to it.

`Backchannel` is the primitive: send a command on the connection the client
already authenticated, and match its reply. `CallerIdentity` is the one
question worth asking that way, `connectionStatus`, cached because a
MongoDB connection authenticates once and stays that identity.
`claims_from` turns the server's answer into the claims a rule reads.

Nothing here decides anything. What the claims *mean* is `policy.py`, and
whether a document is admitted is `voyd.engine.admission` -- this module
only establishes whose prompt it would be reaching.
"""

from __future__ import annotations

import asyncio
from typing import Mapping

from .codec import decode_op_msg, encode_op_msg


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
