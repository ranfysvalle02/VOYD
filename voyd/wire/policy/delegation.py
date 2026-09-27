"""A read that carries a delegated identity: verified, narrowed, stripped.

An agent runtime that multiplexes many users over one pooled connection
cannot re-authenticate per request, so the identity rides in the one
field every driver passes through verbatim -- the command's ``comment``::

    coll.find({...}, comment={"voyd": token})

This module is what happens to that command before anything else in the
pump reads it:

1. **The token is taken out.** From the command and from an ``explain``'s
   inner command, and the command goes on without its ``comment``, so the
   token never reaches a server log, the profiler or ``currentOp``. The
   shape is strict: the comment is exactly ``{"voyd": "<jwt>"}`` or it is
   refused. A comment that is a string, or a document without ``voyd``,
   is the client's own and is forwarded untouched.
2. **It is verified** by ``voyd.engine.delegation.verify`` against keys
   held by ``voyd/wire/jwks.py`` -- never fetched here.
3. **It narrows the connection.** The connection's own identity is the
   one the server reported; only a connection whose user the issuer
   names in ``connection_users`` may present that issuer's tokens.
4. **The collection's terms apply.** ``delegation="forbidden"`` refuses
   it, ``"required"`` refuses a plain read and a token with no actor, and
   ``scope=`` refuses a token that was not granted the scope, by name.
5. **The tenant is the token's.** A collection with ``tenant()`` has the
   principal's tenant pinned into the query, and a query naming another
   is refused.

A cursor keeps the identity it was opened under. A ``getMore`` with no
token continues as that identity; one presenting a different principal
or actor, or presenting any token on a cursor opened without one, is
refused. Writes do not take a delegated identity at all.

Nothing here owns a socket. The connection's identity is asked for by
the pump before ``admit`` is called, because asking is a round trip and
this is the decision, not the transport.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Mapping

from voyd.engine.admission.sides import tenant_of
from voyd.engine.delegation import Identity, Refusal, peek_issuer, verify

from ..codec import LAZY, decode_op_msg, encode_op_msg, encode_sections
from .guarding import Guard, guard_for
from .reads import LEADING_STAGES, reducing_stage

READS = ("find", "aggregate", "count", "distinct")
TOKEN_KEY = "voyd"


def _refused(req_id: int, collection: str | None, why: str,
             verbose: bool) -> bytes:
    where = f" on {collection!r}" if collection else ""
    if verbose:
        print(f"  voyd: REFUSED a delegated read{where}: {why}", flush=True)
    return encode_op_msg(req_id, req_id, 0, {
        "ok": 0.0, "code": 13, "codeName": "Unauthorized",
        "errmsg": f"voyd-wire refuses this read{where}: {why}"})


def _one(cmd: Mapping) -> tuple[str | None, dict | None, str | None]:
    comment = cmd.get("comment")
    if not isinstance(comment, Mapping) or TOKEN_KEY not in comment:
        return None, None, None
    if set(comment) != {TOKEN_KEY}:
        return None, None, ("a comment carrying a voyd token is exactly "
                            "{voyd: <token>}; anything beside it would be "
                            "forwarded with the token removed from under it")
    token = comment[TOKEN_KEY]
    if not isinstance(token, str):
        return None, None, "the voyd token in the comment is not a string"
    return token, {k: v for k, v in cmd.items() if k != "comment"}, None


def take_token(body: Mapping) -> tuple[str | None, dict | None, str | None]:
    """``(token, body without it, why refused)``.

    ``(None, None, None)`` for a command that carries no token, which is
    every command a client without delegation sends.
    """
    token, stripped, why = _one(body)
    if why:
        return None, None, why
    inner = body.get("explain")
    if isinstance(inner, Mapping):
        inner_token, inner_stripped, why = _one(inner)
        if why:
            return None, None, why
        if inner_token is not None:
            if token is not None and token != inner_token:
                return None, None, ("an explain carrying two different "
                                    "tokens is two identities for one read")
            token = inner_token
            stripped = dict(stripped if stripped is not None else body)
            stripped["explain"] = inner_stripped
    return token, stripped, None


def carries_token(body: Mapping) -> bool:
    """Does this command present a delegated token? Cheap: two lookups."""
    inner = body.get("explain")
    return any(isinstance(c, Mapping) and TOKEN_KEY in c
               for c in (body.get("comment"),
                         inner.get("comment") if isinstance(inner, Mapping)
                         else None))


def _verb(body: Mapping) -> tuple[str | None, Mapping]:
    """The read verb and the command that names it (an explain's inner one)."""
    inner = body.get("explain")
    cmd = inner if isinstance(inner, Mapping) else body
    for verb in (*READS, "getMore"):
        if verb in cmd:
            return verb, cmd
    return None, cmd


def _target(cmd: Mapping, verb: str | None,
            guards: dict[str, Guard]) -> tuple[Guard | None, str | None]:
    if verb == "getMore":
        name = cmd.get("collection")
    elif verb is not None:
        name = cmd.get(verb)
    else:
        return None, None
    if not isinstance(name, str):
        return None, None
    return (guard_for(guards, cmd, verb) if verb != "getMore"
            else guards.get(name)), name


def pin_tenant(cmd: Mapping, field: str, value: Any
               ) -> tuple[dict | None, str | None]:
    """The command with ``field`` fixed to ``value`` in its query.

    A query that already names the tenant must name this one exactly --
    a different value, a ``$in`` or a regex is refused rather than
    overridden, because the client asked a question the token does not
    entitle it to and should be told so. A lone ``$vectorSearch`` is not
    rewritten: the tenant is checked on every document it returns, and a
    stage after it would turn off backfill for no gain.
    """
    out = dict(cmd)

    def pinned(query: Any) -> dict | None:
        q = dict(query) if isinstance(query, Mapping) else {}
        if field in q and q[field] != value:
            return None
        q[field] = value
        return q

    other = (f"this query names a {field!r} other than the token's, and a "
             f"delegated read is scoped to its principal's tenant")
    for verb, where in (("find", "filter"), ("count", "query"),
                        ("distinct", "query")):
        if verb in cmd:
            q = pinned(cmd.get(where))
            if q is None:
                return None, other
            out[where] = q
            return out, None
    pipeline = cmd.get("pipeline")
    if "aggregate" not in cmd or not isinstance(pipeline, list):
        return out, None
    stages = list(pipeline)
    lead = stages[0] if stages and isinstance(stages[0], Mapping) else {}
    name = next(iter(lead), None) if len(lead) == 1 else None
    at = 1 if name in LEADING_STAGES else 0
    here = stages[at] if len(stages) > at and isinstance(stages[at], Mapping) else {}
    if len(here) == 1 and "$match" in here:
        q = pinned(here["$match"])
        if q is None:
            return None, other
        stages[at] = {"$match": q}
    elif at == 1 and reducing_stage(stages) is None:
        return out, None                # judged per document; see above
    else:
        stages.insert(at, {"$match": {field: value}})
    out["pipeline"] = stages
    return out, None


class Delegations:
    """One connection's delegated reads: which request, which cursor, whom.

    Per connection, like every other piece of state the pump shares
    between its two directions, because request ids and cursors are.
    """

    def __init__(self, issuers: Mapping, keys: Callable[[str, float], Any],
                 clock: Callable[[], float] = time.time):
        self.issuers = dict(issuers)
        self.keys = keys
        self.clock = clock
        # req_id -> (claims, identity key, cursor id continued or None)
        self.by_request: dict[int, tuple[dict, tuple, int | None]] = {}
        # cursor id -> (identity key, claims)
        self.by_cursor: dict[int, tuple[tuple, dict]] = {}

    @staticmethod
    def wanted(guards: dict[str, Guard], issuers: Mapping) -> bool:
        return bool(issuers) or any(
            g.spec.delegation != "allowed" or g.spec.scope
            for g in guards.values())

    def admit(self, raw: bytes, req_id: int, resp_to: int,
              head: tuple | None, guards: dict[str, Guard],
              connection: Mapping | None, verbose: bool = False
              ) -> tuple[bytes, tuple | None, dict | None, bytes | None]:
        """``(raw, head, claims, refusal)`` for one client command.

        ``claims`` is the delegated identity this command is judged as,
        or ``None`` for a plain one (judged as the connection). ``raw`` and
        ``head`` are the command as it will be forwarded -- the token
        gone, the tenant pinned.
        """
        body = head[1] if head else {}
        token, stripped, why = take_token(body)
        verb, cmd = _verb(stripped if stripped is not None else body)
        guard, named = _target(cmd, verb, guards)
        if why:
            return raw, head, None, _refused(req_id, named, why, verbose)
        more = cmd.get("getMore") if verb == "getMore" else None
        more = more if isinstance(more, int) and not isinstance(more, bool) else None
        if "killCursors" in body:
            for cid in body.get("cursors") or ():
                if isinstance(cid, int):
                    self.by_cursor.pop(cid, None)

        if token is None:
            bound = self.by_cursor.get(more) if more is not None else None
            if bound is not None:
                # A cursor keeps the identity that opened it.
                self.by_request[req_id] = (bound[1], bound[0], more)
                return raw, head, bound[1], None
            if (guard is not None and verb is not None
                    and guard.spec.delegation == "required"):
                return raw, head, None, _refused(
                    req_id, named, "this collection is read only by a "
                    "delegated identity -- an agent acting for a user -- and "
                    "this command carries none. Pass comment={'voyd': token}",
                    verbose)
            return raw, head, None, None

        # From here the command carries a token, and it is never forwarded
        # with it, whatever is decided below.
        if verb is None:
            return raw, head, None, _refused(
                req_id, named, "a delegated identity authorises reads "
                "(find, aggregate, count, distinct, getMore, explain) and "
                "nothing else", verbose)
        claims, key, refusal = self._identity(token, guard, named, req_id,
                                              connection, verbose)
        if refusal is not None:
            return raw, head, None, refusal
        assert claims is not None and stripped is not None

        if more is not None:
            bound = self.by_cursor.get(more)
            if bound is None:
                return raw, head, None, _refused(
                    req_id, named, "this cursor was not opened under a "
                    "delegated identity, and a cursor keeps the identity "
                    "that opened it", verbose)
            if bound[0] != key:
                return raw, head, None, _refused(
                    req_id, named, "this cursor was opened for a different "
                    "principal or actor, and a cursor keeps the identity "
                    "that opened it", verbose)

        if guard is not None and guard.spec.tenant and verb != "getMore":
            value, why = tenant_of(claims, guard.spec.tenant_via)
            if why:
                return raw, head, None, _refused(req_id, named, why, verbose)
            inner = stripped.get("explain")
            target = inner if isinstance(inner, Mapping) else stripped
            fixed, why = pin_tenant(target, guard.spec.tenant, value)
            if why or fixed is None:
                return raw, head, None, _refused(req_id, named,
                                                 why or "unpinnable", verbose)
            if isinstance(inner, Mapping):
                stripped = {**stripped, "explain": fixed}
            else:
                stripped = fixed

        flags = head[0] if head else 0
        ident = head[2] if head else None
        docs = head[3] if head else None
        raw = encode_sections(req_id, resp_to, flags, stripped, ident, docs)
        head = (flags, stripped, ident, docs or [])
        self.by_request[req_id] = (claims, key, more)
        return raw, head, claims, None

    def _identity(self, token: str, guard: Guard | None, named: str | None,
                  req_id: int, connection: Mapping | None, verbose: bool
                  ) -> tuple[dict | None, tuple, bytes | None]:
        def no(why: str) -> tuple[None, tuple, bytes]:
            return None, (), _refused(req_id, named, why, verbose)

        if not self.issuers:
            return no("this command carries a delegated token and the policy "
                      "declares no issuer() to verify it against")
        claimed = peek_issuer(token)
        expected = self.issuers.get(claimed) if claimed else None
        if expected is None:
            return no(f"the token names issuer {claimed!r}, which this policy "
                      f"does not trust")
        if connection is None:
            return no("the deployment did not say who this connection is, so "
                      "whether it may act for anybody is unknown")
        user = connection.get("user")
        if not expected.permits_connection(user):
            return no(f"connection user {user!r} may not present tokens from "
                      f"{expected.url}: a request identity narrows the "
                      f"connection's and must be one it may act for")
        if guard is not None and guard.spec.delegation == "forbidden":
            return no("agents may not read this collection "
                      "(delegation='forbidden')")
        now = self.clock()
        verdict = verify(token, self.keys(expected.url, now), now, expected,
                         require_actor=(guard is not None
                                        and guard.spec.delegation == "required"))
        if isinstance(verdict, Refusal):
            return no(f"the token is not believed ({verdict.reason}): "
                      f"{verdict.detail}")
        assert isinstance(verdict, Identity)
        scope = guard.spec.scope if guard is not None else None
        if scope and scope not in verdict.scopes:
            return no(f"this read needs the scope {scope!r}, and the token "
                      f"grants {list(verdict.scopes) or 'none'}")
        return verdict.claims(), verdict.key, None

    def reply(self, resp_to: int, raw: bytes) -> dict | None:
        """The identity a reply is judged as, or ``None`` for the connection's.

        Also where a cursor learns whom it belongs to: the reply that opens
        one is the only message carrying its id.
        """
        entry = self.by_request.pop(resp_to, None)
        if entry is None:
            return None
        claims, key, more = entry
        decoded = decode_op_msg(raw, LAZY)
        cursor = decoded[1].get("cursor") if decoded else None
        cid = cursor.get("id") if isinstance(cursor, Mapping) else None
        if isinstance(cid, int):
            if more is None and cid:
                self.by_cursor[cid] = (key, claims)
            elif more is not None and not cid:
                self.by_cursor.pop(more, None)
        return claims
