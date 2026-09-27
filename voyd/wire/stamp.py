"""The boundary's half of a signed context receipt: stamping what it served.

`voyd/attest.py` is the format and the verifier, and needs nothing but a
public key. This is the signer, and it is the *last* thing to touch a reply:
after `judge` (every rule, mask, sanitiser and transform), after the
backfill cut, after a pushed-down read's masks, after a virtual stage's
terminal recheck. A stamp signed any earlier would sign something other
than what the client received.

**What is stamped.** A cursor batch from a collection that declared
`attest=True`, answering a `find`, an `aggregate` whose every stage hands
back the stored document (reshaped at most by `$project`/`$addFields`/
`$set`/`$unset`), a read with a virtual stage, or a `getMore` continuing
one of those. Each document carrying an `_id` is stamped. What is not:
`count`, `distinct`, and any pipeline with a `$group`, `$bucket`,
`$replaceRoot`, `$unwind` or other stage whose output is not one stored
document -- there is no source `(_id, content)` pair to attest to, and a
stamp that called a group key a document id would be a signed misstatement.

**A stamp cannot be forged upstream of here, or kept.** `Guard` strips
`_voyd` from every document it is handed before any rule or transform sees
it, and this strips it again from whatever it is about to sign, so a stamp
written into the database, carried back by a client that saved what it
read, or produced by a transform or `@stage` is discarded and replaced.
The only stamps that leave this process are the ones this process made.

**One read, one chain.** Per connection, because a cursor is. A read opened
by a `find` gets a random id; its documents are numbered across every
`getMore`, and each stamp signs the link to the one before it, so a client
holding the whole window can verify all of it from the last signature. The
`getMore` is matched on its *request*, because the reply that drains a
cursor says `id: 0` and names nothing -- the same lesson `_was_reduced`
records.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Any, Mapping

from voyd import attest

from .codec import decode_op_msg, encode_op_msg
from .policy import PRESERVING_STAGES

# Stages that reshape a stored document without replacing it: the output is
# still one source document, with its `_id`, minus or plus some fields.
_SHAPING = frozenset({"$project", "$addFields", "$set", "$unset"})


class Signer:
    """The private key, the policy it signs for, and nothing else.

    Built once in the parent before any fork, like the vault's custody, so
    every worker signs with the same key. Holds no connection.
    """

    def __init__(self, private_key: Any, policy: str):
        self.key = private_key
        self.kid = attest.kid_of(private_key.public_key())
        self.policy = policy

    def stamp(self, doc: Mapping, *, ns: str, caller: str | None,
              read: str, pos: int, prev: str | None,
              principal: str | None = None, actor: str | None = None,
              token: str | None = None) -> dict:
        served = attest.strip(doc)
        payload = {"v": attest.VERSION, "alg": attest.ALG, "kid": self.kid,
                   "policy": self.policy, "ns": ns, "id": served["_id"],
                   "digest": attest.digest(served), "caller": caller,
                   "iat": _now(), "read": read, "pos": pos, "prev": prev,
                   "principal": principal, "actor": actor, "token": token}
        served[attest.FIELD] = attest.sign(payload, self.key)
        return served


def _now() -> str:
    at = datetime.now(timezone.utc)
    return at.strftime("%Y-%m-%dT%H:%M:%S.") + f"{at.microsecond // 1000:03d}Z"


def stampable(body: Mapping) -> str | None:
    """The collection a read's documents would be stamped for, or None."""
    for verb in ("find", "aggregate"):
        target = body.get(verb)
        if isinstance(target, str):
            break
    else:
        return None
    if verb == "aggregate":
        pipeline = body.get("pipeline")
        if not isinstance(pipeline, list):
            return None
        for stage in pipeline:
            if not isinstance(stage, Mapping) or len(stage) != 1:
                return None
            name = next(iter(stage))
            if name not in PRESERVING_STAGES and name not in _SHAPING:
                return None
    return target


class _Read:
    __slots__ = ("id", "pos", "prev")

    def __init__(self) -> None:
        self.id = secrets.token_hex(8)
        self.pos = 0
        self.prev: str | None = None


class Stamps:
    """One connection's open reads: which requests to stamp, and where."""

    __slots__ = ("_asked", "_more", "_open")

    def __init__(self) -> None:
        self._asked: dict[int, str] = {}      # request id -> collection
        self._more: dict[int, int] = {}       # getMore request id -> cursor
        self._open: dict[int, _Read] = {}     # cursor id -> its chain

    def note(self, body: Mapping, req_id: int, guards: Mapping) -> None:
        """Called on the request side, for a command about to be sent."""
        more = body.get("getMore")
        if isinstance(more, int) and more in self._open:
            self._more[req_id] = more
            return
        if "killCursors" in body and isinstance(body.get("cursors"), list):
            for cid in body["cursors"]:
                self._open.pop(cid, None)
            return
        target = stampable(body)
        if target is not None and _signer(guards, target) is not None:
            self._asked[req_id] = target

    def note_virtual(self, collection: str, req_id: int,
                     guards: Mapping) -> None:
        """A read with a `@stage`, answered by the boundary in one batch."""
        if _signer(guards, collection) is not None:
            self._asked[req_id] = collection

    def stamp(self, raw: bytes, resp_to: int, guards: Mapping,
              claims: Mapping | None,
              connection: Mapping | None = None) -> bytes:
        """Stamp a reply to a request `note` recorded. Else forward as is.

        ``claims`` is whom the read was judged as; ``connection`` is whom
        the deployment says the socket is. They differ for a delegated
        read, and the stamp names both: ``caller`` is the connection, and
        ``principal``/``actor``/``token`` the delegated identity.
        """
        if not self._asked and not self._more:
            return raw
        collection = self._asked.pop(resp_to, None)
        cursor_of = self._more.pop(resp_to, None)
        if collection is None and cursor_of is None:
            return raw
        decoded = decode_op_msg(raw)
        if decoded is None:
            return raw
        flags, reply = decoded
        cursor = reply.get("cursor")
        if not isinstance(cursor, Mapping):
            return raw
        key = "firstBatch" if "firstBatch" in cursor else (
            "nextBatch" if "nextBatch" in cursor else None)
        ns = cursor.get("ns")
        if key is None or not isinstance(ns, str) or "." not in ns:
            return raw
        named = ns.split(".", 1)[1]
        if collection is not None and named != collection:
            # A virtual read answers on the collection it read; anything
            # else is not a reply this request should have had.
            return raw
        signer = _signer(guards, named)
        if signer is None:
            return raw
        read = self._open.get(cursor_of) if cursor_of is not None else None
        if read is None:
            read = _Read()
        cursor_id = cursor.get("id")
        parties = _parties(claims)
        delegated = bool(claims and claims.get("delegated"))
        server = connection if delegated else claims
        caller = (attest.caller_hash(server.get("user"), server.get("db"))
                  if server else None)
        out, n = [], 0
        for doc in cursor[key]:
            if not isinstance(doc, Mapping) or "_id" not in doc:
                out.append(doc)
                continue
            stamped = signer.stamp(doc, ns=ns, caller=caller, read=read.id,
                                   pos=read.pos, prev=read.prev,
                                   principal=parties[0], actor=parties[1],
                                   token=parties[2])
            read.prev = attest.link(stamped[attest.FIELD])
            read.pos += 1
            n += 1
            out.append(stamped)
        if isinstance(cursor_id, int) and cursor_id:
            self._open[cursor_id] = read
        elif cursor_of is not None:
            self._open.pop(cursor_of, None)
        guard = guards.get(named)
        if guard is not None:
            guard.stamped += n
        reply = dict(reply)
        reply["cursor"] = dict(cursor)
        reply["cursor"][key] = out
        return encode_op_msg(int.from_bytes(raw[4:8], "little", signed=True),
                             resp_to, flags, reply)


def _parties(claims: Mapping | None
             ) -> tuple[str | None, str | None, str | None]:
    """(principal hash, actor hash, token hash) of a delegated identity's
    claims, or three ``None`` for a plain one."""
    if not claims or not claims.get("delegated"):
        return None, None, None
    principal = claims.get("principal")
    actor = claims.get("actor")
    token = claims.get("token")
    return (attest.principal_hash(principal.get("user"))
            if isinstance(principal, Mapping) else None,
            attest.actor_hash(actor.get("user"))
            if isinstance(actor, Mapping) else None,
            token if isinstance(token, str) else None)


def _signer(guards: Mapping, collection: str) -> Signer | None:
    guard = guards.get(collection)
    return getattr(guard, "signer", None) if guard is not None else None


def announce(guards: Mapping) -> list[str]:
    """What the startup banner says about attestation."""
    signed = sorted(n for n, g in guards.items()
                    if getattr(g, "signer", None) is not None)
    if not signed:
        return []
    signer = guards[signed[0]].signer
    return [f"voyd-wire: attesting {', '.join(signed)} under key "
            f"{signer.kid}, policy {signer.policy[:12]}. Every document "
            f"served from these carries a signed _voyd stamp; verify with "
            f"voyd-verify and the public key"]
