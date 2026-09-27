"""A connection that authenticates with a delegated token: ``MONGODB-OIDC``.

Current drivers speak ``MONGODB-OIDC`` with a callback that returns an
access token. An agent runtime already holds a delegated one, hands it to
the callback, and the driver puts it in ``saslStart``::

    MongoClient("mongodb://boundary:27099/?directConnection=true",
                authMechanism="MONGODB-OIDC",
                authMechanismProperties={"OIDC_CALLBACK": callback})

The conversation, from the MongoDB OIDC authentication spec: the payload
is BSON. With a callback the driver sends one step, ``saslStart`` carrying
``{jwt: <token>}``. A human flow may send ``{n: <principal name>}`` first,
be answered with the identity provider's ``{issuer, clientId}``, and send
the token in a ``saslContinue``.

The boundary reads the token out of that payload, verifies it with the
same ``verify`` a ``comment`` token meets, and **binds** the connection:
every read on it is then delegated as that identity (``Delegations``), and
a ``comment`` token on it may only narrow it -- the same principal, or the
command is refused. Two modes, chosen per deployment with ``voyd-wire
--oidc``:

    terminate     the boundary answers the conversation itself, and the
                  deployment never sees the token or the user. Upstream,
                  the connection is the boundary's own: unauthenticated,
                  or authenticated with the SCRAM credentials in
                  ``--target`` (``upstream.authenticate``). A bound
                  connection may read and nothing else, because every
                  other command would run with the boundary's own
                  privileges. A token that has expired answers the next
                  command with ``ReauthenticationRequired`` (391), which
                  a driver answers by calling its callback again.
    passthrough   the conversation continues to the deployment, which
                  validates the token too (Atlas workload identity). The
                  boundary verifies it first and refuses one it does not
                  believe without forwarding it. After the server says
                  yes, and before the next command is forwarded, the
                  server-reported user must be the one the issuer's
                  ``server_user`` names for the token's principal, in
                  ``$external``, or the connection is closed.

Speculative authentication -- a token riding in the handshake ``hello``
-- is removed from the handshake in both modes, so a driver always
authenticates in a conversation this module sees. That costs one round
trip per new connection and closes the one path by which a token could
authenticate a connection the boundary never verified.

Nothing here owns a socket. The pump asks, forwards or answers, and asks
the deployment ``connectionStatus`` when ``check`` says a passthrough
conversation has succeeded.
"""

from __future__ import annotations

import struct
from typing import Any, Callable, Mapping

import bson

from voyd.engine.delegation import Identity, Refusal

from ..codec import OP_QUERY, decode_op_msg, encode_op_msg
from ..identity import claims_from
from .delegation import Delegations
from .refusals import writes_elsewhere

MECHANISM = "MONGODB-OIDC"
PASSTHROUGH = "passthrough"
TERMINATE = "terminate"
MODES = (PASSTHROUGH, TERMINATE)
EXTERNAL = "$external"

HELLOS = frozenset({"hello", "isMaster", "ismaster"})
# What a terminated connection may send before it has authenticated.
BEFORE_AUTH = frozenset({*HELLOS, "ping", "buildInfo", "buildinfo",
                         "saslStart", "saslContinue", "endSessions",
                         "logout"})
# And after: reads, and what a driver needs to manage the cursors and
# sessions those reads open. Anything else would run upstream with the
# boundary's own credentials, not the token's.
WHILE_BOUND = frozenset({*BEFORE_AUTH, "find", "aggregate", "count",
                         "distinct", "getMore", "killCursors", "explain",
                         "listCollections", "listIndexes"})

AUTHENTICATION_FAILED = 18
UNAUTHORIZED = 13
REAUTHENTICATE = 391


def _error(req_id: int, code: int, name: str, why: str) -> bytes:
    return encode_op_msg(req_id, req_id, 0, {
        "ok": 0.0, "code": code, "codeName": name,
        "errmsg": f"voyd-wire: {why}"})


def _payload(body: Mapping) -> dict | None:
    raw = body.get("payload")
    if isinstance(raw, bson.Binary) or isinstance(raw, (bytes, bytearray)):
        try:
            got = bson.decode(bytes(raw))
        except Exception:                                     # noqa: BLE001
            return None
        return dict(got)
    return None


def _verb(body: Mapping) -> str | None:
    return next(iter(body), None) if body else None


class Oidc:
    """One connection's ``MONGODB-OIDC`` conversation, and what it bound."""

    def __init__(self, mode: str, delegations: Delegations, *,
                 verbose: bool = False,
                 clock: Callable[[], float] | None = None):
        if mode not in MODES:
            raise ValueError(f"--oidc={mode!r} is not one of {list(MODES)}")
        self.mode = mode
        self.delegations = delegations
        self.verbose = verbose
        self.clock = clock if clock is not None else delegations.clock
        # Terminate: the conversation a principal step opened, if any.
        self.conversation = 0
        # Passthrough: tokens verified here and forwarded, by request id,
        # and the one the server has since accepted, still to be checked
        # against what the server says this connection is.
        self.pending: dict[int, Identity] = {}
        self.check: Identity | None = None

    # ---- the request side ------------------------------------------------

    def request(self, raw: bytes, req_id: int, body: Mapping
                ) -> tuple[bytes, bytes | None]:
        """``(raw to forward, answer)``. An answer goes back to the client
        instead of anything being forwarded."""
        verb = _verb(body)
        if verb in HELLOS:
            return self._hello(raw, req_id, body), None
        if verb == "saslStart":
            return self._start(raw, req_id, body)
        if verb == "saslContinue":
            return self._continue(raw, req_id, body)
        if self.mode != TERMINATE:
            return raw, None
        bound = self.delegations.bound
        if bound is None:
            if verb in BEFORE_AUTH:
                return raw, None
            return raw, self._say(_error(
                req_id, UNAUTHORIZED, "Unauthorized",
                f"{verb} requires authentication: this boundary "
                f"authenticates connections with {MECHANISM}"))
        if self.clock() >= bound.expires:
            return raw, self._say(_error(
                req_id, REAUTHENTICATE, "ReauthenticationRequired",
                "the token this connection authenticated with has expired"))
        if verb not in WHILE_BOUND or writes_elsewhere(body):
            return raw, self._say(_error(
                req_id, UNAUTHORIZED, "Unauthorized",
                f"{verb} is not a read. A connection authenticated by a "
                f"delegated token reads, and anything else would run with "
                f"the boundary's own credentials"))
        return raw, None

    def _say(self, answer: bytes) -> bytes:
        if self.verbose:
            decoded = decode_op_msg(answer)
            if decoded is not None:
                print(f"  voyd: {decoded[1].get('errmsg')}", flush=True)
        return answer

    def _hello(self, raw: bytes, req_id: int, body: Mapping) -> bytes:
        drop = {"speculativeAuthenticate"}
        if self.mode == TERMINATE:
            # The deployment's mechanisms are the boundary's credentials,
            # not anything a client authenticates with here.
            drop.add("saslSupportedMechs")
        if not drop & set(body):
            return raw
        decoded = decode_op_msg(raw)
        if decoded is None:
            return raw
        kept = {k: v for k, v in decoded[1].items() if k not in drop}
        return encode_op_msg(req_id, int.from_bytes(raw[8:12], "little",
                                                    signed=True),
                             decoded[0], kept)

    def legacy(self, raw: bytes) -> bytes:
        """The same, for a handshake sent as a legacy ``OP_QUERY``."""
        if len(raw) < 21 or struct.unpack("<i", raw[12:16])[0] != OP_QUERY:
            return raw
        try:
            at = raw.index(b"\x00", 20) + 1          # fullCollectionName
            start = at + 8                            # skip, return
            size = struct.unpack("<i", raw[start:start + 4])[0]
            query = bson.decode(raw[start:start + size])
        except (ValueError, struct.error, Exception):  # noqa: BLE001
            return raw
        if _verb(query) not in HELLOS:
            return raw
        drop = {"speculativeAuthenticate"}
        if self.mode == TERMINATE:
            drop.add("saslSupportedMechs")
        if not drop & set(query):
            return raw
        kept = bson.encode({k: v for k, v in query.items() if k not in drop})
        body = raw[16:start] + kept + raw[start + size:]
        return struct.pack("<i", 16 + len(body)) + raw[4:16] + body

    def _start(self, raw: bytes, req_id: int, body: Mapping
               ) -> tuple[bytes, bytes | None]:
        if body.get("mechanism") != MECHANISM:
            if self.mode == TERMINATE:
                return raw, self._fail(req_id, f"this boundary authenticates "
                                               f"connections with {MECHANISM} "
                                               f"only, not "
                                               f"{body.get('mechanism')!r}")
            # Somebody else's mechanism, the deployment's to judge. The
            # connection is no longer the token's.
            self.delegations.bind(None)
            return raw, None
        payload = _payload(body)
        if payload is None:
            return raw, self._fail(req_id, "the MONGODB-OIDC payload is not "
                                           "a BSON document")
        if "jwt" in payload:
            return self._token(raw, req_id, payload["jwt"], 1)
        if self.mode == PASSTHROUGH:
            return raw, None
        # The principal step: say which identity provider to ask.
        issuers = sorted(self.delegations.issuers)
        if len(issuers) != 1:
            return raw, self._fail(req_id, "this boundary trusts more than "
                                           "one issuer, so it cannot name "
                                           "one; configure the driver with "
                                           "a callback that returns a token")
        self.conversation = 1
        return raw, encode_op_msg(req_id, req_id, 0, {
            "conversationId": 1, "done": False,
            "payload": bson.Binary(bson.encode({"issuer": issuers[0]})),
            "ok": 1.0})

    def _continue(self, raw: bytes, req_id: int, body: Mapping
                  ) -> tuple[bytes, bytes | None]:
        payload = _payload(body)
        if self.mode == PASSTHROUGH:
            if payload is not None and "jwt" in payload:
                return self._token(raw, req_id, payload["jwt"], 0)
            return raw, None
        if not self.conversation or body.get("conversationId") != \
                self.conversation:
            return raw, self._fail(req_id, "no MONGODB-OIDC conversation "
                                           "with that id is open here")
        if payload is None or "jwt" not in payload:
            return raw, self._fail(req_id, "a saslContinue here carries "
                                           "{jwt: <token>}")
        return self._token(raw, req_id, payload["jwt"], self.conversation)

    def _token(self, raw: bytes, req_id: int, token: Any,
               conversation: int) -> tuple[bytes, bytes | None]:
        verdict = self.delegations.verify(token) if isinstance(token, str) \
            else Refusal("malformed", "the jwt is not a string")
        if isinstance(verdict, Refusal):
            if self.mode == TERMINATE:
                self.delegations.bind(None)
            self.conversation = 0
            return raw, self._fail(req_id, f"the token is not believed "
                                           f"({verdict.reason}): "
                                           f"{verdict.detail}")
        if self.mode == PASSTHROUGH:
            self.pending[req_id] = verdict
            return raw, None
        self.delegations.bind(verdict)
        self.conversation = 0
        if self.verbose:
            actor = verdict.actor["user"] if verdict.actor else None
            print(f"  voyd: this connection authenticated as "
                  f"{verdict.principal['user']!r}"
                  + (f" through {actor!r}" if actor else "")
                  + f" ({MECHANISM}, {verdict.issuer})", flush=True)
        return raw, encode_op_msg(req_id, req_id, 0, {
            "conversationId": conversation or 1, "done": True,
            "payload": bson.Binary(b""), "ok": 1.0})

    def _fail(self, req_id: int, why: str) -> bytes:
        return self._say(_error(req_id, AUTHENTICATION_FAILED,
                                "AuthenticationFailed", why))

    # ---- the reply side --------------------------------------------------

    def reply(self, resp_to: int, raw: bytes) -> None:
        """Passthrough: note the server accepting a token verified here."""
        identity = self.pending.pop(resp_to, None)
        if identity is None:
            return
        decoded = decode_op_msg(raw)
        reply = decoded[1] if decoded else {}
        if reply.get("ok") and reply.get("done"):
            self.check = identity

    def settle(self, status: Mapping | None) -> str | None:
        """Passthrough: bind the accepted token if the server agrees whom
        it names. ``None`` when bound; otherwise why the connection closes.
        """
        identity, self.check = self.check, None
        if identity is None:
            return None
        if status is None or not status.get("ok"):
            self.delegations.bind(None)
            return ("the deployment did not answer connectionStatus after "
                    "MONGODB-OIDC, so whether it agrees whom the token "
                    "names is unknown")
        said = claims_from(status)
        issuer = self.delegations.issuers.get(identity.issuer)
        want = (issuer.server_name(identity.principal["user"])
                if issuer is not None else None)
        if said.get("user") != want or said.get("db") != EXTERNAL:
            self.delegations.bind(None)
            return (f"the deployment says this connection is "
                    f"{said.get('db')}.{said.get('user')}, and the verified "
                    f"token names {EXTERNAL}.{want}")
        self.delegations.bind(identity)
        return None

