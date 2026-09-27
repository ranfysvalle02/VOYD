"""Signed context receipts: proving a chunk came through the boundary.

A refusal is invisible by design -- the document that was not served leaves
nothing behind -- so "this prompt was built only from what the boundary
admitted" has, until now, been a claim about a deployment rather than a
property of the prompt. This module makes it a property of the prompt.

A collection declared ``@guard("notes", attest=True)`` has every document it
serves stamped, last, after every rule, mask, sanitiser, transform and
virtual stage has had its turn. The stamp lives in the document, under one
reserved field::

    {"_id": ..., "text": "...", "_voyd": {
        "v": 2, "alg": "Ed25519", "kid": "3f9c0a1b2c3d4e5f",
        "policy": "<sha256 of the policy file>",
        "ns": "app.notes", "id": <the _id>,
        "digest": "<sha256 of the served document, minus _voyd>",
        "caller": "<sha256 of the server-reported user, or null>",
        "principal": "<sha256 of the user a delegated read was for, or null>",
        "actor": "<sha256 of the agent that read it, or null>",
        "token": "<hash of the delegated token's jti, or null>",
        "iat": "2026-09-27T12:00:00.123Z",
        "read": "<random id shared by one read>", "pos": 0,
        "prev": "<link of the stamp at pos-1, or null>",
        "sig": "<base64url Ed25519 signature>"}}

``caller`` is always the connection: whoever the deployment says
authenticated on the socket the read arrived on. A delegated read -- an
agent acting for a user, verified by the boundary (see
``voyd/engine/delegation.py``) -- also names the two parties it was served
to, ``principal`` and ``actor``, and the token that said so, each as a
domain-separated hash for the reason ``caller`` is one. ``principal_hash``
and ``actor_hash`` recompute them from a name, so an auditor who knows whom
to ask about can check a stamp without the stamp naming anybody. A plain
read carries ``null`` in all three.

Version 1 stamps, which predate those three fields, still verify: the
version names the set of fields that were signed. A check that asks about
a principal or an actor fails on a v1 stamp, because it cannot answer.

Everything a verifier needs is here and in this file: a public key and the
document as it was received. No proxy, no database, no network.

**Asymmetric, so a verifier cannot forge.** ``voyd.engine.attest`` signs
plans with an HMAC and says, correctly, that anyone who can verify can also
forge. That is the wrong property for a receipt handed to a client: the
client is exactly who must not be able to mint one. Ed25519 separates the
two -- the proxy holds the private key, every verifier holds only public
keys, and a verifier's key leaking costs nothing.

**The digest, and why it is not BSON bytes.** A stamp has to survive the
trip a document actually takes: a driver decodes it, an application holds it
as a native object, and somebody writes it to a JSON file for an auditor.
Raw BSON bytes do not survive that -- a driver reorders nothing, but JSON
tools and JavaScript objects do, and a Node client cannot tell an Int32
from an Int64 from a whole double at all. So the digest is SHA-256 over a
*type-tagged canonical JSON* encoding of the document (``canonical`` below):

    object     ["o", [[key, value], ...]]   keys sorted by code point
    array      ["a", [value, ...]]          order kept
    string     ["s", "..."]                 exact code points, no normalising
    number     ["n", "5"] / ["n", "0.25"]   every integer type is one type;
                                            a whole double is that integer;
                                            other doubles are Python's
                                            shortest round-trip repr
    bool/null  ["b", true] / ["null"]
    datetime   ["d", <epoch milliseconds>]  BSON's own precision; naive = UTC
    ObjectId   ["oid", "<hex>"]
    Decimal128 ["dec", "<str>"]
    binary     ["bin", <subtype>, "<base64>"]   uuid.UUID is subtype 4
    regex      ["re", pattern, flags]
    timestamp  ["ts", time, inc]
    min/max    ["min"] / ["max"]

serialised with sorted keys, no whitespace and ASCII escapes. It is exact
where a prompt could tell the difference (a changed character, a changed
number, a field added or removed, a nulled value) and deliberately blind
where it could not (key order, which integer width stored a 5). Those two
blind spots are stated, not discovered: an edit that only reorders keys or
widens an integer verifies.

**A read is a chain, not a Merkle tree.** Each stamp carries ``read`` (one
random id per cursor, stable across ``getMore``), ``pos`` (its place in the
whole read, not the batch) and ``prev`` (``link()`` of the stamp before it).
A Merkle root has to be computed over a set that is finished, and a cursor
is finished only when the client decides -- it may never ask for page two --
and there is no reply a driver would hand an application to carry a root in.
A chain needs no end: the stamp at ``pos=k`` signs the link to ``k-1``, so
verifying the last stamp of a window verifies, by hash, every stamp before
it. ``verify_all`` checks every signature anyway and reports, per read,
whether the positions it saw are contiguous from zero.

Nothing here opens a socket. ``bson`` is imported for its types, which every
MongoDB driver install already has; ``cryptography`` is the ``voyd[attest]``
extra and is imported only by the functions that need a key.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from bson import (Binary, Code, DBRef, Decimal128, Int64, MaxKey, MinKey,
                  ObjectId, Regex, Timestamp)
from bson.datetime_ms import DatetimeMS

__all__ = [
    "FIELD", "ALG", "VERSION", "Verdict", "Report",
    "canonical", "digest", "link", "caller_hash", "principal_hash",
    "actor_hash",
    "verify", "verify_all", "strip", "cite",
    "generate", "kid_of", "load_private_key", "load_public_keys",
    "public_pem", "sign",
]

FIELD = "_voyd"
ALG = "Ed25519"
VERSION = 2
VERSIONS = (1, 2)

# Domain separation. A signature over a stamp can never be replayed as a
# signature over a document digest, a caller hash, or anything else this
# package ever hashes, because each is prefixed with what it is.
_DOC = b"voyd-doc-v1\n"
_STAMP = b"voyd-stamp-v1\n"
_LINK = b"voyd-link-v1\n"
_CALLER = b"voyd-caller-v1\n"
_PRINCIPAL = b"voyd-principal-v1\n"
_ACTOR = b"voyd-actor-v1\n"

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

# The stamp's own fields, in the order they are documented, per version.
# `sig` is the one that is not signed.
_SIGNED_V1 = ("v", "alg", "kid", "policy", "ns", "id", "digest", "caller",
              "iat", "read", "pos", "prev")
_SIGNED = (*_SIGNED_V1, "principal", "actor", "token")
_FIELDS = {1: _SIGNED_V1, 2: _SIGNED}


def _signed(stamp: Mapping) -> tuple[str, ...]:
    """The fields this stamp's version signs. Unknown versions sign the
    current set, and fail verification on their version first."""
    v = stamp.get("v")
    return _FIELDS.get(v, _SIGNED) if isinstance(v, int) else _SIGNED


# ---------------------------------------------------------------------------
# Canonical form.

def _number(value: int | float) -> list:
    if isinstance(value, float):
        if math.isnan(value):
            return ["n", "nan"]
        if math.isinf(value):
            return ["n", "inf" if value > 0 else "-inf"]
        if value.is_integer():
            return ["n", str(int(value))]
        return ["n", repr(value)]
    return ["n", str(int(value))]


def _millis(value: datetime) -> int:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    delta = value - _EPOCH
    return (delta.days * 86_400_000 + delta.seconds * 1000
            + delta.microseconds // 1000)


def _tree(value: Any) -> Any:
    """The type-tagged form of one value. See the module docstring."""
    # bool before int: `True` is an `int` in Python and a different BSON type.
    if value is None:
        return ["null"]
    if isinstance(value, bool):
        return ["b", value]
    if isinstance(value, (int, float, Int64)):
        return _number(value)
    if isinstance(value, str):
        return ["s", value]
    if isinstance(value, Mapping):
        items = sorted(((str(k), _tree(v)) for k, v in value.items()),
                       key=lambda kv: kv[0])
        return ["o", [[k, v] for k, v in items]]
    if isinstance(value, (list, tuple)):
        return ["a", [_tree(v) for v in value]]
    if isinstance(value, datetime):
        return ["d", _millis(value)]
    if isinstance(value, DatetimeMS):
        return ["d", int(value)]
    if isinstance(value, ObjectId):
        return ["oid", str(value)]
    if isinstance(value, Decimal128):
        return ["dec", str(value)]
    if isinstance(value, uuid.UUID):
        return ["bin", 4, base64.b64encode(value.bytes).decode("ascii")]
    if isinstance(value, Binary):
        return ["bin", int(value.subtype),
                base64.b64encode(bytes(value)).decode("ascii")]
    if isinstance(value, (bytes, bytearray, memoryview)):
        return ["bin", 0, base64.b64encode(bytes(value)).decode("ascii")]
    if isinstance(value, Code):
        return ["code", str(value), _tree(value.scope) if value.scope else None]
    if isinstance(value, Regex):
        return ["re", str(value.pattern), str(value.flags)]
    if isinstance(value, re.Pattern):
        return ["re", value.pattern, str(value.flags)]
    if isinstance(value, Timestamp):
        return ["ts", value.time, value.inc]
    if isinstance(value, MinKey):
        return ["min"]
    if isinstance(value, MaxKey):
        return ["max"]
    if isinstance(value, DBRef):
        return ["ref", _tree(value.as_doc())]
    raise TypeError(
        f"no canonical form for {type(value).__name__}. A digest over a "
        f"value this file cannot name would verify something other than "
        f"what was served, so it refuses rather than guessing")


def canonical(value: Any) -> bytes:
    """The exact bytes a digest or signature is computed over."""
    return json.dumps(_tree(value), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def strip(doc: Mapping) -> dict:
    """The document without its stamp -- what a prompt should be built from.

    Always a new ``dict``; the stamp is metadata about the chunk, and
    handing it to a model is handing it forty bytes of base64 to read.
    """
    return {k: v for k, v in doc.items() if k != FIELD}


def digest(doc: Mapping) -> str:
    """SHA-256 of the served document, minus any stamp. Hex."""
    return hashlib.sha256(_DOC + canonical(strip(doc))).hexdigest()


def link(stamp: Mapping) -> str:
    """What the next stamp in the same read carries as ``prev``."""
    payload = {k: stamp.get(k) for k in _signed(stamp)}
    return hashlib.sha256(_LINK + canonical(payload)
                          + str(stamp.get("sig")).encode("ascii")).hexdigest()


def caller_hash(user: str | None, db: str | None) -> str | None:
    """The pseudonym a stamp records for who was served.

    A hash rather than the name, so a stamp copied into a prompt log does not
    also copy the user list. **Pseudonymous, not anonymous**: user names are
    a small space and anybody holding a list of them can hash each one and
    compare -- which is exactly what an auditor checking "was this served to
    alice" should be able to do, and what a stranger with the log and a
    guess can do too.
    """
    if not user:
        return None
    raw = _CALLER + f"{db or ''}\n{user}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def principal_hash(user: str | None) -> str | None:
    """The pseudonym a delegated stamp records for the user it was read for.

    The principal's name as the issuer's claim mapping produced it (``sub``
    by default), under its own label, so it never equals a ``caller`` or an
    ``actor`` hash of the same string. Pseudonymous in the same way
    ``caller_hash`` is. The issuer is not part of it: two identity
    providers naming the same ``sub`` produce the same hash.
    """
    if not user:
        return None
    return hashlib.sha256(_PRINCIPAL + user.encode("utf-8")).hexdigest()


def actor_hash(client: str | None) -> str | None:
    """The pseudonym a delegated stamp records for the agent that read it:
    the actor's mapped id (``act.sub`` by default), under its own label."""
    if not client:
        return None
    return hashlib.sha256(_ACTOR + client.encode("utf-8")).hexdigest()


def cite(doc: Mapping) -> str | None:
    """``voyd:<kid>:<digest8>`` -- a citation short enough to put in a prompt.

    Names the key and the first eight hex digits of the digest, which is
    enough for a person to find the chunk in a verified set and nowhere near
    enough to verify anything on its own. ``None`` for an unstamped document.
    """
    stamp = doc.get(FIELD)
    if not isinstance(stamp, Mapping):
        return None
    return f"voyd:{stamp.get('kid')}:{str(stamp.get('digest', ''))[:8]}"


# ---------------------------------------------------------------------------
# Keys.

def _crypto():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:                                  # pragma: no cover
        raise RuntimeError(
            "signed context receipts need the `cryptography` package: "
            "pip install 'voyd[attest]'") from exc
    return serialization, ed25519


def _raw_public(public_key: Any) -> bytes:
    serialization, _ = _crypto()
    return public_key.public_bytes(serialization.Encoding.Raw,
                                   serialization.PublicFormat.Raw)


def kid_of(public_key: Any) -> str:
    """The key id: the first 16 hex digits of SHA-256 over the raw key.

    Derived, never assigned, so two keys cannot share an id by accident and
    a verifier can recompute it from the key it was handed.
    """
    return hashlib.sha256(_raw_public(public_key)).hexdigest()[:16]


def generate() -> tuple[bytes, bytes, str]:
    """``(private PEM, public PEM, kid)`` for a fresh Ed25519 key."""
    serialization, ed25519 = _crypto()
    key = ed25519.Ed25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    return private, public_pem(key.public_key()), kid_of(key.public_key())


def public_pem(public_key: Any) -> bytes:
    serialization, _ = _crypto()
    return public_key.public_bytes(serialization.Encoding.PEM,
                                   serialization.PublicFormat.SubjectPublicKeyInfo)


def load_private_key(pem: bytes | str) -> Any:
    """An Ed25519 private key from PKCS#8 PEM. Raises on anything else."""
    serialization, ed25519 = _crypto()
    data = pem.encode("ascii") if isinstance(pem, str) else pem
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError(f"not an Ed25519 private key: {type(key).__name__}")
    return key


_PEM_BLOCK = re.compile(
    rb"-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----", re.S)


def load_public_keys(pem: bytes | str) -> dict[str, Any]:
    """Every public key in a PEM bundle, by kid.

    A bundle is how rotation works: a verifier keeps the retiring key and
    the new one side by side, stamps signed under either verify, and a key
    is retired by deleting its block. A stamp under a key that is not in the
    bundle is ``unknown kid`` -- never a pass.
    """
    serialization, ed25519 = _crypto()
    data = pem.encode("ascii") if isinstance(pem, str) else pem
    out: dict[str, Any] = {}
    for block in _PEM_BLOCK.findall(data):
        key = serialization.load_pem_public_key(block)
        if not isinstance(key, ed25519.Ed25519PublicKey):
            raise ValueError(f"not an Ed25519 public key: {type(key).__name__}")
        out[kid_of(key)] = key
    if not out:
        raise ValueError("no PUBLIC KEY blocks found")
    return out


def _b64(sig: bytes) -> str:
    return base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sign(payload: Mapping, private_key: Any) -> dict:
    """The stamp: ``payload`` plus ``sig``. Used by the proxy, and by tests."""
    body = {k: payload.get(k) for k in _signed(payload)}
    sig = private_key.sign(_STAMP + canonical(body))
    return {**body, "sig": _b64(sig)}


# ---------------------------------------------------------------------------
# Verification.

@dataclass(frozen=True)
class Verdict:
    """What one document's stamp proves. ``ok`` is the whole answer.

    ``reason`` is written for a person: *which* check failed, because "bad
    signature" and "edited after stamping" and "signed by a key you retired"
    are three different incidents.
    """

    ok: bool
    reason: str
    kid: str | None = None
    policy: str | None = None
    digest: str | None = None
    read: str | None = None
    pos: int | None = None
    citation: str | None = None


def verify_stamp(stamp: Mapping, public_keys: Mapping[str, Any]) -> Verdict:
    """Verify a receipt citation without claiming to have its document.

    A derived write carries only the signed ``_voyd`` metadata; the source
    document is re-read and judged independently by the boundary. Its digest
    cannot be checked against a metadata-only citation, but its signature,
    version and signer can.
    """
    if not isinstance(stamp, Mapping):
        return Verdict(False, "unstamped: no _voyd field")
    fields = _signed(stamp)
    missing = [key for key in (*fields, "sig") if key not in stamp]
    if missing:
        return Verdict(False, f"malformed stamp: missing {', '.join(missing)}")
    kid = stamp.get("kid")
    base: dict[str, Any] = dict(kid=kid if isinstance(kid, str) else None,
                policy=stamp.get("policy"), digest=stamp.get("digest"),
                read=stamp.get("read"), pos=stamp.get("pos"))
    if stamp.get("v") not in VERSIONS or stamp.get("alg") != ALG:
        return Verdict(False, f"unsupported stamp v={stamp.get('v')!r} "
                      f"alg={stamp.get('alg')!r}", **base)
    key = public_keys.get(kid) if isinstance(kid, str) else None
    if key is None:
        return Verdict(False, f"unknown kid {kid!r}: not signed by any key "
                      "this verifier holds", **base)
    try:
        sig = _unb64(str(stamp["sig"]))
        body = {key: stamp.get(key) for key in fields}
        key.verify(sig, _STAMP + canonical(body))
    except Exception:                                          # noqa: BLE001
        return Verdict(False, "bad signature: the stamp was altered, or "
                      "was not made by this key", **base)
    return Verdict(True, "verified", **base)


def verify(doc: Mapping, public_keys: Mapping[str, Any], *,
           policy: str | Iterable[str] | None = None,
           principal: str | None = None,
           actor: str | None = None) -> Verdict:
    """Did this document come through the boundary, unmodified?

    Checks, in order, and stops at the first failure: the stamp is present
    and well formed; its ``kid`` is one of ``public_keys``; the signature
    over the stamp is valid under that key; the document's digest is the one
    the stamp signed; its ``_id`` is the one the stamp names; and, if
    ``policy`` is given (one hash or several), the policy it was served
    under is one of them; if ``principal`` or ``actor`` is given (a name,
    not a hash), the delegated read was served for that user or to that
    agent. A stamp that passes the signature and fails the digest is the
    interesting case: authentic receipt, edited document.
    """
    stamp = doc.get(FIELD) if isinstance(doc, Mapping) else None
    if not isinstance(stamp, Mapping):
        return Verdict(False, "unstamped: no _voyd field")
    verified = verify_stamp(stamp, public_keys)
    base: dict[str, Any] = dict(kid=verified.kid, policy=verified.policy,
                digest=verified.digest, read=verified.read,
                pos=verified.pos, citation=cite(doc))
    if not verified.ok:
        return Verdict(False, verified.reason, **base)
    try:
        actual = digest(doc)
    except TypeError as exc:
        return Verdict(False, f"cannot digest: {exc}", **base)
    if actual != stamp.get("digest"):
        return Verdict(False, "digest mismatch: the document was edited "
                              "after the boundary stamped it", **base)
    if "_id" not in doc or canonical(doc["_id"]) != canonical(stamp.get("id")):
        return Verdict(False, "id mismatch: this stamp belongs to another "
                              "document", **base)
    if policy is not None:
        wanted = {policy} if isinstance(policy, str) else set(policy)
        if stamp.get("policy") not in wanted:
            return Verdict(False, f"stale policy: served under "
                                  f"{str(stamp.get('policy'))[:12]}, not the "
                                  f"expected one", **base)
    for side, name, hashed in (("principal", principal, principal_hash),
                               ("actor", actor, actor_hash)):
        if name is None:
            continue
        if side not in stamp:
            return Verdict(False, f"{side} unknown: a v{stamp.get('v')} "
                                  f"stamp does not record one", **base)
        if stamp.get(side) is None:
            return Verdict(False, f"not delegated: this read names no "
                                  f"{side}, so it was not served "
                                  f"{'for' if side == 'principal' else 'to'} "
                                  f"{name!r}", **base)
        if stamp.get(side) != hashed(name):
            return Verdict(False, f"{side} mismatch: served "
                                  f"{'for' if side == 'principal' else 'to'} "
                                  f"somebody other than {name!r}", **base)
    return Verdict(True, "verified", **base)


@dataclass
class Report:
    """A set of documents -- a context window -- verified together."""

    verdicts: list[Verdict]
    # read id -> (positions seen, contiguous from zero)
    reads: dict[str, tuple[int, bool]] = field(default_factory=dict)
    broken_links: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return (all(v.ok for v in self.verdicts) and bool(self.verdicts)
                and not self.broken_links)


def verify_all(docs: Iterable[Mapping], public_keys: Mapping[str, Any], *,
               policy: str | Iterable[str] | None = None,
               principal: str | None = None,
               actor: str | None = None) -> Report:
    """``verify`` for each, plus the chain between stamps of one read.

    Two stamps at consecutive positions of the same read must be linked:
    the later one's ``prev`` is ``link()`` of the earlier. A break is a
    substitution -- a stamp from another read, or a document from this read
    edited and re-stamped by somebody holding a key -- and fails the whole
    set. A gap (positions 0, 1, 4) is not a failure: a context window is
    allowed to be a subset of a read, and ``reads`` reports which were whole.
    """
    docs = list(docs)
    verdicts = [verify(d, public_keys, policy=policy, principal=principal,
                       actor=actor) for d in docs]
    by_read: dict[str, dict[int, Mapping]] = {}
    for doc, verdict in zip(docs, verdicts):
        if verdict.ok and isinstance(verdict.read, str) \
                and isinstance(verdict.pos, int):
            by_read.setdefault(verdict.read, {})[verdict.pos] = doc[FIELD]
    reads: dict[str, tuple[int, bool]] = {}
    broken: list[str] = []
    for read, stamps in by_read.items():
        positions = sorted(stamps)
        reads[read] = (len(positions), positions == list(range(len(positions))))
        for pos in positions:
            if pos == 0 and stamps[pos].get("prev") is not None:
                broken.append(f"{read}@0: first stamp names a predecessor")
            if pos - 1 in stamps and \
                    stamps[pos].get("prev") != link(stamps[pos - 1]):
                broken.append(f"{read}@{pos}: does not follow {pos - 1}")
    return Report(verdicts, reads, broken)
