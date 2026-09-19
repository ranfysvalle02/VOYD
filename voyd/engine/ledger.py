"""A refusal is an event. This is the record of it, and it is tamper-evident.

``Admission`` makes forgetting *true* -- the next read refuses the fact. It
does not make forgetting **provable**, and those are different products.
``receipts()`` is a set of counters in the memory of one replica: it answers
"how much has this process refused since it started", which is a dashboard,
not evidence. Ask the question an auditor actually asks --

    *show me that this document stopped being reachable at 14:02, and show me
    that the record has not been edited since*

-- and counters have nothing to say. Neither does a log line, because the
party holding the log is the party being audited.

So every revocation appends an entry to an **append-only hash chain**:

    hash_n = sha256(seq_n || hash_{n-1} || canonical(entry_n))

Each entry commits to its predecessor, so the chain has the property that
matters: you cannot remove an entry, reorder two, or backdate one without
changing every hash after it. Verification is arithmetic over public data --
``verify()`` needs no secret and recomputes the whole chain.

**What this proves, exactly.** Integrity of the record, and nothing else. Be
precise about the boundaries, because a proof that overstates itself is worse
than no proof:

- It proves the sequence of recorded refusals has not been altered *since it
  was written*.
- It does **not** prove the rows were deleted. Nothing in this system claims
  that, which is the entire thesis: the row is deliberately still on disk,
  unreachable first and erased on the scope's deadline.
- It does **not** ledger reads. Recording every refused hit would mean a
  write per refused document per query, and the read path refuses tens of
  thousands of documents in a scope's lifetime. That refusals *happen* on
  read is a property of the code, proven by the test suite; that a revocation
  happened, when, and on whose instruction is a fact about the world, and
  only the second kind belongs in a ledger.
- On its own it does **not** stop the operator of this database from
  rewriting the chain from entry zero. A hash chain is only as strong as the
  most recent hash somebody *else* is holding.

**Both directions, or the chain is intact and wrong.** A mark that can be
imposed and lifted is a two-state transition, and a record of only the
imposing half has a failure mode worse than having no record: the chain
attests that a fact stopped being reachable at 14:02, the fact is reachable,
and ``verify()`` passes. Nothing about a hash chain detects an event that was
never written to it. So every lift appends a ``lifted`` entry naming the rule
it removed, and the pair -- impose then lift -- is what an auditor
reconstructs the document's reachability from.

That is also the reason ``revoke`` has no inverse. If it did, this collection
would need to record un-erasures, and an un-erasure is a claim the rest of
the system cannot support: the row is already scheduled for the reaper, so
the chain would be attesting to a state transition whose subject no longer
exists. A reason is reversible on the chain only where it is reversible in
the data. See ``Irreversible`` in ``errors.py``.

That last limitation is the one with a fix, and it shapes the API. Every
``append`` returns its entry's hash, and the HTTP layer hands that back in the
``forget`` response. The caller who asked for the erasure walks away with a
hash that was computed before any dispute existed -- so a later chain that
does not contain it is falsified by a receipt the auditee never held. The
signature below is the weaker half; the client's copy is the strong one.

**The signature is an attestation, not a public proof.** ``head()`` is signed
with HMAC-SHA256, which is symmetric: it proves the entry was produced by
something holding the key. Anyone with the key can also mint one, so it
authenticates the chain head to a *verifier who trusts the key holder* -- your
own auditor, another service -- and does not make the head independently
verifiable by a third party. Asymmetric signatures would, and would cost a
dependency this package deliberately does not have -- the engine installs as a
MongoDB driver and nothing else. The chain is the part that needs no trust;
the signature is convenience on top, and is labelled as such in every
response.

**The ledger does not expire.** Every other collection here inherits one
deadline from one document, which is the argument of the whole repository. The
ledger is the deliberate exception, and it has to be: a proof that is
collected by the same TTL index as the thing it proves is not a proof, it is a
coincidence with a short life. So there is no TTL index on this collection.
Entries are small, bounded by the number of *revocations* rather than the
number of documents, and keeping them is the point. Note what an entry
therefore must not contain: the text of the document it refers to. An audit
record that quotes the secret it was asked to forget is a new copy of the
secret, exempted from every deadline in the system. Ids and reasons only.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import random
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from pymongo.errors import DuplicateKeyError

from .time import aware, now

log = logging.getLogger("engine.ledger")

GENESIS = "0" * 64      # the previous hash of the first entry


def truncate(at: datetime) -> datetime:
    """Drop sub-millisecond precision, before hashing and before storing.

    BSON dates are milliseconds. ``now()`` is microseconds. So an entry
    hashed as written and re-hashed as read back disagree on the timestamp,
    and *every* entry verifies as forged -- which is how this was found: the
    chain was internally consistent and completely unverifiable, the worst
    of the available outcomes, because it would have been discovered by
    whoever was relying on it.

    The fix belongs here rather than in the comparison. Rounding at verify
    time would mean the stored value is not the value that was signed, and a
    verifier reconstructing the hash from the document would have to know to
    apply the same rounding -- a rule that has to be remembered, which this
    codebase has opinions about. Instead the truncated instant is what gets
    written, so the bytes in the database *are* the bytes that were hashed.
    """
    return at.replace(microsecond=(at.microsecond // 1000) * 1000)


def _stamp(value: Any) -> Any:
    """Canonicalise one value for hashing.

    Hashes are compared across processes, drivers and years, so what goes
    into one must not depend on how this particular client decodes BSON, or
    on where the machine doing the comparing is. A hash that depended on
    either would verify where it was written and read as forged where it was
    audited, which is the failure that makes people stop trusting the tool
    rather than the data.

    Datetimes therefore go through ``aware()``: **naive means UTC**, because
    that is what BSON stored. The first version of this called
    ``astimezone(tz=None)``, which assumes *local* time for a naive value --
    so a chain written by a ``tz_aware=False`` client would have hashed
    differently in London and in New York, which is precisely the property
    this paragraph claims to rule out. The engine already had the rule; it
    just was not the one being used here.

    Everything else exotic -- an ObjectId, a Binary -- becomes its ``str``.
    """
    if isinstance(value, datetime):
        return aware(value).isoformat()
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {k: _stamp(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_stamp(v) for v in value]
    return str(value)


def canonical(entry: dict) -> str:
    """The exact bytes a hash is taken over.

    Sorted keys, no whitespace, and the chain fields themselves excluded --
    ``hash`` cannot be an input to ``hash``, and ``_id`` is assigned by the
    database, so including it would make a chain unverifiable after any
    migration that rewrites ids.
    """
    body = {k: _stamp(v) for k, v in entry.items()
            if k not in ("hash", "_id")}
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def digest(entry: dict) -> str:
    """``sha256(seq || prev || canonical(body))`` as hex."""
    material = f'{entry["seq"]}|{entry["prev"]}|{canonical(entry)}'
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class LedgerSpec:
    collection: str = "refusals"
    tenant: str | None = None


class Ledger:
    """An append-only, hash-chained record of refusal events.

    A trait: ``ensure()`` gives it the one index that makes the chain a chain
    rather than a bag -- ``(tenant, seq)`` unique. That index is load-bearing,
    not an optimisation. Two concurrent appends both read the same head and
    both compute ``seq = n + 1``; without the constraint one silently
    overwrites the other's position and the chain forks into two valid-looking
    histories. With it, the loser gets a ``DuplicateKeyError``, re-reads the
    head and re-links. A ledger that can fork under load is not a ledger.
    """

    kind = "ledger"

    def __init__(self, db, spec: LedgerSpec | None = None, *,
                 key: bytes | str | None = None):
        self.db = db
        self.spec = spec or LedgerSpec()
        self.collection = self.spec.collection
        self.tenant = self.spec.tenant
        self._key = key.encode() if isinstance(key, str) else key
        # One in-process writer per chain. Appending is *inherently* serial:
        # an entry cannot be built until the hash of its predecessor exists,
        # so concurrent writers cannot be made to cooperate, only to retry.
        # Retrying is the fallback, not the plan -- twelve concurrent
        # revocations against an unsynchronised writer exhausted five
        # attempts each and raised, which is a lock implemented badly.
        #
        # Per-replica, therefore partial, exactly like the rate limiter here:
        # across processes the unique index is the backstop and the retry
        # below is what handles it. The honest trade for not needing a lock
        # service, and the first thing to revisit if append volume ever
        # justifies one.
        self._locks: dict[Any, asyncio.Lock] = {}

    # ---- schema --------------------------------------------------------

    async def ensure(self) -> bool:
        """The uniqueness constraint, and deliberately no TTL index.

        Every other collection in this engine expires. This one must not --
        see the module docstring. The absence is the feature, so it is
        asserted by a test rather than left to be noticed.
        """
        await self.db[self.collection].create_index(
            [(f, 1) for f in self._scope_fields()] + [("seq", 1)],
            unique=True, name="chain_seq")
        await self.db[self.collection].create_index(
            [(f, 1) for f in self._scope_fields()] + [("subject", 1)],
            name="chain_subject")
        return True

    def _scope_fields(self) -> list[str]:
        return [self.tenant] if self.tenant else []

    def _scope(self, tenant: Any) -> dict:
        if not self.tenant:
            return {}
        if tenant is None:
            raise ValueError(
                f"{self.collection} is scoped by {self.tenant!r}; an entry "
                "without one would join another tenant's chain")
        return {self.tenant: tenant}

    # ---- append --------------------------------------------------------

    async def append(self, event: str, *, tenant: Any = None,
                     reason: str | None = None,
                     subject: Any = None, count: int | None = None,
                     detail: dict | None = None,
                     at: datetime | None = None,
                     attempts: int = 5) -> dict:
        """Link one event onto the end of the chain and return it.

        The return value is the receipt: give it to whoever asked for the
        refusal. Their copy of ``hash`` is what makes a later rewrite of this
        chain detectable by somebody other than its owner.

        ``detail`` is for identifiers and decisions -- who asked, which
        ticket, which policy. Not for document text: see the module
        docstring on why an audit record must not become an exempt copy of
        the secret.
        """
        scope = self._scope(tenant)
        lock = self._locks.setdefault(_stamp(tenant), asyncio.Lock())
        async with lock:
            return await self._append_linked(
                event, scope=scope, tenant=tenant, reason=reason,
                subject=subject, count=count, detail=detail, at=at,
                attempts=attempts)

    async def _append_linked(self, event, *, scope, tenant, reason, subject,
                             count, detail, at, attempts) -> dict:
        # Truncated before it is hashed *and* before it is stored, so the
        # document in the database hashes to the value it carries. See
        # ``truncate``.
        stamp = truncate(at or now())
        for attempt in range(1, attempts + 1):
            head = await self.head_entry(tenant=tenant)
            entry = {
                **scope,
                "seq": (head["seq"] + 1) if head else 0,
                "prev": head["hash"] if head else GENESIS,
                "at": stamp,
                "event": event,
                "reason": reason,
                "subject": _stamp(subject),
                "count": count,
                "detail": _stamp(detail) if detail else None,
            }
            entry["hash"] = digest(entry)
            try:
                await self.db[self.collection].insert_one(dict(entry))
            except DuplicateKeyError:
                # Somebody took this seq first. Re-read the head and re-link:
                # the chain stays linear, which is the whole reason the index
                # is unique. Never a silent overwrite.
                # A writer in another process took this position. Re-read
                # the head and re-link. Jittered, because the whole point of
                # a collision is that two writers are in step and retrying
                # in step keeps them there.
                log.debug("ledger seq %s taken; re-linking (attempt %d)",
                          entry["seq"], attempt)
                await asyncio.sleep(random.uniform(0, 0.02 * attempt))
                continue
            log.info("ledger %s seq=%s event=%s reason=%s subject=%s",
                     self.collection, entry["seq"], event, reason,
                     entry["subject"])
            entry.pop("_id", None)
            return entry
        raise RuntimeError(
            f"{self.collection}: could not append after {attempts} attempts; "
            "the chain head is moving faster than this writer can link to it")

    # ---- read ----------------------------------------------------------

    async def head_entry(self, *, tenant: Any = None) -> dict | None:
        return await self.db[self.collection].find_one(
            self._scope(tenant), sort=[("seq", -1)])

    async def entries(self, *, tenant: Any = None, subject: Any = None,
                      limit: int = 0) -> list[dict]:
        q = self._scope(tenant)
        if subject is not None:
            q["subject"] = _stamp(subject)
        cur = self.db[self.collection].find(q, sort=[("seq", 1)])
        if limit:
            cur = cur.limit(limit)
        return [e async for e in cur]

    # ---- verify --------------------------------------------------------

    async def verify(self, *, tenant: Any = None) -> dict:
        """Recompute the chain. No secret required, which is the point.

        Reports the *first* break and stops describing the chain as intact
        from there on. Three distinct failures, kept distinct because they
        mean different things to whoever is reading:

        ``gap``       a missing sequence number: an entry was deleted.
        ``broken``    ``prev`` does not match the previous entry's hash: the
                      order was changed, or an entry was inserted.
        ``forged``    the stored hash is not the hash of the stored body: the
                      entry itself was edited after the fact.
        """
        chain = await self.entries(tenant=tenant)
        prev = GENESIS
        for i, entry in enumerate(chain):
            if entry["seq"] != i:
                return self._broken("gap", entry, expected=i)
            if entry["prev"] != prev:
                return self._broken("broken", entry, expected=prev)
            if entry["hash"] != digest(entry):
                return self._broken("forged", entry, expected=digest(entry))
            prev = entry["hash"]
        return {"intact": True, "entries": len(chain), "head": prev,
                "signature": self.sign(prev),
                "signed": self._key is not None}

    @staticmethod
    def _broken(fault: str, entry: dict, *, expected: Any) -> dict:
        log.error("ledger chain %s at seq=%s (expected %s)",
                  fault, entry.get("seq"), expected)
        return {"intact": False, "fault": fault, "at_seq": entry.get("seq"),
                "expected": str(expected), "found": str(entry.get("hash"))}

    def sign(self, head: str) -> str | None:
        """HMAC over the chain head, or ``None`` when no key is configured.

        ``None`` is not a degraded signature, it is the absence of one, and
        the responses that carry it say ``signed: false`` rather than
        implying an attestation nobody made. An unsigned chain is still
        tamper-evident -- ``verify()`` needs no key.
        """
        if not self._key:
            return None
        return hmac.new(self._key, head.encode(), hashlib.sha256).hexdigest()

    def signature_valid(self, head: str, signature: str | None) -> bool:
        """Check a signature somebody else produced.

        Deliberately not called anywhere inside this package, and that is the
        correct number of callers. Verifying a signature with the same key
        that just produced it cannot fail: it is a tautology, and a check that
        cannot fail is worse than no check, because it reads as one. (That was
        tried. The deployment falsifier grew a signature check, and the check
        passed after the key was swapped out from under it.)

        So this is the *reader's* half of ``sign()`` -- for the auditor, or
        the service on the other side, holding the key and a signature issued
        earlier. It exists here rather than in their code so that the
        constant-time comparison is not something they have to remember.
        """
        expected = self.sign(head)
        if expected is None or signature is None:
            return False
        return hmac.compare_digest(expected, signature)
