"""Forgetting is a promise. This is the evidence for it.

``Admission`` makes forgetting true; it does not make it *provable*, and the
two are different products. ``receipts()`` is a counter in one replica's
memory -- a dashboard. The question an auditor asks is narrower and harder:

    show me that this document stopped being reachable at 14:02, and show me
    that the record has not been edited since

So revocations are appended to a hash chain. These tests are mostly about the
ways such a chain is *worthless* if it is built carelessly, because that is
the failure mode: a proof that does not hold is worse than no proof, since
somebody relies on it.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from voyd.engine import now
from voyd.engine.ledger import (GENESIS, Ledger, LedgerSpec, _stamp,
                                canonical, digest, truncate)


# --------------------------------------------------------------------------
# the hash itself, with no database anywhere near it
# --------------------------------------------------------------------------

def _entry(seq=0, prev=GENESIS, **kw):
    e = {"seq": seq, "prev": prev, "at": now(), "event": "revoked",
         "reason": "user retracted it", "subject": {"doc_id": "d1"},
         "count": 1, "detail": None, **kw}
    e["hash"] = digest(e)
    return e


def test_the_hash_does_not_cover_itself_or_the_database_id():
    """Or a chain would be unverifiable after any migration that rewrites ids."""
    e = _entry()
    assert "hash" not in canonical(e)
    with_id = {**e, "_id": "anything at all"}
    assert digest(with_id) == e["hash"], (
        "the database's own id got into the hash; the chain now depends on "
        "storage internals rather than on what was recorded")


def test_editing_any_recorded_field_changes_the_hash():
    """The whole point, stated as a property rather than trusted."""
    e = _entry()
    for field, tampered in (("reason", "routine cleanup"),
                            ("count", 2),
                            ("subject", {"doc_id": "d2"}),
                            ("at", now() - timedelta(days=30)),
                            ("event", "expired"),
                            ("seq", 7),
                            ("prev", "f" * 64)):
        assert digest({**e, field: tampered}) != e["hash"], (
            f"{field} could be rewritten without breaking the hash")


def test_a_hash_does_not_depend_on_how_this_client_decodes_bson():
    """A hash that verifies only on the machine that wrote it proves nothing.

    Two clients, one instant. A ``tz_aware=True`` client hands back an aware
    datetime and a default one hands back the same instant naive -- and if
    those hash differently, an audit run on a client configured the other way
    reports every entry forged. The first thing anybody stops trusting is the
    tool, not the data.
    """
    stamp = now()
    assert stamp.tzinfo is not None
    signed = _entry(at=stamp)

    # What a driver without tz_aware would return for the same stored value.
    naive = stamp.replace(tzinfo=None)
    assert digest({**signed, "at": naive}) == signed["hash"], (
        "the same instant hashed differently depending on the client's "
        "codec options")


def test_a_naive_timestamp_is_utc_and_not_the_auditors_local_time():
    """Naive means UTC, because that is what BSON stored.

    The first version used ``astimezone(tz=None)``, which assumes *local*
    time for a naive value -- so a chain written by a default client would
    have hashed differently in London and in New York. Same failure as the
    test above, arriving by geography instead of by codec, and the one that
    would have been found in production rather than here.
    """
    naive = datetime(2026, 9, 18, 14, 2, 0)
    as_utc = naive.replace(tzinfo=timezone.utc)

    assert digest(_entry(at=naive)) == digest(_entry(at=as_utc))
    assert _stamp(naive) == _stamp(as_utc) == "2026-09-18T14:02:00+00:00"


def test_the_timestamp_is_truncated_to_what_bson_can_keep():
    """Rounded before storing, not before comparing.

    Rounding at verify time would mean the stored value is not the value that
    was hashed, and a verifier reconstructing the hash from the document
    would need to know to apply the same rounding -- a rule that has to be
    remembered, which is the failure this repository is organised around.
    """
    t = truncate(now())
    assert t.microsecond % 1000 == 0
    assert truncate(t) == t, "truncation must be idempotent"


# --------------------------------------------------------------------------
# the chain, against a real database
# --------------------------------------------------------------------------


async def test_a_hash_survives_its_own_round_trip(core):
    """The bug that made the first version of this worthless.

    BSON dates are milliseconds; ``now()`` is microseconds. So an entry
    hashed on the way in and re-hashed on the way out disagreed about its own
    timestamp, and *every* entry verified as forged. The chain was internally
    consistent and entirely unverifiable -- the worst available outcome, since
    the person who discovers it is the person relying on it.

    Which is the general hazard with hashing anything a database stores: the
    value you hashed and the value it kept are not automatically the same
    value. Asserted per field, not just end to end, so a later field with a
    lossy encoding fails here rather than in an audit.
    """
    ledger = await _chain(core)
    engine, db = core
    receipt = await ledger.append(
        "revoked", tenant="t1", reason="credential leaked",
        subject={"doc_id": "d1"}, count=1, detail={"ticket": "SEC-41"})

    stored = await db.refusals.find_one({"seq": 0})
    assert digest(stored) == receipt["hash"], (
        "the stored entry does not hash to the receipt handed to the caller")
    for f in ("at", "reason", "subject", "count", "detail", "prev", "seq"):
        assert _stamp(stored[f]) == _stamp(receipt[f]), \
            f"{f} did not survive the round trip byte-for-byte"
    assert (await ledger.verify(tenant="t1"))["intact"]

async def _chain(core, **kw) -> Ledger:
    engine, _ = core
    ledger = engine.ledger("refusals", tenant="tenant", **kw)
    await engine.ensure(search_wait_s=5)
    return ledger


async def test_a_chain_of_revocations_verifies(core):
    ledger = await _chain(core)
    for i in range(5):
        await ledger.append("revoked", tenant="t1", reason=f"r{i}",
                            subject={"doc_id": f"d{i}"}, count=1)

    report = await ledger.verify(tenant="t1")
    assert report["intact"] is True
    assert report["entries"] == 5
    assert report["signed"] is False, "no key was configured; say so"
    assert report["signature"] is None


async def test_a_deleted_entry_is_a_gap_not_a_shorter_chain(core):
    """The attack a hash chain exists to stop: quietly dropping the awkward one."""
    ledger = await _chain(core)
    engine, db = core
    for i in range(4):
        await ledger.append("revoked", tenant="t1", reason=f"r{i}")

    await db.refusals.delete_one({"seq": 2})

    report = await ledger.verify(tenant="t1")
    assert report["intact"] is False
    assert report["fault"] == "gap"
    assert report["at_seq"] == 3, "the break is reported where it is found"


async def test_editing_an_entry_in_place_is_detected(core):
    """Rewriting the reason on a revocation -- with database access."""
    ledger = await _chain(core)
    engine, db = core
    await ledger.append("revoked", tenant="t1", reason="credential leaked")
    await ledger.append("revoked", tenant="t1", reason="user retracted it")

    await db.refusals.update_one({"seq": 0},
                                 {"$set": {"reason": "routine cleanup"}})

    report = await ledger.verify(tenant="t1")
    assert report["intact"] is False
    assert report["fault"] == "forged"
    assert report["at_seq"] == 0


async def test_recomputing_the_hash_after_editing_still_breaks_the_chain(core):
    """The more competent forgery, and the reason links exist at all.

    An editor who knows the scheme fixes the hash too. That is exactly what
    ``prev`` is for: the *next* entry still commits to the old value, so the
    forgery has to be carried all the way to the head -- and the head is what
    the caller was handed a copy of at the time.
    """
    ledger = await _chain(core)
    engine, db = core
    await ledger.append("revoked", tenant="t1", reason="credential leaked")
    await ledger.append("revoked", tenant="t1", reason="user retracted it")

    victim = await db.refusals.find_one({"seq": 0})
    forged = {**victim, "reason": "routine cleanup"}
    forged["hash"] = digest(forged)
    await db.refusals.replace_one({"seq": 0}, forged)

    report = await ledger.verify(tenant="t1")
    assert report["intact"] is False
    assert report["fault"] == "broken", (
        "a re-hashed entry passed its own check; the link from the next "
        "entry is what must catch it")
    assert report["at_seq"] == 1


async def test_a_receipt_handed_out_at_the_time_survives_a_rewritten_chain(core):
    """The only defence against the party that owns the database.

    A hash chain is evidence against somebody who cannot edit it. Against an
    operator who can, the load is carried by the copy the *caller* kept: a
    chain rebuilt from scratch is internally perfect and still does not
    contain their hash.
    """
    ledger = await _chain(core)
    engine, db = core
    receipt = await ledger.append("revoked", tenant="t1",
                                  reason="subject erasure request",
                                  subject={"doc_id": "d1"}, count=1)

    # The operator wipes the chain and rebuilds it without that entry.
    await db.refusals.delete_many({})
    await ledger.append("revoked", tenant="t1", reason="something else")

    report = await ledger.verify(tenant="t1")
    assert report["intact"] is True, "a rebuilt chain verifies -- that is the point"
    entries = await ledger.entries(tenant="t1")
    assert receipt["hash"] not in {e["hash"] for e in entries}, (
        "the held receipt is what falsifies the rebuilt chain")


async def test_two_tenants_do_not_share_a_chain(core):
    """One namespace's history must not be auditable from another's."""
    ledger = await _chain(core)
    await ledger.append("revoked", tenant="t1", reason="a")
    await ledger.append("revoked", tenant="t2", reason="b")
    await ledger.append("revoked", tenant="t1", reason="c")

    t1 = await ledger.entries(tenant="t1")
    assert [e["seq"] for e in t1] == [0, 1], "each tenant's chain is its own"
    assert {e["reason"] for e in t1} == {"a", "c"}
    assert (await ledger.verify(tenant="t1"))["intact"]
    assert (await ledger.verify(tenant="t2"))["intact"]


async def test_a_scoped_chain_refuses_an_entry_with_no_tenant(core):
    ledger = await _chain(core)
    with pytest.raises(ValueError, match="scoped by"):
        await ledger.append("revoked", reason="nobody's")


async def test_concurrent_appends_do_not_fork_the_chain(core):
    """Twelve writers, one head. A chain that forks under load is not a chain.

    Both writers read the same head and compute the same next ``seq``. The
    unique index makes the loser retry instead of overwriting the winner, so
    what comes out is linear -- and still verifies.
    """
    ledger = await _chain(core)
    await asyncio.gather(*(
        ledger.append("revoked", tenant="t1", reason=f"r{i}", count=1)
        for i in range(12)))

    entries = await ledger.entries(tenant="t1")
    assert [e["seq"] for e in entries] == list(range(12)), \
        "sequence numbers were lost or duplicated under concurrency"
    assert len({e["reason"] for e in entries}) == 12, "an append was overwritten"
    assert (await ledger.verify(tenant="t1"))["intact"]


async def test_the_signature_authenticates_the_head_and_says_when_it_cannot(core):
    """HMAC is an attestation, not a public proof, and the field names say so."""
    signed = await _chain(core, key="a-test-key")
    await signed.append("revoked", tenant="t1", reason="a")

    report = await signed.verify(tenant="t1")
    assert report["signed"] is True
    assert signed.signature_valid(report["head"], report["signature"])
    assert not signed.signature_valid(report["head"], "0" * 64)
    assert not signed.signature_valid("f" * 64, report["signature"]), \
        "a signature over a different head must not validate"

    unsigned = Ledger(signed.db, LedgerSpec("refusals", tenant="tenant"))
    assert unsigned.sign(report["head"]) is None
    assert not unsigned.signature_valid(report["head"], report["signature"]), \
        "no key means no attestation, not a pass"


async def test_the_ledger_does_not_expire(core):
    """The deliberate exception to the whole repository's one-deadline rule.

    Everything else here inherits a deadline from one document. A proof
    collected by the same TTL index as the thing it proves is not a proof.
    The absence of a TTL index is therefore a feature, and features get
    tests.
    """
    await _chain(core)          # declared, so ensure() built its indexes
    engine, db = core
    indexes = await db.refusals.index_information()
    ttl = {n: i for n, i in indexes.items() if "expireAfterSeconds" in i}
    assert not ttl, (
        f"the refusal chain is being collected by a TTL index ({ttl}); a "
        "proof with a deadline is a coincidence with a short life")


async def test_an_entry_never_carries_the_text_it_refused(core):
    """An audit record that quotes the secret is a new copy of the secret.

    And a copy in the one collection here with no deadline on it -- so the
    document the caller asked to forget would outlive every mechanism built
    to forget it.
    """
    ledger = await _chain(core)
    engine, db = core
    await ledger.append("revoked", tenant="t1", reason="credential leaked",
                        subject={"doc_id": "d1", "token": "k6kC2pJz"}, count=1)

    entry = await db.refusals.find_one({"seq": 0})
    assert set(entry) <= {"_id", "tenant", "seq", "prev", "at", "event",
                          "reason", "subject", "count", "detail", "hash"}, \
        "an unexpected field on a chain entry -- check it is not document text"
    assert entry["subject"] == {"doc_id": "d1", "token": "k6kC2pJz"}


# --------------------------------------------------------------------------
# and through the handle that actually does the forgetting
# --------------------------------------------------------------------------

async def test_revoking_through_the_handle_lands_on_the_chain(core):
    engine, db = core
    notes = engine.model("notes", tenant="tenant").forgettable()
    chain = engine.ledger("refusals", tenant="tenant")
    notes.witnessed_by(chain)
    await engine.ensure(search_wait_s=5)

    await db.notes.insert_many([
        {"tenant": "t1", "doc_id": "d1", "text": "the admin password is hunter2",
         "expire_at": None},
        {"tenant": "t1", "doc_id": "d2", "text": "the fault code is P0301",
         "expire_at": None},
    ])

    receipt = await notes.witness({"tenant": "t1", "doc_id": "d1"},
                                  reason="credential leaked")

    assert receipt["count"] == 1
    assert receipt["seq"] == 0
    assert receipt["reason"] == "credential leaked"
    assert len(receipt["hash"]) == 64

    # The fact is unreachable, the row is on disk, and the event is on record.
    assert [d["doc_id"] for d in await notes.find({"tenant": "t1"})] == ["d2"]
    assert await db.notes.count_documents({"doc_id": "d1"}) == 1
    assert (await chain.verify(tenant="t1"))["intact"]


async def test_concurrent_revocations_do_not_swap_receipts(core):
    """Each caller gets *their* hash, not whichever finished last.

    The first version returned the count and stashed the receipt on the
    handle for a second method to pick up. Handles are deduplicated per
    collection, so that was shared mutable state on an object every request
    holds -- and the receipt is the one artifact whose whole value is that it
    belongs to a specific caller. Two concurrent erasure requests handed the
    wrong hashes is an audit trail that is worse than none.
    """
    engine, db = core
    notes = engine.model("notes", tenant="tenant").forgettable()
    chain = engine.ledger("refusals", tenant="tenant")
    notes.witnessed_by(chain)
    await engine.ensure(search_wait_s=5)

    await db.notes.insert_many(
        [{"tenant": "t1", "doc_id": f"d{i}", "expire_at": None}
         for i in range(8)])

    receipts = await asyncio.gather(*(
        notes.witness({"tenant": "t1", "doc_id": f"d{i}"}, reason=f"r{i}")
        for i in range(8)))

    for i, receipt in enumerate(receipts):
        assert receipt["reason"] == f"r{i}", (
            f"caller {i} was handed the receipt for {receipt['reason']}")
        assert receipt["count"] == 1
        assert receipt["subject"] == {"tenant": "t1", "doc_id": f"d{i}"}

    hashes = {r["hash"] for r in receipts}
    assert len(hashes) == 8, "two callers were handed the same hash"

    # And every one of them is really in the chain, at its own position.
    entries = {e["hash"]: e for e in await chain.entries(tenant="t1")}
    assert hashes <= set(entries), "a receipt names a link the chain lacks"
    assert (await chain.verify(tenant="t1"))["intact"]


async def test_a_failing_chain_does_not_un_refuse_the_fact(core):
    """The order of the two failures, and it is not the intuitive one.

    An unrecorded refusal is an audit gap. An un-refused fact is a breach.
    They are not the same size, so a ledger that is down must not turn a
    completed revocation into an exception the caller retries.
    """
    engine, db = core
    notes = engine.model("notes", tenant="tenant").forgettable()
    await engine.ensure(search_wait_s=5)

    class Broken:
        async def append(self, *a, **kw):
            raise RuntimeError("the chain is unavailable")

    notes.witnessed_by(Broken())
    await db.notes.insert_one({"tenant": "t1", "doc_id": "d1",
                              "text": "secret", "expire_at": None})

    n = await notes.revoke({"tenant": "t1", "doc_id": "d1"}, reason="leaked")
    assert n == 1, "the revocation must stand even when it cannot be recorded"
    assert await notes.find({"tenant": "t1"}) == []
