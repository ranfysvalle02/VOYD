"""Refusal stops at the process boundary. This is what is honestly outside it.

Three questions a customer's architecture diagram asks within a minute, and
until now this package answered none of them:

  * the vector sitting beside the erased text is a lossy encoding of that
    text. Is the fact actually gone?
  * my cache, my mirrored index, my second service all hold copies. What
    happens to those?
  * the agent already posted a summary to Slack. Now what?

The answers are different for each, and the value is in keeping them
different. One is a bug and is fixed. One is already solved by shredding and
was under-claimed. One cannot be solved by any database, and the only honest
offer is to make finding it a query.
"""

from __future__ import annotations

import asyncio

import pytest

from voyd.engine import (DERIVED, OWNED, SEALED, Deadline, Perimeter,
                         quarantined, revoked)


# ---- 1. the copy that is not stored as text ---------------------------

async def test_an_erased_document_does_not_keep_its_embedding(core):
    """Measured in this repo before it was fixed: after ``revoke()`` the
    surviving vector still separated its own topic from another by 0.9988
    against 0.7992 cosine.

    That is a working attribute-inference oracle over somebody who asked to
    be forgotten -- no inversion model required. You ask the index whether
    a document about X is in there and it says yes. Text reconstruction
    from embeddings is a live research area on top of that; the membership
    answer is merely the floor, and the floor is already a breach.
    """
    engine, db = core
    notes = engine.model("notes", tenant="t").forgettable()
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_one(
        {"t": "a", "doc_id": "d1", "text": "alice's diagnosis",
         "embedding": [0.1] * 8})

    await notes.revoke({"t": "a", "doc_id": "d1"}, reason="subject erasure")

    row = await db.notes.find_one({"doc_id": "d1"})
    assert row is not None, "the row is still evidence of the instruction"
    assert row["embedding"] is None, \
        "the vector is a paraphrase of the text in a format nobody reads " \
        "by eye; erasing one and keeping the other erases nothing"
    assert row["forgotten"]["reason"] == "subject erasure"


async def test_a_held_document_keeps_its_embedding(core):
    """A quarantine is evidence, and the vector is how an investigator
    finds the other documents like it. Destroying it destroys the lead.

    Free to get right, because ``reversible`` already decides who stamps
    the erase deadline and this is the same question: erasure, or hold?
    """
    engine, db = core
    notes = engine.model("notes", tenant="t").admitting(
        Deadline(), revoked(), quarantined())
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_one(
        {"t": "a", "doc_id": "d1", "text": "poisoned", "embedding": [0.2] * 8})

    await notes.quarantine({"t": "a", "doc_id": "d1"}, reason="detector")

    row = await db.notes.find_one({"doc_id": "d1"})
    assert row["embedding"] == [0.2] * 8


async def test_the_derived_fields_are_declarable(core):
    """``embedding`` is the default because it is the one everybody has.
    A deployment with a second lossy encoding -- a summary column, a
    tokenised form, a locality-sensitive hash -- names it here rather than
    discovering the gap in an audit."""
    engine, db = core
    from voyd.engine.admission import AdmissionSpec
    spec = AdmissionSpec("notes", tenant="t",
                         derived_fields=("embedding", "gist"))
    notes = engine.admission("notes", tenant="t", rules=spec.with_defaults().rules)
    notes.spec = spec.with_defaults()
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_one({"t": "a", "doc_id": "d1", "text": "x",
                               "embedding": [0.1] * 4, "gist": "a summary"})

    await notes.revoke({"t": "a", "doc_id": "d1"}, reason="erasure")

    row = await db.notes.find_one({"doc_id": "d1"})
    assert row["embedding"] is None and row["gist"] is None


# ---- 2. who else holds a copy -----------------------------------------

class Cache:
    """A sink that holds plaintext and answers."""

    def __init__(self, name="redis", fail=None):
        self.name, self.holds, self.told = name, OWNED, []
        self._fail = fail

    async def forget(self, ids, *, reason):
        if self._fail == "raise":
            raise RuntimeError("connection refused")
        if self._fail == "hang":
            await asyncio.sleep(30)
        self.told.append((sorted(map(str, ids)), reason))
        return True


class Mirror:
    name, holds = "pinecone-mirror", SEALED

    def __init__(self):
        self.called = False

    async def forget(self, ids, *, reason):
        self.called = True
        return True


class Posted:
    name, holds = "slack-#incidents", DERIVED

    async def forget(self, ids, *, reason):
        raise AssertionError("a message cannot be un-sent")


async def revoking(core, perimeter):
    engine, db = core
    notes = engine.model("notes", tenant="t").forgettable().bounded_by(perimeter)
    chain = engine.ledger("refusals", tenant="t")
    notes.witnessed_by(chain)
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_one({"t": "a", "doc_id": "d1"})
    return notes, chain


async def test_an_owned_sink_is_told_which_ids_not_merely_that_something(core):
    """This asserted only the *reason* once, and missed the bug under it.

    The ids were resolved for inherited refusal and reused here, so on a
    collection tracking no lineage -- the default -- the sink received an
    empty list. It was told that something had been erased and not what,
    and acknowledged. A propagation that names nothing is worse than none,
    because it produces receipts.
    """
    engine, db = core
    cache = Cache()
    notes, chain = await revoking(core, Perimeter().register(cache))
    erased = (await db.notes.find_one({"doc_id": "d1"}))["_id"]
    await db.notes.insert_one({"t": "a", "doc_id": "untouched"})

    await notes.revoke({"t": "a", "doc_id": "d1"}, reason="erasure request")

    assert cache.told == [([str(erased)], "erasure request")], \
        "the sink must be told which ids, and only those"
    acks = (await chain.entries(tenant="a"))[-1]["detail"]["perimeter"]
    assert [(a["sink"], a["acked"]) for a in acks] == [("redis", True)]


async def test_a_sealed_sink_is_not_called_at_all(core):
    """Its copy is ciphertext. Destroying the key erases it with no round
    trip, no acknowledgement, and nothing that can fail."""
    mirror = Mirror()
    notes, chain = await revoking(core, Perimeter().register(mirror))
    await notes.revoke({"t": "a", "doc_id": "d1"}, reason="erasure")

    assert mirror.called is False
    ack = (await chain.entries(tenant="a"))[-1]["detail"]["perimeter"][0]
    assert ack["holds"] == SEALED and ack["acked"] is True
    assert "destroying the key" in ack["detail"]


async def test_a_derived_sink_is_reported_unreachable_by_construction(core):
    """You cannot un-send a message. Listing it is the point -- an
    incident review needs to know it exists."""
    notes, chain = await revoking(core, Perimeter().register(Posted()))
    await notes.revoke({"t": "a", "doc_id": "d1"}, reason="erasure")

    ack = (await chain.entries(tenant="a"))[-1]["detail"]["perimeter"][0]
    assert ack["holds"] == DERIVED and ack["acked"] is False
    assert "only found" in ack["detail"]


@pytest.mark.parametrize("mode", ["raise", "hang"])
async def test_a_broken_sink_cannot_fail_the_erasure(core, monkeypatch, mode):
    """The property that makes this safe to turn on.

    "We could not honour the erasure request because Redis was down" is not
    a sentence anybody should be able to write. The row is already refused;
    the sink's failure is recorded, loudly, and the caller still gets their
    answer.
    """
    from voyd.engine import perimeter as P
    monkeypatch.setattr(P, "SINK_TIMEOUT_S", 0.2)

    cache = Cache(fail=mode)
    notes, chain = await revoking(core, Perimeter().register(cache))
    assert await notes.revoke({"t": "a", "doc_id": "d1"},
                              reason="erasure") == 1
    assert await notes.find({"t": "a"}) == []

    ack = (await chain.entries(tenant="a"))[-1]["detail"]["perimeter"][0]
    assert ack["acked"] is False and ack["detail"]


async def test_a_hold_does_not_notify_the_perimeter(core):
    """A quarantine is not an erasure. Telling a cache to drop a document
    that is merely under review is both wrong and expensive."""
    cache = Cache()
    engine, db = core
    notes = engine.model("notes", tenant="t").admitting(
        Deadline(), revoked(), quarantined()).bounded_by(
            Perimeter().register(cache))
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_one({"t": "a", "doc_id": "d1"})

    await notes.quarantine({"t": "a", "doc_id": "d1"}, reason="detector")
    assert cache.told == []


def test_a_sink_must_declare_which_claim_applies_to_it():
    """Each class is a different claim, and picking the wrong one is the
    only way this module starts lying."""
    class Vague:
        name = "mystery"
        holds = "maybe"

        async def forget(self, ids, *, reason):
            return True

    with pytest.raises(ValueError, match="starts lying"):
        Perimeter().register(Vague())
    with pytest.raises(ValueError, match="who holds what"):
        Perimeter().register(object())


def test_describe_enumerates_the_perimeter_with_its_verbs():
    """The most valuable thing here. Most teams cannot answer "who else
    holds this fact" at all."""
    described = Perimeter().register(Cache()).register(Mirror()) \
        .register(Posted()).describe()
    assert described["sinks"] == {OWNED: ["redis"],
                                  SEALED: ["pinecone-mirror"],
                                  DERIVED: ["slack-#incidents"]}
    assert set(described["claims"]) == {SEALED, OWNED, DERIVED}


# ---- 3. what the model was allowed to see ------------------------------

async def test_a_context_receipt_commits_to_the_policy_that_produced_it(core):
    """The chain proves a revocation happened. It cannot prove the model
    call that produced an answer respected one, and only the second is the
    question an incident review asks."""
    from voyd.engine.admission import _digest_of

    engine, db = core
    notes = engine.model("notes", tenant="t").forgettable()
    chain = engine.ledger("refusals", tenant="t")
    notes.witnessed_by(chain)
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_many([{"t": "a", "doc_id": "d1"},
                                {"t": "a", "doc_id": "d2"}])

    before = await notes.receipt_for(await notes.find({"t": "a"}))
    assert len(before["admitted"]) == 2
    assert before["rules"] == ["deadline", "revoked"]

    await notes.revoke({"t": "a", "doc_id": "d1"}, reason="erasure")
    after = await notes.receipt_for(await notes.find({"t": "a"}))

    assert len(after["admitted"]) == 1
    assert after["chain"] != before["chain"], \
        "the ledger head dates the context against every revocation"
    assert after["hash"] != before["hash"]

    # Recomputable by a third party, with no secret and no cooperation
    # from this database -- the property that makes the chain worth
    # having, one layer up.
    assert _digest_of({k: v for k, v in after.items() if k != "hash"}) \
        == after["hash"]


async def test_a_receipt_will_not_guess_which_chain_it_belongs_to(core):
    """A receipt naming the wrong chain is worse than one that could not
    be issued."""
    from voyd.engine import ScopeRequired

    engine, db = core
    notes = engine.model("notes", tenant="t").forgettable()
    notes.witnessed_by(engine.ledger("refusals", tenant="t"))
    await engine.ensure(search_wait_s=0)

    with pytest.raises(ScopeRequired):
        await notes.receipt_for([])
    assert (await notes.receipt_for([], tenant="a"))["admitted"] == []


# ---- a sealed claim, checked rather than trusted -----------------------

def a_sink(name, holds, *, leaks=None, forget=None):
    from voyd.engine import sink

    async def verify(_id):
        return leaks
    return sink(name, holds, forget=forget,
                verify=None if leaks is None else verify)


async def test_a_sealed_sink_that_actually_caches_plaintext_is_caught():
    """The one way this module can lie, and it lies quietly, in a
    compliance answer: a sink declaring ``sealed`` is *trusted* about it,
    so if it really caches plaintext the perimeter reports an erasure that
    did not happen."""
    p = Perimeter().register(a_sink("honest", SEALED, leaks=False)) \
                   .register(a_sink("liar", SEALED, leaks=True))
    by_name = {a.sink: a for a in await p.audit(shredded_id="x")}

    assert by_name["honest"].acked is True
    assert by_name["liar"].acked is False
    assert "MISDECLARED" in by_name["liar"].detail


async def test_a_sealed_sink_with_no_verify_is_unchecked_not_passing():
    """A claim nobody checked and a claim that was checked must not look
    the same -- the same argument ``voyd verify`` makes about a skipped
    test."""
    p = Perimeter().register(a_sink("quiet", SEALED))
    ack = (await p.audit(shredded_id="x"))[0]
    assert ack.acked is False
    assert "unchecked, not confirmed" in ack.detail


async def test_an_audit_that_raises_does_not_read_as_a_pass():
    from voyd.engine import sink

    async def explode(_id):
        raise RuntimeError("mirror unreachable")

    p = Perimeter().register(sink("broken", SEALED, verify=explode))
    ack = (await p.audit(shredded_id="x"))[0]
    assert ack.acked is False and "raised" in ack.detail


# ---- re-driving what never answered ------------------------------------

async def test_an_unanswered_sink_is_retried_and_then_confirmed(core):
    """A sink that was down during a revocation otherwise stays
    unacknowledged forever -- an open breach in an audit trail with
    nobody assigned to it."""
    from voyd.engine import PerimeterLog

    engine, db = core
    cache = Cache(fail="raise")
    log = PerimeterLog(db, "perimeter")
    await log.ensure()
    notes = engine.model("notes", tenant="t").forgettable().bounded_by(
        Perimeter().register(cache), log_to=log)
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_one({"t": "a", "doc_id": "d1"})

    await notes.revoke({"t": "a", "doc_id": "d1"}, reason="erasure")
    assert len(await log.outstanding()) == 1

    cache._fail = None                                  # the cache comes back
    settled = await notes.perimeter.redrive(log)

    assert [a.acked for a in settled] == [True]
    assert await log.outstanding() == []
    row = await db.perimeter.find_one({})
    assert row["confirmed"] is True and row["attempts"] == 1


async def test_a_retry_past_the_horizon_is_closed_unconfirmed(core):
    """The bound is the design. A retry a week later against a cache that
    has since evicted the key achieves nothing and would write a success
    into the record -- and a false success is worse than a gap that is
    honestly marked.
    """
    from datetime import timedelta

    from voyd.engine import PerimeterLog

    engine, db = core
    cache = Cache(fail="raise")
    log = PerimeterLog(db, "perimeter")
    await log.ensure()
    notes = engine.model("notes", tenant="t").forgettable().bounded_by(
        Perimeter().register(cache), log_to=log)
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_one({"t": "a", "doc_id": "d1"})
    await notes.revoke({"t": "a", "doc_id": "d1"}, reason="erasure")

    cache._fail = None
    settled = await notes.perimeter.redrive(log, older_than=timedelta(0))

    assert [a.acked for a in settled] == [False]
    assert "expired" in settled[0].detail
    assert cache.told == [], "past the horizon it is not even attempted"

    row = await db.perimeter.find_one({})
    assert row["open"] is False, "it is no longer work"
    assert row["confirmed"] is False, \
        "and it is permanently a finding: 'never confirmed' must not be " \
        "deleted, or its absence reads as a success"


async def test_the_log_never_stores_the_text_it_was_asked_to_forget(core):
    """An audit record that quotes the secret is a fresh copy of it,
    exempt from every deadline in the system -- the rule ``ledger.py``
    already follows."""
    from voyd.engine import PerimeterLog

    engine, db = core
    log = PerimeterLog(db, "perimeter")
    await log.ensure()
    notes = engine.model("notes", tenant="t").forgettable().bounded_by(
        Perimeter().register(Cache(fail="raise")), log_to=log)
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_one({"t": "a", "doc_id": "d1",
                               "text": "the admin password is hunter2"})

    await notes.revoke({"t": "a", "doc_id": "d1"}, reason="leaked")

    row = await db.perimeter.find_one({})
    assert "hunter2" not in str(row)
    assert set(row) >= {"sink", "ids", "reason", "open", "confirmed"}
    assert row["expire_at"] is not None, \
        "operational state, unlike the chain, which keeps no TTL on purpose"


def test_registering_a_sink_costs_three_lines():
    """The decision not to ship vendor adapters only holds if registering
    is nearly free -- a perimeter nobody registers anything into is a
    ``describe()`` that prints an empty dict."""
    from voyd.engine import sink

    async def drop(ids, *, reason):
        return True

    p = Perimeter().register(sink("redis", OWNED, forget=drop))
    assert p.describe()["sinks"] == {OWNED: ["redis"]}
