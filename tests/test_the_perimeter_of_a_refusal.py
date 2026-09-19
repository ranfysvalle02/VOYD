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


async def test_an_owned_sink_is_told_and_the_acknowledgement_is_recorded(core):
    cache = Cache()
    notes, chain = await revoking(core, Perimeter().register(cache))
    await notes.revoke({"t": "a", "doc_id": "d1"}, reason="erasure request")

    assert cache.told and cache.told[0][1] == "erasure request"
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
