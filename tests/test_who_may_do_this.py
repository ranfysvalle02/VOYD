"""May this caller *do* this — the third question, which had no answer.

    Guard       may this caller read the scope?          a passcode
    Admission   may this document reach a prompt?        rules, per document
    Authority   may this caller perform this operation?  -- nothing

The gap was invisible because the first two are so carefully separated and
both are about *reading*. Every verb that changes reachability was
available to anyone holding a handle, which in practice means anyone
holding the scope's passcode -- so "re-admit a document an injection
detector flagged" sat behind the same credential as "search this scope",
and three separate features had to stay off the HTTP surface because of it.

The asymmetry is the design. Withholding a fact and granting one back are
not equally dangerous and must not be equally available.
"""

from __future__ import annotations

import pytest

from voyd.engine import (GRANTS_REACHABILITY, RELEASE, REVOKE, WITHHOLDS,
                         Anyone, AuthorityRequired, Deadline, Grants,
                         NotAuthorised, Recorded, quarantined, revoked)


async def guarded(core, authority, *, tenant="t"):
    engine, db = core
    docs = engine.model("notes", tenant=tenant).admitting(
        Deadline(), revoked(), quarantined()).authorised_by(authority)
    chain = engine.ledger("refusals", tenant=tenant)
    docs.witnessed_by(chain)
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_one({"t": "a", "doc_id": "d1"})
    return docs, chain


# ---- the asymmetry ----------------------------------------------------

async def test_a_pipeline_may_withhold_and_may_not_grant(core):
    """The shape most services want, and the reason it has a name.

    An indexing pipeline should be able to quarantine anything suspicious
    at three in the morning, and should not be able to put a flagged
    document back in front of a model.
    """
    docs, _ = await guarded(core, Grants.withholding_only())
    bot = docs.for_caller({"sub": "indexer"})

    assert await bot.quarantine({"t": "a", "doc_id": "d1"},
                                reason="injection detector") == 1

    with pytest.raises(NotAuthorised) as caught:
        await bot.release({"t": "a", "doc_id": "d1"}, reason="looks fine")
    assert "reachable again" in str(caught.value), \
        "the error should say why this direction is the dangerous one"

    reviewer = docs.for_caller({"sub": "alice", "may": ["release"]})
    assert await reviewer.release({"t": "a", "doc_id": "d1"},
                                  reason="reviewed, benign") == 1


def test_granting_and_withholding_are_named_sets():
    """Named rather than left for each deployment to rediscover."""
    assert RELEASE in GRANTS_REACHABILITY
    assert REVOKE in WITHHOLDS
    assert not (GRANTS_REACHABILITY & WITHHOLDS)


@pytest.mark.parametrize("verb, kwargs", [
    ("revoke", {"reason": "erasure"}),
    ("quarantine", {"reason": "detector"}),
])
async def test_every_reachability_verb_asks(core, verb, kwargs):
    docs, _ = await guarded(core, Grants())
    nobody = docs.for_caller({"sub": "nobody"})
    with pytest.raises(NotAuthorised):
        await getattr(nobody, verb)({"t": "a", "doc_id": "d1"}, **kwargs)


# ---- fail closed, and never silently -----------------------------------

async def test_an_unbound_caller_raises_rather_than_passing(core):
    """Neither answer is acceptable. Permitting makes the authority
    decorative; refusing silently makes a revocation report success having
    done nothing, which is the worst failure this package has."""
    docs, _ = await guarded(core, Grants())

    with pytest.raises(AuthorityRequired, match="who is asking"):
        await docs.revoke({"t": "a", "doc_id": "d1"}, reason="erasure")

    assert len(await docs.for_caller({"sub": "x", "may": ["revoke"]})
               .find({"t": "a"})) == 1, "and nothing was written"


async def test_an_unknown_operation_is_denied(core):
    """A verb added to this package is not retroactively granted to every
    caller holding an old token."""
    grants = Grants()
    assert grants.permits("some_future_verb", {"may": ["revoke"]},
                          collection="notes") is False


async def test_no_authority_means_unchanged(core):
    """By default the caller of a library *is* the application -- it
    already holds the database, and demanding an authority from a script
    would be theatre."""
    engine, db = core
    docs = engine.model("notes", tenant="t").forgettable()
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_one({"t": "a", "doc_id": "d1"})

    assert docs.authority is None
    assert await docs.revoke({"t": "a", "doc_id": "d1"}, reason="x") == 1


async def test_shred_and_derive_are_gated_too(core):
    """Every verb that changes what a scope contains, not just the
    obvious two."""
    engine, db = core
    docs = engine.model("notes", tenant="t").admitting(
        Deadline(), revoked(), lineage_field="lineage").authorised_by(Grants())
    await engine.ensure(search_wait_s=0)
    src = (await db.notes.insert_one({"t": "a", "doc_id": "d1"})).inserted_id

    nobody = docs.for_caller({"sub": "nobody"})
    with pytest.raises(NotAuthorised):
        await nobody.derive({"t": "a", "text": "a summary"}, parents=[src])
    with pytest.raises(NotAuthorised):
        await nobody.shred("a")


# ---- the record learns who ---------------------------------------------

async def test_the_chain_records_the_actor(core):
    """It could say what stopped being reachable, when, and on what
    instruction -- and not by whom. "Somebody released the document the
    detector flagged" was the strongest sentence available to an auditor.
    """
    docs, chain = await guarded(core, Grants.withholding_only())

    await docs.for_caller({"sub": "indexer"}).quarantine(
        {"t": "a", "doc_id": "d1"}, reason="detector")
    await docs.for_caller({"sub": "alice@acme", "may": ["release"]}).release(
        {"t": "a", "doc_id": "d1"}, reason="reviewed")

    entries = await chain.entries(tenant="a")
    assert [(e["event"], e["actor"]) for e in entries] == [
        ("quarantined", "indexer"), ("lifted", "alice@acme")]
    assert (await chain.verify(tenant="a"))["intact"] is True


async def test_the_actor_is_hashed_so_it_cannot_be_attached_afterwards(core):
    """An attributable record you can edit is not attributable."""
    from voyd.engine import digest

    docs, chain = await guarded(core, Anyone())
    await docs.for_caller({"sub": "alice"}).revoke(
        {"t": "a", "doc_id": "d1"}, reason="erasure")

    entry = (await chain.entries(tenant="a"))[-1]
    assert entry["actor"] == "alice"
    forged = {k: v for k, v in entry.items() if k != "_id"}
    forged["actor"] = "bob"
    assert digest(forged) != entry["hash"]


async def test_an_unattributed_entry_says_so(core):
    """``None`` where nothing knows, rather than naming a service account
    nobody checked."""
    engine, db = core
    docs = engine.model("notes", tenant="t").forgettable()
    chain = engine.ledger("refusals", tenant="t")
    docs.witnessed_by(chain)
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_one({"t": "a", "doc_id": "d1"})

    await docs.revoke({"t": "a", "doc_id": "d1"}, reason="erasure")
    assert (await chain.entries(tenant="a"))[-1]["actor"] is None


async def test_anyone_permits_everything_and_still_records(core):
    """A real answer for internal tools, and a decision rather than an
    absence: installing it is typed out, installing nothing is a default.
    """
    docs, chain = await guarded(core, Anyone())
    await docs.for_caller({"sub": "ops"}).revoke(
        {"t": "a", "doc_id": "d1"}, reason="erasure")
    assert (await chain.entries(tenant="a"))[-1]["actor"] == "ops"


# ---- denials are a signal ----------------------------------------------

async def test_denials_can_be_counted_because_a_climbing_one_is_probing(core):
    """The same reasoning that counts ``not_cleared`` apart from
    ``deadline``: a climbing denial is somebody trying doors."""
    watched = Recorded(Grants.withholding_only())
    docs, _ = await guarded(core, watched)
    bot = docs.for_caller({"sub": "indexer"})

    await bot.quarantine({"t": "a", "doc_id": "d1"}, reason="detector")
    with pytest.raises(NotAuthorised):
        await bot.release({"t": "a", "doc_id": "d1"}, reason="nope")

    assert watched.allowed == 1
    assert watched.denied == [{"operation": RELEASE, "collection": "notes",
                               "actor": "indexer"}]


def test_an_authority_cannot_verify_the_claims_it_is_handed():
    """Stated because the alternative is an authorisation system whose
    only input is the attacker's -- the same sentence ``for_caller``
    carries, for the same reason."""
    from voyd.engine import authority as A
    assert "only input is the" in A.Grants.__doc__
