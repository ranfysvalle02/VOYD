"""``voyd verify`` is only worth shipping if it can fail.

A checker that passes on a broken deployment is worse than no checker: it
converts an unknown into a false assurance, and somebody makes a retention
promise on the strength of it. The README's claims are checked by the rest of
this suite; what *this* file checks is the checker -- that each of its four
checks actually detects the thing it claims to detect.

So each test breaks the guarantee on purpose and asserts that ``verify``
notices. The mechanism is the same one an application would get wrong: the
read path stops refusing, or the ledger stops recording.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from tests.conftest import TEST_MONGO_URI
from voyd.engine import DerivationBroken

from voyd import verify as V


def test_verify_needs_neither_fastapi_nor_a_server():
    """It runs where the problem is, which is the database.

    The point of the tool is that a stranger can point it at their own
    deployment. If it needed the ``app`` extra, the people most likely to
    have inherited a leaking retrieval stack could not run it.
    """
    import subprocess
    import sys

    out = subprocess.run(
        [sys.executable, "-c",
         "import sys, voyd.verify; "
         "assert 'fastapi' not in sys.modules, 'the falsifier pulled the Host'; "
         "print('clean')"],
        capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert "clean" in out.stdout


def test_a_check_that_fails_reports_the_reason_and_the_exit_code():
    """The shape of a failure, without a database.

    ``Check`` is small on purpose -- an exit status and a sentence -- and the
    exit status is what CI reads.
    """
    c = V.Check("deadline", "an expired document is unreachable")
    assert c.ok
    c.note("something contextual")
    assert c.ok, "a note is not a failure"
    c.fail("search returned an expired document")
    assert not c.ok
    assert "search returned an expired document" in c.notes


async def test_the_whole_run_passes_against_a_healthy_deployment(core):
    """The baseline. If this is red, nothing below means anything."""
    engine, db = core
    v = V.Verifier(db.client, db, quiet=True, uri=TEST_MONGO_URI)
    assert await v.run() is True, [
        (c.name, c.notes) for c in v.checks if not c.ok]
    assert [c.name for c in v.checks] == ["deadline", "revocation",
                                          "starvation", "clearance",
                                          "reversal", "inheritance",
                                          "shredding", "chain"]


async def test_the_deadline_check_fails_when_the_read_path_stops_refusing(core):
    """Break admission; the check must catch it.

    The break is deliberately the *historical* one: a handle that returns
    everything, which is what six read paths in this repository once did by
    forgetting a filter. ``including_refused()`` is that behaviour with a
    name, so it is the honest way to simulate it.
    """
    engine, db = core
    v = V.Verifier(db.client, db, quiet=True, uri=TEST_MONGO_URI)
    parked = await v.park_sweeper()
    try:
        await v.declare()
        v.docs = v.docs.including_refused()      # the guarantee, switched off
        check = await v.check_deadline(parked=parked)
    finally:
        await v.unpark_sweeper()

    assert not check.ok, (
        "the read path returned expired documents and verify reported the "
        "deployment healthy -- the checker is decoration")
    assert any("expired document" in n for n in check.notes)


async def test_the_revocation_check_fails_when_the_row_is_deleted(core):
    """The subtler break, and the one a reasonable person would ship.

    Deleting on ``forget`` passes any check that only asks "is it
    unreachable". It is still wrong: unreachable-first is the claim, the row
    is the evidence, and you cannot investigate what you erased. So the
    check asserts the row survives, and this proves the assertion bites.
    """
    engine, db = core
    v = V.Verifier(db.client, db, quiet=True, uri=TEST_MONGO_URI)
    await v.declare()

    original = v.docs.revoke

    async def revoke_and_delete(filters, **kw):
        n = await original(filters, **kw)
        await db.verify_docs.delete_many(filters)     # the plausible mistake
        return n

    v.docs.revoke = revoke_and_delete
    check = await v.check_revocation()

    assert not check.ok
    assert any("deleted" in n for n in check.notes), (
        f"the row was erased on request and the check passed: {check.notes}")


async def test_the_reversal_check_fails_when_an_erasure_can_be_undone(core):
    """The break somebody ships on purpose, under pressure, at 3am.

    "Support needs to un-forget a document" is a reasonable-sounding ask,
    and the patch that grants it is one line. It passes every other check
    in this file: the document is refused when revoked, the row survives,
    the chain verifies. What it breaks is the thing only this check looks
    at -- the chain now attests to a refusal that was silently taken back,
    which is a record that is intact and false.
    """
    engine, db = core
    v = V.Verifier(db.client, db, quiet=True, uri=TEST_MONGO_URI)
    await v.declare()

    async def helpful_undo(off, filters=None, **kw):     # the 3am patch
        return (await db.verify_held.update_many(
            filters, {"$unset": {"forgotten": ""}})).modified_count, None

    v.held.lift = helpful_undo
    check = await v.check_reversal()

    assert not check.ok
    assert any("undone" in n or "lifted" in n for n in check.notes), (
        f"a revocation was reversed and the check passed: {check.notes}")


async def test_the_reversal_check_fails_when_a_hold_erases_its_evidence(core):
    """The break nobody ships on purpose, and nobody notices either.

    The tempting implementation of ``quarantine`` is "``revoke`` with a
    different field name", which inherits the erase deadline -- so the
    document under investigation is scheduled for deletion by the act of
    opening the investigation. Every read is correct, the mark is correct,
    the chain is correct, and the evidence is gone in a minute.
    """
    engine, db = core
    v = V.Verifier(db.client, db, quiet=True, uri=TEST_MONGO_URI)
    await v.declare()

    original = v.held.quarantine

    async def quarantine_and_schedule(filters=None, **kw):
        n = await original(filters, **kw)
        await db.verify_held.update_many(filters, {"$set": {"expire_at": V.now()}})
        return n

    v.held.quarantine = quarantine_and_schedule
    check = await v.check_reversal()

    assert not check.ok
    assert any("evidence" in n or "deadline" in n for n in check.notes), (
        f"a hold scheduled its own evidence for deletion: {check.notes}")


async def test_the_inheritance_check_fails_when_the_mark_does_not_travel(core):
    """The state of the world before this work, and it passed everything.

    Revoke the source only, exactly as ``revoke()`` used to. Every other
    check in this file still holds: the source is unreachable, its row
    survives, the chain verifies. Only this one notices that the summary
    quoting it is still being served.
    """
    engine, db = core
    v = V.Verifier(db.client, db, quiet=True, uri=TEST_MONGO_URI)
    await v.declare()

    original = v.held.impose

    async def source_only(on, filters=None, **kw):     # no propagation
        v.held.spec = replace(v.held.spec, lineage_field=None)
        try:
            return await original(on, filters, **kw)
        finally:
            v.held.spec = replace(v.held.spec, lineage_field="lineage")

    v.held.impose = source_only
    check = await v.check_inheritance()

    assert not check.ok
    assert any("expected 3" in n or "returned" in n for n in check.notes), (
        f"a summary of an erased fact stayed reachable: {check.notes}")


async def test_the_inheritance_check_fails_when_a_new_summary_can_be_written(core):
    """The other half, and the trivial race without it.

    Propagation alone covers only work that already existed. Revoke at
    14:02, summarise at 14:03, and the contamination is clean -- so the
    write side has to refuse too, and this proves the check notices when
    it does not.
    """
    engine, db = core
    v = V.Verifier(db.client, db, quiet=True, uri=TEST_MONGO_URI)
    await v.declare()

    original = v.held.derive

    async def derive_anyway(documents, *, parents, **kw):
        try:
            return await original(documents, parents=parents, **kw)
        except DerivationBroken:
            docs = [documents] if isinstance(documents, dict) else list(documents)
            result = await db.verify_held.insert_many(
                [{**d, "lineage": []} for d in docs])   # the plausible mistake
            return list(result.inserted_ids)

    v.held.derive = derive_anyway
    check = await v.check_inheritance()

    assert not check.ok
    assert any("derived from an erased parent" in n for n in check.notes), (
        f"a fact was written out of an erased one: {check.notes}")


async def test_the_starvation_check_fails_when_the_page_is_truncated(core):
    """Restore the old fixed budget; the check must catch the regression.

    ``limit * 2``, admitted, sliced -- exactly what both read paths did
    before, and what a future simplification would reach for on the grounds
    that the refill loop looks like over-engineering.
    """
    engine, db = core
    v = V.Verifier(db.client, db, quiet=True, uri=TEST_MONGO_URI)
    await v.declare()

    async def fixed_budget(vector, *, limit, text=None, filters=None, **kw):
        from voyd.engine.admission import Page
        hits = await v.engine.search("verify_docs", vector, text=text,
                                     limit=limit * 2, filters=filters)
        kept, tally = v.docs._classify(list(hits))
        return Page(kept[:limit], refused=tally, examined=len(hits))

    v.docs.search = fixed_budget
    check = await v.check_starvation()

    assert not check.ok
    assert any("shortening the answer" in n for n in check.notes), check.notes


async def test_the_clearance_check_fails_when_a_missing_claim_is_a_pass(core):
    """The break is the one a reasonable implementation ships.

    Treating an absent clearance claim as "unrestricted" is what makes the
    happy path pass first, and it is how datasets become world-readable on
    the one code path nobody threaded the claim through. So the check asserts
    an unclaimed caller gets nothing, and this proves that assertion bites.
    """
    engine, db = core
    v = V.Verifier(db.client, db, quiet=True, uri=TEST_MONGO_URI)
    await v.declare()

    # The mistake, stated directly: a missing claim reads as the top level.
    class MissingClaimIsFine:
        reason = "not_cleared"
        needs_caller = True
        bypassable = False

        def refuses(self, doc, *, when=None, caller=None):
            held = (caller or {}).get("clearance")
            if held is None:
                return False                  # <- the bug
            return V.LEVELS.index(doc.get("classification", "public")) > \
                V.LEVELS.index(held)

        def clause(self):
            return None

    from voyd.engine.admission import AdmissionSpec
    v.classified.spec = AdmissionSpec(
        "verify_classified", tenant="scope",
        rules=(MissingClaimIsFine(),))
    v.classified.rules = v.classified.spec.rules

    check = await v.check_clearance()
    assert not check.ok
    assert any("no clearance claim" in n for n in check.notes), check.notes


async def test_the_clearance_check_fails_when_the_audit_handle_leaks(core):
    """``including_refused()`` waiving every rule is the naive implementation.

    It was the implementation here, and with a caller-aware rule installed it
    turns "let me see the deleted rows" into a privilege escalation.
    """
    engine, db = core
    v = V.Verifier(db.client, db, quiet=True, uri=TEST_MONGO_URI)
    await v.declare()

    from voyd.engine.admission import Admission

    # Patched on the class, not the instance: verify calls
    # ``for_caller(...).including_refused()``, so the escape hatch is reached
    # on a *clone*. An instance patch silently does nothing -- which is worth
    # knowing, because it is also how somebody would try to audit this.
    original = Admission.including_refused

    def waives_everything(self):
        handle = original(self)
        handle._caller = {"clearance": "secret"}     # <- the escalation
        return handle

    Admission.including_refused = waives_everything
    try:
        check = await v.check_clearance()
    finally:
        Admission.including_refused = original

    assert not check.ok
    assert any("way around access control" in n for n in check.notes), \
        check.notes


async def test_the_chain_check_fails_when_nothing_was_recorded(core):
    """A refusal that leaves no evidence must not read as a healthy chain.

    An empty chain verifies -- vacuously, since there is nothing to break --
    so "intact" alone would pass on a deployment recording nothing at all.
    That is the one way this check could have been useless.
    """
    engine, db = core
    v = V.Verifier(db.client, db, quiet=True, uri=TEST_MONGO_URI)
    await v.declare()

    check = await v.check_chain()      # no revocation has happened yet

    assert not check.ok
    assert any("no entries" in n for n in check.notes), check.notes


async def test_the_sweeper_setting_is_restored(core):
    """It parks a server global. Leaving it parked stops TTL for everyone.

    This is the one way the tool could do real damage: a laptop or CI server
    where expired documents are silently never collected again, in every
    database, because a check exited early.
    """
    engine, db = core
    v = V.Verifier(db.client, db, quiet=True, uri=TEST_MONGO_URI)
    if not await v.park_sweeper():
        pytest.skip("this deployment does not allow setParameter")

    was = v._ttl_was
    parked = await db.client.admin.command(
        {"getParameter": 1, "ttlMonitorSleepSecs": 1})
    assert parked["ttlMonitorSleepSecs"] == V.PARKED, "it did not park at all"

    await v.unpark_sweeper()

    after = await db.client.admin.command(
        {"getParameter": 1, "ttlMonitorSleepSecs": 1})
    assert after["ttlMonitorSleepSecs"] == was, (
        f"ttlMonitorSleepSecs left at {after['ttlMonitorSleepSecs']} instead "
        f"of {was}; expired documents are no longer being collected")
