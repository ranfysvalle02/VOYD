"""``voyd verify`` -- run the falsifier against *your* deployment.

Every retrieval system's README makes claims. None of them hands you the
experiment that would disprove them, which is the wrong way round: the claim
in this repository is about a failure that is *silent by construction* --
a forgotten document that answers a query, scored and well-formed, with
nothing logged and nothing to page on. A property whose violation is invisible
cannot be checked by looking, so it has to be attacked.

That is what this does. Not a health check -- health checks confirm what is
configured. This plants documents that must not be reachable, asks for them
in every way the codebase can be asked, and fails if any read path answers.
The tests in ``tests/`` prove it on the author's machine against the author's
schema; this proves it on yours, against your indexes, your MongoDB version,
your tier, and whatever your deployment actually degraded to.

Six checks, each mapped to a way this has really gone wrong:

``deadline``    An expired document, with the TTL monitor deliberately parked
                so the row is *provably* still on disk, must be unreachable
                on every read path. This is the window the whole design is
                about: measured at up to 60s wide, and the interval in which
                a system that trusts only its TTL index serves deleted data.

``revocation``  A revoked document must be unreachable on the next read, with
                no sweeper involved -- and its row must still be there
                afterwards, because "unreachable first, erased second" is the
                claim, and a version of this that deleted the row would pass
                a weaker test while breaking the actual promise.

``starvation``  A page of refusals must not silently shorten the answer. 40
                expired rows ahead of 6 live ones returned zero hits for a
                limit of 5 -- indexed, on disk, and reported as an empty
                scope. This check exists because that bug shipped.

``clearance``   A document above the caller's clearance must be absent, not
                low-ranked -- and the audit handle must not be a way around
                that. Both enforcement points are compared against each
                other, because the failure that matters is them disagreeing:
                the ``$vectorSearch`` path only ever uses one of them.

``reversal``    A hold can be lifted and keeps no erase deadline while held;
                an erasure cannot be lifted by any route. The asymmetry is
                easy to state and easy to get backwards, and a deployment
                that has it backwards looks completely healthy -- a
                quarantine that erases its own evidence surfaces nothing
                until the evidence is gone, and an undoable erasure leaves
                a chain that is intact and false.

``chain``       The refusal ledger, recomputed from entry zero. Needs no key.

Exit status is the point, so this belongs in CI:

    voyd verify --uri "$MONGO_URI"      # 0 = every check held, 1 = one did not

It is destructive only inside a database it creates and drops (``voyd_verify_*``),
and it never touches application data. What it *does* touch is a server
global: parking ``ttlMonitorSleepSecs`` is how the deadline check proves the
row is still on disk. That is a whole-server setting, so do not run this
concurrently with anything else that cares -- the value is restored on the way
out, including on failure.
"""

from __future__ import annotations

import argparse
import asyncio
import random
import sys
import uuid
from dataclasses import dataclass, field
from datetime import timedelta

from .engine import (REVOKED, Clearance, Deadline, Engine,
                     Irreversible, now, quarantined, revoked)

DIMS = 8
PARKED = 86_400          # seconds: the TTL monitor, effectively stopped
LEVELS = ("public", "internal", "secret")


def vec(seed: int) -> list[float]:
    random.seed(seed)
    return [random.random() for _ in range(DIMS)]


@dataclass
class Check:
    name: str
    claim: str
    ok: bool = True
    notes: list[str] = field(default_factory=list)

    def fail(self, note: str) -> None:
        self.ok = False
        self.notes.append(note)

    def note(self, note: str) -> None:
        self.notes.append(note)


class Verifier:
    """The six checks, and the parked-sweeper scaffolding they need."""

    def __init__(self, client, db, *, quiet: bool = False):
        self.client = client
        self.engine = Engine(client, db)
        self.db = self.engine.db
        self.quiet = quiet
        self.checks: list[Check] = []
        self._ttl_was: int | None = None

    def say(self, line: str = "") -> None:
        if not self.quiet:
            print(line, flush=True)

    # ---- the sweeper ---------------------------------------------------

    async def park_sweeper(self) -> bool:
        """Stop the TTL monitor, so "still on disk" is a fact and not a race.

        Without this the check is a coin flip: the reaper may or may not have
        run between planting the document and reading it, and a pass would
        mean nothing. Returns False when the deployment will not allow it --
        ``setParameter`` needs privileges a hosted tier may not grant -- and
        the deadline check then says it could not prove the stronger claim
        rather than quietly proving the weaker one.
        """
        try:
            res = await self.client.admin.command(
                {"setParameter": 1, "ttlMonitorSleepSecs": PARKED})
            self._ttl_was = int(res.get("was", 60))
            return True
        except Exception as exc:  # noqa: BLE001 - a hosted tier may refuse
            self.say(f"  ! could not park the TTL monitor ({exc}).")
            return False

    async def unpark_sweeper(self) -> None:
        if self._ttl_was is None:
            return
        try:
            await self.client.admin.command(
                {"setParameter": 1, "ttlMonitorSleepSecs": self._ttl_was})
        except Exception:  # noqa: BLE001
            self.say(f"  ! FAILED to restore ttlMonitorSleepSecs to "
                     f"{self._ttl_was}. Do it by hand -- expired documents "
                     f"are not being collected on this server.")

    # ---- setup ---------------------------------------------------------

    async def declare(self):
        docs = self.engine.model("verify_docs", tenant="scope")
        docs.searchable(text_paths=("text",), dimensions=DIMS)
        # forgettable() declares the TTL too -- one policy, and the check
        # below depends on both halves being the same declaration.
        self.docs = docs.forgettable()
        self.chain = self.engine.ledger("verify_chain", tenant="scope")
        self.docs.witnessed_by(self.chain)

        # A second collection, because clearance is a policy a collection
        # either has or does not, and bolting it onto the collection above
        # would change what the other checks are measuring.
        classified = self.engine.model("verify_classified", tenant="scope")
        classified.searchable(text_paths=("text",), dimensions=DIMS)
        self.classified = classified.admitting(
            Deadline(), revoked(), Clearance(order=LEVELS))

        # A third, for the reversal check. Quarantine has to be declared to
        # exist, and declaring it on ``verify_docs`` would change what the
        # deadline and starvation checks are measuring.
        holdable = self.engine.model("verify_held", tenant="scope")
        self.held = holdable.admitting(Deadline(), revoked(), quarantined())
        self.held.witnessed_by(self.chain)

        await self.engine.ensure(search_wait_s=90)
        return self.docs

    async def plant(self, text: str, *, seed: int = 1, expire_at="pin",
                    scope: str = "s1") -> dict:
        doc = {"scope": scope, "text": text, "embedding": vec(seed),
               "expire_at": None if expire_at == "pin" else expire_at}
        await self.db.verify_docs.insert_one(dict(doc))
        return doc

    async def indexed(self, n: int, *, scope: str = "s1",
                      timeout: float = 90.0) -> bool:
        """Wait until mongot can see ``n`` rows.

        Load-bearing: an index that is still building returns zero rows
        rather than raising, so without this wait every check below would
        pass for the wrong reason -- "the document was refused" and "the
        index was not ready" look identical from here, and that
        indistinguishability is the bug this repository blocks startup over.
        """
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            # The primitive on purpose, and one of the two reasons this file
            # is exempt from the no-reaching-past-the-handle guard: the
            # question here is what *mongot* has, not what may be returned.
            # Asking through the handle would conflate "not indexed yet" with
            # "indexed and refused", and the whole point of waiting is to
            # tell those apart before any check runs.
            hits = await self.engine.search("verify_docs", vec(1), limit=100,
                                            filters={"scope": scope})
            if len(hits) >= n:
                return True
            await asyncio.sleep(0.5)
        return False

    async def every_read_path(self, *, scope: str = "s1") -> dict[str, list]:
        """Ask for the documents in every way that carries the guarantee.

        The point of enumerating them is that the historical bug was never
        "the rule is wrong" -- it was "one read path did not apply it". Six
        read paths once went to MongoDB with a tenant filter and no deadline,
        so a check that exercised one of them would have passed on the day
        they all leaked.

        ``engine.search`` is deliberately **not** in this list. It is the
        search primitive and it admits nothing -- it returns what mongot
        ranked. The guaranteed path is ``handle.search()``, which is what
        ``Memory.recall`` and ``MongoStore.vector_search`` are one line of
        each. ``raw_search_leaks`` below asserts that the primitive really
        does return forgotten documents, because a sharp edge described only
        in a docstring gets held by somebody who did not read it.
        """
        return {
            "handle.search": list(await self.docs.search(
                vec(1), text="the", limit=50, filters={"scope": scope})),
            "handle.find": await self.docs.find({"scope": scope}),
            "handle.find_one": [d for d in
                                [await self.docs.find_one({"scope": scope})]
                                if d],
            "handle.count": await self.docs.count({"scope": scope}),
        }

    async def raw_search_leaks(self, text: str, *, scope: str) -> bool:
        """Does the *unwrapped* primitive return the forgotten document?

        Expected: yes. ``engine.search`` is the mechanism, not the guarantee
        -- deadlines are deliberately not pushed into the vector index, so a
        ``$vectorSearch`` hit has never been filtered by anything. Reporting
        it here turns the one genuine footgun in the engine into a line of
        output, and a *falsified* expectation is worth knowing too: if this
        stops leaking, the read-path check above has quietly become a
        tautology and would keep passing after somebody removed it.
        """
        hits = await self.engine.search("verify_docs", vec(1), text="the",
                                        limit=50, filters={"scope": scope})
        return any(h.get("text") == text for h in hits)

    # ---- the checks ----------------------------------------------------

    async def check_deadline(self, *, parked: bool) -> Check:
        c = Check("deadline",
                  "an expired document is unreachable while its row is on disk")
        doomed = "verify-doomed the fault code is P0301"
        await self.plant(doomed, expire_at=now() + timedelta(hours=1))
        await self.plant("verify-live the user's name is Dana")
        if not await self.indexed(2):
            c.fail("mongot did not index the planted documents; nothing was "
                   "proven either way")
            return c

        await self.db.verify_docs.update_one(
            {"text": doomed}, {"$set": {"expire_at": now() - timedelta(minutes=5)}})

        on_disk = await self.db.verify_docs.count_documents({"text": doomed})
        if on_disk != 1:
            c.note("the row was already collected, so this proved only that "
                   "deletion works -- park the TTL monitor for the real claim")
        elif parked:
            c.note("the row is still on disk (TTL monitor parked), so every "
                   "refusal below is the read path and not the sweeper")

        reads = await self.every_read_path()
        for path, result in reads.items():
            if path == "handle.count":
                if result != 1:
                    c.fail(f"{path} counted {result} reachable, expected 1")
                continue
            leaked = [d for d in result if d.get("text") == doomed]
            if leaked:
                c.fail(f"{path} returned an expired document")

        if await self.raw_search_leaks(doomed, scope="s1"):
            c.note("engine.search (the primitive) does return it, as "
                   "designed -- the deadline is not in the vector index, so "
                   "the read path is the guarantee. Search through the "
                   "handle instead: docs.search(...)")
        else:
            c.note("engine.search did not return it either, so this run did "
                   "not actually test the read path -- check the index is "
                   "ready before trusting the pass above")
        return c

    async def check_revocation(self) -> Check:
        c = Check("revocation",
                  "a revoked fact is refused on the next read, and its row stays")
        secret = "verify-secret the admin password is hunter2"
        await self.plant(secret, scope="s2")
        await self.plant("verify-kept fault code P0301", scope="s2")
        if not await self.indexed(2, scope="s2"):
            c.fail("mongot did not index the planted documents")
            return c

        n = await self.docs.revoke({"scope": "s2", "text": secret},
                                   reason="voyd verify")
        if n != 1:
            c.fail(f"revoke() marked {n} documents, expected 1")

        reads = await self.every_read_path(scope="s2")
        for path, result in reads.items():
            if path == "handle.count":
                continue
            if [d for d in result if d.get("text") == secret]:
                c.fail(f"{path} returned a revoked document")

        still_there = await self.db.verify_docs.count_documents({"text": secret})
        if still_there != 1:
            c.fail("the revoked row was deleted. Unreachable-first is the "
                   "claim; a delete here would pass a weaker test and break "
                   "the promise -- you cannot investigate what you erased")
        else:
            c.note("the row is still on disk and already unreachable")

        seen = await self.docs.including_refused().find(
            {"scope": "s2", "text": secret})
        if not seen:
            c.fail("including_refused() could not see the revoked row, so "
                   "there is no way to audit what was forgotten")
        return c

    async def check_starvation(self) -> Check:
        c = Check("starvation", "a page of refusals is refilled, not truncated")
        for i in range(40):
            await self.plant(f"verify-starve doomed {i}", scope="s3")
        for i in range(6):
            await self.plant(f"verify-starve live {i}", scope="s3")
        if not await self.indexed(46, scope="s3"):
            c.fail("mongot did not index the planted documents")
            return c

        await self.db.verify_docs.update_many(
            {"scope": "s3", "text": {"$regex": "doomed"}},
            {"$set": {"expire_at": now() - timedelta(minutes=5)}})

        page = await self.docs.search(vec(1), text="verify-starve", limit=5,
                                      filters={"scope": "s3"})
        if len(page) < 5:
            c.fail(f"asked for 5 reachable documents, got {len(page)} with 6 "
                   f"live and indexed; refusal is shortening the answer "
                   f"(examined {page.examined}, refused {page.refused})")
        if page.starved:
            c.fail("the page reports itself starved, which is at least honest")
        if any("doomed" in d["text"] for d in page):
            c.fail("an expired document was in the page")
        c.note(f"filled 5 of 5 after examining {page.examined} candidates, "
               f"refusing {sum(page.refused.values())}")
        return c

    async def check_clearance(self) -> Check:
        c = Check("clearance",
                  "a document above the caller's clearance is absent, not ranked")
        rows = [{"scope": "s4", "text": f"verify-{lvl}", "classification": lvl,
                 "expire_at": None, "embedding": vec(1)} for lvl in LEVELS]
        rows.append({"scope": "s4", "text": "verify-untagged",
                     "expire_at": None, "embedding": vec(1)})
        await self.db.verify_classified.insert_many(rows)

        expected = {"public": {"verify-public"},
                    "internal": {"verify-public", "verify-internal"},
                    "secret": {"verify-public", "verify-internal",
                               "verify-secret"}}
        for level, want in expected.items():
            handle = self.classified.for_caller({"clearance": level})
            got = {d["text"] for d in await handle.find({"scope": "s4"})}
            if got != want:
                c.fail(f"a caller cleared for {level} saw {sorted(got)}, "
                       f"expected {sorted(want)}")
            # The same set by the other route. These two are two enforcement
            # points for one rule, and a disagreement means the vector path
            # -- which only ever uses the second -- is the wrong one.
            raw = [d async for d in self.db.verify_classified.find(
                {"scope": "s4"})]
            per_doc = {d["text"] for d in handle.reachable(raw)}
            if per_doc != want:
                c.fail(f"the query and the per-document check disagree for "
                       f"{level}: {sorted(per_doc)} vs {sorted(got)}")

        blind = self.classified.for_caller({})
        if await blind.find({"scope": "s4"}):
            c.fail("a caller with no clearance claim was served documents; "
                   "a missing claim must be the lowest level, not a pass")

        if {d["text"] for d in await self.classified.for_caller(
                {"clearance": "secret"}).find({"scope": "s4"})} & \
                {"verify-untagged"}:
            c.fail("an untagged document was served; untagged is not public, "
                   "or every row predating the policy is world-readable")

        auditor = self.classified.for_caller(
            {"clearance": "public"}).including_refused()
        leaked = {d["text"] for d in await auditor.find({"scope": "s4"})} - \
            {"verify-public"}
        if leaked:
            c.fail(f"including_refused() served {sorted(leaked)} to a caller "
                   f"cleared for public only -- the audit handle is a way "
                   f"around access control")
        else:
            c.note("the audit handle sees forgotten rows and nothing above "
                   "the caller's clearance")
        return c

    async def check_chain(self) -> Check:
        c = Check("chain", "the refusal ledger recomputes intact")
        report = await self.chain.verify(tenant="s2")
        if not report.get("intact"):
            c.fail(f"the refusal chain does not verify: {report}")
            return c
        if not report.get("entries"):
            c.fail("no entries on the chain, so the revocation above was not "
                   "recorded -- refusal happened and left no evidence")
            return c
        # Deliberately *not* checking the signature here. This process signed
        # it with the key it is holding, so re-verifying it with that same key
        # cannot fail -- it is the vacuous pass this checker refuses to accept
        # anywhere else. A signature is verified by whoever did not produce
        # it; see ``Ledger.signature_valid``.
        c.note(f"{report['entries']} entr(y/ies), head {report['head'][:16]}..., "
               f"signed={report['signed']}"
               + ("" if report["signed"] else
                  " (unsigned, and reported as such -- still tamper-evident, "
                  "because verifying the chain needs no key)"))
        return c

    async def check_reversal(self) -> Check:
        """The asymmetry, attacked from both sides.

        Two claims that are easy to state and easy to get backwards, and a
        deployment where either one fails looks completely healthy:

        - a **hold** can be lifted, and the row keeps no erase deadline
          while it is held. A quarantine that quietly schedules its own
          subject for deletion is an investigation with a countdown on it,
          and nothing surfaces that until the evidence is gone.
        - an **erasure** cannot be lifted, by any route -- including
          ``release()``, which is the one somebody reaches for at 3am.

        Checked here rather than left to the suite because the second claim
        is the kind that a local patch, a fork, or a well-meaning
        "unrevoke for support" endpoint would quietly remove, and the whole
        premise of this command is that a property nobody can see being
        violated has to be attacked rather than looked at.
        """
        c = Check("reversal",
                  "a hold can be lifted, an erasure cannot, and both reach "
                  "the chain")
        await self.db.verify_held.insert_many([
            {"scope": "s3", "text": "verify-flagged", "expire_at": None},
            {"scope": "s3", "text": "verify-erased", "expire_at": None},
        ])
        flagged = {"scope": "s3", "text": "verify-flagged"}
        erased = {"scope": "s3", "text": "verify-erased"}

        if await self.held.quarantine(flagged, reason="voyd verify") != 1:
            c.fail("quarantine() did not mark the document")
            return c
        if await self.held.find({"scope": "s3", "text": "verify-flagged"}):
            c.fail("a quarantined document was returned by a read")
        row = await self.db.verify_held.find_one(flagged)
        if row is None:
            c.fail("the held row was deleted; you cannot investigate what "
                   "you erased")
        elif row.get("expire_at") is not None:
            c.fail("a hold stamped an erase deadline, so the evidence is "
                   "scheduled for deletion while the investigation runs")
        else:
            c.note("held, unreachable, and no deadline on the evidence")

        if await self.held.release(flagged, reason="voyd verify: cleared") != 1:
            c.fail("release() did not lift the hold")
        if not await self.held.find({"scope": "s3", "text": "verify-flagged"}):
            c.fail("a released document is still unreachable, so quarantine "
                   "is a graveyard rather than a workflow")

        await self.held.revoke(erased, reason="voyd verify")
        try:
            await self.held.lift(REVOKED, erased, reason="voyd verify")
        except Irreversible:
            c.note("an erasure refused to be lifted, as it must")
        else:
            c.fail("a REVOKED mark was lifted. An erasure that can be undone "
                   "is not an erasure, and the chain still says it happened")
        if await self.held.release(erased, reason="voyd verify"):
            c.fail("release() removed a revocation, so the front door is "
                   "weaker than the general form it is built on")
        if await self.held.find({"scope": "s3", "text": "verify-erased"}):
            c.fail("a revoked document became reachable again")

        # How an investigation ends when the answer is "yes, it was
        # malicious". Reasons are not mutually exclusive, and a write path
        # that skips already-refused documents makes this return 0 -- the
        # row keeps only the reversible mark, and the next release() puts
        # it back in front of a model.
        await self.db.verify_held.insert_one(
            {"scope": "s3", "text": "verify-escalated", "expire_at": None})
        both = {"scope": "s3", "text": "verify-escalated"}
        await self.held.quarantine(both, reason="voyd verify: suspected")
        if await self.held.revoke(both, reason="voyd verify: confirmed") != 1:
            c.fail("a quarantined document could not be erased, so an "
                   "investigation that concludes 'malicious' has no way to "
                   "act and the document stays one release() from a prompt")
        else:
            c.note("a hold can escalate to an erasure; reasons stack")
        return c

    # ---- driver --------------------------------------------------------

    async def run(self) -> bool:
        caps = await self.engine.connect()
        parked = await self.park_sweeper()
        try:
            # Declared before the tier is reported, deliberately: until
            # ``ensure()`` has waited for the indexes, the tier reads
            # "cosine (indexes building)" and would have every run announce a
            # degraded deployment that is about to be fine.
            await self.declare()
            self.say(f"  mongodb {'.'.join(str(p) for p in caps.version)}  "
                     f"tier={self.engine.search_tier}  search={caps.search}")
            if self.engine.search_tier.startswith("cosine"):
                self.say("  ! no Atlas Search on this deployment, so the "
                         "checks below ran against the in-process cosine "
                         "fallback. They still hold -- but they did not test "
                         "your $vectorSearch, which is the path that has "
                         "never been filtered by a deadline.")
            self.say()
            for coro in (self.check_deadline(parked=parked),
                         self.check_revocation(),
                         self.check_starvation(),
                         self.check_clearance(),
                         self.check_reversal(),
                         self.check_chain()):
                check = await coro
                self.checks.append(check)
                self.report(check)
        finally:
            await self.unpark_sweeper()
        return all(c.ok for c in self.checks)

    def report(self, c: Check) -> None:
        self.say(f"  [{'ok  ' if c.ok else 'FAIL'}] {c.name}: {c.claim}")
        for n in c.notes:
            self.say(f"         {n}")


async def verify(uri: str, *, quiet: bool = False, keep: bool = False) -> bool:
    from pymongo import AsyncMongoClient

    client = AsyncMongoClient(uri)
    name = f"voyd_verify_{uuid.uuid4().hex[:8]}"
    v = Verifier(client, client[name], quiet=quiet)
    v.say(f"voyd verify -- against {uri.split('@')[-1]}")
    v.say(f"  scratch database: {name} (dropped on the way out)")
    v.say()
    try:
        ok = await v.run()
    finally:
        if not keep:
            await client.drop_database(name)
        else:
            v.say(f"\n  kept {name} for inspection")
        await client.close()

    v.say()
    if ok:
        v.say("  every check held. A forgotten fact cannot reach a prompt on "
              "this deployment.")
    else:
        v.say("  AT LEAST ONE CHECK FAILED. On this deployment, a fact that "
              "was supposed to be forgotten can reach a prompt. The failing "
              "check above names the read path.")
    return ok


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="voyd verify",
        description="Attack this deployment's refusal guarantee and report "
                    "whether it held. Exit 0 if it did.")
    p.add_argument("--uri", default="mongodb://localhost:27018/?directConnection=true",
                   help="MongoDB connection string to verify")
    p.add_argument("--quiet", action="store_true",
                   help="print nothing; use the exit status")
    p.add_argument("--keep", action="store_true",
                   help="do not drop the scratch database")
    args = p.parse_args(argv)
    return 0 if asyncio.run(verify(args.uri, quiet=args.quiet,
                                   keep=args.keep)) else 1


if __name__ == "__main__":
    sys.exit(main())
