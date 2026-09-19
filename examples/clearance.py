"""The question neither layer was asking: may this reach *this* caller?

    docker compose up -d
    uv run python examples/clearance.py     # ~5 seconds, no API key, no vendor

A passcode on a scope is all-or-nothing. So the moment one document in a
scope is more sensitive than the rest, the available answers are "everyone
gets everything" and "split the scope" -- and one retrieval boundary per
sensitivity level is four owners of one deadline all over again.

So sensitivity is a field on the document, clearance is a claim on the
caller, and they meet in the layer that already refuses things. What this
prints is the same query, run three times, by three people.

The vectors are fake on purpose: the thing being demonstrated is the
boundary, not the model.
"""

from __future__ import annotations

import asyncio
import os
import random
import uuid

from pymongo import AsyncMongoClient

from voyd.engine import Clearance, Deadline, Engine, revoked

URI = os.environ.get("VOYD_TEST_MONGO_URI",
                     "mongodb://localhost:27018/?directConnection=true")
DIMS = 8
LEVELS = ("public", "internal", "secret")

NOTES = [
    ("public",   "the office is closed on Monday"),
    ("internal", "Q3 headcount plan is 14 engineers"),
    ("secret",   "the 2019 acquisition fell through over the pension liability"),
    (None,       "an untagged note nobody classified"),
]


def vec(seed: float) -> list[float]:
    random.seed(seed)
    return [random.random() for _ in range(DIMS)]


def head(text: str) -> None:
    print(f"\n{text}")


async def main() -> None:
    client = AsyncMongoClient(URI)
    db_name = f"core_clearance_{uuid.uuid4().hex[:8]}"
    engine = Engine(client, client[db_name])

    notes = engine.model("notes", tenant="team")
    notes.searchable(text_paths=("text",), dimensions=DIMS)
    docs = notes.admitting(Deadline(), revoked(), Clearance(order=LEVELS))

    await engine.connect()
    await engine.ensure(search_wait_s=60)

    try:
        for level, text in NOTES:
            await engine.db.notes.insert_one({
                "team": "acme", "text": text, "classification": level,
                "expire_at": None, "embedding": vec(1)})

        print(f"  {len(NOTES)} notes in one scope, one retrieval boundary, "
              f"one deadline.")
        print("  Same query, three callers:")

        for clearance in LEVELS:
            hits = await docs.for_caller({"clearance": clearance}).find(
                {"team": "acme"})
            head(f"  caller cleared for {clearance!r}:")
            for h in hits:
                print(f"    - [{h['classification']}] {h['text']}")
            print(f"    {len(hits)} of {len(NOTES)} reachable")

        head("  Note what is missing from all three: the untagged note.")
        print("    Untagged is not public. A document with no label is refused")
        print("    until somebody declares a default -- otherwise every row")
        print("    written before the policy existed is world-readable, which")
        print("    is the population most likely to predate anyone thinking")
        print("    about sensitivity at all.")

        head("  And a caller who simply did not send a claim:")
        blind = await docs.for_caller({}).find({"team": "acme"})
        print(f"    {len(blind)} reachable. A missing claim is the lowest")
        print("    level, not a pass -- the other way round is how a dataset")
        print("    becomes world-readable on the one code path nobody")
        print("    threaded the claim through.")

        head("  The audit handle, which exists to see what was forgotten.")
        print("    Somebody revokes the public note -- so it is now both")
        print("    forgotten AND within a 'public' caller's clearance, which")
        print("    is the combination that tells the two rules apart:")
        # Bound, and it has to be: a handle with a clearance rule refuses to
        # read *or write* without knowing who is asking. Unbound, this
        # revocation matched zero rows and returned success -- which is how
        # this example found a bug the test suite did not have.
        await docs.for_caller({"clearance": "secret"}).revoke(
            {"team": "acme", "classification": "public"}, reason="retracted")

        public = docs.for_caller({"clearance": "public"})
        print(f"    ordinary read:        {len(await public.find({'team': 'acme'}))} row(s)"
              "   <- revoked, so refused")
        auditor = public.including_refused()
        seen = await auditor.find({"team": "acme"})
        print(f"    including_refused(): {len(seen)} row(s)"
              "   <- the forgotten one is back")
        for h in seen:
            print(f"      - [{h['classification']}] {h['text']}")
        print("    One row, not four. The audit handle waived the *revocation*")
        print("    and could not waive the *clearance* -- the internal and")
        print("    secret notes are still absent. One method waiving both")
        print("    would make 'let me see the deleted rows' a privilege")
        print("    escalation.")

        head("  Everything above is one collection, one TTL index, one scope.")
        print("    No second boundary, no per-level namespace, nothing to keep")
        print("    in step.")
    finally:
        await client.drop_database(db_name)
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
