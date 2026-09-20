"""Forgetting that survives being summarised.

    docker compose up -d
    uv run python examples/lineage.py    # ~5 seconds, no API key, no vendor

``refuse.py`` forgets a fact. This shows the way that is not enough, and it is
the failure that defeats the guarantee using the guarantee's own storage.

An agent retrieves a document, summarises it, and writes the summary back into
the same collection -- which is what retrieval that writes back *is*. Later
somebody asks for the source to be erased. ``revoke()`` honours that request
perfectly, against the source. The summary, which quotes it, keeps scoring
well forever.

The erasure is satisfied. The information is not gone. Every receipt in the
system says the system worked.

The fix costs no new read-path rule: ``revoked()`` already refuses anything
carrying the mark, and what was missing is that the mark did not *travel*.
``derive()`` records what a document was made out of -- transitively closed at
write time, so a grandchild already names the grandparent -- and one indexed
query reaches the whole subtree at any depth.
"""

from __future__ import annotations

import asyncio
import uuid

from pymongo import AsyncMongoClient

from voyd.engine import Deadline, DerivationBroken, Engine, revoked

URI = "mongodb://localhost:27018/?directConnection=true"

DIAGNOSIS = "alice was treated for a stress fracture in March"
SUMMARY = "patient summary: one orthopaedic episode, resolved"
BRIEFING = "ward briefing: no outstanding orthopaedic cases"
UNRELATED = "the fault code is P0301"


async def main() -> None:
    client = AsyncMongoClient(URI)
    name = f"core_lineage_{uuid.uuid4().hex[:8]}"
    engine = Engine(client, client[name])
    await engine.connect()

    try:
        notes = engine.model("notes").admitting(
            Deadline(), revoked(), lineage_field="lineage")
        chain = engine.ledger("refusals")
        notes.witnessed_by(chain)
        await engine.ensure(search_wait_s=0)

        src = (await engine.db.notes.insert_one(
            {"text": DIAGNOSIS})).inserted_id
        await engine.db.notes.insert_one({"text": UNRELATED})

        print("\n  An agent reads the record and writes what it concluded.")
        summary, = await notes.derive({"text": SUMMARY}, parents=[src])
        briefing, = await notes.derive({"text": BRIEFING}, parents=[summary])
        print(f"    reachable -> {len(await notes.find({}))} facts")

        kid = await engine.db.notes.find_one({"_id": briefing})
        print(f"\n    the briefing's lineage is {len(kid['lineage'])} deep: "
              f"it names the summary")
        print("    AND the diagnosis, because closure happens at write time.")
        print("    That is why the erasure below is one query, not a walk.")

        print("\n  Alice asks to be forgotten. Erase the source only:")
        print("    revoke({'_id': <diagnosis>})")
        n = await notes.revoke({"_id": src}, reason="subject erasure request")
        print(f"    -> {n} facts marked, not 1")

        left = [d["text"] for d in await notes.find({})]
        print(f"\n    reachable -> {left}")
        print("       the summary and the briefing went with it. A summary of")
        print("       a summary is still the fact somebody asked to erase.")
        print(f"    on disk   -> {await engine.db.notes.count_documents({})} "
              f"rows. Unreachable first, erased second, as always.")

        print("\n  And the race is closed from the write side too. An agent")
        print("  that still holds the text and tries to write it back:")
        try:
            await notes.derive({"text": "late summary"}, parents=[src])
        except DerivationBroken as e:
            print(f"    DerivationBroken: {str(e).split('.')[0].split(': ', 1)[1]}")
        print("       Refused, not written-and-marked: reaching here means")
        print("       something read a document it should not have been given.")

        print("\n  The chain says how far the erasure reached:")
        entry = (await chain.entries())[-1]
        print(f"    seq {entry['seq']}  {entry['event']}  {entry['reason']}")
        print(f"              detail={entry['detail']}")
        print("       'you asked to erase 1 fact and 2 things made out of it")
        print("        went too' is the sentence an auditor needs, and one")
        print("        total cannot say it.")

        print("\n  facts erased: 1.  facts made unreachable: 3.")
        print("  paragraphs quoting an erased fact still in the index: 0\n")
    finally:
        await client.drop_database(name)
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
