"""Forget something *now*, without deleting it. The operation nobody has.

    docker compose up -d
    uv run python examples/refuse.py      # ~5 seconds, no API key, no vendor

``forget.py`` shows a deadline arriving on its own. This shows the other half,
and the half no vector database offers at all: somebody asks you to forget a
fact *right now* -- an erasure request, a leaked credential, a retracted
document -- and you have to answer for when it stopped being reachable.

Every system's honest answer to that is "whenever the sweeper got to it",
because deletion is the only tool they have and deletion is eventually
consistent by nature. A TTL monitor runs about once a minute (measured here:
60.0s). A lifecycle rule runs about once a day. In that window the fact is
still ranking into prompts.

The distinction this example draws:

    delete   a storage operation. Eventually. Best effort. Unprovable.
    revoke   a retrieval guarantee. Next read. Immediate. Counted.

The row is deliberately still on disk at the end of this program. That is not
a failure to clean up -- it is the proof. Unreachable first, erased second, in
that order, because the reverse order is the bug.
"""

from __future__ import annotations

import asyncio
import random
import uuid

from pymongo import AsyncMongoClient

from voyd.engine import Engine

URI = "mongodb://localhost:27018/?directConnection=true"
DIMS = 8

SECRET = "the admin password is hunter2"
KEPT = "the fault code is P0301"


def vec(seed: int) -> list[float]:
    rng = random.Random(seed)
    return [rng.random() for _ in range(DIMS)]


async def main() -> None:
    client = AsyncMongoClient(URI)
    name = f"core_refuse_{uuid.uuid4().hex[:8]}"
    engine = Engine(client, client[name])
    await engine.connect()

    try:
        notes = engine.model("notes").forgettable()
        await engine.ensure(search_wait_s=0)

        await engine.db.notes.insert_many([
            {"text": SECRET, "vector": vec(1)},
            {"text": KEPT, "vector": vec(2)},
        ])

        print("\n  Two facts, no deadlines. Both pinned, both reachable.")
        print(f"    recall -> {[d['text'] for d in await notes.find({})]}")

        print("\n  Now somebody says: forget that first one. Right now.")
        n = await notes.revoke({"text": SECRET}, reason="credential leaked")
        print(f"    revoke() marked {n} fact(s) unreachable")

        reachable = [d["text"] for d in await notes.find({})]
        on_disk = await engine.db.notes.count_documents({})
        print(f"\n    recall  -> {reachable}")
        print(f"    on disk -> {on_disk} rows        <- the secret is STILL HERE")
        print("       and it is already unreachable. No sweeper ran. Nothing")
        print("       was deleted. The next read simply refused it.")

        print("\n  The same query, straight at the collection, for contrast --")
        print("  this is what every other system's read path looks like:")
        leaked = [d["text"] async for d in engine.db.notes.find({})]
        print(f"    find() -> {leaked}")
        print("       ^ the revoked fact, returned as a normal result.")

        print("\n  Audit can still see it, but has to say so out loud:")
        audit = await notes.including_forgotten().find_one({"text": SECRET})
        mark = audit["forgotten"]
        print(f"    including_forgotten() -> reason={mark['reason']!r}")
        print(f"                             unreachable since {mark['at'].isoformat()}")

        print("\n  And it is counted, so it is provable rather than merely true:")
        r = notes.receipts()
        print(f"    revoked_total       {r['revoked_total']}   (exact)")
        print(f"    refused_at_boundary {r['refused_at_boundary']}   (a lower bound --")
        print("       the same rule runs inside the query, so MongoDB dropped this")
        print("       one server-side and the handle never had to reject it.")
        print("       Search hits are the case that does reach the boundary:")
        raw = [d async for d in engine.db.notes.find({})]
        kept_hits = notes.reachable(raw)
        r = notes.receipts()
        print(f"       after admitting {len(raw)} raw hits -> {len(kept_hits)} kept, "
              f"refused_at_boundary {r['refused_at_boundary']})")

        print("\n  delete calls issued by this program: 0")
        print("  facts that reached a prompt after being forgotten: 0\n")
    finally:
        await client.drop_database(name)
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
