"""Watch it forget. The whole thesis, observed rather than promised.

    docker compose up -d
    uv run python examples/forget.py

Start here. The other engine examples show the parts working; this one stays to
watch the deadline actually land, and prints a timeline while it does.
``why_this_belongs_in_the_database.py`` is the companion: same mechanism, but
it shows what happens when a read path *forgets* to check the deadline.

There are two deadlines in play, and that is the point:

1. **Retrieval refuses an expired memory immediately.** MongoDB's TTL monitor
   runs about once a minute, so an expired row stays *on disk* for a window
   after its deadline. Most systems will happily serve it during that window --
   a deleted document still answering queries is the bug this exists to remove.
   So ``recall()`` checks ``expire_at`` on every hit before returning it. The
   deadline is enforced on read, not just by the janitor.

2. **Then the reaper takes the row, and the vector goes with it.** One
   ``expire_at`` on one document. Not a row here and an embedding there.

The demo turns ``ttlMonitorSleepSecs`` down to 1 so step 2 takes seconds
instead of a minute. That is a local-development knob for the sake of a visible
demo -- the production default is 60, and nothing in VOYD depends on the value.

Pure Engine: no FastAPI, no API key, no embedding vendor. The vectors are fake
so this runs with nothing installed but a database.

Run this alone. ``ttlMonitorSleepSecs`` is a *server-global* parameter, and
this script parks it and restores the previous value. The test suite has a
reaper test that does the same thing, so running the two at once makes each
restore the other's temporary value -- and the failure shows up as an
unrelated test asserting the wrong row count.
"""

from __future__ import annotations

import asyncio
import os
import time
from datetime import timedelta

from pymongo import AsyncMongoClient

from voyd import Engine

URI = os.getenv("VOYD_MONGO_URI", "mongodb://localhost:27018/?directConnection=true")
DIMS = 8
LIFESPAN = timedelta(seconds=8)

# Deliberately not a round number, so "did it actually expire?" is answerable.
SESSION = "sess-forget-demo"

T0 = 0.0


def clock() -> str:
    return f"t+{time.monotonic() - T0:5.1f}s"


def say(msg: str) -> None:
    print(f"  {clock()}  {msg}")


def vec(n: float) -> list[float]:
    return [n] * DIMS


async def rows(engine) -> int:
    """How many memory documents physically exist, expired or not."""
    return await engine.db.memories.count_documents({})


async def vectors(engine) -> int:
    """How many embeddings physically exist. The number that must not drift."""
    return await engine.db.memories.count_documents(
        {"embedding": {"$ne": None}})


async def main() -> None:
    global T0
    client = AsyncMongoClient(URI)

    was = 60
    try:
        await client.drop_database("voyd_forget_demo")
        engine = Engine(client, client["voyd_forget_demo"])
        await engine.connect()

        # Local-only: make the reaper visible on a human timescale.
        try:
            res = await client.admin.command(
                {"setParameter": 1, "ttlMonitorSleepSecs": 1})
            was = res.get("was", 60)
        except Exception as exc:  # noqa: BLE001 - a managed cluster will refuse
            print(f"note: could not speed up the TTL monitor ({exc}).\n"
                  "      the deadline still holds; the reaper just takes "
                  "up to a minute.\n")

        mem = engine.model("memories", tenant="scope").memory(
            default_ttl=LIFESPAN, dimensions=DIMS)
        await engine.ensure()
        print(f"search tier: {engine.search_tier}\n")

        # ---- two memories in ONE collection, with different deadlines ----
        # This is what makes "remember for 8 seconds" and "remember forever"
        # the same storage path instead of two subsystems.
        T0 = time.monotonic()
        await mem.remember(SESSION, "the fault code is P0301", vec(0.9))
        await mem.remember(SESSION, "the user's name is Dana", vec(0.9),
                           pinned=True)
        say(f"remembered 2: one expiring in {LIFESPAN.seconds}s, one pinned")

        # Embedding/indexing is asynchronous. An index that is still building
        # must never be mistaken for an empty one, so wait for the hit.
        for _ in range(60):
            hits = await mem.recall(SESSION, vec(0.9), text="P0301")
            if len(hits) == 2:
                break
            await asyncio.sleep(0.5)
        else:
            raise SystemExit(
                "nothing became searchable in 30s -- is Atlas Local up? "
                "docker compose up -d")

        say(f"recall -> {sorted(h['text'] for h in hits)}")
        say(f"on disk: {await rows(engine)} rows, "
            f"{await vectors(engine)} vectors")

        # ---- beat 1: retrieval fails closed before the reaper arrives ----
        print()
        say("waiting for the deadline...")
        seen_gap = False
        deadline = time.monotonic() + LIFESPAN.total_seconds() + 30
        while time.monotonic() < deadline:
            await asyncio.sleep(0.4)
            recalled = await mem.recall(SESSION, vec(0.9), text="P0301")
            texts = {h["text"] for h in recalled}
            on_disk = await rows(engine)

            if "the fault code is P0301" not in texts:
                if not seen_gap and on_disk == 2:
                    # THE WINDOW: unreachable by recall, still physically present.
                    say("DEADLINE PASSED")
                    say(f"recall -> {sorted(texts)}   <- expired memory is "
                        "already unreachable")
                    say(f"on disk: {on_disk} rows                     "
                        "<- but the row is still here")
                    say("      retrieval enforces the deadline; it does not "
                        "wait for the janitor.")
                    seen_gap = True
                if on_disk == 1:
                    break

        # ---- beat 2: the reaper takes the row, vector included ----
        print()
        say(f"reaper ran: {await rows(engine)} row, "
            f"{await vectors(engine)} vector")
        survivors = await mem.recall(SESSION, vec(0.9))
        say(f"recall -> {sorted(h['text'] for h in survivors)}   "
            "<- pinned memory untouched")

        gone = await engine.db.memories.count_documents(
            {"text": "the fault code is P0301"})
        assert gone == 0, "the expired memory outlived its deadline"
        assert await vectors(engine) == 1, "a vector outlived its document"

        print("\n  the document and its embedding left together, because they "
              "were never\n  two things. one expire_at, one index, one owner "
              "of the deadline.")
        print("\n  delete calls issued by this program: 0")

    finally:
        try:
            await client.admin.command(
                {"setParameter": 1, "ttlMonitorSleepSecs": was})
        except Exception:  # noqa: BLE001 - best effort; it is a local knob
            pass
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
