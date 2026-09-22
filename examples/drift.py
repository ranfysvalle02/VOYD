"""How long does a vector index disagree with the collection behind it?

    docker compose up -d mongo
    uv run python examples/drift.py     # ~30 seconds, no API key, no vendor

**This example measures MongoDB, not VOYD.** Nothing here imports the
boundary or starts the proxy. It exists because `README.md` opens with a
claim about what a vector index does during the window after a fact is
forgotten, and half of that claim was inferred rather than measured. This
is the measurement, and it came out differently than expected.

Four numbers, on whatever deployment `VOYD_MONGO_URI` points at:

    time-to-visible     insert a document; how long until search finds it
    time-to-invisible   delete it; how long until search stops
    stale window        change its vector; how long until ranking follows
    expired-but-there   a row past its deadline: is it still ranked, and
                        is it still on disk while that happens

The third one needs care, and the first version of this got it wrong in a
way worth keeping as a comment. Asking "is the document still returned"
after an update measures nothing when the collection is nearly empty: an
approximate-nearest-neighbour search asked for 50 candidates out of one
document returns that document regardless of distance. It looked like a
30-second staleness window and it was a test with no control. So the
collection is padded, and what is measured is the **score** -- which moves
only when the index's copy of the vector actually changes.

What this found is not what prompted it. A proposal argued for selling a
detector for documents the index ranks and the collection does not have.
That bucket is structurally empty -- `$vectorSearch` materialises hits
from the collection, so a deleted row drops out in a round trip -- and the
proposal was deleted. `LIMITS.md` section 6 keeps the numbers.
"""

from __future__ import annotations

import os
import random
import statistics
import time
import uuid
from datetime import timedelta

from pymongo import MongoClient
from pymongo.operations import SearchIndexModel

from voyd.engine.time import now

URI = os.getenv("VOYD_MONGO_URI",
                "mongodb://localhost:27018/?directConnection=true")
DIMS = 8
INDEX = "drift_vector"
FILLER = 200
TRIALS = 8


def vec(seed: int) -> list[float]:
    rng = random.Random(seed)
    return [rng.random() for _ in range(DIMS)]


def summarise(label: str, xs: list[float], unit: str = "ms") -> None:
    scale = 1000 if unit == "ms" else 1
    xs = sorted(xs)
    print(f"    {label:20} n={len(xs)}  min={xs[0]*scale:.0f}{unit}  "
          f"p50={statistics.median(xs)*scale:.0f}{unit}  "
          f"max={xs[-1]*scale:.0f}{unit}")


def main() -> None:
    client: MongoClient = MongoClient(URI, serverSelectionTimeoutMS=8000)
    name = f"voyd_drift_{uuid.uuid4().hex[:8]}"
    db = client[name]
    try:
        db.create_collection("probe")
        try:
            db.probe.create_search_index(SearchIndexModel(
                name=INDEX, type="vectorSearch",
                definition={"fields": [{
                    "type": "vector", "path": "embedding",
                    "numDimensions": DIMS, "similarity": "cosine"}]}))
        except Exception as exc:                               # noqa: BLE001
            print(f"\n  no Atlas Search on this deployment "
                  f"({type(exc).__name__}). This example measures an index "
                  f"against its collection, so it needs one:\n"
                  f"  `docker compose up -d mongo` runs Atlas Local, which "
                  f"has a real mongot.\n")
            return

        # Padding, so the nearest-neighbour search has something to choose
        # between. Without it every query returns every document and the
        # staleness measurement below has no control.
        db.probe.insert_many([{"embedding": vec(1000 + i), "text": "filler"}
                              for i in range(FILLER)])
        db.probe.create_index("expire_at", expireAfterSeconds=0)

        print("\n  waiting for the index to become queryable", end="", flush=True)
        until = time.monotonic() + 300
        while time.monotonic() < until:
            state = list(db.probe.list_search_indexes(INDEX))
            if state and state[0].get("queryable"):
                break
            print(".", end="", flush=True)
            time.sleep(1)
        print(" ok\n")

        A = vec(1)
        B = [1.0 - x for x in A]          # the opposite corner from A

        def ranked(oid) -> bool:
            return any(h["_id"] == oid for h in db.probe.aggregate([
                {"$vectorSearch": {"index": INDEX, "path": "embedding",
                                   "queryVector": A, "numCandidates": 400,
                                   "limit": 250}}]))

        def score(oid) -> float | None:
            hits = db.probe.aggregate([
                {"$vectorSearch": {"index": INDEX, "path": "embedding",
                                   "queryVector": A, "numCandidates": 400,
                                   "limit": 250}},
                {"$addFields": {"s": {"$meta": "vectorSearchScore"}}}])
            return next((h["s"] for h in hits if h["_id"] == oid), None)

        def wait(predicate, budget: float = 60.0) -> float:
            start = time.perf_counter()
            while not predicate():
                if time.perf_counter() - start > budget:
                    break
                time.sleep(0.005)
            return time.perf_counter() - start

        visible, invisible, stale = [], [], []
        for i in range(TRIALS):
            oid = db.probe.insert_one({"embedding": A, "text": "v1"}).inserted_id
            visible.append(wait(lambda: ranked(oid)))

            was = score(oid)
            db.probe.update_one({"_id": oid}, {"$set": {"embedding": B}})
            stale.append(wait(
                lambda: (lambda s: s is None or abs(s - was) > 0.02)(score(oid))))

            db.probe.delete_one({"_id": oid})
            invisible.append(wait(lambda: not ranked(oid)))
            print(f"    trial {i + 1}/{TRIALS}", end="\r", flush=True)

        print("  1. the index against its collection            \n")
        summarise("time-to-visible", visible)
        summarise("stale window", stale)
        summarise("time-to-invisible", invisible)

        print("\n     The middle number is real: for about one poll interval "
              "the index\n     ranks by a vector the document no longer has. "
              "That is a freshness\n     problem and it belongs to everybody "
              "doing retrieval.")
        print("\n     The last number is the surprise. A deleted document "
              "stops being\n     returned in roughly one round trip, not one "
              "poll interval -- because\n     `$vectorSearch` hands back "
              "documents from the *collection*. There is\n     nothing to "
              "return for a row that is not there, so a vector index\n"
              "     cannot serve a document that has been deleted.")

        print("\n  2. and the window that actually matters\n")
        oid = db.probe.insert_one(
            {"embedding": A, "text": "expired on insert",
             "expire_at": now() - timedelta(days=1)}).inserted_id
        wait(lambda: ranked(oid))
        print("     a row inserted already past its deadline:")
        print(f"       in the collection : "
              f"{db.probe.count_documents({'_id': oid}) == 1}")
        print(f"       ranked by search  : {ranked(oid)}")
        waited = wait(lambda: not ranked(oid), budget=130.0)
        on_disk = db.probe.count_documents({"_id": oid}) == 1
        print(f"\n       stopped being ranked after {waited:.1f}s")
        print(f"       still in the collection then: {on_disk}")

        print("\n     So the exposure is the *sweeper*, not the index. The "
              "row was really\n     there the whole time and search returned "
              "it correctly -- which is why\n     a faster index would not "
              "close this window and a verdict on the read\n     path does. "
              "That is the whole argument, measured.\n")
    finally:
        client.drop_database(name)
        client.close()


if __name__ == "__main__":
    main()
