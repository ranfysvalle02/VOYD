"""Measure the three claims the README makes without a number attached.

    docker compose up -d --wait mongo
    uv run python bench/measure.py            # ~4 minutes
    uv run python bench/measure.py --quick    # ~1 minute, smaller sizes
    uv run python bench/measure.py --sizes 100,1000,10000,25000

Three questions, in descending order of how much the argument rests on them:

1. **How long does an expired document stay on disk?** The whole reason the
   deadline is enforced on read is that MongoDB's TTL monitor runs "about once
   a minute", and every other system will serve a dead row during that window.
   "About" is doing a lot of work in a security argument, so this measures the
   distribution.

2. **Where is the cosine cliff?** ``COSINE_CAP = 10_000`` is asserted, not
   derived. This walks collection sizes and reports the latency curve, so the
   constant is either defensible or wrong on the record.

3. **What do the three tiers actually cost?** ``hybrid`` / ``vector`` /
   ``cosine`` are described as better-to-worse with no figures.

This is a laptop benchmark against single-node Atlas Local: the numbers are
for *relative* comparison and order of magnitude, not a capacity plan. Every
table it prints says so. Absolute latency on a real replica set with real
network will differ; the shape -- cosine growing linearly while the indexed
tiers stay flat -- is the part that transfers.

Nothing here is a test. It makes no assertions and is not run by CI: a
benchmark that fails the build on a busy runner teaches people to ignore CI.

**Run it alone.** Not for accuracy -- though a busy machine does skew the
numbers -- but because the test suite's session fixture drops databases by
prefix, and a benchmark and a test run will delete each other's data mid-flight.
The same warning the examples carry, for the same reason.
"""

from __future__ import annotations

import argparse
import asyncio
import random
import statistics
import time
import uuid
from datetime import timedelta

from pymongo import AsyncMongoClient

from voyd.engine import Engine
from voyd.engine.time import now

URI = "mongodb://localhost:27018/?directConnection=true"
DIMS = 1024          # the production default; cosine cost is linear in this
REPEATS = 25         # queries per measurement
TTL_SAMPLES = 8


def vec(seed: int) -> list[float]:
    rng = random.Random(seed)
    return [rng.random() for _ in range(DIMS)]


def pct(values: list[float], p: float) -> float:
    """Nearest-rank percentile. No interpolation, no numpy."""
    if not values:
        return float("nan")
    ordered = sorted(values)
    idx = min(len(ordered) - 1, int(round(p / 100 * (len(ordered) - 1))))
    return ordered[idx]


async def timed(engine, fn, repeats: int = REPEATS) -> dict:
    """Run it repeats times, discard the first as warm-up, report ms.

    Also reports whether the queries were *actually* served by the tier the
    caller thinks it is measuring. An unready or unhappy index degrades to
    cosine and still returns rows, so a benchmark that trusts its own label
    will cheerfully print three identical numbers for three tiers -- which is
    what the first run of this file did. ``degraded`` is the guard against
    publishing that.
    """
    before = engine.health()["search"]["degraded_searches"]
    await fn()
    samples = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        await fn()
        samples.append((time.perf_counter() - t0) * 1000)
    after = engine.health()["search"]["degraded_searches"]
    return {
        "p50": pct(samples, 50),
        "p99": pct(samples, 99),
        "min": min(samples),
        "max": max(samples),
        "degraded": after - before,
    }


# ---- 1. how long does an expired document stay on disk? ----------------

async def measure_ttl_lag(engine, samples: int) -> list[float]:
    """Insert a row already past its deadline; wait for the reaper to take it.

    The row is inserted *expired*, so the clock starts at insert and the
    measured value is the worst case a caller can experience: the full
    distance to the next sweep. This is the window during which a system that
    only trusts its TTL index is serving a deleted document.
    """
    db = engine.db
    lags: list[float] = []
    engine.model("ttlbench").expiring()
    await engine.ensure(search_wait_s=0)

    for i in range(samples):
        marker = f"ttl-{uuid.uuid4().hex}"
        t0 = time.perf_counter()
        await db.ttlbench.insert_one(
            {"marker": marker, "expire_at": now() - timedelta(seconds=1)})

        # Poll for physical absence. 0.25s granularity is well under the
        # ~60s sweep this is measuring.
        while await db.ttlbench.count_documents({"marker": marker}) == 1:
            if time.perf_counter() - t0 > 180:
                print("    (gave up after 180s -- is the TTL monitor running?)")
                break
            await asyncio.sleep(0.25)
        lag = time.perf_counter() - t0
        lags.append(lag)
        print(f"    sample {i + 1}/{samples}: {lag:6.1f}s on disk after expiry")

    return lags


# ---- 2 & 3. tier latency and the cosine cliff --------------------------

async def seed_to(engine, collection: str, have: int, want: int) -> None:
    """Top the collection up to `want` rows. Two tenants, alternating.

    Incremental on purpose. Building a fresh 1024-dimension index per size --
    and leaving the old, now-dropped collection's spec registered -- meant
    every later ``ensure()`` waited on an index for a collection that no
    longer existed, so nothing was ever queryable and every "indexed"
    measurement was really the fallback. One collection, seeded upward.
    """
    db = engine.db
    batch = []
    for i in range(have, want):
        batch.append({
            "voyd_id": "tenant_a" if i % 2 else "tenant_b",
            "text": f"document {i} fault code P{i % 9000:04d}",
            "vector": vec(i),
        })
        if len(batch) == 500:
            await db[collection].insert_many(batch)
            batch = []
    if batch:
        await db[collection].insert_many(batch)


async def wait_indexed(engine, collection: str, rows: int, timeout: float = 300) -> bool:
    """Wait until mongot serves the query *itself*.

    The obvious version of this -- "poll until search returns hits" -- is
    wrong, and wrongly convincing: the cosine fallback returns hits too, so it
    is satisfied instantly while mongot is still building. It then reports
    fallback latency under an indexed label.

    So readiness is two facts, neither sufficient alone: the indexes report
    queryable, *and* a probe query completes without incrementing
    ``degraded_searches``.
    """
    deadline = time.perf_counter() + timeout
    while time.perf_counter() < deadline:
        if engine.health()["search"]["indexes_ready"]:
            before = engine.health()["search"]["degraded_searches"]
            hits = await engine.search(collection, vec(1), limit=10,
                                       filters={"voyd_id": "tenant_a"})
            after = engine.health()["search"]["degraded_searches"]
            if hits and after == before:
                return True
        await asyncio.sleep(1.0)
    return False


async def measure_tiers(engine, collection: str, rows: int) -> dict:
    """Latency per tier at the collection's current size."""
    from dataclasses import replace

    out: dict[str, dict | None] = {}
    se = engine.search_engine
    original = se.capabilities

    indexed = await wait_indexed(engine, collection, rows)
    if indexed:
        async def hybrid():
            await engine.search(collection, vec(7), text="P0301", limit=5,
                                filters={"voyd_id": "tenant_a"})

        async def vector_only():
            await engine.search(collection, vec(7), limit=5,
                                filters={"voyd_id": "tenant_a"})

        out["hybrid"] = await timed(engine, hybrid) if original.rank_fusion else None
        out["vector"] = await timed(engine, vector_only)
    else:
        print(f"    (mongot never served {rows} rows itself within the "
              f"timeout; indexed tiers skipped rather than mislabelled)")
        out["hybrid"] = out["vector"] = None

    # Force the fallback: capabilities is frozen, so swap it wholesale.
    se.capabilities = replace(original, search=False, rank_fusion=False)
    try:
        async def cosine_tier():
            await engine.search(collection, vec(7), limit=5,
                                filters={"voyd_id": "tenant_a"})

        # Cosine is linear and unforgiving; fewer repeats at large sizes.
        out["cosine"] = await timed(engine, cosine_tier,
                                    repeats=5 if rows > 5000 else REPEATS)
    finally:
        se.capabilities = original

    return out


# ---- reporting ---------------------------------------------------------

def row(label: str, m: dict | None) -> str:
    if m is None:
        return f"| {label} | – | – | not measured |"
    # A measurement that degraded is a cosine measurement. Say so in the table
    # rather than letting the label imply an index served it.
    note = ""
    if label != "cosine" and m.get("degraded"):
        note = f" (degraded {m['degraded']}x -- actually cosine)"
    return (f"| {label}{note} | {m['p50']:.1f} | {m['p99']:.1f} | "
            f"{m['min']:.1f}–{m['max']:.1f} |")


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", default="100,1000,5000,10000",
                    help="comma-separated collection sizes")
    ap.add_argument("--quick", action="store_true",
                    help="small sizes and fewer TTL samples")
    ap.add_argument("--skip-ttl", action="store_true")
    ap.add_argument("--ttl-samples", type=int, default=None,
                    help="how many expiry lags to sample (default 8)")
    args = ap.parse_args()

    sizes = [100, 1000] if args.quick else [int(s) for s in args.sizes.split(",")]
    ttl_samples = args.ttl_samples or (3 if args.quick else TTL_SAMPLES)

    client = AsyncMongoClient(URI)

    # Collect our own leftovers first. An interrupted run leaves a database
    # full of 1024-dimension indexes that mongot goes on maintaining forever,
    # which is the "everything got mysteriously slow" the test suite's own
    # sweep exists to prevent. Done here rather than in conftest because only
    # this process knows that no other benchmark is running.
    stale = [n for n in await client.list_database_names()
             if n.startswith("bench_")]
    for name in stale:
        await client.drop_database(name)
    if stale:
        print(f"swept {len(stale)} leftover bench database(s)")

    db_name = f"bench_{uuid.uuid4().hex[:10]}"
    engine = Engine(client, client[db_name])
    await engine.connect()

    health = engine.health()["search"]
    print(f"\nVOYD benchmark -- single-node Atlas Local, dims={DIMS}")
    print(f"tier available: {health['tier']}   (laptop numbers: relative, "
          f"not a capacity plan)\n")

    try:
        if not args.skip_ttl:
            print("1. How long does an expired document stay on disk?")
            print("   (inserted already-expired, so this is the worst case:")
            print("    the full distance to the next TTL sweep)")
            lags = await measure_ttl_lag(engine, ttl_samples)
            if lags:
                print(f"\n   n={len(lags)}  min={min(lags):.1f}s  "
                      f"p50={pct(lags, 50):.1f}s  p99={pct(lags, 99):.1f}s  "
                      f"max={max(lags):.1f}s")
                print(f"   mean={statistics.mean(lags):.1f}s\n")
                print("   Every second of that is a window in which a system "
                      "trusting only\n   its TTL index serves a deleted "
                      "document. Hence the read-path check.\n")

        print("2 & 3. Tier latency, and where cosine stops being a fallback\n")
        collection = "bench"
        engine.model(collection, tenant="voyd_id").searchable(
            vector_path="vector", dimensions=DIMS, text_paths=("text",))
        report = await engine.ensure(search_wait_s=240)
        print(f"  indexes queryable: {report.get('search_ready')}\n")

        results: dict[int, dict] = {}
        have = 0
        for size in sorted(sizes):
            print(f"  seeding to {size} rows...")
            await seed_to(engine, collection, have, size)
            have = size
            results[size] = await measure_tiers(engine, collection, size)

        print("\n| rows | tier | p50 ms | p99 ms | range ms |")
        print("|---|---|---|---|---|")
        for size, tiers in results.items():
            for name in ("hybrid", "vector", "cosine"):
                if name in tiers:
                    print(f"| {size} " + row(name, tiers[name]))

        print("\n  cosine scaling (the cliff):")
        base = None
        for size, tiers in results.items():
            m = tiers.get("cosine")
            if not m:
                continue
            if base is None:
                base, base_size = m["p50"], size
                print(f"    {size:>6} rows: {m['p50']:8.1f} ms  (baseline)")
            else:
                factor = m["p50"] / base if base else float("nan")
                print(f"    {size:>6} rows: {m['p50']:8.1f} ms  "
                      f"({factor:.1f}x the {base_size}-row cost)")
        print("\n  COSINE_CAP is 10_000. Compare the largest p50 above against "
              "the\n  latency you are willing to serve while degraded.\n")
    finally:
        await client.drop_database(db_name)
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
