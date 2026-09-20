"""Measure the tax the README asks you to pay: the admission check itself.

    uv run python bench/admission.py                 # CPU + over-fetch, no DB
    uv run python bench/admission.py --atlas         # + end-to-end on Atlas
    uv run python bench/admission.py --out bench/results

[`bench/measure.py`](measure.py) measures the *search* layer -- TTL lag, per-tier
latency, the cosine cliff -- through the unwrapped primitive. It never touches
admission. This measures admission, which is the thing being sold and the thing
a reviewer objects to first: *"so you pay on every read, forever."* The answer
should be a number.

Two of the three scenarios need no database at all, because the cost being
measured is CPU in this process:

1. **Per-hit classification cost.** The egress check (`_classify`) over pages
   of 1/10/100 candidates, at a few rule counts. Reported as microseconds per
   document, p50/p95/p99. This is the "pay on every read" number.

2. **Over-fetch factor.** Enforcing on read means forgotten hits are fetched
   and dropped, so a page of `limit` live rows may cost more than `limit`
   candidates. `saturate()` refills instead of guessing; this drives it over a
   corpus at several refusal rates and reports `examined / admitted` and the
   starvation rate -- reusing `Page.examined` and `Page.starved`, which already
   carry the instrumentation.

3. **End-to-end on Atlas (optional).** The same over-fetch, but through a real
   server-embedded `$vectorSearch` index (Voyage autoEmbed, cluster from
   `.env`). The `examined/admitted` ratio here is real; the wall-clock includes
   cloud round-trips and is labelled as such rather than sold as the overhead.

Laptop numbers are for order-of-magnitude and shape, not a capacity plan --
the same disclaimer `bench/measure.py` carries. Nothing here is a test and CI
does not run it: a benchmark that fails the build on a busy runner teaches
people to ignore CI.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import random
import statistics
import sys
import time
import uuid
from datetime import timedelta
from pathlib import Path

from voyd.engine import Deadline, quarantined, revoked
from voyd.engine.admission import Admission, AdmissionSpec
from voyd.engine.time import now

ROOT = Path(__file__).resolve().parents[1]

# The rule sets a real handle installs. "deadline+revoked" is exactly what
# forgettable() gives you; the third is the next most common addition.
RULE_SETS = {
    "deadline+revoked": lambda: (Deadline(), revoked()),
    "deadline+revoked+quarantined": lambda: (Deadline(), revoked(), quarantined()),
}


def pct(values: list[float], p: float) -> float:
    if not values:
        return float("nan")
    ordered = sorted(values)
    idx = min(len(ordered) - 1, int(round(p / 100 * (len(ordered) - 1))))
    return ordered[idx]


def _handle(rules) -> Admission:
    """A handle with no engine and no DB: all we exercise is the check."""
    return Admission(None, AdmissionSpec("bench", rules=tuple(rules)))


def _doc(i: int, *, refused: bool) -> dict:
    """A candidate. Refused ones are expired; the rest are pinned (no deadline)."""
    if refused:
        return {"_id": i, "expire_at": now() - timedelta(minutes=5)}
    return {"_id": i, "expire_at": None}


def _page(n: int, rate: float, rng: random.Random, *, worst_case: bool) -> list[dict]:
    k = int(round(n * rate))
    flags = [True] * k + [False] * (n - k)
    if worst_case:
        flags.sort(reverse=True)   # every refused row ranked ahead of a live one
    else:
        rng.shuffle(flags)
    return [_doc(i, refused=f) for i, f in enumerate(flags)]


# ---- 1. per-hit classification cost ------------------------------------

def measure_cpu(page_sizes, repeats: int, rate: float) -> dict:
    rng = random.Random(1234)
    out: dict = {}
    for label, make in RULE_SETS.items():
        handle = _handle(make())
        by_size: dict = {}
        for n in page_sizes:
            page = _page(n, rate, rng, worst_case=False)
            for _ in range(min(50, repeats)):     # warm-up
                handle._classify(page)
            per_doc_us: list[float] = []
            for _ in range(repeats):
                t0 = time.perf_counter_ns()
                handle._classify(page)
                per_doc_us.append((time.perf_counter_ns() - t0) / 1000 / n)
            by_size[n] = {
                "p50_us": pct(per_doc_us, 50),
                "p95_us": pct(per_doc_us, 95),
                "p99_us": pct(per_doc_us, 99),
            }
        out[label] = by_size
    return {"refusal_rate": rate, "repeats": repeats, "by_rule_set": out}


# ---- 2. over-fetch factor ----------------------------------------------

async def measure_overfetch(rates, *, limit: int, corpus: int,
                            trials: int, rounds: int) -> dict:
    rng = random.Random(99)
    out: dict = {}
    for rate in rates:
        for worst in (False, True):
            ratios: list[float] = []
            starved = 0
            round_counts: list[int] = []
            for _ in range(trials):
                docs = _page(corpus, rate, rng, worst_case=worst)

                asked: list[int] = []

                async def fetch(k: int) -> list[dict]:
                    asked.append(k)
                    return docs[:k]

                handle = _handle((Deadline(), revoked()))
                page = await handle.saturate(fetch, limit=limit, rounds=rounds)
                admitted = len(page) or 1
                ratios.append(page.examined / admitted)
                round_counts.append(len(asked))
                if page.starved:
                    starved += 1
            key = f"{rate:.2f}" + ("/worst" if worst else "/shuffled")
            out[key] = {
                "examined_per_admitted_p50": pct(ratios, 50),
                "examined_per_admitted_p99": pct(ratios, 99),
                "rounds_p50": pct([float(r) for r in round_counts], 50),
                "rounds_max": max(round_counts),
                "starved_rate": starved / trials,
            }
    return {"limit": limit, "corpus": corpus, "trials": trials,
            "rounds_cap": rounds, "by_rate": out}


# ---- 3. end-to-end on Atlas (optional) ---------------------------------

def _dotenv(key: str) -> str | None:
    if key in os.environ:
        return os.environ[key]
    env = ROOT / ".env"
    if not env.exists():
        return None
    for line in env.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            if k.strip() == key:
                return v.strip().strip('"')
    return None


async def measure_atlas(*, rate: float, corpus: int, limit: int) -> dict | None:
    uri = _dotenv("VOYD_ATLAS_URI")
    if not uri:
        print("  atlas: skipped (no VOYD_ATLAS_URI in env or .env)")
        return None

    from pymongo import AsyncMongoClient
    from voyd.engine import Engine

    model = os.environ.get("VOYD_ATLAS_EMBED_MODEL", "voyage-4")
    client = AsyncMongoClient(uri)
    name = f"bench_admission_{uuid.uuid4().hex[:8]}"
    engine = Engine(client, client[name])
    await engine.connect()
    try:
        engine.model("bench", tenant="t").searchable(
            text_paths=("text",), auto_embed=model)
        docs = engine.model("bench", tenant="t").forgettable()
        await engine.ensure(search_wait_s=300)
        if not engine.search_engine.embeds_itself("bench"):
            print(f"  atlas: cluster refused autoEmbed with {model!r}; skipped")
            return None

        rows = [{"t": "t1", "text": f"maintenance note {i}: fault code P{i:04d} "
                 f"on subsystem {i % 7}"} for i in range(corpus)]
        await engine.db.bench.insert_many(rows)

        # Wait for mongot to embed + index enough of the corpus to fill a page.
        for _ in range(100):
            if len(await docs.search([], text="fault code",
                                     filters={"t": "t1"}, limit=limit)) >= limit:
                break
            await asyncio.sleep(3)

        # Revoke a fraction so the page has to refill past refused hits.
        to_revoke = int(round(corpus * rate))
        if to_revoke:
            await docs.revoke({"t": "t1", "text": {"$regex": r"P00[0-4]\d"}},
                              reason="bench", everything=False)

        samples = []
        page = None
        for _ in range(20):
            t0 = time.perf_counter()
            page = await docs.search([], text="fault code",
                                     filters={"t": "t1"}, limit=limit)
            samples.append((time.perf_counter() - t0) * 1000)
        admitted = len(page) or 1
        return {
            "model": model, "corpus": corpus, "limit": limit,
            "requested_refusal_rate": rate,
            "examined_per_admitted": page.examined / admitted,
            "admitted": len(page),
            "starved": page.starved,
            "wall_ms_p50_incl_cloud_rtt": pct(samples, 50),
            "wall_ms_p99_incl_cloud_rtt": pct(samples, 99),
        }
    finally:
        await client.drop_database(name)
        await client.close()


# ---- reporting ---------------------------------------------------------

def render_markdown(result: dict) -> str:
    env = result["env"]
    lines = [
        "# Admission overhead (measured)",
        "",
        f"- generated: {result['generated']}",
        f"- machine: {env['machine']}, Python {env['python']}, "
        f"pymongo {env['pymongo']}",
        "- laptop numbers: relative and order-of-magnitude, not a capacity plan.",
        "",
        "## 1. Per-hit classification cost (CPU, no database)",
        "",
        f"Refusal rate {result['cpu']['refusal_rate']:.0%}, "
        f"{result['cpu']['repeats']} repeats. Microseconds per candidate.",
        "",
        "| rule set | page | p50 us | p95 us | p99 us |",
        "|---|---|---|---|---|",
    ]
    for rules, by_size in result["cpu"]["by_rule_set"].items():
        for n, m in by_size.items():
            lines.append(f"| {rules} | {n} | {m['p50_us']:.2f} | "
                         f"{m['p95_us']:.2f} | {m['p99_us']:.2f} |")
    of = result["overfetch"]
    lines += [
        "",
        "## 2. Over-fetch factor (saturate, no database)",
        "",
        f"limit={of['limit']}, corpus={of['corpus']}, trials={of['trials']}, "
        f"rounds cap={of['rounds_cap']}. `worst` ranks every refused row ahead "
        "of a live one; `shuffled` interleaves them.",
        "",
        "| refusal rate | examined/admitted p50 | p99 | rounds p50 | starved rate |",
        "|---|---|---|---|---|",
    ]
    for key, m in of["by_rate"].items():
        lines.append(
            f"| {key} | {m['examined_per_admitted_p50']:.2f} | "
            f"{m['examined_per_admitted_p99']:.2f} | {m['rounds_p50']:.0f} | "
            f"{m['starved_rate']:.0%} |")
    atlas = result.get("atlas")
    lines += ["", "## 3. End-to-end on Atlas autoEmbed", ""]
    if atlas:
        lines += [
            f"model {atlas['model']}, corpus {atlas['corpus']}, limit "
            f"{atlas['limit']}, requested refusal ~{atlas['requested_refusal_rate']:.0%}.",
            "",
            f"- examined/admitted: **{atlas['examined_per_admitted']:.2f}** "
            f"(admitted {atlas['admitted']}, starved {atlas['starved']})",
            f"- wall-clock p50/p99 **including cloud round-trips**: "
            f"{atlas['wall_ms_p50_incl_cloud_rtt']:.0f} / "
            f"{atlas['wall_ms_p99_incl_cloud_rtt']:.0f} ms -- this is network to a "
            "cloud cluster, not the admission cost; see scenario 1 for that.",
        ]
    else:
        lines.append("Not run (pass `--atlas` with `VOYD_ATLAS_URI` set).")
    lines.append("")
    return "\n".join(lines)


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeats", type=int, default=2000)
    ap.add_argument("--trials", type=int, default=400)
    ap.add_argument("--rate", type=float, default=0.5,
                    help="refusal rate for the CPU scenario")
    ap.add_argument("--atlas", action="store_true",
                    help="also run the end-to-end Atlas autoEmbed scenario")
    ap.add_argument("--out", default="bench/results",
                    help="directory for admission.json and admission.md")
    args = ap.parse_args()

    print("admission overhead -- CPU classification + over-fetch")
    cpu = measure_cpu([1, 10, 100], repeats=args.repeats, rate=args.rate)
    overfetch = await measure_overfetch(
        [0.0, 0.1, 0.5, 0.8, 0.9], limit=10, corpus=500,
        trials=args.trials, rounds=4)

    atlas = None
    if args.atlas:
        print("running the Atlas end-to-end scenario (index build ~minutes)...")
        atlas = await measure_atlas(rate=0.4, corpus=120, limit=10)

    import pymongo
    result = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S %z"),
        "env": {
            "machine": f"{platform.system()} {platform.machine()}",
            "python": platform.python_version(),
            "pymongo": pymongo.__version__,
        },
        "cpu": cpu,
        "overfetch": overfetch,
        "atlas": atlas,
    }

    out_dir = ROOT / args.out
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "admission.json").write_text(json.dumps(result, indent=2))
    md = render_markdown(result)
    (out_dir / "admission.md").write_text(md)
    print("\n" + md)
    print(f"wrote {out_dir/'admission.json'} and {out_dir/'admission.md'}")


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
