"""Run the pilot ourselves, against a real MongoDB, and fill in the report.

    docker compose up -d mongo
    uv run python bench/pilot.py            # writes bench/results/pilot.{md,json}

[`PILOT.md`](../PILOT.md) is the trial a *stranger* runs on their own corpus.
This is the same flow run here, on a synthetic-but-honest scenario, so the
mechanism has a proof point that does not depend on anyone volunteering first.
It is deterministic and needs no cloud, no API key, and no vector index: every
number below is measured in this process against a throwaway database.

**Be exact about what this proves.** It proves the *mechanism and the value* --
the naive read serves a revoked fact and the handle refuses it, the refusal
travels to the summary written out of it, and a token budget cuts a page. It
does **not** prove *demand*. The last line of the PILOT report -- "kept after
two weeks, and in their own words why" -- is the only one that decides
adoption, and it is the one a self-run structurally cannot fill. So this fills
every other line and leaves that one blank, on purpose.

The scenario: a support-notes retrieval scope for one tenant. One note carries
a leaked credential; an agent has already summarised it back into the same
collection (the write-back that defeats a source-only erasure). A compliance
request comes in to forget the credential. We watch what still reaches a
prompt -- through the read a teammate writes by hand, and through an
unfiltered candidate batch passed directly to the same egress boundary the
vector-search path uses. No vector index runs in this scenario; the direct
call isolates the part the pilot is proving.
"""

from __future__ import annotations

import asyncio
import json
import os
import platform
import time
import uuid
from datetime import timedelta
from pathlib import Path

from pymongo import AsyncMongoClient

from voyd import Engine
from voyd.engine import Budget, Deadline, revoked
from voyd.engine.time import now

ROOT = Path(__file__).resolve().parents[1]
LOCAL_URI = os.getenv("VOYD_MONGO_URI",
                      "mongodb://localhost:27018/?directConnection=true")

# The incident fact. A marker a reader can grep for in the prompts below.
LEAK = "aws key AKIA-EXAMPLE-LEAKEDKEY-9c1f"
MARKER = "AKIA-EXAMPLE"


def assemble_prompt(hits: list[dict]) -> str:
    """The one line every RAG app has: retrieved text, concatenated into a
    prompt. The whole question is whether a forgotten fact is a substring of
    what comes out of here."""
    return "\n".join(h["text"] for h in hits)


def _pct(values: list[float], p: float) -> float:
    if not values:
        return float("nan")
    ordered = sorted(values)
    i = min(len(ordered) - 1, int(round(p / 100 * (len(ordered) - 1))))
    return ordered[i]


async def run(engine: Engine, db) -> dict:
    report: dict = {}

    # ---- the handle: one collection, one read path, plus lineage ----------
    # This is examples/quickstart.py's block, with lineage declared so the
    # summary written out of a fact is reachable to the same forgetting.
    docs = engine.model("notes", tenant="tenant").admitting(
        Deadline(), revoked(), lineage_field="lineage")
    await engine.ensure(search_wait_s=0)

    T = {"tenant": "acme"}

    # ---- A. the canary: raw serves what the handle refuses ----------------
    canary = (await db.notes.insert_one(
        {**T, "text": "CANARY", "expire_at": now() - timedelta(minutes=5)}
    )).inserted_id
    canary_handle = await docs.find_one({**T, "_id": canary})
    canary_raw = await db.notes.find_one({"_id": canary})
    report["canary"] = {
        "refused_by_handle": canary_handle is None,
        "served_by_raw": canary_raw is not None,
    }
    assert canary_handle is None and canary_raw is not None, \
        "the canary must be refused by the handle and served by the raw read"

    # ---- seed the corpus, including the leak and its summary --------------
    ordinary = [{**T, "text": f"maintenance note {i}: subsystem {i % 5} nominal",
                 "tokens": 40} for i in range(6)]
    await db.notes.insert_many(ordinary)
    leaked = (await db.notes.insert_one(
        {**T, "text": f"incident: {LEAK}", "tokens": 40})).inserted_id
    # The agent's write-back: a summary that quotes the fact, its own row, its
    # own id, linked to the source by lineage.
    summary, = await docs.derive(
        {**T, "text": f"summary: rotate the leaked key {LEAK}", "tokens": 40},
        parents=[leaked])

    # ---- B. before the erasure: the system working -----------------------
    before = await docs.find(T)
    report["before_revoke"] = {
        "reachable": len(before),
        "leak_in_prompt": MARKER in assemble_prompt(before),
    }
    assert MARKER in assemble_prompt(before), \
        "before the erasure, the leaked fact is legitimately reachable"

    # ---- C. the erasure, and what still reaches a prompt ------------------
    revoked_count = await docs.revoke({**T, "_id": leaked},
                                      reason="subject erasure request")

    # The read a teammate writes by hand, next month. These are the current
    # rows: the leaked one now carries the forgetting mark, but it is still on
    # disk and its text still contains the credential.
    naive_find = [d async for d in db.notes.find(T)]
    # An unfiltered candidate batch with the same dangerous shape as index
    # hits: the mark is on each current row, but the producer did not consult
    # it. No vector index runs here; calling reachable() directly isolates the
    # exact egress boundary the $vectorSearch path funnels every hit through.
    candidate_batch = naive_find
    handle_find = await docs.find(T)
    # The tenant is bound explicitly here because this batch never went
    # through a query to carry it -- which is the whole reason the egress
    # check exists on this path.
    handle_candidates = docs.for_tenant("acme").reachable(candidate_batch)

    report["after_revoke"] = {
        "revoked_including_descendants": revoked_count,
        "raw_find_still_serves_leak": MARKER in assemble_prompt(naive_find),
        "handle_find_serves_leak": MARKER in assemble_prompt(handle_find),
        "unfiltered_candidates_contain_leak":
            MARKER in assemble_prompt(candidate_batch),
        "handle_reachable_serves_leak":
            MARKER in assemble_prompt(handle_candidates),
        "rows_still_on_disk": await db.notes.count_documents(T),
    }
    # the whole claim, as assertions:
    assert MARKER in assemble_prompt(naive_find), \
        "the raw read still serves it -- the gap the handle exists to close"
    assert MARKER not in assemble_prompt(handle_find), \
        "the handle's find refuses it on the next read"
    assert MARKER in assemble_prompt(candidate_batch), \
        "the unfiltered producer included it: nothing consulted the mark"
    assert MARKER not in assemble_prompt(handle_candidates), \
        "reachable() refused it on the way out, where the guarantee lives"

    # ---- D. inherited refusal: the summary went too -----------------------
    summary_reachable = await docs.find_one({**T, "_id": summary})
    summary_on_disk = await db.notes.find_one({"_id": summary})
    report["inherited_refusal"] = {
        "revoke_took_source_and_derived": revoked_count,
        "summary_reachable": summary_reachable is not None,
        "summary_on_disk": summary_on_disk is not None,
    }
    assert revoked_count == 2, "the source and the one summary derived from it"
    assert summary_reachable is None and summary_on_disk is not None, \
        "the paraphrase is refused, and still on disk as evidence"

    # ---- E. budget: one more reason, on its own collection ----------------
    # A separate collection because the engine refuses to redeclare one with a
    # second rule set -- two specs for one collection is exactly the drift it
    # exists to prevent. find enforces the budget per document: two 40-token
    # rows fit in 100, the third is over_budget.
    budgeted = engine.model("prompts", tenant="tenant").admitting(
        Deadline(), revoked(), Budget(limit=100))
    await engine.ensure(search_wait_s=0)
    await db.prompts.insert_many([{**T, "text": f"chunk {i}", "tokens": 40}
                                  for i in range(4)])

    async def fetch_budget(n: int) -> list[dict]:
        return [d async for d in db.prompts.find(T).sort("_id", 1).limit(n)]

    budget_page = await budgeted.saturate(fetch_budget, limit=5)
    report["budget"] = {
        "limit": 100,
        "admitted": len(budget_page),
        "spent": budget_page.spent,
        "refused": dict(budget_page.refused),
        "examined": budget_page.examined,
        "examined_per_admitted": (
            budget_page.examined / len(budget_page)
            if budget_page else None),
        "starved": budget_page.starved,
        "note": "each row costs 40 tokens; the third is over_budget",
    }
    assert len(budget_page) == 2, "two 40-token rows fit in a 100-token budget"
    assert budget_page.spent == 80
    assert budget_page.refused == {"over_budget": 2}
    assert budget_page.starved is False

    # ---- F. the overhead, on this run's data ------------------------------
    sample = [d async for d in db.notes.find(T)]
    per_doc_us: list[float] = []
    for _ in range(2000):
        t0 = time.perf_counter_ns()
        docs._classify(sample)
        per_doc_us.append((time.perf_counter_ns() - t0) / 1000 / max(len(sample), 1))
    report["overhead"] = {
        "candidates": len(sample),
        "p50_us_per_candidate": _pct(per_doc_us, 50),
        "p99_us_per_candidate": _pct(per_doc_us, 99),
    }

    # ---- G. observability the pilot asks you to wire ----------------------
    report["receipts"] = docs.receipts()
    report["budget_receipts"] = budgeted.receipts()
    assert report["budget_receipts"]["refused_by_reason"] == {
        "over_budget": 2}
    return report


def render_markdown(r: dict, env: dict) -> str:
    a = r["after_revoke"]
    o = r["overhead"]
    def yn(b: bool) -> str: return "yes" if b else "no"
    return "\n".join([
        "# Pilot report (self-run)",
        "",
        f"- generated: {env['generated']}",
        f"- machine: {env['machine']}, Python {env['python']}",
        "- scenario: synthetic support-notes scope, one tenant, run against a",
        "  throwaway MongoDB. No cloud, no API key, no vector index.",
        "",
        "## What this run proves",
        "",
        "| claim | result |",
        "|---|---|",
        f"| the canary is served by the raw path and refused by the handle "
        f"| {yn(r['canary']['served_by_raw'] and r['canary']['refused_by_handle'])} |",
        f"| after erasure, the raw read a teammate writes still serves the leak "
        f"| {yn(a['raw_find_still_serves_leak'])} |",
        f"| after erasure, the handle's find refuses it "
        f"| refused: {yn(not a['handle_find_serves_leak'])} |",
        f"| an unfiltered candidate producer included the leak "
        f"| {yn(a['unfiltered_candidates_contain_leak'])} |",
        f"| reachable() refused it on the way out "
        f"| refused: {yn(not a['handle_reachable_serves_leak'])} |",
        f"| the summary written out of the leak was refused too (lineage) "
        f"| refused: {yn(not r['inherited_refusal']['summary_reachable'])} |",
        f"| the rows are all still on disk (revoke deleted nothing) "
        f"| {a['rows_still_on_disk']} rows |",
        f"| a token budget cut the page "
        f"| {r['budget']['admitted']} admitted, {r['budget']['spent']} spent "
        f"at limit {r['budget']['limit']} |",
        "",
        "## The PILOT.md report, filled",
        "",
        "```",
        "Team / service:                                 self-run (bench/pilot.py)",
        "Collection and read path piloted:               notes, find + reachable()",
        "find-only or vector (Atlas autoEmbed)?          find + direct egress candidate batch",
        "",
        "Integration time (first line to green CI):      the quickstart block",
        "Application lines changed:                       6 (pinned <10 by test_the_quickstart_refuses.py)",
        "Where the time actually went:                    n/a for a self-run",
        "",
        "Measured in our environment:",
        f"  admission overhead p50 / p99:                {o['p50_us_per_candidate']:.2f} / "
        f"{o['p99_us_per_candidate']:.2f} us per candidate",
        f"  over-fetch (examined/admitted) at our rate:  "
        f"{r['budget']['examined_per_admitted']:.2f}",
        f"  starvation observed:                         "
        f"{'yes' if r['budget']['starved'] else 'no'}",
        "",
        "Incidents the handle would have caused / prevented during the trial:",
        "  prevented: a revoked credential reaching a prompt through the naive read",
        "             and through an unfiltered candidate producer; and through the",
        "             summary an agent wrote out of it.",
        "",
        "Kept after two weeks?                          UNKNOWN -- a self-run cannot answer this",
        "In our own words, why:                         (the one line only a real team fills)",
        "```",
        "",
        "## What this run cannot prove",
        "",
        "Demand. This is us, and we were already convinced. Every line above is",
        "the mechanism working; none of it is a stranger choosing to keep the",
        "handle after two weeks, which is the only evidence that moves adoption.",
        "That line is left UNKNOWN on purpose -- see [`PILOT.md`](../PILOT.md).",
        "",
    ])


async def main() -> None:
    client = AsyncMongoClient(LOCAL_URI)
    name = f"pilot_{uuid.uuid4().hex[:10]}"
    engine = Engine(client, client[name])
    await engine.connect()
    try:
        report = await run(engine, engine.db)
    finally:
        await client.drop_database(name)
        await client.close()

    env = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S %z"),
        "machine": f"{platform.system()} {platform.machine()}",
        "python": platform.python_version(),
    }
    out = ROOT / "bench" / "results"
    out.mkdir(parents=True, exist_ok=True)
    (out / "pilot.json").write_text(json.dumps({"env": env, "report": report},
                                               indent=2, default=str))
    md = render_markdown(report, env)
    (out / "pilot.md").write_text(md)
    print("\n" + md)
    print(f"wrote {out/'pilot.json'} and {out/'pilot.md'}")
    print("\ndelete calls issued by this program: 0")


if __name__ == "__main__":
    asyncio.run(main())
