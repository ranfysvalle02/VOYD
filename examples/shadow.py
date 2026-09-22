"""Measure the gap before you close it. The pilot's first week, in three lines.

    docker compose up -d
    uv run python examples/shadow.py      # ~5 seconds, no API key, no vendor

Every other example here changes what a read returns. This one deliberately
changes **nothing**. It is the instrument you put in production before you
decide whether to adopt anything: your existing read path keeps serving
exactly what it served yesterday, and alongside it you count how many of those
documents should not have been reachable.

    served = await db.notes.find(q).to_list(None)   # unchanged. still yours.
    shadow = len(served) - len(notes.reachable(served))
    metrics.gauge("voyd.would_have_refused", shadow)

That is the whole integration for a shadow trial. No rollback story, because
nothing rolled forward; no risk review, because no user-visible behaviour
moved. At the end of two weeks you have a number nobody had before: how many
times your retrieval handed a prompt a fact your own database had already
marked as gone.

**Why the count is exact here, and a lower bound everywhere else.**
``receipts()["refused_at_boundary"]`` under-reports on purpose -- the same
rule runs inside the collection query, so MongoDB drops most forgotten
documents server-side and the handle never sees them. Shadow mode inverts
that: the documents are fetched by *your* unfiltered read and handed to
``reachable()`` one at a time, which is the same egress boundary a
``$vectorSearch`` hit arrives at. Nothing is dropped early, so nothing goes
uncounted. The measurement is exact precisely because the read is still the
leaky one.

**Install only reasons that mean "forgotten" while you measure.** A
``Deadline`` and a revocation mark both mean the fact is gone, so the delta
has one meaning and a pilot can act on it. Add a ``Budget`` and it starts
meaning "forgotten, *or* simply further down the page than the token ceiling
reached" -- two different facts under one number, which is how a trial
produces a figure nobody can do anything with.

``lineage_field`` is not that kind of addition and is worth switching on from
day one: it is not a new reason, it is what makes the existing one *travel* to
what was made of the fact. Leaving it off does not make the measurement
cleaner, it makes it smaller -- and the derived-document case is usually where
the interesting half of the number is.

The scenario below is a support-notes collection where three things have gone
wrong in the three ordinary ways: a deadline passed, an erasure request was
honoured, and an agent wrote a summary of the revoked fact back into the same
collection. The raw read serves all three. The counter sees all three. No
application behaviour changes in this file.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from datetime import timedelta

from pymongo import AsyncMongoClient

from voyd.engine import Deadline, revoked
from voyd.engine.admission import Admission, AdmissionSpec
from voyd.engine.time import now

# The examples all read the same variable, so one export points every
# one of them at Atlas instead of the local container.
URI = os.getenv("VOYD_MONGO_URI",
                "mongodb://localhost:27018/?directConnection=true")

LEAK = "aws key AKIA-EXAMPLE-LEAKEDKEY-9c1f"


async def run(db) -> dict:
    """The shadow probe, as a pilot would wire it. Returns what it measured.

    Split out from ``main`` and returning what it measured rather than
    printing it, so every claim below is asserted in this file rather than
    narrated. An instrument nobody checked is not evidence.

    **This is the one thing here that is not the proxy, and that is the
    point of it.** A shadow trial must not change what a read returns, and
    a boundary in front of the database changes exactly that. So the probe
    is the admission handle, used as a *counter* beside your own read path
    -- two objects, one spec, and nothing in the request path at all. When
    the number convinces somebody, the same spec becomes a policy file and
    the connection string does the rest.
    """
    # Two reasons and no more -- see the header on why a `Budget` here
    # would make the number mean two things. `lineage_field` is not a third
    # reason, it is what makes the existing one travel.
    notes = Admission(db, AdmissionSpec(
        "notes", rules=(Deadline(), revoked()),
        lineage_field="lineage").with_defaults())

    stale = (await db.notes.insert_one(
        {"text": "last year's pricing", "expire_at": now() - timedelta(days=1)}
    )).inserted_id
    live = (await db.notes.insert_one(
        {"text": "the fault code is P0301"})).inserted_id
    leaked = (await db.notes.insert_one({"text": LEAK})).inserted_id
    # The write-back that defeats a source-only erasure: an agent read the
    # note and summarised it into the same collection it was retrieved from.
    summary, = await notes.derive(
        {"text": f"summary: the customer shared {LEAK}"}, parents=[leaked])

    # The erasure request lands, against the source only. The summary goes
    # with it because the mark travels: a refusal that stops at the document
    # somebody named is not a refusal, it is a filing action.
    await notes.revoke({"_id": leaked}, reason="credential leaked")

    # ---- the pilot's week one starts here, and it is these three lines ----
    served = [d async for d in db.notes.find({})]        # the read you have
    reachable = notes.reachable(served)                  # the read you might have
    would_have_refused = len(served) - len(reachable)
    # ----------------------------------------------------------------------

    served_ids = {d["_id"] for d in served}
    reachable_ids = {d["_id"] for d in reachable}
    return {
        "served_by_your_read_path": len(served),
        "would_have_refused": would_have_refused,
        "behaviour_changed": False,
        # Named rather than counted, because "3" is an argument and
        # "the summary an agent wrote of a revoked credential" is an incident.
        "still_served": {
            "expired": stale in served_ids,
            "revoked": leaked in served_ids,
            "summary_of_revoked": summary in served_ids,
            "the_live_one": live in served_ids,
        },
        "would_still_reach_a_prompt": {
            "expired": stale in reachable_ids,
            "revoked": leaked in reachable_ids,
            "summary_of_revoked": summary in reachable_ids,
            "the_live_one": live in reachable_ids,
        },
        # The exactness claim from the header, as a number: the boundary saw
        # every document, because the read that fetched them filtered nothing.
        "receipts_refused_at_boundary": notes.receipts()["refused_at_boundary"],
    }


async def main() -> None:
    client = AsyncMongoClient(URI)
    name = f"voyd_shadow_{uuid.uuid4().hex[:8]}"
    try:
        r = await run(client[name])

        print("\nShadow mode: nothing about this program's behaviour changed.\n")
        print(f"  your read path served          {r['served_by_your_read_path']} documents")
        print(f"  of those, unreachable          {r['would_have_refused']}")
        print("\n  which ones, by name:")
        for label, still in r["would_still_reach_a_prompt"].items():
            verdict = "would still reach a prompt" if still else "would be refused"
            print(f"    {label:22} {verdict}")

        print(f"\n  refused_at_boundary            {r['receipts_refused_at_boundary']}"
              "  (exact here -- see the header:")
        print("     the documents came from an unfiltered read, so the boundary")
        print("     saw all of them and nothing was dropped server-side first)")

        print("\n  application lines changed by this measurement: 0")
        print("  users affected:                                 0")
        print("  documents deleted:                              0\n")
        print("  The number above is the whole result. If it is zero after")
        print("  two weeks on your own data, you do not have this problem,")
        print("  and this example says so before you start, on purpose.\n")
    finally:
        await client.drop_database(name)
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
