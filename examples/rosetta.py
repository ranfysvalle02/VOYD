"""Five everyday mechanisms, one protocol -- and `deleted=true` is rule zero.

    docker compose up -d
    uv run python examples/rosetta.py     # ~5 seconds, no API key, no vendor

`deleted=true` is admission control with one reason, one boolean, enforced by
convention: re-added to every read path, forgettable in any of them, and only
ever able to say "gone / not gone". VOYD's actual object is the *reason*, and a
reason is a first-class thing -- `reason` + `refuses(doc)` + `clause()`, the
same public contract a stranger uses in
`tests/test_the_policy_file_is_the_configuration.py`.

So here are five mechanisms a team would otherwise scatter across their read
paths as five different filter conventions, written instead as five Rules on
one handle:

    soft-delete   `deleted=true`                     -- a custom rule, below
    TTL / expiry  a deadline in the past             -- Deadline(), shipped
    feature flag  visible only to callers who hold it -- a custom rule, below
    RLS           an audience the caller must be in   -- Restricted(), shipped
    token budget  refuse once the prompt is full      -- Budget(), shipped

Two of them are written here, against the public protocol, to show the
extension point is real and not decoration. The other three ship. One
`admitting(...)` handle enforces all of them at once -- structurally, so no
read path can skip any -- and reports each by name.

The payoff is in two parts. Part A shows the four query-expressible reasons
enforced on *both* halves at once, agreeing: the thing a hand-written
`deleted=true` filter never gives you, because a `$vectorSearch` hit does not
pass through it. Part B is the one `deleted=true` can never become: a budget is
not a per-document property at all -- it is a running total -- so it has no
query half by nature. Not a stronger flag; a different kind of predicate.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from datetime import timedelta

from pymongo import AsyncMongoClient

from voyd.engine import Budget, Deadline, Restricted, now
from voyd.engine.admission import Admission, AdmissionSpec

# The examples all read the same variable, so one export points every
# one of them at Atlas instead of the local container.
URI = os.getenv("VOYD_MONGO_URI",
                "mongodb://localhost:27018/?directConnection=true")


# ---- two mechanisms, written as a stranger would, against the protocol ----

class SoftDeleted:
    """`deleted=true`, made a first-class rule -- both halves, from the
    humblest flag. This is the whole of what a soft-delete column is, and it is
    the smallest possible member of the same protocol as everything below it.
    """

    reason = "deleted"
    field = "deleted"

    def refuses(self, doc: dict, *, when=None) -> bool:
        return bool(doc.get(self.field))

    def clause(self) -> dict:
        return {self.field: {"$ne": True}}


class BehindFlag:
    """Visible only to a caller who holds the feature flag the document names.

    Caller-aware, and about nothing at all to do with erasure -- a fact that is
    not deleted, not expired, and perfectly valid, that this reader still may
    not see yet. A soft-delete column cannot express "for whom".
    """

    reason = "behind_flag"
    needs_caller = True
    field = "feature"
    claim = "flags"

    def refuses(self, doc: dict, *, when=None, caller: dict | None = None) -> bool:
        needed = doc.get(self.field)
        if not needed:
            return False                       # names no flag: visible to all
        return needed not in set((caller or {}).get(self.claim) or [])

    def clause(self) -> dict | None:
        return None                            # not expressible without a caller

    def clause_for(self, caller: dict | None) -> dict:
        enabled = sorted((caller or {}).get(self.claim) or [])
        return {"$or": [{self.field: {"$exists": False}},
                        {self.field: None},
                        {self.field: {"$in": enabled}}]}


def _names(docs) -> set[str]:
    return {d["name"] for d in docs}


async def part_a(db) -> None:
    """The four query-expressible reasons, on one handle, agreeing on both
    halves."""
    # One handle, four reasons -- two shipped, two a stranger wrote.
    docs = Admission(db, AdmissionSpec("catalog", rules=(
        SoftDeleted(), Deadline(), BehindFlag(), Restricted())))

    caller = {"flags": ["beta"], "groups": ["support"]}
    reader = docs.for_caller(caller)

    # Five documents. One is clean; each of the others trips exactly one reason.
    await db.catalog.insert_many([
        {"name": "live", "audience": ["support"]},
        {"name": "soft_deleted", "audience": ["support"], "deleted": True},
        {"name": "expired", "audience": ["support"],
         "expire_at": now() - timedelta(hours=1)},
        {"name": "behind_gamma", "audience": ["support"], "feature": "gamma"},
        {"name": "wrong_audience", "audience": ["legal"]},
    ])

    print("\n  Part A -- four reasons, one handle, both halves")
    print("    caller holds flags=['beta'], groups=['support']")

    raw = [d async for d in db.catalog.find({})]
    reachable = reader.reachable(raw)
    queried = await reader.find({})

    print(f"    raw collection returns : {sorted(_names(raw))}")
    print(f"    handle.find returns    : {sorted(_names(queried))}   (query half)")
    print(f"    reachable(raw) returns : {sorted(_names(reachable))}   (per-doc half)")

    assert _names(raw) == {"live", "soft_deleted", "expired",
                           "behind_gamma", "wrong_audience"}
    assert _names(queried) == {"live"}, "the query half admits only the clean doc"
    assert _names(reachable) == {"live"}, "the per-document half agrees exactly"

    reasons = reader.receipts()["refused_by_reason"]
    print(f"    each refused by name   : {reasons}")
    for reason in ("deleted", "deadline", "behind_flag", "not_cleared"):
        assert reasons.get(reason) == 1, f"{reason} was not reported once"

    print("    -> one read enforced soft-delete, TTL, a feature flag and RLS")
    print("       together, and the two enforcement points returned the same")
    print("       set. A hand-written `deleted=true` filter is one of these,")
    print("       on one of the halves, that somebody has to remember.")


async def part_b(db) -> None:
    """The reason `deleted=true` can never become: a running total."""
    budgeted = Admission(db, AdmissionSpec(
        "prompts", rules=(Deadline(), Budget(limit=100))))

    await db.prompts.insert_many(
        [{"name": f"chunk-{i}", "tokens": 40} for i in range(4)])

    print("\n  Part B -- the one with no query half, by nature")
    assert Budget(limit=100).clause() is None
    print("    Budget(limit=100).clause() is None -- a budget is not a field on")
    print("    a document, it is a total across the read, so there is nothing to")
    print("    push into a query. It lives entirely on the egress check.")

    # A cumulative rule needs a deterministic order, and the handle refuses
    # the read without one: "the first 100 tokens" is only a fact about an
    # *ordered* page, so an unordered one would charge the budget against
    # whichever documents the server happened to return first.
    page = await budgeted.find({}, sort=[("_id", 1)])
    print("    four chunks at 40 tokens each, budget 100:")
    print(f"      admitted {len(page)}, spent {page.spent}, "
          f"refused {dict(page.refused)}")
    assert len(page) == 2, "two 40-token chunks fit in 100"
    assert page.spent == 80
    assert "over_budget" in page.refused
    print("    -> the page stopped at the token ceiling. No boolean field, no")
    print("       deadline, no caller could express that -- and it is the same")
    print("       Rule protocol, refusing for a fifth kind of reason.")


async def main() -> None:
    print(__doc__.split("\n\n")[0])
    client = AsyncMongoClient(URI)
    name = f"voyd_example_rosetta_{uuid.uuid4().hex[:8]}"
    try:
        await part_a(client[name])
        await part_b(client[name])
        print("\n  Five reasons, one protocol, enforced once. `deleted=true` is")
        print("  rule zero: the smallest, on one half, by convention.\n")
    finally:
        await client.drop_database(name)
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
