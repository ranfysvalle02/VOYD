"""A data breach that arrives as an answer.

    docker compose up -d
    uv run python examples/tenancy.py    # ~5 seconds, no API key, no vendor

Cross-tenant leakage in retrieval is not an exotic failure. It is the ordinary
one, and the reason is specific: `find({"tenant_id": t})` is easy to remember,
and **a `$vectorSearch` hit never passes through that query at all.** One read
path prunes correctly and another does not, which is the exact shape
[`AHA.md`](../docs/AHA.md) step 4 calls a silent hole. Nothing errors. A
well-scored, well-formed row from somebody else's company is ranked into a
prompt, and the answer is returned to a customer who was never entitled to it.

This shows the four things that matter, in order, and the fourth is the one
nobody expects.

1. **The raw read leaks**, and that is the baseline to beat.
2. **The tenant becomes required.** `model("notes", tenant="tenant_id")` and
   an unscoped `find({})` *raises* rather than returning everything. You no
   longer have to remember the filter; you have to remember nothing.
3. **A tenant id that is a query operator is refused.** This is the real
   breach, already fixed here and worth seeing:
   `{"tenant_id": {"$ne": "globex"}}` passes a presence check and then matches
   every tenant. `$vectorSearch`'s filter accepts `$ne`, so a presence check
   plus a vector index is a leak with a green test suite.
4. **And the tenant holds on the way out too.** Hand the egress boundary a
   batch you assembled yourself -- which is what a search hit *is* -- and it
   is filtered per document against the tenant the read is bound to. An
   unbound read *raises* rather than quietly returning every tenant, the same
   way `find({})` does, because those are the same mistake reached by
   different roads.

   This is the fix in the commit that added this example. The scope used to
   be a query-half rule: enforced in the collection query and in the index
   filter, absent on the way out. By this package's own step 4 that is a
   silent hole, and it was sitting on the constraint a reader is least likely
   to check.

No vector index is built here: `reachable()` is the same egress boundary the
`$vectorSearch` path calls, so the direct call isolates the part being shown
without a 100-second index build. That is the same choice `bench/pilot.py`
makes, for the same reason.
"""

from __future__ import annotations

import asyncio
import os
import uuid

from pymongo import AsyncMongoClient

from voyd import Engine
from voyd.engine import ScopeInvalid, ScopeRequired

# The examples all read the same variable, so one export points every
# one of them at Atlas instead of the local container.
URI = os.getenv("VOYD_MONGO_URI",
                "mongodb://localhost:27018/?directConnection=true")

CORPUS = [
    {"tenant_id": "acme",   "text": "acme salary bands, 2026"},
    {"tenant_id": "acme",   "text": "acme q3 roadmap"},
    {"tenant_id": "globex", "text": "globex merger memo -- confidential"},
]


async def main() -> None:
    client = AsyncMongoClient(URI)
    name = f"voyd_example_tenancy_{uuid.uuid4().hex[:8]}"
    engine = Engine(client, client[name])
    await engine.connect()
    try:
        notes = engine.model("notes", tenant="tenant_id").forgettable()
        await engine.ensure(search_wait_s=0)
        await engine.db.notes.insert_many([dict(d) for d in CORPUS])

        print("\n  Two tenants in one collection. Acme is asking.\n")

        raw = [d async for d in engine.db.notes.find({})]
        print("  1. the raw read a teammate writes next month")
        print(f"       db.notes.find({{}}) -> {len(raw)} documents, "
              f"{len({d['tenant_id'] for d in raw})} tenants")
        print(f"       including: {[d['text'] for d in raw if d['tenant_id'] != 'acme']}")

        print("\n  2. the tenant is not a filter you remember, it is required")
        try:
            await notes.find({})
        except ScopeRequired as exc:
            print(f"       find({{}}) -> ScopeRequired: {str(exc).split(';')[0]}")
        acme = await notes.find({"tenant_id": "acme"})
        print(f"       find({{'tenant_id': 'acme'}}) -> {[d['text'] for d in acme]}")

        print("\n  3. ...and it has to be an id, not an operator")
        for bad in ({"$ne": "globex"}, {"$exists": True}):
            try:
                await notes.find({"tenant_id": bad})
            except ScopeInvalid:
                print(f"       find({{'tenant_id': {bad}}}) -> ScopeInvalid")
        print("       A presence check would pass both. `$vectorSearch`'s filter")
        print("       accepts $ne, so presence + a vector index is a leak with a")
        print("       green test suite.")

        print("\n  4. and the tenant holds on the way OUT, where search hits arrive")
        candidates = [d async for d in engine.db.notes.find({})]
        print(f"       a candidate batch off the index: {len(candidates)} docs, 2 tenants")
        try:
            notes.reachable(candidates)
        except ScopeRequired:
            print("       reachable(batch) -> ScopeRequired")
            print("         An unbound read raises rather than returning every")
            print("         tenant -- the same refusal find({}) makes, because")
            print("         they are the same mistake by different roads.")
        for who in ("acme", "globex"):
            kept = notes.for_tenant(who).reachable(candidates)
            print(f"       for_tenant({who!r}).reachable(batch) -> "
                  f"{[d['text'] for d in kept]}")
        print(f"       refused: {notes.receipts()['refused_by_reason']}")
        print("\n       find() and search() bind this themselves, from the tenant")
        print("       their filters already require. Only a batch you assembled")
        print("       yourself has to name it, because it has no filters to read.")

        print("\n  Now both halves agree, which is the whole rule: a constraint")
        print("  pushed into a query must also exist per document, or one read")
        print("  path prunes and another serves the same row to the wrong"
              " customer.\n")
    finally:
        await client.drop_database(name)
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
