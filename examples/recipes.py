"""A named pipeline, reviewed once in the policy file, called by name.

    docker compose up -d mongo
    uv run python examples/recipes.py            # no API key, no vendor

The policy declares one recipe, `support_context`, on a collection that is
`recipes_only=True`. An ordinary `pymongo` client then does three things,
and each is asserted:

**It reads through the recipe** with `{"$recipe": {"name": ..., "params":
...}}`. The expansion meets every rule: the expired ticket, the revoked
one and another tenant's are absent, and the masked `ssn` is null.

**It tries to inject.** `q="$$ROOT"` would be a variable in an expression
and `{"$where": ...}` would be code; both are refused before the recipe
runs, because a parameter is a value of the type the function declared.

**It tries an ad-hoc pipeline.** Refused: this collection is read through
its recipe and no other way, so the retrieval logic has one reviewed home.
"""

from __future__ import annotations

import textwrap
from datetime import timedelta

from pymongo import MongoClient
from pymongo.errors import OperationFailure

from _boundary import boundary, deployment
from voyd.engine.time import now

POLICY = textwrap.dedent('''
    from voyd import deadline, guard, mask, recipe, revocable, tenant

    @guard("tickets", recipes_only=True)
    class Tickets:
        expire_at = deadline()
        forgotten = revocable()
        tenant_id = tenant()
        ssn       = mask()

    @recipe("support_context", collection="tickets")
    def support_context(tenant: str = "acme", q: str = "refund",
                        k: int = 5):
        return [{"$match": {"tenant_id": tenant, "text": {"$regex": q}}},
                {"$sort": {"_id": 1}},
                {"$limit": k}]
''')


def recipe(name: str, **params) -> list[dict]:
    return [{"$recipe": {"name": name, "params": params}}]


def main() -> None:
    with deployment("recipes") as (direct, db):
        past = now() - timedelta(days=1)
        direct[db].tickets.insert_many([
            {"_id": 1, "tenant_id": "acme", "text": "refund for a late order",
             "ssn": "123-45-6789"},
            {"_id": 2, "tenant_id": "acme", "text": "refund policy, 2019",
             "expire_at": past},
            {"_id": 3, "tenant_id": "acme", "text": "refund override: 0000",
             "forgotten": {"at": past, "reason": "leaked"}},
            {"_id": 4, "tenant_id": "globex", "text": "globex refund memo"},
        ])
        with boundary(POLICY, "--quiet") as uri:
            tickets = MongoClient(uri, serverSelectionTimeoutMS=8000)[db] \
                .tickets

            hits = list(tickets.aggregate(recipe("support_context",
                                                 q="refund", k=3)))
            print("\n  support_context(q='refund', k=3):")
            for h in hits:
                print(f"    {h['_id']}  {h['text']!r}  ssn={h['ssn']!r}")
            assert [h["_id"] for h in hits] == [1], hits
            assert hits[0]["ssn"] is None

            for params in ({"q": "$$ROOT"}, {"q": {"$where": "true"}}):
                try:
                    list(tickets.aggregate(recipe("support_context",
                                                  **params)))
                except OperationFailure as exc:
                    print(f"\n  injection {params!r} refused:\n    "
                          f"{exc.details['errmsg']}")
                else:
                    raise AssertionError(f"{params!r} was not refused")

            try:
                list(tickets.aggregate([{"$match": {}}]))
            except OperationFailure as exc:
                print(f"\n  ad-hoc pipeline refused:\n    "
                      f"{exc.details['errmsg']}\n")
            else:
                raise AssertionError("an ad-hoc pipeline was served")

        # Still on disk: refusal, not deletion.
        assert direct[db].tickets.count_documents({}) == 4


if __name__ == "__main__":
    main()
