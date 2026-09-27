"""Relevance and recency combined in the boundary: bm25, then freshness.

    docker compose up -d mongo
    uv run python examples/operators/fresh_news.py

A newsroom collection with a `deadline()` on a withdrawn story. The client
asks for the three best stories about a query, where "best" is relevant
*and* recent:

    $match {desk: "autos"}                     mongod
    $bm25 {query, sort: false}                 the boundary
    $freshness {field: published_at,           the boundary, from $$NOW
                halfLife: "3d",
                multiply: "score"}
    $match {score > 0}, $sort, $limit 3        mongod, on a temporary one

`$freshness` writes the decay (1.0 now, 0.5 three days ago) and multiplies
the BM25 score by it in place, so the native `$sort` after it orders by
relevance times recency. The week-old story that matches best loses to
yesterday's that matches nearly as well; the story that matches nothing
is filtered out by mongod; the withdrawn one, past its deadline, is not a
candidate at all. To fuse by rank instead of by product, `$rrf` takes the
two fields as they are -- see `examples/operators/README.md`.
"""

from __future__ import annotations

import sys
from datetime import timedelta
from pathlib import Path

from pymongo import MongoClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _boundary import boundary, deployment  # noqa: E402

from voyd.engine.time import now  # noqa: E402

POLICY = '''
from voyd import deadline, guard
from voyd.contrib import rank

rank.install("$bm25", "$freshness")

@guard("news")
class News:
    expire_at = deadline()
'''

QUERY = "brake recall sensor"


def main() -> None:
    t = now()
    stories = [
        (1, "Brake sensor recall widens to three models, brake recall "
            "details", 7),
        (2, "Recall: brake sensor fault on 2024 sedans", 1),
        (3, "Dealers report brake sensor recall backlog", 2),
        (4, "New EV range figures published", 0),
        (5, "Withdrawn: brake recall rumour", 0),
    ]
    with deployment("fresh_news") as (direct, db):
        scratch = f"{db}_tmp"
        direct[db].news.insert_many([
            {"_id": i, "desk": "autos", "headline": h,
             "published_at": t - timedelta(days=age),
             **({"expire_at": t - timedelta(hours=1)} if i == 5 else {})}
            for i, h, age in stories])
        try:
            with boundary(POLICY, "--virtual-db", scratch, "--quiet") as uri:
                client = MongoClient(uri, serverSelectionTimeoutMS=8000)
                top = list(client[db].news.aggregate([
                    {"$match": {"desk": "autos"}},
                    {"$bm25": {"query": QUERY, "field": "headline",
                               "sort": False}},
                    {"$addFields": {"relevance": "$score"}},
                    {"$freshness": {"field": "published_at",
                                    "halfLife": "3d", "multiply": "score"}},
                    {"$match": {"score": {"$gt": 0}}},
                    {"$sort": {"score": -1}},
                    {"$limit": 3},
                ]))
                client.close()
            print(f"\n  Top stories for {QUERY!r}:\n")
            for s in top:
                print(f"  score {s['score']:.3f}  bm25 {s['relevance']:>5.2f}"
                      f"  fresh {s['freshness']:.2f}  {s['headline']}")
            got = [s["_id"] for s in top]
            assert got == [2, 3, 1], got
            assert all(0 < s["freshness"] <= 1 for s in top)
            print("\n  yesterday's recall outranks last week's; the withdrawn "
                  "story was never a candidate\n")
        finally:
            direct.drop_database(scratch)


if __name__ == "__main__":
    main()
