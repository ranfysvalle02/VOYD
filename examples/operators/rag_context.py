"""Retrieval context built in the boundary: bm25, dedupe, mmr, pack, cite.

    docker compose up -d mongo
    uv run python examples/operators/rag_context.py    # no API key, offline

The policy file is three lines of `voyd.contrib` plus a `@guard`. An
ordinary `pymongo` client then asks for a prompt's worth of context in one
`aggregate`:

    $match {tenant_id: acme}              mongod, judged on the way out
    $addFields {chunks: {$chunk}}         the boundary, per document
    $unwind $chunks                       mongod, on a temporary collection
    $bm25    {query, publish: corpus}     the boundary, over admitted chunks
    $dedupe  {threshold: 0.8}             the boundary
    $mmr     {k: 4, score: score}         the boundary
    $contextPack {budget: 40}             the boundary, publishes $$context
    $cite    {source: [title]}            the boundary, publishes $$citations

What comes back is ranked, de-duplicated, diverse, inside a token budget
and numbered -- and computed only from what this caller may read. The
collection also holds an expired manual, a revoked one and another
tenant's; none of their words reaches the corpus statistics, the ranking
or the prompt.

The client then builds its prompt from the served chunks and their
`[n]` markers. It stops there: VOYD never calls a model, and this example
does not either. Sending the prompt is the client's business, with its own
key, below the boundary.
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
from voyd import deadline, guard, revocable, tenant
from voyd import contrib

contrib.install()

@guard("manuals")
class Manuals:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()
'''

MANUALS = [
    ("Brake system", "Fault B1342 means the brake pressure sensor is out of "
     "range. Check the sensor connector first. Replace the sensor if the "
     "fault returns. Fault B1342 means the brake pressure sensor is out of "
     "range."),
    ("ECU", "A stuck ECU is reset by holding the start button for ten "
     "seconds. Reset it twice if the dash stays dark."),
    ("Brake pads", "Brake pads wear faster in city driving. Replace them "
     "when the sensor warns at three millimetres."),
]
EXPIRED = "Old procedure: ignore fault B1342 and bleed the brake line."
REVOKED = "Leaked: the brake sensor override code is 0000."
GLOBEX = "Globex brake sensor bulletin, confidential."

QUESTION = "What does brake fault B1342 mean and what do I check?"

PIPELINE = [
    {"$match": {"tenant_id": "acme"}},
    {"$addFields": {"chunks": {"$chunk": {"input": "$text",
                                          "by": "sentences", "size": 1}}}},
    {"$unwind": "$chunks"},
    {"$bm25": {"query": QUESTION, "field": "chunks", "publish": "corpus"}},
    {"$dedupe": {"field": "chunks", "threshold": 0.8}},
    {"$mmr": {"k": 4, "lambda": 0.7, "score": "score", "field": "chunks"}},
    {"$contextPack": {"budget": 40, "field": "chunks", "minTokens": 4}},
    {"$cite": {"source": ["title"]}},
]


def prompt(question: str, served: list[dict]) -> str:
    """The client's side: a prompt from what the boundary served. No call."""
    lines = [f"{d['citation']} {d['chunks']}" for d in served]
    sources = {d["citation"]: d["source"] for d in served}
    return ("Answer from the numbered context only and cite it.\n\n"
            "Context:\n" + "\n".join(lines) + "\n\nSources:\n"
            + "\n".join(f"{k} {v}" for k, v in sorted(sources.items()))
            + f"\n\nQuestion: {question}")


def main() -> None:
    with deployment("rag_context") as (direct, db):
        scratch = f"{db}_tmp"
        past = now() - timedelta(days=1)
        direct[db].manuals.insert_many(
            [{"_id": i, "tenant_id": "acme", "title": t, "text": x}
             for i, (t, x) in enumerate(MANUALS, 1)]
            + [{"_id": 10, "tenant_id": "acme", "title": "Old",
                "text": EXPIRED, "expire_at": past},
               {"_id": 11, "tenant_id": "acme", "title": "Leak",
                "text": REVOKED, "forgotten": {"at": past, "reason": "leak"}},
               {"_id": 12, "tenant_id": "globex", "title": "Globex",
                "text": GLOBEX}])
        try:
            with boundary(POLICY, "--virtual-db", scratch, "--quiet") as uri:
                client = MongoClient(uri, serverSelectionTimeoutMS=8000)
                served = list(client[db].manuals.aggregate(PIPELINE))
                client.close()

            print("\n  Served context, in rank order:\n")
            for d in served:
                cut = " (trimmed)" if d["truncated"] else ""
                print(f"  {d['citation']} {d['score']:>6.3f}  "
                      f"{d['chunks']}{cut}")
            assert served, "nothing was served"
            assert {d["_id"] for d in served} <= {1, 2, 3}, served
            body = " ".join(d["chunks"] for d in served)
            for refused in ("Old procedure", "override code", "Globex"):
                assert refused not in body, refused
            assert body.count("Fault B1342 means") <= 1, "a duplicate survived"
            tokens = sum(-(-len(d["chunks"]) // 4) for d in served)
            assert tokens <= 40, tokens
            assert served[0]["citation"] == "[1]"
            print(f"\n  {len(served)} chunks, about {tokens} tokens, from "
                  f"admitted manuals only; the repeated sentence was "
                  f"dropped")
            left = [n for n in direct[scratch].list_collection_names()
                    if not n.startswith("system.")]
            assert left == [], left

            print("\n  The prompt the client would send to its own model:\n")
            for line in prompt(QUESTION, served).splitlines():
                print(f"    {line}")
            print()
        finally:
            direct.drop_database(scratch)


if __name__ == "__main__":
    main()
