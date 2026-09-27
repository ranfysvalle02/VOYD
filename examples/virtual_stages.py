"""Pipeline stages mongod does not have, run by the boundary. No model in it.

    docker compose up -d mongo
    uv run python examples/virtual_stages.py     # no API key, no vendor

The policy file declares four names MongoDB has never heard of --
`$redactEmails`, `$chunk` and `$wordCount` as expression operators, and
`$stats` and `$keywordRank` as stages -- and an ordinary `pymongo` client
uses them in an ordinary `aggregate`, mixed with `$unwind`, `$match`,
`$sort` and `$limit` that mongod runs itself:

    $match {tenant: acme}                     mongod, judged on the way out
    $addFields {clean: {$redactEmails}}       the boundary
    $addFields {chunks: {$chunk}}             the boundary
    $unwind, then $addFields {$wordCount}     mongod on a temp, the boundary
    $stats {as: "corpus"}                     the boundary, publishes $$corpus
    $keywordRank {idf: "$$corpus.idf"}        the boundary
    $match, $sort, $limit                     mongod, on a temporary collection

Three things are shown, and asserted:

**The virtual steps only ever see admitted documents.** The collection
holds a live note, an expired one, a revoked one and another tenant's. The
chunks, the word counts and the corpus statistics are computed from the
live one alone -- `$$corpus` is a pipeline variable, and nothing a refused
row said can move it.

**The native steps after a virtual one ran in mongod, on a temporary
collection, and it is gone.** The profiler on the temporary database is the
evidence it existed; `list_collection_names()` is the evidence it does not.

**The boundary never calls a model.** VOYD guarantees what context the
client *receives*. What the client does with it -- build a prompt, call its
own model with its own key -- happens below, in the client, outside the
proxy. With `ANTHROPIC_API_KEY` set and `anthropic` installed *in the
client's environment* it asks Claude; otherwise it prints the prompt it
would have sent.
"""

from __future__ import annotations

import os
import textwrap
from datetime import timedelta

from pymongo import MongoClient

from _boundary import boundary, deployment
from voyd.engine.time import now

POLICY = textwrap.dedent('''
    import math
    import re

    from voyd import deadline, guard, operator, revocable, stage, tenant

    @guard("manuals")
    class Manuals:
        expire_at = deadline()
        forgotten = revocable()
        tenant_id = tenant()

    EMAIL = re.compile(r"[\\w.+-]+@[\\w-]+\\.[\\w.]+")

    def words(text):
        return re.findall(r"[a-z0-9]+", str(text).lower())

    @operator("$redactEmails")
    def redact_emails(doc, args, ctx):
        return EMAIL.sub("[email]", str(args))

    @operator("$chunk")
    def chunk(doc, args, ctx):
        toks = str(args["of"]).split()
        size = int(args.get("size", 8))
        return [" ".join(toks[i:i + size]) for i in range(0, len(toks), size)]

    @operator("$wordCount")
    def word_count(doc, args, ctx):
        return len(words(args))

    @stage("$stats")
    def stats(args, docs, ctx):
        """Document frequency over the admitted chunks, published."""
        field = args.get("field", "text")
        n = len(docs)
        df = {}
        for d in docs:
            for w in set(words(d.get(field, ""))):
                df[w] = df.get(w, 0) + 1
        ctx.publish(args["as"], {
            "n": n,
            "idf": {w: math.log((1 + n) / (1 + c)) + 1 for w, c in df.items()},
        })
        return docs

    @stage("$keywordRank")
    def keyword_rank(args, docs, ctx):
        """Score each chunk by the idf of the query words it contains."""
        idf, field = args["idf"], args.get("field", "text")
        query = [w for q in args["words"] for w in words(q)]
        out = []
        for d in docs:
            have = set(words(d.get(field, "")))
            score = round(sum(idf.get(w, 0.0) for w in query if w in have), 3)
            out.append({**d, "score": score})
        return out
''')

LIVE = ("Brake fault B1342 means the pressure sensor is out of range. "
        "Check the connector first, then replace the sensor. "
        "Escalate to service@acme.example if the fault returns.")
EXPIRED = "Old procedure: bleed the brake fault line and ignore B1342."
REVOKED = "Leaked: the brake fault override code is 0000."
GLOBEX = "Globex brake fault B1342 bulletin, confidential."

PIPELINE = [
    {"$match": {"tenant_id": "acme"}},
    {"$addFields": {"clean": {"$redactEmails": "$text"}}},
    {"$addFields": {"chunks": {"$chunk": {"of": "$clean", "size": 8}}}},
    {"$unwind": "$chunks"},
    {"$addFields": {"words": {"$wordCount": "$chunks"}}},
    {"$stats": {"as": "corpus", "field": "chunks"}},
    {"$keywordRank": {"words": ["brake fault", "sensor"],
                      "idf": "$$corpus.idf", "field": "chunks"}},
    {"$match": {"score": {"$gt": 0}}},
    {"$sort": {"score": -1}},
    {"$limit": 3},
    {"$project": {"_id": 1, "chunks": 1, "score": 1, "words": 1}},
]


def answer(question: str, context: list[str]) -> str:
    """The client's own model call. Nothing here runs inside the boundary.

    The proxy has no key and makes no call; this function is the part of
    the application that owns inference, and it only ever sees what the
    boundary served.
    """
    prompt = ("Answer from the context only.\n\nContext:\n"
              + "\n".join(f"- {c}" for c in context)
              + f"\n\nQuestion: {question}")
    if os.getenv("ANTHROPIC_API_KEY"):
        try:
            import anthropic
        except ImportError:
            pass
        else:
            reply = anthropic.Anthropic().messages.create(
                model="claude-sonnet-5", max_tokens=300,
                messages=[{"role": "user", "content": prompt}])
            return "".join(getattr(b, "text", "") for b in reply.content)
    return "(offline: no client-side model configured)\n" + textwrap.indent(
        prompt, "    ")


def main() -> None:
    with deployment("virtual") as (direct, db):
        scratch = f"{db}_tmp"
        past = now() - timedelta(days=1)
        direct[db].manuals.insert_many([
            {"_id": 1, "tenant_id": "acme", "text": LIVE},
            {"_id": 2, "tenant_id": "acme", "text": EXPIRED,
             "expire_at": past},
            {"_id": 3, "tenant_id": "acme", "text": REVOKED,
             "forgotten": {"at": past, "reason": "leaked"}},
            {"_id": 4, "tenant_id": "globex", "text": GLOBEX},
        ])
        # Evidence the temporary collection existed: the profiler.
        direct[scratch].command("profile", 2)
        try:
            with boundary(POLICY, "--virtual-db", scratch, "--quiet") as uri:
                client = MongoClient(uri, serverSelectionTimeoutMS=8000)
                print("\n  Four manuals: one live, one expired, one revoked, "
                      "one another tenant's.\n")
                hits = list(client[db].manuals.aggregate(PIPELINE))
                client.close()

            for h in hits:
                print(f"  score {h['score']:>5}  {h['words']:>2} words  "
                      f"{h['chunks']}")
            assert hits and all(h["_id"] == 1 for h in hits), hits
            text = " ".join(h["chunks"] for h in hits)
            for refused in ("Old procedure", "override code", "Globex"):
                assert refused not in text, refused
            assert "service@acme.example" not in text
            print("\n  every chunk is from the live manual; the email was "
                  "redacted before chunking")

            ran = [p for p in direct[scratch]["system.profile"].find(
                {"op": "command", "command.aggregate": {"$exists": True}})
                if str(p["ns"]).split(".", 1)[1].startswith("t_")]
            left = [n for n in direct[scratch].list_collection_names()
                    if not n.startswith("system.")]
            print(f"  native steps run on a temporary collection: "
                  f"{len(ran)}; temporary collections left: {len(left)}")
            assert ran, "the native suffix did not run on a temporary one"
            assert left == [], left

            print("\n  The client, outside the boundary, owns inference:\n")
            print(textwrap.indent(
                answer("What does B1342 mean and what do I check first?",
                       [h["chunks"] for h in hits]), "  "))
            print()
        finally:
            direct.drop_database(scratch)


if __name__ == "__main__":
    main()
