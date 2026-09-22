"""A data breach that arrives as an answer.

    docker compose up -d
    uv run python examples/tenancy.py    # ~5 seconds, no API key, no vendor

Cross-tenant leakage in retrieval is not an exotic failure. It is the ordinary
one, and the reason is specific: `find({"tenant_id": t})` is easy to remember,
and **a `$vectorSearch` hit never passes through that query at all.** One read
path prunes correctly and another does not, which is a silent hole:
the filter narrows and nothing says it did. Nothing errors. A
well-scored, well-formed row from somebody else's company is ranked into a
prompt, and the answer is returned to a customer who was never entitled to it.

**The client below imports `MongoClient` and nothing else.** The tenant is
not a filter anybody remembers, and it is also not an API anybody calls: it
is a line in a policy file, enforced by the connection string.

Four things, in order, and the fourth is the one nobody expects.

1. **The raw read leaks**, and that is the baseline to beat.
2. **An unscoped read returns nothing, rather than everything.** The
   boundary judges each document against the scope the batch itself
   declares, and a batch spanning two tenants declares none -- so every row
   in it is refused. You no longer have to remember the filter. Forgetting
   it now costs you an empty page instead of somebody else's data.
3. **A tenant id that is a query operator buys nothing.**
   `{"tenant_id": {"$ne": "nobody"}}` passes a presence check and then
   matches every tenant. `$vectorSearch`'s filter accepts `$ne`, so a
   presence check plus a vector index is a leak with a green test suite --
   and here the operator simply produces the mixed batch from (2), which is
   refused whole.
4. **A projection cannot blind the boundary.** This is the one nobody
   expects, and it is the proof that the check is per document rather than
   per query. The verdict is read off fields *on the document*; a
   projection that removes them and does not pin the tenant leaves the
   boundary nothing to judge with, so the read is **refused outright**
   rather than served unjudged. Pin the tenant and the same projection is
   fine -- the server already pruned, and the boundary says so rather than
   being uniformly strict about a shape.

No vector index is built here. The per-document check is the same code on
every path, so these isolate the part being shown without a 100-second
index build, which is the cluster's clock rather than this example's.
"""

from __future__ import annotations

from pymongo import MongoClient
from pymongo.errors import PyMongoError

from _boundary import boundary, deployment

CORPUS = [
    {"tenant_id": "acme",   "text": "acme salary bands, 2026"},
    {"tenant_id": "acme",   "text": "acme q3 roadmap"},
    {"tenant_id": "globex", "text": "globex merger memo -- confidential"},
]

POLICY = '''
from voyd import guard, deadline, revocable, tenant

@guard("notes")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()
'''


def _refused(call) -> str:
    """Run something that must not be served, and report the refusal."""
    try:
        call()
    except PyMongoError as exc:
        return str(exc).split(".")[0]
    raise AssertionError("this was served, and it must not have been")


def main() -> None:
    with deployment("tenancy") as (direct, name):
        direct[name].notes.insert_many([dict(d) for d in CORPUS])

        with boundary(POLICY) as uri:
            client = MongoClient(uri, serverSelectionTimeoutMS=8000)
            notes = client[name].notes
            try:
                print("\n  Two tenants in one collection. Acme is asking.\n")

                raw = list(direct[name].notes.find({}))
                others = [d["text"] for d in raw if d["tenant_id"] != "acme"]
                print("  1. the raw read a teammate writes next month")
                print(f"       db.notes.find({{}}) -> {len(raw)} documents, "
                      f"{len({d['tenant_id'] for d in raw})} tenants")
                print(f"       including: {others}")
                assert others

                print("\n  2. through the boundary, an unscoped read "
                      "returns nothing")
                print("     rather than everything")
                served = list(notes.find({}))
                print(f"       find({{}}) -> {served}")
                print("       Three rows on disk, two tenants in the batch, "
                      "so the")
                print("       batch declares no scope and every document in "
                      "it is")
                print("       refused. Forgetting the filter costs an empty "
                      "page.")
                assert served == []

                acme = sorted(d["text"] for d in
                              notes.find({"tenant_id": "acme"}))
                print(f"       find({{'tenant_id': 'acme'}}) -> {acme}")
                assert acme == ["acme q3 roadmap", "acme salary bands, 2026"]

                print("\n  3. ...and an operator in the tenant buys nothing")
                sneaky = list(notes.find({"tenant_id": {"$ne": "nobody"}}))
                print(f"       find({{'tenant_id': {{'$ne': 'nobody'}}}}) -> "
                      f"{sneaky}")
                print("       A presence check would pass that and hand back "
                      "every")
                print("       tenant. Here it is the mixed batch from (2), "
                      "refused")
                print("       whole -- because the scope is checked against "
                      "the")
                print("       document, not against the shape of the query.")
                assert sneaky == []

                print("\n  4. and a projection cannot blind it")
                why = _refused(lambda: list(notes.find({}, {"text": 1,
                                                           "_id": 0})))
                print(f"       find({{}}, {{'text': 1}}) -> refused: {why}")
                print("         The verdict is read off fields on the "
                      "document.")
                print("         Remove them without pinning the tenant and "
                      "there is")
                print("         nothing left to judge with -- which is a "
                      "read this")
                print("         boundary will not stand behind, rather than "
                      "one it")
                print("         serves unjudged. That is what a $vectorSearch "
                      "hit is:")
                print("         a document no query pruned.")

                kept = sorted(d["text"] for d in notes.find(
                    {"tenant_id": "acme"}, {"text": 1, "_id": 0}))
                print(f"       ...but pin the tenant and it is fine -> {kept}")
                print("         The server already pruned, so the boundary "
                      "says so")
                print("         rather than being uniformly strict about a "
                      "shape.")
                assert kept == ["acme q3 roadmap", "acme salary bands, 2026"]

                print("\n  Now both halves agree, which is the whole rule: a "
                      "constraint")
                print("  pushed into a query must also exist per document, or "
                      "one read")
                print("  path prunes and another serves the same row to the "
                      "wrong customer.")
                print("\n  Application lines changed: 0\n")
            finally:
                client.close()


if __name__ == "__main__":
    main()
