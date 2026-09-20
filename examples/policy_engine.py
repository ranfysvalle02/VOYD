"""Casbin owns the subject. VOYD owns the objects.

    docker compose up -d mongo
    uv run --with casbin python examples/policy_engine.py

A policy engine answers *may this subject do this to this object?* -- one
subject, one object, a boolean. Retrieval asks something the same shape only
until you look: *which of these five hundred candidates may reach the prompt?*

The tempting adapter wraps `enforce()` in a Rule and calls it per hit. It
works and it is the wrong shape twice over: it is one Python matcher call per
candidate, and it pushes nothing into the database, so the read fetches
everything and discards most of it.

The division below is the one that survives contact. Casbin is good at the
part VOYD has no vocabulary for -- role graphs, hierarchies, domains, all of
it reasoning about *who is asking*. VOYD is good at the part Casbin has no
mechanism for -- turning the answer into a filter that runs server-side and
holds on the `$vectorSearch` path too. So Casbin flattens the subject once,
and VOYD filters the objects once:

    roles = enforcer.get_implicit_roles_for_user("alice")
    docs.for_caller({"groups": roles}).find({})     # -> {"acl": {"$in": [...]}}

One call each, and `Restricted` compiles the result into an indexed query.

What this does *not* do is make Casbin the engine. It cannot be: a token
budget refuses a document because of the other documents in the same read,
and `enforce(sub, obj, act)` is a pure function of two arguments with nowhere
to put the third. Part B shows that directly -- see `docs/policy-engines.md`
for the argument and `examples/rosetta.py` for the protocol it comes from.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
import uuid

from pymongo import AsyncMongoClient

from voyd.engine import Budget, Distinct, Engine, Restricted

MODEL = """
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
"""

# A four-level hierarchy. VOYD has no opinion about any of it, on purpose:
# "a senior engineer is an engineer" is a statement about people, and this
# package's whole discipline is to not grow vocabulary it cannot enforce.
POLICY = """p, reader, notes, read
g, engineer, reader
g, senior_engineer, engineer
g, alice, senior_engineer
g, bob, contractor
"""

DOCS = [
    {"doc_id": "d1", "acl": ["reader"], "tokens": 40,
     "text": "onboarding checklist"},
    {"doc_id": "d2", "acl": ["contractor"], "tokens": 40,
     "text": "contractor handbook"},
    {"doc_id": "d3", "acl": ["senior_engineer"], "tokens": 40,
     "text": "incident postmortem"},
    {"doc_id": "d4", "acl": ["finance"], "tokens": 40,
     "text": "quarterly forecast"},
]


def enforcer():
    """A real Casbin enforcer over the model and policy above.

    The file is `policy_engine.py` rather than `casbin.py` for a dull and
    load-bearing reason: a script's own directory goes first on `sys.path`,
    so `examples/casbin.py` would import *itself* here and fail with
    `module 'casbin' has no attribute 'Enforcer'`.
    """
    import casbin

    directory = tempfile.mkdtemp()
    model_path = os.path.join(directory, "model.conf")
    policy_path = os.path.join(directory, "policy.csv")
    with open(model_path, "w") as fh:
        fh.write(MODEL)
    with open(policy_path, "w") as fh:
        fh.write(POLICY)
    return casbin.Enforcer(model_path, policy_path)


async def part_a(engine, casbin_enforcer):
    """Casbin resolves who you are; VOYD turns that into one query."""
    print("\n  A. the subject is Casbin's, the objects are VOYD's")
    print("  " + "-" * 66)

    docs = engine.model("notes").admitting(
        Restricted(field="acl", claim="groups"))

    for who in ("alice", "bob"):
        # Subject-side, once per request. No documents are involved: this is
        # a walk over a role graph, which is exactly what Casbin is for.
        roles = casbin_enforcer.get_implicit_roles_for_user(who) + [who]

        handle = docs.for_caller({"groups": roles})
        page = await handle.find({})

        print(f"\n  {who}")
        print(f"    casbin flattens -> {roles}")
        # The clause is what the server ran. Not a debug aid: it is the
        # optimisation half, and `_admit` re-checks every row it returns.
        print(f"    voyd filters    -> {handle._query({})['$and'][0]}")
        print(f"    reaches a prompt-> {sorted(d['doc_id'] for d in page)}")


async def part_b(engine):
    """The rule no policy engine can hold, because it is not about one doc."""
    print("\n\n  B. the same document, the same caller, two answers")
    print("  " + "-" * 66)

    docs = engine.model("budgeted").admitting(
        Budget(limit=100, cost_field="tokens"))

    alone = await docs.find({"doc_id": "small"}, sort=[("doc_id", 1)])
    whole = await docs.find({}, sort=[("doc_id", 1)])

    print(f"\n    'small' asked for on its own -> "
          f"{sorted(d['doc_id'] for d in alone)}")
    print(f"    'small' behind a 95-token row -> "
          f"{sorted(d['doc_id'] for d in whole)}")
    print(f"    refused, by reason            -> "
          f"{docs.receipts()['refused_by_reason']}")
    # And it is not one awkward example. `Distinct` is set-relative for the
    # same reason: whether this row is redundant depends on which other rows
    # are in the page. Two cumulative rules, one handle, separate state.
    deduped = engine.model("chunks").admitting(
        Budget(limit=100, cost_field="tokens"), Distinct("chunk"))
    page = await deduped.find({}, sort=[("rank", 1)])
    print("\n    four chunks, two of them the same passage")
    print(f"    admitted                      -> "
          f"{[d['doc_id'] for d in page]}")
    print(f"    refused, by reason            -> "
          f"{deduped.receipts()['refused_by_reason']}")

    print("\n    `enforce(sub, obj, act)` takes a subject and an object.")
    print("    There is no argument for 'the rest of the page', so no")
    print("    matcher can return both of those answers. Nor can an index")
    print("    filter: it decides each candidate on its own, before the")
    print("    page exists. This reason only has an egress half.")


async def main():
    uri = os.environ.get("VOYD_MONGO_URI",
                         "mongodb://localhost:27018/?directConnection=true")
    try:
        casbin_enforcer = enforcer()
    except ImportError:
        print("\n  needs pycasbin, which VOYD does not depend on:\n"
              "      uv run --with casbin python examples/policy_engine.py\n")
        return

    client = AsyncMongoClient(uri, tz_aware=True)
    name = f"casbin_demo_{uuid.uuid4().hex[:10]}"
    engine = Engine(client, client[name])
    await engine.connect()
    try:
        await client[name].notes.insert_many([dict(d) for d in DOCS])
        await client[name].budgeted.insert_many([
            {"doc_id": "big", "tokens": 95},
            {"doc_id": "small", "tokens": 10},
        ])
        await client[name].chunks.insert_many([
            {"doc_id": "a1", "chunk": "h1", "tokens": 30, "rank": 1},
            {"doc_id": "b1", "chunk": "h2", "tokens": 30, "rank": 2},
            {"doc_id": "a2", "chunk": "h1", "tokens": 30, "rank": 3},
            {"doc_id": "c1", "chunk": "h3", "tokens": 30, "rank": 4},
        ])
        await part_a(engine, casbin_enforcer)
        await part_b(engine)
        print("\n  Two engines, one read, neither doing the other's job.\n")
    finally:
        await client.drop_database(name)
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
