"""The native steps after a virtual one run in mongod, and leave nothing.

A pipeline like

    $match -> $addFields{$chunk} -> $unwind -> $addFields{$wordCount}
           -> $match{words > n} -> $sort

has virtual steps in it that only this boundary can run and native ones
that only mongod runs exactly. The native ones after a virtual step run on
a temporary collection holding the virtual step's output. The claims:

    The answer is right, and it is computed from admitted documents only.
    The temporary collection is gone when the read is -- after an error too.
    A proxy that died mid-read has its leftovers swept by the next one.
    The sweep never drops anything it did not name.
    No client can read the temporary database through the boundary.

Live: a real `voyd-wire` in front of a real deployment, and a plain
`pymongo` client. Each test gets its own temporary database (`--virtual-db`)
so two runs on one cluster cannot sweep each other's.
"""

from __future__ import annotations

import time
from datetime import timedelta

import pytest
from pymongo import MongoClient
from pymongo.errors import OperationFailure

from voyd.engine.time import now
from voyd.wire.scratch import scratch_name

pytestmark = pytest.mark.needs_mongo

POLICY = """
from voyd import guard, deadline, revocable, tenant, mask, stage, operator

@guard("notes")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()
    ssn       = mask()

SHOWN = []

@operator("$chunk")
def chunk(doc, args, ctx):
    words = str(args["of"]).split()
    size = int(args["size"])
    return [" ".join(words[i:i + size]) for i in range(0, len(words), size)]

@operator("$wordCount")
def word_count(doc, args, ctx):
    return len(str(args).split())

@stage("$stats")
def stats(args, docs, ctx):
    words = [d.get("words", 0) for d in docs]
    ctx.publish(args["as"], {"n": len(docs),
                             "meanWords": sum(words) / max(len(words), 1)})
    return docs

@stage("$boom")
def boom(args, docs, ctx):
    raise RuntimeError("the stage fell over")

@stage("$pass")
def passthrough(args, docs, ctx):
    return docs
"""

LONG = " ".join(f"w{i}" for i in range(12))


def seed(direct, database):
    past = now() - timedelta(days=1)
    direct[database].notes.insert_many([
        {"_id": 1, "tenant_id": "acme", "text": LONG, "ssn": "123-45-6789"},
        {"_id": 2, "tenant_id": "acme", "text": "short one"},
        {"_id": 3, "tenant_id": "acme", "text": "expired " + LONG,
         "expire_at": past},
        {"_id": 4, "tenant_id": "acme", "text": "revoked " + LONG,
         "forgotten": {"at": past, "reason": "asked"}},
        {"_id": 5, "tenant_id": "globex", "text": "globex " + LONG},
    ])


@pytest.fixture
def tmpdb(direct, database):
    name = f"{database}_tmp"
    try:
        yield name
    finally:
        direct.drop_database(name)


def client_for(wire):
    return MongoClient(wire.uri, serverSelectionTimeoutMS=10_000)


def test_the_native_suffix_runs_on_admitted_rows_and_leaves_nothing(
        boundary, direct, database, tmpdb):
    seed(direct, database)
    wire = boundary(POLICY, "--virtual-db", tmpdb)
    with client_for(wire) as client:
        out = list(client[database].notes.aggregate([
            {"$match": {"tenant_id": "acme"}},
            {"$addFields": {"chunks": {"$chunk": {"of": "$text",
                                                  "size": 5}}}},
            {"$unwind": "$chunks"},
            {"$addFields": {"words": {"$wordCount": "$chunks"}}},
            {"$match": {"words": {"$gte": 5}}},
            {"$sort": {"_id": 1, "chunks": 1}},
        ]))
    # Doc 1 chunks into 5+5+2; the two five-word chunks survive. Doc 2 is
    # too short. The expired, revoked and globex rows were never chunked.
    assert [(d["_id"], d["words"]) for d in out] == [(1, 5), (1, 5)]
    assert all(d["ssn"] is None for d in out)
    assert direct[tmpdb].list_collection_names() == []


def test_a_group_after_a_virtual_step_reduces_admitted_rows_only(
        boundary, direct, database, tmpdb):
    seed(direct, database)
    wire = boundary(POLICY, "--virtual-db", tmpdb)
    with client_for(wire) as client:
        out = list(client[database].notes.aggregate([
            {"$match": {"tenant_id": "acme"}},
            {"$addFields": {"words": {"$wordCount": "$text"}}},
            {"$group": {"_id": "$tenant_id", "n": {"$sum": 1},
                        "words": {"$sum": "$words"}}},
        ]))
    assert out == [{"_id": "acme", "n": 2, "words": 14}]
    assert direct[tmpdb].list_collection_names() == []


def test_a_published_variable_reaches_the_native_steps(
        boundary, direct, database, tmpdb):
    seed(direct, database)
    wire = boundary(POLICY, "--virtual-db", tmpdb)
    with client_for(wire) as client:
        out = list(client[database].notes.aggregate([
            {"$match": {"tenant_id": "acme"}},
            {"$addFields": {"words": {"$wordCount": "$text"}}},
            {"$stats": {"as": "corpus"}},
            {"$match": {"$expr": {"$gt": ["$words", "$$corpus.meanWords"]}}},
            {"$addFields": {"of": "$$corpus.n"}},
        ]))
    # Mean over the two admitted rows is 7; the refused ones, 13 words
    # each, would have moved it and did not get the chance.
    assert [(d["_id"], d["of"]) for d in out] == [(1, 2)]


def test_a_trailing_virtual_step_creates_no_temporary_collection(
        boundary, direct, database, tmpdb):
    seed(direct, database)
    wire = boundary(POLICY, "--virtual-db", tmpdb)
    with client_for(wire) as client:
        out = list(client[database].notes.aggregate([
            {"$match": {"tenant_id": "acme"}}, {"$pass": {}}]))
    assert sorted(d["_id"] for d in out) == [1, 2]
    assert tmpdb not in direct.list_database_names()


def test_a_failed_read_leaves_nothing_either(boundary, direct, database,
                                             tmpdb):
    seed(direct, database)
    wire = boundary(POLICY, "--virtual-db", tmpdb, "--virtual-max-docs", "1")
    with client_for(wire) as client:
        with pytest.raises(OperationFailure, match="RuntimeError"):
            list(client[database].notes.aggregate([
                {"$match": {"tenant_id": "acme"}}, {"$limit": 1}, {"$boom": {}},
                {"$sort": {"_id": 1}}]))
        with pytest.raises(OperationFailure, match="--virtual-max-docs"):
            list(client[database].notes.aggregate([
                {"$match": {"tenant_id": "acme"}}, {"$pass": {}},
                {"$sort": {"_id": 1}}]))
        # A server-side error in the suffix, after the temp was made.
        with pytest.raises(OperationFailure, match="failed in MongoDB"):
            list(client[database].notes.aggregate([
                {"$match": {"tenant_id": "acme"}}, {"$limit": 1},
                {"$pass": {}}, {"$sort": {"_id": "sideways"}}]))
    assert direct[tmpdb].list_collection_names() == []


def test_a_crashed_proxys_leftovers_are_swept_and_nothing_else(
        boundary, direct, database, tmpdb):
    old = scratch_name("deadbeef", now=time.time() - 3600)
    fresh = scratch_name("deadbeef")
    for name in (old, fresh, "keep_me"):
        direct[tmpdb][name].insert_one({"left": "behind"})
    # A name that looks like ours in a database that is not.
    direct[database][old].insert_one({"not": "ours"})

    boundary(POLICY, "--virtual-db", tmpdb, "--virtual-max-age", "600")
    left = set(direct[tmpdb].list_collection_names())
    assert old not in left, "an hour-old temporary collection survived"
    assert {fresh, "keep_me"} <= left
    assert old in direct[database].list_collection_names()


def test_the_periodic_sweep_catches_what_ages_while_it_runs(
        boundary, direct, database, tmpdb):
    wire = boundary(POLICY, "--virtual-db", tmpdb, "--virtual-max-age", "2")
    name = scratch_name("deadbeef")
    direct[tmpdb][name].insert_one({"left": "behind"})
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if name not in direct[tmpdb].list_collection_names():
            break
        time.sleep(0.5)
    assert name not in direct[tmpdb].list_collection_names()
    assert wire.port


def test_no_client_reaches_the_temporary_database(boundary, direct,
                                                  database, tmpdb):
    name = scratch_name("deadbeef")
    direct[tmpdb][name].insert_one({"somebody": "else's admitted row"})
    wire = boundary(POLICY, "--virtual-db", tmpdb)
    with client_for(wire) as client:
        scratch = client[tmpdb]
        for attempt in (lambda: list(scratch[name].find()),
                        lambda: list(scratch[name].aggregate([])),
                        lambda: scratch[name].insert_one({"x": 1}),
                        lambda: scratch.list_collection_names(),
                        lambda: scratch[name].watch(),
                        lambda: client.admin.command(
                            "renameCollection", f"{tmpdb}.{name}",
                            to=f"{database}.stolen")):
            with pytest.raises(OperationFailure, match="refuses commands"):
                attempt()
        # Its name is visible, and nothing else about it.
        assert tmpdb in client.list_database_names()
    assert direct[tmpdb][name].count_documents({}) == 1
