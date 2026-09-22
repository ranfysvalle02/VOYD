"""An ordinary driver, an ordinary connection string, a real deployment.

Everything else in this suite is pure, which is the property that lets the
check run inside a proxy at all. This file is the other half: the claims that
are only true if the *queries* are right, and which a mock would answer by
proving the mock was filtered.

The driver here is plain `pymongo`. It has never heard of this package, no
import was added to it and no read path was rewritten -- the connection
string points at `voyd-wire` instead of at the cluster, and that is the whole
integration. Every assertion is made twice: once through the boundary and
once around it, because "the boundary refused it" and "the row is still on
disk" are two different statements and only the unguarded client can make the
second.

Marked `needs_mongo`, so the pure run stays pure.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pymongo import MongoClient
from pymongo.errors import OperationFailure

from tests.conftest import MODEL, scratch_name

pytestmark = pytest.mark.needs_mongo

UTC = timezone.utc
POLICY = """
from voyd import guard, deadline, revocable, tenant

@guard("notes", on_delete="revoke")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()
"""


def past() -> datetime:
    return datetime.now(UTC) - timedelta(hours=1)


def future() -> datetime:
    return datetime.now(UTC) + timedelta(days=1)


@pytest.fixture
def guarded(boundary, database):
    """A boundary in front of `database`, and a driver pointed at it."""
    wire = boundary(POLICY)
    client = MongoClient(wire.uri, serverSelectionTimeoutMS=15_000)
    try:
        yield client[database].notes
    finally:
        client.close()


def test_an_expired_row_is_refused_while_it_is_still_on_disk(guarded, direct,
                                                             database):
    # The whole bug class. MongoDB's TTL monitor runs about once a minute,
    # so this document exists, is indexed, and would be returned with a
    # confident score for the length of that window.
    guarded.insert_many([
        {"_id": "live", "tenant_id": "acme", "expire_at": future()},
        {"_id": "gone", "tenant_id": "acme", "expire_at": past()},
    ])

    served = [d["_id"] for d in guarded.find({"tenant_id": "acme"})]
    assert served == ["live"]

    # Around the boundary: the row the client could not read is right there.
    # Refusal is a retrieval guarantee, not a storage event.
    on_disk = {d["_id"] for d in direct[database].notes.find({})}
    assert on_disk == {"live", "gone"}


def test_the_refusal_reaches_every_way_out_not_only_find(guarded, direct,
                                                         database):
    guarded.insert_many([
        {"_id": "live", "tenant_id": "acme", "expire_at": future()},
        {"_id": "gone", "tenant_id": "acme", "expire_at": past()},
    ])
    flt = {"tenant_id": "acme"}
    # A boundary that filtered `find` and not `findOne` would be a second
    # read path with a different guarantee, which is the failure this
    # project exists to remove -- one connection string, every read.
    assert guarded.find_one({**flt, "_id": "gone"}) is None
    assert guarded.find_one({**flt, "_id": "live"})["_id"] == "live"
    assert [d["_id"] for d in guarded.aggregate([{"$match": flt}])] == ["live"]
    assert guarded.count_documents(flt) == 1
    assert direct[database].notes.count_documents(flt) == 2


def test_a_revoked_fact_is_unreachable_on_the_next_read(guarded, direct,
                                                        database):
    guarded.insert_one({"_id": "n1", "tenant_id": "acme",
                        "expire_at": future()})
    assert guarded.find_one({"tenant_id": "acme"})["_id"] == "n1"

    # An operator's erasure request, written as the mark the policy
    # declared. No sweeper runs, nothing is deleted, and the next read
    # cannot see it.
    direct[database].notes.update_one(
        {"_id": "n1"}, {"$set": {"forgotten": {"at": past()}}})

    assert guarded.find_one({"tenant_id": "acme"}) is None
    assert direct[database].notes.find_one({"_id": "n1"}) is not None


def test_the_tenant_is_enforced_on_both_halves(guarded, database, direct):
    guarded.insert_many([
        {"_id": "ours", "tenant_id": "acme", "expire_at": future()},
        {"_id": "theirs", "tenant_id": "globex", "expire_at": future()},
    ])
    # Half one, per document on the way out: a read that named no tenant is
    # not a read of everything. Each document arrives at the boundary from
    # outside the scope the read declared, and is refused as `off_scope`.
    assert list(guarded.find({})) == []
    # Including the query that names several, which is the same leak with
    # an extra step.
    assert list(guarded.find({"tenant_id": {"$in": ["acme", "globex"]}})) == []

    # Half two, in the query: a reduction has no batch to take the scope
    # from, so an unpinned tenant is not a narrower answer -- it is every
    # tenant's rows summarised into one number. That one is refused by
    # name rather than answered with a zero.
    for unscoped in (lambda: guarded.count_documents({}),
                     lambda: guarded.distinct("tenant_id")):
        with pytest.raises(OperationFailure) as refused:
            unscoped()
        assert "voyd-wire" in (refused.value.details or {}).get("errmsg", "")

    # Two different mistakes, and both of them leak. Scoped reads work.
    assert [d["_id"] for d in guarded.find({"tenant_id": "acme"})] == ["ours"]
    assert [d["_id"] for d in guarded.find({"tenant_id": "globex"})] == ["theirs"]
    assert guarded.count_documents({"tenant_id": "acme"}) == 1
    assert direct[database].notes.count_documents({}) == 2


def test_a_delete_becomes_a_revocation_with_the_row_still_on_disk(
        guarded, direct, database):
    # `on_delete="revoke"` in the policy file. Every `deleteOne` already
    # written in somebody's application stops being a wish: unreachable on
    # the next read, row kept for the investigation, deadline pulled in so
    # the reaper collects it on the schedule it already had.
    guarded.insert_one({"_id": "n1", "tenant_id": "acme",
                        "expire_at": future()})
    result = guarded.delete_one({"_id": "n1", "tenant_id": "acme"})
    assert result.acknowledged

    assert guarded.find_one({"tenant_id": "acme"}) is None
    kept = direct[database].notes.find_one({"_id": "n1"})
    assert kept is not None, "the row was really deleted; nothing to audit"
    assert kept.get("forgotten"), "deleted without recording that it was"


def test_a_write_still_writes_and_a_ping_is_still_a_ping(guarded, direct,
                                                         database):
    # The boundary rewrites reads and one write. Everything else has to go
    # through untouched, or adopting it is a rewrite of the application
    # after all.
    guarded.insert_one({"_id": "n1", "tenant_id": "acme",
                        "expire_at": future(), "body": "first"})
    guarded.update_one({"_id": "n1", "tenant_id": "acme"},
                       {"$set": {"body": "second"}})
    assert guarded.find_one({"tenant_id": "acme"})["body"] == "second"
    assert direct[database].notes.find_one({"_id": "n1"})["body"] == "second"
    assert guarded.database.command("ping")["ok"] == 1


def test_a_page_is_refused_across_every_batch_the_client_asks_for(
        guarded, direct, database):
    # A cursor is several round trips, and a boundary that checked the
    # first reply and forwarded the rest would pass a small test and leak
    # on a real one.
    live = [{"_id": f"live{i}", "tenant_id": "acme", "expire_at": future()}
            for i in range(30)]
    dead = [{"_id": f"gone{i}", "tenant_id": "acme", "expire_at": past()}
            for i in range(30)]
    guarded.insert_many(live + dead)

    served = [d["_id"] for d in guarded.find({"tenant_id": "acme"},
                                             batch_size=7)]
    assert len(served) == 30
    assert all(i.startswith("live") for i in served)
    assert direct[database].notes.count_documents({}) == 60


# ---- the server owns the encoding --------------------------------------

AUTO_POLICY = f"""
from voyd import guard, deadline, revocable, tenant, auto_embed

@guard("notes", on_delete="revoke")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()
    body      = auto_embed({MODEL!r})

# An ordinary guarded collection beside it, declaring nothing about who
# embeds. A client vector is correct here and must keep working -- without
# it this cannot tell "refuses the right query" from "refuses $vectorSearch".
@guard("archive")
class Archive:
    expire_at = deadline()
    tenant_id = tenant()
"""


def test_a_client_vector_is_refused_where_the_server_owns_the_index(
        boundary, database):
    # Comparing a vector to an index built by a different model does not
    # fail -- it returns a number between -1 and 1, which is the whole
    # problem. So it is refused by name, and told which form works.
    wire = boundary(AUTO_POLICY)
    client = MongoClient(wire.uri, serverSelectionTimeoutMS=15_000)
    try:
        db = client[database]
        with pytest.raises(OperationFailure) as refused:
            list(db.notes.aggregate([{"$vectorSearch": {
                "index": "engine_vector_index", "path": "embedding",
                "queryVector": [0.1] * 1024, "numCandidates": 10,
                "limit": 5}}]))
        said = (refused.value.details or {}).get("errmsg", "")
        assert "voyd-wire" in said and MODEL in said
        assert "$vectorSearch.query" in said, "refused without saying what works"

        # Not because $vectorSearch is banned. The collection that declared
        # nothing about embedding is forwarded, and whatever comes back
        # comes from the server.
        try:
            list(db.archive.aggregate([{"$vectorSearch": {
                "index": "engine_vector_index", "path": "embedding",
                "queryVector": [0.1] * 1024, "numCandidates": 10,
                "limit": 5}}]))
        except OperationFailure as server_said:
            # No index exists on `archive` in this throwaway database, so
            # Atlas refuses it. That is the right outcome; the claim is
            # only that the *boundary* did not.
            assert "voyd-wire" not in (server_said.details or {}).get(
                "errmsg", ""), "the boundary refused a collection that " \
                               "declared nothing about who embeds"
    finally:
        client.close()


@pytest.mark.slow
def test_search_refuses_on_the_path_that_bypasses_the_query(
        atlas_uri, boundary):
    """The claim that needs a cluster that can actually embed.

    A `$vectorSearch` hit does not pass through the collection query, so
    every pushed-down clause in this package is an optimisation and none of
    them is the guarantee. The per-document check on the way out is. This
    builds a real server-embedded index on a real Atlas cluster, makes an
    expired document rank *first* for a query it is the best answer to, and
    asserts it never reaches the caller.
    """
    direct = MongoClient(atlas_uri, serverSelectionTimeoutMS=15_000)
    database = scratch_name()
    try:
        # `--ensure` is the operator step: it creates the collection, the
        # TTL index, the tenant index and the autoEmbed search index the
        # policy declares. Provisioning is not an application's job.
        wire = boundary(AUTO_POLICY, ensure=True, target=atlas_uri,
                        db=database)

        client = MongoClient(wire.uri, serverSelectionTimeoutMS=20_000)
        try:
            notes = client[database].notes
            notes.insert_many([
                {"_id": "gone", "tenant_id": "acme", "expire_at": past(),
                 "body": "the fault code is P0301, a cylinder 1 misfire"},
                {"_id": "live", "tenant_id": "acme", "expire_at": future(),
                 "body": "the coolant temperature sensor reads high"},
            ])

            # mongot indexes asynchronously. Poll for the *live* document
            # rather than sleeping: a fixed sleep is either flaky or slow,
            # and usually both on somebody else's machine.
            def search(text, limit=5):
                return list(notes.aggregate([{"$vectorSearch": {
                    "index": "engine_vector_index", "path": "body",
                    "query": text, "numCandidates": 50, "limit": limit,
                    "filter": {"tenant_id": "acme"}}}]))

            import time
            until = time.monotonic() + 180
            hits: list = []
            while time.monotonic() < until:
                hits = search("coolant temperature")
                if hits:
                    break
                time.sleep(3)
            assert hits, "the server-embedded index never became queryable"

            # The expired document is the best answer to this question, so
            # it ranks first -- and is refused on the way out anyway.
            served = [d["_id"] for d in search("cylinder misfire fault code")]
            assert "gone" not in served, (
                "an expired document reached a prompt through the search "
                "path, which no pushed-down filter can prevent")
            assert "live" in served

            # And it really was there to be ranked: around the boundary,
            # the same query returns it.
            unguarded = direct[database].notes.aggregate([{"$vectorSearch": {
                "index": "engine_vector_index", "path": "body",
                "query": "cylinder misfire fault code",
                "numCandidates": 50, "limit": 5}}])
            assert "gone" in [d["_id"] for d in unguarded], (
                "the expired document did not rank at all, so this test "
                "would have passed without the boundary doing anything")
        finally:
            client.close()
    finally:
        # The search index is dropped with the database that holds it.
        direct.drop_database(database)
        direct.close()
