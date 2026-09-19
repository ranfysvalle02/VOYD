"""An exhibit: why the deadline belongs under the query engine, not above it.

    docker compose up -d
    uv run python examples/why_this_belongs_in_the_database.py

``examples/forget.py`` shows the feature working. This one shows the feature
being *forgotten*, which is the more interesting claim, because it is the one
that decides where the primitive should live.

The claim under examination
---------------------------
A TTL on a retrieval scope is easy to implement and nearly impossible to
enforce from the application, because **when you forget the deadline on one
read path, nothing fails.** There is no exception, no warning, no slow query,
no elevated error rate. You get an answer. It is well formed, it is
confidently scored, and it is wrong in a way that only the data's owner could
ever notice -- and they are not looking, because they were told the scope
expired.

That is not a hypothetical. VOYD shipped it.

The evidence
------------
VOYD's ``Memory`` trait had this right from the beginning: ``recall()``
re-checks ``live()`` on every hit before returning it. VOYD's *product* path
-- ``get_void``, ``list_voids``, ``vector_search`` -- never did. So for the
roughly sixty seconds between a void's deadline and MongoDB's TTL monitor
collecting it, an expired void was fully alive: void-scoped search returned
its documents, namespace-wide search returned them too, ``GET /v1/voids``
listed it, and ingest would cheerfully add more rows to a scope that was over.

Measured at the time, with the reaper parked so nothing could be credited to
it:

    void-scoped search on the EXPIRED void -> ['deadvoid.md']
    namespace-wide search                  -> ['livevoid.md', 'deadvoid.md']
    list_voids                             -> ['deadvoid', 'livevoid']

Fixed in commit ``00aa928``. Five of the six regression tests written with the
fix fail without it. The sixth -- a void with no deadline at all -- passes
either way on purpose: the same bug inverted would make every *permanent*
void vanish, so it is the control.

What this script does
---------------------
It reconstructs that state from scratch and runs the same query twice: once
the way the code did before the fix (raw ``engine.search``, scoped by tenant,
no deadline clause), and once through ``store.vector_search``, which refuses
expired rows. Then it shows where that rule ended up living.

The TTL monitor is parked at ``ttlMonitorSleepSecs=3600`` for the duration, so
nothing below can be attributed to the reaper, and restored in a ``finally``.
That is a *server-global* parameter, so run this alone: the suite has a reaper
test that parks it too, and concurrently each restores the other's temporary
value -- surfacing as an unrelated test asserting the wrong row count.
Vectors are fake -- no embedding vendor, no API key. Everything runs at the
``MongoStore`` level, so no VOYD server is needed.

This is an argument about layering, not about any vendor. The point is only
this: a deadline enforced by remembering to write a clause is enforced as
reliably as it is remembered, and the number of places to remember it grows
with every read path anyone adds.

Which is why it is no longer written that way. Those six call sites now go
through one ``Admission`` handle with no unfiltered read on it, and the
``_unexpired()`` helper they each had to remember to call is deleted. This
exhibit still reproduces the leak, because the leak is a property of the
database and not of our code -- but the second half now shows a rule that
cannot be forgotten rather than one that merely was not.
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from datetime import timedelta

from bson import ObjectId

from voyd.config import MongoConfig
from voyd.engine.time import now
from voyd.store.mongo import MongoStore

URI = os.getenv("VOYD_MONGO_URI", "mongodb://localhost:27018/?directConnection=true")
DIMS = 8
DB_NAME = "voyd_exhibit_forgotten_deadline"

# Deliberately long enough that nothing here can be explained by the reaper
# happening to run: the whole exhibit lives inside the leak window.
PARKED_TTL_SECS = 3600

# The six read paths in voyd/store/mongo.py that can reach void or document
# data. Each one used to carry the deadline clause itself, by hand; the second
# column is what it goes through now. One object, six callers, nothing to
# remember.
READ_PATHS = (
    ("get_void", "admission_voids.find_one()"),
    ("list_voids", "admission_voids.find()"),
    ("get_document", "admission_documents.find_one()"),
    ("list_documents", "admission_documents.find()"),
    ("count_indexed", "admission_documents.match() inside $match"),
    ("vector_search", "admission_documents.reachable(), doubled fetch budget"),
)

T0 = time.monotonic()


def clock() -> str:
    return f"t+{time.monotonic() - T0:5.1f}s"


def say(msg: str) -> None:
    print(f"  {clock()}  {msg}")


def head(msg: str) -> None:
    print(f"\n  {msg}\n  {'-' * len(msg)}")


def vec(n: float) -> list[float]:
    return [n] * DIMS


def names(hits: list[dict]) -> list[str]:
    return sorted(h.get("name", "?") for h in hits)


async def main() -> int:
    store = MongoStore(MongoConfig(uri=URI, db_name=DB_NAME))
    await store.connect()
    client = store.client

    was = None
    try:
        # Park the reaper BEFORE anything is written. If this fails we stop:
        # an exhibit whose central control is missing would tell a story it
        # cannot support, which is worse than no exhibit.
        try:
            res = await client.admin.command(
                {"setParameter": 1, "ttlMonitorSleepSecs": PARKED_TTL_SECS})
            was = res.get("was", 60)
        except Exception as exc:  # noqa: BLE001 - a managed cluster will refuse
            print(f"note: this server refuses setParameter ({exc}).\n"
                  "      without parking the TTL monitor, an expired document\n"
                  "      disappearing could be the reaper rather than the read\n"
                  "      path, and the exhibit would prove nothing. stopping.")
            return 0

        say(f"TTL monitor parked: ttlMonitorSleepSecs {was} -> {PARKED_TTL_SECS}")
        say("nothing below can be credited to the reaper. for the next hour")
        say("this server does not collect a single expired document.")

        await client.drop_database(DB_NAME)
        await store.ensure_schema(vector_dimensions=DIMS)
        say(f"search tier: {store.search_tier}")

        # ---- two scopes in one collection, one deadline already passed ----
        voyd_id = ObjectId()
        dead_at = now() - timedelta(minutes=5)      # over, and not yet reaped
        live_at = now() + timedelta(hours=6)        # still open

        await store.create_void(voyd_id, "deadvoid", {}, dead_at)
        await store.create_void(voyd_id, "livevoid", {}, live_at)
        await store.add_document(
            voyd_id, "deadvoid", "d1", name="deadvoid.md",
            text="the cylinder 1 misfire was caused by a cracked coil pack",
            expire_at=dead_at)
        await store.add_document(
            voyd_id, "livevoid", "d2", name="livevoid.md",
            text="the cylinder 3 misfire was caused by a fouled plug",
            expire_at=live_at)

        # Embedding is a worker in the real system; here we set the vectors
        # directly so the exhibit needs no vendor and no API key.
        async for doc in store.db.documents.find({}, {"_id": 1}):
            await store.set_embedding(doc["_id"], vec(0.9))

        say("two voids in one collection: 'deadvoid' expired 5 minutes ago,")
        say("'livevoid' expires in 6 hours. one document in each, each")
        say("carrying its void's expire_at.")

        on_disk = await store.db.documents.count_documents({})
        assert on_disk == 2, f"expected 2 document rows on disk, saw {on_disk}"
        say(f"on disk: {on_disk} rows -- including the expired one, because "
            "the reaper is parked")

        # An index that is still building returns zero rows rather than
        # raising, which is indistinguishable from an empty database. Wait for
        # the hit before drawing any conclusion from an absence.
        for _ in range(60):
            warm = await store.engine.search(
                "documents", vec(0.9), limit=10, filters={"voyd_id": voyd_id})
            if len(warm) == 2:
                break
            await asyncio.sleep(0.5)
        else:
            raise SystemExit(
                "nothing became searchable in 30s -- is Atlas Local up? "
                "docker compose up -d")

        # ---- the unguarded query: exactly what VOYD shipped ----------------
        head("1. the query as it was written before commit 00aa928")
        print("     engine.search('documents', vec, "
              "filters={'voyd_id': ..., 'token': 'deadvoid'})")
        print("     tenant-scoped and void-scoped. correct in every respect")
        print("     except one: nothing in it mentions the deadline.\n")

        leaked = await store.engine.search(
            "documents", vec(0.9), limit=10,
            filters={"voyd_id": voyd_id, "token": "deadvoid"})

        say(f"result -> {names(leaked)}")
        assert len(leaked) == 1, (
            "the pre-fix query should return the expired document; it returned "
            f"{names(leaked)}. if this now returns nothing, the exhibit's "
            "premise has changed -- check whether the deadline moved into the "
            "index, and rewrite this script rather than deleting the assert")
        hit = leaked[0]
        assert hit["name"] == "deadvoid.md", f"unexpected hit {hit['name']}"

        exp = hit.get("expire_at")
        say(f"score  -> {hit.get('score')}")
        say(f"expire_at on the returned row -> {exp} (in the past)")
        print()
        print(f"     text returned to the caller:\n       "
              f"{hit['text']!r}")
        print()
        print("     read that back as an operator would see it. it is not an")
        print("     error. it is not a warning. it is not a timeout or a slow")
        print("     query or a degraded tier. It is an ANSWER: one hit, ranked,")
        print("     scored, well formed, indistinguishable from a correct one.")
        print("     The row even carries the evidence against itself -- an")
        print("     expire_at five minutes in the past -- and nobody reads it,")
        print("     because nothing anywhere is wrong enough to page anyone.")
        print()
        print("     A test suite passes. A dashboard is green. The scope the")
        print("     user was told had expired answered a question.")

        # ---- the guarded query: the same search, one clause added ----------
        head("2. the same search through store.vector_search()")
        print("     identical scope, identical vector. the only difference is")
        print("     the Admission handle, refusing on the read path.\n")

        guarded = await store.vector_search(voyd_id, vec(0.9), token="deadvoid")
        say(f"void-scoped on the EXPIRED void -> {names(guarded)}")
        assert guarded == [], (
            f"vector_search leaked an expired document: {names(guarded)}")

        alive = await store.vector_search(voyd_id, vec(0.9), token="livevoid")
        say(f"void-scoped on the LIVE void    -> {names(alive)}")
        assert names(alive) == ["livevoid.md"], (
            f"the live void must still answer; got {names(alive)}")

        # The namespace-wide path is the one that made this a cross-scope leak
        # rather than a single bad route: no token, so get_void never gated it.
        wide = await store.vector_search(voyd_id, vec(0.9))
        say(f"namespace-wide (no token)       -> {names(wide)}")
        assert names(wide) == ["livevoid.md"], (
            f"namespace-wide search leaked past a deadline: {names(wide)}")

        # And the control: the expired row is still physically present. What
        # changed is the read path, not the storage.
        still_there = await store.db.documents.count_documents({})
        assert still_there == 2, (
            "the expired row should still be on disk -- if it is gone, "
            "something collected it and the comparison above is not clean")
        say(f"on disk: {still_there} rows -- unchanged. the document did not "
            "move;")
        say("the query did.")

        # ---- what remembering it costs ------------------------------------
        head("3. the cost of getting this right, enumerated")
        print("     every read path in voyd/store/mongo.py that can reach void")
        print("     or document data has to carry the deadline itself:\n")
        for fn, how in READ_PATHS:
            print(f"       {fn:<16} {how}")
        print()
        assert len(READ_PATHS) == 6, "the enumeration below says six"

        # Guard the enumeration against drift: if someone adds a read path and
        # does not add it here, the exhibit's closing number is stale.
        for fn, _ in READ_PATHS:
            assert hasattr(store, fn), (
                f"MongoStore has no {fn}() -- the read-path enumeration in "
                "this exhibit is out of date")

        print("     Six call sites. One small codebase. Written by the person")
        print("     who wrote the thesis, in a repository whose entire premise")
        print("     is that the deadline must hold. One of them was missed, and")
        print("     the miss survived a full rewrite of the project -- because")
        print("     a missed deadline clause does not look like a bug. It looks")
        print("     like a result.")
        print()
        print("     Nothing here argues the application layer is careless. The")
        print("     argument is narrower and harder to dismiss: correctness by")
        print("     universal recall does not survive contact with a growing")
        print("     codebase, and this particular failure is silent, so the")
        print("     usual feedback loop that catches drift never fires.")
        print()
        print("     A platform that owned the deadline -- that made an expired")
        print("     scope unreadable at the layer below every query, the way an")
        print("     unauthorised read is unreadable -- would not make this")
        print("     mistake cheaper to avoid. It would make it unavailable.")

        # ---- what we measured, and where VOYD therefore puts the check ----
        head("4. where the check could go, measured today against Atlas Local")
        print("     These are measurements from this machine against Atlas")
        print("     Local, not claims about any product's roadmap:\n")
        print("     - living() works verbatim as a $vectorSearch filter.")
        print("       $exists and $or are both supported there, and it returns")
        print("       exactly the null / absent / future set. (An earlier commit")
        print("       message in this repo said otherwise; it was wrong.)")
        print()
        print("     - The lexical leg can express the same rule with range +")
        print("       equals: null + mustNot: exists. Placed in compound.filter")
        print("       it leaves relevance scores byte-identical to the query")
        print("       without it. Placed in compound.must, a document's score")
        print("       changes according to HOW it satisfied the deadline: rows")
        print("       matching via range or equals: null gained a full point,")
        print("       while a row with no expire_at field at all -- satisfying")
        print("       the rule via mustNot: exists -- kept its original score.")
        print("       That reorders results by a field with nothing to do with")
        print("       relevance.")
        print()
        print("     - A 'search' index definition can be updated in place. A")
        print("       'vectorSearch' index definition cannot:")
        print("       update_search_index validates the new definition as a")
        print("       lexical one and fails with '\"mappings\" is required'.")
        print("       So pushing the deadline into the vector index is not an")
        print("       edit; it is a drop and rebuild on every deployment that")
        print("       already has the old definition.")
        print()
        print("     So VOYD enforces the deadline in the read path. Not because")
        print("     the index cannot express it, but because the read path is")
        print("     the layer that cannot drift out from under the code, and it")
        print("     stays correct on the in-process cosine fallback, where there")
        print("     is no index to push anything into.")
        print()
        print("     And it is no longer six places to remember: those six read")
        print("     paths go through one handle with no unfiltered find on it,")
        print("     so the naive read and the safe read are the same read.")

        print(f"\n  {clock()}  exhibit holds. every assertion above passed.")
        return 0

    finally:
        try:
            await client.drop_database(DB_NAME)
        except Exception:  # noqa: BLE001 - cleanup is best effort
            pass
        if was is not None:
            try:
                await client.admin.command(
                    {"setParameter": 1, "ttlMonitorSleepSecs": was})
                print(f"  {clock()}  TTL monitor restored to {was}s")
            except Exception as exc:  # noqa: BLE001
                print(f"  WARNING: could not restore ttlMonitorSleepSecs to "
                      f"{was} ({exc}). this server's reaper is still parked.")
        await store.close()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
