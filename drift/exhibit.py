"""The four owners, drifting. The README's table, executed.

    docker compose up -d --wait mongo
    docker compose -f drift/docker-compose.drift.yml up -d --wait
    uv run --extra drift python drift/exhibit.py

The claim this file exists to test is the load-bearing one:

    "Four owners, four clocks, four ways to drift -- and the drift *is* the
    bug. The vector outlives the document. The bytes outlive the row."

That is an architecture argument, and until now it was prose. Here it is as
two runs of the same scenario against real services:

  Act I  -- Postgres owns the row, Qdrant owns the vector, MinIO owns the
            bytes, and a cron job is supposed to keep them agreeing. One
            document is ingested into all three with a deadline, the deadline
            passes, the cron does what a cron does, and we ask the retrieval
            system a question.

  Act II -- The same document, the same deadline, in VOYD.

Two rules, because an exhibit that cheats proves nothing:

1. **Every system gets its real mechanism.** Postgres gets a DELETE (it has
   no TTL; a cron is genuinely how this is done). S3 gets a real lifecycle
   rule, applied through the real API, and we report exactly what it promises.
   Qdrant gets its real delete API. Nothing is stubbed and nothing is
   sabotaged.

2. **Every claim is checked, not narrated.** Each step asserts the state it
   describes. If a future version of any of these services fixes the problem,
   this file fails, and that is the correct outcome -- the argument should be
   falsifiable.

What this is NOT: a benchmark, or a claim that these are bad systems. Qdrant
is a good vector database. The point is narrower and harder to dodge: the
*deadline* has four owners, so keeping them agreeing is an application's job,
and an application that forgets has no way to find out.
"""

from __future__ import annotations

import asyncio
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone

PG = "postgresql://drift:drift@localhost:55432/drift"
QDRANT = "http://localhost:56333"
S3_ENDPOINT = "http://localhost:59000"
S3_KEY, S3_SECRET = "driftkey", "driftsecret"
MONGO = "mongodb://localhost:27018/?directConnection=true"

DIMS = 8
TTL_SECONDS = 5
SECRET = "the 2019 acquisition fell through because of the pension liability"

failures: list[str] = []


def vec(seed: int) -> list[float]:
    rng = random.Random(seed)
    return [rng.random() for _ in range(DIMS)]


def now() -> datetime:
    return datetime.now(timezone.utc)


def check(label: str, condition: bool, detail: str = "") -> bool:
    """Assert, but keep going: one exhibit should report every finding."""
    mark = "ok  " if condition else "FAIL"
    print(f"    [{mark}] {label}" + (f" -- {detail}" if detail else ""))
    if not condition:
        failures.append(label)
    return condition


def banner(text: str) -> None:
    print(f"\n{'=' * 72}\n{text}\n{'=' * 72}")


# ---- Act I: four owners -------------------------------------------------

async def act_one() -> None:
    import asyncpg
    from qdrant_client import AsyncQdrantClient
    from qdrant_client.models import Distance, PointStruct, VectorParams

    banner("ACT I -- Postgres + Qdrant + S3 + a cron job")

    run = uuid.uuid4().hex[:8]
    table = f"documents_{run}"
    collection = f"vectors_{run}"
    bucket = f"drift-{run}"
    doc_id = 1

    pg = await asyncpg.connect(PG)
    qd = AsyncQdrantClient(url=QDRANT)

    import aioboto3
    session = aioboto3.Session(aws_access_key_id=S3_KEY,
                               aws_secret_access_key=S3_SECRET,
                               region_name="us-east-1")

    async with session.client("s3", endpoint_url=S3_ENDPOINT) as s3:
        try:
            # ---- ingest, into all three -------------------------------
            print("\n  1. Ingest one document. Three writes, because three "
                  "systems own\n     three pieces of it.")

            await pg.execute(f"""
                CREATE TABLE {table} (
                    id         integer PRIMARY KEY,
                    text       text NOT NULL,
                    expire_at  timestamptz
                )""")
            deadline = now() + timedelta(seconds=TTL_SECONDS)
            await pg.execute(
                f"INSERT INTO {table} (id, text, expire_at) VALUES ($1, $2, $3)",
                doc_id, SECRET, deadline)

            await qd.create_collection(
                collection_name=collection,
                vectors_config=VectorParams(size=DIMS, distance=Distance.COSINE))
            await qd.upsert(collection_name=collection, points=[
                PointStruct(id=doc_id, vector=vec(1),
                            payload={"text": SECRET, "pg_id": doc_id})])

            await s3.create_bucket(Bucket=bucket)
            await s3.put_object(Bucket=bucket, Key=f"{doc_id}/source.txt",
                                Body=SECRET.encode())

            check("the row is in Postgres",
                  await pg.fetchval(f"SELECT count(*) FROM {table}") == 1)
            check("the vector is in Qdrant",
                  (await qd.count(collection_name=collection)).count == 1)
            check("the bytes are in S3",
                  "Contents" in await s3.list_objects_v2(Bucket=bucket))
            print(f"\n     deadline: {deadline.isoformat()} "
                  f"(in {TTL_SECONDS}s)")

            # ---- register the deadline everywhere it can be registered --
            print("\n  2. Register the deadline with every owner that will "
                  "take one.")

            # S3 takes a real lifecycle rule, applied through the real API.
            # Its granularity is the finding: days, not seconds.
            await s3.put_bucket_lifecycle_configuration(
                Bucket=bucket,
                LifecycleConfiguration={"Rules": [{
                    "ID": "expire-sources",
                    "Filter": {"Prefix": f"{doc_id}/"},
                    "Status": "Enabled",
                    "Expiration": {"Days": 1},
                }]})
            rules = await s3.get_bucket_lifecycle_configuration(Bucket=bucket)
            days = rules["Rules"][0]["Expiration"]["Days"]
            check("the S3 lifecycle rule is real and applied", days == 1,
                  f"but its granularity is {days} day(s) -- the deadline "
                  f"is {TTL_SECONDS}s")

            # Postgres and Qdrant have nowhere to put a deadline. Rather than
            # assert that, the next step measures it: let the deadline pass
            # and ask both of them, before any cleanup runs.
            print("     Postgres and Qdrant have no deadline field to "
                  "register it with,\n     so the next step measures what "
                  "they do on their own.")

            # ---- the deadline passes, and nothing happens -------------
            print(f"\n  3. Wait {TTL_SECONDS}s for the deadline to pass, then "
                  f"ask each owner\n     *before* any cleanup runs.")
            await asyncio.sleep(TTL_SECONDS + 1)

            still_there = await pg.fetchval(
                f"SELECT count(*) FROM {table} WHERE expire_at < now()")
            check("Postgres still holds the expired row", still_there == 1,
                  "it has no TTL: the deadline is a column, not a policy")

            qd_after = (await qd.count(collection_name=collection)).count
            check("Qdrant still holds the vector", qd_after == 1,
                  "nothing in a vector database expires a point")

            print("\n  4. So the cron runs. It deletes expired rows, which is "
                  "exactly\n     what it was written to do -- and all it was "
                  "written to do.")
            deleted = await pg.execute(
                f"DELETE FROM {table} WHERE expire_at < now()")
            check("the cron deleted the expired row", deleted == "DELETE 1",
                  "Postgres is now correct")
            check("the document is gone from the system of record",
                  await pg.fetchval(f"SELECT count(*) FROM {table}") == 0)

            # ---- the question ----------------------------------------
            print("\n  5. Now ask the retrieval system a question. This is "
                  "the call an\n     agent makes -- it queries the vector "
                  "index, not Postgres.")

            hits = await qd.query_points(collection_name=collection,
                                         query=vec(1), limit=3)
            points = hits.points
            leaked = [p for p in points if p.payload.get("text") == SECRET]

            if leaked:
                p = leaked[0]
                print(f"\n     -> returned {len(points)} hit(s). Top hit:")
                print(f"        score   {p.score:.4f}")
                print(f"        text    {p.payload['text']!r}")
                print(f"        pg_id   {p.payload.get('pg_id')} "
                      f"<- this row no longer exists")
            check("THE DELETED DOCUMENT ANSWERED THE QUERY", bool(leaked),
                  "a confident, scored, well-formed hit from a deleted document")

            body = await s3.get_object(Bucket=bucket, Key=f"{doc_id}/source.txt")
            served = (await body["Body"].read()).decode()
            check("and S3 still serves the bytes", served == SECRET,
                  "the lifecycle rule cannot fire for ~a day")

            print("\n     Nothing above is broken. Postgres did its job. The "
                  "cron did its\n     job. The lifecycle rule is valid. Qdrant "
                  "stored what it was given.\n     Every component is correct "
                  "and the system is wrong, which is why\n     nothing paged "
                  "anyone.")

            # ---- what the fix would have to be ------------------------
            print("\n  6. What would it take to fix this *here*?")
            print("     Delete the vector too -- the reconciliation nobody "
                  "wrote:")
            await qd.delete(collection_name=collection,
                            points_selector=[doc_id])
            after = (await qd.count(collection_name=collection)).count
            check("a second delete, to a second system, fixes it", after == 0,
                  "one more call, in one more place, that must never be "
                  "forgotten or fail")
            print("\n     That call is the whole problem: it is application "
                  "code, it is not\n     transactional with the first delete, "
                  "and if it fails or is skipped\n     the only symptom is an "
                  "answer that should not exist.")

        finally:
            try:
                await pg.execute(f"DROP TABLE IF EXISTS {table}")
            finally:
                await pg.close()
            try:
                await qd.delete_collection(collection_name=collection)
            except Exception:
                pass
            await qd.close()
            try:
                objs = await s3.list_objects_v2(Bucket=bucket)
                for o in objs.get("Contents", []):
                    await s3.delete_object(Bucket=bucket, Key=o["Key"])
                await s3.delete_bucket(Bucket=bucket)
            except Exception:
                pass


# ---- Act II: one owner --------------------------------------------------

async def act_two() -> None:
    from pymongo import AsyncMongoClient

    from voyd.engine import Engine

    banner("ACT II -- the same document, the same deadline, in VOYD")

    client = AsyncMongoClient(MONGO)
    name = f"core_drift_{uuid.uuid4().hex[:8]}"
    engine = Engine(client, client[name])
    await engine.connect()

    try:
        mem = engine.model("memories", tenant="scope").memory()
        await engine.ensure(search_wait_s=0)

        print("\n  1. Ingest. One write, because one document owns both the "
              "text and\n     the vector, and one field owns the deadline.")
        await mem.remember("agent-1", SECRET, vec(1),
                           ttl=timedelta(seconds=TTL_SECONDS))

        hits = await mem.recall("agent-1", vec(1))
        check("it is recallable before the deadline",
              any(h["text"] == SECRET for h in hits))

        print(f"\n  2. Wait {TTL_SECONDS}s. Nothing is scheduled. No cron is "
              f"registered.")
        await asyncio.sleep(TTL_SECONDS + 1)

        print("\n  3. Ask the same question.")
        hits = await mem.recall("agent-1", vec(1))
        check("the expired memory does NOT answer",
              not any(h["text"] == SECRET for h in hits),
              "refused on read, before the reaper has run")

        on_disk = await engine.db.memories.count_documents({"text": SECRET})
        check("and its row is still on disk", on_disk == 1,
              "this is the window every other system serves from")

        print("\n     That is the whole difference. The row is *still there* "
              "-- the TTL\n     monitor has not swept yet -- and it already "
              "cannot reach a prompt,\n     because the read path owns the "
              "same deadline the reaper does.")
        print("\n  4. There is no second delete to forget. The row and its "
              "embedding\n     are one document, so the reaper takes them "
              "together, and the\n     change stream on that delete is what "
              "reclaims any bytes.")
        print("\n     delete calls issued by this program: 0")

    finally:
        await client.drop_database(name)
        await client.close()


async def main() -> int:
    print(__doc__.split("\n\n")[0])
    try:
        await act_one()
        await act_two()
    except Exception as exc:
        print(f"\n!! exhibit could not complete: {type(exc).__name__}: {exc}")
        print("   Are both stacks up?")
        print("     docker compose up -d --wait mongo")
        print("     docker compose -f drift/docker-compose.drift.yml up -d --wait")
        return 2

    banner("VERDICT")
    if failures:
        print(f"{len(failures)} check(s) failed:")
        for f in failures:
            print(f"  - {f}")
        print("\nIf the failing check is 'THE DELETED DOCUMENT ANSWERED THE "
              "QUERY',\nthen one of these services has changed and the "
              "README's table needs\nupdating. That is a good outcome for an "
              "argument to have.")
        return 1

    print("Four owners: the row was deleted, and the vector answered anyway.")
    print("One owner:   the deadline was enforced before the row was even "
          "swept.")
    print("\nThe difference is not a feature. It is where the deadline lives.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
