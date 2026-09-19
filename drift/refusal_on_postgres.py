"""Refusal is a pattern, not a MongoDB feature. Here it is on Postgres.

    docker compose -f drift/docker-compose.drift.yml up -d --wait drift-postgres
    uv run --extra drift python drift/refusal_on_postgres.py

`exhibit.py` next door argues that four owners of one deadline is the bug.
This file argues the *other* half of the thesis, and it argues it against
VOYD's own framing -- because "you should use MongoDB" and "retrieval is
missing a guarantee" are different claims, and only the second one is
interesting. If the first is all this is, a reader is right to dismiss it.

So: pgvector, one table, no MongoDB anywhere in this file. Everything VOYD
claims is structural is reproduced in SQL, and the two places where it is
genuinely *harder* are measured rather than skipped.

Four acts:

  I    The bug, on Postgres. A row past its deadline, a cleanup job that has
       not run yet -- which is the normal state of a cleanup job -- and a
       vector query that answers with it. Same failure, different vendor.

  II   Refusal, on Postgres. The deadline in the read path, so the same
       query cannot return it, whatever the cleanup job is doing.

  III  The structural part, and the part people skip. A filtered query is a
       convention: it holds until somebody writes a second query. So the
       table is revoked and a *view* is the only thing granted -- the
       database itself refuses to serve the unfiltered rows, to that role,
       at all. That is Postgres's version of "there is no unfiltered read on
       the handle", and it is enforced by the engine rather than by review.

  IV   Inherited refusal. Erase a source and the summary written out of it
       goes too, transitively, via a recursive CTE.

And then, honestly, **what is harder here**, because an argument that only
lists its wins is marketing:

  - Postgres has no TTL. There is no equivalent of handing the deadline to
    the storage engine; `pg_cron` or an external job is the answer, which
    means the deadline has two owners again the moment you need the rows
    actually gone. VOYD's one-owner claim is genuinely stronger on MongoDB,
    and that is a property of the engine, not of the argument.
  - The view trick costs a role and a grant. It is real enforcement, and it
    is also the kind of thing that survives exactly as long as nobody runs
    the app as the owning role.

What carries over completely: refusal belongs in the read path, the unsafe
read must be *named* rather than available by default, and a refusal has to
travel to what was made out of the fact. None of those is a MongoDB feature.
"""

from __future__ import annotations

import asyncio
import random
import sys
from datetime import datetime, timedelta, timezone

PG = "postgresql://drift:drift@localhost:55432/drift"
DIMS = 8
SECRET = "the 2019 acquisition fell through because of the pension liability"
KEPT = "the fault code is P0301"

failures: list[str] = []


def check(ok: bool, label: str) -> None:
    print(f"    [{'ok  ' if ok else 'FAIL'}] {label}")
    if not ok:
        failures.append(label)


def vec(seed: int) -> str:
    rng = random.Random(seed)
    return "[" + ",".join(f"{rng.random():.6f}" for _ in range(DIMS)) + "]"


def now() -> datetime:
    return datetime.now(timezone.utc)


async def setup(conn) -> None:
    """Idempotent teardown first, so a re-run is never a different run.

    ``DROP OWNED BY`` is the only way to shed a role's grants, and it
    raises rather than no-ops when the role is absent -- which is the
    normal state of the first run.
    """
    if await conn.fetchval(
            "SELECT 1 FROM pg_roles WHERE rolname = 'voyd_reader'"):
        await conn.execute("DROP OWNED BY voyd_reader CASCADE")
        await conn.execute("DROP ROLE voyd_reader")
    await conn.execute("DROP TABLE IF EXISTS facts CASCADE")
    await conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
    await conn.execute(f"""
        CREATE TABLE facts (
            id          bigserial PRIMARY KEY,
            text        text NOT NULL,
            embedding   vector({DIMS}) NOT NULL,
            expire_at   timestamptz,
            forgotten   jsonb,
            lineage     bigint[] NOT NULL DEFAULT '{{}}'
        )""")
    await conn.execute("CREATE INDEX ON facts USING gin (lineage)")


# ---- Act I: the same bug, different vendor ----------------------------

async def act_one(conn) -> int:
    print("\n  ACT I -- the bug, on Postgres. No MongoDB in this file.\n")
    secret_id = await conn.fetchval(
        "INSERT INTO facts (text, embedding, expire_at) "
        "VALUES ($1, $2, $3) RETURNING id",
        SECRET, vec(1), now() - timedelta(seconds=1))
    await conn.execute(
        "INSERT INTO facts (text, embedding, expire_at) VALUES ($1, $2, NULL)",
        KEPT, vec(2))

    print("  1. One fact past its deadline, one pinned. The cleanup job has")
    print("     not run yet -- which is the normal state of a cleanup job.")
    print("     Postgres has no TTL, so 'not yet' can mean any length of time.\n")

    rows = await conn.fetch(
        "SELECT text FROM facts ORDER BY embedding <=> $1 LIMIT 5", vec(1))
    hits = [r["text"] for r in rows]
    print("  2. The query an agent writes. Vector similarity, nothing else:")
    print("       SELECT text FROM facts ORDER BY embedding <=> $1 LIMIT 5")
    print(f"     -> {hits[0]!r}")
    check(SECRET in hits, "THE EXPIRED FACT ANSWERED THE QUERY, scored and "
                          "well-formed, with nothing logged")
    check(await conn.fetchval("SELECT count(*) FROM facts") == 2,
          "and its row is still on disk, because nothing deleted it")
    return secret_id


# ---- Act II: refusal in the read path ---------------------------------

LIVE = """(expire_at IS NULL OR expire_at > now())
          AND forgotten IS NULL"""


async def act_two(conn) -> None:
    print("\n  ACT II -- refusal, in the read path. Same table, same index.\n")
    rows = await conn.fetch(
        f"SELECT text FROM facts WHERE {LIVE} "
        f"ORDER BY embedding <=> $1 LIMIT 5", vec(1))
    hits = [r["text"] for r in rows]
    print("       SELECT ... WHERE (expire_at IS NULL OR expire_at > now())")
    print("                    AND forgotten IS NULL")
    print(f"     -> {hits}")
    check(SECRET not in hits, "the expired fact is refused on read, with no "
                              "cleanup job involved")
    check(await conn.fetchval("SELECT count(*) FROM facts") == 2,
          "and the row is still there -- unreachable first, erased second")

    print("\n     Which is the easy half, and the half everybody already")
    print("     knows. It is also a *convention*: it holds until the next")
    print("     author writes the second query.")


# ---- Act III: make it structural, not conventional --------------------

async def act_three(conn) -> None:
    print("\n  ACT III -- the structural part. A convention is not a")
    print("             guarantee, so take the unfiltered read away.\n")
    await conn.execute(f"""
        CREATE VIEW facts_admitted AS
        SELECT id, text, embedding, expire_at, lineage FROM facts
        WHERE {LIVE}""")
    await conn.execute("CREATE ROLE voyd_reader NOLOGIN")
    await conn.execute("GRANT SELECT ON facts_admitted TO voyd_reader")
    # Deliberately no grant on `facts` itself. The unfiltered read is not
    # discouraged, not linted, not code-reviewed -- it is not available.
    print("       CREATE VIEW facts_admitted AS SELECT ... WHERE <live>")
    print("       GRANT SELECT ON facts_admitted TO voyd_reader")
    print("       -- and no GRANT on `facts`. That is the whole trick.\n")

    await conn.execute("SET ROLE voyd_reader")
    try:
        rows = await conn.fetch(
            "SELECT text FROM facts_admitted ORDER BY embedding <=> $1 LIMIT 5",
            vec(1))
        check(SECRET not in [r["text"] for r in rows],
              "the granted read cannot return an expired fact")

        leaked = None
        try:
            leaked = await conn.fetch("SELECT text FROM facts LIMIT 5")
        except Exception as exc:  # noqa: BLE001 - the refusal is the result
            print(f"     the naive read raises: {type(exc).__name__}: "
                  f"{str(exc).splitlines()[0]}")
        check(leaked is None,
              "a read path written by somebody who never heard of the "
              "deadline cannot compile, let alone leak")
    finally:
        await conn.execute("RESET ROLE")

    print("\n     That is Postgres's version of 'there is no unfiltered read")
    print("     on the handle'. Different mechanism, identical property: the")
    print("     failure mode is inverted, and seeing everything has to be")
    print("     asked for by a role that can.")


# ---- Act IV: a refusal travels --------------------------------------

async def act_four(conn, secret_id: int) -> None:
    print("\n  ACT IV -- inherited refusal. Erase a fact, and the paragraph")
    print("            an agent wrote out of it goes too.\n")
    summary_id = await conn.fetchval(
        "INSERT INTO facts (text, embedding, lineage) "
        "VALUES ($1, $2, $3) RETURNING id",
        "summary: the pension liability killed the 2019 deal", vec(1),
        [secret_id])
    await conn.execute(
        "INSERT INTO facts (text, embedding, lineage) VALUES ($1, $2, $3)",
        "board briefing, drawn from the summary", vec(1),
        [secret_id, summary_id])

    print("  1. A summary of the fact, and a briefing drawn from the summary.")
    print("     Each stores the transitive closure of what it came from, so")
    print("     the walk below is one query at any depth.\n")

    marked = await conn.fetchval("""
        WITH RECURSIVE tainted AS (
            SELECT id FROM facts WHERE id = $1
            UNION
            SELECT f.id FROM facts f JOIN tainted t ON t.id = ANY(f.lineage)
        )
        UPDATE facts SET forgotten = jsonb_build_object(
                             'at', now(), 'reason', $2::text),
                         expire_at = LEAST(COALESCE(expire_at, now()), now())
        WHERE id IN (SELECT id FROM tainted)
        RETURNING 1""", secret_id, "subject erasure request")
    n = await conn.fetchval(
        "SELECT count(*) FROM facts WHERE forgotten IS NOT NULL")
    print("  2. One recursive CTE erases the source and everything downstream:")
    print(f"     -> {n} row(s) now carry the mark (source + summary + briefing)")

    await conn.execute("SET ROLE voyd_reader")
    try:
        rows = await conn.fetch("SELECT text FROM facts_admitted")
        texts = [r["text"] for r in rows]
    finally:
        await conn.execute("RESET ROLE")

    check(n == 3 and marked is not None,
          "the source, its summary and the summary's summary all went")
    check(not any("pension liability" in t for t in texts),
          "and nothing downstream of the erased fact can reach a prompt")
    check(texts == [KEPT], "while the unrelated fact is untouched")
    check(await conn.fetchval("SELECT count(*) FROM facts") == 4,
          "every row is still on disk -- this erased reachability, not bytes")


# ---- what is harder here ---------------------------------------------

def epilogue() -> None:
    print("""
  WHAT IS HARDER HERE, stated because an argument that lists only its wins
  is marketing:

  * Postgres has no TTL. There is no handing the deadline to the storage
    engine -- pg_cron or an external job is the answer, so the moment you
    need the rows actually *gone* the deadline has two owners again, and
    keeping them agreeing is back to being your problem. VOYD's one-owner
    claim really is stronger on MongoDB. That is a property of the engine,
    not of the argument, and conflating the two is what makes this sound
    like advocacy.

  * The view costs a role and a grant, and it holds exactly as long as
    nobody runs the application as the owning role. MongoDB's version --
    a handle object with no unfiltered method on it -- is weaker against a
    determined caller and stronger against an ordinary Tuesday.

  WHAT CARRIES OVER COMPLETELY, which is the point of this file:

  * Deletion is a storage event; refusal is a retrieval guarantee. True of
    every database, including the two in this directory.
  * A rule you have to remember to apply is not enforced. The fix is to
    make the unfiltered read unavailable and give the safe one the short
    name -- a view and a grant here, a handle there.
  * A refusal that does not travel to what was made out of the fact is
    defeated by a summary. Recursive CTE here, one indexed $in there.

  Refusal is missing from retrieval everywhere. VOYD is one implementation
  of it, on the engine where the deadline can have a single owner.
""")


async def main() -> int:
    try:
        import asyncpg
    except ImportError:
        print("needs the drift extra:  uv sync --extra drift")
        return 2
    try:
        conn = await asyncpg.connect(PG)
    except Exception as exc:  # noqa: BLE001 - a missing service is not a bug
        print(f"no Postgres at {PG}: {exc}\n"
              f"  docker compose -f drift/docker-compose.drift.yml "
              f"up -d --wait drift-postgres")
        return 2

    print("\n  refusal, ported off MongoDB -- pgvector, one table, no Mongo")
    try:
        await setup(conn)
        secret_id = await act_one(conn)
        await act_two(conn)
        await act_three(conn)
        await act_four(conn, secret_id)
        epilogue()
    finally:
        await conn.close()

    if failures:
        print(f"  {len(failures)} claim(s) did not hold:")
        for f in failures:
            print(f"    - {f}")
        return 1
    print("  every claim in this file held on pgvector.\n")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
