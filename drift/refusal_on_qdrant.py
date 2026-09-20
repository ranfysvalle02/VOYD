"""Is refusal *enforceable* on a rowless engine, or only *conventional*?

    docker compose -f drift/docker-compose.drift.yml up -d --wait drift-qdrant
    uv run --extra drift python drift/refusal_on_qdrant.py   # 0 = every claim held

`refusal_on_postgres.py` next door ported the whole thesis to pgvector and, in
its third act, reached the strongest version of the guarantee: revoke the
table, grant only a view, and the naive read *raises* `permission denied`. The
database itself refuses to serve the unfiltered rows. That is refusal as a
property of the engine, not of the caller's memory.

This file asks whether that third act is even possible on a vector database
with no rows -- Qdrant -- because [`ideas.md`](README.md) pre-registered it as
the more interesting target: "Qdrant has no rows at all: refusal has to live
in the payload filter, and whether that is *enforceable* or merely
*conventional* is a genuinely open question. If it turns out to be
conventional, that is a finding worth publishing on its own."

It is a finding, not an adapter. Four acts, each measured against the real
service on the stock image, and then -- because an argument that only lists
its wins is marketing -- exactly what is harder here.

  I    The bug. A point past its deadline, cleanup not yet run, the search
       answers with it. Same failure, different engine.

  II   Refusal in the read path. The deadline as a payload filter, so the
       same query cannot return it. This works, cleanly.

  III  The crux, and the finding. Postgres could make the *unfiltered* read
       fail. Qdrant, on the stock image, cannot: there is no row, no view, no
       GRANT, and no collection-level default filter. The filter is a
       convention -- it holds until the next caller omits it, and then the
       expired point is served with a confident score. We do not assert that;
       we issue the unfiltered query a second time and watch it leak.

  IV   Inherited refusal. Postgres walked the derivation edge with a recursive
       CTE, in the database. Qdrant has no such thing: forgetting a source
       does not reach the summary written out of it unless the application
       walks the lineage in the payload and rewrites each descendant itself.

The honest one-line result is printed in the verdict, and the process exits
non-zero if any measured claim fails -- including, pointedly, if a future
Qdrant closes the gap and the unfiltered read stops leaking. That would be a
good outcome for an argument to have.
"""

from __future__ import annotations

import asyncio
import random
import sys
import time

QDRANT = "http://localhost:56333"
DIMS = 8
SECRET = "the 2019 acquisition fell through because of the pension liability"
KEPT = "the fault code is P0301"

failures: list[str] = []


def check(ok: bool, label: str) -> None:
    print(f"    [{'ok  ' if ok else 'FAIL'}] {label}")
    if not ok:
        failures.append(label)


def vec(seed: int) -> list[float]:
    rng = random.Random(seed)
    return [rng.random() for _ in range(DIMS)]


def _texts(response) -> set[str]:
    return {p.payload.get("text") for p in response.points}


async def run() -> None:
    from qdrant_client import AsyncQdrantClient
    from qdrant_client.models import (Distance, FieldCondition, Filter,
                                      IsEmptyCondition, MatchValue,
                                      PayloadField, PointStruct, Range,
                                      VectorParams)

    qd = AsyncQdrantClient(url=QDRANT)
    collection = f"refusal_{int(time.time())}"

    # "Living" as a payload filter: the deadline is in the future, OR there is
    # no deadline at all (a pinned point). Qdrant's Range is numeric, so the
    # deadline is stored as an epoch, and the absent case is IsEmpty. This is
    # the exact equivalent of the collection query VOYD pushes down -- and,
    # crucially, it is *all* the enforcement Qdrant offers.
    def living(now: float) -> Filter:
        return Filter(should=[
            FieldCondition(key="expire_at", range=Range(gt=now)),
            IsEmptyCondition(is_empty=PayloadField(key="expire_at")),
        ])

    try:
        await qd.create_collection(
            collection_name=collection,
            vectors_config=VectorParams(size=DIMS, distance=Distance.COSINE))

        # ---- Act I: the bug ------------------------------------------------
        print("\n  I. The bug: an expired point, cleanup not yet run.")
        now = time.time()
        await qd.upsert(collection_name=collection, points=[
            PointStruct(id=1, vector=vec(1),
                        payload={"text": SECRET, "expire_at": now - 100}),
            PointStruct(id=2, vector=vec(1),
                        payload={"text": KEPT}),          # pinned: no deadline
        ])
        naive = await qd.query_points(collection_name=collection,
                                      query=vec(1), limit=5)
        check(SECRET in _texts(naive),
              "the expired point answers the naive query (the bug)")

        # ---- Act II: refusal in the read path ------------------------------
        print("\n  II. Refusal in the read path: the deadline as a filter.")
        refused = await qd.query_points(collection_name=collection,
                                        query=vec(1), limit=5,
                                        query_filter=living(time.time()))
        check(SECRET not in _texts(refused),
              "the same query with the living() filter does not return it")
        check(KEPT in _texts(refused),
              "and the pinned point still comes back")

        # ---- Act III: the crux, and the finding ----------------------------
        print("\n  III. The finding. Postgres could make the *unfiltered* read")
        print("       raise. Here there is no row, no view, no GRANT to hang")
        print("       that on -- so the next caller who omits the filter is")
        print("       served the expired point again.")
        second_caller = await qd.query_points(collection_name=collection,
                                               query=vec(1), limit=5)
        check(SECRET in _texts(second_caller),
              "the unfiltered read STILL leaks -- refusal here is CONVENTIONAL, "
              "not enforced by the engine")
        print("       (The closest mechanism, JWT payload claims, needs the")
        print("        server booted with an api_key and RBAC and a token")
        print("        minted per caller -- a per-token filter the issuer must")
        print("        still remember, not a collection-level default. Off on")
        print("        the stock image, which is what this measures.)")

        # ---- Act IV: inherited refusal -------------------------------------
        print("\n  IV. Inherited refusal: no recursive CTE, so it costs an")
        print("      application-side walk of the lineage.")
        base = time.time()
        await qd.upsert(collection_name=collection, points=[
            PointStruct(id=10, vector=vec(2),
                        payload={"text": SECRET, "expire_at": base + 3600}),
            PointStruct(id=11, vector=vec(2),
                        payload={"text": f"summary: {SECRET}",
                                 "expire_at": base + 3600, "lineage": [10]}),
        ])
        # Forget the source: move its deadline into the past.
        await qd.set_payload(collection_name=collection,
                             payload={"expire_at": base - 100}, points=[10])
        after_source = await qd.query_points(
            collection_name=collection, query=vec(2), limit=5,
            query_filter=living(time.time()))
        summary_present = any(p.payload.get("lineage") == [10]
                              for p in after_source.points)
        check(summary_present,
              "forgetting the source did NOT reach the summary written from it")

        # The only way to reach it: the application finds descendants by payload
        # and rewrites each one's deadline. No engine did this for us.
        descendants = await qd.query_points(
            collection_name=collection, query=vec(2), limit=50,
            query_filter=Filter(must=[FieldCondition(
                key="lineage", match=MatchValue(value=10))]))
        ids = [p.id for p in descendants.points]
        if ids:
            await qd.set_payload(collection_name=collection,
                                 payload={"expire_at": base - 100}, points=ids)
        swept = await qd.query_points(
            collection_name=collection, query=vec(2), limit=5,
            query_filter=living(time.time()))
        check(not any(p.payload.get("lineage") == [10] for p in swept.points),
              "only an explicit application-side walk of the payload reached it")

    finally:
        try:
            await qd.delete_collection(collection_name=collection)
        except Exception:
            pass
        await qd.close()


def _print_findings() -> None:
    print("\n  What is genuinely harder on Qdrant, stated rather than skipped:")
    print("   - No TTL. Nothing in a vector database expires a point, so the")
    print("     deadline has two owners the moment you need it gone -- the")
    print("     same thing that is true of Postgres, and not of MongoDB.")
    print("   - No rows, so no view and no GRANT. Refusal cannot be made a")
    print("     property of the engine on the stock image; it lives in a")
    print("     payload filter every read must remember. That is the finding.")
    print("   - No recursive query. Inherited refusal is an application-side")
    print("     transitive closure over the payload, not one query.")
    print("\n  What carries over completely: refusal belongs in the read path,")
    print("  and it works -- Act II is clean. What does not carry over is Act")
    print("  III: the *structural* version, where the unsafe read cannot be")
    print("  written, needs something Qdrant does not have.")


async def main() -> int:
    print(__doc__.split("\n\n")[0])
    try:
        await run()
    except Exception as exc:  # noqa: BLE001
        print(f"\n!! could not complete: {type(exc).__name__}: {exc}")
        print("   Is Qdrant up?")
        print("     docker compose -f drift/docker-compose.drift.yml up -d "
              "--wait drift-qdrant")
        return 2

    _print_findings()
    print(f"\n{'=' * 72}\nVERDICT")
    if failures:
        print(f"{len(failures)} check(s) failed:")
        for f in failures:
            print(f"  - {f}")
        print("\nIf the failed check is 'the unfiltered read STILL leaks', then")
        print("a Qdrant release has added a collection-level default filter and")
        print("this finding needs updating -- a good outcome for an argument.")
        return 1

    print("Refusal on Qdrant is real in the read path and CONVENTIONAL at the")
    print("engine: the filter works, and nothing forces the next caller to use")
    print("it. The structural third act that Postgres reaches is not available")
    print("on the stock image. A whole class of vector databases can express")
    print("this guarantee only politely -- which is the finding.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
