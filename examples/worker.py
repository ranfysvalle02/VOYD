"""Tuesday. A worker that survives a 429. No Celery. No Redis. One MongoDB.

    docker compose up -d
    uv run python examples/worker.py

The document *is* the job. An atomic claim takes the next one; running N of
these is safe with no coordinator. The only decision a worker makes on failure
is the one that matters: **is this the world, or is this the document?**

    a 429, a dropped socket, a rate limit   -> the world. retry it.
    malformed arguments, an empty payload   -> the document. park it, move on.

``queue.fail(job, exc)`` is that decision. Raise ``PermanentFailure`` and the
job is parked immediately; raise anything else and it goes back on the queue
until it runs out of attempts. That is the whole retry taxonomy -- the one a
placeholder API key taught us, the expensive way.

Pure Engine: ``from voyd import Engine, PermanentFailure``. No FastAPI, no
vendor. The "work" here is fake so the loop runs with nothing installed but a
database.
"""

from __future__ import annotations

import asyncio
import os

from pymongo import AsyncMongoClient

from voyd import Engine, PermanentFailure

URI = os.getenv("VOYD_MONGO_URI", "mongodb://localhost:27018/?directConnection=true")


async def handle(job: dict) -> dict:
    """Do the work, or fail in a way that says whose fault it is.

    ``op`` drives the outcome so the two failure paths are both exercised:
    a transient error that clears on retry, and a permanent one that never will.
    """
    op = job["op"]
    if op == "poison":
        # The argument itself is broken. Retrying cannot help, so do not burn
        # attempts pretending it might.
        raise PermanentFailure("malformed payload: no text to process")
    if op == "flaky" and int(job.get("attempts", 0)) < 1:
        # The world was briefly broken. This is exactly what a retry is for.
        raise RuntimeError("429 Too Many Requests")
    return {"result": f"processed {op}"}


async def main() -> None:
    client = AsyncMongoClient(URI)
    await client.drop_database("voyd_worker_demo")
    engine = Engine(client, client["voyd_worker_demo"])
    await engine.connect()

    # ``when`` is what counts as work. A matching document is a job; the queue
    # never needs a second store to know that.
    tasks = engine.model("tasks").queue(when={"indexed": False}, max_attempts=3)
    await engine.ensure(search_wait_s=0)

    await engine.db.tasks.insert_many([
        {"op": "embed", "indexed": False},
        {"op": "flaky", "indexed": False},    # fails once (429), then succeeds
        {"op": "poison", "indexed": False},   # never succeeds; parked, not retried
        {"op": "resize", "indexed": False},
    ])

    done = parked = retried = 0
    while True:
        job = await tasks.claim()             # atomic; safe across N workers
        if job is None:
            break                             # nothing claimable -> drained
        try:
            update = await handle(job)
        except Exception as exc:              # noqa: BLE001 -- fail() does the routing
            gave_up = await tasks.fail(job, exc)
            if gave_up:
                parked += 1
                print(f"  parked (the document): {job['op']} -> {exc}")
            else:
                retried += 1
                print(f"  back on the queue (the world): {job['op']} -> {exc}")
            continue
        await tasks.complete(job, update)
        done += 1
        print(f"  done: {job['op']} -> {update['result']}")

    print(f"\ndrained: {done} done, {parked} parked, {retried} retries survived")
    still_pending = await engine.db.tasks.count_documents({"indexed": False})
    assert still_pending == 0, "a claim loop must drain, not spin"
    print("nothing left claimable — the queue emptied itself")

    await client.close()


if __name__ == "__main__":
    asyncio.run(main())
