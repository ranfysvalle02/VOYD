"""A retrieval backend. No Redis. No vector DB. No cron. One MongoDB.

    docker compose up -d
    uv run python examples/agent.py

An agent here is a **caller**, not the category. It uses the ``memory`` trait,
which is a composition of admission -- a worked example of the handle, not a
product. The comparison set for a memory product is recall@k; this is judged on
what it *refuses*, so the demo shows the trait and does not pretend to be Mem0.
Embeddings are your job; this file passes fake vectors so the pitch runs with
no vendor. Swap in Voyage, OpenAI, whatever -- ``remember()`` takes floats, not
an API key.
"""

from __future__ import annotations

import asyncio
import os
from datetime import timedelta

from pymongo import AsyncMongoClient

from voyd import Engine, PermanentFailure

URI = os.getenv("VOYD_MONGO_URI", "mongodb://localhost:27018/?directConnection=true")
DIMS = 8


def vec(n: float) -> list[float]:
    return [n] * DIMS


async def main() -> None:
    client = AsyncMongoClient(URI)
    await client.drop_database("voyd_agent_demo")
    engine = Engine(client, client["voyd_agent_demo"])
    await engine.connect()

    mem = engine.model("memories", tenant="session").memory(
        default_ttl=timedelta(hours=1), dimensions=DIMS)
    tools = engine.model("calls").queue(when={"indexed": False}, max_attempts=3)
    await engine.ensure()

    session = "sess-1"
    await mem.remember(session, "user prefers concise answers", vec(0.1))
    await mem.remember(session, "the user's name is Dana", vec(0.9), pinned=True)

    hits: list = []
    deadline = asyncio.get_running_loop().time() + 30
    while asyncio.get_running_loop().time() < deadline:
        hits = await mem.recall(session, vec(0.9), text="Dana")
        if hits:
            break
        await asyncio.sleep(0.5)
    if not hits:
        raise SystemExit("search indexed nothing in 30s — is Atlas Local up? docker compose up -d")
    print("tier:", engine.search_tier)
    print("recalled:", [h["text"] for h in hits])
    print("other session:", await mem.recall("sess-2", vec(0.9)))

    await engine.db.calls.insert_many([
        {"tool": "embed", "indexed": False},
        {"tool": "broken_args", "indexed": False},
    ])
    world = await tools.claim()
    call = await tools.claim()
    print("429 is the world — retry:", not await tools.fail(world, RuntimeError("429")))
    print("bad args are the call — park:",
          await tools.fail(call, PermanentFailure("malformed")))
    print("health:", engine.health()["search"])

    await client.close()


if __name__ == "__main__":
    asyncio.run(main())
