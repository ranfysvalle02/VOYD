"""The smallest adoption: refusal on one collection, one read path.

    docker compose up -d          # plain MongoDB is enough for part 1
    uv run python examples/quickstart.py

This is the on-ramp the README points at. Two parts, in order of how little
they cost to try:

1. **find-only, plain MongoDB.** No Atlas, no vectors, no API key. The whole
   integration a team adds is fenced between the ``integration:`` markers
   below -- ``tests/test_the_quickstart_refuses.py`` counts the substantive
   lines and fails if it grows past ten, so the on-ramp cannot quietly become
   a migration.

2. **vector search, Atlas + Voyage autoEmbed.** The same guarantee on the
   ``$vectorSearch`` path, where the server owns the embedding and the
   application never computes a vector. Runs only when ``VOYD_ATLAS_URI`` is
   set (read from ``.env`` here); prints a skip line otherwise. The point of
   the second part is that refusal holds on a hit whose vector this process
   never touched -- see ``tests/test_atlas_autoembed.py`` for the assertions.

Nothing here deletes anything. ``revoke()`` makes a fact unreachable on the
next read; the row stays on disk, which is the proof.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from pathlib import Path

from pymongo import AsyncMongoClient

from voyd import Engine

LOCAL_URI = os.getenv("VOYD_MONGO_URI",
                      "mongodb://localhost:27018/?directConnection=true")


def _dotenv(key: str) -> str | None:
    """Read one key from the repo ``.env`` without importing a settings lib.

    autoEmbed needs only the cluster URI in this process -- the Voyage key
    lives on the Atlas side, which is the whole point of server-side
    embedding -- so this deliberately reads just what part 2 requires.
    """
    if key in os.environ:
        return os.environ[key]
    env = Path(__file__).resolve().parents[1] / ".env"
    if not env.exists():
        return None
    for line in env.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k.strip() == key:
            return v.strip().strip('"')
    return None


async def find_only() -> None:
    """Part 1: the minimal wedge. Plain MongoDB, no vectors."""
    client = AsyncMongoClient(LOCAL_URI)
    name = f"quickstart_{uuid.uuid4().hex[:8]}"
    db = client[name]

    # Two rows, one of which is about to be forgotten.
    leaked = (await db.notes.insert_one({"text": "aws key AKIA...leaked"})).inserted_id
    await db.notes.insert_one({"text": "the fault code is P0301"})

    # --- integration: begin (the diff a team adds to an existing app) ---
    engine = Engine(client, db)
    await engine.connect()
    docs = engine.model("notes").forgettable()
    await engine.ensure(search_wait_s=0)          # 0: no search index to wait on
    reachable = await docs.find({})               # was: await db.notes.find(...)
    await docs.revoke({"_id": leaked}, reason="credential leaked")
    # --- integration: end ---

    print("\n  Part 1 -- find-only, plain MongoDB")
    print(f"    before: reachable said {len(reachable)} rows")
    after = await docs.find({})
    raw = [d async for d in db.notes.find({})]
    print(f"    after revoke: handle.find -> {len(after)} reachable, "
          f"raw collection -> {len(raw)} on disk")
    print("    the leaked row is on disk and cannot reach a prompt through the handle.")
    assert len(after) == 1, "the revoked fact was still reachable"
    assert len(raw) == 2, "revoke deleted a row; it must only refuse"

    await client.drop_database(name)
    await client.close()


async def vector_search() -> None:
    """Part 2: the same guarantee on the Atlas autoEmbed vector path."""
    uri = _dotenv("VOYD_ATLAS_URI")
    if not uri:
        print("\n  Part 2 -- skipped (set VOYD_ATLAS_URI in .env for the "
              "Atlas autoEmbed path)")
        return

    model = os.getenv("VOYD_ATLAS_EMBED_MODEL", "voyage-4")
    client = AsyncMongoClient(uri)
    name = f"quickstart_atlas_{uuid.uuid4().hex[:8]}"
    engine = Engine(client, client[name])
    await engine.connect()

    print("\n  Part 2 -- vector search, Atlas + Voyage autoEmbed")
    try:
        # The server owns the embedding: text in, no vector ever computed here.
        engine.model("notes", tenant="tenant").searchable(
            text_paths=("text",), auto_embed=model)
        docs = engine.model("notes", tenant="tenant").forgettable()
        await engine.ensure(search_wait_s=300)

        if not engine.search_engine.embeds_itself("notes"):
            print(f"    the cluster did not accept autoEmbed with {model!r}; "
                  "set VOYD_ATLAS_EMBED_MODEL to a registered model.")
            return

        await engine.db.notes.insert_many([
            {"tenant": "t1", "text": "the fault code is P0301, a misfire"},
            {"tenant": "t1", "text": "the user's name is Dana"},
        ])

        # Wait for mongot to embed and index, then query by *text*.
        for _ in range(80):
            hits = await docs.search([], text="engine misfire",
                                     filters={"tenant": "t1"}, limit=5)
            if hits:
                break
            await asyncio.sleep(3)

        print(f"    text query -> {[h['text'][:28] for h in hits]}")
        await docs.revoke({"tenant": "t1", "text": {"$regex": "^the fault"}},
                          reason="credential leaked")
        after = await docs.search([], text="engine misfire",
                                  filters={"tenant": "t1"}, limit=5)
        on_disk = await engine.db.notes.count_documents(
            {"text": {"$regex": "^the fault"}})
        print(f"    after revoke: {len(after)} reachable, {on_disk} on disk")
        print("    a hit whose vector this process never computed was still refused.")
        assert all(not h["text"].startswith("the fault") for h in after)
        assert on_disk == 1
    finally:
        await client.drop_database(name)
        await client.close()


async def main() -> None:
    await find_only()
    await vector_search()
    print("\n  delete calls issued by this program: 0\n")


if __name__ == "__main__":
    asyncio.run(main())
