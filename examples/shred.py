"""The question refusal cannot answer: "and your backups?"

    docker compose up -d
    export CRYPT_SHARED_LIB_PATH=/path/to/mongo_crypt_v1.{so,dylib}
    uv run --extra crypto python examples/shred.py      # ~90 seconds

``refuse.py`` makes a fact unreachable on the next read while its row is
still on disk, and that row is the proof. It is also the finding a security
reviewer writes down, and they are right: refusal is a property of *this
application's read path*, and a restored snapshot does not run this
application's read path.

So this shows the other erasure. A key per scope, the text as ciphertext at
rest, and destroying the key makes every copy unreadable at once -- the row,
the replica, the snapshot, the export somebody took in March -- without any
of them being visited.

And then it measures the part everybody overstates. Destroying a key is not
instant either: a client that decrypted the document before the shred keeps
decrypting it until its key cache turns over. This program waits for that to
happen and prints the number, which is about sixty seconds -- the same shape,
and very nearly the same figure, as the TTL monitor window this whole package
exists to talk about.

That is the argument for having both rather than choosing:

    the key cache is a window where the ciphertext is still readable
        -> refusal already refused the document, with no window at all
    refusal only binds this application's read path
        -> the key is gone, so a backup restored next year is noise
"""

from __future__ import annotations

import asyncio
import time
import uuid

from pymongo import AsyncMongoClient

from voyd.engine import Deadline, Engine, revoked
from voyd.engine.keyring import Keyring, KeyringSpec, available

URI = "mongodb://localhost:27018/?directConnection=true"
SECRET = "alice was treated for a stress fracture in March"
KEPT = "the fault code is P0301"
PATIENCE = 120


async def main() -> None:
    ok, why = available()
    if not ok:
        print(f"\n  automatic encryption is unavailable: {why}")
        print("  refusal works without it; this example is about the half")
        print("  that survives a backup, and it needs the crypt library.\n")
        return

    client = AsyncMongoClient(URI)
    name = f"core_shred_{uuid.uuid4().hex[:8]}"
    engine = Engine(client, client[name])
    await engine.connect()
    ring = Keyring(engine.db, KeyringSpec(sealed={"notes": ("text",)}))
    await ring.ensure()
    await ring.key_for("alice")
    await ring.key_for("bob")

    writer = AsyncMongoClient(URI, auto_encryption_opts=ring.client_options())
    try:
        notes = engine.model("notes").admitting(Deadline(), revoked())
        await engine.ensure(search_wait_s=0)
        await writer[name].notes.insert_many([
            {"key_scope": "alice", "text": SECRET},
            {"key_scope": "bob", "text": KEPT},
        ])
        print(f"\n  Two facts, two scopes, two keys. ({why})")

        raw = await engine.db.notes.find_one({"key_scope": "alice"})
        print("\n  1. What is actually on disk, read by a client with no key")
        print("     -- which is what a DBA, a replica and a backup all are:")
        print(f"       text -> Binary(subtype={raw['text'].subtype}), "
              f"{len(raw['text'])} bytes")
        print(f"       contains the plaintext? "
              f"{SECRET.encode() in bytes(raw['text'])}")

        print("\n  2. Refusal, for contrast. Immediate, and local to us:")
        await notes.revoke({"key_scope": "alice"}, reason="erasure request")
        print(f"       reachable here -> "
              f"{[d['key_scope'] for d in await notes.find({})]}")
        print("       ...and the ciphertext is still in every backup taken")
        print("       before now. Refusal has nothing to say about those.")

        print("\n  3. So destroy the key. One operation, no sweeper visits")
        print("     any copy of the data, anywhere:")
        await ring.shred("alice")
        cold = AsyncMongoClient(URI,
                                auto_encryption_opts=ring.client_options())
        try:
            try:
                await cold[name].notes.find_one({"key_scope": "alice"})
                print("       a cold client STILL read it -- shred failed")
            except Exception as e:
                print(f"       a cold client now fails: {type(e).__name__}")
            other = await cold[name].notes.find_one({"key_scope": "bob"})
            print(f"       and bob is untouched: {other['text']!r}")
            print("       (per-scope keys: one erasure is not everybody's)")
        finally:
            await cold.close()

        print("\n  4. The part people overstate. This client read alice")
        print("     before the shred, so it holds a cached key. Waiting")
        print("     to see how long it keeps working:")
        t0 = time.monotonic()
        held = None
        while time.monotonic() - t0 < PATIENCE:
            try:
                await writer[name].notes.find_one({"key_scope": "alice"})
                await asyncio.sleep(2)
            except Exception:
                held = time.monotonic() - t0
                break
        if held:
            print(f"       the warm client stopped decrypting after "
                  f"~{held:.0f}s")
        else:
            print(f"       STILL decrypting after {PATIENCE}s.")
            print("       The cache turnover is not a contract and it is not")
            print("       a constant -- measured at ~60s in one shape and")
            print("       past two minutes in this one. Which is the point:")
            print("       you cannot build a guarantee on it.")

        print("\n  5. Meanwhile, look what happened to the row:")
        row = await engine.db.notes.find_one({"key_scope": "alice"})
        if row is None:
            print("       gone. The reaper took it during the wait above --")
            print("       because step 2's revoke gave it a deadline in the")
            print("       past, and the TTL monitor got there on its own.")
            print("       All three layers, in order, in one run.")
        else:
            print(f"       still on disk: {len(row['text'])} bytes of noise,")
            print("       waiting for the reaper on its own schedule.")

        print("""
  So: three mechanisms, and each is honest about what it costs.

    refusal          immediate     this read path only     unreachable now
    crypto erasure   eventual      every copy, everywhere  unreadable soon
    the TTL reaper   ~60s          this deployment only    gone eventually

  The middle row is why the bottom one is not enough, and the top row is
  why the middle one is not enough. The key cache is a window in which the
  ciphertext is still readable -- and refusal had already refused the
  document, on the first read after the request, with no window at all.
  Refusal in turn binds only this application; the key is gone from all of
  them, including the backup nobody has restored yet.

  Neither is the answer. Both is.
""")
    finally:
        await writer.close()
        await client.drop_database(name)
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
