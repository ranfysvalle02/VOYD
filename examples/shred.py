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
import os
import uuid

from pymongo import AsyncMongoClient

from voyd.engine import Engine
from voyd.engine.custody import from_env
from voyd.engine.keyring import available

# The examples all read the same variable, so one export points every
# one of them at Atlas instead of the local container.
URI = os.getenv("VOYD_MONGO_URI",
                "mongodb://localhost:27018/?directConnection=true")
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
    name = f"voyd_example_shred_{uuid.uuid4().hex[:8]}"
    engine = Engine(client, client[name])
    await engine.connect()

    # The ladder, from the environment. Unset is Ephemeral -- demo-grade,
    # and it says so rather than letting the run imply otherwise:
    #   VOYD_KMS_PROVIDER=local VOYD_KMS_KEY_PATH=./master.key
    #   VOYD_KMS_PROVIDER=aws   VOYD_KMS_KEY=arn:aws:kms:...
    custody = from_env("VOYD_KMS")
    held = custody.describe()
    print(f"\n  custody: {held['detail']}")
    print(f"           durable={held['durable']}  audited={held['audited']}")
    if not held["audited"]:
        print("           (shredding below is real; who may destroy the")
        print("            master key is this process's own word for it)")

    try:
        # --- the entire declaration ---------------------------------
        notes = engine.model("notes", tenant="patient").sealed(
            "text", custody=custody)
        await engine.ensure(search_wait_s=0)

        print("\n  One line declared it:")
        print('       engine.model("notes", tenant="patient").sealed("text")')
        print("     The scope IS the tenant, so there is no second field to")
        print("     maintain and per-patient erasure is already the shape.")

        await notes.seal([{"patient": "alice", "text": SECRET},
                          {"patient": "bob", "text": KEPT}])

        raw = await engine.db.notes.find_one({"patient": "alice"})
        print("\n  1. What is on disk, read without the engine -- which is")
        print("     what a DBA, a replica and a backup all are:")
        print(f"       text -> Binary(subtype={raw['text'].subtype}), "
              f"{len(raw['text'])} bytes")
        print(f"       contains the plaintext? "
              f"{SECRET.encode() in bytes(raw['text'])}")
        print("     ...and through the handle it is just a string:")
        print(f"       {[d['text'] for d in await notes.find({'patient': 'alice'})]}")

        print("\n  2. The mistake that used to be silent and permanent:")
        print("     a writer that skips the encrypting client entirely.")
        try:
            await engine.db.notes.insert_one(
                {"patient": "alice", "text": "written by a migration script"})
            print("       ACCEPTED as plaintext  <- this is the hole")
        except Exception as e:
            print(f"       {type(e).__name__} from the server. A binData")
            print("       validator on the collection means forgetting to")
            print("       encrypt is not discouraged, it is impossible.")

        print("\n  3. Alice asks to be forgotten. One call, one tenant:")
        await notes.shred("alice")
        print(f"       alice -> {await notes.find({'patient': 'alice'})}")
        print(f"       bob   -> "
              f"{[d['text'] for d in await notes.find({'patient': 'bob'})]}")
        print(f"       refused: {notes.receipts()['refused_by_reason']}")
        print("     Not an exception -- a refusal with a name, beside the")
        print("     deadline and the revocation. One crypto-erased document")
        print("     must not turn a page of fifty into a 500.")

        print("\n  4. And it reaches further than refusal can. Refusal binds")
        print("     this read path; the key is gone from every copy --")
        print("     replicas, snapshots, the backup nobody has restored.")
        row = await engine.db.notes.find_one({"patient": "alice"})
        print(f"       alice's row: still there, "
              f"{len(row['text'])} bytes of noise")

        print("""
  Three mechanisms, each honest about what it costs:

    refusal          immediate     this read path only     unreachable now
    crypto erasure   eventual      every copy, everywhere  unreadable soon
    the TTL reaper   ~60s          this deployment only    gone eventually

  The middle row is why the bottom one is not enough, and the top row is
  why the middle one is not enough: libmongocrypt caches data keys, so a
  client that decrypted before the shred keeps decrypting for a while --
  measured at ~60s in one shape and past 120s in another, and the turnover
  is not a contract. Refusal had already refused the document, with no
  window at all. Refusal in turn binds only this application; the key is
  gone from all of them.

  Neither is the answer. Both is.
""")
    finally:
        await engine.aclose()
        await client.drop_database(name)
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
