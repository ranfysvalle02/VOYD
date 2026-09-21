"""The question refusal cannot answer: "and your backups?"

    docker compose up -d
    export CRYPT_SHARED_LIB_PATH=/path/to/mongo_crypt_v1.{so,dylib}
    uv run --extra crypto python examples/shred.py      # ~15 seconds

``refuse.py`` makes a fact unreachable on the next read while its row is
still on disk, and that row is the proof. It is also the finding a security
reviewer writes down, and they are right: refusal is a property of *this
application's read path*, and a restored snapshot does not run this
application's read path.

So this shows the other erasure. A key per scope, the text as ciphertext at
rest, and destroying the key makes every copy unreadable at once -- the row,
the replica, the snapshot, the export somebody took in March -- without any
of them being visited.

**And none of it is an API.** `text = sealed()` is a line in a policy file,
and the erasure needs no new verb at all: the key vault is an ordinary
collection, so `delete_one({"keyAltNames": "alice"})` is how any driver in
any language asks. The program below imports `MongoClient` and nothing else.

The part everybody overstates is the ordering, and it is the part the
boundary has to get right. Destroying a key is not instant at the reader:
libmongocrypt caches data keys, so a client that decrypted the document a
moment ago keeps decrypting it until that cache turns over -- measured at
about sixty seconds, which is the same shape, and very nearly the same
figure, as the TTL monitor window this whole package exists to complain
about. A shred on its own therefore opens a second delete-is-a-wish window
inside the feature whose entire purpose is to close the first one.

So the boundary revokes the documents *first* and lets the key die second.
Unreachable now, unreadable everywhere shortly. That is the argument for
having both rather than choosing:

    the key cache is a window where the ciphertext is still readable
        -> refusal already refused the document, with no window at all
    refusal only binds this application's read path
        -> the key is gone, so a backup restored next year is noise
"""

from __future__ import annotations

from pymongo import MongoClient

from _boundary import boundary, deployment

SECRET = "alice was treated for a stress fracture in March"
KEPT = "the fault code is P0301"

POLICY = '''
from voyd import guard, deadline, revocable, tenant, sealed

@guard("notes", on_delete="revoke")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()
    text      = sealed()
'''


def main() -> None:
    from voyd.engine.keyring import available

    ok, why = available()
    if not ok:
        print(f"\n  automatic encryption is unavailable: {why}")
        print("  refusal works without it; this example is about the half")
        print("  that survives a backup, and it needs the crypt library.\n")
        return

    with deployment("shred") as (direct, name):
        with boundary(POLICY, "--key-vault", name, wait_s=60) as uri:
            client = MongoClient(uri, serverSelectionTimeoutMS=8000)
            notes = client[name].notes
            try:
                print("\n  The entire declaration, in the policy file:")
                print("       tenant_id = tenant()")
                print("       text      = sealed()")
                print("     The scope IS the tenant, so there is no second "
                      "field to")
                print("     maintain and per-patient erasure is already the "
                      "shape.")

                # Written as plaintext by a client that does no encryption.
                # The boundary seals it on the way past.
                notes.insert_many([
                    {"tenant_id": "alice", "text": SECRET},
                    {"tenant_id": "bob", "text": KEPT},
                ])

                raw = direct[name].notes.find_one({"tenant_id": "alice"})
                print("\n  1. What is on disk, read without the boundary -- "
                      "which is")
                print("     what a DBA, a replica and a backup all are:")
                print(f"       text -> Binary(subtype={raw['text'].subtype}), "
                      f"{len(raw['text'])} bytes")
                print(f"       contains the plaintext? "
                      f"{SECRET.encode() in bytes(raw['text'])}")
                assert SECRET.encode() not in bytes(raw["text"])
                print("     ...and through the connection string it is just "
                      "a string:")
                got = [d["text"] for d in notes.find({"tenant_id": "alice"})]
                print(f"       {got}")
                assert got == [SECRET]

                print("\n  2. Alice asks to be forgotten. No new verb -- the "
                      "key")
                print("     vault is an ordinary collection:")
                print("       db.__keys.delete_one({'keyAltNames': 'alice'})")
                client[name]["__keys"].delete_one({"keyAltNames": "alice"})

                alice = list(notes.find({"tenant_id": "alice"}))
                bob = [d["text"] for d in notes.find({"tenant_id": "bob"})]
                print(f"       alice -> {alice}")
                print(f"       bob   -> {bob}")
                assert alice == [], (
                    "alice's key was destroyed and her document was still "
                    "served: the revocation did not precede the shred, so "
                    "the key cache is a window")
                assert bob == [KEPT], (
                    "one key per collection would have taken bob with her")
                print("     Read *immediately*. A boundary that only "
                      "destroyed the")
                print("     key would still be serving this plaintext out of "
                      "the")
                print("     cache for about a minute, and would look exactly "
                      "like")
                print("     this one until you timed it.")

                print("\n  3. And the evidence stays. Nothing was destroyed "
                      "except")
                print("     the key:")
                on_disk = direct[name].notes.count_documents({})
                row = direct[name].notes.find_one({"tenant_id": "alice"})
                print(f"       rows on disk -> {on_disk}")
                print(f"       the mark     -> "
                      f"{row['forgotten']['reason']!r}")
                print(f"       the bytes    -> {len(row['text'])} bytes of "
                      f"noise to every")
                print("                        reader that does not hold a "
                      "key nobody holds")
                assert on_disk == 2
                assert row["forgotten"]["reason"] == "key destroyed"

                vault = direct[name]["__keys"]
                assert vault.count_documents({"keyAltNames": "alice"}) == 0
                assert vault.count_documents({"keyAltNames": "bob"}) == 1

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

  Application lines changed: 0
""")
            finally:
                client.close()


if __name__ == "__main__":
    main()
