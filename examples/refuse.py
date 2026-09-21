"""Forget something *now*, without deleting it. The operation nobody has.

    docker compose up -d
    uv run python examples/refuse.py      # ~5 seconds, no API key, no vendor

``forget.py`` shows a deadline arriving on its own. This shows the other half,
and the half no vector database offers at all: somebody asks you to forget a
fact *right now* -- an erasure request, a leaked credential, a retracted
document -- and you have to answer for when it stopped being reachable.

Every system's honest answer to that is "whenever the sweeper got to it",
because deletion is the only tool they have and deletion is eventually
consistent by nature. A TTL monitor runs about once a minute (measured here:
60.0s). A lifecycle rule runs about once a day. In that window the fact is
still ranking into prompts.

The distinction this example draws:

    delete   a storage operation. Eventually. Best effort. Unprovable.
    revoke   a retrieval guarantee. Next read. Immediate. Counted.

**And the program below imports nothing from this package.** It writes a
policy file, starts the boundary, and then speaks to an ordinary
`pymongo.MongoClient`. The verb it uses to forget is `delete_one`, which was
already in its code. That is the point: the operation nobody has is reached
through the verb everybody already wrote.

The row is deliberately still on disk at the end of this program. That is not
a failure to clean up -- it is the proof. Unreachable first, erased second, in
that order, because the reverse order is the bug.
"""

from __future__ import annotations

from pymongo import MongoClient

from _boundary import boundary, deployment

SECRET = "the admin password is hunter2"
KEPT = "the fault code is P0301"

POLICY = '''
from voyd import guard, deadline, revocable

@guard("notes", on_delete="revoke")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
'''


def main() -> None:
    with deployment("refuse") as (direct, name):
        direct[name].notes.insert_many([
            {"text": SECRET},
            {"text": KEPT},
        ])

        with boundary(POLICY) as uri:
            client = MongoClient(uri, serverSelectionTimeoutMS=8000)
            notes = client[name].notes
            try:
                print("\n  Two facts, no deadlines. Both pinned, both "
                      "reachable.")
                reachable = sorted(d["text"] for d in notes.find({}))
                print(f"    recall -> {reachable}")
                assert reachable == sorted([SECRET, KEPT])

                print("\n  Now somebody says: forget that first one. Right "
                      "now.")
                print("  The verb is the one already in their code:")
                print("    db.notes.delete_one({'text': ...})")
                res = notes.delete_one({"text": SECRET})
                print(f"    -> deleted_count={res.deleted_count}   "
                      f"(the driver is satisfied)")
                assert res.deleted_count == 1

                reachable = [d["text"] for d in notes.find({})]
                on_disk = direct[name].notes.count_documents({})
                print(f"\n    recall  -> {reachable}")
                print(f"    on disk -> {on_disk} rows        "
                      f"<- the secret is STILL HERE")
                print("       and it is already unreachable. No sweeper ran. "
                      "Nothing")
                print("       was deleted. The next read simply refused it.")
                assert reachable == [KEPT]
                assert on_disk == 2, (
                    "a delete that really deleted is not a refusal")

                print("\n  The same query, straight at the collection, for "
                      "contrast --")
                print("  this is what every other system's read path looks "
                      "like:")
                leaked = sorted(d["text"] for d in direct[name].notes.find({}))
                print(f"    find() -> {leaked}")
                print("       ^ the revoked fact, returned as a normal "
                      "result.")
                assert SECRET in leaked

                print("\n  Audit can still see it, and has to go around the "
                      "boundary to do so:")
                row = direct[name].notes.find_one({"text": SECRET})
                mark = row["forgotten"]
                print(f"    forgotten -> reason={mark['reason']!r}")
                print(f"                 unreachable since "
                      f"{mark['at'].isoformat()}")
                assert mark["reason"] == "deleted via voyd-wire"

                print("\n  And the deadline was pulled in, so the bytes go "
                      "on the")
                print("  schedule they already had -- unreachable first, "
                      "erased second:")
                print(f"    expire_at -> {row['expire_at'].isoformat()}")
                assert row["expire_at"] is not None

                print("\n  Application lines changed: 0")
                print("  delete calls issued by the boundary: 0")
                print("  facts that reached a prompt after being forgotten: "
                      "0\n")
            finally:
                client.close()


if __name__ == "__main__":
    main()
