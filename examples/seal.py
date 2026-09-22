"""Crypto-shredding through a driver that has never heard of this package.

    docker compose up -d mongo
    uv run python examples/seal.py     # ~10 seconds, no API key, no vendor

`examples/shred.py` is the same guarantee in-process: a key per scope,
ciphertext at rest, destroying the key making every copy unreadable. That
version binds an *import*. A team adopting it edits their application, and
the writer that forgets -- the migration script, the Node service, the
shell, the one written next year -- writes plaintext that no later fix
reaches, because it is already in the backup.

This one binds the *connection*. The client below imports `MongoClient` and
nothing else. It has no `schema_map`, no `AutoEncryptionOpts`, no
`crypt_shared`, and no VOYD import. It changed a connection string, and the
bytes on its disk are ciphertext.

Three things, and the third is the one that took a defect to get right.

**Writes seal.** A plain `insert_one` of a plain string lands as a BSON
Binary with subtype 6, under a key belonging to that tenant and nobody else.

**Reads unseal, and refuse what they cannot.** A document whose key is gone
is refused by name, beside the expired and the revoked -- not raised, because
a crypto-erased document is a normal state and a page of fifty containing one
must return forty-nine rather than a 500.

**An erasure is two things in one order.** Destroying a key is not instant at
the reader: libmongocrypt caches data keys, so a process that decrypted a
scope a moment ago keeps decrypting it for about a minute -- the same shape,
and very nearly the same number, as the TTL window this project opens by
complaining about. So the boundary revokes the scope's documents *first*,
which is immediate and has no window, and destroys the key *second*, which
reaches every copy that exists anywhere. Unreachable first, erased second.
The reverse order is the bug, and the reverse order is what this shipped
with until somebody pointed a client at it. See LIMITS.md §5.

This file asserts rather than prints-and-hopes. An example that cannot fail
is a screenshot.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

from pymongo import MongoClient

ROOT = Path(__file__).resolve().parents[1]
URI = os.getenv("VOYD_MONGO_URI",
                "mongodb://localhost:27018/?directConnection=true")
DB = f"voyd_example_seal_{uuid.uuid4().hex[:8]}"

SECRET = "alice was treated for a stress fracture in March"
KEPT = "the fault code is P0301"

POLICY = """
from voyd import guard, deadline, revocable, tenant, sealed

@guard("notes", on_delete="revoke")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()
    text      = sealed()
"""


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main() -> None:
    try:
        import pymongocrypt  # noqa: F401
    except ImportError:
        print("\n  examples/seal.py needs pymongocrypt (the crypto extra).")
        print("  Skipped, loudly: a demo that silently did nothing would be "
              "the exact\n  failure this repository is named after.\n")
        return

    direct = MongoClient(URI)
    policy = ROOT / f".voydfile_seal_{uuid.uuid4().hex[:6]}.py"
    policy.write_text(POLICY)
    port = _free_port()
    host = URI.split("//", 1)[1].split("/", 1)[0]
    proxy = subprocess.Popen(
        [sys.executable, "-m", "voyd.wire", "--config", str(policy),
         "--listen", str(port), "--target", host, "--key-vault", DB,
         "--quiet"],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        until = time.monotonic() + 20
        while time.monotonic() < until:
            try:
                with socket.create_connection(("127.0.0.1", port), 0.2):
                    break
            except OSError:
                time.sleep(0.1)

        client = MongoClient(f"mongodb://localhost:{port}/"
                             "?directConnection=true",
                             serverSelectionTimeoutMS=8000)

        def reachable(who: str) -> list:
            return sorted(d["text"] for d in
                          client[DB].notes.find({"tenant_id": who}))

        print("\n  A plain pymongo client. No encryption configured on it, "
              "no VOYD import\n  in it. It changed a connection string.\n")

        client[DB].notes.insert_many([
            {"tenant_id": "alice", "text": SECRET},
            {"tenant_id": "bob", "text": KEPT},
        ])
        print("    db.notes.insert_one({'tenant_id': 'alice', "
              "'text': <a string>})\n")

        served = reachable("alice")
        print(f"  through the boundary  {served[0]!r}")
        assert served == [SECRET]

        on_disk = direct[DB].notes.find_one({"tenant_id": "alice"})["text"]
        assert on_disk != SECRET, "the plaintext reached the disk"
        assert getattr(on_disk, "subtype", None) == 6, (
            "a BSON Binary with subtype 6 is an encrypted value; this is not")
        print(f"  on disk               {repr(on_disk)[:44]}...', 6)")
        print("                        which is what the replica, the "
              "snapshot and the")
        print("                        backup all get, and what a DBA with "
              "a shell gets\n")

        print("  Now an erasure request. No new verb -- the key vault is an "
              "ordinary\n  collection, so every driver can already ask:\n")
        print("    db['__keys'].delete_one({'keyAltNames': 'alice'})\n")
        client[DB]["__keys"].delete_one({"keyAltNames": "alice"})

        # Immediately. Not in sixty seconds, when the key cache turns over.
        gone = reachable("alice")
        print(f"  alice, immediately    {gone}   <- refused on the very "
              f"next read")
        assert gone == [], (
            "alice's key was destroyed and her document was still served: "
            "the revocation did not precede the shred, so the key cache is "
            "a window")

        others = reachable("bob")
        print(f"  bob                   {others}")
        assert others == [KEPT], "erasing one subject took out another"

        rows = direct[DB].notes.count_documents({})
        print(f"  rows on disk          {rows}   <- nothing was destroyed")
        assert rows == 2

        row = direct[DB].notes.find_one({"tenant_id": "alice"})
        assert row is not None
        assert row["forgotten"]["reason"] == "key destroyed"
        assert getattr(row["text"], "subtype", None) == 6
        print(f"  the mark              {row['forgotten']['reason']!r} "
              f"at {row['forgotten']['at'].isoformat()}")
        print("  alice's bytes         still there, and noise -- in this "
              "database, in")
        print("                        every replica, and in every backup "
              "ever taken\n")

        vault = direct[DB]["__keys"]
        assert vault.count_documents({"keyAltNames": "alice"}) == 0
        assert vault.count_documents({"keyAltNames": "bob"}) == 1
        print("  Application lines changed: 0")
        print("  Copies of alice's plaintext that remain readable: 0")
        print("  Backups anybody had to visit to achieve that: 0\n")
        client.close()
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
        policy.unlink(missing_ok=True)
        direct.drop_database(DB)
        direct.close()


if __name__ == "__main__":
    main()
