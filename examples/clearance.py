"""The question neither layer was asking: may this reach *this* caller?

    docker compose up -d rs
    uv run python examples/clearance.py     # ~8 seconds, no API key, no vendor

A passcode on a scope is all-or-nothing. So the moment one document in a
scope is more sensitive than the rest, the available answers are "everyone
gets everything" and "split the scope" -- and one retrieval boundary per
sensitivity level is four owners of one deadline all over again.

So sensitivity is a field on the document, clearance is a rung on a ladder,
and they meet in the layer that already refuses things. What this prints is
the same query, run by three people, through one connection string.

**Where the caller's rung comes from is the whole design.** The boundary
does not invent an identity and does not trust one the client asserts -- an
authorisation system whose only input is the attacker's would be worse than
none. It asks the *server*: `connectionStatus` reports the roles the
deployment granted this authenticated connection.

But a role says who somebody **is**, not how far up a ladder they stand.
Nothing in `db.createRole({role: "analyst"})` carries a level. So the policy
file says, once, in the same place it says everything else:

    classification = clearance(
        order=("public", "internal", "secret"),
        roles={"analyst": "internal", "sec-cleared": "secret"})

That mapping is the difference between a rule that can be declared and one
that can only be described. Without it the boundary finds no level, "no
claim is the lowest, not the highest", and the collection refuses every
document to everybody -- fail-closed, which is the right direction and the
wrong outcome.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from pymongo import MongoClient
from pymongo.errors import PyMongoError

from _boundary import free_port

ROOT = Path(__file__).resolve().parents[1]
RS_URI = os.getenv(
    "VOYD_RS_URI",
    "mongodb://voyd:voyd@localhost:27021,localhost:27022,localhost:27023"
    "/?replicaSet=voydrs&authSource=admin")

POLICY = '''
from voyd import guard, deadline, revocable, clearance

@guard("notes")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    classification = clearance(
        order=("public", "internal", "secret"),
        roles={"analyst": "internal", "sec-cleared": "secret"})
'''

NOTES = [
    ("public",   "the office is closed on Monday"),
    ("internal", "Q3 headcount plan is 14 engineers"),
    ("secret",   "the 2019 acquisition fell through over the pension"),
    (None,       "an untagged note nobody classified"),
]

CAST = [("reader", None, "holds no mapped role"),
        ("ana", "analyst", "cleared to 'internal'"),
        ("sec", "sec-cleared", "cleared to 'secret'")]


def main() -> None:
    admin = MongoClient(RS_URI, serverSelectionTimeoutMS=4000)
    try:
        admin.admin.command("ping")
    except Exception as exc:                                   # noqa: BLE001
        print(f"\n  no authenticated deployment at {RS_URI.split('@')[-1]}: "
              f"{type(exc).__name__}")
        print("  This example is about an identity the *server* vouches for,")
        print("  so it needs one: `docker compose up -d rs`. Every other")
        print("  example runs against the plain container.\n")
        admin.close()
        return

    name = f"voyd_example_clearance_{uuid.uuid4().hex[:8]}"
    made: list[str] = []
    try:
        for role in ("analyst", "sec-cleared"):
            admin[name].command("createRole", role, privileges=[],
                                roles=[{"role": "read", "db": name}])
        for user, role, _ in CAST:
            roles = [{"role": "read", "db": name}]
            if role:
                roles = [{"role": role, "db": name}]
            admin[name].command("createUser", user, pwd="pw", roles=roles)
            made.append(user)
        admin[name].notes.insert_many(
            [{"classification": lvl, "text": t} if lvl else {"text": t}
             for lvl, t in NOTES])
        _serve(name)
    finally:
        for user in made:
            try:
                admin[name].command("dropUser", user)
            except PyMongoError:
                pass
        for role in ("analyst", "sec-cleared"):
            try:
                admin[name].command("dropRole", role)
            except PyMongoError:
                pass
        admin.drop_database(name)
        admin.close()


def _serve(name: str) -> None:
    """The boundary in front of the authenticated set, then the story."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "voydfile.py"
        path.write_text(POLICY)
        port = free_port()
        proc = subprocess.Popen(
            [sys.executable, "-m", "voyd.wire.proxy", "--config", str(path),
             "--listen", str(port), "--target", RS_URI],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True)
        try:
            until = time.monotonic() + 30
            while time.monotonic() < until:
                try:
                    with socket.create_connection(("127.0.0.1", port), 0.2):
                        break
                except OSError:
                    time.sleep(0.1)
            _story(port, name)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


def _as(port: int, user: str, database: str) -> MongoClient:
    return MongoClient(
        f"mongodb://{user}:pw@localhost:{port}/?directConnection=true"
        f"&authSource={database}", serverSelectionTimeoutMS=8000)


def _story(port: int, name: str) -> None:
    print(f"\n  {len(NOTES)} notes in one collection, one retrieval boundary,")
    print("  one deadline. Same query, three callers, and the only thing")
    print("  that differs is a role the deployment granted.\n")

    expected = {
        "reader": [],
        "ana": ["Q3 headcount plan is 14 engineers",
                "the office is closed on Monday"],
        "sec": ["Q3 headcount plan is 14 engineers",
                "the 2019 acquisition fell through over the pension",
                "the office is closed on Monday"],
    }
    for user, role, note in CAST:
        client = _as(port, user, name)
        try:
            got = sorted(d["text"] for d in client[name].notes.find({}))
        finally:
            client.close()
        print(f"  {user} ({note}):")
        for text in got:
            print(f"    - {text}")
        if not got:
            print("    (nothing)")
        print(f"    {len(got)} of {len(NOTES)} reachable")
        assert got == expected[user], f"{user} saw {got}"

    print("\n  Note what is missing from all three: the untagged note.")
    print("    Untagged is not public. A document with no label is refused")
    print("    until somebody declares a default -- otherwise every row")
    print("    written before the policy existed is world-readable, which")
    print("    is the population most likely to predate anyone thinking")
    print("    about sensitivity at all.")

    print("\n  And `reader` is the one worth staring at. They authenticated,")
    print("    they can read the database, and they hold no role this policy")
    print("    maps -- so they are cleared for the *lowest* rung, which is")
    print("    nothing. The other default is the one that makes a demo work")
    print("    on the first try and a deployment world-readable on the last.")

    print("\n  Everything above is one collection, one TTL index, one scope.")
    print("    No second boundary, no per-level namespace, nothing to keep")
    print("    in step.")
    print("\n  Application lines changed: 0\n")


if __name__ == "__main__":
    main()
