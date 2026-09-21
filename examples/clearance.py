"""The question neither layer was asking: may this reach *this* caller?

    docker compose up -d rs
    uv run python examples/clearance.py     # ~8 seconds, no API key, no vendor

A passcode on a scope is all-or-nothing. So the moment one document in a
scope is more sensitive than the rest, the available answers are "everyone
gets everything" and "split the scope" -- and one retrieval boundary per
sensitivity level is four owners of one deadline all over again.

So sensitivity is a field on the document, audience is a claim on the
caller, and they meet in the layer that already refuses things. What this
prints is the same query, run by two people, through one connection
string.

**Where the claim comes from is the whole design.** The boundary does not
invent an identity and does not trust one the client asserts -- an
authorisation system whose only input is the attacker's would be worse than
none. It asks the *server*: `connectionStatus` reports the roles the
deployment granted this authenticated connection, and
`restricted_to("groups")` reads them. `db.createRole({role: "legal"})` is
how a deployment already spells an audience, so there is nothing further to
declare and nothing to keep in step.

That is also the honest limit of this example, and it is worth stating
rather than demonstrating around. An **ordered** clearance -- public <
internal < secret -- needs somebody to say which level a role corresponds
to, and nothing in a MongoDB role says that. The wire supplies `user`,
`db`, `groups` and `roles`; a rule wanting `clearance` finds no claim, "no
claim is the lowest, not the highest", and the collection refuses every
document to everybody. Fail-closed, which is the right direction and the
wrong outcome -- so the boundary **says so at boot**, naming the collection
and the claim, rather than letting it present as "VOYD broke my reads".
Closing it properly wants a declared role-to-level mapping in the policy
file. See `NEXT-TODO.md`.

Set membership is what a MongoDB role already is, and it is what this
shows.
"""

from __future__ import annotations

import os
import uuid

from pymongo import MongoClient
from pymongo.errors import PyMongoError

from _boundary import free_port

RS_URI = os.getenv(
    "VOYD_RS_URI",
    "mongodb://voyd:voyd@localhost:27021,localhost:27022,localhost:27023"
    "/?replicaSet=voydrs&authSource=admin")

POLICY = '''
from voyd import guard, deadline, restricted_to, revocable

@guard("notes")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    audience = restricted_to("groups")
'''


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
    tag = uuid.uuid4().hex[:6]
    legal, desk = f"legal_{tag}", f"desk_{tag}"
    users = []
    try:
        for role in (legal, desk):
            admin[name].command("createRole", role, privileges=[],
                                roles=[{"role": "read", "db": name}])
        for user, role in ((f"lawyer_{tag}", legal), (f"seller_{tag}", desk)):
            admin[name].command("createUser", user, pwd="pw",
                                roles=[{"role": role, "db": name}])
            users.append(user)

        admin[name].notes.insert_many([
            {"text": "the settlement terms", "audience": [legal]},
            {"text": "this quarter's discount ladder", "audience": [desk]},
            {"text": "the all-hands date", "audience": [legal, desk]},
            {"text": "a note nobody classified"},
        ])

        # `_boundary.boundary()` targets VOYD_MONGO_URI. This example is
        # the one that cannot use it: the claim comes from the server, so
        # the target has to be the authenticated set.
        _run_against(name, tag, legal, desk)
    finally:
        for user in users:
            try:
                admin[name].command("dropUser", user)
            except PyMongoError:
                pass
        for role in (legal, desk):
            try:
                admin[name].command("dropRole", role)
            except PyMongoError:
                pass
        admin.drop_database(name)
        admin.close()


def _run_against(name: str, tag: str, legal: str, desk: str) -> None:
    """Serve the policy in front of the authenticated set, then tell it."""
    import subprocess
    import sys
    import socket
    import tempfile
    import time
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "voydfile.py"
        path.write_text(POLICY)
        port = free_port()
        proc = subprocess.Popen(
            [sys.executable, "-m", "voyd.wire.proxy", "--config", str(path),
             "--listen", str(port), "--target", RS_URI],
            cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True)
        try:
            until = time.monotonic() + 30
            while time.monotonic() < until:
                try:
                    with socket.create_connection(("127.0.0.1", port), 0.2):
                        break
                except OSError:
                    time.sleep(0.1)
            _story(port, name, tag, legal, desk)
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


def _story(port: int, name: str, tag: str, legal: str, desk: str) -> None:
    print("\n  Four notes in one collection, one retrieval boundary, one")
    print("  deadline. Same query, two callers, and the difference between")
    print("  them is a role the deployment granted -- not a header either")
    print("  of them sent.\n")

    expected = {
        f"lawyer_{tag}": ["the all-hands date", "the settlement terms"],
        f"seller_{tag}": ["the all-hands date",
                          "this quarter's discount ladder"],
    }
    for user, want in expected.items():
        client = _as(port, user, name)
        try:
            got = sorted(d["text"] for d in client[name].notes.find({}))
            print(f"  {user}:")
            for text in got:
                print(f"    - {text}")
            print(f"    {len(got)} of 4 reachable")
            assert got == want, f"{user} saw {got}"
        finally:
            client.close()

    print("\n  Note what is missing from both: the unclassified note.")
    print("    Untagged is not public. A document with no audience is")
    print("    refused until somebody declares a default -- otherwise every")
    print("    row written before the policy existed is world-readable,")
    print("    which is the population most likely to predate anyone")
    print("    thinking about sensitivity at all.")

    print("\n  And the claim is not the caller's to assert. It is the")
    print("    server's answer to `connectionStatus`, asked by the boundary")
    print("    on the caller's own connection -- so a client that would like")
    print("    to be in `legal` has to convince the deployment, not us.")

    print("\n  Everything above is one collection, one TTL index, one scope.")
    print("    No second boundary, no per-level namespace, nothing to keep")
    print("    in step.")
    print("\n  Application lines changed: 0\n")


if __name__ == "__main__":
    main()
