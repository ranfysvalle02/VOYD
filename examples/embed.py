"""The index owns the vector, and the query cannot go around it.

    docker compose up -d mongo
    uv run python examples/embed.py     # ~6 seconds, no API key, no vendor

`embedded_with(model)` refuses a **document** whose stored vector came from
the wrong model. The number that makes it worth having, measured against a
real embedding API on two generations of one vendor's model at the same
width:

    identical text, old model vs new       cosine -0.053
    unrelated text, both on the new one    cosine +0.301

A model swap does not degrade ranking, it *inverts* it. Unrelated text scores
five times higher than the document you were looking for, with no error, no
log and a healthy-looking `describe()`.

Nothing refused the **query**, and that is the same failure one level up: one
message rather than one row. `auto_embed` removes the client-side embedder
that makes it possible -- the index holds text, mongot embeds it on write and
embeds the query with the same model at read time, so nothing in the
application ever computes a vector and nothing can drift from the index.

A client that sends its own `queryVector` anyway has put the embedder back,
through a driver that never read the policy file. That is exactly the caller
the wire boundary exists for, so the boundary refuses it by name and says
which form works instead.

**This needs no Atlas and no embedding model**, which is the point worth
noticing: the decision is a `$vectorSearch` body and a dict. Creating the
`autoEmbed` index is still the library's job and needs a real cluster --
see `LIMITS.md` section 5 -- but the *refusal* is pure, and pure is what let
it move to a wire at all.
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
from pymongo.errors import OperationFailure

ROOT = Path(__file__).resolve().parents[1]
URI = os.getenv("VOYD_MONGO_URI",
                "mongodb://localhost:27018/?directConnection=true")
DB = f"voyd_example_embed_{uuid.uuid4().hex[:8]}"

POLICY = """
from voyd import guard, deadline, revocable, tenant, auto_embed

@guard("notes", on_delete="revoke")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()
    body      = auto_embed("voyage-4")

# An ordinary guarded collection beside it, with no declaration about who
# embeds. A client vector is correct here, and must keep working -- without
# this the demo below could not tell "refuses the right query" from
# "refuses $vectorSearch".
@guard("archive")
class Archive:
    expire_at = deadline()
    tenant_id = tenant()
"""


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _vector_search(client, collection: str, **stage):
    stage.setdefault("index", "engine_vector_index")
    stage.setdefault("numCandidates", 100)
    stage.setdefault("limit", 10)
    return list(client[DB][collection].aggregate(
        [{"$vectorSearch": stage}]))


def main() -> None:
    direct = MongoClient(URI)
    policy = ROOT / f".voydfile_embed_{uuid.uuid4().hex[:6]}.py"
    policy.write_text(POLICY)
    port = _free_port()
    host = URI.split("//", 1)[1].split("/", 1)[0]
    proxy = subprocess.Popen(
        [sys.executable, "tools/voyd_wire.py", "--config", str(policy),
         "--listen", str(port), "--target", host, "--quiet"],
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
        client[DB].notes.insert_one(
            {"tenant_id": "acme", "body": "the fault code is P0301"})
        client[DB].archive.insert_one(
            {"tenant_id": "acme", "body": "last quarter's notes"})

        print("\n  One word in the policy file:  body = auto_embed('voyage-4')")
        print("  The application is not edited. No driver is told.\n")

        print("  A client computes its own vector and asks for a ranking:")
        print("    db.notes.aggregate([{'$vectorSearch': "
              "{'queryVector': [...]}}])")
        try:
            _vector_search(client, "notes", path="embedding",
                           queryVector=[0.1] * 1024)
            raise AssertionError(
                "a client vector reached an index the server owns -- this is "
                "the failure the example exists to demonstrate being absent")
        except OperationFailure as refused:
            # `details["errmsg"]` rather than `str(refused)`: pymongo appends
            # the whole reply to the exception text, so printing that would
            # show this message twice and bury the point of the example.
            said = (refused.details or {}).get("errmsg", str(refused))
            assert "voyd-wire" in said and "voyage-4" in said
            print("    -> refused, and told which form works:\n")
            for sentence in said.split(". "):
                if sentence.strip():
                    print(f"       {sentence.strip().rstrip('.')}.")

        print("\n  Not because $vectorSearch is banned. The collection that")
        print("  declared nothing about embedding still takes a client "
              "vector:")
        print("    db.archive.aggregate([{'$vectorSearch': "
              "{'queryVector': [...]}}])")
        try:
            _vector_search(client, "archive", path="embedding",
                           queryVector=[0.1] * 1024)
            print("    -> forwarded (and the server answered)")
        except OperationFailure as server_said:
            # No vector index exists on `archive` in this throwaway database,
            # so Atlas refuses it -- which is the right outcome for this
            # demonstration and has to be distinguished from ours. The claim
            # is that the *boundary* did not refuse it.
            said = (server_said.details or {}).get("errmsg", str(server_said))
            assert "voyd-wire" not in said, (
                "the boundary refused a collection that declared nothing "
                "about who embeds")
            print("    -> forwarded; the error came from the server, not "
                  "from the boundary")
            print(f"       ({said[:64]}...)")

        print("\n  And ordinary reads are untouched, still refusing the "
              "ordinary way:")
        mine = [d["body"] for d in client[DB].notes.find(
            {"tenant_id": "acme"})]
        theirs = list(client[DB].notes.find({"tenant_id": "globex"}))
        print(f"    acme    {mine}")
        print(f"    globex  {theirs}   <- never in scope")
        assert mine == ["the fault code is P0301"]
        assert theirs == []

        print("\n  Vectors this process computed: 0")
        print("  Ways for a client embedder to drift from the index: 0")
        print("  Databases consulted to decide that: 0\n")
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
