"""The whole pitch, with no VOYD import in the part that matters.

    docker compose up -d mongo
    uv run python examples/wire.py     # ~8 seconds, no API key, no vendor

This starts the boundary from `voydfile.py`, points a plain `pymongo` client
at it, and asserts what comes back. The client below is deliberately ordinary:
it imports `MongoClient` and nothing else, so everything it demonstrates is
equally true of the Node driver, of Compass, and of a notebook -- they all
send the same bytes.

Two halves, and the second one is the one that was missing until now.

**Reads refuse.** An expired row and a revoked row are on disk and are not
reachable through the boundary. Nothing was deleted to achieve that.

**Writes forget.** `deleteOne` -- a verb already in everybody's code -- stops
being a wish and becomes a contract. The row is marked, unreachable on the
next read, still on disk for the investigation, and its deadline is pulled in
so the reaper collects it on the schedule it already had. The driver is told
`deleted_count=1`, which is true in the only sense the caller cared about.

This file asserts rather than prints-and-hopes. The examples are
executable evidence and CI runs every one of them, so an example that
cannot fail is a screenshot.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import uuid
from datetime import timedelta
from pathlib import Path

from pymongo import MongoClient

from voyd.engine.time import now

ROOT = Path(__file__).resolve().parents[1]
URI = os.getenv("VOYD_MONGO_URI",
                "mongodb://localhost:27018/?directConnection=true")
DB = f"voyd_example_wire_{uuid.uuid4().hex[:8]}"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main() -> None:
    direct = MongoClient(URI)
    past = now() - timedelta(days=1)
    direct[DB].notes.insert_many([
        {"tenant_id": "acme", "text": "the fault code is P0301"},
        {"tenant_id": "acme", "text": "last year's pricing", "expire_at": past},
        {"tenant_id": "acme", "text": "aws key AKIA-EXAMPLE",
         "forgotten": {"at": past, "reason": "credential leaked"}},
        {"tenant_id": "acme", "text": "a note somebody will delete"},
        {"tenant_id": "globex", "text": "globex merger memo"},
    ])

    port = _free_port()
    host = URI.split("//", 1)[1].split("/", 1)[0]
    proxy = subprocess.Popen(
        [sys.executable, "-m", "voyd.wire", "--config", "voydfile.py",
         "--listen", str(port), "--target", host],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        until = time.monotonic() + 15
        while time.monotonic() < until:
            try:
                with socket.create_connection(("127.0.0.1", port), 0.2):
                    break
            except OSError:
                time.sleep(0.1)

        client = MongoClient(f"mongodb://localhost:{port}/"
                             "?directConnection=true",
                             serverSelectionTimeoutMS=8000)
        def texts():
            return sorted(d["text"]
                          for d in client[DB].notes.find({"tenant_id": "acme"}))

        print("\n  Five documents. One expired, one revoked, one belongs to "
              "another tenant.\n")

        raw = sorted(d["text"] for d in direct[DB].notes.find({}))
        print(f"  direct, no boundary   {len(raw)} documents")
        assert len(raw) == 5

        served = texts()
        print(f"  through the boundary  {served}")
        assert served == ["a note somebody will delete",
                          "the fault code is P0301"], served
        print("                        the expired and the revoked are "
              "refused, and")
        print("                        globex was never in scope\n")

        print("  Now a delete, written the way it already is in their code:")
        print("    db.notes.delete_one({'text': 'a note somebody will delete'})")
        res = client[DB].notes.delete_one(
            {"text": "a note somebody will delete"})
        print(f"    -> deleted_count={res.deleted_count}   "
              f"(the driver is satisfied)\n")
        assert res.deleted_count == 1

        assert texts() == ["the fault code is P0301"], texts()
        print("  reachable now         ['the fault code is P0301']")

        on_disk = direct[DB].notes.count_documents({})
        print(f"  rows on disk          {on_disk}   <- nothing was destroyed")
        assert on_disk == 5, "a delete that really deleted is not a refusal"

        row = direct[DB].notes.find_one({"text": "a note somebody will delete"})
        assert row is not None
        assert row["forgotten"]["reason"] == "deleted via voyd-wire"
        assert row["expire_at"] is not None
        print(f"  the mark              {row['forgotten']['reason']!r} "
              f"at {row['forgotten']['at'].isoformat()}")
        print("  the deadline          set, so the reaper collects the bytes")
        print("                        on the schedule they already had\n")

        print("  Application lines changed: 0")
        print("  Deletes issued by the boundary: 0")
        print("  Facts that reached a prompt after being forgotten: 0\n")
        client.close()
    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy.kill()
        direct.drop_database(DB)
        direct.close()


if __name__ == "__main__":
    main()
