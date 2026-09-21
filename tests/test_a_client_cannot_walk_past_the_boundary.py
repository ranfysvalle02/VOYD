"""`directConnection=true` is client configuration, not enforcement.

A boundary whose guarantee depends on a connection-string option the caller
must remember is a convention, which is the thing this whole package exists
to replace. A driver without it reads the `hosts` array out of `hello` and
connects to the real cluster nodes, straight past the policy.

Measured before this was fixed, against a local deployment: the client read
the container's internal hostname, could not resolve it, and gave up -- so
locally the bug is a *usability* failure. Against Atlas those hosts resolve
perfectly, which makes the identical bug a **silent bypass**. The dangerous
version is the one that works.

So `hello` is rewritten. The care is in what is *not* rewritten, because
this is where a topology rewrite turns into an outage.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from voyd.wire import proxy as w

from .conftest import free_port, mongo_host  # noqa: E402

pymongo = pytest.importorskip("pymongo")
ROOT = Path(__file__).resolve().parents[1]
HERE = "localhost:27099"

# What a replica set member actually says about itself.
HELLO = {
    "isWritablePrimary": True,
    "setName": "rs0",
    "hosts": ["node-a:27017", "node-b:27017", "node-c:27017"],
    "passives": ["node-d:27017"],
    "arbiters": ["node-e:27017"],
    "me": "node-a:27017",
    "primary": "node-a:27017",
    "maxWireVersion": 25,
    "ok": 1.0,
}


def rewritten(reply: dict) -> dict:
    raw = w.encode_op_msg(1, 2, 0, reply)
    out = w.rewrite_topology(raw, 1, 2, HERE)
    if out is None:
        return reply
    return w.decode_op_msg(out)[1]


def test_the_client_is_told_this_boundary_is_the_whole_cluster():
    """The lie that makes it stay."""
    got = rewritten(HELLO)
    assert got["hosts"] == [HERE]
    assert got["me"] == HERE
    assert got["primary"] == HERE
    assert got["passives"] == [] and got["arbiters"] == []


def test_the_replica_set_name_survives():
    """Stripping `setName` makes a driver treat the target as a standalone,
    which **silently disables retryable writes**. A correctness regression
    handed over as a topology tidy-up is the worst kind."""
    assert rewritten(HELLO)["setName"] == "rs0"


@pytest.mark.parametrize("flag,value", [
    ("isWritablePrimary", False),
    ("secondary", True),
], ids=["not-writable", "secondary"])
def test_writability_is_passed_through_and_never_forced(flag, value):
    """The hazard, and the reason this function is careful rather than
    clever.

    Forcing `isWritablePrimary: True` is the tempting version: it makes the
    client stay no matter what. It is also exactly the signal a driver uses
    to notice a failover -- so masking it means the client keeps writing
    happily to a boundary whose upstream is now a secondary, and nothing
    anywhere notices. A boundary that lies about writability has made
    itself the outage it was meant to survive.
    """
    reply = dict(HELLO, **{flag: value})
    reply.pop("isWritablePrimary", None) if flag == "secondary" else None
    got = rewritten(reply)
    assert got[flag] is value


def test_a_reply_that_is_not_hello_is_left_alone():
    """Fewer rewrites, fewer invented bugs.

    Two things stop an unrelated message being touched, and only one of
    them is load-bearing: the `hello` detection is a fast path, and the
    guarantee is the equality check that returns `None` when no field
    changed. Removing the detection breaks nothing -- which a sabotage run
    established, so the comment in the source says so instead of implying
    a protection that is not there.
    """
    for reply in ({"ok": 1.0, "n": 1},
                  {"cursor": {"id": 0, "ns": "a.b", "firstBatch": []}, "ok": 1.0},
                  {"ok": 0.0, "code": 10107}):
        raw = w.encode_op_msg(1, 2, 0, reply)
        assert w.rewrite_topology(raw, 1, 2, HERE) is None


def test_a_hello_that_is_already_correct_is_not_re_encoded():
    """A standalone advertises no hosts. Re-framing a message that needed no
    change is a chance to introduce a bug for no benefit."""
    standalone = {"isWritablePrimary": True, "maxWireVersion": 25, "ok": 1.0}
    raw = w.encode_op_msg(1, 2, 0, standalone)
    assert w.rewrite_topology(raw, 1, 2, HERE) is None


def test_a_driver_with_no_direct_connection_stays_on_the_boundary(db, tmp_path):
    """End to end, with the default connection string a real application
    uses -- no options, no discipline, nothing to remember."""
    from datetime import timedelta

    from voyd.engine.time import now

    db.notes.insert_many([
        {"tenant_id": "acme", "text": "live"},
        {"tenant_id": "acme", "text": "gone",
         "expire_at": now() - timedelta(days=1)},
    ])
    policy = tmp_path / "voydfile.py"
    policy.write_text("from voyd import guard, deadline, revocable, tenant\n"
                      "@guard('notes')\n"
                      "class N:\n"
                      "    expire_at = deadline()\n"
                      "    forgotten = revocable()\n"
                      "    tenant_id = tenant()\n")
    port = free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "voyd.wire.proxy", "--config", str(policy),
         "--listen", str(port), "--target", mongo_host(), "--advertise-self"],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        until = time.monotonic() + 15
        while time.monotonic() < until:
            try:
                with socket.create_connection(("127.0.0.1", port), 0.2):
                    break
            except OSError:
                time.sleep(0.1)

        # No `directConnection`. This is the string somebody actually writes.
        client = pymongo.MongoClient(f"mongodb://localhost:{port}/",
                                     serverSelectionTimeoutMS=10000)
        try:
            got = sorted(d["text"] for d in
                         client[db.name].notes.find({"tenant_id": "acme"}))
            seen = {f"{s.address[0]}:{s.address[1]}"
                    for s in client.topology_description
                    .server_descriptions().values()}
        finally:
            client.close()

        assert got == ["live"], "the boundary still refuses"
        assert seen == {f"localhost:{port}"}, (
            f"the client found its way to {seen} -- it walked past")
    finally:
        proc.terminate()
        proc.wait(timeout=10)
