"""A prompt that can prove where its chunks came from.

    docker compose up -d mongo
    uv run python examples/attest.py     # ~5 seconds, no API key, no vendor

Every other example shows something the boundary *refused*. A refusal leaves
nothing behind, which is the point and also the problem: a week later, the
prompt that produced a bad answer cannot say whether its context came
through the boundary at all, under which policy, or whether somebody edited
a chunk on the way to the model.

`@guard("notes", attest=True)` makes that a property of the chunk. Every
document served from the collection carries a `_voyd` stamp, signed with an
Ed25519 key the proxy holds, over the document exactly as it was served --
masks applied, transforms run -- plus the policy file's hash and a pseudonym
for who read it. Anyone with the public key can check it, with no proxy and
no database.

Four things, in order:

1. **A plain driver reads through the boundary** and gets stamped
   documents. The client imports `MongoClient`; nothing about the read
   changed.
2. **Verification is offline.** `voyd.attest.verify` is handed a document
   and a public key and nothing else.
3. **One edited field fails.** The stamp's signature is still valid -- it
   is an authentic receipt -- and the digest no longer matches, which is the
   verdict that says *somebody edited this after the boundary*.
4. **A prompt cites its chunks.** `strip()` takes the stamp off before the
   text reaches a model; `cite()` leaves a `voyd:<kid>:<digest8>` behind
   that an auditor can match against the verified set later.

This file asserts rather than prints-and-hopes.
"""

from __future__ import annotations

import copy
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from pymongo import MongoClient

from _boundary import boundary, deployment
from voyd import attest

POLICY = '''
from voyd import guard, deadline, revocable, mask

@guard("notes", attest=True)
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    ssn       = mask()
'''


def main() -> None:
    later = datetime.now(timezone.utc) + timedelta(days=1)
    with tempfile.TemporaryDirectory() as tmp, \
            deployment("attest") as (direct, name):
        private, public, kid = attest.generate()
        key = Path(tmp) / "attest.pem"
        key.write_bytes(private)
        keys = attest.load_public_keys(public)

        direct[name].notes.insert_many([
            {"_id": 1, "text": "the fault code is P0301", "expire_at": later},
            {"_id": 2, "text": "replace the coil pack on cylinder 1",
             "expire_at": later, "ssn": "123-45-6789"},
            {"_id": 3, "text": "this one was revoked", "expire_at": later,
             "forgotten": True},
        ])

        with boundary(POLICY, "--attest-key", str(key)) as uri:
            client = MongoClient(uri, serverSelectionTimeoutMS=8000)
            try:
                window = list(client[name].notes.find({}).sort("_id", 1))
            finally:
                client.close()

    print(f"\n  Served {len(window)} documents under key {kid}.\n")
    assert [d["_id"] for d in window] == [1, 2]
    assert window[1]["ssn"] is None, "the mask ran before the stamp"

    # 2. Offline: a document and a public key, nothing else.
    report = attest.verify_all(window, keys)
    assert report.ok, [v.reason for v in report.verdicts]
    for verdict in report.verdicts:
        print(f"  ok    {verdict.citation}  {verdict.reason}")

    # 3. One field, edited after the boundary.
    tampered = copy.deepcopy(window[0])
    tampered["text"] = "the fault code is P0420"
    verdict = attest.verify(tampered, keys)
    assert not verdict.ok and verdict.reason.startswith("digest mismatch")
    print(f"  FAIL  {verdict.citation}  {verdict.reason}")

    restored = dict(window[1], ssn="123-45-6789")
    assert not attest.verify(restored, keys).ok
    print("  FAIL  a masked value put back is not what was served\n")

    # 4. The prompt: text without stamps, a citation per chunk.
    prompt = "\n".join(f"[{attest.cite(d)}] {attest.strip(d)['text']}"
                       for d in window)
    assert "_voyd" not in prompt and "sig" not in prompt
    print("  The prompt a model would see:\n")
    for line in prompt.splitlines():
        print(f"    {line}")
    print()


if __name__ == "__main__":
    main()
