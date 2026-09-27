"""An export with the PII taken out in the boundary, not in the client.

    docker compose up -d mongo
    uv run python examples/operators/pii_safe_export.py

Support tickets hold emails, phone numbers, SSNs and card numbers in free
text, and a `card_number` field. The policy masks the field with `mask()`
and installs `voyd.contrib.text`; the export is one `aggregate`:

    $match {tenant_id: acme}                          mongod
    $addFields {body: {$normalizeWhitespace}}         the boundary
    $addFields {body: {$redactPII}}                   the boundary
    $addFields {preview: {$truncate}, words: ...}     the boundary

So what leaves is redacted even for a client that forgot to redact, and a
digit run that fails the Luhn check -- an order number -- is left alone.
The direct connection shows the originals are still on disk: this is a
read-path guarantee, not a rewrite of the data. A revoked ticket is not
exported at all.

Limits, as `voyd/contrib/text.py` states them: patterns, not a classifier.
Names and street addresses are not detected.
"""

from __future__ import annotations

import sys
from datetime import timedelta
from pathlib import Path

from pymongo import MongoClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _boundary import boundary, deployment  # noqa: E402

from voyd.engine.time import now  # noqa: E402

POLICY = '''
from voyd import guard, mask, revocable, tenant
from voyd.contrib import text

text.install("$redactPII", "$normalizeWhitespace", "$truncate",
             "$wordCount")

@guard("tickets")
class Tickets:
    forgotten   = revocable()
    tenant_id   = tenant()
    card_number = mask()
'''

TICKETS = [
    "Customer  ana@acme.example   called from (555) 123-4567 about a\n"
    "double charge on card 4111 1111 1111 1111. Order 4111 1111 1111 1112.",
    "SSN 123-45-6789 was pasted into the chat by mistake; the login came "
    "from 203.0.113.9.",
    "No personal data here, just a refund for order 1234567890123.",
]
REVOKED = "Escalation notes for bob@acme.example, removed on request."

PIPELINE = [
    {"$match": {"tenant_id": "acme"}},
    {"$addFields": {"body": {"$normalizeWhitespace": "$body"}}},
    {"$addFields": {"body": {"$redactPII": "$body"}}},
    {"$addFields": {"preview": {"$truncate": {"input": "$body",
                                              "length": 48}},
                    "words": {"$wordCount": "$body"}}},
]


def main() -> None:
    with deployment("pii_export") as (direct, db):
        past = now() - timedelta(days=1)
        direct[db].tickets.insert_many(
            [{"_id": i, "tenant_id": "acme", "body": b,
              "card_number": "4111111111111111"}
             for i, b in enumerate(TICKETS, 1)]
            + [{"_id": 9, "tenant_id": "acme", "body": REVOKED,
                "forgotten": {"at": past, "reason": "erasure request"}}])
        with boundary(POLICY, "--quiet") as uri:
            client = MongoClient(uri, serverSelectionTimeoutMS=8000)
            rows = list(client[db].tickets.aggregate(PIPELINE))
            client.close()

        print("\n  Exported through the boundary:\n")
        for r in rows:
            print(f"  #{r['_id']} ({r['words']} words) {r['body']}")
            print(f"      preview: {r['preview']}")
        dump = repr(rows)
        for secret in ("ana@acme.example", "123-4567", "123-45-6789",
                       "4111 1111 1111 1111", "203.0.113.9",
                       "4111111111111111", "bob@acme.example"):
            assert secret not in dump, secret
        assert "4111 1111 1111 1112" in dump, "a Luhn-invalid run was eaten"
        assert "1234567890123" in dump
        assert all(r["card_number"] is None for r in rows)
        assert sorted(r["_id"] for r in rows) == [1, 2, 3]

        raw = direct[db].tickets.find_one({"_id": 1})
        assert "ana@acme.example" in raw["body"]
        print("\n  no email, phone, SSN, card or IP left; the order numbers "
              "that fail Luhn are intact;\n  the masked card_number is null; "
              "the revoked ticket is absent; the originals are on disk\n")


if __name__ == "__main__":
    main()
