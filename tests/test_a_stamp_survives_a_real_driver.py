"""A stamp survives a real driver: pymongo through `voyd-wire`, verified offline.

The live half of `test_a_signed_chunk_cannot_be_edited_after_the_boundary.
py`. The claims that only a real cursor can test: a read spanning several
`getMore` batches is one chain, a projection is stamped as served, a count
is not stamped at all, and nothing the database stores under `_voyd` ever
reaches the client.
"""

from __future__ import annotations

import pytest

pytest.importorskip("cryptography")

import hashlib
from datetime import datetime, timedelta, timezone

from voyd import attest

pytestmark = pytest.mark.needs_mongo

POLICY = """
from voyd import guard, deadline, revocable, mask

@guard("notes", attest=True)
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    ssn       = mask()
"""


@pytest.fixture
def live(boundary, database, direct, tmp_path):
    from pymongo import MongoClient

    private, public, _ = attest.generate()
    key = tmp_path / "attest.pem"
    key.write_bytes(private)
    wire = boundary(POLICY, "--attest-key", str(key))
    client = MongoClient(wire.uri, serverSelectionTimeoutMS=15_000)
    later = datetime.now(timezone.utc) + timedelta(days=1)
    around = direct[database].notes
    around.insert_many(
        [{"_id": i, "text": f"note {i}", "expire_at": later,
          "ssn": f"{i}-secret"} for i in range(7)]
        + [{"_id": 99, "text": "forgotten", "expire_at": later,
            "forgotten": True},
           {"_id": 100, "text": "carries a forged stamp", "expire_at": later,
            "_voyd": {"kid": "forged", "sig": "AAAA"}}])
    try:
        yield (client[database].notes, around,
               attest.load_public_keys(public))
    finally:
        client.close()


def _policy_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def test_a_read_across_batches_is_one_verified_chain(live):
    guarded, _, keys = live
    window = list(guarded.find({}).sort("_id", 1).batch_size(3))
    assert [d["_id"] for d in window] == [0, 1, 2, 3, 4, 5, 6, 100]
    report = attest.verify_all(window, keys, policy=_policy_hash(POLICY))
    assert report.ok, [v.reason for v in report.verdicts]
    assert list(report.reads.values()) == [(8, True)]
    # Masked on the way out, and stamped as the null it left as.
    assert all(d["ssn"] is None for d in window if d["_id"] != 100)
    # The stored forgery was replaced, not forwarded.
    assert window[-1]["_voyd"]["kid"] != "forged"


def test_a_tampered_field_fails_and_an_untouched_one_still_passes(live):
    guarded, _, keys = live
    one, two = list(guarded.find({"_id": {"$in": [1, 2]}}).sort("_id", 1))
    one["text"] = "note 1, as the model was told it"
    assert not attest.verify(one, keys).ok
    assert attest.verify(two, keys).ok


def test_a_projection_is_stamped_as_what_was_served(live):
    guarded, _, keys = live
    doc = guarded.find_one({"_id": 3}, {"text": 1})
    assert set(doc) == {"_id", "text", "_voyd"}
    assert attest.verify(doc, keys).ok


def test_a_count_and_a_group_carry_no_stamp(live):
    guarded, _, _ = live
    assert guarded.count_documents({}) == 8
    grouped = list(guarded.aggregate([{"$group": {"_id": None, "n": {"$sum": 1}}}]))
    assert grouped and "_voyd" not in grouped[0]


def test_a_stamp_is_the_boundarys_and_never_the_rows(live):
    guarded, around, keys = live
    served = guarded.find_one({"_id": 4})
    # A client saves what it read, stamp and all. The row now carries it.
    around.replace_one({"_id": 4}, dict(served, text="edited by the app"))
    assert around.find_one({"_id": 4})["_voyd"] == served["_voyd"]
    again = guarded.find_one({"_id": 4})
    assert again["text"] == "edited by the app"
    assert again["_voyd"]["digest"] != served["_voyd"]["digest"]
    assert attest.verify(again, keys).ok
