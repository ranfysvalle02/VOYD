"""A signed chunk cannot be edited after the boundary, and nobody can mint one.

Pure: no cluster, no proxy process. The stamper is driven with the same
OP_MSG bytes the transport hands it, and the verifier is handed documents
exactly as a driver would have decoded them.
`test_a_stamp_survives_a_real_driver.py` is the live half.
"""

from __future__ import annotations

import pytest

pytest.importorskip("cryptography")

import copy
import json
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone

from bson import Binary, Decimal128, Int64, ObjectId, json_util

from voyd import attest
from voyd.engine.admission import AdmissionSpec
from voyd.engine.admission.masks import Mask
from voyd.engine.admission.rules import Deadline, revoked
from voyd.engine.plan import ATTEST_REMOVED, structural
from voyd.wire.codec import decode_op_msg, encode_op_msg
from voyd.wire.policy import Guard
from voyd.wire.stamp import Signer, Stamps, stampable

POLICY = "a" * 64
FUTURE = datetime(2099, 1, 1)


def keypair():
    private, public, kid = attest.generate()
    return attest.load_private_key(private), public, kid


KEY, PUBLIC, KID = keypair()
KEYS = attest.load_public_keys(PUBLIC)


def guard(*, masks=(), transforms=(), signer=True) -> Guard:
    g = Guard(AdmissionSpec("notes", rules=(Deadline("expire_at"),
                                            revoked("forgotten")),
                            masks=tuple(masks), transforms=tuple(transforms),
                            attest=True))
    if signer:
        g.signer = Signer(KEY, POLICY)
    return g


def reply(docs, *, cursor_id=0, first=True, resp_to=1) -> bytes:
    key = "firstBatch" if first else "nextBatch"
    return encode_op_msg(900, resp_to, 0, {
        "cursor": {key: docs, "id": Int64(cursor_id), "ns": "app.notes"},
        "ok": 1.0})


def batch_of(raw: bytes) -> list:
    decoded = decode_op_msg(raw)
    assert decoded is not None
    cursor = decoded[1]["cursor"]
    return cursor.get("firstBatch", cursor.get("nextBatch"))


def served(docs, g=None, *, claims=None) -> list:
    """What the boundary hands a client for one `find`, stamps included."""
    g = g or guard()
    guards = {"notes": g}
    stamps = Stamps()
    stamps.note({"find": "notes", "$db": "app"}, 1, guards)
    kept = g.filter(list(docs), claims)
    return batch_of(stamps.stamp(reply(kept), 1, guards, claims))


def note(n=0, **extra):
    return {"_id": n, "text": f"note {n}", "expire_at": FUTURE, **extra}


# ---- canonical form ---------------------------------------------------

RICH = {
    "_id": ObjectId("65f000000000000000000001"),
    "z": 1, "a": {"y": [1, 2.5, "三"], "b": None},
    "when": datetime(2026, 9, 27, 12, 0, 0, 123000),
    "money": Decimal128("10.10"),
    "blob": Binary(b"\x00\x01", 0),
    "big": Int64(2 ** 40),
    "flag": True,
    "emoji": "café \U0001f600",
}


def test_key_order_does_not_change_the_digest():
    shuffled = dict(reversed(list(RICH.items())))
    shuffled["a"] = {"b": None, "y": [1, 2.5, "三"]}
    assert attest.digest(shuffled) == attest.digest(RICH)


def test_every_bson_type_a_driver_hands_back_survives_extended_json():
    for mode in (json_util.CANONICAL_JSON_OPTIONS,
                 json_util.RELAXED_JSON_OPTIONS):
        back = json_util.loads(json_util.dumps(RICH, json_options=mode))
        assert attest.digest(back) == attest.digest(RICH), mode


def test_an_aware_and_a_naive_utc_datetime_are_the_same_instant():
    aware = dict(RICH, when=RICH["when"].replace(tzinfo=timezone.utc))
    assert attest.digest(aware) == attest.digest(RICH)


def test_integer_width_is_not_content_but_every_value_is():
    assert attest.digest({"n": Int64(5)}) == attest.digest({"n": 5})
    assert attest.digest({"n": 5.0}) == attest.digest({"n": 5})
    assert attest.digest({"n": 5}) != attest.digest({"n": "5"})
    assert attest.digest({"n": True}) != attest.digest({"n": 1})
    assert attest.digest({"n": None}) != attest.digest({})
    assert attest.digest({"s": "é"}) != attest.digest({"s": "é"})
    assert attest.digest({"a": [1, 2]}) != attest.digest({"a": [2, 1]})


def test_the_digest_is_stable_across_releases():
    # Pinned. A change to the canonical form invalidates every stamp ever
    # issued, so it has to be a deliberate edit of this number.
    assert attest.digest({"_id": 1, "text": "hello"}) == attest.digest(
        {"text": "hello", "_id": Int64(1)})
    assert attest.canonical({"_id": 1, "text": "hello"}) == (
        b'["o",[["_id",["n","1"]],["text",["s","hello"]]]]')


def test_a_value_the_canonical_form_cannot_name_is_refused():
    with pytest.raises(TypeError):
        attest.canonical({"x": object()})


# ---- tamper detection -------------------------------------------------

def test_a_served_document_verifies():
    doc = served([note(1)])[0]
    verdict = attest.verify(doc, KEYS, policy=POLICY)
    assert verdict.ok, verdict.reason
    assert verdict.citation == f"voyd:{KID}:{doc['_voyd']['digest'][:8]}"
    assert attest.cite(doc) == verdict.citation


@pytest.mark.parametrize("edit", [
    lambda d: d.__setitem__("text", "note 1 (edited)"),
    lambda d: d.__setitem__("added", 1),
    lambda d: d.pop("expire_at"),
    lambda d: d.__setitem__("expire_at", FUTURE + timedelta(milliseconds=1)),
])
def test_editing_any_field_of_the_document_is_caught(edit):
    doc = copy.deepcopy(served([note(1)])[0])
    edit(doc)
    verdict = attest.verify(doc, KEYS)
    assert not verdict.ok and verdict.reason.startswith("digest mismatch")


def test_moving_a_stamp_onto_another_document_is_caught():
    one, two = served([note(1), note(2)])
    forged = dict(two, _voyd=one["_voyd"])
    assert not attest.verify(forged, KEYS).ok
    # Same content, different _id: the digest covers _id, so it is caught
    # there; the id check is the second line of defence.
    same = dict(one, _id=99)
    assert not attest.verify(same, KEYS).ok


@pytest.mark.parametrize("field,value", [
    ("policy", "b" * 64), ("ns", "app.other"), ("caller", "c" * 64),
    ("iat", "2020-01-01T00:00:00.000Z"), ("pos", 7), ("read", "0" * 16),
    ("prev", "d" * 64), ("digest", "e" * 64), ("id", 2),
])
def test_editing_any_field_of_the_stamp_breaks_its_signature(field, value):
    doc = copy.deepcopy(served([note(1)])[0])
    doc["_voyd"][field] = value
    verdict = attest.verify(doc, KEYS)
    assert not verdict.ok and verdict.reason.startswith("bad signature")


def test_an_unstamped_or_malformed_document_never_passes():
    assert attest.verify(note(1), KEYS).reason.startswith("unstamped")
    doc = copy.deepcopy(served([note(1)])[0])
    del doc["_voyd"]["sig"]
    assert attest.verify(doc, KEYS).reason.startswith("malformed")


def test_a_stale_policy_is_named_when_one_is_expected():
    doc = served([note(1)])[0]
    verdict = attest.verify(doc, KEYS, policy="f" * 64)
    assert not verdict.ok and verdict.reason.startswith("stale policy")
    assert attest.verify(doc, KEYS, policy=["f" * 64, POLICY]).ok


# ---- keys and rotation ------------------------------------------------

def test_a_stamp_from_a_key_the_verifier_does_not_hold_is_unknown():
    _, other_public, _ = keypair()
    doc = served([note(1)])[0]
    verdict = attest.verify(doc, attest.load_public_keys(other_public))
    assert not verdict.ok and verdict.reason.startswith("unknown kid")


def test_relabelling_a_stamp_with_a_held_kid_fails_the_signature():
    _, other_public, other_kid = keypair()
    doc = copy.deepcopy(served([note(1)])[0])
    doc["_voyd"]["kid"] = other_kid
    both = attest.load_public_keys(PUBLIC + other_public)
    assert attest.verify(doc, both).reason.startswith("bad signature")


def test_rotation_is_a_bundle_holding_both_keys_until_the_old_one_retires():
    new_key, new_public, new_kid = keypair()
    old_doc = served([note(1)])[0]
    rotated = guard()
    rotated.signer = Signer(new_key, POLICY)
    new_doc = served([note(2)], rotated)[0]
    bundle = attest.load_public_keys(PUBLIC + new_public)
    assert set(bundle) == {KID, new_kid}
    assert attest.verify(old_doc, bundle).ok
    assert attest.verify(new_doc, bundle).ok
    retired = attest.load_public_keys(new_public)
    assert not attest.verify(old_doc, retired).ok
    assert attest.verify(new_doc, retired).ok


def test_the_kid_is_derived_from_the_key_not_assigned():
    assert KID == attest.kid_of(KEY.public_key())
    assert len(KID) == 16


# ---- what cannot forge a stamp ----------------------------------------

class Forger:
    """A transform that tries to hand a client a stamp of its own."""

    name = "forger"

    def __init__(self, stamp):
        self.stamp = stamp

    def on_egress(self, docs, *, request):
        return [dict(d, _voyd=self.stamp, text="rewritten by a transform")
                for d in docs]


def test_a_transform_cannot_keep_or_forge_a_stamp():
    genuine = served([note(1)])[0]["_voyd"]
    out = served([note(1)], guard(transforms=(Forger(genuine),)))[0]
    # The transform's rewrite is served -- transforms may shape a page --
    # but under a stamp the boundary made over the rewritten text.
    assert out["text"] == "rewritten by a transform"
    assert out["_voyd"] != genuine
    assert attest.verify(out, KEYS).ok


def test_a_stamp_stored_in_the_row_is_stripped_before_anything_sees_it():
    seen = []

    class Looker:
        name = "looker"

        def on_egress(self, docs, *, request):
            seen.extend("_voyd" in d for d in docs)
            return docs

    stored = note(1, _voyd={"kid": "forged", "sig": "x"})
    out = served([stored], guard(transforms=(Looker(),)))[0]
    assert seen == [False]
    assert out["_voyd"]["kid"] == KID and attest.verify(out, KEYS).ok


def test_a_client_that_saves_what_it_read_does_not_launder_an_edit():
    doc = copy.deepcopy(served([note(1)])[0])
    doc["text"] = "edited, then saved back with its old stamp"
    again = served([doc])[0]
    # Re-served, the edit is stamped as what it now is -- and the old stamp
    # still refuses to vouch for the edited text.
    assert attest.verify(again, KEYS).ok
    assert again["_voyd"]["digest"] != served([note(1)])[0]["_voyd"]["digest"]


# ---- masks ------------------------------------------------------------

def test_a_masked_value_is_stamped_as_the_null_it_left_as():
    out = served([note(1, ssn="123-45-6789")],
                 guard(masks=(Mask("ssn"),)))[0]
    assert out["ssn"] is None and attest.verify(out, KEYS).ok
    # A client that "restores" the value cannot then claim it was served.
    restored = dict(out, ssn="123-45-6789")
    assert not attest.verify(restored, KEYS).ok


def test_a_stripped_mask_is_stamped_as_absent():
    out = served([note(1, ssn="x")], guard(masks=(Mask("ssn", strip=True),)))[0]
    assert "ssn" not in out and attest.verify(out, KEYS).ok
    assert not attest.verify(dict(out, ssn=None), KEYS).ok


# ---- reads, batches, and what is not stamped --------------------------

def test_a_read_across_getmore_is_one_chain():
    g = guard()
    guards = {"notes": g}
    stamps = Stamps()
    stamps.note({"find": "notes", "batchSize": 2, "$db": "app"}, 1, guards)
    first = batch_of(stamps.stamp(reply([note(0), note(1)], cursor_id=77),
                                  1, guards, None))
    stamps.note({"getMore": Int64(77), "collection": "notes"}, 2, guards)
    second = batch_of(stamps.stamp(
        reply([note(2), note(3)], cursor_id=77, first=False, resp_to=2),
        2, guards, None))
    stamps.note({"getMore": Int64(77), "collection": "notes"}, 3, guards)
    last = batch_of(stamps.stamp(
        reply([note(4)], cursor_id=0, first=False, resp_to=3),
        3, guards, None))
    window = first + second + last
    assert [d["_voyd"]["pos"] for d in window] == [0, 1, 2, 3, 4]
    assert len({d["_voyd"]["read"] for d in window}) == 1
    report = attest.verify_all(window, KEYS)
    assert report.ok and list(report.reads.values()) == [(5, True)]
    assert g.stamped == 5
    # Drained: the cursor's chain is forgotten, not kept for the life of
    # the connection.
    assert not stamps._open


def test_a_subset_of_a_read_verifies_and_says_it_is_a_subset():
    window = served([note(i) for i in range(4)])
    report = attest.verify_all([window[0], window[2]], KEYS)
    assert report.ok and list(report.reads.values()) == [(2, False)]


def test_a_stamp_from_another_read_cannot_be_spliced_into_a_chain():
    a = served([note(0), note(1)])
    b = served([note(0), note(1)])
    report = attest.verify_all([a[0], b[1]], KEYS)
    # Different reads: each verifies alone, and neither is whole.
    assert report.ok and sorted(report.reads.values()) == [(1, False),
                                                           (1, True)]
    # The same read, reordered, is still one chain: order in the list is
    # not order in the read.
    assert attest.verify_all([a[1], a[0]], KEYS).ok


def test_two_documents_of_one_read_cannot_trade_positions():
    a = served([note(0), note(1), note(2)])
    swapped = copy.deepcopy(a)
    swapped[1]["_voyd"]["prev"] = "0" * 64
    assert not attest.verify_all(swapped, KEYS).ok


def test_reads_whose_output_is_not_a_stored_document_are_not_stamped():
    assert stampable({"find": "notes"}) == "notes"
    assert stampable({"aggregate": "notes", "pipeline": [
        {"$match": {}}, {"$project": {"text": 1}}]}) == "notes"
    for pipeline in ([{"$group": {"_id": "$tenant"}}], [{"$count": "n"}],
                     [{"$unwind": "$tags"}], [{"$replaceRoot": {}}]):
        assert stampable({"aggregate": "notes", "pipeline": pipeline}) is None
    assert stampable({"count": "notes"}) is None
    assert stampable({"distinct": "notes", "key": "text"}) is None


def test_a_collection_that_did_not_attest_is_forwarded_byte_for_byte():
    g = guard(signer=False)
    stamps = Stamps()
    stamps.note({"find": "notes"}, 1, {"notes": g})
    raw = reply([note(1)])
    assert stamps.stamp(raw, 1, {"notes": g}, None) is raw


def test_the_caller_is_a_pseudonym_the_server_reported():
    out = served([note(1)], claims={"user": "alice", "db": "admin"})[0]
    assert out["_voyd"]["caller"] == attest.caller_hash("alice", "admin")
    assert "alice" not in json.dumps(out["_voyd"])
    assert served([note(1)])[0]["_voyd"]["caller"] is None


def test_strip_is_what_a_prompt_is_built_from():
    doc = served([note(1)])[0]
    assert "_voyd" not in attest.strip(doc) and "_voyd" in doc


# ---- the plan, the CLI --------------------------------------------------

def test_turning_attestation_off_is_a_finding_and_not_a_fail_open():
    on = {"notes": AdmissionSpec("notes", rules=(Deadline("expire_at"),),
                                 attest=True)}
    off = {"notes": AdmissionSpec("notes", rules=(Deadline("expire_at"),))}
    found = structural(on, off)
    assert [f.kind for f in found] == [ATTEST_REMOVED]
    assert not found[0].fails_open


def test_voyd_verify_passes_a_clean_window_and_fails_a_tampered_one(tmp_path):
    keys = tmp_path / "attest.pub"
    keys.write_bytes(PUBLIC)
    window = served([note(i, money=Decimal128("1.5"),
                          oid=ObjectId()) for i in range(3)])
    clean = tmp_path / "clean.jsonl"
    clean.write_text("".join(json_util.dumps(d) + "\n" for d in window))
    run = [sys.executable, "-m", "voyd.verify", "--keys", str(keys),
           "--policy", POLICY]
    ok = subprocess.run([*run, str(clean)], capture_output=True, text=True)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert "3 of 3 verified" in ok.stdout

    window[1]["text"] = "tampered"
    bad = tmp_path / "bad.jsonl"
    bad.write_text("".join(json_util.dumps(d) + "\n" for d in window))
    failed = subprocess.run([*run, str(bad)], capture_output=True, text=True)
    assert failed.returncode == 1
    assert "FAIL line 2" in failed.stdout and "digest mismatch" in failed.stdout


def test_voyd_wire_refuses_to_attest_without_a_key(tmp_path):
    policy = tmp_path / "voydfile.py"
    policy.write_text(
        "from voyd import guard, deadline\n"
        "@guard('notes', attest=True)\n"
        "class Notes:\n    expire_at = deadline()\n")
    out = subprocess.run([sys.executable, "-m", "voyd.wire", "--config",
                          str(policy), "--listen", "1"],
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 2 and "--attest-key" in out.stderr


def test_keygen_writes_a_pair_and_never_overwrites(tmp_path):
    path = str(tmp_path / f"k{uuid.uuid4().hex[:4]}")
    run = [sys.executable, "-m", "voyd.wire", "--attest-keygen", path]
    first = subprocess.run(run, capture_output=True, text=True, timeout=60)
    assert first.returncode == 0, first.stderr
    pub = attest.load_public_keys(open(path + ".pub", "rb").read())
    key = attest.load_private_key(open(path, "rb").read())
    assert list(pub) == [attest.kid_of(key.public_key())]
    again = subprocess.run(run, capture_output=True, text=True, timeout=60)
    assert again.returncode == 2
