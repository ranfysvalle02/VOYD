"""A receipt names whom an agent read for, and by whom -- without naming them.

A delegated read's stamp carries ``principal``, ``actor`` and ``token``
beside ``caller``, which stays the connection. All three are signed, so
none can be changed; each is a hash, so the stamp names nobody; and
``voyd-verify --principal/--actor`` recomputes them, so an auditor who
knows whom to ask about can prove it. A v1 stamp, made before those
fields existed, still verifies.

Pure, except the last test, which is the live half: a real driver, a real
``voyd-wire``, a delegated read, and ``voyd-verify`` on what came back.
"""

from __future__ import annotations

import pytest

pytest.importorskip("cryptography")

import copy
import subprocess
import sys
from datetime import datetime

from bson import Int64, json_util

from voyd import attest
from voyd.engine.admission import AdmissionSpec
from voyd.engine.admission.rules import Deadline
from voyd.testing import TestIssuer
from voyd.wire.codec import decode_op_msg, encode_op_msg
from voyd.wire.policy import Guard
from voyd.wire.stamp import Signer, Stamps

POLICY = "a" * 64
FUTURE = datetime(2099, 1, 1)
PRIVATE, PUBLIC, KID = attest.generate()
KEY = attest.load_private_key(PRIVATE)
KEYS = attest.load_public_keys(PUBLIC)

SERVER = {"user": "svc-agent", "db": "admin", "roles": [], "groups": []}
DELEGATED = {"user": "alice", "roles": ["support"], "delegated": True,
             "principal": {"user": "alice", "roles": ["support"]},
             "actor": {"user": "support-bot", "roles": ["support"]},
             "scopes": ["notes:read"], "issuer": "https://login.test",
             "token": "f" * 64}


def guard() -> Guard:
    g = Guard(AdmissionSpec("notes", rules=(Deadline("expire_at"),),
                            attest=True))
    g.signer = Signer(KEY, POLICY)
    return g


def served(claims, connection=SERVER, n: int = 2) -> list:
    g = guard()
    guards = {"notes": g}
    stamps = Stamps()
    stamps.note({"find": "notes", "$db": "app"}, 1, guards)
    docs = [{"_id": i, "text": f"note {i}", "expire_at": FUTURE}
            for i in range(n)]
    raw = encode_op_msg(900, 1, 0, {"cursor": {
        "firstBatch": docs, "id": Int64(0), "ns": "app.notes"}, "ok": 1.0})
    out = stamps.stamp(raw, 1, guards, claims, connection)
    decoded = decode_op_msg(out)
    assert decoded is not None
    return decoded[1]["cursor"]["firstBatch"]


def test_a_delegated_stamp_names_both_parties_and_the_token_by_hash():
    stamp = served(DELEGATED)[0]["_voyd"]
    assert stamp["v"] == 2
    assert stamp["principal"] == attest.principal_hash("alice")
    assert stamp["actor"] == attest.actor_hash("support-bot")
    assert stamp["token"] == "f" * 64
    # The caller is the connection the read arrived on, not the principal.
    assert stamp["caller"] == attest.caller_hash("svc-agent", "admin")
    text = str(stamp)
    assert "alice" not in text and "support-bot" not in text


def test_the_three_hashes_are_domain_separated():
    same = "alice"
    assert len({attest.principal_hash(same), attest.actor_hash(same),
                attest.caller_hash(same, None)}) == 3
    assert attest.principal_hash(None) is None
    assert attest.actor_hash("") is None


def test_a_plain_read_carries_null_parties_and_its_caller():
    stamp = served(SERVER)[0]["_voyd"]
    assert (stamp["principal"], stamp["actor"], stamp["token"]) == (
        None, None, None)
    assert stamp["caller"] == attest.caller_hash("svc-agent", "admin")
    assert attest.verify(served(SERVER)[0], KEYS).ok


@pytest.mark.parametrize("field", ["principal", "actor", "token", "caller"])
def test_tampering_with_any_party_breaks_the_signature(field):
    doc = copy.deepcopy(served(DELEGATED)[0])
    doc["_voyd"][field] = "0" * 64
    verdict = attest.verify(doc, KEYS)
    assert not verdict.ok and verdict.reason.startswith("bad signature")


@pytest.mark.parametrize("field", ["principal", "actor", "token"])
def test_dropping_a_party_is_a_malformed_stamp(field):
    doc = copy.deepcopy(served(DELEGATED)[0])
    del doc["_voyd"][field]
    verdict = attest.verify(doc, KEYS)
    assert not verdict.ok and "missing" in verdict.reason


def test_verify_checks_the_principal_and_actor_when_asked():
    doc = served(DELEGATED)[0]
    assert attest.verify(doc, KEYS).ok
    assert attest.verify(doc, KEYS, principal="alice").ok
    assert attest.verify(doc, KEYS, principal="alice",
                         actor="support-bot").ok
    wrong = attest.verify(doc, KEYS, principal="bob")
    assert not wrong.ok and wrong.reason.startswith("principal mismatch")
    wrong = attest.verify(doc, KEYS, actor="billing-bot")
    assert not wrong.ok and wrong.reason.startswith("actor mismatch")
    plain = attest.verify(served(SERVER)[0], KEYS, principal="alice")
    assert not plain.ok and plain.reason.startswith("not delegated")


def test_a_version_one_stamp_still_verifies_and_cannot_answer_for_a_party():
    doc = {"_id": 1, "text": "old"}
    v1 = {"v": 1, "alg": attest.ALG, "kid": KID, "policy": POLICY,
          "ns": "app.notes", "id": 1, "digest": attest.digest(doc),
          "caller": None, "iat": "2026-01-01T00:00:00.000Z",
          "read": "0" * 16, "pos": 0, "prev": None}
    stamped = {**doc, "_voyd": attest.sign(v1, KEY)}
    assert set(stamped["_voyd"]) == {*v1, "sig"}
    assert attest.verify(stamped, KEYS).ok
    asked = attest.verify(stamped, KEYS, principal="alice")
    assert not asked.ok and "v1 stamp does not record" in asked.reason
    # And a v1 chain links as it always did.
    second = {**v1, "pos": 1, "id": 2, "digest": attest.digest(
        {"_id": 2, "text": "old"}), "prev": attest.link(stamped["_voyd"])}
    report = attest.verify_all(
        [stamped, {"_id": 2, "text": "old",
                   "_voyd": attest.sign(second, KEY)}], KEYS)
    assert report.ok and not report.broken_links


def test_relabelling_a_v2_stamp_as_v1_breaks_the_signature():
    doc = copy.deepcopy(served(DELEGATED)[0])
    doc["_voyd"]["v"] = 1
    assert not attest.verify(doc, KEYS).ok


def _cli(tmp_path, docs, *flags):
    keys = tmp_path / "attest.pub"
    keys.write_bytes(PUBLIC)
    window = tmp_path / "window.jsonl"
    window.write_text("".join(json_util.dumps(d) + "\n" for d in docs))
    return subprocess.run([sys.executable, "-m", "voyd.verify", "--keys",
                           str(keys), *flags, str(window)],
                          capture_output=True, text=True)


def test_voyd_verify_checks_principal_and_actor_flags(tmp_path):
    docs = served(DELEGATED, n=3)
    assert _cli(tmp_path, docs).returncode == 0
    ok = _cli(tmp_path, docs, "--principal", "alice", "--actor",
              "support-bot")
    assert ok.returncode == 0 and "3 of 3 verified" in ok.stdout
    bad = _cli(tmp_path, docs, "--principal", "bob")
    assert bad.returncode == 1 and "principal mismatch" in bad.stdout
    bad = _cli(tmp_path, docs, "--actor", "billing-bot")
    assert bad.returncode == 1 and "actor mismatch" in bad.stdout
    plain = _cli(tmp_path, served(SERVER), "--principal", "alice")
    assert plain.returncode == 1 and "not delegated" in plain.stdout


# ---- live ----------------------------------------------------------------

IDP = TestIssuer("https://login.receipts.test", audience="voyd://receipts")

LIVE = '''
from voyd import guard, issuer, revocable

issuer("{url}", audience="{aud}", jwks="{jwks}", connection_users=("*",))

@guard("notes", attest=True)
class Notes:
    forgotten = revocable()
'''


@pytest.mark.needs_mongo
def test_a_real_delegated_read_verifies_as_alice_through_support_bot(
        boundary, direct, database, tmp_path):
    from pymongo import MongoClient

    jwks = IDP.write_jwks(str(tmp_path / "jwks.json"))
    key = tmp_path / "attest.pem"
    key.write_bytes(PRIVATE)
    direct[database].notes.insert_many([{"_id": i, "text": f"n{i}"}
                                        for i in range(3)])
    wire = boundary(LIVE.format(url=IDP.url, aud=IDP.audience, jwks=jwks),
                    "--attest-key", str(key))
    client = MongoClient(wire.uri, serverSelectionTimeoutMS=15_000)
    try:
        token = IDP.mint("alice", actor="support-bot")
        docs = list(client[database].notes.find({}, comment={"voyd": token}))
    finally:
        client.close()
    assert len(docs) == 3
    assert all(d["_voyd"]["principal"] == attest.principal_hash("alice")
               for d in docs)
    ok = _cli(tmp_path, docs, "--principal", "alice", "--actor",
              "support-bot")
    assert ok.returncode == 0, ok.stdout
    assert _cli(tmp_path, docs, "--principal", "mallory").returncode == 1
