"""A document is admitted and one of its values is not.

`mask()` is the first declaration here that rewrites an admitted document
instead of deciding whether to admit it. That makes it the first one with
two new ways to fail, and this file is about both:

    the value comes back anyway -- through a transform that restores it, a
    batch the fast path forwarded untouched, a reduced reply nobody judged;

    the value comes back as something else -- a yes/no from a filter, an
    order from a sort, a list from `distinct`, a group key, a renamed copy.

The first is closed by where the mask runs: inside `_admit`, after every
rule, on every pass, so there is nowhere after it for a transform to
stand. The second is closed by refusing the command before it is sent.
Both are asserted below against adversarial shapes rather than tidy ones.

Pure: no cluster, no driver, no network. The live half is in
`test_a_real_driver_through_a_real_boundary.py`.
"""

from __future__ import annotations

import textwrap
from datetime import datetime, timedelta, timezone

import bson
import pytest

from voyd.declare import OPTIONS, REGISTRY, TRANSFORMS, load
from voyd.engine.admission import AdmissionSpec
from voyd.engine.admission.core import AdmissionCore
from voyd.engine.admission.masks import Mask
from voyd.engine.admission.rules import Deadline, revoked
from voyd.engine.plan import (MASK_ADDED, MASK_LOOSENED, MASK_REMOVED,
                              structural)
from voyd.wire.codec import (decode_op_msg, encode_op_msg,
                             encode_sections)
from voyd.wire.policy import (Guard, enforce, mask_reduced,
                              refuse_masked_reference, unsuppliable_claims)

UTC = timezone.utc
NOW = datetime(2026, 9, 26, tzinfo=UTC)
FUTURE = NOW + timedelta(days=7)
PAST = NOW - timedelta(days=7)

SSN = "123-45-6789"


def contract(_id, **extra):
    return {"_id": _id, "text": "terms", "expire_at": FUTURE,
            "ssn": SSN, "internal": "do not share", **extra}


MASKS = (Mask("ssn"), Mask("internal", strip=True))


def core(*transforms, masks=MASKS) -> AdmissionCore:
    return AdmissionCore(db=None, spec=AdmissionSpec(
        "contracts", rules=(Deadline("expire_at"), revoked("forgotten")),
        masks=masks, transforms=tuple(transforms)))


class Named:
    def __init__(self, name, fn):
        self.name = name
        self._fn = fn

    def on_egress(self, docs, *, request):
        return self._fn(docs)


@pytest.fixture(autouse=True)
def _clean_registry():
    REGISTRY.clear()
    OPTIONS.clear()
    TRANSFORMS.clear()
    yield
    REGISTRY.clear()
    OPTIONS.clear()
    TRANSFORMS.clear()


# ---- the declaration ---------------------------------------------------

def _policy(tmp_path, body: str) -> dict:
    path = tmp_path / "voydfile.py"
    path.write_text(textwrap.dedent(body))
    return load(str(path))


def test_the_declaration_compiles_to_masks_beside_the_rules(tmp_path):
    specs = _policy(tmp_path, """
        from voyd import guard, deadline, tenant, mask

        @guard("contracts")
        class Contracts:
            expire_at = deadline()
            tenant_id = tenant()
            ssn       = mask()
            internal  = mask(strip=True)
            salary    = mask(visible_to="hr")
        """)
    spec = specs["contracts"]
    assert spec.masks == (Mask("ssn"), Mask("internal", strip=True),
                          Mask("salary", visible_to=("hr",)))
    # A mask is not a rule: the refusal reasons are what they were.
    assert [r.reason for r in spec.rules] == ["deadline"]
    assert "masks [ssn (null), internal (strip)" in spec.describe()


def test_a_collection_that_only_masks_is_a_guard(tmp_path):
    # It refuses nothing of its own, and it is still not a slower read.
    specs = _policy(tmp_path, """
        from voyd import guard, mask

        @guard("people")
        class People:
            ssn = mask()
        """)
    assert specs["people"].masks == (Mask("ssn"),)


def test_masking_the_id_is_refused_at_load(tmp_path):
    with pytest.raises(ValueError, match="_id"):
        _policy(tmp_path, """
            from voyd import guard, deadline, mask

            @guard("contracts")
            class Contracts:
                expire_at = deadline()
                _id       = mask()
            """)


def test_an_empty_audience_is_refused_rather_than_read_as_nobody():
    from voyd import mask

    with pytest.raises(ValueError, match="empty audience"):
        mask(visible_to=())


# ---- the engine: the value does not come back ---------------------------

def test_the_document_is_admitted_and_the_value_is_not():
    handle = core()
    stored = contract(1)
    [served] = handle.reachable([stored], when=NOW)
    assert served["ssn"] is None                    # kept, says nothing
    assert "internal" not in served                 # not even there
    assert served["text"] == "terms"
    # Never a mutation: the caller's own dict still holds the value.
    assert stored["ssn"] == SSN
    assert handle.receipts()["masked_total"] == 2
    assert not any(k.startswith("__") for k in served)


def test_a_refused_document_is_still_refused_and_not_masked_into_a_pass():
    handle = core()
    served = handle.reachable([contract(1), contract(2, expire_at=PAST)],
                              when=NOW)
    assert [d["_id"] for d in served] == [1]
    assert handle.receipts()["refused_by_reason"] == {"deadline": 1}


@pytest.mark.parametrize("name,fn", [
    # The cache merge: the same document, from somewhere that never masked.
    ("restore", lambda docs: [contract(d["_id"]) for d in docs]),
    # In-place: put the value back on the dict it was handed.
    ("mutate", lambda docs: [d.update(ssn=SSN, internal="x") or d
                             for d in docs]),
    # Invented: a document the boundary never saw, carrying the value.
    ("invent", lambda docs: docs + [contract(9)]),
])
def test_a_transform_cannot_unmask_a_value(name, fn):
    served = core(Named(name, fn)).reachable([contract(1)], when=NOW)
    assert served, name
    for doc in served:
        assert doc["ssn"] is None, name
        assert "internal" not in doc, name


def test_a_transform_is_never_shown_the_value():
    seen = []

    def look(docs):
        seen.extend(docs)
        return docs

    handle = core(Named("look", look))
    handle.reachable([contract(1)], when=NOW)
    assert seen and all(d.get("ssn") is None and "internal" not in d
                        for d in seen)
    # Masked in the pre-pass and passed through the terminal one: counted
    # once per value served, not once per pass.
    assert handle.receipts()["masked_total"] == 2


def test_an_audience_sees_the_value_and_nobody_else_does():
    masks = (Mask("ssn", visible_to=("hr",)),)
    handle = core(masks=masks)
    hr = handle.for_caller({"roles": ["hr"]}).reachable([contract(1)],
                                                        when=NOW)
    other = handle.for_caller({"roles": ["sales"]}).reachable([contract(1)],
                                                              when=NOW)
    unknown = handle.reachable([contract(1)], when=NOW)
    assert hr[0]["ssn"] == SSN
    assert other[0]["ssn"] is None
    assert unknown[0]["ssn"] is None                # unknown is not entitled


# ---- the wire: the bytes do not carry it ---------------------------------

def _batch(docs, *, ns="db.contracts") -> bytes:
    return encode_op_msg(7, 3, 0, {"cursor": {"id": 0, "ns": ns,
                                              "firstBatch": docs}, "ok": 1})


def _served(raw: bytes) -> list:
    decoded = decode_op_msg(raw)
    assert decoded is not None
    return decoded[1]["cursor"]["firstBatch"]


def guards(masks=MASKS) -> dict:
    spec = AdmissionSpec("contracts", rules=(revoked("forgotten"),),
                         masks=masks)
    return {"contracts": Guard(spec)}


def test_the_reply_bytes_are_rewritten_before_the_driver_sees_them():
    g = guards()
    raw = _batch([contract(1, expire_at=None)])
    out = enforce(raw, 7, 3, g, False)
    [doc] = _served(out)
    assert doc["ssn"] is None and "internal" not in doc
    assert SSN.encode() not in out
    assert g["contracts"].masked == 2


def test_a_batch_no_mask_touches_is_forwarded_byte_for_byte():
    raw = _batch([{"_id": 1, "text": "no masked fields here"}])
    assert enforce(raw, 7, 3, guards(), False) is raw


def test_a_reply_the_rules_ran_on_server_side_is_still_masked():
    # A pushed-down read skips per-document judging; it must not skip this.
    g = guards()
    out = mask_reduced(_batch([{"_id": 1, "ssn": SSN}]), 7, 3, g)
    assert _served(out) == [{"_id": 1, "ssn": None}]
    assert g["contracts"].masked == 1


def test_an_audience_on_a_mask_makes_the_guard_ask_who_is_calling():
    g = guards((Mask("ssn", visible_to=("hr",)),))["contracts"]
    assert g.needs_caller
    odd = guards((Mask("ssn", visible_to=("gold",), via="tier"),))
    assert unsuppliable_claims(odd["contracts"]) == ["tier"]


# ---- the command: the value does not leave as something else -------------

def _cmd(body: dict, ident: str | None = None, docs=None) -> bytes:
    if ident is None:
        return encode_op_msg(11, 0, 0, {**body, "$db": "db"})
    return encode_sections(11, 0, 0, {**body, "$db": "db"}, ident, docs)


REFUSED = [
    ("filter", {"find": "contracts", "filter": {"ssn": SSN}}),
    ("filter-nested", {"find": "contracts",
                       "filter": {"$or": [{"a": 1}, {"ssn.last4": "6789"}]}}),
    ("expr", {"find": "contracts",
              "filter": {"$expr": {"$eq": ["$ssn", SSN]}}}),
    ("sort", {"find": "contracts", "filter": {}, "sort": {"ssn": 1}}),
    ("renamed-projection", {"find": "contracts", "projection": {"x": "$ssn"}}),
    ("distinct", {"distinct": "contracts", "key": "ssn"}),
    ("count", {"count": "contracts", "query": {"internal": {"$exists": 1}}}),
    ("group", {"aggregate": "contracts", "cursor": {},
               "pipeline": [{"$group": {"_id": "$ssn"}}]}),
    ("project-rename", {"aggregate": "contracts", "cursor": {},
                        "pipeline": [{"$project": {"tax": "$ssn"}}]}),
    ("root", {"aggregate": "contracts", "cursor": {},
              "pipeline": [{"$replaceWith": {"d": "$$ROOT"}}]}),
    ("getField", {"aggregate": "contracts", "cursor": {},
                  "pipeline": [{"$project": {
                      "x": {"$getField": "ssn"}}}]}),
    ("facet", {"aggregate": "contracts", "cursor": {},
               "pipeline": [{"$facet": {"a": [{"$sortByCount": "$ssn"}]}}]}),
    ("match", {"aggregate": "contracts", "cursor": {},
               "pipeline": [{"$match": {"ssn": SSN}}]}),
    ("search-path", {"aggregate": "contracts", "cursor": {},
                     "pipeline": [{"$search": {"text": {
                         "query": "6789", "path": "ssn"}}}]}),
    ("explain", {"explain": {"find": "contracts", "filter": {"ssn": SSN}}}),
    ("fam-unprojected", {"findAndModify": "contracts", "query": {"_id": 1},
                         "update": {"$set": {"text": "x"}}}),
]


@pytest.mark.parametrize("name,body", REFUSED, ids=[n for n, _ in REFUSED])
def test_a_command_that_reaches_a_masked_value_is_refused(name, body):
    out = refuse_masked_reference(_cmd(body), 11, guards(), False)
    assert out is not None, name
    reply = decode_op_msg(out)[1]
    assert reply["ok"] == 0.0 and "masked field" in reply["errmsg"]


def test_a_server_side_copy_is_refused_in_the_sequence_a_driver_sends():
    # pymongo puts update statements in a kind-1 section, not the body.
    copy = _cmd({"update": "contracts"}, "updates",
                [{"q": {}, "u": [{"$set": {"x": "$ssn"}}]}])
    rename = _cmd({"update": "contracts"}, "updates",
                  [{"q": {}, "u": {"$rename": {"ssn": "x"}}}])
    oracle = _cmd({"delete": "contracts"}, "deletes",
                  [{"q": {"ssn": SSN}, "limit": 1}])
    for raw in (copy, rename, oracle):
        assert refuse_masked_reference(raw, 11, guards(), False) is not None


ALLOWED = [
    ("plain", {"find": "contracts", "filter": {"text": "terms"}}),
    ("exclude", {"find": "contracts", "projection": {"ssn": 0}}),
    # The value stays under its own name, where the mask finds it.
    ("include", {"find": "contracts", "projection": {"ssn": 1, "text": 1}}),
    ("unset", {"aggregate": "contracts", "cursor": {},
               "pipeline": [{"$unset": ["ssn", "internal"]},
                            {"$group": {"_id": "$text"}}]}),
    ("count", {"count": "contracts", "query": {"text": "terms"}}),
    ("fam-projected", {"findAndModify": "contracts", "query": {"_id": 1},
                       "update": {"$set": {"ssn": "new"}},
                       "fields": {"ssn": 0, "internal": 0}}),
]


@pytest.mark.parametrize("name,body", ALLOWED, ids=[n for n, _ in ALLOWED])
def test_a_command_that_leaves_the_value_alone_is_forwarded(name, body):
    assert refuse_masked_reference(_cmd(body), 11, guards(), False) is None


def test_writing_a_masked_field_is_allowed():
    raw = _cmd({"update": "contracts"}, "updates",
               [{"q": {"_id": 1}, "u": {"$set": {"ssn": "987-65-4321"}}}])
    assert refuse_masked_reference(raw, 11, guards(), False) is None


def test_the_audience_may_ask_about_the_value_it_may_read():
    g = guards((Mask("ssn", visible_to=("hr",)),))
    raw = _cmd({"find": "contracts", "filter": {"ssn": SSN}})
    assert refuse_masked_reference(raw, 11, g, False, {"roles": ["hr"]}) \
        is None
    assert refuse_masked_reference(raw, 11, g, False, {"roles": []}) \
        is not None


def test_a_policy_with_no_mask_pays_nothing():
    g = {"contracts": Guard(AdmissionSpec("contracts"))}
    raw = _cmd({"find": "contracts", "filter": {"ssn": SSN}})
    assert refuse_masked_reference(raw, 11, g, False) is None


# ---- the plan: removing a mask is widening -------------------------------

def _spec(*masks):
    return {"contracts": AdmissionSpec("contracts", masks=tuple(masks))}


@pytest.mark.parametrize("before,after,kind,opens", [
    ((Mask("ssn"),), (), MASK_REMOVED, True),
    ((Mask("ssn", strip=True),), (Mask("ssn"),), MASK_LOOSENED, True),
    ((Mask("ssn"),), (Mask("ssn", visible_to=("hr",)),), MASK_LOOSENED, True),
    ((Mask("ssn", visible_to=("hr",)),),
     (Mask("ssn", visible_to=("hr", "legal")),), MASK_LOOSENED, True),
    ((), (Mask("ssn"),), MASK_ADDED, False),
])
def test_a_plan_reports_a_mask_that_stops_hiding_as_fail_open(before, after,
                                                              kind, opens):
    [found] = structural(_spec(*before), _spec(*after))
    assert found.kind == kind
    assert found.fails_open is opens


def test_tightening_a_mask_is_not_fail_open():
    [found] = structural(_spec(Mask("ssn", visible_to=("hr", "legal"))),
                         _spec(Mask("ssn", visible_to=("hr",))))
    assert not found.fails_open


def test_the_mask_count_is_a_metric():
    from voyd.wire.metrics import HELP, Layout

    assert "masked_total" in HELP
    assert Layout(("contracts",)).index("masked_total", "contracts") >= 0


def test_no_bson_value_survives_a_strip():
    # `strip=True` removes the key, so not even the field name is in the
    # bytes -- the property that makes it the right choice when presence
    # is itself the fact.
    out = enforce(_batch([contract(1, expire_at=None)]), 7, 3, guards(),
                  False)
    assert b"internal" not in out
    assert bson.decode(out[21:])["cursor"]["firstBatch"][0]["ssn"] is None


# ---- a real driver, a real boundary --------------------------------------

LIVE_POLICY = """
from voyd import guard, deadline, tenant, mask

@guard("contracts")
class Contracts:
    expire_at = deadline()
    tenant_id = tenant()
    ssn       = mask()
    internal  = mask(strip=True)
"""


@pytest.fixture
def live(boundary, database, direct):
    from pymongo import MongoClient

    wire = boundary(LIVE_POLICY)
    client = MongoClient(wire.uri, serverSelectionTimeoutMS=15_000)
    try:
        yield client[database].contracts, direct[database].contracts
    finally:
        client.close()


@pytest.mark.needs_mongo
def test_pymongo_reads_the_contract_and_not_the_ssn(live):
    from pymongo.errors import OperationFailure

    guarded, around = live
    later = datetime.now(UTC) + timedelta(days=1)
    guarded.insert_many([
        {"_id": i, "tenant_id": "acme", "text": f"c{i}", "expire_at": later,
         "ssn": f"{i}{SSN}", "internal": "x"} for i in range(3)])
    acme = {"tenant_id": "acme"}

    # Every way a document comes back: judged, pushed down, reshaped,
    # and one batch at a time through `getMore`.
    for docs in (list(guarded.find(acme)),
                 list(guarded.find(acme, {"ssn": 1})),
                 list(guarded.find(acme, batch_size=1)),
                 list(guarded.aggregate([{"$match": acme},
                                         {"$addFields": {"seen": True}}]))):
        assert len(docs) == 3
        assert all(d["ssn"] is None and "internal" not in d for d in docs)

    # Every way the value would come back as something else.
    probe = {**acme, "ssn": f"0{SSN}"}
    for attempt in (
            lambda: list(guarded.find(probe)),
            lambda: list(guarded.find(acme).sort("ssn", 1)),
            lambda: guarded.distinct("ssn", acme),
            lambda: guarded.count_documents(probe),
            lambda: list(guarded.aggregate([{"$match": acme},
                                            {"$group": {"_id": "$ssn"}}])),
            lambda: list(guarded.aggregate([{"$match": acme},
                                            {"$project": {"t": "$ssn"}}])),
            lambda: guarded.database.command(
                "explain", {"find": "contracts", "filter": probe}),
            lambda: guarded.update_many(acme, [{"$set": {"t": "$ssn"}}]),
            lambda: guarded.find_one_and_update(
                {**acme, "_id": 0}, {"$set": {"text": "y"}})):
        with pytest.raises(OperationFailure, match="masked field"):
            attempt()

    # Allowed: projecting it away, and writing it.
    assert guarded.find_one_and_update(
        {**acme, "_id": 0}, {"$set": {"ssn": "new"}},
        projection={"ssn": 0, "internal": 0})["_id"] == 0

    # Around the boundary: nothing was destroyed, nothing was copied.
    on_disk = {d["_id"]: d for d in around.find({})}
    assert on_disk[1]["ssn"] == f"1{SSN}" and on_disk[1]["internal"] == "x"
    assert on_disk[0]["ssn"] == "new"
    assert all("t" not in d for d in on_disk.values())
