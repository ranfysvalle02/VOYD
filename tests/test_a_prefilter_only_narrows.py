"""The rules in `$vectorSearch.filter`: opt-in, all or nothing, never alone.

`prefilter=True` copies a guard's refusal into the vector index's filter so
refused rows are not ranked into a page the boundary then empties. The
claims held here are the ones that keep it safe:

    it only narrows       the client's filter is kept and ANDed, never
                          replaced
    all or nothing        one rule that cannot be a filter and the stage is
                          forwarded unchanged
    off means off         a guard without a confirmed index gets `None`,
                          which the proxy reads as "forward the bytes sent"
    the leading stage     a `$rankFusion` is a reduction and is left to
                          `reads.py`; its vector leg is not rewritten
    the index knows       `--ensure` declares the fields, and an index
                          without them is drift, not a prefilter

Pure except the last test, which needs a cluster that embeds.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from voyd import auto_embed, deadline, guard, revocable, sealed, tenant
from voyd.declare import OPTIONS, REGISTRY
from voyd.engine import Clearance, Deadline, revoked
from voyd.engine.admission import AdmissionSpec
from voyd.engine.admission.rules import Unrecoverable
from voyd.engine.search import drifted
from voyd.wire.codec import decode_op_msg, encode_op_msg
from voyd.wire.ensure import search_specs
from voyd.wire.policy import (Guard, clause_paths, index_declares,
                              prefilter_fields, rewrite_derived_read,
                              rewrite_vector_search)

UTC = timezone.utc
INDEX = "engine_vector_index"


@pytest.fixture(autouse=True)
def _clean_registry():
    REGISTRY.clear()
    OPTIONS.clear()
    yield
    REGISTRY.clear()
    OPTIONS.clear()


def opted_in(*rules, tenant_field="tenant_id") -> Guard:
    spec = AdmissionSpec("notes", rules=tuple(rules) or
                         (Deadline("expire_at"), revoked("forgotten")),
                         tenant=tenant_field)
    g = Guard(spec)
    g.prefilter_index = INDEX
    return g


def search(stage: dict, *rest: dict, collection="notes") -> bytes:
    return encode_op_msg(7, 0, 0, {
        "aggregate": collection, "$db": "app",
        "pipeline": [{"$vectorSearch": stage}, *rest], "cursor": {}})


def stage_of(raw: bytes) -> dict:
    decoded = decode_op_msg(raw)
    assert decoded is not None
    return decoded[1]["pipeline"][0]["$vectorSearch"]


VECTOR = {"index": INDEX, "path": "body", "query": "misfire",
          "numCandidates": 50, "limit": 5}


# ---- it only narrows ---------------------------------------------------

def test_the_client_filter_is_kept_and_the_rules_are_anded_beside_it():
    before = datetime.now(UTC) - timedelta(milliseconds=1)  # BSON is ms
    raw = rewrite_vector_search(
        search({**VECTOR, "filter": {"tenant_id": "acme"}}),
        7, 0, {"notes": opted_in()})
    assert raw is not None
    flt = stage_of(raw)["filter"]
    assert flt["$and"][0] == {"tenant_id": "acme"}, "the tenant was lost"
    rules = flt["$and"][1:]
    assert {"$or": [{"forgotten": None},
                    {"forgotten": {"$exists": False}}]} in rules
    deadline_arm = next(r for r in rules if any(
        "expire_at" in arm for arm in r["$or"]))
    # The instant is the request's: taken now, not cached at startup.
    instant = deadline_arm["$or"][2]["expire_at"]["$gt"]
    assert before <= instant.replace(tzinfo=UTC) <= datetime.now(UTC)


def test_a_search_with_no_filter_gets_only_the_rules():
    raw = rewrite_vector_search(search(VECTOR), 7, 0, {"notes": opted_in()})
    assert raw is not None
    assert len(stage_of(raw)["filter"]["$and"]) == 2


def test_the_rest_of_the_pipeline_and_the_stage_are_untouched():
    raw = rewrite_vector_search(
        search(VECTOR, {"$limit": 3}), 7, 0, {"notes": opted_in()})
    assert raw is not None
    body = decode_op_msg(raw)[1]
    assert body["pipeline"][1:] == [{"$limit": 3}]
    assert {k: v for k, v in stage_of(raw).items() if k != "filter"} == VECTOR


def test_a_prefiltered_search_is_still_judged_on_the_way_out():
    # Not a reduction: `reads.py` leaves it alone, so the proxy does not
    # mark it reduced, so the egress pass runs.
    assert rewrite_derived_read(search(VECTOR), 7, 0,
                                {"notes": opted_in()}, False) == (None, None)
    g = opted_in(tenant_field=None)
    past = datetime.now(UTC) - timedelta(hours=1)
    kept = g.filter([{"_id": 1, "expire_at": past}, {"_id": 2}])
    assert [d["_id"] for d in kept] == [2]


# ---- all or nothing, and off means off --------------------------------

def test_not_opted_in_is_forwarded_byte_for_byte():
    g = opted_in()
    g.prefilter_index = None
    assert rewrite_vector_search(search(VECTOR), 7, 0, {"notes": g}) is None


def test_a_rule_that_cannot_be_a_filter_leaves_the_stage_alone():
    g = opted_in(Deadline("expire_at"), Unrecoverable(field="body"))
    assert rewrite_vector_search(search(VECTOR), 7, 0, {"notes": g}) is None


def test_a_rule_that_needs_the_caller_leaves_the_stage_alone_without_one():
    g = opted_in(Deadline("expire_at"), Clearance(order=("public", "secret")))
    assert rewrite_vector_search(search(VECTOR), 7, 0, {"notes": g}) is None


def test_another_index_or_another_collection_is_not_rewritten():
    guards = {"notes": opted_in()}
    other = {**VECTOR, "index": "somebody_elses_index"}
    assert rewrite_vector_search(search(other), 7, 0, guards) is None
    assert rewrite_vector_search(
        search(VECTOR, collection="archive"), 7, 0, guards) is None


def test_a_rank_fusion_is_a_reduction_and_its_vector_leg_is_not_rewritten():
    fused = encode_op_msg(7, 0, 0, {
        "aggregate": "notes", "$db": "app", "cursor": {},
        "pipeline": [{"$rankFusion": {"input": {"pipelines": {
            "v": [{"$vectorSearch": VECTOR}],
            "t": [{"$search": {"index": "t", "text": {
                "query": "x", "path": "body"}}}]}}}}]})
    guards = {"notes": opted_in(tenant_field=None)}
    assert rewrite_vector_search(fused, 7, 0, guards) is None
    pushed, refusal = rewrite_derived_read(fused, 7, 0, guards, False)
    assert refusal is None and pushed is not None
    pipeline = decode_op_msg(pushed)[1]["pipeline"]
    assert "$match" in pipeline[0], "one $match over the fused result"
    assert pipeline[1]["$rankFusion"]["input"]["pipelines"]["v"] == [
        {"$vectorSearch": VECTOR}]


def test_only_the_vector_filter_dialect_is_accepted():
    assert clause_paths({"a": None, "b": {"$gt": 3}}) == {"a", "b"}
    assert clause_paths({"$or": [{"a": 1}, {"b": {"$exists": False}}]}) == {
        "a", "b"}
    assert clause_paths({"a": {"$regex": "x"}}) is None
    assert clause_paths({"$expr": {"$gt": ["$a", 1]}}) is None
    assert clause_paths({"a": {"nested": 1}}) is None


# ---- the index knows ---------------------------------------------------

def declare(prefilter: bool):
    @guard("notes", prefilter=prefilter)
    class Notes:
        expire_at = deadline()
        forgotten = revocable()
        tenant_id = tenant()
        body = auto_embed("voyage-3")
    return {"notes": Guard(REGISTRY["notes"])}


def test_ensure_declares_the_rule_fields_only_when_asked():
    plain = search_specs(declare(False), OPTIONS)["notes"]
    assert plain.filterable() == ("tenant_id",)
    guards = declare(True)
    spec = search_specs(guards, OPTIONS)["notes"]
    assert set(spec.filterable()) == {"tenant_id", "expire_at", "forgotten"}
    assert set(prefilter_fields(guards["notes"])) == {"expire_at", "forgotten"}
    definition = spec.auto_embed_definition()
    assert index_declares(definition, spec.filterable())
    # An index built before the opt-in is drift, and cannot answer it.
    old = plain.auto_embed_definition()
    assert drifted("vectorSearch", definition, old)
    assert not index_declares(old, spec.filterable())


def test_a_prefilter_with_no_index_to_live_in_is_refused_at_load():
    with pytest.raises(ValueError, match="auto_embed"):
        @guard("notes", prefilter=True)
        class Notes:
            expire_at = deadline()


def test_a_prefilter_over_a_rule_that_is_not_a_query_is_refused_at_load():
    with pytest.raises(ValueError, match="Unrecoverable"):
        @guard("notes", prefilter=True)
        class Notes:
            expire_at = deadline()
            tenant_id = tenant()
            secret = sealed()
            body = auto_embed("voyage-3")


# ---- against a cluster that embeds -------------------------------------

PREFILTER_POLICY = """
from voyd import guard, deadline, revocable, tenant, auto_embed

@guard("notes", prefilter=True)
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()
    body      = auto_embed({model!r})
"""


@pytest.mark.slow
def test_a_page_of_one_is_not_spent_on_an_expired_row(atlas_uri, boundary):
    """Without the prefilter, `limit: 1` ranks the expired row and the
    boundary refuses it: an empty page. With it, the live row is ranked."""
    import time

    from pymongo import MongoClient

    from tests.conftest import MODEL, scratch_name

    direct = MongoClient(atlas_uri, serverSelectionTimeoutMS=15_000)
    database = scratch_name()
    try:
        wire = boundary(PREFILTER_POLICY.format(model=MODEL), ensure=True,
                        target=atlas_uri, db=database)
        client = MongoClient(wire.uri, serverSelectionTimeoutMS=20_000)
        try:
            notes = client[database].notes
            notes.insert_many([
                {"_id": "gone", "tenant_id": "acme",
                 "expire_at": datetime.now(UTC) - timedelta(hours=1),
                 "body": "the fault code is P0301, a cylinder 1 misfire"},
                {"_id": "live", "tenant_id": "acme",
                 "expire_at": datetime.now(UTC) + timedelta(days=1),
                 "body": "the coolant temperature sensor reads high"},
            ])

            def ask(text):
                return [d["_id"] for d in notes.aggregate([{"$vectorSearch": {
                    "index": INDEX, "path": "body", "query": text,
                    "numCandidates": 50, "limit": 1,
                    "filter": {"tenant_id": "acme"}}}])]

            until = time.monotonic() + 180
            while time.monotonic() < until and not ask("coolant"):
                time.sleep(3)
            assert ask("cylinder misfire fault code") == ["live"]
        finally:
            client.close()
    finally:
        direct.drop_database(database)
        direct.close()
