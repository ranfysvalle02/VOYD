"""A derived-memory policy names sources the boundary can verify."""

from __future__ import annotations

import asyncio
import textwrap
from datetime import datetime

import pytest

from voyd import declare
from voyd.engine.admission import AdmissionSpec
from voyd.wire.codec import decode_sections, encode_op_msg, encode_sections
from voyd.wire.policy import Guard, derive_on_update


def policy(tmp_path, body: str) -> str:
    path = tmp_path / "voydfile.py"
    path.write_text(textwrap.dedent(body))
    return str(path)


def test_a_derived_collection_requires_a_lineage_field(tmp_path):
    with pytest.raises(ValueError, match="needs lineage_field"):
        declare.load(policy(tmp_path, """
            from voyd import guard, revocable

            @guard("notes", attest=True)
            class Notes:
                forgotten = revocable()

            @guard("memories", derived_from=("notes",))
            class Memories:
                forgotten = revocable()
        """))


def test_a_derived_collection_requires_attested_named_sources(tmp_path):
    with pytest.raises(ValueError, match="must declare attest=True"):
        declare.load(policy(tmp_path, """
            from voyd import guard, revocable

            @guard("notes")
            class Notes:
                forgotten = revocable()

            @guard("memories", lineage_field="lineage",
                   derived_from=("notes",))
            class Memories:
                forgotten = revocable()
        """))


def test_a_derived_collection_keeps_its_allowed_sources(tmp_path):
    specs = declare.load(policy(tmp_path, """
        from voyd import guard, revocable

        @guard("notes", attest=True)
        class Notes:
            forgotten = revocable()

        @guard("memories", lineage_field="lineage",
               derived_from=("notes",))
        class Memories:
            forgotten = revocable()
    """))
    assert specs["memories"].derived_from == ("notes",)


class _Sources:
    async def cited_parentage(self, database, guard, citations, guards, claims):
        assert database == "app"
        assert citations == [{"citation": "signed"}]
        return ["source"], [datetime(2099, 1, 1)], "acme", []


def _derived_guard() -> Guard:
    guard = Guard(AdmissionSpec("memories", lineage_field="lineage",
                                derived_from=("notes",), tenant="tenant_id"))
    guard.cascade = _Sources()
    return guard


def test_a_cited_set_replaces_client_provenance_with_the_boundarys():
    raw = encode_sections(1, 0, 0, {"update": "memories", "$db": "app"},
                          "updates", [{"q": {"_id": "memory"}, "u": {
                              "$set": {"text": "summary", "_voyd_from": [
                                  {"citation": "signed"}]}}}])
    rewritten, refused = asyncio.run(derive_on_update(
        raw, 1, 0, {"memories": _derived_guard()}, False,
        {"user": "writer", "db": "admin"}))
    assert refused is None
    decoded = decode_sections(rewritten)
    assert decoded is not None
    values = decoded[3][0]["u"]["$set"]
    assert values["text"] == "summary"
    assert values["lineage"] == ["source"]
    assert values["tenant_id"] == "acme"
    assert "_voyd_from" not in values


def test_a_cited_update_cannot_set_the_boundary_owned_deadline():
    sooner = datetime(2098, 1, 1)
    raw = encode_sections(1, 0, 0, {"update": "memories", "$db": "app"},
                          "updates", [{"q": {"_id": "memory"}, "u": {
                              "$set": {"text": "summary", "expire_at": sooner,
                                       "_voyd_from": [{"citation": "signed"}]}}}])
    rewritten, refused = asyncio.run(derive_on_update(
        raw, 1, 0, {"memories": _derived_guard()}, False,
        {"user": "writer", "db": "admin"}))
    assert rewritten == raw
    assert refused is not None


def test_an_uncited_replacement_of_a_derived_memory_is_refused():
    raw = encode_sections(1, 0, 0, {"update": "memories", "$db": "app"},
                          "updates", [{"q": {"_id": "memory"},
                                       "u": {"text": "summary"}}])
    _rewritten, refused = asyncio.run(derive_on_update(
        raw, 1, 0, {"memories": _derived_guard()}, False,
        {"user": "writer", "db": "admin"}))
    assert refused is not None


def test_an_uncited_modifier_update_of_a_derived_memory_is_refused():
    raw = encode_sections(1, 0, 0, {"update": "memories", "$db": "app"},
                          "updates", [{"q": {"_id": "memory"},
                                       "u": {"$set": {"text": "summary"}}}])
    _rewritten, refused = asyncio.run(derive_on_update(
        raw, 1, 0, {"memories": _derived_guard()}, False,
        {"user": "writer", "db": "admin"}))
    assert refused is not None


def test_a_pipeline_update_of_a_derived_memory_is_refused():
    raw = encode_sections(1, 0, 0, {"update": "memories", "$db": "app"},
                          "updates", [{"q": {"_id": "memory"},
                                       "u": [{"$set": {"text": "summary"}}]}])
    _rewritten, refused = asyncio.run(derive_on_update(
        raw, 1, 0, {"memories": _derived_guard()}, False,
        {"user": "writer", "db": "admin"}))
    assert refused is not None


def test_find_one_and_update_of_a_derived_memory_is_refused():
    raw = encode_op_msg(1, 0, 0, {"findAndModify": "memories", "$db": "app",
                                   "query": {"_id": "memory"},
                                   "update": {"$set": {"text": "summary"}}})
    _rewritten, refused = asyncio.run(derive_on_update(
        raw, 1, 0, {"memories": _derived_guard()}, False,
        {"user": "writer", "db": "admin"}))
    assert refused is not None