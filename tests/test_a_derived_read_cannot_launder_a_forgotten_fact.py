"""The mirror of `$out`/`$merge`, and it was open for longer.

`filter_batch` is a per-document check, and it had a precondition nothing
was checking: the reply has to be made of the *stored documents*, still
carrying the fields the verdict is read from. Three shapes break that and
were all forwarded --

    distinct   -> {"values": [...]}   no cursor, so no batch, so no filter
    count      -> {"n": 2}            the same
    $group     -> a cursor of new documents with no marks on them

-- and the third is the quiet one. The batch arrives, `Guard.filter` runs,
and `len(kept) == len(batch)` holds because a reshaped document has nothing
to refuse it *on*. The boundary said yes by having nothing to say no about.

The answer is not `$out`'s answer. `$out` cannot be made safe by a proxy;
a count can, because the refusal is a *query* and the server can be made to
reduce over admitted documents only. So these are rewritten rather than
refused -- and this file's job is to pin the line between the two, because
a push-down that is narrower than the guarantee is the same bug with an
extra step.

Pure, with no database anywhere near it. `test_the_boundary_seals_and_shreds`
and the wire tests drive the same paths through a real `mongod`.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
bson = pytest.importorskip("bson")
import voyd_wire as w  # noqa: E402

from voyd.engine.admission.rules import Deadline, revoked  # noqa: E402
from voyd.engine.admission.spec import AdmissionSpec  # noqa: E402

GUARDED = "notes"


def guards(*, tenant: str | None = None, rules=None) -> dict[str, w.Guard]:
    spec = AdmissionSpec(GUARDED, tenant=tenant,
                         rules=rules if rules is not None
                         else (Deadline(at_field="expire_at"),
                               revoked("forgotten")))
    return {GUARDED: w.Guard(spec)}


def through(body: dict, *, tenant: str | None = None, rules=None):
    """`(pipeline_or_query_after_rewrite, refusal_reason)` for one command."""
    raw = w.encode_op_msg(11, 0, 0, {**body, "$db": "app"})
    pushed, refusal = w.rewrite_derived_read(
        raw, 11, 11, guards(tenant=tenant, rules=rules), False)
    if refusal is not None:
        _flags, err = w.decode_op_msg(refusal)
        assert err["ok"] == 0.0
        return None, err["errmsg"]
    if pushed is None:
        return None, None
    _flags, out = w.decode_op_msg(pushed)
    return out, None


# --- the three shapes that were open: rewritten, not refused ---------------

def test_distinct_gets_the_refusal_pushed_into_its_query():
    out, why = through({"distinct": GUARDED, "key": "owner"})
    assert why is None, why
    assert out is not None and "$and" in out["query"]


def test_count_gets_the_refusal_pushed_into_its_query():
    out, why = through({"count": GUARDED, "query": {"owner": "a"}})
    assert why is None, why
    assert out is not None
    assert out["query"]["owner"] == "a", "the caller's query survives"
    assert out["query"]["$and"], "and the boundary's is added to it"


@pytest.mark.parametrize("stage", [
    {"$group": {"_id": None, "n": {"$sum": 1}}},
    {"$count": "n"},
    {"$bucket": {"groupBy": "$x", "boundaries": [0, 1]}},
    {"$sortByCount": "$owner"},
    {"$replaceRoot": {"newRoot": "$inner"}},
    {"$facet": {"a": [{"$count": "n"}]}},
    {"$searchMeta": {"index": "v"}},
    {"$unwind": "$tags"},
    {"$project": {"owner": 1}},
    {"$set": {"forgotten": None}},
])
def test_a_reducing_pipeline_reduces_over_admitted_documents_only(stage):
    """The stage keeps working; what changes is what it is handed.

    `$project` and `$set` are on this list deliberately. They keep the
    document and take away -- or write over -- the fields the verdict is
    read from, which is the same leak wearing an ordinary face:
    `$set: {forgotten: None}` is a revoked document that passes.
    """
    out, why = through({"aggregate": GUARDED, "pipeline": [stage]})
    assert why is None, why
    assert out is not None
    assert list(out["pipeline"][0]) == ["$match"], "the refusal goes in front"
    assert out["pipeline"][0]["$match"]["$and"], "and it carries the rules"
    assert out["pipeline"][1] == stage, "the caller's stage is untouched"
    assert len(out["pipeline"]) == 2


def test_the_push_down_goes_after_vector_search_not_before_it():
    """`$vectorSearch` must be the first stage, so the refusal follows it."""
    search = {"$vectorSearch": {"index": "v", "path": "embedding",
                                "limit": 10}}
    out, why = through({"aggregate": GUARDED,
                        "pipeline": [search, {"$count": "n"}]})
    assert why is None, why
    assert out is not None
    assert out["pipeline"][0] == search
    assert "$match" in out["pipeline"][1]
    assert out["pipeline"][2] == {"$count": "n"}


# --- what must stay byte-identical -----------------------------------------

@pytest.mark.parametrize("stage", [
    {"$match": {"owner": "a"}},
    {"$sort": {"score": -1}},
    {"$limit": 10},
    {"$skip": 5},
    {"$sample": {"size": 3}},
    {"$vectorSearch": {"index": "v", "path": "embedding", "limit": 10}},
    {"$search": {"index": "t", "text": {"query": "x", "path": "body"}}},
])
def test_ordinary_retrieval_is_not_touched(stage):
    """This is the workload the package exists for, and `filter_batch`
    already covers it. Rewriting it would be cost with no guarantee."""
    out, why = through({"aggregate": GUARDED, "pipeline": [stage]})
    assert (out, why) == (None, None)


def test_a_find_is_not_a_derived_read():
    assert through({"find": GUARDED, "filter": {}}) == (None, None)


def test_an_unguarded_collection_is_never_the_boundary_s_business():
    for body in ({"distinct": "elsewhere", "key": "o"},
                 {"count": "elsewhere"},
                 {"aggregate": "elsewhere", "pipeline": [{"$count": "n"}]}):
        assert through(body) == (None, None)


# --- the three cases where the rewrite would be a lie ----------------------

def test_a_rule_that_cannot_be_a_query_refuses_instead_of_pushing_down():
    """`_query` in admission/core.py says a rule with no clause "is simply
    enforced on the way out instead". There is no way out of a count, so a
    push-down built from the rules that *can* express themselves is
    narrower than the guarantee -- too high by exactly the rows the silent
    rule would have caught."""
    class Unexpressible:
        field = "sealed"
        bypassable = True

        def clause(self):
            return None

        def reachable(self, doc):
            return True

    _out, why = through({"count": GUARDED},
                        rules=(Deadline(at_field="expire_at"),
                               Unexpressible()))
    assert why is not None and "cannot be asked as a query" in why


def test_a_rule_that_asks_who_is_calling_refuses_instead():
    """This process holds no caller. It forwards yours."""
    class NeedsCaller:
        field = "clearance"
        needs_caller = True
        bypassable = False

        def clause(self):
            return {"clearance": {"$lte": 1}}

        def clause_for(self, caller):
            return None

    _out, why = through({"count": GUARDED},
                        rules=(NeedsCaller(),))
    assert why is not None and "cannot be asked as a query" in why


def test_an_unpinned_tenant_refuses_rather_than_summarising_everybody():
    """`Guard.filter` takes the scope from the batch it is judging. A
    reduction has no batch, so an unpinned tenant is not a narrower answer
    -- it is every tenant's rows summarised into one number."""
    _out, why = through({"count": GUARDED, "query": {}}, tenant="org")
    assert why is not None and "org" in why

    _out, why = through({"aggregate": GUARDED,
                         "pipeline": [{"$count": "n"}]}, tenant="org")
    assert why is not None and "org" in why


def test_a_pinned_tenant_is_pushed_down_like_any_other():
    out, why = through({"count": GUARDED, "query": {"org": "acme"}},
                       tenant="org")
    assert why is None, why
    assert out is not None and out["query"]["org"] == "acme"

    out, why = through({"aggregate": GUARDED,
                        "pipeline": [{"$match": {"org": "acme"}},
                                     {"$count": "n"}]}, tenant="org")
    assert why is None, why
    assert out is not None
    assert out["pipeline"][1] == {"$match": {"org": "acme"}}, (
        "the caller's own $match survives, after the boundary's")


def test_a_tenant_pinned_to_null_is_pinned():
    """`admission/core.py` is explicit that `None`, `0` and `""` are tenant
    ids a caller may legitimately hold. Reading a pinned null as "unpinned"
    would refuse a read that was perfectly well scoped."""
    for scope in (None, 0, ""):
        out, why = through({"count": GUARDED, "query": {"org": scope}},
                           tenant="org")
        assert why is None, (scope, why)
        assert out is not None and out["query"]["org"] == scope


def test_a_tenant_pinned_to_a_set_is_not_pinned():
    """`{"org": {"$in": [...]}}` is several tenants, and one number over
    several tenants is the leak with an extra step."""
    _out, why = through({"count": GUARDED,
                         "query": {"org": {"$in": ["a", "b"]}}}, tenant="org")
    assert why is not None


# --- reaching another collection -------------------------------------------

@pytest.mark.parametrize("stage", [
    {"$lookup": {"from": "other", "as": "j"}},
    {"$unionWith": "other"},
    {"$graphLookup": {"from": "other", "as": "j"}},
])
def test_a_stage_that_reads_another_collection_is_refused(stage):
    """Push-down cannot help: those documents were never covered by this
    guard, and the policy for where they came from was not declared."""
    _out, why = through({"aggregate": GUARDED, "pipeline": [stage]})
    assert why is not None and "another collection" in why


# --- the ways around it ----------------------------------------------------

def test_explain_of_a_reduction_is_refused_not_quietly_rewritten():
    """An explain plan quotes the query. Rewriting it would describe a
    command the client did not send; forwarding it would hand back the
    plan for an unjudged reduction."""
    _out, why = through({"explain": {"count": GUARDED}})
    assert why is not None
    _out, why = through({"explain": {"aggregate": GUARDED,
                                     "pipeline": [{"$count": "n"}]}})
    assert why is not None


def test_explain_of_an_ordinary_read_is_left_alone():
    assert through({"explain": {"find": GUARDED, "filter": {}}}) == (None, None)
    assert through({"explain": {"aggregate": GUARDED,
                                "pipeline": [{"$match": {}}]}}) == (None, None)


def test_a_later_stage_cannot_hide_behind_an_earlier_one():
    """The pipeline is judged whole. `$match` first does not buy `$group`."""
    out, why = through({"aggregate": GUARDED,
                        "pipeline": [{"$match": {"owner": "a"}},
                                     {"$limit": 5},
                                     {"$group": {"_id": "$owner"}}]})
    assert why is None, why
    assert out is not None and "$match" in out["pipeline"][0]
    assert len(out["pipeline"]) == 4, "the refusal was inserted, not swapped in"


def test_a_stage_the_boundary_cannot_read_is_handled_not_forwarded():
    """Malformed, multi-key, or not a document at all. The fail-open
    version of this line is how the fan-out identity check was wrong for
    weeks: unreadable must not mean allowed."""
    for pipeline in ([{"$match": {}, "$group": {}}], ["nonsense"], [{}]):
        out, why = through({"aggregate": GUARDED, "pipeline": pipeline})
        assert (out, why) != (None, None), pipeline


def test_the_callers_own_and_clause_is_kept():
    """Narrowing a query must not mean discarding half of it."""
    mine = [{"a": 1}, {"b": 2}]
    out, why = through({"count": GUARDED, "query": {"$and": mine}})
    assert why is None, why
    assert out is not None and out["query"]["$and"][:2] == mine
    assert len(out["query"]["$and"]) > 2


def test_a_malformed_caller_and_clause_is_kept_not_quietly_dropped():
    """Their bug, kept so the server says so. Silently making a malformed
    query valid is a worse habit than the error."""
    out, why = through({"count": GUARDED, "query": {"$and": "garbage"}})
    assert why is None, why
    assert out is not None and out["query"]["$and"][0] == "garbage"
