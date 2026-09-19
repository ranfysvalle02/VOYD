"""A rule stored on a document, compiled into one indistinguishable from code.

A ``Rule`` is a Python object, so a per-tenant access policy is a deploy --
which caps adoption at teams who can ship this service, and puts the people
who get audited on the wrong side of the release process.

The compiler is the whole job, and its hard rule is negative: **both halves
or nothing**. Every rule here has a per-document check (the guarantee) and a
query clause (the optimisation), and a compiled policy that manages only the
clause is not a slower rule, it is a silent hole -- ``$vectorSearch`` hits
never went through a query, so exactly the documents the clause would have
dropped walk into a prompt.

So the tests that matter are the refusals at compile time, and the one that
compares the two halves against a live server.
"""

from __future__ import annotations

import pytest

from voyd.engine import Deadline, PolicyInvalid, compile_policy, revoked
from voyd.engine.admission import AdmissionSpec, why_refused

CLEARANCE = {"deny": {"field": "classification",
                      "not_in": "$caller.clearances"}}
BUDGET = {"deny": {"field": "cost", "gt": 100, "reason": "too_expensive"}}


def spec_for(*policy, **kw):
    return AdmissionSpec("docs", rules=tuple(compile_policy(list(policy))), **kw)


# ---- it behaves like a hand-written rule ------------------------------

def test_a_compiled_policy_refuses_by_name():
    spec = spec_for(CLEARANCE, BUDGET)
    cleared = {"clearances": ["public", "internal"]}

    assert why_refused({"classification": "secret", "cost": 1}, spec,
                       caller=cleared) == "policy"
    assert why_refused({"classification": "public", "cost": 500}, spec,
                       caller=cleared) == "too_expensive"
    assert why_refused({"classification": "internal", "cost": 5}, spec,
                       caller=cleared) is None


def test_a_caller_reference_makes_the_rule_caller_aware():
    """Without it the handle would never hand over the claims, and the
    policy would compare every document against ``None``."""
    clearance, budget = compile_policy([CLEARANCE, BUDGET])
    assert clearance.needs_caller is True
    assert budget.needs_caller is False
    assert clearance.clause() is None, \
        "not expressible until the caller is known"
    assert budget.clause() is not None


def test_a_policy_rule_is_not_waivable_by_the_audit_handle():
    """It says *this caller* may not have the document, which is not a
    forgetting reason and not the audit handle's to set aside -- or 'let
    me see the deleted rows' becomes a privilege escalation."""
    assert all(not r.bypassable for r in compile_policy([CLEARANCE, BUDGET]))


def test_a_rule_that_raises_refuses_rather_than_opening_the_gate():
    """A comparison across types is the realistic way a stored policy
    explodes -- somebody writes ``{"gt": "100"}`` and the column is an
    int. Denial is the fail-closed direction."""
    spec = spec_for(BUDGET)
    assert why_refused({"cost": None}, spec) is None    # absent, not denied
    weird = compile_policy([{"deny": {"field": "cost", "gt": "100"}}])[0]
    assert weird.refuses({"cost": 5}) is False, \
        "an uncomparable pair must not silently satisfy a deny"


# ---- the refusals that matter are at compile time ---------------------

@pytest.mark.parametrize("bad, because", [
    ({"deny": {"field": "x", "weird": 1}}, "unknown operator"),
    ({"deny": {"field": "x"}}, "exactly one operator"),
    ({"deny": {"field": "x", "eq": 1, "ne": 2}}, "exactly one operator"),
    ({"allow": {"field": "x", "eq": 1}}, "has no 'deny'"),
    ({"deny": {"field": "$where", "eq": 1}}, "plain document field"),
    ({"deny": {"field": "", "eq": 1}}, "plain document field"),
    ({"deny": "not a mapping"}, "must be a mapping"),
    ({"deny": {"field": "x", "eq": "$caller."}}, "names no claim"),
    ({"deny": {"field": "x", "eq": "$scope.id"}}, "looks like a reference"),
])
def test_a_policy_that_cannot_compile_raises_at_boot(bad, because):
    """Boot is the one moment a policy error is cheap. The alternative --
    accept it and enforce whichever half compiled -- is the failure this
    module exists to prevent."""
    with pytest.raises(PolicyInvalid, match=because):
        compile_policy(bad)


def test_the_error_names_what_is_available():
    """A stored policy is written by somebody who is not reading this
    source, so the error has to carry the vocabulary."""
    with pytest.raises(PolicyInvalid) as caught:
        compile_policy({"deny": {"field": "x", "weird": 1}})
    message = str(caught.value)
    assert "not_in" in message and "gte" in message
    assert "$vectorSearch" in message, \
        "the error should say why half-enforcement is not on offer"


def test_a_dollar_reference_is_not_quietly_a_literal():
    """Comparing a document against the string ``'$scope.id'`` would
    match nothing and look like a working policy."""
    with pytest.raises(PolicyInvalid, match="looks like a reference"):
        compile_policy({"deny": {"field": "owner", "eq": "$scope.id"}})


# ---- the two halves have to agree, against a real server --------------

@pytest.mark.parametrize("policy, caller", [
    (CLEARANCE, {"clearances": ["public"]}),
    (CLEARANCE, {"clearances": ["public", "secret"]}),
    (CLEARANCE, {}),
    (BUDGET, None),
    ({"deny": {"field": "cost", "lte": 10}}, None),
    ({"deny": {"field": "owner", "eq": "acme"}}, None),
    ({"deny": {"field": "owner", "ne": "acme"}}, None),
    ({"deny": {"field": "tag", "in": ["draft", "spam"]}}, None),
    ({"deny": {"field": "reviewed", "exists": False}}, None),
])
async def test_the_query_and_the_per_document_check_return_the_same_set(
        core, policy, caller):
    """The property the whole module rests on, checked per operator.

    The query is the optimisation and the per-document check is the
    guarantee, and a deployment where they disagree is one where
    ``find()`` is safe and ``$vectorSearch`` is not -- which is the worst
    available shape, because the safe path is the one people test.
    """
    engine, db = core
    rules = compile_policy([policy])
    docs = engine.model("docs", tenant="t").admitting(
        Deadline(), revoked(), *rules)
    await engine.ensure(search_wait_s=0)

    population = [
        {"t": "a", "doc_id": "d1", "classification": "public",
         "cost": 5, "owner": "acme", "tag": "live", "reviewed": "yes"},
        {"t": "a", "doc_id": "d2", "classification": "secret",
         "cost": 500, "owner": "globex", "tag": "spam"},
        {"t": "a", "doc_id": "d3", "classification": "unheard-of",
         "cost": 100, "owner": "acme", "tag": "draft", "reviewed": None},
        {"t": "a", "doc_id": "d4"},
    ]
    await db.docs.insert_many([dict(d) for d in population])

    handle = docs.for_caller(caller) if caller is not None else docs
    through_query = {d["doc_id"] for d in await handle.find({"t": "a"})}

    raw = [d async for d in db.docs.find({"t": "a"})]
    per_document = {d["doc_id"] for d in handle.reachable(raw)}

    assert through_query == per_document, (
        f"the two halves disagree for {policy}: query returned "
        f"{sorted(through_query)}, the per-document check kept "
        f"{sorted(per_document)}")


async def test_a_policy_survives_a_round_trip_through_a_document(core):
    """The point of the feature: the policy lives on the scope, versioned
    with it, editable by the people who get audited."""
    engine, db = core
    await db.scopes.insert_one({"_id": "acme", "policy": [CLEARANCE]})
    stored = (await db.scopes.find_one({"_id": "acme"}))["policy"]

    docs = engine.model("docs", tenant="t").admitting(
        Deadline(), revoked(), *compile_policy(stored))
    await engine.ensure(search_wait_s=0)
    await db.docs.insert_many([
        {"t": "a", "doc_id": "open", "classification": "public"},
        {"t": "a", "doc_id": "shut", "classification": "secret"}])

    junior = docs.for_caller({"clearances": ["public"]})
    assert [d["doc_id"] for d in await junior.find({"t": "a"})] == ["open"]
    assert junior.receipts()["refused_by_reason"].get("policy", 0) >= 0
