"""Casbin decides who you are; this decides which rows you get.

``examples/policy_engine.py`` makes a claim with two halves, and both are
the kind that rot quietly: that VOYD can express what people actually write
in a policy engine, and that a policy engine cannot express what VOYD does.
Either could stop being true without a line of this repository changing --
the first if an operator's semantics drift, the second if somebody decides a
cumulative rule should quietly become per-document.

So both halves are checked here against a real ``casbin.Enforcer``, not
against a description of one. The forward direction compares *sets of
documents*, per caller, because "I wrote something that looks equivalent" is
exactly the error this file exists to catch.

Skipped unless pycasbin is installed, which VOYD does not depend on and
never will: the argument in ``docs/policy-engines.md`` is that these are two
layers, and a dependency would be the opposite claim.
"""

from __future__ import annotations

import os
import tempfile

import pytest

casbin = pytest.importorskip("casbin")

from voyd.engine import Budget, Restricted, compile_policy
from voyd.engine.admission.spec import AdmissionSpec, why_refused


class Obj:
    """An attribute bag, because Casbin matchers say ``r.obj.field``."""

    def __init__(self, **kw):
        self.__dict__.update(kw)


DOCS = [
    {"doc_id": "d1", "Owner": "alice", "dept": "eng", "level": 1},
    {"doc_id": "d2", "Owner": "bob", "dept": "hr", "level": 3},
    {"doc_id": "d3", "Owner": "alice", "dept": "eng", "level": 3},
    {"doc_id": "d4", "Owner": "carol", "dept": "eng", "level": 2},
]

CALLERS = {
    "alice": {"id": "alice", "dept": "eng", "level": 2},
    "bob": {"id": "bob", "dept": "hr", "level": 3},
    "dave": {"id": "dave", "dept": "ops", "level": 0},
}

HEAD = """
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
"""


def enforcer(model: str, policy: str = "") -> "casbin.Enforcer":
    directory = tempfile.mkdtemp()
    model_path = os.path.join(directory, "model.conf")
    policy_path = os.path.join(directory, "policy.csv")
    with open(model_path, "w") as fh:
        fh.write(model)
    with open(policy_path, "w") as fh:
        fh.write(policy)
    return casbin.Enforcer(model_path, policy_path)


def admitted_by_voyd(rules, caller) -> set[str]:
    spec = AdmissionSpec(collection="notes", rules=tuple(rules))
    return {d["doc_id"] for d in DOCS
            if why_refused(d, spec, caller=caller) is None}


def admitted_by_casbin(enf, caller) -> set[str]:
    return {d["doc_id"] for d in DOCS
            if enf.enforce(Obj(**caller), Obj(**d), "read")}


# The matcher, and the policy meant to be identical to it. Named so a
# failure says which pair disagreed rather than which index.
EQUIVALENT = {
    "owner match (abac_model.conf)": (
        "m = r.sub.id == r.obj.Owner\n",
        {"deny": {"field": "Owner", "ne": "$caller.id"}}),
    "same dept, level at or below the caller's": (
        "m = r.sub.dept == r.obj.dept && r.obj.level <= r.sub.level\n",
        [{"deny": {"field": "dept", "ne": "$caller.dept"}},
         {"deny": {"field": "level", "gt": "$caller.level"}}]),
    "a constant ceiling on level": (
        "m = r.obj.level < 3\n",
        {"deny": {"field": "level", "gte": 3}}),
    "department equality": (
        "m = r.obj.dept == r.sub.dept\n",
        {"deny": {"field": "dept", "ne": "$caller.dept"}}),
}


@pytest.mark.parametrize("label", sorted(EQUIVALENT), ids=str)
def test_a_compiled_policy_decides_what_casbin_decides(label):
    """Set equality per caller, against a live enforcer."""
    matcher, policy = EQUIVALENT[label]
    enf = enforcer(HEAD + matcher)
    rules = compile_policy(policy)
    for name, caller in CALLERS.items():
        theirs = admitted_by_casbin(enf, caller)
        ours = admitted_by_voyd(rules, caller)
        assert ours == theirs, (
            f"{label}, caller {name}: casbin admits {sorted(theirs)}, "
            f"VOYD admits {sorted(ours)}. The two are supposed to be the "
            f"same policy, so one of them has drifted")


def test_the_group_acl_pattern_is_a_shipped_rule_not_a_compiled_one():
    """The commonest enterprise shape: document carries an ACL, caller
    carries groups, admit on a non-empty intersection.

    ``Restricted`` is the rule for it, and the reason it is a rule rather
    than a ``compile_policy`` operator is that the operators compare a
    document field against *one* value. Intersection is a different
    predicate, and giving ``in`` two meanings depending on the shape of
    what it was handed is how an operator starts lying.
    """
    docs = [{"doc_id": "a", "acl": ["eng"]},
            {"doc_id": "b", "acl": ["hr"]},
            {"doc_id": "c", "acl": []},
            {"doc_id": "d"}]
    rule = Restricted(field="acl", claim="groups")
    spec = AdmissionSpec(collection="n", rules=(rule,))
    caller = {"groups": ["eng", "contractors"]}

    admitted = {d["doc_id"] for d in docs
                if why_refused(d, spec, caller=caller) is None}
    assert admitted == {"a"}, "intersection is the whole semantics"

    # And it has a server-side half, which is the part Casbin has no
    # mechanism for at all: `$in` on an array field *is* intersection.
    assert rule.clause_for(caller) == {"acl": {"$in": ["contractors", "eng"]}}


def test_a_cumulative_rule_cannot_be_expressed_by_a_per_object_matcher():
    """The load-bearing claim of ``docs/policy-engines.md``.

    ``enforce(sub, obj, act)`` is a pure function of a subject and an
    object. A budget refuses a document because of the *other* documents in
    the same read, so the same pair has two answers and no matcher can
    return both. Demonstrated rather than asserted: it is the difference
    between a gap somebody could close and a boundary nobody can.
    """
    spec = AdmissionSpec(collection="n",
                         rules=(Budget(limit=100, cost_field="tokens"),))
    small = {"doc_id": "small", "tokens": 10}
    whale = {"doc_id": "whale", "tokens": 95}

    def admitted(page):
        tab = Budget(limit=100, cost_field="tokens").new_tab()
        return [d["doc_id"] for d in page
                if why_refused(d, spec, tab=tab) is None]

    assert admitted([small]) == ["small"]
    assert admitted([whale, small]) == ["whale"]

    # The same (caller, document) pair, two verdicts. That is the property
    # a per-object predicate cannot have, and the reason the egress check
    # is the only layer every reason can live in.
    enf = enforcer(HEAD + "m = r.obj.tokens <= 100\n")
    assert enf.enforce(Obj(id="a"), Obj(**small), "read") is True
    assert enf.enforce(Obj(id="a"), Obj(**small), "read") is True
