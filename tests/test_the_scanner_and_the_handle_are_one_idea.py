"""One idea, two enforcement points -- and the exact line where one of them ends.

`scanner/README.md` and this repository's front page both claim that what
`voyd-scan` infers statically from a team's conventions is the same thing the
handle enforces at runtime as a `Rule`. That claim was prose. It is the kind
that rots in the worst way available, because both halves keep working
separately while the sentence joining them quietly stops being true.

So it is checked here, from the rules themselves rather than from a list
somebody maintains:

    a rule's query half names its own field
    -> a repository that honours that rule filters on that field
    -> `voyd-scan` recovers the field from the convention, not from a list
    -> the read that forgets it is the finding

The test may synthesise its fixtures from `clause()` because the scanner
reads filter *keys* and nothing else. The only thing it needs from a rule is
the field name that rule declares -- which is precisely the thing under test,
handed over by the rule and never typed out here.

**The second half matters more than the first.** `docs/AHA.md` argues that a
rule which can express itself in a query but not per document is not a slower
rule, it is a silent hole. This file establishes the mirror image, which has
never been written down anywhere in this repository:

> A rule with no query half is invisible to **every** static analyser, not
> just to this one. There is no filter to look for.

That is why the scanner is a floor and not a product, and why the handle is
not an optimisation of it. The rules sort themselves into three groups by
their query half alone, and each group gets a different, honest answer about
what a source scan can ever do for it.
"""

from __future__ import annotations

import inspect
from datetime import datetime, timedelta, timezone

import pytest

import voyd_scan
from voyd.engine import (Budget, Clearance, Deadline, Distinct, EmbeddedWith,
                         Marked, Restricted, Unrecoverable)
from voyd.engine.admission import rules as rules_module

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
PAST = NOW - timedelta(days=1)


def _fields_named_by(clause: dict | None) -> set[str]:
    """The document fields a query half constrains.

    Operators are skipped and dotted paths are cut at the first segment, so
    ``{"$or": [{"forgotten": None}, {"forgotten.at": {...}}]}`` names one
    field. This is deliberately the same reduction ``voyd_scan`` applies to a
    filter it finds in source -- the point of the file is that the two ends
    agree about what a field is.
    """
    out: set[str] = set()
    stack: list = [clause]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for k, v in node.items():
                if k.startswith("$"):
                    stack.append(v)
                else:
                    out.add(k.split(".")[0])
        elif isinstance(node, list):
            stack.extend(node)
    return out


def _a_repository_that_honours(field: str, *, honouring: int = 3) -> dict[str, str]:
    """The source a team *without* VOYD writes to enforce one rule by hand.

    Several reads carry the filter because somebody remembered, and one does
    not because somebody did not. That is the founding incident, and it is the
    only fixture this file needs: the scanner is told nothing except this.
    """
    body = "".join(
        f"    db.notes.find({{'user': u, {field!r}: {{'$gt': 0}}}})\n"
        for _ in range(honouring)
    )
    return {"app.py": "def reads(db, u):\n" + body + "    db.notes.find({'user': u})\n"}


# Rules whose query half stands on its own: the rule alone tells you what to
# filter, so a static scanner has something to recover.
UNCONDITIONAL = [
    pytest.param(Deadline(), {"expire_at": PAST}, id="Deadline"),
    pytest.param(Marked(field="forgotten", reason="forgotten"),
                 {"forgotten": {"at": PAST}}, id="Marked"),
    pytest.param(EmbeddedWith(model="voyage-3"),
                 {"embedded_with": "last-quarters-model", "embedding": [1.0]},
                 id="EmbeddedWith"),
]

# Rules whose query half exists but cannot be written without knowing who is
# asking. ``clause()`` is None; ``clause_for(caller)`` is not.
CALLER_DEPENDENT = [
    pytest.param(Restricted(), {"groups": ["sales"]}, {"audience": ["legal"]},
                 id="Restricted"),
    pytest.param(Clearance(order=("public", "secret")), {"clearance": "public"},
                 {"classification": "secret"}, id="Clearance"),
]

# Rules with no query half at all, by nature rather than by omission.
NO_QUERY_HALF = [
    pytest.param(Budget(limit=100), id="Budget"),
    pytest.param(Distinct(on="hash"), id="Distinct"),
    pytest.param(Unrecoverable(), id="Unrecoverable"),
]


@pytest.mark.parametrize("rule,refused_doc", UNCONDITIONAL)
def test_what_the_handle_refuses_at_runtime_the_scanner_finds_in_source(rule, refused_doc):
    """Both ends of one idea, on one rule, in one assertion each.

    The runtime half: this document is refused, per document, on the way out.
    The static half: a repository enforcing the same rule by hand has a read
    that forgets it, and the scanner finds that read -- having been handed the
    field by the rule's own `clause()` and never told it.
    """
    assert rule.refuses(dict(refused_doc), when=NOW), "the runtime half"

    fields = _fields_named_by(rule.clause())
    assert fields, "an unconditional rule must name its field in clause()"
    field = sorted(fields)[0]

    report = voyd_scan.analyze(_a_repository_that_honours(field))
    assert report.bearing == {"notes"}
    assert [m.field for m in report.marks["notes"]] == [field]
    assert len(report.leaks) == 1
    assert report.leaks[0].line == 5, "the read that forgot it, by line"


@pytest.mark.parametrize("rule", [
    pytest.param(Deadline(at_field="settles_on"), id="a deadline nobody named"),
    pytest.param(Marked(field="held_until", reason="held"), id="a mark nobody named"),
])
def test_the_scanner_recovers_a_field_this_repository_has_never_heard_of(rule):
    """The anti-circularity check, and the reason the scanner is worth shipping.

    If the fixtures only ever used ``expire_at``, this whole file would be
    proving that a hard-coded list contains what the hard-coded list contains.
    So the rule picks a field name that appears in no list anywhere -- it is
    asserted absent from ``voyd_scan.MARKS`` right here -- and the scanner
    still has to find it, from the convention alone.
    """
    field = sorted(_fields_named_by(rule.clause()))[0]
    assert voyd_scan._norm(field) not in voyd_scan.MARKS, (
        f"{field} must be a name the scanner was never told, or this proves nothing")

    report = voyd_scan.analyze(_a_repository_that_honours(field))
    mark = report.marks["notes"][0]
    assert (mark.field, mark.source) == (field, "inferred")
    assert len(report.leaks) == 1


@pytest.mark.parametrize("rule,caller,refused_doc", CALLER_DEPENDENT)
def test_a_caller_dependent_rule_hands_a_static_scanner_nothing(rule, caller, refused_doc):
    """Group two, and the first honest limit.

    `Restricted` and `Clearance` have a query half, but it cannot be written
    without knowing who is asking -- `clause()` is None and `clause_for(caller)`
    is not. A source scan has no caller and never will, so the rule itself
    offers it nothing.

    The convention still does, which is the point: the scanner recovers
    `audience` the same way it recovers a deadline, because it is not reading
    the rule, it is reading what the reads agree on. Two different routes to
    the same field, and only one of them is available to a tool that runs
    before the program does.
    """
    assert rule.refuses(dict(refused_doc), when=NOW, caller=caller), "the runtime half"
    assert rule.clause() is None, "nothing to recover without a caller"

    field = sorted(_fields_named_by(rule.clause_for(caller)))[0]
    report = voyd_scan.analyze(_a_repository_that_honours(field))
    assert [m.field for m in report.marks["notes"]] == [field]
    assert len(report.leaks) == 1


@pytest.mark.parametrize("rule", NO_QUERY_HALF)
def test_a_rule_with_no_query_half_is_invisible_to_every_static_analyser(rule):
    """Group three, and the sentence this file exists to be able to say.

    A budget is a running total, not a property of a document. `Distinct` is
    about a document's relationship to the others on the page. `Unrecoverable`
    is about whether a value can be read at all. None of the three can be
    written as a filter -- `clause()` is None and there is no caller, no clock
    and no configuration that would make one appear.

    So there is no filter in anybody's source for a scanner to look for, and
    no filter that a *missing* filter could be the deviation from. This is not
    a gap in `voyd-scan` to be closed by a better parser; Semgrep and CodeQL
    have exactly the same nothing to work with. The reads these rules refuse
    look, in source, precisely like the reads they admit.

    That is the strongest argument in this repository for the handle existing
    at all. The scanner can hand you your own number for the rules that have a
    query half. For the rest, a per-document check on the way out is not the
    better option -- it is the only place they can live.
    """
    assert rule.clause() is None
    assert not hasattr(rule, "clause_for"), "not caller-dependent; simply absent"

    # There is no honest fixture to write here, and that *is* the finding: any
    # source we could synthesise would be a repository with no convention to
    # deviate from. The scanner correctly reports nothing rather than
    # inventing a mark, which is the behaviour that keeps its other numbers
    # worth reading.
    report = voyd_scan.analyze({"app.py": (
        "def reads(db, u):\n"
        "    db.notes.find({'user': u})\n"
        "    db.notes.find({'user': u})\n"
        "    db.notes.find({'user': u})\n"
    )})
    assert report.bearing == set()
    assert report.leaks == []


def test_every_shipped_rule_is_on_one_side_of_that_line_or_the_other():
    """The closing statement, over the whole rule set rather than a sample.

    A rule is statically recoverable exactly when it has a query half that
    needs no caller. That is not a tendency, it is the partition -- and this
    asserts it over every rule in the package, so a rule added later cannot
    quietly land in neither group and leave the claim above describing a set
    it is no longer about.

    If this fails because you added a rule: decide which side it is on and
    add it to the lists at the top. If it has a query half, the scanner can
    find the teams who enforce it by hand. If it does not, say so in its
    docstring the way `Budget` does, because that is a fact about every static
    analyser and not about this one.
    """
    shipped = {
        name: obj for name, obj in vars(rules_module).items()
        if inspect.isclass(obj) and hasattr(obj, "clause")
        and obj.__module__ == rules_module.__name__
        and name not in ("Rule", "CumulativeRule")
    }
    assert len(shipped) >= 7, "the rule set shrank; this test is now checking less"

    accounted = {p.values[0].__class__.__name__
                 for p in UNCONDITIONAL + CALLER_DEPENDENT + NO_QUERY_HALF}
    missing = set(shipped) - accounted
    assert not missing, (
        f"{sorted(missing)} is a shipped rule this file has not placed. A rule "
        "is either statically recoverable or it is not, and which one decides "
        "what voyd-scan can honestly promise about it.")
