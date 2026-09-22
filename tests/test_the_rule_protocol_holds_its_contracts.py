"""What a rule is promised, and what it is not allowed to get away with.

`rules.py` states four contracts in prose and `spec.why_refused` implements
them. None of them were asserted anywhere, which put the ordering
guarantees of the whole protocol in the same category as the conventions
this project exists to replace: correct, and correct because somebody
remembered.

**One of them is a security property, and it got sharper this week.** A
rule that raises must be treated as a *refusal*, because an exception
inside a filter is how the filter gets skipped. That was a defensive note
about the builtins; it is now the contract that holds when a stranger's
rule -- installed from a policy file, written against a documented
protocol, never reviewed here -- throws on a document shape its author did
not consider. A boundary that admitted on error would hand the gate to the
worst-written rule in the file.

The other three are about *order*, and each one is a number that would
otherwise be quietly wrong:

- a cumulative rule is asked last, so a budget never spends room on a
  document a deadline was going to refuse;
- among cumulative rules the ones that *charge* are asked last of all, so
  a budget never spends room on a duplicate a de-duplicator drops;
- each cumulative rule gets its own running total, so a budget and a
  de-duplicator declared together do not share one.

Every assertion here is on an observable -- which documents came back and
what the receipts say -- rather than on the sort key. A test that asserted
the key would pass on an implementation that sorted correctly and then
ignored the result.

No database. These are pure functions of a document and a list of rules.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta


from voyd.engine import Budget, Deadline, revoked
from voyd.engine.admission import Admission, AdmissionSpec
from voyd.engine.admission.rules import Distinct
from voyd.engine.time import now

PAST = now() - timedelta(days=1)


def handle(*rules) -> Admission:
    """An admission handle with no database behind it.

    `Admission(None, spec)` is the construction the wire uses, and it is
    the evidence that the per-document check needs no deployment.
    """
    return Admission(None, AdmissionSpec("notes", rules=rules))


# ---- a rule must not be able to open the gate by failing -----------------

@dataclass(frozen=True)
class Exploding:
    """A rule written by somebody having a bad day."""
    reason: str = "boom"
    field: str = "anything"

    def refuses(self, doc, *, when: datetime | None = None) -> bool:
        raise RuntimeError("a rule somebody else wrote, badly")

    def clause(self) -> dict | None:
        return None


@dataclass(frozen=True)
class LyingAboutTypes:
    """Worse than raising: it returns something that is not a bool."""
    reason: str = "nonsense"
    field: str = "anything"

    def refuses(self, doc, *, when: datetime | None = None):
        return "not a boolean"

    def clause(self) -> dict | None:
        return None


def test_a_rule_that_raises_refuses_rather_than_admits(caplog):
    """The contract that matters most, and the one a policy file can now
    reach. An exception inside a filter is how the filter gets skipped."""
    docs = [{"_id": 1, "text": "a live document"}]
    with caplog.at_level(logging.ERROR):
        kept = handle(Deadline(), Exploding()).reachable(docs)
    assert kept == [], (
        "a rule raised and the document was served. A third-party rule "
        "can now be installed from a policy file, so this is the gate "
        "being handed to the worst-written rule in the file")


def test_a_rule_that_raises_is_counted_under_its_own_reason():
    """Refusing is not enough: an operator has to be able to see *which*
    rule is failing, or a broken rule looks like a strict one."""
    h = handle(Deadline(), Exploding())
    h.reachable([{"_id": 1}])
    assert h.receipts()["refused_by_reason"] == {"boom": 1}


def test_a_rule_that_raises_is_logged_with_a_traceback(caplog):
    """The refusal is the safe outcome and the log is the only place the
    defect is visible. A silent fail-closed rule is a collection that
    reads as empty for a reason nobody can find."""
    with caplog.at_level(logging.ERROR):
        handle(Exploding()).reachable([{"_id": 1}])
    assert any("boom" in r.message or "boom" in str(r.args)
               for r in caplog.records), caplog.text


def test_only_the_failing_rule_stops_being_trusted():
    """One broken rule must not take the others with it -- the document is
    refused, and a *different* document that the other rules refuse is
    still refused for the right reason."""
    h = handle(revoked(), Exploding())
    h.reachable([{"_id": 1, "forgotten": {"at": PAST, "reason": "leak"}}])
    # `revoked` is declared first and answers first, so the reason is its
    # own rather than the exception's.
    assert h.receipts()["refused_by_reason"] == {"revoked": 1}


def test_a_rule_that_returns_a_non_bool_is_read_as_truthy():
    """Not a crash, and worth pinning: Python's truthiness means a rule
    returning a non-empty string refuses. That is the fail-closed
    direction, which is the one to be stuck with."""
    assert handle(LyingAboutTypes()).reachable([{"_id": 1}]) == []


# ---- a cumulative rule is asked last ------------------------------------

def test_a_budget_does_not_pay_for_a_document_a_deadline_refuses():
    """Declared budget-first on purpose. If the order were the declared
    one, the expired document would spend 90 of 100 and the live one
    would come back `over_budget` -- a page short by one, for a reason
    that has nothing to do with the room it actually needed."""
    h = handle(Budget(limit=100), Deadline())
    kept = h.reachable([
        {"_id": "expired", "tokens": 90, "expire_at": PAST},
        {"_id": "live", "tokens": 90},
    ])
    assert [d["_id"] for d in kept] == ["live"]
    assert h.receipts()["refused_by_reason"] == {"deadline": 1}, (
        "an `over_budget` here means the budget charged for a document "
        "the deadline was going to refuse")


def test_the_spent_total_is_the_sum_of_what_was_admitted():
    """What `Tab.charge` promises, and the reason the ordering exists at
    all. Two 40-token documents admitted out of a 100-token budget, and
    the expired one between them charged nothing."""
    h = handle(Budget(limit=100), Deadline())
    page = h.reachable([
        {"_id": 1, "tokens": 40},
        {"_id": 2, "tokens": 40, "expire_at": PAST},
        {"_id": 3, "tokens": 40},
    ])
    assert [d["_id"] for d in page] == [1, 3]


# ---- and the ones that charge are asked last of all ---------------------

def test_a_budget_does_not_pay_for_a_duplicate_a_deduplicator_drops():
    """The same argument one level in, and it arrived with the second
    cumulative rule. `Distinct` refuses without charging; `Budget`
    charges. Declared the other way round, three copies of one passage
    would report `over_budget` for content that never reached the page."""
    h = handle(Budget(limit=100), Distinct(on="h"))
    kept = h.reachable([{"_id": i, "tokens": 40, "h": "same"}
                        for i in range(3)])
    assert [d["_id"] for d in kept] == [0]
    assert h.receipts()["refused_by_reason"] == {"redundant": 2}, (
        "an `over_budget` here means the budget spent room on copies "
        "`Distinct` was about to drop")


def test_the_declared_order_still_decides_among_pure_rules():
    """Only the cumulative ones are reordered. A document that is both
    expired and revoked reports whichever was declared first, because an
    operator needs to know it was *quarantined* rather than merely
    expired -- the two demand different responses."""
    doc = {"_id": 1, "expire_at": PAST,
           "forgotten": {"at": PAST, "reason": "leak"}}
    first = handle(Deadline(), revoked())
    first.reachable([dict(doc)])
    assert first.receipts()["refused_by_reason"] == {"deadline": 1}

    second = handle(revoked(), Deadline())
    second.reachable([dict(doc)])
    assert second.receipts()["refused_by_reason"] == {"revoked": 1}


# ---- each cumulative rule brings its own total --------------------------

def test_two_cumulative_rules_do_not_share_a_running_total():
    """`Tabs` keys state by `id(rule)`. A budget and a de-duplicator have
    nothing to say to each other, and two budgets over different fields
    are two budgets -- if they shared, the first one's limit would
    silently govern the second."""
    h = handle(Budget(limit=100), Budget(limit=100, cost_field="other"))
    kept = h.reachable([{"_id": 1, "tokens": 60, "other": 60}])
    assert len(kept) == 1, (
        "60 and 60 each fit in their own 100-token budget; a shared tab "
        "would have made the second one see 120")


def test_a_fresh_read_starts_a_fresh_total():
    """The tab is per read, never on the handle. A handle is shared across
    concurrent callers, so a total living on it would bleed one request's
    spend into another's -- and the second read of a page would come back
    short for no reason the caller can see."""
    h = handle(Budget(limit=100))
    docs = [{"_id": 1, "tokens": 80}]
    assert len(h.reachable([dict(d) for d in docs])) == 1
    assert len(h.reachable([dict(d) for d in docs])) == 1


def test_the_contracts_are_read_off_the_class_not_the_declaration():
    """`needs_tab` and `charges` are class attributes, so a rule author
    gets the ordering by declaring what their rule *is* rather than by
    remembering where to put it in a list."""
    assert Budget(limit=1).needs_tab is True
    assert Budget(limit=1).charges is True
    assert Distinct(on="h").needs_tab is True
    assert getattr(Distinct(on="h"), "charges", False) is False
    assert getattr(Deadline(), "needs_tab", False) is False
