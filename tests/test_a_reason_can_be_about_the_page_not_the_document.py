"""Set-relative reasons: the ones no index and no policy engine can hold.

Every other rule in this package answers a question about *one document*.
``Deadline`` reads a field, ``Marked`` reads a mark, ``Clearance`` compares a
field to a claim -- ask any of them twice about the same document and you get
the same answer, which is what lets them be pushed into a query.

These two are different in kind:

    over_budget   there is no room left in the prompt
    redundant     this content is already in the prompt

Both are properties of the *page being assembled*, not of the row. The same
document is admitted alone and refused in company, so no query predicate can
express either -- a filter decides each candidate before the page exists --
and neither can ``enforce(subject, object, action)``, which has no argument
for the rest of the set. The argument is ``docs/policy-engines.md``; this
file is the part that has to keep being true.

``Budget`` shipped first and looked like a special case. ``Distinct`` is here
to show it was not: two members, one protocol, and -- since ``Tabs`` replaced
the single shared ``Tab`` -- composable on one handle, which is the thing
that was a construction error until it was not.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from voyd.engine import now

from voyd.engine.admission import (Admission, AdmissionSpec, Budget, Deadline,
                                   Distinct, OVER_BUDGET, REDUNDANT, revoked)


def handle(*rules, docs=None):
    """A handle with no database: these rules never touch one."""
    return Admission(None, AdmissionSpec("notes", rules=rules))


async def admit(h, docs):
    """What ``reachable`` admits, which is the search path's entry point."""
    return [d["_id"] for d in await _reachable(h, docs)]


async def _reachable(h, docs):
    return h.reachable(docs)


# ---- the rule on its own -------------------------------------------------

def test_the_same_document_is_admitted_alone_and_refused_in_company():
    """The defining property of a set-relative reason, stated once.

    If this ever passes for a rule that also returns a ``clause()``, that
    rule is lying about having a server-side half.
    """
    h = handle(Distinct("chunk"))
    twin = {"_id": 2, "chunk": "a"}

    assert h.reachable([twin]) == [twin]
    assert h.reachable([{"_id": 1, "chunk": "a"}, twin]) == [
        {"_id": 1, "chunk": "a"}]

    assert Distinct("chunk").clause() is None, (
        "a set-relative rule must report no server-side half rather than a "
        "wrong one -- a query cannot ask what else the query will return")


def test_a_live_copy_survives_an_expired_one_that_ranked_above_it():
    """The regression that killed the first design, and the sharpest test here.

    A passage is indexed twice and the higher-ranked copy has expired. The
    obvious implementation pre-scans the candidates to pick a winner per
    cluster -- and that pre-scan runs before ``Deadline`` has refused
    anything, so it awards the slot to the expired copy. The live copy is
    then ``redundant`` behind a document that never reached the page, and
    the caller gets an empty result with two refusals and no error.

    Losing a live document silently is the failure this whole package
    exists to remove, so the rule fills its set *during* admission: only a
    document that actually got through can claim a slot.
    """
    h = handle(Deadline(), Distinct("chunk"))
    past, future = now() - timedelta(hours=1), now() + timedelta(hours=1)
    docs = [{"_id": "stale", "chunk": "a", "expire_at": past},
            {"_id": "live", "chunk": "a", "expire_at": future}]

    assert [d["_id"] for d in h.reachable(docs)] == ["live"]
    assert h.receipts()["refused_by_reason"] == {"deadline": 1}


def test_the_best_ranked_member_of_a_cluster_is_the_one_kept():
    """Relevance order decides the winner, so the page keeps the best copy
    rather than whichever the loop happened to reach first."""
    h = handle(Distinct("chunk"))
    docs = [{"_id": 1, "chunk": "a"}, {"_id": 2, "chunk": "b"},
            {"_id": 3, "chunk": "a"}, {"_id": 4, "chunk": "b"}]
    assert [d["_id"] for d in h.reachable(docs)] == [1, 2]
    assert h.receipts()["refused_by_reason"] == {REDUNDANT: 2}


def test_a_document_with_no_computable_identity_is_admitted():
    """This rule fails *open* and it is the only one here that does.

    Every other reason answers "may this reach a prompt" and fails closed. A
    missing hash is not evidence that a document is a duplicate, so refusing
    it would delete content over an absent field.
    """
    h = handle(Distinct("chunk"))
    docs = [{"_id": 1}, {"_id": 2}, {"_id": 3, "chunk": None}]
    assert [d["_id"] for d in h.reachable(docs)] == [1, 2, 3]


def test_an_unhashable_identity_does_not_raise():
    """``on`` is caller-supplied, so it can return anything at all."""
    h = handle(Distinct(lambda d: d.get("tags")))
    docs = [{"_id": 1, "tags": ["x"]}, {"_id": 2, "tags": ["x"]}]
    assert [d["_id"] for d in h.reachable(docs)] == [1, 2]


def test_naming_the_identity_is_required():
    """There is no safe default for 'these two are the same content'."""
    with pytest.raises(ValueError, match="must name the field or callable"):
        Distinct()
    with pytest.raises(TypeError, match="field name or a callable"):
        Distinct(on=17)


# ---- the composition that used to be a construction error ----------------

def test_a_budget_and_a_deduplicator_compose_on_one_handle():
    """Two cumulative rules, two separate running totals.

    This is the declaration that used to raise ``one cumulative rule``. The
    hazard behind that error was real and was *shared state*: one ``Tab``
    serving two rules meant the first one's limit governed the second. Keying
    per-read state by rule removes the hazard without removing the feature.
    """
    h = handle(Deadline(), revoked(),
               Budget(limit=100, cost_field="tokens"),
               Distinct("chunk"))
    docs = [
        {"_id": 1, "chunk": "a", "tokens": 40},
        {"_id": 2, "chunk": "a", "tokens": 40},   # redundant, costs nothing
        {"_id": 3, "chunk": "b", "tokens": 40},
        {"_id": 4, "chunk": "c", "tokens": 40},   # no room: 120 > 100
    ]
    assert [d["_id"] for d in h.reachable(docs)] == [1, 3]
    assert h.receipts()["refused_by_reason"] == {REDUNDANT: 1, OVER_BUDGET: 1}


def test_the_duplicate_does_not_spend_the_budget_it_was_refused_before():
    """And declaration order must *not* be what decides it.

    A redundant document must never be charged for: if it were, four copies
    of one passage would eat a 100-token ceiling and the caller would see
    ``over_budget`` for content that never reached the page -- with
    ``Page.spent`` reporting room that nothing occupies.

    This is declared in the order that would break it, ``Budget`` first, and
    it still holds: ``why_refused`` sorts charging rules after observing
    ones, because getting that right is the engine's job rather than the
    next caller's. The composition found this the first time two cumulative
    rules were allowed on one handle.
    """
    h = handle(Budget(limit=100, cost_field="tokens"), Distinct("chunk"))
    docs = [{"_id": i, "chunk": "same", "tokens": 40} for i in range(1, 5)]

    kept = h.reachable(docs)
    assert [d["_id"] for d in kept] == [1]
    # One admitted, three refused as duplicates, and no budget pressure at
    # all -- which is the point. Four 40-token rows would have blown a
    # 100-token ceiling if redundancy were charged.
    assert h.receipts()["refused_by_reason"] == {REDUNDANT: 3}


def test_two_equal_budgets_do_not_share_a_total():
    """The sharpest case for keying state by identity rather than value.

    ``Budget(limit=10)`` twice produces two objects that compare *equal* --
    frozen dataclasses with identical fields. Anything keyed by value merges
    them, which silently restores the bug the old restriction guarded.
    """
    tight, also_tight = Budget(limit=50, cost_field="tokens"), Budget(
        limit=50, cost_field="tokens")
    assert tight == also_tight, "the premise: they are equal"

    h = handle(tight, also_tight)
    docs = [{"_id": 1, "tokens": 30}, {"_id": 2, "tokens": 30}]
    # Each tab is charged 30 independently, so each has 20 left and the
    # second document fits in neither. If they shared, the first would read
    # 60 spent -- same admitted set here, but for the wrong reason, so the
    # check that matters is the tabs being distinct objects.
    h.reachable(docs)
    tabs = h._open_tab()
    assert tabs.for_rule(tight) is not tabs.for_rule(also_tight)


def test_break_glass_sees_the_duplicates():
    """``redundant`` is not a reason a fact is forgotten, so an audit read
    gets them back. An auditor asking what was reachable wants the copies."""
    h = handle(Distinct("chunk"))
    docs = [{"_id": 1, "chunk": "a"}, {"_id": 2, "chunk": "a"}]
    assert [d["_id"] for d in
            h.including_refused().reachable(docs)] == [1, 2]
