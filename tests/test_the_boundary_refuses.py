"""The per-document check, asked directly.

``why_refused`` is the whole guarantee: every read path in this package ends
at it, and it is pure, so it is testable without a database. What is asserted
here is not that each rule has a branch for each case -- that is coverage --
but the four properties the rest of the system is built on top of:

    it fails closed    an unreadable deadline, an unlabelled document, an
                       unmapped role and a rule that raises are all refusals.
    it names the reason  a refusal is reported, not merged: an operator
                       responds differently to `quarantined` than to
                       `deadline`, so the first reason is the specific one.
    the order is not the declared order  cumulative rules are asked last and
                       the ones that *charge* last of all, so a budget never
                       spends room on a document another rule refuses.
    the two halves agree  a rule's `clause()` is an optimisation, so the
                       documents it drops server-side must be exactly the
                       ones `refuses` would drop on the way out.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from voyd.engine import UTC, now
from voyd.engine.admission import (DEADLINE, NOT_CLEARED, OVER_BUDGET,
                                   QUARANTINED, REDUNDANT, REVOKED, UNCOSTED,
                                   UNREADABLE, UNRECOVERABLE, AdmissionSpec,
                                   Budget, Clearance, Deadline, Distinct,
                                   EmbeddedWith, Marked, Restricted,
                                   Unrecoverable, quarantined, revoked,
                                   why_refused)
from voyd.engine.admission.rules import Tab, Tabs

PAST = now() - timedelta(hours=1)
FUTURE = now() + timedelta(hours=1)


def spec(*rules, **kw) -> AdmissionSpec:
    return AdmissionSpec("notes", rules=tuple(rules), **kw)


def ask(doc, *rules, caller=None, when=None):
    """One document against a spec built from `rules`, with a fresh page."""
    s = spec(*rules)
    tab = Tabs({id(r): r.new_tab() for r in s.rules
                if getattr(r, "needs_tab", False)})
    return why_refused(doc, s, caller=caller, when=when, tab=tab)


# ---- a deadline is checked on the way out, and fails closed ------------

def test_a_deadline_that_has_passed_is_refused_while_the_row_is_on_disk():
    # The whole bug class: the TTL monitor runs about once a minute, so this
    # document exists and would be ranked. It is refused anyway.
    assert ask({"expire_at": PAST}, Deadline()) == DEADLINE
    assert ask({"expire_at": FUTURE}, Deadline()) is None


def test_no_deadline_is_pinned_and_an_unreadable_one_is_not():
    assert ask({}, Deadline()) is None
    assert ask({"expire_at": None}, Deadline()) is None
    # A lifetime that cannot be established is not a long one.
    assert ask({"expire_at": "next tuesday"}, Deadline()) == UNREADABLE
    assert ask({"expire_at": 1_700_000_000}, Deadline()) == UNREADABLE


def test_a_naive_deadline_is_read_as_utc_rather_than_crashing():
    # BSON has no zone and a default client decodes naive. Comparing that to
    # an aware now() raises, and an exception inside a filter is how the
    # filter gets skipped -- which is the leak, not the crash.
    assert ask({"expire_at": PAST.replace(tzinfo=None)}, Deadline()) == DEADLINE
    assert ask({"expire_at": FUTURE.replace(tzinfo=None)}, Deadline()) is None


def test_a_deadline_is_evaluated_at_an_instant_not_only_at_now():
    doc = {"expire_at": now() + timedelta(minutes=30)}
    assert ask(doc, Deadline(), when=now()) is None
    assert ask(doc, Deadline(), when=now() + timedelta(hours=2)) == DEADLINE


# ---- a mark is an instruction, and it has a time ------------------------

def test_a_mark_refuses_on_the_next_read_without_waiting_for_a_sweeper():
    assert ask({"forgotten": {"at": PAST}}, revoked()) == REVOKED
    assert ask({}, revoked()) is None


def test_a_mark_does_not_refuse_before_it_was_imposed():
    # Reconstructing what a model was allowed to see at 14:02 must not place
    # a 14:05 erasure before the answer that quoted the fact.
    mark = {"forgotten": {"at": now()}}
    assert ask(mark, revoked(), when=now() - timedelta(minutes=5)) is None
    assert ask(mark, revoked(), when=now() + timedelta(minutes=5)) == REVOKED


def test_a_mark_with_no_readable_time_refuses_at_every_instant():
    for mark in ({"forgotten": True}, {"forgotten": {"at": "yesterday"}},
                 {"forgotten": {}}):
        assert ask(mark, revoked(), when=PAST) == REVOKED, mark


def test_reversibility_is_declared_on_the_reason_not_decided_by_the_verb():
    # `lift()` and the erase-deadline stamp both read this, so the two
    # Marked flavours must disagree about it.
    assert revoked().reversible is False
    assert quarantined().reversible is True
    assert ask({"quarantined": {"at": PAST}}, quarantined()) == QUARANTINED


# ---- who is asking ------------------------------------------------------

def test_clearance_fails_closed_in_every_direction_it_can():
    rule = Clearance(order=("public", "internal", "secret"),
                     roles=(("analyst", "internal"),), claim="roles")
    analyst = {"roles": ["analyst"]}

    assert ask({"classification": "internal"}, rule, caller=analyst) is None
    # above their rung
    assert ask({"classification": "secret"}, rule,
               caller=analyst) == NOT_CLEARED
    # no claim at all is the lowest rung, not a pass
    assert ask({"classification": "internal"}, rule, caller=None) == NOT_CLEARED
    # an unmapped role is an unanswered question
    assert ask({"classification": "public"}, rule,
               caller={"roles": ["intern"]}) == NOT_CLEARED
    # a label this deployment does not define is not a low one
    assert ask({"classification": "cosmic"}, rule,
               caller=analyst) == NOT_CLEARED
    # untagged is not public -- and untagged is the population written
    # before anybody thought about this
    assert ask({}, rule, caller=analyst) == NOT_CLEARED


def test_clearance_takes_the_highest_rung_any_held_role_maps_to():
    rule = Clearance(order=("public", "internal", "secret"),
                     roles=(("reader", "public"), ("chief", "secret")),
                     claim="roles")
    both = {"roles": ["reader", "chief"]}
    assert ask({"classification": "secret"}, rule, caller=both) is None


def test_clearance_is_not_bypassable_and_a_forgetting_reason_is():
    # `including_refused()` exists so an auditor can see what was forgotten.
    # It is not entitled to what is above their own clearance.
    assert Clearance(order=("a",)).bypassable is False
    assert Restricted().bypassable is False
    # A forgetting reason does not declare it at all, which is the default:
    # an auditor is entitled to read what was forgotten.
    assert getattr(revoked(), "bypassable", True) is True
    assert getattr(Deadline(), "bypassable", True) is True


def test_an_unfilled_audience_is_a_restriction_not_an_absent_one():
    rule = Restricted(field="audience", claim="groups")
    legal = {"groups": ["legal"]}
    assert ask({"audience": ["legal", "deal-desk"]}, rule, caller=legal) is None
    assert ask({"audience": ["sales"]}, rule, caller=legal) == NOT_CLEARED
    assert ask({"audience": []}, rule, caller=legal) == NOT_CLEARED
    assert ask({}, rule, caller=legal) == NOT_CLEARED


def test_only_unbypassable_keeps_the_caller_rules_and_drops_the_rest():
    s = spec(Deadline(), Clearance(order=("public", "secret"),
                                   roles=(("a", "public"),), claim="roles"))
    doc = {"expire_at": PAST, "classification": "secret"}
    assert why_refused(doc, s, caller={"roles": ["a"]}) == DEADLINE
    assert why_refused(doc, s, caller={"roles": ["a"]},
                       only_unbypassable=True) == NOT_CLEARED
    cleared = {"expire_at": PAST, "classification": "public"}
    assert why_refused(cleared, s, caller={"roles": ["a"]},
                       only_unbypassable=True) is None


# ---- a vector is a (vector, model) pair ---------------------------------

def test_a_vector_from_another_model_is_refused_and_a_pending_one_is_not():
    rule = EmbeddedWith(model="v2")
    assert ask({"embedding": [0.1], "embedded_with": "v2"}, rule) is None
    assert ask({"embedding": [0.1], "embedded_with": "v1"}, rule) == "wrong_model"
    assert ask({"embedding": [0.1]}, rule) == "wrong_model"
    # No vector yet is pending, not wrong: the embed worker has to see it.
    assert ask({"embedded_with": "v1"}, rule) is None


def test_ciphertext_reaching_a_read_path_that_never_decrypted_it_is_named():
    from bson.binary import Binary
    rule = Unrecoverable(field="text")
    sealed = Binary(b"\x01\x02", 6)
    assert ask({"text": sealed}, rule) == UNRECOVERABLE
    # Not every Binary is ciphertext -- a thumbnail is not a refusal.
    assert ask({"text": Binary(b"\x01\x02", 0)}, rule) is None
    assert ask({"text": "plain"}, rule) is None


# ---- set-relative reasons: a property of the page, not the document -----

def test_a_budget_admits_a_strict_prefix_and_latches_closed():
    rule = Budget(limit=100, cost_field="tokens")
    s = spec(Deadline(), rule)
    tab = Tabs({id(rule): rule.new_tab()})

    def verdict(cost):
        return why_refused({"tokens": cost}, s, tab=tab)

    assert verdict(60) is None
    # Does not fit. Not partially spent, and the page is now closed: a
    # later small hit is not slipped in ahead of it, because that would
    # reorder results by size rather than by relevance.
    assert verdict(60) == OVER_BUDGET
    assert verdict(1) == OVER_BUDGET
    assert tab.spent == 60


def test_the_same_document_is_admitted_alone_and_refused_in_company():
    # The property no index filter and no policy engine can express.
    doc = {"tokens": 80}
    assert ask(doc, Budget(limit=100)) is None
    rule = Budget(limit=100)
    s, tab = spec(rule), None
    tab = Tabs({id(rule): rule.new_tab()})
    assert why_refused(doc, s, tab=tab) is None
    assert why_refused(dict(doc), s, tab=tab) == OVER_BUDGET


def test_a_cost_that_cannot_be_read_is_refused_but_does_not_close_the_page():
    rule = Budget(limit=100)
    s = spec(rule)
    tab = Tabs({id(rule): rule.new_tab()})
    for bad in (None, "many", -1, True, 3.7):
        assert why_refused({"tokens": bad}, s, tab=tab) == UNCOSTED, bad
    # One uncostable document says nothing about the room left.
    assert why_refused({"tokens": 90}, s, tab=tab) is None


def test_a_duplicate_is_dropped_and_the_first_survivor_takes_the_slot():
    rule = Distinct(on="chunk")
    s = spec(Deadline(), rule)
    tab = Tabs({id(rule): rule.new_tab()})
    assert why_refused({"chunk": "a"}, s, tab=tab) is None
    assert why_refused({"chunk": "a"}, s, tab=tab) == REDUNDANT
    assert why_refused({"chunk": "b"}, s, tab=tab) is None
    # An expired copy that ranked higher must not claim the slot and lose
    # the live one behind it.
    assert why_refused({"chunk": "c", "expire_at": PAST}, s, tab=tab) == DEADLINE
    assert why_refused({"chunk": "c"}, s, tab=tab) is None


def test_a_document_with_no_computable_identity_is_admitted():
    # This rule answers "is this a duplicate", and a missing hash is not
    # evidence that it is one. Failing closed here deletes content.
    rule = Distinct(on="chunk")
    s = spec(rule)
    tab = Tabs({id(rule): rule.new_tab()})
    assert why_refused({}, s, tab=tab) is None
    assert why_refused({"chunk": ["unhashable"]}, s, tab=tab) is None


def test_distinct_refuses_to_guess_what_makes_two_documents_the_same():
    with pytest.raises(ValueError):
        Distinct()
    with pytest.raises(TypeError):
        Distinct(on=3)


def test_a_budget_whose_arithmetic_would_be_ambiguous_fails_at_construction():
    # Cheap at construction, rather than every document `over_budget` at
    # runtime with receipts that still look exact.
    with pytest.raises(TypeError):
        Budget(limit=3.7)          # type: ignore[arg-type]
    with pytest.raises(TypeError):
        Budget(limit=True)         # type: ignore[arg-type]
    with pytest.raises(ValueError):
        Budget(limit=-1)
    with pytest.raises(ValueError):
        Tab(limit=10).charge(-1)


# ---- the asking order is the package's, not the policy author's ---------

def test_a_budget_never_spends_room_on_a_document_another_rule_refuses():
    budget = Budget(limit=100)
    # Declared *first*, which is the order that would be wrong.
    s = spec(budget, Deadline(), revoked())
    tab = Tabs({id(budget): budget.new_tab()})
    assert why_refused({"tokens": 90, "expire_at": PAST}, s, tab=tab) == DEADLINE
    assert tab.spent == 0, "an expired document was charged for"
    assert why_refused({"tokens": 90}, s, tab=tab) is None
    assert tab.spent == 90


def test_a_de_duplicator_is_asked_before_the_budget_that_charges():
    # Four copies of one passage must not report `over_budget` for content
    # that never reached the page.
    budget, distinct = Budget(limit=100), Distinct(on="chunk")
    s = spec(budget, distinct)
    tab = Tabs({id(budget): budget.new_tab(), id(distinct): distinct.new_tab()})
    assert why_refused({"chunk": "a", "tokens": 90}, s, tab=tab) is None
    for _ in range(3):
        assert why_refused({"chunk": "a", "tokens": 90}, s, tab=tab) == REDUNDANT
    assert tab.spent == 90


def test_two_cumulative_rules_do_not_share_one_running_total():
    # Keyed by identity, so two equal-but-deliberate declarations cannot
    # have one limit silently govern the other.
    a, b = Budget(limit=100), Budget(limit=100)
    assert a == b and id(a) != id(b)
    tabs = Tabs({id(a): a.new_tab(), id(b): b.new_tab()})
    assert tabs.for_rule(a) is not tabs.for_rule(b)


def test_among_the_pure_rules_the_declared_order_is_what_is_reported():
    # An operator responds differently to a quarantine than to an expiry,
    # so the reasons are reported rather than merged into "refused".
    doc = {"expire_at": PAST, "quarantined": {"at": PAST}}
    assert ask(doc, Deadline(), quarantined()) == DEADLINE
    assert ask(doc, quarantined(), Deadline()) == QUARANTINED


# ---- a rule must not be able to open the gate ---------------------------

def test_a_rule_that_raises_refuses_the_document_and_is_named():
    class Exploding:
        reason = "jurisdiction"

        def refuses(self, doc, *, when=None):
            raise RuntimeError("upstream is down")

        def clause(self):
            return None

    # An exception inside a filter is how the filter gets skipped, and a
    # third-party rule must not be a way back to that.
    assert ask({}, Exploding()) == "jurisdiction"


def test_a_third_party_costing_callable_that_raises_is_uncosted_not_free():
    def cost(doc):
        raise RuntimeError("tokenizer exploded")

    rule = Budget(limit=100, cost=cost)
    s = spec(rule)
    tab = Tabs({id(rule): rule.new_tab()})
    assert why_refused({}, s, tab=tab) == UNCOSTED
    assert tab.spent == 0


def test_a_spec_with_no_rules_still_refuses_the_two_defaults():
    # `with_defaults` is what stops a bare spec from being an open gate.
    s = AdmissionSpec("notes")
    assert why_refused({"expire_at": PAST}, s) == DEADLINE
    assert why_refused({"forgotten": {"at": PAST}}, s) == REVOKED
    assert why_refused({}, s) is None


# ---- the query half is an optimisation, so it has to agree --------------

def test_the_deadline_clause_drops_exactly_what_the_check_would():
    # Both halves in one place, because a clause that is *narrower* than the
    # check is a silent leak and a clause that is wider is only slower.
    clause = Deadline().clause()
    arms = clause["$or"]
    assert {"expire_at": None} in arms
    assert {"expire_at": {"$exists": False}} in arms
    # Pinned rows -- explicit null and missing -- are matched by the clause
    # and admitted by the check. They must not disagree.
    assert why_refused({"expire_at": None}, spec(Deadline())) is None


def test_a_mark_clause_admits_the_unmarked_and_only_the_unmarked():
    arms = revoked().clause()["$or"]
    assert {"forgotten": None} in arms
    assert {"forgotten": {"$exists": False}} in arms
    at = revoked().clause_at(now())["$or"]
    # At an instant, a mark imposed *later* is still readable.
    assert any("$gt" in str(arm) for arm in at)


def test_the_rules_with_no_expressible_clause_say_so_rather_than_guess():
    # A clause-only rule would be a hole; per-document-only is merely
    # slower. Each of these is the second kind, on purpose.
    for rule in (Unrecoverable(), Clearance(order=("a",)), Restricted(),
                 Budget(limit=1), Distinct(on="chunk")):
        assert rule.clause() is None, rule


def test_a_clearance_clause_for_a_caller_cleared_for_nothing_matches_nothing():
    rule = Clearance(order=("public", "internal", "secret"),
                     roles=(("analyst", "internal"),), claim="roles")
    assert rule.clause_for(None) == {"classification": {"$in": []}}
    assert rule.clause_for({"roles": ["analyst"]}) == {
        "classification": {"$in": ["public", "internal"]}}


def test_a_model_clause_keeps_the_rows_still_waiting_for_a_vector():
    arms = EmbeddedWith(model="v2").clause()["$or"]
    assert {"embedding": None} in arms
    assert {"embedded_with": "v2"} in arms


# ---- the spec is a declaration, compared by value -----------------------

def test_two_specs_disagreeing_about_the_tenant_are_not_the_same_spec():
    # Handles are deduplicated by spec equality, so leaving the tenant out
    # of identity let declaration order decide whether it was enforced.
    assert AdmissionSpec("notes") != AdmissionSpec("notes", tenant="tenant_id")


def test_a_spec_says_what_it_refuses_in_one_line():
    s = AdmissionSpec("notes", tenant="tenant_id",
                      rules=(Deadline(), revoked()),
                      subjects="chapters", subject_key="title")
    line = s.describe()
    assert "notes" in line and "deadline" in line and "revoked" in line
    assert "tenant_id" in line and "chapters" in line and "title" in line


def test_a_subject_declaration_that_cannot_be_acted_on_is_refused_at_load():
    with pytest.raises(ValueError):
        AdmissionSpec("notes", subjects=" ").with_defaults()
    with pytest.raises(ValueError):
        AdmissionSpec("notes", subject_key="title").with_defaults()
    # One level only: a redaction whose depth nobody can state is worse
    # than one that refuses to start.
    with pytest.raises(ValueError):
        AdmissionSpec("notes", subjects="a.b").with_defaults()


def test_a_cumulative_rule_with_nowhere_to_keep_its_total_is_refused():
    class Halfway:
        reason = "budgetish"
        needs_tab = True

        def refuses(self, doc, *, when=None, tab=None):
            return False

        def clause(self):
            return None

    with pytest.raises(TypeError):
        AdmissionSpec("notes", rules=(Halfway(),)).with_defaults()


def test_the_clock_is_pinned_rather_than_inherited():
    assert now().tzinfo is UTC
    assert Marked(field="f", reason="r").refuses({"f": {"at": PAST}})
