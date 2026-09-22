"""A plan is only worth having if it is honest about its own coverage.

Two things are being asserted here, and the second is the harder one.

The first is that the comparison is right: a rule removed shows up as
documents becoming reachable, a rule added shows up as documents becoming
refused, and a collection that loses its `@guard` shows up as both -- a
structural finding that needs no data, and a count that needs some.

The second is that the plan **refuses to answer** the questions it cannot.
A set-relative rule is not a weaker per-document rule, it is a different
question, and a plan that quietly evaluated `budget(4000)` against one
document at a time would print a confident number about a page that never
existed. So the tests below assert what is set aside as hard as they
assert what is counted -- because the failure mode of a planning tool is
not being wrong, it is being narrow and sounding total.

Pure: no cluster, no driver, no network. That is the point of the split --
every case here would need fixture data on a real deployment, and none of
them needs a deployment.
"""

from __future__ import annotations

import json
import textwrap
from datetime import datetime, timedelta, timezone

import pytest

from voyd.declare import OPTIONS, REGISTRY, load
from voyd.engine.plan import (GUARD_ADDED, GUARD_REMOVED, NEEDS_CALLER,
                              SET_RELATIVE, SUBJECTS_REMOVED, TENANT_CHANGED,
                              TENANT_REMOVED, compare, plan, plannable,
                              structural)
from voyd.wire.plan import as_json, render
from voyd.wire.plan import main as plan_main

UTC = timezone.utc
NOW = datetime(2026, 9, 22, tzinfo=UTC)
PAST = NOW - timedelta(days=7)
FUTURE = NOW + timedelta(days=7)


@pytest.fixture(autouse=True)
def _clean_registry():
    REGISTRY.clear()
    OPTIONS.clear()
    yield
    REGISTRY.clear()
    OPTIONS.clear()


def policy(tmp_path, name: str, body: str) -> str:
    path = tmp_path / name
    path.write_text(textwrap.dedent(body))
    return str(path)


def specs(tmp_path, name: str, body: str) -> dict:
    return load(policy(tmp_path, name, body))


# ---- the comparison ----------------------------------------------------

def test_dropping_a_rule_is_counted_as_documents_becoming_reachable(tmp_path):
    current = specs(tmp_path, "in_force.py", """
        from voyd import guard, deadline, revocable
        @guard("notes")
        class Notes:
            expire_at = deadline()
            forgotten = revocable()
    """)
    proposed = specs(tmp_path, "proposed.py", """
        from voyd import guard, deadline
        @guard("notes")
        class Notes:
            expire_at = deadline()
    """)
    # A mark is *presence*, not truth: `revocable()` refuses a document
    # that carries the field at all, so an unmarked one omits it.
    docs = [{"expire_at": FUTURE, "forgotten": "gdpr-4411"},
            {"expire_at": FUTURE, "forgotten": "gdpr-4412"},
            {"expire_at": PAST},      # expired under both
            {"expire_at": FUTURE}]    # admitted under both
    one = compare("notes", current["notes"], proposed["notes"], docs, when=NOW)
    assert one.newly_reachable == {"revoked": 2}
    assert one.newly_refused == {}
    assert one.unchanged_refused == 1
    assert one.unchanged_admitted == 1
    assert one.sampled == 4


def test_adding_a_rule_is_counted_in_the_other_direction(tmp_path):
    current = specs(tmp_path, "in_force.py", """
        from voyd import guard, deadline
        @guard("notes")
        class Notes:
            expire_at = deadline()
    """)
    proposed = specs(tmp_path, "proposed.py", """
        from voyd import guard, deadline, holdable
        @guard("notes")
        class Notes:
            expire_at = deadline()
            held = holdable()
    """)
    docs = [{"expire_at": FUTURE, "held": "under review"},
            {"expire_at": FUTURE}]
    one = compare("notes", current["notes"], proposed["notes"], docs, when=NOW)
    assert one.newly_refused == {"quarantined": 1}
    assert one.newly_reachable == {}


def test_a_document_refused_for_a_different_reason_is_neither_direction(tmp_path):
    # It did not become reachable and it did not stop being reachable. A
    # bucket that folded this into either one would move a document across
    # the boundary in a report where nothing moved.
    current = specs(tmp_path, "in_force.py", """
        from voyd import guard, deadline, revocable
        @guard("notes")
        class Notes:
            expire_at = deadline()
            forgotten = revocable()
    """)
    proposed = specs(tmp_path, "proposed.py", """
        from voyd import guard, deadline, revocable, holdable
        @guard("notes")
        class Notes:
            held = holdable()
            expire_at = deadline()
            forgotten = revocable()
    """)
    docs = [{"expire_at": PAST, "held": "under review"}]
    one = compare("notes", current["notes"], proposed["notes"], docs, when=NOW)
    assert one.reason_changed == {("deadline", "quarantined"): 1}
    assert not one.newly_reachable and not one.newly_refused


def test_an_unguarded_collection_admits_everything(tmp_path):
    # Not a quirk: it is what deleting a `@guard` means, and the counts
    # have to say so or the structural finding stands alone with a zero
    # beside it.
    current = specs(tmp_path, "in_force.py", """
        from voyd import guard, deadline, revocable
        @guard("notes")
        class Notes:
            expire_at = deadline()
            forgotten = revocable()
    """)
    docs = [{"expire_at": PAST},
            {"expire_at": FUTURE, "forgotten": "gdpr-4411"}]
    one = compare("notes", current["notes"], None, docs, when=NOW)
    assert one.newly_reachable == {"deadline": 1, "revoked": 1}


# ---- what it refuses to answer -----------------------------------------

def test_a_set_relative_rule_is_set_aside_by_name(tmp_path):
    # `budget` refuses a document because of the *other* documents on the
    # page. Evaluated against a sample it would either raise or invent an
    # answer about a page that never existed.
    loaded = specs(tmp_path, "in_force.py", """
        from voyd import guard, deadline, budget
        @guard("notes")
        class Notes:
            expire_at = deadline()
            tokens = budget(4000)
    """)
    kept, aside = plannable(loaded["notes"], with_caller=False)
    assert [(s.rule, s.why) for s in aside] == [("over_budget", SET_RELATIVE)]
    assert all(not getattr(r, "needs_tab", False) for r in kept.rules)
    # And the rest of the policy is still planned, not abandoned with it.
    assert any(r.reason == "deadline" for r in kept.rules)


def test_a_caller_rule_is_set_aside_unless_a_caller_is_named(tmp_path):
    loaded = specs(tmp_path, "in_force.py", """
        from voyd import guard, deadline, clearance
        @guard("notes")
        class Notes:
            expire_at = deadline()
            level = clearance(order=("public", "secret"),
                              roles={"analyst": "secret"})
    """)
    _, aside = plannable(loaded["notes"], with_caller=False)
    assert [s.why for s in aside] == [NEEDS_CALLER]
    # Named, and it becomes an ordinary rule.
    kept, aside = plannable(loaded["notes"], with_caller=True)
    assert aside == ()
    assert any(getattr(r, "needs_caller", False) for r in kept.rules)


def test_setting_every_rule_aside_reports_that_nothing_was_compared(tmp_path):
    # The trap this guards: `with_defaults()` installs a deadline and a
    # revocation whenever `rules` is empty, so a spec stripped to nothing
    # would come back guarded by two rules the operator never wrote -- and
    # the plan would report a difference this code invented.
    loaded = specs(tmp_path, "in_force.py", """
        from voyd import guard, budget
        @guard("notes")
        class Notes:
            tokens = budget(4000)
    """)
    kept, aside = plannable(loaded["notes"], with_caller=False)
    assert kept is None and len(aside) == 1
    one = compare("notes", loaded["notes"], loaded["notes"],
                  [{"tokens": 10}], when=NOW)
    assert one.not_compared is True
    assert one.sampled == 0 and not one.changed


def test_an_absent_guard_is_not_an_empty_one(tmp_path):
    # `None` in, `None` out. Running a bare spec through `with_defaults()`
    # would manufacture the two default rules for a collection no policy
    # guards, and `guard_removed` would silently become "no change".
    kept, aside = plannable(None, with_caller=False)
    assert kept is None and aside == ()


# ---- findings that do not need data ------------------------------------

def test_a_removed_guard_is_structural_and_fails_open(tmp_path):
    current = specs(tmp_path, "in_force.py", """
        from voyd import guard, deadline
        @guard("notes")
        class Notes:
            expire_at = deadline()
    """)
    found = structural(current, {})
    assert [(s.kind, s.fails_open) for s in found] == [(GUARD_REMOVED, True)]


def test_a_new_guard_is_structural_and_does_not_fail_open(tmp_path):
    proposed = specs(tmp_path, "proposed.py", """
        from voyd import guard, deadline
        @guard("notes")
        class Notes:
            expire_at = deadline()
    """)
    found = structural({}, proposed)
    assert [(s.kind, s.fails_open) for s in found] == [(GUARD_ADDED, False)]


def test_dropping_the_tenant_is_reported_even_with_no_documents(tmp_path):
    # The tenant is enforced by the handle against the scope a read is
    # bound to, not by a rule, so no per-document count would ever catch
    # this. It has to be structural or it is nothing.
    current = specs(tmp_path, "in_force.py", """
        from voyd import guard, deadline, tenant
        @guard("notes")
        class Notes:
            expire_at = deadline()
            tenant_id = tenant()
    """)
    proposed = specs(tmp_path, "proposed.py", """
        from voyd import guard, deadline
        @guard("notes")
        class Notes:
            expire_at = deadline()
    """)
    found = structural(current, proposed)
    assert [(s.kind, s.fails_open) for s in found] == [(TENANT_REMOVED, True)]
    assert "tenant_id" in found[0].detail


def test_moving_the_tenant_to_another_field_is_not_assumed_safe(tmp_path):
    current = specs(tmp_path, "in_force.py", """
        from voyd import guard, deadline, tenant
        @guard("notes")
        class Notes:
            expire_at = deadline()
            tenant_id = tenant()
    """)
    proposed = specs(tmp_path, "proposed.py", """
        from voyd import guard, deadline, tenant
        @guard("notes")
        class Notes:
            expire_at = deadline()
            org_id = tenant()
    """)
    found = structural(current, proposed)
    assert [(s.kind, s.fails_open) for s in found] == [(TENANT_CHANGED, True)]


def test_embedded_subjects_ceasing_to_be_subjects_fails_open(tmp_path):
    current = specs(tmp_path, "in_force.py", """
        from voyd import guard, deadline, revocable, subjects
        @guard("books")
        class Books:
            expire_at = deadline()
            forgotten = revocable()
            chapters = subjects(key="slug")
    """)
    proposed = specs(tmp_path, "proposed.py", """
        from voyd import guard, deadline, revocable
        @guard("books")
        class Books:
            expire_at = deadline()
            forgotten = revocable()
    """)
    found = structural(current, proposed)
    assert [(s.kind, s.fails_open) for s in found] == [(SUBJECTS_REMOVED, True)]


def test_a_plan_with_no_documents_still_carries_the_structural_findings(tmp_path):
    current = specs(tmp_path, "in_force.py", """
        from voyd import guard, deadline
        @guard("notes")
        class Notes:
            expire_at = deadline()
    """)
    result = plan(current, {}, lambda _c: iter(()))
    assert result.sampled == 0
    assert result.fails_open is True
    assert result.changed is True


# ---- the clock ---------------------------------------------------------

def test_the_same_policy_at_two_instants_is_a_real_question(tmp_path):
    # Nothing about the policy changed. The plan is run against one clock,
    # and a deadline is a function of it -- which is what makes `--at` a
    # question with an answer rather than a flag that does nothing.
    loaded = specs(tmp_path, "in_force.py", """
        from voyd import guard, deadline
        @guard("notes")
        class Notes:
            expire_at = deadline()
    """)
    doc = {"expire_at": NOW + timedelta(days=1)}
    fresh = compare("notes", loaded["notes"], loaded["notes"], [doc], when=NOW)
    assert fresh.unchanged_admitted == 1
    later = compare("notes", loaded["notes"], loaded["notes"], [doc],
                    when=NOW + timedelta(days=30))
    assert later.unchanged_refused == 1


# ---- the whole plan ----------------------------------------------------

def test_fails_open_is_true_only_in_the_admitting_direction(tmp_path):
    current = specs(tmp_path, "in_force.py", """
        from voyd import guard, deadline
        @guard("notes")
        class Notes:
            expire_at = deadline()
    """)
    proposed = specs(tmp_path, "proposed.py", """
        from voyd import guard, deadline, holdable
        @guard("notes")
        class Notes:
            expire_at = deadline()
            held = holdable()
    """)
    tighter = plan(current, proposed, lambda _c: [{"expire_at": FUTURE,
                                                   "held": "hold"}], when=NOW)
    assert tighter.changed is True
    assert tighter.fails_open is False, (
        "a change that refuses more must not fail a build, or the gate "
        "teaches people to bypass it")
    looser = plan(proposed, current, lambda _c: [{"expire_at": FUTURE,
                                                  "held": "hold"}], when=NOW)
    assert looser.fails_open is True


def test_one_collection_can_be_asked_about_alone(tmp_path):
    current = specs(tmp_path, "in_force.py", """
        from voyd import guard, deadline
        @guard("notes")
        class Notes:
            expire_at = deadline()
        @guard("cases")
        class Cases:
            expire_at = deadline()
    """)
    result = plan(current, {}, lambda _c: iter(()), collections=["notes"])
    assert [c.collection for c in result.collections] == ["notes"]
    assert [s.collection for s in result.structural] == ["notes"]


# ---- what it prints ----------------------------------------------------

def test_the_report_leads_with_what_becomes_reachable(tmp_path):
    current = specs(tmp_path, "in_force.py", """
        from voyd import guard, deadline, revocable
        @guard("notes")
        class Notes:
            expire_at = deadline()
            forgotten = revocable()
    """)
    proposed = specs(tmp_path, "proposed.py", """
        from voyd import guard, deadline
        @guard("notes")
        class Notes:
            expire_at = deadline()
    """)
    result = plan(current, proposed,
                  lambda _c: [{"expire_at": FUTURE, "forgotten": "gdpr-1"}],
                  when=NOW)
    text = render(result)
    assert "become reachable" in text
    assert "were refused as revoked" in text
    # The reachable section is above everything else it printed.
    assert text.index("become reachable") < text.index("newly reachable:")


def test_the_report_names_what_it_did_not_plan(tmp_path):
    loaded = specs(tmp_path, "in_force.py", """
        from voyd import guard, deadline, budget
        @guard("notes")
        class Notes:
            expire_at = deadline()
            tokens = budget(4000)
    """)
    result = plan(loaded, loaded, lambda _c: [{"expire_at": FUTURE,
                                               "tokens": 10}], when=NOW)
    text = render(result)
    assert SET_RELATIVE in text
    assert "notes.over_budget" in text
    assert "A sample is not a page" in text


def test_the_json_carries_the_bit_a_gate_reads(tmp_path):
    current = specs(tmp_path, "in_force.py", """
        from voyd import guard, deadline
        @guard("notes")
        class Notes:
            expire_at = deadline()
    """)
    result = plan(current, {}, lambda _c: iter(()))
    blob = json.loads(json.dumps(as_json(result)))
    assert blob["fails_open"] is True
    assert blob["structural"][0]["kind"] == GUARD_REMOVED


# ---- the command --------------------------------------------------------

def test_the_command_exits_nonzero_when_the_boundary_opens(tmp_path, capsys):
    # The product. A policy change that opens the boundary fails a build.
    a = policy(tmp_path, "in_force.py", """
        from voyd import guard, deadline, revocable
        @guard("notes")
        class Notes:
            expire_at = deadline()
            forgotten = revocable()
    """)
    b = policy(tmp_path, "proposed.py", """
        from voyd import guard, deadline, revocable
        @guard("other")
        class Other:
            expire_at = deadline()
            forgotten = revocable()
    """)
    assert plan_main(["--current", a, "--proposed", b]) == 1
    assert GUARD_REMOVED in capsys.readouterr().out


def test_the_command_exits_zero_when_it_only_closes(tmp_path, capsys):
    a = policy(tmp_path, "in_force.py", """
        from voyd import guard, deadline
        @guard("notes")
        class Notes:
            expire_at = deadline()
    """)
    b = policy(tmp_path, "proposed.py", """
        from voyd import guard, deadline, holdable
        @guard("notes")
        class Notes:
            expire_at = deadline()
            held = holdable()
    """)
    assert plan_main(["--current", a, "--proposed", b]) == 0
    capsys.readouterr()


def test_the_command_needs_no_cluster_for_the_structural_half(tmp_path, capsys):
    # No --target, no credentials, no network. This is the form that runs
    # in a pull request, where there is no production cluster to reach.
    a = policy(tmp_path, "in_force.py", """
        from voyd import guard, deadline, tenant
        @guard("notes")
        class Notes:
            expire_at = deadline()
            tenant_id = tenant()
    """)
    b = policy(tmp_path, "proposed.py", """
        from voyd import guard, deadline
        @guard("notes")
        class Notes:
            expire_at = deadline()
    """)
    assert plan_main(["--current", a, "--proposed", b, "--json"]) == 1
    blob = json.loads(capsys.readouterr().out)
    assert blob["sampled"] == 0
    assert blob["structural"][0]["kind"] == TENANT_REMOVED


def test_a_policy_file_that_will_not_load_is_an_error_not_a_verdict(
        tmp_path, capsys):
    # Exit 2, not 0 and not 1. A plan that could not be computed must not
    # be reported as a plan that found nothing -- that is the one way this
    # tool could wave a change through.
    a = policy(tmp_path, "in_force.py", """
        from voyd import guard, deadline
        @guard("notes")
        class Notes:
            expire_at = deadline()
    """)
    b = policy(tmp_path, "proposed.py", "x = 1\n")
    assert plan_main(["--current", a, "--proposed", b]) == 2
    assert "voyd-plan:" in capsys.readouterr().err


# ---- reading real documents --------------------------------------------

def test_a_full_read_is_allowed_to_make_a_claim_a_sample_is_not(tmp_path):
    # Not cosmetic. "Nothing becomes reachable" is a statement about the
    # collection, and a sample cannot support it -- so the sampled form
    # says where its number came from and the full read does not have to.
    current = specs(tmp_path, "in_force.py", """
        from voyd import guard, deadline
        @guard("notes")
        class Notes:
            expire_at = deadline()
    """)
    docs = [{"expire_at": FUTURE}]
    estimate = plan(current, current, lambda _c: docs, when=NOW)
    assert "--all to say it about the collection" in render(estimate)
    complete = plan(current, current, lambda _c: docs, when=NOW,
                    exhaustive=True)
    assert "--all" not in render(complete)


def test_the_sampler_reads_around_the_boundary(direct, database, tmp_path):
    """A plan has to see the documents the current policy refuses.

    The one thing the pure half cannot check, and the reason it is worth a
    cluster: sampling *through* the proxy would return only what is
    already admitted, and a plan that could not see a refused document
    could never report that one is about to become reachable.
    """
    from voyd.wire.plan import Sampler

    db = direct[database]
    db.notes.insert_many([{"expire_at": PAST} for _ in range(30)]
                         + [{"expire_at": FUTURE} for _ in range(10)])
    current = specs(tmp_path, "in_force.py", """
        from voyd import guard, deadline
        @guard("notes")
        class Notes:
            expire_at = deadline()
        @guard("never_created")
        class Absent:
            expire_at = deadline()
    """)
    sampler = Sampler(db, size=1000, everything=True)
    result = plan(current, {}, sampler, when=NOW, exhaustive=True)

    notes = next(c for c in result.collections if c.collection == "notes")
    assert notes.sampled == 40
    # The thirty the boundary refuses are exactly the ones the plan is
    # about. A sample taken through the proxy would have found none of them.
    assert notes.newly_reachable == {"deadline": 30}
    # And a collection the policy declares but the cluster has never seen
    # is reported, not raised: the structural finding for it still holds.
    assert sampler.missing == ["never_created"]
    assert any(s.collection == "never_created" for s in result.structural)
