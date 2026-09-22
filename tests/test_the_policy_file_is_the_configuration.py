"""A policy file is wrong at load time or it is not wrong at all.

The product is a file and a connection string, so the loader is the product's
whole configuration surface -- and the failure it must not have is the one it
had: a policy file that looks like a working one, a boundary that comes up
announcing what it refuses, and a rule that was silently skipped. Every
assertion here is about a mistake being *loud*, at load, rather than
surfacing as somebody's query returning the wrong rows.

The second half is that the declarative form is not a second mechanism: what
a class body compiles to is the same `Rule` objects a stranger writes by
hand, so the two are compared directly rather than trusted to agree.
"""

from __future__ import annotations

import textwrap

import pytest

from voyd import (budget, clearance, deadline, distinct, embedded_with, guard,
                  holdable, restricted_to, revocable, sealed, subjects, tenant)
from voyd.declare import OPTIONS, REGISTRY, load
from voyd.engine import Clearance, Deadline
from voyd.engine.admission import REVOKED


@pytest.fixture(autouse=True)
def _clean_registry():
    """The registry is module state, so a test must not inherit another's."""
    REGISTRY.clear()
    OPTIONS.clear()
    yield
    REGISTRY.clear()
    OPTIONS.clear()


def policy(tmp_path, body: str) -> str:
    path = tmp_path / "voydfile.py"
    path.write_text(textwrap.dedent(body))
    return str(path)


# ---- what a class body compiles to -------------------------------------

def test_a_declaration_compiles_to_the_rules_a_stranger_writes_by_hand():
    @guard("notes")
    class Notes:
        expire_at = deadline()
        forgotten = revocable()
        tenant_id = tenant()

    spec = REGISTRY["notes"]
    assert spec.collection == "notes"
    assert spec.tenant == "tenant_id"
    # The same objects, not a parallel representation of them.
    assert Deadline(at_field="expire_at") in spec.rules
    assert any(getattr(r, "field", None) == "forgotten"
               and r.reason == REVOKED and r.reversible is False
               for r in spec.rules)


def test_the_field_name_on_the_left_is_the_field_the_rule_reads():
    @guard("docs")
    class Docs:
        gone_at = deadline()
        retracted = revocable()
        held = holdable()
        audience = restricted_to("groups")
        tokens = budget(8000)
        chunk = distinct()
        vector_model = embedded_with("v2")

    by_reason = {r.reason: r for r in REGISTRY["docs"].rules}
    assert by_reason["deadline"].at_field == "gone_at"
    assert by_reason["revoked"].field == "retracted"
    assert by_reason["quarantined"].field == "held"
    assert by_reason["quarantined"].reversible is True
    assert by_reason["not_cleared"].field == "audience"
    assert by_reason["over_budget"].cost_field == "tokens"
    assert by_reason["redundant"].on == "chunk"
    assert by_reason["wrong_model"].field == "vector_model"


def test_a_clearance_ladder_is_declarable_and_carries_its_role_map():
    @guard("docs")
    class Docs:
        expire_at = deadline()
        classification = clearance(
            order=("public", "internal", "secret"),
            roles={"analyst": "internal"}, via="roles")

    rule, = [r for r in REGISTRY["docs"].rules if isinstance(r, Clearance)]
    assert rule.field == "classification"
    assert rule.order == ("public", "internal", "secret")
    assert rule.claim == "roles"
    assert dict(rule.roles) == {"analyst": "internal"}


def test_an_embedded_subject_array_is_a_shape_declaration_not_a_rule():
    @guard("books")
    class Books:
        expire_at = deadline()
        forgotten = revocable()
        chapters = subjects(key="title")

    spec = REGISTRY["books"]
    assert spec.subjects == "chapters"
    assert spec.subject_key == "title"
    # It declares *where* the subjects are; something else still refuses them.
    assert not any(getattr(r, "field", None) == "chapters" for r in spec.rules)


def test_auto_embed_is_recorded_against_the_index_and_not_as_a_rule():
    @guard("notes")
    class Notes:
        expire_at = deadline()
        text = "unused"          # a constant is not a rule and is skipped
        body = __import__("voyd").auto_embed("voyage-3")

    assert OPTIONS["notes"]["auto_embed"] == {"body": "voyage-3"}
    assert all(getattr(r, "field", None) != "body"
               for r in REGISTRY["notes"].rules)


def test_guard_returns_the_class_it_was_given():
    @guard("notes")
    class Notes:
        expire_at = deadline()

    assert Notes.__name__ == "Notes"


# ---- a stranger's rule is a first-class line ---------------------------

def test_a_third_party_rule_in_a_class_body_is_installed_and_rebound():
    from dataclasses import dataclass

    @dataclass(frozen=True)
    class Jurisdiction:
        allowed: str
        field: str = "region"
        reason: str = "off_jurisdiction"

        def refuses(self, doc, *, when=None):
            return doc.get(self.field) != self.allowed

        def clause(self):
            return {self.field: self.allowed}

    @guard("notes")
    class Notes:
        expire_at = deadline()
        region = Jurisdiction(allowed="eu")

    rule, = [r for r in REGISTRY["notes"].rules
             if r.reason == "off_jurisdiction"]
    # Rebound to the attribute name, so a policy file does not say it twice.
    assert rule.field == "region"
    assert rule.refuses({"region": "us"}) is True


def test_half_a_rule_raises_rather_than_being_skipped_in_silence():
    # This project's own named failure: the boundary came up announcing
    # "refuses on [deadline, revoked]" while serving every document the
    # stranger's rule was written to refuse.
    class Misspelled:
        reason = "off_jurisdiction"

        def refuse(self, doc, *, when=None):     # not `refuses`
            return True

        def clause(self):
            return None

    with pytest.raises(ValueError, match="missing"):
        @guard("notes")
        class Notes:
            expire_at = deadline()
            region = Misspelled()


def test_a_rule_whose_reason_is_not_a_name_is_refused():
    class Nameless:
        reason = 7

        def refuses(self, doc, *, when=None):
            return True

        def clause(self):
            return None

    with pytest.raises(ValueError, match="not a string"):
        @guard("notes")
        class Notes:
            expire_at = deadline()
            region = Nameless()


def test_a_rule_whose_verdict_is_not_callable_is_refused():
    class NotAVerdict:
        reason = "nope"
        refuses = True
        clause = None

    with pytest.raises(ValueError):
        @guard("notes")
        class Notes:
            expire_at = deadline()
            region = NotAVerdict()


# ---- every way a policy file can be wrong, at load ---------------------

def test_a_guard_that_refuses_nothing_is_worse_than_no_guard():
    with pytest.raises(ValueError, match="no rules"):
        @guard("notes")
        class Notes:
            note = "this is not a rule"


def test_two_clocks_are_the_drift_this_exists_to_remove():
    with pytest.raises(ValueError, match="two deadline"):
        @guard("notes")
        class Notes:
            expire_at = deadline()
            erase_at = deadline()


def test_a_scope_with_two_keys_is_not_a_scope():
    with pytest.raises(ValueError, match="two tenant"):
        @guard("notes")
        class Notes:
            expire_at = deadline()
            tenant_id = tenant()
            org_id = tenant()


def test_two_subject_arrays_are_no_answer_to_which_thing_is_the_subject():
    with pytest.raises(ValueError, match="two subject arrays"):
        @guard("books")
        class Books:
            forgotten = revocable()
            chapters = subjects(key="title")
            notes = subjects(key="title")


def test_a_subject_nothing_can_name_is_one_no_erasure_can_reach():
    for bad in ("", "   "):
        with pytest.raises(ValueError, match="key="):
            subjects(key=bad)
    with pytest.raises((ValueError, TypeError)):
        subjects(key=None)          # type: ignore[arg-type]


def test_subjects_with_nothing_to_refuse_them_is_refused():
    with pytest.raises(ValueError, match="no reason to refuse"):
        @guard("books")
        class Books:
            chapters = subjects(key="title")
            tenant_id = tenant()


def test_sealing_without_a_tenant_makes_erasure_all_or_nothing():
    # One key per collection means the subject who asked to be forgotten
    # takes every other tenant with them.
    with pytest.raises(ValueError, match="no tenant"):
        @guard("notes")
        class Notes:
            expire_at = deadline()
            body = sealed()


def test_sealing_with_a_tenant_records_the_field_as_ciphertext():
    @guard("notes")
    class Notes:
        expire_at = deadline()
        tenant_id = tenant()
        body = sealed()

    assert OPTIONS["notes"]["sealed"] == ("body",)
    assert OPTIONS["notes"]["scope_field"] == "tenant_id"
    # And the safety net rides along: a sealed field reaching a read path
    # that never decrypted it is refused by name, not served as a blob.
    assert any(r.reason == "unrecoverable" and r.field == "body"
               for r in REGISTRY["notes"].rules)


def test_two_declarations_naming_the_same_model_have_to_agree():
    # Every document the index embeds would be refused by the rule beside
    # it, and the collection would read as empty.
    import voyd
    with pytest.raises(ValueError, match="auto_embed"):
        @guard("notes")
        class Notes:
            expire_at = deadline()
            vector_model = embedded_with("v1")
            body = voyd.auto_embed("v2")


def test_a_delete_cannot_become_a_revocation_with_nowhere_to_record_it():
    # Without a field to write the mark into, the delete would silently
    # do nothing at all.
    with pytest.raises(ValueError, match="revocable"):
        @guard("notes", on_delete="revoke")
        class Notes:
            expire_at = deadline()


def test_on_delete_revoke_is_opt_in_and_forward_is_the_default():
    @guard("notes", on_delete="revoke")
    class Notes:
        expire_at = deadline()
        forgotten = revocable()

    assert OPTIONS["notes"]["on_delete"] == "revoke"

    @guard("other")
    class Other:
        expire_at = deadline()

    assert OPTIONS["other"]["on_delete"] == "forward"


def test_an_unknown_on_delete_is_refused_before_a_boundary_starts():
    with pytest.raises(ValueError, match="on_delete"):
        @guard("notes", on_delete="ignore")
        class Notes:
            expire_at = deadline()


def test_a_clearance_that_cannot_be_an_ordering_is_refused():
    with pytest.raises(ValueError, match="needs an order"):
        clearance(order=())
    with pytest.raises(ValueError, match="repeats a level"):
        clearance(order=("public", "public"))
    # A role cleared for a level this policy does not define is cleared for
    # nothing, silently -- so it is not silent.
    with pytest.raises(ValueError, match="not in order"):
        clearance(order=("public", "secret"), roles={"analyst": "internal"})


def test_a_budget_with_no_arithmetic_is_refused_where_it_is_written():
    with pytest.raises(TypeError):
        @guard("notes")
        class Notes:
            expire_at = deadline()
            tokens = budget(8000.5)      # type: ignore[arg-type]


# ---- loading the file --------------------------------------------------

def test_load_executes_the_file_and_returns_what_it_declared(tmp_path):
    path = policy(tmp_path, """
        from voyd import guard, deadline, revocable, tenant

        @guard("notes", on_delete="revoke")
        class Notes:
            expire_at = deadline()
            forgotten = revocable()
            tenant_id = tenant()
    """)
    specs = load(path)
    assert set(specs) == {"notes"}
    assert specs["notes"].tenant == "tenant_id"
    assert OPTIONS["notes"]["on_delete"] == "revoke"


def test_a_policy_file_declaring_nothing_would_be_a_boundary_that_refuses_nothing(tmp_path):
    path = policy(tmp_path, """
        from voyd import guard  # noqa: F401
    """)
    with pytest.raises(ValueError, match="declared no collections"):
        load(path)


def test_loading_replaces_the_previous_policy_rather_than_accumulating(tmp_path):
    (tmp_path / "one.py").write_text(textwrap.dedent("""
        from voyd import guard, deadline
        @guard("first")
        class First:
            expire_at = deadline()
    """))
    (tmp_path / "two.py").write_text(textwrap.dedent("""
        from voyd import guard, deadline
        @guard("second")
        class Second:
            expire_at = deadline()
    """))
    assert set(load(str(tmp_path / "one.py"))) == {"first"}
    # A reload that inherited the last file's collections would serve rules
    # nobody in this file declared.
    assert set(load(str(tmp_path / "two.py"))) == {"second"}


def test_the_shipped_voydfile_is_a_policy_this_loader_accepts():
    # It is the example every reader copies and the one the container runs.
    specs = load("voydfile.py")
    assert "notes" in specs
    assert specs["notes"].tenant == "tenant_id"
    assert OPTIONS["notes"]["on_delete"] == "revoke"
    assert "deadline" in specs["notes"].describe()


def test_importing_voyd_offers_the_vocabulary_and_no_handle():
    import voyd
    assert "guard" in voyd.__all__
    # There is one way to use this and it is not an import. A handle
    # re-exported here would be a second door onto the guarantee.
    for name in ("Engine", "Model", "Admission", "AdmissionSpec"):
        assert not hasattr(voyd, name), f"voyd.{name} is application-facing"
