"""The two things a compliance pipeline needs that a terminal cannot give.

A plan printed to a log answers a question once, for whoever was
watching. The questions that arrive later are different ones:

    whose access did this widen?   one plan, run against no caller, sets
                                   every caller-dependent rule aside by
                                   name -- correctly, and unhelpfully.
    what did the check say then?   and has anybody edited it since?

So: a role matrix, and an attestation.

The matrix tests are mostly about **not double counting**. One document
reachable by four roles is one document that got out, and a headline
number that summed the roles would grow with the size of the role table
rather than with the size of the exposure.

The attestation tests are mostly about **not overclaiming**. This is a
symmetric MAC: anyone who can verify can forge. It is evidence of
integrity, never of origin, and the assertions below pin the difference
in the sentences the tool prints, because that is where a reader will
take the claim from.

Pure: no cluster, no driver, no network.
"""

from __future__ import annotations

import json
import textwrap
from datetime import datetime, timedelta, timezone

import pytest

from voyd.declare import OPTIONS, REGISTRY, load
from voyd.engine import attest
from voyd.engine.plan import matrix
from voyd.wire.plan import main as plan_main
from voyd.wire.plan import matrix_as_json, render_matrix

UTC = timezone.utc
NOW = datetime(2026, 9, 22, tzinfo=UTC)
FUTURE = NOW + timedelta(days=30)

WIDENS = """
    from voyd import clearance, deadline, guard

    @guard("records")
    class Records:
        expire_at = deadline()
        sensitivity = clearance(order=("public", "phi"),
                                roles={{"clinician": "phi",
                                        "support": "{support}"}})
"""

ROLES = {"tier1-support": {"roles": ["support"]},
         "clinician": {"roles": ["clinician"]},
         "analyst": {"roles": ["analyst"]}}

# Half public, half PHI. The public half is the control: it must not move
# for anybody, or the number being reported is not the number described.
DOCS = [{"sensitivity": "phi" if i % 2 else "public", "expire_at": FUTURE}
        for i in range(824)]


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


@pytest.fixture
def widening(tmp_path):
    """Support is promoted from `public` to `phi`. Nobody else moves."""
    before = specs(tmp_path, "in_force.py", WIDENS.format(support="public"))
    after = specs(tmp_path, "proposed.py", WIDENS.format(support="phi"))
    return before, after


# ---- whose access did this widen? --------------------------------------

def test_the_matrix_names_the_role_that_gains(widening):
    before, after = widening
    result = matrix(before, after, lambda _c: DOCS, ROLES, when=NOW,
                    exhaustive=True)
    assert result.worst == "tier1-support"
    assert result.plans["tier1-support"].newly_reachable_total == 412
    # The control. A role whose mapping did not change gains nothing, and
    # the public documents do not move for anybody.
    assert result.plans["clinician"].newly_reachable_total == 0
    assert result.plans["analyst"].newly_reachable_total == 0


def test_the_headline_is_the_worst_role_and_not_the_sum(widening):
    """Summing roles measures the role table, not the exposure.

    Three roles that each gain the same 412 documents have exposed 412
    documents between them, not 1,236. A number that grows when somebody
    adds a read-only role to the JSON is not a number about a leak.
    """
    before, after = widening
    everyone = {name: {"roles": ["support"]}
                for name in ("one", "two", "three")}
    result = matrix(before, after, lambda _c: DOCS, everyone, when=NOW)
    assert all(p.newly_reachable_total == 412
               for p in result.plans.values())
    assert result.newly_reachable_total == 412


def test_the_data_is_read_once_however_many_roles_there_are(widening):
    """A second role handed an exhausted cursor reports zero and looks clean.

    This is the correctness requirement hiding inside what looks like an
    optimisation: `sample` returns whatever a cluster is streaming, so
    the loops have to be inverted underneath rather than the function
    called again per role.
    """
    before, after = widening
    calls = []

    def sample(collection):
        calls.append(collection)
        return iter(DOCS)          # single-use, like a real cursor

    result = matrix(before, after, sample, ROLES, when=NOW)
    assert calls == ["records"], "the collection was sampled once per role"
    assert all(p.sampled == len(DOCS) for p in result.plans.values())


def test_a_structural_finding_is_held_once_not_per_role(tmp_path):
    # Printing `tenant_removed` once per role scales the loudest line in
    # the report by the size of the role table until it reads as noise.
    before = specs(tmp_path, "in_force.py", """
        from voyd import guard, deadline, tenant
        @guard("records")
        class Records:
            expire_at = deadline()
            tenant_id = tenant()
    """)
    after = specs(tmp_path, "proposed.py", """
        from voyd import guard, deadline
        @guard("records")
        class Records:
            expire_at = deadline()
    """)
    result = matrix(before, after, lambda _c: iter(()), ROLES, when=NOW)
    assert [s.kind for s in result.structural] == ["tenant_removed"]
    assert all(p.structural == [] for p in result.plans.values())
    # And the one bit a gate reads still sees it, which is the whole
    # reason holding it apart is safe.
    assert result.fails_open is True
    assert render_matrix(result).count("tenant_removed") == 1


def test_planning_against_no_caller_at_all_is_refused(widening):
    before, after = widening
    with pytest.raises(ValueError, match="at least one named caller"):
        matrix(before, after, lambda _c: DOCS, {}, when=NOW)


def test_the_report_leads_with_the_role_that_gains_most(widening):
    before, after = widening
    text = render_matrix(matrix(before, after, lambda _c: DOCS, ROLES,
                                when=NOW, exhaustive=True))
    assert text.index("tier1-support") < text.index("analyst")
    assert "were refused as not_cleared" in text
    assert "worst caller: tier1-support" in text


# ---- what did the check say, and has it been edited? -------------------

def envelope_for(plan: dict, **policies) -> dict:
    return attest.envelope(plan=plan, policies=policies, tool="suite",
                           at=NOW)


def test_an_intact_envelope_verifies_and_says_what_that_covers():
    doc = envelope_for({"fails_open": False}, current="a", proposed="b")
    ok, why = attest.verify(doc)
    assert ok
    # Unsigned. The sentence has to say what was *not* ruled out, because
    # a reader takes the strength of the claim from the wording.
    assert "unsigned" in why and "nothing deliberate" in why


def test_an_edited_payload_fails_without_needing_a_key():
    doc = envelope_for({"fails_open": True, "newly_reachable_total": 412},
                       current="a", proposed="b")
    doc["payload"]["plan"]["newly_reachable_total"] = 0
    ok, why = attest.verify(doc)
    assert not ok and "has been edited" in why


def test_a_signature_catches_an_editor_who_recomputed_the_digest():
    # The digest alone is integrity against accident. Anybody editing a
    # compliance artifact on purpose recomputes it, which is the whole
    # reason the signature exists.
    doc = attest.sign(envelope_for({"fails_open": True}, current="a"),
                      b"the-key")
    doc["payload"]["plan"]["fails_open"] = False
    doc["payload_sha256"] = attest.digest(attest.canonical(doc["payload"]))
    assert attest.verify(doc)[0] is True, "the digest was recomputed"
    ok, why = attest.verify(doc, b"the-key")
    assert not ok and "signature does not match" in why


def test_a_key_on_an_unsigned_envelope_is_an_error_not_a_pass():
    # The quiet failure this prevents: a pipeline that stopped signing
    # keeps verifying green, because an unsigned document trivially has
    # no bad signature.
    doc = envelope_for({"fails_open": False}, current="a")
    ok, why = attest.verify(doc, b"the-key")
    assert not ok and "unsigned" in why


def test_signing_with_an_empty_key_is_refused():
    with pytest.raises(ValueError, match="empty one would produce"):
        attest.sign(envelope_for({}, current="a"), b"")


def test_a_policy_edited_after_the_check_is_stale_not_corrupt():
    # Two different findings. The artifact is fine; the thing somebody is
    # about to rely on is not the thing that was checked.
    doc = envelope_for({"fails_open": False}, current="a", proposed="b")
    assert attest.verify(doc)[0] is True
    fresh, note = attest.policies_match(doc, {"current": "a",
                                              "proposed": "EDITED"})
    assert not fresh and "proposed" in note and "current" not in note


def test_the_envelope_records_digests_and_never_paths():
    # A path is not evidence: it names a file that may since have been
    # edited, moved, or deleted with the branch.
    doc = envelope_for({}, current="policy contents here")
    assert doc["payload"]["policies"]["current"] == attest.digest(
        "policy contents here")
    assert "/" not in json.dumps(doc["payload"]["policies"])


def test_the_canonical_form_does_not_depend_on_key_order():
    # The signature is over bytes. Two dicts that differ only in
    # insertion order must not produce two signatures, or an artifact
    # stops verifying when an unrelated library reorders a dict.
    one = attest.canonical({"b": 1, "a": {"d": 2, "c": 3}})
    two = attest.canonical({"a": {"c": 3, "d": 2}, "b": 1})
    assert one == two


# ---- the command ------------------------------------------------------

def test_the_command_writes_and_then_verifies_an_attestation(
        tmp_path, capsys, monkeypatch):
    before = policy(tmp_path, "in_force.py", WIDENS.format(support="public"))
    after = policy(tmp_path, "proposed.py", WIDENS.format(support="phi"))
    roles = tmp_path / "roles.json"
    roles.write_text(json.dumps(ROLES))
    out = tmp_path / "plan.att.json"
    monkeypatch.setenv("VOYD_ATTEST_KEY", "s3cret")

    assert plan_main(["--current", before, "--proposed", after,
                      "--as-each", str(roles), "--attest", str(out),
                      "--sign", "env:VOYD_ATTEST_KEY"]) == 0
    capsys.readouterr()

    assert plan_main(["--verify", str(out), "--sign", "env:VOYD_ATTEST_KEY",
                      "--current", before, "--proposed", after]) == 0
    said = capsys.readouterr().out
    assert "digest and signature both check out" in said
    assert "the attested policies are the ones on disk" in said


def test_verifying_an_attestation_of_a_policy_since_edited_fails(
        tmp_path, capsys):
    before = policy(tmp_path, "in_force.py", WIDENS.format(support="public"))
    after = policy(tmp_path, "proposed.py", WIDENS.format(support="phi"))
    out = tmp_path / "plan.att.json"
    assert plan_main(["--current", before, "--proposed", after,
                      "--attest", str(out)]) == 0
    capsys.readouterr()

    with open(after, "a") as handle:
        handle.write("\n# a later edit\n")
    assert plan_main(["--verify", str(out), "--current", before,
                      "--proposed", after]) == 1
    assert "STALE" in capsys.readouterr().out


def test_the_key_is_never_taken_on_the_command_line(tmp_path, capsys):
    # argv is in the process table, the shell history and any CI log that
    # echoes its own commands. A signing key that leaks makes every
    # attestation it ever produced forgeable, retroactively.
    before = policy(tmp_path, "in_force.py", WIDENS.format(support="public"))
    assert plan_main(["--current", before, "--proposed", "none",
                      "--attest", str(tmp_path / "x.json"),
                      "--sign", "hunter2"]) == 2
    assert "argv is not a secret" in capsys.readouterr().err


def test_signing_without_attesting_is_refused(tmp_path, capsys):
    before = policy(tmp_path, "in_force.py", WIDENS.format(support="public"))
    assert plan_main(["--current", before, "--proposed", "none",
                      "--sign", "env:NOPE"]) == 2
    assert "nothing to sign" in capsys.readouterr().err


def test_asking_for_one_caller_and_a_table_at_once_is_refused(
        tmp_path, capsys):
    before = policy(tmp_path, "in_force.py", WIDENS.format(support="public"))
    after = policy(tmp_path, "proposed.py", WIDENS.format(support="phi"))
    assert plan_main(["--current", before, "--proposed", after,
                      "--as", '{"roles": ["support"]}',
                      "--as-each", json.dumps(ROLES)]) == 2
    assert "which number is the answer" in capsys.readouterr().err


def test_an_attestation_that_cannot_be_written_is_fatal(tmp_path, capsys):
    # Unlike --report. An attestation is the reason a compliance pipeline
    # runs this at all, and a run that quietly produced no evidence while
    # exiting 0 is a gap nobody notices until somebody asks for it.
    before = policy(tmp_path, "in_force.py", WIDENS.format(support="public"))
    assert plan_main(["--current", before, "--proposed", "none",
                      "--attest", str(tmp_path / "no-dir" / "x.json")]) == 2
    assert "could not attest" in capsys.readouterr().err


def test_the_matrix_json_carries_the_role_table(tmp_path):
    before = specs(tmp_path, "in_force.py", WIDENS.format(support="public"))
    after = specs(tmp_path, "proposed.py", WIDENS.format(support="phi"))
    blob = json.loads(json.dumps(matrix_as_json(
        matrix(before, after, lambda _c: DOCS, ROLES, when=NOW))))
    assert blob["worst_caller"] == "tier1-support"
    assert blob["newly_reachable_total"] == 412
    assert set(blob["callers"]) == set(ROLES)
    assert blob["callers"]["clinician"]["newly_reachable_total"] == 0
