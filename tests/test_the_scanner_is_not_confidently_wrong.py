"""The first thing a stranger runs, and the one that judges *their* code.

`voyd-scan` is the top of this project's funnel: a dependency-free file
somebody points at a repository they care about, before they have installed
anything or believed anything. It had 1,043 lines and no test, which is an
uncomfortable place for a tool whose whole argument is that instruments
which are confidently wrong are worse than no instrument.

Two failures matter here and they are not symmetric.

A **false negative** -- a leak it does not report -- is this project's own
thesis turned on itself: a confident all-clear over a read that can still
serve a forgotten fact. A **false positive** is cheaper in principle and
more expensive in practice, because it is spent on somebody else's
codebase: a tool that cries about clean reads is one nobody runs twice, and
an unrun scanner reports nothing at all.

So this file asserts findings *and* the absence of findings, and it spends
more of its length on the second. `analyze()` is pure -- a dict of path to
source, no I/O -- so all of it runs without a database, a network, or a
temporary file, except the handful at the bottom that are about the command
line itself.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import voyd_scan as v

# A TTL index names its own field: the declared path, no inference needed.
TTL = 'db.notes.create_index("expire_at", expireAfterSeconds=0)\n'


def scan(code: str, name: str = "app.py", **kw) -> v.Report:
    return v.analyze({name: code}, **kw)


def statuses(report: v.Report) -> list[str]:
    return [r.status for r in report.reads]


# --------------------------------------------------------------------------
# It finds the thing it exists to find.
# --------------------------------------------------------------------------

def test_a_read_that_ignores_a_declared_deadline_is_a_leak():
    report = scan(TTL + 'db.notes.find({"topic": "x"})')
    assert [r.status for r in report.leaks] == ["leak"]
    assert report.leaks[0].line == 2


def test_an_unfiltered_read_of_a_marked_collection_is_the_whole_story():
    """`find()` with no filter at all needs no explanation beyond itself."""
    report = scan(TTL + "db.notes.find({})")
    assert report.leaks[0].why == "empty filter"


def test_a_lookup_by_id_is_still_a_leak():
    """The sharpest case, and the one a naive scanner would wave through.

    A primary-key read looks maximally specific and is exactly the read that
    keeps serving a fact somebody revoked -- so `_id` is never allowed to
    count as the filter that satisfies a mark.
    """
    report = scan(TTL + 'db.notes.find_one({"_id": oid})')
    assert len(report.leaks) == 1
    assert "_id" in v.NEVER_A_CONVENTION


def test_a_read_is_judged_against_every_mark_not_merely_one():
    """A deadline and a revocation are the same defect in different clothes.

    A read that remembers one and forgets the other is not half safe, and
    the message has to name which one was forgotten or the finding is not
    actionable.
    """
    code = (TTL + 'db.notes.update_one({"_id": 1}, {"$set": {"forgotten": 1}})\n'
            'db.notes.find({"expire_at": {"$gt": now}})')
    report = scan(code)
    assert {m.field for m in report.marks["notes"]} == {"expire_at",
                                                        "forgotten"}
    assert len(report.leaks) == 1
    assert report.leaks[0].why == "filter does not name `forgotten`", (
        "with two marks on the collection, 'the mark' does not say which -- "
        "and the read already names the other one")


# --------------------------------------------------------------------------
# It does not find things that are not there. The expensive half.
# --------------------------------------------------------------------------

def test_a_read_that_names_the_mark_is_silent():
    report = scan(TTL + 'db.notes.find({"expire_at": {"$gt": now}})')
    assert report.leaks == []
    assert statuses(report) == ["filtered"]


def test_a_collection_with_no_mark_is_not_a_finding():
    """Most collections in a repository are not marked and never will be.

    Reporting them would bury the ones that are, which is the failure mode
    of every linter anybody has ever turned off.
    """
    report = scan(TTL + 'db.audit_log.find({"level": "warn"})')
    assert report.leaks == []
    assert report.reads[-1].why == "no mark on this collection"


def test_a_field_every_read_names_is_not_a_convention():
    """Unanimity is a schema, not a rule, and manufacturing a mark out of it
    would let a real leak look filtered for naming the unanimous field."""
    report = scan('db.docs.find({"org": 1, "a": 1})\n'
                  'db.docs.find({"org": 1, "b": 2})\n'
                  'db.docs.find({"org": 1, "c": 3})')
    assert report.marks == {}
    assert report.leaks == []


def test_three_judgeable_reads_is_the_smallest_thing_that_can_be_a_finding():
    """The documented floor, pinned so it cannot drift quietly.

    Two supporting reads and one deviation is the smallest shape that clears
    both the support floor and the threshold. That is a deliberate choice --
    it is also the least evidence this tool will ever act on, so the number
    is asserted here rather than left to a constant nobody re-reads.
    """
    three = ('db.docs.find({"k": 1, "a": 1})\n'
             'db.docs.find({"k": 1, "b": 2})\n'
             'db.docs.find({"c": 3})')
    assert (v.CONVENTION_SUPPORT, v.CONVENTION_THRESHOLD) == (2, 0.6)
    assert len(scan(three).leaks) == 1

    # ...and two judgeable reads cannot: there is no majority to deviate from.
    assert scan('db.docs.find({"k": 1, "a": 1})\n'
                'db.docs.find({"c": 3})').leaks == []


def test_a_field_half_the_reads_name_is_a_disagreement_not_a_rule():
    report = scan('db.docs.find({"k": 1, "a": 1})\n'
                  'db.docs.find({"k": 1, "b": 2})\n'
                  'db.docs.find({"c": 3})\n'
                  'db.docs.find({"d": 4})')
    assert report.leaks == []


# --------------------------------------------------------------------------
# The inference, which is the part a rule-based scanner cannot do.
# --------------------------------------------------------------------------

def test_a_convention_is_found_without_anybody_declaring_it():
    """No TTL index, no known spelling: `is_active` is not in `MARKS`.

    This is the claim the README makes and the reason the file exists --
    the majority establishes the spec, so the deviation is the finding.
    """
    report = scan('db.docs.find({"is_active": True, "a": 1})\n'
                  'db.docs.find({"is_active": True, "b": 2})\n'
                  'db.docs.find_one({"is_active": True})\n'
                  'db.docs.find({"c": 3})')
    assert "isactive" not in v.MARKS
    mark = report.marks["docs"][0]
    assert (mark.field, mark.source, mark.support, mark.total) == \
           ("is_active", "inferred", 3, 4)
    assert len(report.leaks) == 1 and report.leaks[0].line == 4


def test_an_inferred_finding_carries_the_evidence_for_itself():
    """A declared mark is checkable by reading; an inferred one is only as
    good as the convention behind it, so the count travels with it."""
    report = scan('db.docs.find({"is_active": 1, "a": 1})\n'
                  'db.docs.find({"is_active": 1, "b": 2})\n'
                  'db.docs.find({"is_active": 1, "c": 3})\n'
                  'db.docs.find({"d": 4})')
    assert "3 of 4 reads" in report.leaks[0].why


def test_the_inference_gets_stronger_on_a_bigger_codebase():
    """The economics that invert: more reads make the majority harder to
    argue with, where a pattern matcher only gets noisier."""
    many = "".join(f'db.docs.find({{"is_active": 1, "k{i}": {i}}})\n'
                   for i in range(30))
    report = scan(many + 'db.docs.find({"k": 1})')
    mark = report.marks["docs"][0]
    assert (mark.support, mark.total) == (30, 31)
    assert len(report.leaks) == 1


# --------------------------------------------------------------------------
# The suppression mechanism, which is the part that rots if nobody watches.
# --------------------------------------------------------------------------

def test_an_audit_claim_moves_a_read_rather_than_silencing_it():
    report = scan(TTL + 'db.notes.find({"t": 1})  # voyd: audit -- admin export')
    assert report.leaks == [] and statuses(report) == ["audited"]
    assert report.reads[0].reason == "admin export"


def test_an_audit_claim_with_no_reason_is_itself_a_finding():
    report = scan(TTL + 'db.notes.find({"t": 1})  # voyd: audit')
    assert statuses(report) == ["stale"]


def test_a_filtered_claim_on_a_read_that_does_not_filter_is_a_finding():
    """The annotation that would otherwise suppress forever. A `filtered`
    claim asserts something this tool can check, so it is checked."""
    report = scan(TTL + 'db.notes.find({"t": 1})  # voyd: filtered')
    assert statuses(report) == ["stale"]
    assert "use `voyd: audit" in report.reads[0].why


def test_a_filtered_claim_on_an_already_visible_filter_is_stale():
    """The ratchet's teeth: an annotation that has outlived its reason."""
    report = scan(TTL + 'db.notes.find({"expire_at": 1})  # voyd: filtered')
    assert statuses(report) == ["stale"]


def test_a_claim_inside_a_string_literal_suppresses_nothing():
    """The suppression mechanism must not be reachable from inside data.

    A tool whose all-clear can be triggered by a doctest, a fixture, or a
    templated string is not one you would let gate a build.
    """
    report = scan(TTL + 'S = "# voyd: audit -- nope"\n'
                        'db.notes.find({"topic": 1})')
    assert len(report.leaks) == 1
    assert report.leaks[0].claim is None


# --------------------------------------------------------------------------
# It never reports "clean" on the strength of having established nothing.
# --------------------------------------------------------------------------

def test_a_file_that_does_not_parse_does_not_take_the_scan_with_it():
    report = v.analyze({"ok.py": TTL + 'db.notes.find({"t": 1})',
                        "broken.py": "def ( oops"})
    assert len(report.leaks) == 1, (
        "one unparseable file must not turn a repository into an all-clear")


def test_recognising_no_read_at_all_is_reported_as_unmeasured(tmp_path, capsys):
    """The failure that looks exactly like success.

    Every path existed, every file parsed, and the scanner saw no read --
    because this team has a repository class. "No collection carries a mark"
    and "I could not see a single read" print the same way in a lesser tool
    and are completely different facts.
    """
    (tmp_path / "store.py").write_text("class Repo:\n    def all(self):\n"
                                       "        return self._rows\n")
    assert v.main([str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "recognised no database read at all" in out
    assert "treat this as\nunmeasured rather than clean" in out


def test_a_directory_with_no_python_says_so(tmp_path, capsys):
    (tmp_path / "notes.txt").write_text("hello")
    assert v.main([str(tmp_path)]) == 0
    assert "Nothing was checked." in capsys.readouterr().out


def test_a_path_that_does_not_exist_is_an_error_not_an_all_clear(tmp_path):
    with pytest.raises(v.ScanError):
        v.collect_sources([tmp_path / "nope"], [])


def test_a_wrapper_is_invisible_until_it_is_named():
    """Honest blindness, and the flag that cures it."""
    code = TTL + 'store.notes.fetch_all({"t": 1})'
    assert scan(code).reads == []
    assert len(scan(code, read_verbs=["fetch_all"]).leaks) == 1


# --------------------------------------------------------------------------
# The command line, because the exit code is what CI actually reads.
# --------------------------------------------------------------------------

def _repo(tmp_path: Path, code: str) -> str:
    (tmp_path / "app.py").write_text(code)
    return str(tmp_path)


def test_the_exit_code_carries_the_count(tmp_path):
    code = TTL + 'db.notes.find({"a": 1})\ndb.notes.find({"b": 2})'
    assert v.main([_repo(tmp_path, code)]) == 2


def test_a_clean_repository_exits_zero(tmp_path):
    assert v.main([_repo(tmp_path, TTL + 'db.notes.find({"expire_at": 1})')]) == 0


def test_the_exit_code_is_clamped_below_the_byte_that_wraps(tmp_path):
    """300 findings must not exit 44, and 256 must not exit 0 -- which is
    the worst possible reading, delivered to the tool whose entire argument
    is that nothing is ever wrong enough to notice."""
    code = TTL + "".join(f'db.notes.find({{"k{i}": {i}}})\n' for i in range(300))
    assert v.main([_repo(tmp_path, code)]) == v.EXIT_MAX == 254


def test_strict_counts_the_unjudged_and_the_default_does_not(tmp_path):
    code = TTL + "db.notes.find(build_filter())"
    path = _repo(tmp_path, code)
    assert v.main([path]) == 0
    assert v.main([path, "--strict"]) == 1


def test_the_json_report_is_machine_readable(tmp_path, capsys):
    code = TTL + 'db.notes.find({"a": 1})'
    assert v.main([_repo(tmp_path, code), "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["files_scanned"] == 1
    assert payload["deadline_bearing_collections"] == ["notes"]
    assert payload["strict_obligations"] == 1
    leak = payload["candidate_leaks"][0]
    assert (leak["collection"], leak["line"]) == ("notes", 2)
    assert payload["marks"]["notes"][0]["field"] == "expire_at"
