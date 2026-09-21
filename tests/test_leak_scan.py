"""The leak scanner is a credibility instrument, so its classifier is pinned.

An instrument that hands a stranger "you have N leaks" earns nothing if N is
noise. These fixtures fix the judgements it makes -- a collection carries a
mark, a read is filtered, a read is a leak, a read is indeterminate -- and the
ones it must refuse to make: a read on a collection with no mark is not
counted, and a filter it cannot see is never called a leak.

Two later sections carry more weight than the classifier does, because they
are where the tool stops being a pattern match:

- **inference.** The scanner has to work out what the mark is *called* without
  being told, from the repository's own conventions. A rule that only fires on
  names hard-coded here is one anybody could have written in Semgrep.
- **the ratchet.** An indeterminate read is a proof obligation discharged in
  the source. What separates that from a suppression file is that a claim
  which stops describing its code becomes a finding itself, so those cases are
  pinned hardest.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from voyd_scan import (EXIT_ERROR, EXIT_MAX, ScanError, analyze,
                       collect_sources, main)


def _leaks(report):
    return {(r.file, r.line) for r in report.leaks}


def test_a_write_that_names_the_mark_makes_the_collection_bearing():
    report = analyze({"a.py": (
        "def f(db):\n"
        "    db.notes.insert_one({'expire_at': 1, 'text': 't'})\n"
        "    return db.notes.find({'tenant': 't'})\n"
    )})
    assert report.bearing == {"notes"}
    assert _leaks(report) == {("a.py", 3)}
    assert report.leaks[0].why == "filter does not name the mark"


def test_a_filtered_read_is_not_a_leak_and_also_proves_bearing():
    report = analyze({"a.py": (
        "def f(db):\n"
        "    return db.notes.find({'expire_at': {'$gt': 0}})\n"
    )})
    assert report.bearing == {"notes"}          # filtering it proves it has it
    assert report.leaks == []
    assert len(report.filtered) == 1


def test_an_empty_and_a_missing_filter_are_both_leaks():
    report = analyze({"a.py": (
        "def f(db):\n"
        "    db.notes.create_index('expire_at', expireAfterSeconds=60)\n"
        "    a = db.notes.find({})\n"
        "    b = db.notes.find()\n"
    )})
    assert report.bearing == {"notes"}          # the TTL index proves it
    assert _leaks(report) == {("a.py", 3), ("a.py", 4)}
    whys = {r.why for r in report.leaks}
    assert whys == {"empty filter", "no filter"}


def test_a_non_literal_filter_is_indeterminate_never_a_leak():
    """A filter built by a helper cannot be read, so it is not accused."""
    report = analyze({"a.py": (
        "def f(db, q):\n"
        "    db.notes.update_one({'_id': 1}, {'$set': {'revoked': True}})\n"
        "    return db.notes.find(q)\n"          # q is a Name: unknowable
    )})
    assert report.bearing == {"notes"}          # the $set on revoked proves it
    assert report.leaks == []
    assert len(report.indeterminate) == 1
    assert report.indeterminate[0].why == "filter is not a literal"


def test_a_filter_built_partly_by_a_helper_is_indeterminate():
    """The shape that produced a false positive on this repository's own code.

    ``{"$match": handle.match({...})}`` is a literal dict, so the old
    classifier read its keys -- ``$match``, ``$group`` -- saw no mark, and
    called it a leak. The keys it could see were a shell around a sub-filter
    returned by a call. The header promises a helper-built filter is never
    counted as a leak, and an instrument that overstates on the repository it
    ships from is worth less than no instrument.
    """
    report = analyze({"a.py": (
        "def f(db, handle):\n"
        "    db.notes.insert_one({'expire_at': 1})\n"
        "    return db.notes.aggregate([\n"
        "        {'$match': handle.match({'tenant': 't'})},\n"
        "        {'$group': {'_id': '$indexed'}},\n"
        "    ])\n"
    )})
    assert report.bearing == {"notes"}
    assert report.leaks == []
    assert len(report.indeterminate) == 1
    assert report.indeterminate[0].why == "filter is partly built elsewhere"


def test_unpacking_a_base_filter_is_indeterminate():
    """``{**base(), ...}`` is the other way the visible keys are a shell."""
    report = analyze({"a.py": (
        "def f(db, base):\n"
        "    db.notes.insert_one({'expire_at': 1})\n"
        "    return db.notes.find({**base(), 'tenant': 't'})\n"
    )})
    assert report.leaks == []
    assert len(report.indeterminate) == 1


def test_a_variable_value_still_leaves_the_keys_visible():
    """The limit of the rule above, pinned so it cannot swallow the signal.

    ``{'tenant': t}`` has a computed *value* and fully visible *keys*, and
    keys are what the mark check reads. If this ever became indeterminate the
    scanner would report nothing and look reassuring.
    """
    report = analyze({"a.py": (
        "def f(db, t):\n"
        "    db.notes.insert_one({'expire_at': 1})\n"
        "    return db.notes.find({'tenant': t})\n"
    )})
    assert _leaks(report) == {("a.py", 3)}


def test_a_collection_with_no_mark_is_not_counted():
    """No accusation without evidence the collection carries a deadline."""
    report = analyze({"a.py": (
        "def f(db):\n"
        "    return db.sessions.find({})\n"       # nothing marks sessions
    )})
    assert report.bearing == set()
    assert report.leaks == []


def test_bearing_is_discovered_across_files():
    """The write that proves a deadline and the read that forgets it are
    routinely in different modules; the scan is whole-repo for that reason."""
    report = analyze({
        "models.py": "def w(db):\n    db.notes.insert_one({'deleted': False})\n",
        "api.py": "def r(db):\n    return db.notes.find({'user': u})\n",
    })
    assert report.bearing == {"notes"}
    assert _leaks(report) == {("api.py", 2)}


def test_soft_delete_conventions_count_as_marks():
    for field_name in ("deleted", "is_deleted", "deleted_at", "isDeleted"):
        report = analyze({"a.py": (
            "def f(db):\n"
            f"    db.docs.insert_one({{'{field_name}': False}})\n"
            "    return db.docs.find({'q': 1})\n"
        )})
        assert report.bearing == {"docs"}, field_name
        assert len(report.leaks) == 1, field_name


def test_a_read_through_a_handle_is_invisible_by_construction():
    """``docs.find(...)`` -- a plain variable receiver -- is not a raw
    collection access, so the scanner never sees it. That is correct: the
    handle is the thing that cannot leak, and this tool hunts raw reads."""
    report = analyze({"a.py": (
        "def f(db, docs):\n"
        "    db.notes.insert_one({'expire_at': 1})\n"
        "    return docs.find({})\n"             # docs is a Name, not db.notes
    )})
    assert report.bearing == {"notes"}
    assert report.leaks == []                    # nothing read db.notes raw


def test_json_shape_is_stable_for_sharing():
    report = analyze({"a.py": (
        "def f(db):\n"
        "    db.notes.insert_one({'expire_at': 1})\n"
        "    return db.notes.find({})\n"
    )})
    d = report.as_dict()
    assert d["deadline_bearing_collections"] == ["notes"]
    assert d["reads_against_them"] == 1
    assert d["candidate_leaks"][0]["line"] == 3
    assert d["filtered_reads"] == 0


def test_collect_sources_honours_allow(tmp_path: Path):
    """A designated audit module that legitimately reads everything is
    exempted by path, the same shape as the in-package guard's allowlist."""
    (tmp_path / "app").mkdir()
    (tmp_path / "audit").mkdir()
    (tmp_path / "app" / "svc.py").write_text("x = 1\n")
    (tmp_path / "audit" / "reports.py").write_text("y = 2\n")

    got = collect_sources([tmp_path], allow=[tmp_path / "audit"])
    names = {Path(p).name for p in got}
    assert names == {"svc.py"}, "the audit module must be excluded"


# The two ways an instrument lies about its own result. Neither is about
# classification -- both are about the scanner reporting "clean" when it has
# not actually established anything, which is the defect it exists to find,
# committed by the tool.

def test_a_path_that_does_not_exist_is_an_error_not_a_clean_bill():
    """`voyd-scan ./scr` for `./src` must not print a clean result.

    ``Path.rglob`` on a missing directory yields nothing rather than
    raising, so the natural implementation scans zero files, finds zero
    leaks, and exits 0 -- confidently, and about nothing. A stranger's first
    run is exactly where a typo is likely and a false all-clear is fatal to
    the only thing this tool has, which is credibility.
    """
    with pytest.raises(ScanError):
        collect_sources([Path("no/such/directory")], allow=[])

    assert main(["no/such/directory"]) == EXIT_ERROR


def test_the_exit_code_cannot_wrap_around_to_success():
    """256 leaks must not exit 0.

    The exit status is one byte, and the documented contract is "the exit
    code is the number of candidate leaks, so it drops into CI". Unclamped,
    the single worst repository this tool could be pointed at reports
    success -- nothing wrong enough to notice, which is this project's whole
    complaint. So the count is clamped and the real number is printed.
    """
    src = ("def f(db):\n"
           "    db.notes.insert_one({'expire_at': 1})\n"
           + "".join(f"    db.notes.find({{'i': {i}}})\n" for i in range(300)))
    report = analyze({"a.py": src})
    assert len(report.leaks) == 300                      # all of them counted
    assert min(len(report.leaks), EXIT_MAX) == EXIT_MAX  # none of them lost
    assert EXIT_MAX & 0xFF != 0, "an exit code that wraps to 0 reads as clean"
    assert EXIT_MAX < EXIT_ERROR, "a full count must not be read as a failure"


# --------------------------------------------------------------------------
# Inference: the scanner has to work out *what the mark is called* without
# being told. A pattern that only fires on names this file already knows is
# a rule anybody could have written in Semgrep; the inference is the claim.
# --------------------------------------------------------------------------

def _src(*reads: str, collection: str = "orders") -> dict[str, str]:
    body = "".join(f"    db.{collection}.find({r})\n" for r in reads)
    return {"a.py": "def f(db, u, q):\n" + body}


def test_the_convention_is_inferred_from_a_field_nobody_declared():
    """The whole point, in one case: `valid_until` is in no list anywhere.

    Three reads name it, one does not. The convention is the spec, so the
    deviation is the finding -- and the finding arrives with the evidence
    for it, because an inferred rule the reader cannot audit is worse than
    no rule.
    """
    report = analyze(_src(
        "{'user': u, 'valid_until': {'$gt': 0}}",
        "{'user': u, 'valid_until': {'$gt': 0}}",
        "{'user': u, 'valid_until': {'$gt': 0}}",
        "{'user': u}",
    ))
    assert report.bearing == {"orders"}
    marks = {m.field: m for m in report.marks["orders"]}
    assert marks["valid_until"].source == "inferred"
    assert (marks["valid_until"].support, marks["valid_until"].total) == (3, 4)
    assert _leaks(report) == {("a.py", 5)}
    assert "3 of 4" in report.leaks[0].why, "the evidence travels with the finding"


def test_a_ttl_index_names_its_own_field():
    """`expireAfterSeconds` is MongoDB's word; the field next to it is the
    team's. That pairing hands over `Y` for a name this file has never seen,
    which is why a hard-coded list is a shortcut and not the mechanism."""
    report = analyze({"a.py": (
        "def f(db, u):\n"
        "    db.sessions.create_index('purge_after', expireAfterSeconds=0)\n"
        "    return db.sessions.find({'user': u})\n"
    )})
    assert [m.field for m in report.marks["sessions"]] == ["purge_after"]
    assert _leaks(report) == {("a.py", 3)}


def test_a_ttl_index_declared_as_a_key_list_is_read_too():
    report = analyze({"a.py": (
        "def f(db, u):\n"
        "    db.sessions.create_index([('purge_after', 1)], expireAfterSeconds=60)\n"
        "    return db.sessions.find({'user': u})\n"
    )})
    assert [m.field for m in report.marks["sessions"]] == ["purge_after"]


def test_a_field_every_read_names_is_a_schema_not_a_finding():
    """No deviation, nothing to say.

    This is the guard that keeps inference from flooding the output with
    every column a collection happens to have -- and it is load-bearing in
    the other direction too: see the test below.
    """
    report = analyze(_src("{'user': u}", "{'user': u}", "{'user': u}"))
    assert report.bearing == set()
    assert report.leaks == []


def test_a_unanimous_field_cannot_exonerate_a_read_that_forgets_the_deadline():
    """The failure mode the rule above exists to prevent.

    If a field named by every read became a mark, then every read would
    satisfy it, and a collection whose reads all filter `tenant` and all
    forget `expire_at` would come back clean -- the instrument reporting
    zero because it found a rule that nothing violates. The declared mark
    still has to be named, by all of them.
    """
    report = analyze({"a.py": (
        "def f(db, u):\n"
        "    db.orders.insert_one({'expire_at': 1})\n"
        "    db.orders.find({'tenant': u})\n"
        "    db.orders.find({'tenant': u})\n"
        "    db.orders.find({'tenant': u})\n"
    )})
    assert len(report.leaks) == 3


def test_one_read_is_not_a_convention_however_lonely_the_others_are():
    """Support floor, which is where inference has to refuse to speak.

    A single read that names a field is a fact about that read, not a rule
    the others are breaking. Without this the first `find` anyone writes
    against a new collection becomes the spec, and every existing read is
    retroactively a leak -- an instrument that manufactures findings out of
    the smallest possible sample earns nothing.
    """
    report = analyze(_src("{'live': True}", "{'a': 1}", "{'b': 2}", "{'c': 3}"))
    assert report.bearing == set()


def test_inference_gets_stronger_as_the_codebase_grows():
    """The economics claim, pinned. Nine honouring reads and one deviation
    is a finding; the same single deviation against two honouring reads is
    not. More code means more signal here, which is the opposite of how
    pattern-matching static analysis usually scales."""
    strong = analyze(_src(*(["{'user': u, 'live': True}"] * 9 + ["{'user': u}"])))
    assert len(strong.leaks) == 1
    weak = analyze(_src("{'user': u, 'live': True}", "{'user': u}"))
    assert weak.leaks == []


def test_identity_is_never_a_convention():
    """`find_one({'_id': x})` is the sharpest leak there is -- a lookup by
    primary key that can still serve a forgotten fact. If `_id` could be
    inferred as a mark, those reads would exonerate themselves."""
    report = analyze({"a.py": (
        "def f(db, x):\n"
        "    db.orders.insert_one({'expire_at': 1})\n"
        "    db.orders.find_one({'_id': x})\n"
        "    db.orders.find_one({'_id': x})\n"
        "    db.orders.find_one({'_id': x})\n"
    )})
    assert all(m.field != "_id" for m in report.marks["orders"])
    assert len(report.leaks) == 3


def test_a_read_must_name_every_mark_the_collection_carries():
    """A deadline and a tenant key are the same defect in different clothes,
    so a read that remembers one and forgets the other is not half safe."""
    report = analyze({"a.py": (
        "def f(db, u, t):\n"
        "    db.orders.insert_one({'expire_at': 1})\n"
        "    db.orders.find({'tenant': t, 'expire_at': {'$gt': 0}})\n"
        "    db.orders.find({'tenant': t, 'expire_at': {'$gt': 0}})\n"
        "    db.orders.find({'tenant': t, 'expire_at': {'$gt': 0}})\n"
        "    db.orders.find({'expire_at': {'$gt': 0}})\n"   # forgets the tenant
    )})
    fields = {m.field for m in report.marks["orders"]}
    assert fields == {"expire_at", "tenant"}
    assert _leaks(report) == {("a.py", 6)}
    assert "tenant" in report.leaks[0].why


# --------------------------------------------------------------------------
# The ratchet: an indeterminate read is a proof obligation, dischargeable in
# the source. What makes it a ratchet rather than a suppression file is that
# a claim which stops describing its code becomes a finding itself.
# --------------------------------------------------------------------------

def test_a_claim_discharges_an_indeterminate_read():
    report = analyze({"a.py": (
        "def f(db, u):\n"
        "    db.notes.insert_one({'expire_at': 1})\n"
        "    return db.notes.find(living(u))  # voyd: filtered(expire_at) -- living() applies it\n"
    )})
    assert report.indeterminate == []
    assert len(report.discharged) == 1
    assert report.discharged[0].reason == "living() applies it"


def test_a_claim_on_a_multi_line_read_is_still_found():
    """Every real filter worth annotating spans lines. The claim binds to the
    call's whole extent, not to the line the receiver happens to be on."""
    report = analyze({"a.py": (
        "def f(db, u):\n"
        "    db.notes.insert_one({'expire_at': 1})\n"
        "    return db.notes.aggregate([\n"
        "        # voyd: filtered(expire_at) -- the stage helper applies it\n"
        "        {'$match': stage(u)},\n"
        "    ])\n"
    )})
    assert len(report.discharged) == 1


def test_an_audit_claim_names_an_unfiltered_read_rather_than_hiding_it():
    """The static half of `including_refused()`: a door with an alarm, not a
    permanent pass. The read leaves the leak column and arrives in one that
    is still printed, still counted, and carries the author's reason."""
    report = analyze({"a.py": (
        "def f(db):\n"
        "    db.notes.insert_one({'expire_at': 1})\n"
        "    return db.notes.find({})  # voyd: audit -- the retention report, by design\n"
    )})
    assert report.leaks == []
    assert len(report.audited) == 1
    assert report.audited[0].reason == "the retention report, by design"


def test_an_audit_claim_without_a_reason_is_itself_the_finding():
    """A break-glass with no reason is a suppression comment wearing a
    costume. It does not silence the read; it replaces one finding with
    another that names the missing justification."""
    report = analyze({"a.py": (
        "def f(db):\n"
        "    db.notes.insert_one({'expire_at': 1})\n"
        "    return db.notes.find({})  # voyd: audit\n"
    )})
    assert report.leaks == []
    assert len(report.stale) == 1
    assert "no reason given" in report.stale[0].why


def test_a_filtered_claim_cannot_discharge_a_visible_leak():
    """The claim says "you cannot see my filter, trust me" -- but the filter
    here is perfectly visible and does not name the mark. Honouring that
    would let one comment silence any finding, which is the whole of what is
    wrong with a suppression file."""
    report = analyze({"a.py": (
        "def f(db, u):\n"
        "    db.notes.insert_one({'expire_at': 1})\n"
        "    return db.notes.find({'user': u})  # voyd: filtered -- no it is not\n"
    )})
    assert len(report.stale) == 1
    assert "use `voyd: audit" in report.stale[0].why


def test_a_claim_that_is_no_longer_needed_is_reported():
    """mypy's `warn_unused_ignores`, and for the same reason: an annotation
    added once outlives the code it was written about. A claim on a read
    that now plainly filters the mark is stale, and saying so is what stops
    the annotations drifting into decoration nobody rereads."""
    report = analyze({"a.py": (
        "def f(db):\n"
        "    return db.notes.find({'expire_at': {'$gt': 0}})  # voyd: filtered -- stale now\n"
    )})
    assert report.filtered == []
    assert len(report.stale) == 1
    assert "already visible" in report.stale[0].why


def test_a_claim_inside_a_string_is_not_a_claim():
    """The suppression mechanism must not be reachable from inside a
    docstring or a test fixture. `tokenize`, not a regex over lines."""
    report = analyze({"a.py": (
        "def f(db, u):\n"
        "    db.notes.insert_one({'expire_at': 1})\n"
        "    doc = '# voyd: audit -- in a string'\n"
        "    return db.notes.find({'user': u})\n"
    )})
    assert len(report.leaks) == 1
    assert report.audited == []


def test_strict_counts_the_obligations_and_the_default_does_not(tmp_path: Path):
    """Two contracts at once. The documented exit code stays "the number of
    candidate leaks", so nobody's CI changes meaning under them -- and
    `--strict` is the opt-in that turns the unjudged column into something
    that can be driven to zero and held there.
    """
    (tmp_path / "a.py").write_text(
        "def f(db, q):\n"
        "    db.notes.insert_one({'expire_at': 1})\n"
        "    db.notes.find({'user': 1})\n"          # a leak
        "    db.notes.find(q)\n"                    # unjudged
    )
    assert main([str(tmp_path)]) == 1
    assert main([str(tmp_path), "--strict"]) == 2

    (tmp_path / "a.py").write_text(
        "def f(db, q):\n"
        "    db.notes.insert_one({'expire_at': 1})\n"
        "    db.notes.find({'user': 1, 'expire_at': {'$gt': 0}})\n"
        "    db.notes.find(q)  # voyd: filtered(expire_at) -- the helper applies it\n"
    )
    assert main([str(tmp_path), "--strict"]) == 0, "the ratchet can reach zero"


def test_the_json_carries_the_evidence_for_every_inferred_mark():
    """A number somebody is asked to act on has to be auditable. The JSON
    says which field, by what route, and on what support -- so an inferred
    finding can be disputed on its evidence rather than on faith."""
    report = analyze(_src(
        "{'user': u, 'valid_until': 1}",
        "{'user': u, 'valid_until': 1}",
        "{'user': u, 'valid_until': 1}",
        "{'user': u}",
    ))
    d = report.as_dict()
    assert d["marks"]["orders"] == [
        {"field": "valid_until", "source": "inferred", "support": 3, "reads": 4}]
    assert d["strict_obligations"] == 1
