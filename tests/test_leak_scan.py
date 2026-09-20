"""The leak scanner is a credibility instrument, so its classifier is pinned.

An instrument that hands a stranger "you have N leaks" earns nothing if N is
noise. These fixtures fix the four judgements it makes -- a collection is
deadline-bearing, a read is filtered, a read is a leak, a read is
indeterminate -- and the two it must refuse to make: a read on a collection
with no mark is not counted, and a filter it cannot see is never called a leak.
"""

from __future__ import annotations

from pathlib import Path

from tools.leak_scan import analyze, collect_sources


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
