"""The pilot's raw-read guard has to fire on the mistake and stay quiet otherwise.

A guard that cannot fail is decoration, and a guard that fires on the safe
path is one a pilot team disables on day two. So this pins both edges:
the raw ``db.<collection>`` read is caught, the handle read is not, and prose
mentioning ``.find`` does not trip it.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from raw_read_guard import main, raw_reads  # noqa: E402


def test_it_flags_the_raw_collection_read():
    src = (
        "async def recall(db):\n"
        "    return [d async for d in db.notes.find({})]\n"
    )
    assert raw_reads(src, "notes") == [2]


def test_it_flags_subscript_and_get_collection_and_engine_db():
    src = (
        "async def a(db):\n"
        "    await db['notes'].find_one({})\n"          # subscript
        "async def b(db):\n"
        "    await db.get_collection('notes').aggregate([])\n"  # get_collection
        "async def c(engine):\n"
        "    await engine.db.notes.count_documents({})\n"       # nested attribute
    )
    assert raw_reads(src, "notes") == [2, 4, 6]


def test_it_does_not_flag_a_read_through_the_handle():
    src = (
        "async def recall(docs, vector):\n"
        "    a = await docs.find({})\n"
        "    b = await docs.search(vector, limit=5)\n"
        "    c = await docs.including_refused().find({})\n"
        "    return a, b, c\n"
    )
    assert raw_reads(src, "notes") == [], \
        "reads through the handle must not trip the guard"


def test_it_ignores_a_different_collection():
    src = "async def r(db):\n    return await db.other.find({})\n"
    assert raw_reads(src, "notes") == []


def test_it_reads_code_not_prose():
    src = (
        "def r(db):\n"
        "    # db.notes.find({}) is the thing we are replacing\n"
        "    return 'call db.notes.find here'\n"
    )
    assert raw_reads(src, "notes") == []


def test_the_cli_exit_code_counts_offenders(tmp_path):
    clean = tmp_path / "clean.py"
    clean.write_text("async def r(docs):\n    return await docs.find({})\n")
    assert main(["--collection", "notes", str(clean)]) == 0

    bad = tmp_path / "bad.py"
    bad.write_text("async def r(db):\n    return await db.notes.find({})\n")
    assert main(["--collection", "notes", str(bad)]) == 1


def test_allow_exempts_a_designated_audit_path(tmp_path):
    audit = tmp_path / "audit"
    audit.mkdir()
    (audit / "reports.py").write_text(
        "async def r(db):\n    return await db.notes.find({})\n")
    assert main(["--collection", "notes", "--allow", str(audit),
                 str(tmp_path)]) == 0
