"""Two tools, one lesson, and it had been learned in only one of them.

`voyd-scan` fixed this twice and wrote both fixes up. A path that does not
exist must not print a clean bill of health, because `Path.rglob` on a missing
directory yields nothing rather than raising, so `./scr` for `./src` scans
zero files and reports success. And a count carried in an exit status must be
clamped, because a status is one byte and 256 findings exiting 0 is the worst
possible repository reading as the best one.

`tools/raw_read_guard.py` had **neither**, for as long as it existed, and
`PILOT.md` gate 2 tells a piloting team to put exactly that tool in CI. So the
failure mode was: typo a path, get `clean: no raw reads`, and have a green
check on the collection you installed VOYD to protect, forever.

The per-tool test caught it in the tool somebody thought to write a test
about. That is the actual defect this file exists to fix -- not the exit
codes, which are four lines. A property that is true of *a category of thing*
should be asserted over the category, so the next outward tool is covered
before anybody remembers it needs to be. `CLIS` is the category; adding a
tool is a row.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

# Every command this repository points *outward* -- at a stranger's source
# tree rather than its own. Each takes paths, counts what it finds, and
# carries that count in its exit status, which is what makes both failures
# below possible in all of them.
CLIS = {
    "voyd-scan": [sys.executable, "scanner/voyd_scan"],
    "raw_read_guard": [sys.executable, "tools/raw_read_guard.py",
                       "--collection", "notes"],
}

# A findings count above one byte. Generated rather than committed: the point
# is the arithmetic, and a fixture file of 300 reads is 300 lines nobody
# reads.
def _too_many(tmp_path: Path) -> Path:
    src = tmp_path / "many"
    src.mkdir()
    (src / "m.py").write_text(
        "def f(db):\n"
        "    db.notes.insert_one({'expire_at': 1})\n"
        + "".join(f"    db.notes.find({{'i': {i}}})\n" for i in range(300)))
    return src


def _run(argv: list[str], *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(argv + list(args), cwd=ROOT, capture_output=True,
                          text=True)


@pytest.mark.parametrize("name", sorted(CLIS), ids=str)
def test_a_path_that_does_not_exist_is_an_error_not_a_clean_bill(name):
    """The failure that is fatal because it is *reassuring*.

    A tool that finds nothing and a tool that looked at nothing print the same
    thing unless somebody makes them different. Only one of those is a result
    about the user's code.
    """
    proc = _run(CLIS[name], "./definitely-not-a-real-path")
    assert proc.returncode == 255, (
        f"{name} exited {proc.returncode} on a path that does not exist; "
        f"255 is reserved for 'the scan could not run'.\n{proc.stdout}")
    assert "clean" not in proc.stdout.lower(), (
        f"{name} used the word 'clean' about a directory it never read")
    assert "no such path" in (proc.stdout + proc.stderr).lower(), (
        f"{name} must say which path was missing, or the operator cannot fix it")


@pytest.mark.parametrize("name", sorted(CLIS), ids=str)
def test_the_exit_code_cannot_wrap_around_to_success(name, tmp_path):
    """300 findings must not exit 0, 44, or anything below the clamp.

    An exit status is one byte. Unclamped, the single worst source tree either
    tool could be pointed at reports success -- nothing wrong enough to
    notice, which is this project's whole complaint, committed by the
    instrument.
    """
    proc = _run(CLIS[name], str(_too_many(tmp_path)))
    assert proc.returncode == 254, (
        f"{name} exited {proc.returncode} on 300 findings; expected the "
        f"clamp at 254.\n{proc.stdout[-500:]}")
    assert "300" in proc.stdout, (
        f"{name} clamped the status but must still print the real number")
