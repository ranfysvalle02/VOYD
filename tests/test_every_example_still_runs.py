"""The front page's first instruction is `uv run python examples/...`.

Fifteen runnable programs are advertised, and until this file existed eight
of the then fourteen were executed by nothing. CI linted them, which catches a syntax
error and an unused import and no rename in the engine they call. The one
thing a stranger does first was the one thing nothing checked.

The list is built by globbing `examples/`, so a new example is covered the day
it lands. Skipping one costs a line in ``EXEMPT`` with a reason, which is the
same mechanism `__all__`, `COUNTED` and the scanner's break-glass claims all
use: the safe thing is the default and the other thing has to be said out loud.

Each example is run in a **subprocess**, deliberately. They are programs, not
importable modules -- `asyncio.run` in `main()`, a `finally` that drops the
database, an exit code. Importing and calling `main()` would test something
adjacent to what a reader actually does.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from .conftest import TEST_MONGO_URI

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = sorted(ROOT.glob("examples/*.py"))

# Every exemption is a sentence somebody had to write. Two kinds only: needs
# something this suite does not stand up, or cannot safely share a server with
# a test run.
EXEMPT = {
    "scope.py":
        "needs a running HTTP service (VOYD_URL / VOYD_API_KEY); it is the "
        "one example about the surface rather than the engine",
    "quickstart.py":
        "waits on a real mongot index build -- over 100s measured -- and is "
        "covered by tests/test_the_quickstart_refuses.py against the same path",
    "agent.py":
        "91s measured, for the same index build. The guarantee it shows is "
        "covered by tests/test_engine_agents.py",
    "forget.py":
        "turns ttlMonitorSleepSecs down to 1 -- a server global, so running it "
        "beside the suite makes it and test_the_deadline_is_enforced_twice.py "
        "restore each other's value. See the footgun note in conftest.py. "
        "Covered by tests/test_engine_expiry.py",
    "why_this_belongs_in_the_database.py":
        "same server global, same reason",
}

RUNNABLE = [p for p in EXAMPLES if p.name not in EXEMPT]


def test_every_exemption_names_a_file_that_exists():
    """An exemption for a deleted example silently stops covering nothing.

    It reads as a considered decision forever, which is worse than an absent
    line: the next person sees a justified skip rather than a stale one.
    """
    names = {p.name for p in EXAMPLES}
    ghosts = sorted(set(EXEMPT) - names)
    assert not ghosts, f"EXEMPT names examples that no longer exist: {ghosts}"
    assert RUNNABLE, "every example is exempt; this file now proves nothing"


@pytest.mark.parametrize("example", RUNNABLE, ids=lambda p: p.name)
def test_the_example_runs(example: Path):
    """It runs, it exits 0, and it prints something.

    The last one is not padding. Several of these programs make their point in
    the output rather than in an assertion -- `rosetta.py` shows five rules
    refusing together, `refuse.py` ends by printing that it issued zero
    deletes -- so a silent success is a program that stopped demonstrating
    what it is linked from the README to demonstrate.
    """
    # Every example reads this one variable, which is the reason they were
    # normalised: three of them used to hardcode the URI and one read
    # VOYD_TEST_MONGO_URI, so a suite pointed at a non-default server drove
    # them four different ways.
    env = dict(os.environ, VOYD_MONGO_URI=TEST_MONGO_URI)
    proc = subprocess.run([sys.executable, str(example)], cwd=ROOT, env=env,
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, (
        f"{example.name} exited {proc.returncode}\n"
        f"--- stdout ---\n{proc.stdout[-2000:]}\n"
        f"--- stderr ---\n{proc.stderr[-2000:]}")
    assert proc.stdout.strip(), f"{example.name} ran and printed nothing"
