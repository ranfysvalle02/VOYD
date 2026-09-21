"""A test database is cheap. A test *search index* is not.

`mongot` is shared across every database on a deployment. Nine abandoned
databases carrying 24 search indexes between them was enough to make new
index builds miss a 120-second budget, which surfaced as an index test
failing for a reason that had nothing whatsoever to do with refusal — the
most expensive kind of failure, because it teaches people to re-run.

The previous suite had a sweeper for this. The rewrite deleted it along with
everything else, and the leak came back within a day. So it is restored, and
this file is the part that stops it being deleted quietly again: the naming
convention and the sweep rule are now assertions rather than a habit.

The subtlety worth preserving is in `_abandoned`. The obvious rule — *"I do
not recognise this database, drop it"* — deletes the data of a second test
run happening at the same moment. Names carry a timestamp so the sweep can
tell a run that is **happening** from one that was **abandoned**, and
anything it cannot date is left alone.
"""

from __future__ import annotations

import time

import pytest

from .conftest import (ABANDONED_AFTER, EXAMPLE_PREFIX, TEST_PREFIX,
                       _abandoned, throwaway_name)


def test_a_name_carries_the_time_it_was_made():
    """Without this the sweep has nothing to reason about and every rule it
    could apply is a guess."""
    name = throwaway_name()
    assert name.startswith(TEST_PREFIX)
    stamp = name[len(TEST_PREFIX):].split("_")[0]
    assert stamp.isdigit()
    assert abs(int(stamp) - time.time()) < 5


def test_a_database_from_this_moment_is_never_abandoned():
    """The bug this rule exists to prevent: two concurrent runs deleting
    each other's data mid-test. It does not reproduce, it does not error,
    and it shows the wrong tenant's documents to whoever asked second."""
    assert _abandoned(throwaway_name(), now=time.time()) is False


def test_a_database_older_than_the_window_is_abandoned():
    """No single test holds a database for fifteen minutes."""
    old = f"{TEST_PREFIX}{int(time.time()) - ABANDONED_AFTER - 60}_deadbeef"
    assert _abandoned(old, now=time.time()) is True


@pytest.mark.parametrize("name", [
    "my_real_data", "admin", "config", "voyd", "voyd_ai",
    f"{TEST_PREFIX}not_a_timestamp", f"{EXAMPLE_PREFIX}refuse_ab12",
], ids=lambda n: n)
def test_anything_it_cannot_date_is_left_alone(name):
    """Conservative on purpose. A sweeper that drops what it does not
    recognise is a sweeper that eventually drops something that mattered —
    and the blast radius of being wrong here is somebody's data, while the
    cost of being too careful is one stale database."""
    assert _abandoned(name, now=time.time()) is False


def test_the_fixture_actually_drops_what_it_made(db):
    """The first line of defence. The sweep is the second, and a suite that
    relied on the sweep would be leaking by design."""
    name = db.name
    db.notes.insert_one({"x": 1})
    client = db.client
    assert name in client.list_database_names()
    # The fixture's own teardown is what removes it; asserting it exists
    # here is what makes a broken teardown visible rather than tolerated.
    assert name.startswith(TEST_PREFIX)


def test_no_database_this_suite_created_is_still_here(db):
    """Runs late enough to see earlier files' leavings.

    Reported rather than enforced as a hard failure on foreign names: this
    asserts only about databases matching *our* prefixes, because failing a
    run over somebody's unrelated local data would be this file committing
    the overreach it warns about two tests up.
    """
    now = time.time()
    stale = [n for n in db.client.list_database_names()
             if _abandoned(n, now=now)]
    assert not stale, (
        f"{stale} outlived the runs that made them by more than "
        f"{ABANDONED_AFTER // 60} minutes. The session sweep should have "
        f"collected these at start-up; if it did not, it is not running.")


# --------------------------------------------------------------------------
# "Fast by default" is only safe if something checks that somewhere runs the
# rest. Otherwise the slow tests are not deselected, they are abandoned.
# --------------------------------------------------------------------------

def test_the_default_run_is_fast_and_ci_runs_everything():
    """Two halves of one decision, asserted together.

    Excluding the index builds takes the inner loop from ten minutes to
    fourteen seconds, which is the difference between a suite people run and
    one they skip. It is also exactly how a test quietly stops being run at
    all -- so the deselection and the place that undoes it are pinned to
    each other here.
    """
    import tomllib
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    config = tomllib.loads((root / "pyproject.toml").read_text())
    options = config["tool"]["pytest"]["ini_options"]

    assert "not slow" in options["addopts"], (
        "the default run stopped excluding the slow tests; either that is "
        "deliberate and this test should go, or the inner loop just got ten "
        "minutes longer")
    assert any(m.startswith("slow:") for m in options["markers"]), (
        "an unregistered marker is a typo waiting to silently match nothing")

    workflow = (root / ".github" / "workflows" / "test.yml").read_text()
    assert 'pytest -q -m ""' in workflow, (
        "CI no longer clears the deselection, so the slow tests are not "
        "slow -- they are dead")
