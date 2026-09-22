"""The one thing in this suite that deletes data, tested like it.

`sweep` exists because a `finally` block does not run after `kill -9`, so
each run drops the throwaway databases an earlier one abandoned. That makes
it the only code here that issues `dropDatabase` against a name it was not
handed -- it *decides* the name -- and the cost of getting that decision
wrong is somebody's data rather than a red test.

So the rule is asserted directly, against a stand-in that records what it
was asked to drop instead of dropping it. Two directions, and the second is
the one that matters: it must reach a database this suite abandoned, and it
must not reach anything else, including a database this suite is using right
now in another process.

Pure: no cluster, no driver, no network.
"""

from __future__ import annotations

import time

from tests.conftest import STALE_AFTER_S, scratch_name, sweep

NOW = 1_800_000_000.0
OLD = int(NOW - STALE_AFTER_S - 60)
RECENT = int(NOW - 60)


class FakeClient:
    """A client that remembers what it was told to drop."""

    def __init__(self, names):
        self._names = list(names)
        self.dropped: list[str] = []

    def list_database_names(self):
        return list(self._names)

    def drop_database(self, name):
        self.dropped.append(name)


def test_it_reaches_a_database_an_earlier_run_abandoned():
    client = FakeClient([f"voyd_test_{OLD}_abc12345"])
    assert sweep(client, now=NOW) == [f"voyd_test_{OLD}_abc12345"]
    assert client.dropped == [f"voyd_test_{OLD}_abc12345"]


def test_it_never_reaches_a_run_that_is_still_going():
    # The whole reason for the window. Two suites on one cluster is an
    # ordinary thing -- a laptop and CI against the same Atlas project --
    # and a sweep that dropped the other one's database would be this
    # harness causing the failure it is meant to clean up after.
    client = FakeClient([f"voyd_test_{RECENT}_abc12345"])
    assert sweep(client, now=NOW) == []
    assert client.dropped == []


def test_it_never_reaches_a_database_that_is_not_ours():
    # Everything a real cluster has beside the test databases, including
    # names that share the prefix and names that merely look like one.
    theirs = ["admin", "local", "config", "voyd", "voyd_prod",
              "voyd_test", "voyd_testing", f"voyd_test_{OLD}",
              f"voyd_test_{OLD}_abc_extra", "voyd_test_notanumber_abc12345",
              f"notvoyd_test_{OLD}_abc12345", f"x_voyd_test_{OLD}_abc12345"]
    client = FakeClient(theirs)
    assert sweep(client, now=NOW) == []
    assert client.dropped == []


def test_it_picks_the_abandoned_ones_out_of_a_real_looking_cluster():
    old = [f"voyd_test_{OLD}_aaaaaaaa", f"voyd_test_{OLD - 99_999}_bbbbbbbb"]
    client = FakeClient(["admin", "voyd", *old,
                         f"voyd_test_{RECENT}_cccccccc"])
    assert sorted(sweep(client, now=NOW)) == sorted(old)


def test_the_name_this_suite_generates_is_one_the_sweep_can_read():
    # The two halves have to agree, and they are written in different
    # functions: a name the sweep cannot parse is a leak that never gets
    # collected, and it would look exactly like the sweep working.
    name = scratch_name()
    assert name.startswith("voyd_test_")
    client = FakeClient([name])
    # Not yet -- it was made this second.
    assert sweep(client) == []
    # And after the window, by the same rule.
    assert sweep(client, now=time.time() + STALE_AFTER_S + 1) == [name]


def test_two_names_in_the_same_second_are_still_two_databases():
    assert scratch_name() != scratch_name()
