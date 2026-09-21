"""The pilot's first week is an instrument, so the instrument is checked.

`PILOT.md` asks a stranger to put three lines into production on the promise
that they change nothing and produce an exact number. Both halves of that
promise are testable, and neither is obvious:

- **changes nothing.** The raw read must still return every document it
  returned before, including the ones the handle would refuse. A shadow probe
  that quietly filtered the caller's own list would be the worst possible bug
  here -- it would silently do the adoption the team had not agreed to yet.
- **exact, not a lower bound.** `receipts()["refused_at_boundary"]`
  under-reports by design, because the same rule runs inside the collection
  query and MongoDB drops most forgotten documents server-side. Shadow mode
  gets an exact count *because* the read feeding it is the unfiltered one, so
  every document reaches the boundary to be counted. That inversion is the
  subtlest thing in the pilot and the easiest to lose.
"""

from __future__ import annotations

from examples.shadow import run


async def test_the_shadow_probe_changes_nothing_and_counts_exactly(core):
    engine, db = core
    r = await run(engine, db)

    # Four documents in, four documents out: the read path is untouched.
    assert r["served_by_your_read_path"] == 4
    assert r["still_served"] == {
        "expired": True, "revoked": True,
        "summary_of_revoked": True, "the_live_one": True,
    }, "the existing read path must keep serving exactly what it served before"

    # Three of the four should never have been reachable, and the fourth must
    # survive -- a probe that refuses everything measures nothing.
    assert r["would_have_refused"] == 3
    assert r["would_still_reach_a_prompt"] == {
        "expired": False, "revoked": False,
        "summary_of_revoked": False, "the_live_one": True,
    }

    # The exactness claim. Every document was fetched by an unfiltered read,
    # so every document reached the egress boundary and was counted there --
    # unlike the ordinary `find` path, where the query drops them first and
    # the receipt is honestly a floor.
    assert r["receipts_refused_at_boundary"] == r["would_have_refused"]

    assert r["behaviour_changed"] is False
