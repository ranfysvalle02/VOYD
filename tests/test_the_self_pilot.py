"""The self-pilot is executable evidence, so CI executes it.

The generated markdown is a report, not the proof. ``bench.pilot.run`` is the
proof: assertions against a real MongoDB for the raw/handle gap, candidate
egress, inherited refusal and cumulative budget metadata.
"""

from __future__ import annotations

from bench.pilot import run


async def test_the_self_pilot_proves_every_claim_it_prints(core):
    engine, db = core
    report = await run(engine, db)

    assert report["canary"] == {
        "refused_by_handle": True,
        "served_by_raw": True,
    }
    assert report["after_revoke"]["raw_find_still_serves_leak"] is True
    assert report["after_revoke"]["handle_find_serves_leak"] is False
    assert report["after_revoke"]["unfiltered_candidates_contain_leak"] is True
    assert report["after_revoke"]["handle_reachable_serves_leak"] is False
    assert report["inherited_refusal"]["summary_reachable"] is False

    budget = report["budget"]
    assert budget["admitted"] == 2
    assert budget["spent"] == 80
    assert budget["refused"] == {"over_budget": 2}
    assert budget["examined_per_admitted"] == 2.0
    assert budget["starved"] is False
    assert report["budget_receipts"]["refused_by_reason"] == {
        "over_budget": 2}
