"""`numCandidates` is a boundary concern, not a tuning knob.

`$vectorSearch` draws `numCandidates` and returns `limit`. MongoDB's own
guidance is to scale the pool with how selective your filter is -- but a
collection that *refuses* things has a second, independent reason for the
pool to come back short, and it is the bigger one: if half of what the index
ranks here is already forgotten, a pool sized for `limit` returns half a
page and `saturate` pays for another round trip to find that out.

The number was `max(50, limit * 10)`: a constant somebody guessed once, the
same for a scope where nothing is ever revoked and a scope where almost
everything is.

Here is the part worth the abstraction. **No other component can compute
this.** The index does not know your deadline, so it cannot know what
fraction of what it ranks is already gone. The driver does not. The only
component that knows the refusal rate is the one doing the refusing -- and
on the search path its count is *exact*, because a `$vectorSearch` hit
passes through no query, so every candidate is either admitted or counted.

So the boundary sizes its own fetch, from measurement rather than from a
guess. It only ever raises the ask, and refill still guarantees the page:
this is an optimisation on top of correctness, never a replacement for it.
"""

from __future__ import annotations

import pytest

from voyd.engine.admission.receipts import Receipts


def test_a_cold_boundary_asks_for_no_more_than_it_used_to():
    """Nothing measured means nothing inferred. A factor above 1.0 on the
    first read would be a guess dressed as a measurement."""
    assert Receipts().over_fetch() == 1.0


def test_one_refusal_does_not_move_the_number():
    """The minimum sample, and the reason for it: a single refusal in the
    first handful of documents is noise, and reacting to it would triple
    the pool for a collection that is perfectly healthy."""
    r = Receipts()
    r.observe(10, 9)
    assert r.over_fetch() == 1.0


@pytest.mark.parametrize("examined,admitted,expected", [
    (100, 100, 1.0),     # nothing refused -- ask for what you want
    (100, 50, 2.0),      # half refused -- ask for twice as many
    (100, 25, 4.0),      # three quarters -- four times
    (1000, 100, 10.0),   # ninety percent -- ten times
], ids=["none", "half", "three-quarters", "ninety-percent"])
def test_the_factor_is_the_arithmetic_and_not_a_heuristic(
        examined, admitted, expected):
    """`1 / (1 - rate)` is the expected over-fetch exactly. If you refuse
    half of what arrives you must ask for twice as many to come back with a
    full page -- there is no tuning constant in that, which is why this is
    derived rather than configured."""
    r = Receipts()
    r.observe(examined, admitted)
    assert r.over_fetch() == pytest.approx(expected, rel=1e-6)


def test_a_scope_where_everything_is_forgotten_is_capped():
    """Without a ceiling, a scope refusing 99.9% would ask for a pool the
    size of the collection -- turning a cheap wrong answer into an expensive
    one, which is not an improvement."""
    r = Receipts()
    r.observe(1000, 1)
    assert r.over_fetch() == 12.0


def test_it_can_only_ever_raise_the_ask():
    """The floor is the whole safety argument. This sits on top of refill:
    if the estimate is wrong, `saturate` still fills the page -- but an
    estimate that *lowered* the ask could make a page short that would
    otherwise have been complete."""
    for examined, admitted in ((100, 100), (100, 120), (0, 0), (50, 0)):
        assert Receipts().over_fetch() >= 1.0
        r = Receipts()
        r.observe(examined, admitted)
        assert r.over_fetch() >= 1.0


def test_the_number_is_visible_to_whoever_pays_for_it():
    """A caller watching their over-fetch climb is looking at the cost of
    their own refusal rate. That is a tuning conversation, and it cannot
    happen if the number is buried."""
    r = Receipts()
    r.observe(200, 100)
    out = r.as_dict()
    assert out["search_examined"] == 200
    assert out["search_admitted"] == 100
    assert out["over_fetch"] == 2.0


def test_the_search_path_records_what_it_threw_away():
    """End to end, and with no database in sight -- which is the point.

    `reachable()` is the search path's entry point and a pure function, so
    the arithmetic that sizes the next fetch is computed by the same code
    that would run inside a proxy, a browser, or anywhere else this boundary
    is carried to.
    """
    from datetime import timedelta

    from voyd.engine import Deadline, revoked
    from voyd.engine.admission import Admission, AdmissionSpec
    from voyd.engine.time import now

    notes = Admission(None, AdmissionSpec(
        "notes", rules=(Deadline(), revoked())))
    past = now() - timedelta(days=1)

    kept = notes.reachable([
        {"text": "live"},
        {"text": "gone", "expire_at": past},
        {"text": "also gone", "expire_at": past},
    ])

    assert len(kept) == 1
    out = notes.receipts()
    assert out["search_examined"] == 3
    assert out["search_admitted"] == 1
    # Three examined is below the minimum sample, so nothing is inferred yet
    # -- the count is being gathered, not acted on.
    assert out["over_fetch"] == 1.0
