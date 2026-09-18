"""The limiter is pure, so its edges are cheap to pin down without a clock."""

from __future__ import annotations

import pytest

from voyd.ratelimit import RateLimiter


def test_allows_up_to_the_limit_then_blocks():
    rl = RateLimiter(limit=3, window_s=60)
    assert [rl.check("k", now=0) for _ in range(3)] == [True, True, True]
    assert rl.check("k", now=0) is False


def test_keys_are_independent():
    rl = RateLimiter(limit=1, window_s=60)
    assert rl.check("a", now=0) is True
    assert rl.check("b", now=0) is True
    assert rl.check("a", now=0) is False


def test_the_window_slides_rather_than_resetting_in_steps():
    """A fixed window would let 2*limit through across a boundary; this must not."""
    rl = RateLimiter(limit=2, window_s=10)
    assert rl.check("k", now=0) is True
    assert rl.check("k", now=9) is True
    assert rl.check("k", now=9.5) is False   # both attempts still in window
    assert rl.check("k", now=10.5) is True   # the first has aged out, the second has not
    assert rl.check("k", now=10.6) is False


def test_blocked_attempts_do_not_extend_the_penalty():
    """Hammering while blocked must not keep pushing the window forward, or a
    client that retries in a loop could lock itself out permanently."""
    rl = RateLimiter(limit=1, window_s=10)
    assert rl.check("k", now=0) is True
    for t in range(1, 10):
        assert rl.check("k", now=t) is False
    assert rl.check("k", now=10.1) is True


def test_reset_clears_a_key():
    rl = RateLimiter(limit=1, window_s=60)
    rl.check("k", now=0)
    assert rl.check("k", now=0) is False
    rl.reset("k")
    assert rl.check("k", now=0) is True


def test_idle_keys_are_swept_so_memory_tracks_active_callers():
    rl = RateLimiter(limit=5, window_s=10, sweep_at=4)
    for i in range(10):
        rl.check(f"key-{i}", now=0)
    rl.check("late", now=100)   # crosses sweep_at with everything else expired
    assert len(rl._hits) == 1


def test_limit_must_be_positive():
    with pytest.raises(ValueError):
        RateLimiter(limit=0, window_s=60)
