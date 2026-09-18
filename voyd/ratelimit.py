"""A small in-process rate limiter for the credential endpoints.

Argon2 makes each login guess expensive, which is a cost ceiling, not a limit:
an attacker can still run guesses in parallel forever. This caps the *rate*.

Deliberately in-process and dependency-free. It is per-replica, so N replicas
allow N times the limit -- still a bound, and the honest trade for keeping a
password form from needing Redis. Attempts are pruned lazily, so memory tracks
the number of *recently active* keys, not total traffic.
"""

from __future__ import annotations

import time
from collections import deque


def client_ip(request) -> str:
    """The peer address. Proxy headers are ignored on purpose -- ``X-Forwarded-For``
    is attacker-controlled unless a trusted proxy rewrites it, and trusting it
    here would make the limiter free to bypass."""
    client = getattr(request, "client", None)
    return getattr(client, "host", None) or "unknown"


class RateLimiter:
    """Sliding-window limiter: at most ``limit`` hits per ``window_s`` per key."""

    def __init__(self, limit: int, window_s: float, *, sweep_at: int = 2048):
        if limit < 1:
            raise ValueError("limit must be >= 1")
        self.limit = limit
        self.window_s = float(window_s)
        self._sweep_at = sweep_at
        self._hits: dict[str, deque[float]] = {}

    def check(self, key: str, *, now: float | None = None) -> bool:
        """Record an attempt. Returns False once the key is over its limit.

        A blocked attempt is not recorded, so a caller that keeps hammering
        does not extend its own penalty indefinitely.
        """
        now = time.monotonic() if now is None else now
        cutoff = now - self.window_s

        if len(self._hits) >= self._sweep_at:
            self._sweep(cutoff)

        hits = self._hits.setdefault(key, deque())
        while hits and hits[0] <= cutoff:
            hits.popleft()

        if len(hits) >= self.limit:
            return False
        hits.append(now)
        return True

    def _sweep(self, cutoff: float) -> None:
        """Drop keys whose attempts have all aged out."""
        self._hits = {k: v for k, v in self._hits.items() if v and v[-1] > cutoff}

    def reset(self, key: str) -> None:
        """Forget a key. Called on success, so one good login clears the count."""
        self._hits.pop(key, None)

    def clear(self) -> None:
        """Forget everything. For tests, which must not inherit each other's attempts."""
        self._hits.clear()
