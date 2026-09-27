"""The keys a delegated token is verified with, held off the request path.

``verify`` is pure and takes its keys as an argument; this is where they
come from. A JWKS is a file or an ``https://`` URL, read once at startup
and again every ``refresh`` seconds by a task of its own, so a slow or
failing identity provider never stalls a read: verification uses the last
good set. Past ``max_age`` seconds without a successful read, that set is
no longer handed out and every delegated read refuses -- keys nobody has
been able to confirm for an hour are not keys to keep believing.

A ``kid`` the held set does not name is a refusal in ``verify``, never a
fetch here. Fetching on demand would hand every client a way to make the
boundary call the identity provider, as often as it likes, from inside a
read.
"""

from __future__ import annotations

import asyncio
import json
import time
import urllib.request
from typing import Callable, Mapping

from voyd.engine.delegation import Issuer, keys_from_jwks

FETCH_TIMEOUT_S = 10.0
MAX_JWKS_BYTES = 1024 * 1024


def read_jwks(where: str) -> dict[str, dict]:
    """One JWKS, read now. Raises with the reason on any failure."""
    if where.startswith("https://"):
        request = urllib.request.Request(
            where, headers={"Accept": "application/json",
                            "User-Agent": "voyd-wire"})
        with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT_S) as got:
            raw = got.read(MAX_JWKS_BYTES + 1)
    else:
        path = where.removeprefix("file://")
        with open(path, "rb") as handle:
            raw = handle.read(MAX_JWKS_BYTES + 1)
    if len(raw) > MAX_JWKS_BYTES:
        raise ValueError(f"{where}: larger than {MAX_JWKS_BYTES} bytes")
    return keys_from_jwks(json.loads(raw))


class Trust:
    """Every declared issuer's current keys, and the loop that renews them."""

    def __init__(self, issuers: Mapping[str, Issuer],
                 clock: Callable[[], float] = time.time,
                 reader: Callable[[str], dict[str, dict]] = read_jwks):
        self.issuers = dict(issuers)
        self.clock = clock
        self.reader = reader
        # `voyd-wire --oidc`: whether connections authenticate with these
        # issuers' tokens (`passthrough` or `terminate`), and for
        # `terminate` the boundary's own upstream SCRAM credentials.
        self.oidc: str | None = None
        self.upstream_auth: tuple[str, str, str] | None = None
        self.held: dict[str, dict[str, dict]] = {}
        self.at: dict[str, float] = {}
        self.why: dict[str, str] = {}

    def load(self, url: str) -> bool:
        issuer = self.issuers[url]
        try:
            self.held[url] = self.reader(issuer.jwks)
        except Exception as exc:                              # noqa: BLE001
            self.why[url] = f"{type(exc).__name__}: {exc}"
            return False
        self.at[url] = self.clock()
        self.why.pop(url, None)
        return True

    def preload(self) -> list[str]:
        """Read every JWKS once, at startup. Returns what could not be read.

        A key *file* that cannot be read is a configuration error and the
        caller refuses to start; a URL that cannot be reached is a warning,
        because the provider may come back and the refresh will find it.
        """
        return [url for url in self.issuers if not self.load(url)]

    def keys(self, url: str, now: float) -> dict[str, dict] | None:
        """The keys to verify with, or ``None`` if there are none current."""
        issuer = self.issuers.get(url)
        at = self.at.get(url)
        if issuer is None or at is None:
            return None
        if now - at > issuer.max_age:
            return None
        return self.held.get(url)

    async def refreshing(self, stopping: asyncio.Event) -> None:
        """Renew each issuer's keys on its own interval until shutdown."""
        due = {url: self.clock() + i.refresh for url, i in self.issuers.items()}
        while not stopping.is_set():
            now = self.clock()
            for url, when in due.items():
                if now >= when:
                    await asyncio.to_thread(self.load, url)
                    due[url] = self.clock() + self.issuers[url].refresh
            wait = max(0.5, min(due.values(), default=now + 60) - self.clock())
            try:
                await asyncio.wait_for(stopping.wait(), timeout=min(wait, 60))
            except asyncio.TimeoutError:
                pass
