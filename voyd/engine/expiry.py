"""TTL: expiry as infrastructure, not a cron job.

A TTL index makes the database responsible for deleting things that have aged
out. No reaper process, no scheduled job, no "did the cleanup task run last
night" incident.

Two modes, and the difference matters:

- **per-document** (``at_field``): the document carries its own deadline. A
  document with no deadline field, or a null one, is kept **forever**. That is
  the property that lets one collection hold both expiring and permanent
  records -- scratch notes next to a user's name, a session next to a
  collection. Pinning is the absence of a deadline, not a second field.
- **fixed age** (``after``): everything expires a fixed duration after its
  timestamp. The right shape for logs and metrics.

The caveat worth stating plainly, because people trip on it: **MongoDB's TTL
monitor runs about once a minute**, so expiry is eventual, not instant. An
expired document can still be read for up to a minute or so. Never use a TTL
index as a security boundary -- check the deadline in your query too.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import timedelta

from pymongo.errors import OperationFailure

log = logging.getLogger("engine.expiry")


@dataclass(frozen=True)
class ExpirySpec:
    """A declared TTL policy for one collection.

    Exactly one of ``at_field`` (per-document deadline) or ``after`` (fixed age
    from ``at_field``'s timestamp) describes the intent.
    """

    collection: str
    at_field: str = "expire_at"
    after: timedelta | None = None

    @property
    def seconds(self) -> int:
        """``0`` means "expire exactly at the stored time"."""
        return int(self.after.total_seconds()) if self.after else 0

    def describe(self) -> str:
        if self.after is None:
            return (f"{self.collection}.{self.at_field}: per-document deadline "
                    f"(null = kept forever)")
        return f"{self.collection}.{self.at_field}: {self.after} after timestamp"


class Expiry:
    """Applies TTL policies."""

    def __init__(self, db):
        self.db = db
        self.specs: list[ExpirySpec] = []

    def register(self, spec: ExpirySpec) -> None:
        self.specs.append(spec)

    async def ensure(self) -> int:
        applied = 0
        for spec in self.specs:
            try:
                await self.db[spec.collection].create_index(
                    spec.at_field, expireAfterSeconds=spec.seconds)
                applied += 1
                log.debug("TTL: %s", spec.describe())
            except OperationFailure as exc:
                # Changing expireAfterSeconds on an existing index needs collMod.
                if exc.code == 85:  # IndexOptionsConflict
                    try:
                        await self.db.command({
                            "collMod": spec.collection,
                            "index": {"keyPattern": {spec.at_field: 1},
                                      "expireAfterSeconds": spec.seconds},
                        })
                        applied += 1
                    except OperationFailure as mod_exc:
                        log.warning("could not update TTL on %s: %s",
                                    spec.collection, mod_exc)
                else:
                    log.warning("could not create TTL on %s.%s: %s",
                                spec.collection, spec.at_field, exc)
        return applied
