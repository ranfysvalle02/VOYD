"""A job queue where the document *is* the job.

No broker, no separate queue store, no serialisation format. A document matching
``when`` is work to be done; an atomic ``find_one_and_update`` claims it, so
running N replicas is safe with no coordination.

The design exists because of one specific bug, which is worth stating plainly
since it is the whole argument for the retry policy:

    A placeholder API key made every embed call fail. Each failure marked its
    document permanently un-processable. Supplying a valid key later fixed
    nothing -- no jobs were left to claim, so the search index stayed empty
    forever, silently, with no error anywhere.

The lesson generalises: **a handler failing usually says something about the
world, not about the document.** Bad keys, rate limits, and network blips are
transient and must be retried; only a bounded number of attempts, or a failure
the caller explicitly calls permanent, should consume a job.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, ClassVar

from pymongo import ReturnDocument

from .time import now

log = logging.getLogger("engine.jobs")

DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_VISIBILITY = timedelta(seconds=120)


class PermanentFailure(Exception):
    """Raise from a handler when the *document* is the problem.

    Empty text, an unsupported format, malformed content -- retrying cannot
    help, so the job is parked immediately instead of burning its attempts.
    """


@dataclass
class JobQueue:
    """Claim-based work over one collection.

    ``status_field`` moves ``pending -> True`` on success, ``"error"`` when
    parked. ``attempts_field`` counts tries so a poisoned document cannot block
    the queue forever. ``visibility`` is how long a crashed worker may hold a
    claim before another replica reclaims it -- without this, a kill -9 pins
    the job until someone notices.
    """

    # `Any`, as in every other trait (see search.py): this is the engine's
    # UTC-bound database handle, and `object` made all five uses of it
    # below unindexable without describing anything true about it.
    db: Any
    collection: str
    when: dict
    status_field: str = "indexed"
    attempts_field: str = "attempts"
    max_attempts: int = DEFAULT_MAX_ATTEMPTS
    claimed_field: str = "claimed_at"
    visibility: timedelta = DEFAULT_VISIBILITY
    kind: ClassVar[str] = "queue"

    def _attempts_ok(self) -> dict:
        return {"$or": [
            {self.attempts_field: {"$exists": False}},
            {self.attempts_field: {"$lt": self.max_attempts}},
        ]}

    def claimable(self) -> dict:
        """Jobs that match, are not currently held, and still have attempts.

        ``when`` alone is not enough: ``{status: {$ne: true}}`` would match
        ``pending`` and two replicas would claim the same document. A pending
        claim older than ``visibility`` is treated as a dead worker.
        """
        stale = now() - self.visibility
        fresh = {"$and": [
            self.when,
            {self.status_field: {"$ne": "pending"}},
            self._attempts_ok(),
        ]}
        expired = {"$and": [
            {self.status_field: "pending"},
            {"$or": [
                {self.claimed_field: {"$lte": stale}},
                {self.claimed_field: {"$exists": False}},
            ]},
            self._attempts_ok(),
        ]}
        return {"$or": [fresh, expired]}

    async def ensure(self) -> bool:
        """Index the claim scan. Unindexed find_one_and_update is a collection
        scan on every tick, which is the queue's scale cliff."""
        await self.db[self.collection].create_index([
            (self.status_field, 1),
            (self.claimed_field, 1),
        ])
        return True

    async def claim(self) -> dict | None:
        """Atomically take the next job, or None. Safe across replicas.
        Oldest ``_id`` first, so a hot new write cannot starve the backlog."""
        return await self.db[self.collection].find_one_and_update(
            self.claimable(),
            {"$set": {self.status_field: "pending", self.claimed_field: now()}},
            sort=[("_id", 1)],
            return_document=ReturnDocument.AFTER,
        )

    async def complete(self, job: dict, update: dict | None = None) -> None:
        await self.db[self.collection].update_one(
            {"_id": job["_id"]},
            {"$set": {**(update or {}), self.status_field: True},
             "$unset": {self.claimed_field: ""}},
        )

    async def release(self, job: dict) -> None:
        """Return a job for another attempt, counting the try."""
        await self.db[self.collection].update_one(
            {"_id": job["_id"]},
            {"$set": {self.status_field: False},
             "$inc": {self.attempts_field: 1},
             "$unset": {self.claimed_field: ""}},
        )

    async def park(self, job: dict, update: dict | None = None) -> None:
        """Give up on a job without blocking the queue."""
        await self.db[self.collection].update_one(
            {"_id": job["_id"]},
            {"$set": {**(update or {}), self.status_field: "error"},
             "$unset": {self.claimed_field: ""}},
        )

    async def fail(self, job: dict, exc: Exception,
                   *, park_update: dict | None = None) -> bool:
        """Route a failure. Returns True if the job was parked for good.

        Retry unless the handler declared the document itself unusable, or the
        job has exhausted its attempts.
        """
        if isinstance(exc, PermanentFailure):
            log.info("parking %s %s: %s", self.collection, job["_id"], exc)
            await self.park(job, park_update)
            return True

        attempts = int(job.get(self.attempts_field, 0)) + 1
        if attempts >= self.max_attempts:
            log.error("giving up on %s %s after %d attempts: %s",
                      self.collection, job["_id"], attempts, exc)
            await self.park(job, park_update)
            return True

        log.warning("attempt %d/%d failed for %s %s: %s",
                    attempts, self.max_attempts, self.collection, job["_id"], exc)
        await self.release(job)
        return False


def backoff(failures: int, base: float, *, cap: float = 60.0) -> float:
    """Slow the whole loop down after repeated failures.

    A bad credential should cost a slow trickle of retries, not a hot loop
    against someone else's API.
    """
    if failures < 3:
        return base
    return min(base * 2 ** (failures - 2), cap)
