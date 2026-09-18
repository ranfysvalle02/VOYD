"""What can this deployment actually do?

Every other part of the engine degrades against what this probe reports: pick
the best available tier, announce it, never pretend.

It exists because the opposite bit us. Atlas support used to be inferred from
the connection string -- ``"mongodb.net" in uri`` -- which calls the Atlas Local
container, reached at ``mongodb://localhost``, "not Atlas". Every local run
silently used a fallback path and ``$vectorSearch`` never executed at all, for
months, without a single log line. Asking the server is the only honest question.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from pymongo.errors import OperationFailure

log = logging.getLogger("engine.capabilities")

# $rankFusion (reciprocal rank fusion as a first-class aggregation stage) is 8.1+.
RANK_FUSION_MIN_VERSION = (8, 1)


@dataclass(frozen=True)
class Capabilities:
    """A deployment's answer, probed once at connect time."""

    version: tuple[int, ...] = ()
    search: bool = False          # mongot present: $search / $vectorSearch
    rank_fusion: bool = False     # $rankFusion available
    change_streams: bool = False  # replica set / sharded: watch() works

    @property
    def search_tier(self) -> str:
        if not self.search:
            return "cosine"
        return "hybrid" if self.rank_fusion else "vector"

    def describe(self) -> str:
        v = ".".join(str(p) for p in self.version) or "unknown"
        return (f"MongoDB {v} | search={self.search_tier} "
                f"| change_streams={self.change_streams}")


async def detect(client, db) -> Capabilities:
    """Probe the live deployment.

    ``$listSearchIndexes`` is the honest test for search: Atlas and Atlas Local
    answer it, a plain ``mongod`` raises ``Unrecognized pipeline stage name``.
    """
    info = await client.admin.command("buildInfo")
    version = tuple(info.get("versionArray", [])[:3])

    search = await _supports_search(db)
    change_streams = await _supports_change_streams(client)

    caps = Capabilities(
        version=version,
        search=search,
        rank_fusion=search and version >= RANK_FUSION_MIN_VERSION,
        change_streams=change_streams,
    )
    log.info("capabilities: %s", caps.describe())
    if not caps.search:
        log.warning(
            "Atlas Search unavailable: semantic search will fall back to exact "
            "in-process cosine, which is correct but scales linearly. "
            "Run a search-capable deployment (mongodb/mongodb-atlas-local).")
    return caps


async def _supports_search(db) -> bool:
    try:
        # Any collection will do; the stage itself is what is being probed.
        cursor = await db["__engine_probe"].aggregate(
            [{"$listSearchIndexes": {}}, {"$limit": 1}])
        await cursor.to_list(1)
        return True
    except OperationFailure:
        return False


async def _supports_change_streams(client) -> bool:
    """A standalone mongod has no oplog, so watch() cannot work. Checking the
    topology is cheaper and clearer than opening a stream to see it fail."""
    try:
        hello = await client.admin.command("hello")
    except OperationFailure:
        return False
    return bool(hello.get("setName") or hello.get("msg") == "isdbgrid")
