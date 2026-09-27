"""Temporary collections for the native steps after a virtual one.

    [{"$match": ...}, {"$keywordRank": ...}, {"$match": ...}, {"$sort": ...}]
                       ^ runs here            ^ runs in mongod, on a temp

A native stage after a virtual one has to run somewhere, and the only
engine that runs `$group`, `$sort` and `$setWindowFields` exactly is
mongod. So the virtual step's output is written to a temporary collection,
the rest of the pipeline runs there, and the collection is dropped.

**Only what was admitted is ever written here.** The native prefix is never
`$out` into a temporary collection -- that would copy refused documents to
a place no policy guards. What lands here is what a virtual step produced
from documents the boundary already admitted, masked and neutralised, and
then judged again. See `policy/stages.py`.

**The connection is the boundary's own**, opened per worker from the same
`--target` URI (and so the same credentials) the proxy was started with,
the way `cascade.py` opens one. Not the client's: the temporary database is
refused to every client (see `refuse_scratch`), so the client's session has
nothing it could do there, and borrowing it would put the boundary's
housekeeping inside a transaction the client might be running.

**A temporary collection does not outlive its read**, and three things make
that true rather than hoped for:

1. it is dropped in a `finally`, on every exit path the interpreter gets;
2. every proxy sweeps the temporary database when it starts, and again
   every so often, dropping what is older than `--virtual-max-age` --
   including other instances' leftovers, which is what makes a `kill -9`
   recoverable;
3. nothing outside that database, and nothing inside it this module did
   not name, is ever dropped. The name is the permission.

Names are ``t_<instance>_<unix seconds>_<uuid>``: the instance says which
proxy made it, the time is what a sweep reads, and the uuid makes two
reads in one second two collections.
"""

from __future__ import annotations

import asyncio
import logging
import re
import secrets
import time
import uuid
from typing import Any, Mapping

from .policy.stages import StageError, Virtuals

log = logging.getLogger("voyd.scratch")

NAME = re.compile(r"^t_([0-9a-f]{8})_(\d{10})_([0-9a-f]{32})$")


def scratch_name(instance: str, now: float | None = None) -> str:
    """A fresh temporary collection name for ``instance``."""
    return (f"t_{instance}_{int(now if now is not None else time.time()):010d}"
            f"_{uuid.uuid4().hex}")


def created_at(name: str) -> int | None:
    """The unix second a temporary collection was named in, or `None` if
    this is not a name this module makes."""
    match = NAME.match(name)
    return int(match.group(2)) if match else None


def ours(database: str, name: str, scratch_db: str) -> bool:
    """May this module drop ``database.name``? Only by name, and only here."""
    return database == scratch_db and created_at(name) is not None


class Scratch:
    """One worker's temporary collections, and the sweep that bounds them."""

    def __init__(self, uri: str, virtuals: Virtuals, *,
                 verbose: bool = False, client: Any = None,
                 instance: str | None = None) -> None:
        self.uri = uri
        self.database = virtuals.database
        self.max_age_s = virtuals.max_age_s
        self.verbose = verbose
        self.instance = instance or secrets.token_hex(4)
        self._client = client
        self.created = 0
        self.swept = 0

    async def open(self) -> None:
        if self._client is None:
            from pymongo import AsyncMongoClient

            self._client = AsyncMongoClient(self.uri)
        try:
            gone = await self.sweep()
        except Exception as exc:                               # noqa: BLE001
            # Housekeeping never stops a boundary from starting; the
            # periodic sweep tries again.
            print(f"voyd-wire: could not sweep {self.database!r} at start: "
                  f"{type(exc).__name__}: {exc}", flush=True)
            return
        if gone:
            print(f"voyd-wire: swept {len(gone)} temporary collection(s) "
                  f"older than {self.max_age_s:g}s from {self.database!r}",
                  flush=True)

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.close()
            self._client = None

    async def drop(self, name: str) -> None:
        """Drop one temporary collection. Refuses anything else, loudly."""
        if not ours(self.database, name, self.database):
            raise ValueError(f"refusing to drop {self.database}.{name}: not "
                             f"a temporary collection this boundary names")
        await self._client[self.database].drop_collection(name)

    async def sweep(self, now: float | None = None) -> list[str]:
        """Drop temporary collections older than the max age. Any instance's."""
        if self._client is None:
            return []
        cutoff = (now if now is not None else time.time()) - self.max_age_s
        names = await self._client[self.database].list_collection_names()
        gone = []
        for name in names:
            stamp = created_at(name)
            if stamp is None or stamp >= cutoff:
                continue
            await self.drop(name)
            gone.append(name)
        self.swept += len(gone)
        return gone

    async def sweeping(self, stopping: asyncio.Event) -> None:
        """Sweep every quarter of the max age (at most once a minute)."""
        every = min(60.0, max(1.0, self.max_age_s / 4))
        while not stopping.is_set():
            try:
                await asyncio.wait_for(stopping.wait(), timeout=every)
            except asyncio.TimeoutError:
                pass
            if stopping.is_set():
                return
            try:
                await self.sweep()
            except Exception as exc:                           # noqa: BLE001
                log.warning("sweep of %s failed: %s", self.database, exc)

    async def run(self, docs: list[dict], pipeline: list, *,
                  let: Mapping | None = None, collation: Any = None,
                  max_docs: int) -> list[dict]:
        """``pipeline`` in mongod over ``docs``, via a temporary collection.

        Each document is stored as ``{_id: <position>, d: <document>}`` and
        the pipeline is run behind ``$sort: {_id: 1}, $replaceWith: "$d"``.
        That keeps the order a ranking arrived in, and it lets two rows
        share an `_id` -- which `$unwind` in an earlier native step makes
        ordinary -- without the collection's unique index refusing them.
        """
        from pymongo.errors import PyMongoError

        if self._client is None:
            raise StageError("the temporary-collection connection is closed")
        name = scratch_name(self.instance)
        coll = self._client[self.database][name]
        try:
            await self._client[self.database].create_collection(name)
            self.created += 1
            if docs:
                await coll.insert_many(
                    [{"_id": at, "d": doc} for at, doc in enumerate(docs)])
            options: dict = {}
            if let:
                options["let"] = dict(let)
            if collation:
                options["collation"] = collation
            cursor = await coll.aggregate(
                [{"$sort": {"_id": 1}}, {"$replaceWith": "$d"}, *pipeline],
                **options)
            out = await cursor.to_list(max_docs + 1)
        except PyMongoError as exc:
            raise StageError(f"the native steps after a virtual one failed "
                             f"in MongoDB: {exc}") from exc
        except (TypeError, ValueError) as exc:
            raise StageError(f"a virtual step produced a value BSON cannot "
                             f"carry: {exc}") from exc
        finally:
            try:
                await self.drop(name)
            except Exception as exc:                           # noqa: BLE001
                # The sweep is the second line, and this is why it exists.
                log.warning("could not drop %s.%s: %s", self.database,
                            name, exc)
        if len(out) > max_docs:
            raise StageError(
                f"the native steps after a virtual one produced more than "
                f"{max_docs} documents (--virtual-max-docs); truncating would "
                f"answer a different question without saying so")
        return out
