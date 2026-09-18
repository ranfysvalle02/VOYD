"""Durable change-stream handlers.

A change stream turns "something happened in the database" into an event without
a broker. The catch is that a change stream is *not* a stable pipe: primary
elections, failovers and network blips all break it, and on a replica set those
are routine rather than exceptional.

The bug this encodes: the first version of this collector exited on its first
exception. One primary election silently stopped all blob garbage collection for
the life of the process and orphaned every object created afterwards -- a bill
that grows quietly, forever, with a single misleading log line.

So: a broken stream is resumed, not fatal. Only a deployment that cannot support
streams at all is terminal, and that is reported as unsupported.

**Known limits, stated up front.** This is not Kafka. There are no consumer
groups, no fan-out, no replay beyond the oplog window, and delivery is
at-least-once -- a handler that runs twice must be idempotent. Every replica
running a reactor sees every event.
"""

from __future__ import annotations

import asyncio
import logging

from pymongo.errors import OperationFailure, PyMongoError

log = logging.getLogger("engine.reactor")

# Retrying cannot help: no replica set, or streams unsupported.
UNSUPPORTED_CODES = {40573, 148}
# The stored token has aged out of the oplog window.
HISTORY_LOST = 286

MAX_BACKOFF = 30.0
MAX_HANDLER_TRIES = 3


class _Redeliver(Exception):
    """A handler failed. Do not advance the resume token."""


class Reactor:
    """Watches a database for changes and dispatches to handlers.

    ``checkpoint``/``restore`` persist the resume token, so a restart picks up
    where it left off instead of missing everything that happened while down.
    """

    def __init__(self, db, *, checkpoint=None, restore=None,
                 name: str = "reactor"):
        self.db = db
        self.name = name
        self._checkpoint = checkpoint
        self._restore = restore
        self._handlers: dict[tuple[str, str], list] = {}
        self._stop = asyncio.Event()
        self._fail_id = None
        self._fail_n = 0
        # Observability, for the same reason search counts its fallbacks: a
        # reactor that resumed is fine, a reactor that lost a window is a
        # silent bill, and a reactor that gave up is silently doing nothing.
        # Logged-once is not enough to alert on.
        self.resumes = 0
        self.windows_lost = 0
        self.events_skipped = 0
        self.events_dispatched = 0
        self.unsupported = False
        self.last_error: str | None = None

    def on(self, operation: str, collection: str):
        """Register a handler. ``@reactor.on("delete", "files")``.

        Delete handlers receive the pre-image, which is the only way to learn
        what a deleted document contained -- requires
        ``changeStreamPreAndPostImages`` on the collection.
        """
        def decorator(fn):
            self._handlers.setdefault((operation, collection), []).append(fn)
            return fn
        return decorator

    def watches(self) -> tuple[set[str], set[str]]:
        ops = {op for op, _ in self._handlers}
        colls = {coll for _, coll in self._handlers}
        return ops, colls

    async def stop(self) -> None:
        self._stop.set()

    async def run(self) -> None:
        """Watch forever, reconnecting with backoff. Returns only when stopped
        or when the deployment cannot support change streams at all."""
        if not self._handlers:
            return

        delay = 1.0
        while not self._stop.is_set():
            try:
                await self._watch()
                delay = 1.0  # clean exit means stop was requested
            except asyncio.CancelledError:
                raise
            except _Redeliver:
                delay = 1.0
            except OperationFailure as exc:
                if exc.code == HISTORY_LOST:
                    # Retrying with this token fails identically forever. Drop it
                    # and resume from now: we lose the gap, not the reactor.
                    #
                    # Counted, not just logged. This is the one branch that
                    # loses data: every delete in the gap is a blob nobody
                    # will ever collect, and the symptom is a storage bill
                    # rather than an error. windows_lost > 0 means "go
                    # reconcile storage against the database".
                    self.windows_lost += 1
                    self.last_error = "resume token older than the oplog window"
                    log.warning("%s: resume token too old; restarting from now "
                                "(events in the gap are lost; windows_lost=%d)",
                                self.name, self.windows_lost)
                    await self._save(None)
                    delay = 1.0
                elif exc.code in UNSUPPORTED_CODES:
                    self.unsupported = True
                    self.last_error = exc.details.get("codeName", str(exc))
                    log.warning("%s: change streams unsupported on this "
                                "deployment (%s); handlers will not run",
                                self.name, exc.details.get("codeName", exc))
                    return
                else:
                    self.resumes += 1
                    self.last_error = exc.details.get("codeName", str(exc))
                    log.warning("%s interrupted (%s); resuming in %.0fs", self.name,
                                exc.details.get("codeName", exc), delay)
            except PyMongoError as exc:
                # Elections, failovers and network blips are routine on a replica
                # set; every one of them is a resume, not a failure.
                self.resumes += 1
                self.last_error = str(exc)
                log.warning("%s error (%s); resuming in %.0fs", self.name, exc, delay)
            except Exception:  # pragma: no cover - deliberately broad: this loop
                # is the only thing keeping blob GC alive, and exiting it costs
                # orphaned objects forever. Cancellation is re-raised above.
                self.resumes += 1
                log.exception("%s: unexpected error; resuming in %.0fs",
                              self.name, delay)

            try:
                await asyncio.wait_for(self._stop.wait(), timeout=delay)
            except asyncio.TimeoutError:
                pass
            delay = min(delay * 2, MAX_BACKOFF)

    async def _watch(self) -> None:
        ops, colls = self.watches()
        pipeline = [{"$match": {"operationType": {"$in": sorted(ops)},
                                "ns.coll": {"$in": sorted(colls)}}}]
        kwargs: dict = {"full_document_before_change": "whenAvailable"}
        token = await self._load()
        if token:
            kwargs["resume_after"] = token

        # PyMongo async: watch() is a coroutine returning the stream.
        async with await self.db.watch(pipeline, **kwargs) as stream:
            async for change in stream:
                if self._stop.is_set():
                    return
                ok = await self._dispatch(change)
                self.events_dispatched += 1
                token = change.get("_id")
                if ok:
                    await self._save(token)
                    self._fail_id = None
                    self._fail_n = 0
                    continue
                # At-least-once: do not checkpoint a failed handler, or the
                # event is lost. After MAX_HANDLER_TRIES skip it so a poison
                # event cannot stall the stream forever.
                if token == self._fail_id:
                    self._fail_n += 1
                else:
                    self._fail_id = token
                    self._fail_n = 1
                if self._fail_n >= MAX_HANDLER_TRIES:
                    self.events_skipped += 1
                    log.error("%s: skipping event after %d handler failures: %s",
                              self.name, self._fail_n, token)
                    await self._save(token)
                    self._fail_n = 0
                    self._fail_id = None
                else:
                    raise _Redeliver

    async def _dispatch(self, change: dict) -> bool:
        key = (change["operationType"], change.get("ns", {}).get("coll"))
        ok = True
        for handler in self._handlers.get(key, []):
            try:
                await handler(change)
            except asyncio.CancelledError:
                raise  # shutdown, not a handler failure
            except Exception:  # deliberately broad: one bad handler must
                # not break the stream for every other handler.
                log.exception("%s: handler %s failed", self.name,
                              getattr(handler, "__name__", handler))
                ok = False
        return ok

    def health(self) -> dict:
        """What a probe needs to distinguish three very different states.

        A reactor with ``resumes`` climbing is healthy: elections happen. A
        reactor with ``windows_lost > 0`` has dropped deletes on the floor and
        orphaned whatever they pointed at -- reconcile storage. A reactor with
        ``unsupported`` is running nothing at all, which otherwise looks
        exactly like a quiet database.
        """
        return {
            "name": self.name,
            "watching": sorted(f"{op}:{coll}" for op, coll in self._handlers),
            "events_dispatched": self.events_dispatched,
            "resumes": self.resumes,
            "windows_lost": self.windows_lost,
            "events_skipped": self.events_skipped,
            "unsupported": self.unsupported,
            "last_error": self.last_error,
        }

    async def _load(self):
        return await self._restore() if self._restore else None

    async def _save(self, token) -> None:
        if self._checkpoint:
            await self._checkpoint(token)
