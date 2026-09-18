"""What happens *mid-flight*, which is where this class of bug actually lives.

The suite already proves the reactor starts, dispatches, and does not
checkpoint a failed handler. Every one of those is a property of a healthy
stream. The failures that cost money are the ones that arrive after minute
forty of an otherwise fine process:

- a primary election breaks the stream (routine on a replica set),
- the process was down long enough that its resume token aged out of the
  oplog window,
- the deployment cannot do change streams at all,
- a handler is poisoned by one specific event and fails forever.

The reactor handles all four. What it did *not* do was make any of them
visible: each was a single log line, and a log line is not something you can
alert on. The three states look identical from outside the process --

    a reactor resuming after an election      -> fine, ignore
    a reactor that lost its oplog window      -> deletes went uncollected;
                                                 reconcile storage now
    a reactor on an unsupported deployment    -> nothing has ever run

-- and the last two are indistinguishable from "a quiet database" unless
somebody is reading logs at the moment it happens. So they are counted, and
they are on ``health()``, for exactly the reason search counts its fallbacks.

These drive the real ``run()`` loop with a stream that fails the way the world
fails. No MongoDB required: the failure modes are driver exceptions, and
faking the *database* would prove nothing, but faking the *election* is the
only way to have one on demand.
"""

from __future__ import annotations

import asyncio

import pytest
from pymongo.errors import AutoReconnect, OperationFailure

from voyd.engine import Reactor
from voyd.engine.reactor import HISTORY_LOST


class FakeStream:
    """One change stream attempt: yields, then does what the world did."""

    def __init__(self, events, error=None):
        self._events = list(events)
        self._error = error

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self._events:
            return self._events.pop(0)
        if self._error:
            raise self._error
        raise StopAsyncIteration


class FakeDb:
    """A database whose ``watch()`` returns a scripted sequence of attempts."""

    def __init__(self, attempts):
        self.attempts = list(attempts)
        self.watch_calls: list[dict] = []

    async def watch(self, pipeline, **kwargs):
        self.watch_calls.append(kwargs)
        if not self.attempts:
            # Nothing left to script: block so run() sits in the loop until
            # the test stops it, rather than spinning.
            return FakeStream([], error=asyncio.CancelledError())
        return self.attempts.pop(0)


def delete_event(token: str, coll: str = "documents") -> dict:
    return {"operationType": "delete", "ns": {"coll": coll}, "_id": token}


async def run_briefly(reactor, seconds: float = 0.5) -> None:
    """Run the loop, then stop it. Backoff is real, so keep scripts short."""
    task = asyncio.create_task(reactor.run())
    await asyncio.sleep(seconds)
    await reactor.stop()
    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, Exception):
        pass


def build(db, collected: list):
    r = Reactor(db, name="test-gc")

    @r.on("delete", "documents")
    async def _on_delete(change):
        collected.append(change["_id"])

    return r


# ---- an election is routine, and says so ------------------------------

async def test_an_election_mid_stream_resumes_and_is_counted():
    """The bug the module docstring describes: the first version exited here,
    and blob GC stopped for the life of the process."""
    collected: list = []
    db = FakeDb([
        FakeStream([delete_event("a")], error=AutoReconnect("primary stepped down")),
        FakeStream([delete_event("b")]),
    ])
    r = build(db, collected)

    await run_briefly(r, 1.4)

    assert "a" in collected, "the event before the election was dropped"
    assert "b" in collected, "the reactor did not resume after the election"
    assert r.resumes >= 1, "a resume happened and was not counted"
    assert r.health()["resumes"] >= 1
    assert r.windows_lost == 0, "an election is not a lost window"
    assert r.unsupported is False


async def test_a_resumed_stream_asks_to_continue_where_it_stopped():
    """Resuming from scratch would re-deliver or skip; the token is the point."""
    saved: list = []
    db = FakeDb([
        FakeStream([delete_event("a")], error=AutoReconnect("blip")),
        FakeStream([delete_event("b")]),
    ])
    r = Reactor(db, name="test-gc",
                checkpoint=lambda t: _append(saved, t),
                restore=lambda: _last(saved))

    @r.on("delete", "documents")
    async def _ok(_change):
        return None

    await run_briefly(r, 1.4)

    assert saved, "no resume token was ever checkpointed"
    # The second watch() call must carry the token from the first attempt.
    assert len(db.watch_calls) >= 2
    assert db.watch_calls[1].get("resume_after") == "a", db.watch_calls


async def _append(store: list, token) -> None:
    store.append(token)


async def _last(store: list):
    return store[-1] if store else None


# ---- a lost oplog window loses data, and must be loud -----------------

async def test_an_aged_out_resume_token_is_dropped_counted_and_restarted():
    """The one branch that loses events.

    Retrying an aged-out token fails identically forever, so the reactor drops
    it and restarts from now -- losing the gap rather than the reactor. That is
    the right trade and it is also a silent data loss: every delete in the gap
    is a blob nobody will collect. ``windows_lost`` is how an operator finds
    out without reading logs.
    """
    saved: list = ["stale-token"]
    history_lost = OperationFailure(
        "resume token too old", HISTORY_LOST,
        {"codeName": "ChangeStreamHistoryLost"})

    db = FakeDb([
        FakeStream([], error=history_lost),
        FakeStream([delete_event("after")]),
    ])
    collected: list = []
    r = Reactor(db, name="test-gc",
                checkpoint=lambda t: _append(saved, t),
                restore=lambda: _last(saved))

    @r.on("delete", "documents")
    async def _on_delete(change):
        collected.append(change["_id"])

    await run_briefly(r, 1.4)

    assert r.windows_lost == 1, "a lost oplog window was not counted"
    assert r.health()["windows_lost"] == 1
    assert "oplog" in (r.last_error or ""), r.last_error
    # The poisoned token was cleared -- that is the None in the sequence.
    # It is not the *last* entry, because the reactor then resumed and
    # checkpointed real progress again: ['stale-token', None, 'after'].
    assert None in saved, f"the aged-out token was never dropped: {saved}"
    assert saved.index(None) > saved.index("stale-token")
    # And the reactor is still alive afterwards.
    assert "after" in collected, "the reactor did not restart after the gap"


async def test_a_lost_window_is_distinguishable_from_an_election():
    """The whole point of two counters instead of one.

    An operator's response differs: an election needs nothing, a lost window
    needs a storage reconciliation. A single "errors" counter would make them
    the same alert.
    """
    election = FakeDb([FakeStream([], error=AutoReconnect("stepped down")),
                       FakeStream([])])
    lost = FakeDb([FakeStream([], error=OperationFailure(
        "too old", HISTORY_LOST, {"codeName": "ChangeStreamHistoryLost"})),
        FakeStream([])])

    a, b = build(election, []), build(lost, [])
    await run_briefly(a, 1.3)
    await run_briefly(b, 1.3)

    # The election shows up as a resume and nothing else.
    assert a.resumes >= 1 and a.windows_lost == 0, a.health()
    # The lost window shows up as a lost window. It is deliberately *not*
    # counted as a resume, so an alert on windows_lost cannot be drowned out
    # by ordinary failover noise.
    assert b.windows_lost == 1 and b.resumes == 0, b.health()


# ---- an unsupported deployment is running nothing ---------------------

@pytest.mark.parametrize("code", [40573, 148])
async def test_an_unsupported_deployment_stops_and_is_flagged(code):
    """A standalone mongod cannot do this at all.

    Retrying forever would be a busy loop against a certainty, so the reactor
    returns -- and that is the most dangerous quiet state in the system: no
    handler will ever run, and nothing else about the process looks wrong.
    """
    db = FakeDb([FakeStream([], error=OperationFailure(
        "not supported", code, {"codeName": "Location40573"}))])
    r = build(db, [])

    await asyncio.wait_for(r.run(), timeout=5)   # returns on its own

    assert r.unsupported is True
    assert r.health()["unsupported"] is True
    assert r.last_error


async def test_a_reactor_that_never_started_is_not_reported_as_healthy():
    """No handlers means run() returns immediately; health must not imply it
    is watching something."""
    r = Reactor(FakeDb([]), name="idle")
    await asyncio.wait_for(r.run(), timeout=5)
    assert r.health()["watching"] == []
    assert r.health()["events_dispatched"] == 0


# ---- a poison event must not stall the stream forever -----------------

async def test_a_permanently_failing_handler_is_skipped_and_counted():
    """At-least-once means a failed handler is retried. Retried *forever*
    means one bad event stops all collection behind it, so it is skipped
    after MAX_HANDLER_TRIES -- and the skip is counted, because a skipped
    delete is an orphaned object."""
    attempts = [FakeStream([delete_event("poison")]) for _ in range(6)]
    db = FakeDb(attempts)
    r = Reactor(db, name="test-gc")
    tries = []

    @r.on("delete", "documents")
    async def _always_fails(change):
        tries.append(change["_id"])
        raise RuntimeError("this one event can never be handled")

    # Backoff resets to 1s on a redeliver, so three tries needs ~2.1s.
    await run_briefly(r, 3.2)

    assert len(tries) >= 3, f"gave up too early: {tries}"
    assert r.events_skipped >= 1, "a poison event was never skipped"
    assert r.health()["events_skipped"] >= 1


async def test_the_engine_reports_every_reactor_it_handed_out(core):
    """``engine.reactor()`` hands the object to a caller to run, so the engine
    has to keep a reference or ``health()`` cannot see it -- and a reactor
    nobody can see is the failure mode this whole file is about."""
    engine, _ = core
    r = engine.reactor(name="gc-1")

    @r.on("delete", "documents")
    async def _noop(_change):
        return None

    reported = engine.health()["reactors"]
    assert [x["name"] for x in reported] == ["gc-1"]
    assert reported[0]["watching"] == ["delete:documents"]
    assert reported[0]["windows_lost"] == 0
    assert reported[0]["unsupported"] is False
