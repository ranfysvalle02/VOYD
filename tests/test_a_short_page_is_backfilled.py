"""`limit: 10` means ten admissible neighbours, not ten minus the dead.

The egress check drops refused hits from a `$vectorSearch` batch, and it
is the guarantee -- so without anything else a collection whose nearest
rows are mostly expired answers a page of ten with two. The proxy asks the
index for more and cuts the reply back to the client's `limit` *after* the
check, which is what these tests hold it to:

    it fills          refused rows are replaced from further down the ranking
    it cannot widen   the cut only removes; nothing refused comes back, and
                      no page is ever longer than the client asked for
    it keeps order    the server's score order survives, as a prefix
    it is bounded     the factor is a policy knob, capped, and 1 is off
    it knows its lane any stage after `$vectorSearch` leaves the query alone

Pure: no cluster, no driver, no network.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from voyd.declare import OPTIONS, REGISTRY, TRANSFORMS, guard, deadline, revocable
from voyd.engine.admission import AdmissionSpec, Deadline, revoked
from voyd.wire.codec import decode_op_msg, encode_op_msg
from voyd.wire.policy import Backfill, Guard, enforce
from voyd.wire.policy.backfill import CEILING, overfetch

UTC = timezone.utc
PAST = datetime.now(UTC) - timedelta(hours=1)
FUTURE = datetime.now(UTC) + timedelta(days=1)


def notes(backfill: int = 4, transforms=()) -> dict[str, Guard]:
    spec = AdmissionSpec("notes", rules=(Deadline("expire_at"),
                                         revoked("forgotten")),
                         transforms=tuple(transforms))
    return {"notes": Guard(spec, backfill=backfill)}


def search(limit=10, candidates=100, *rest, **extra) -> dict:
    stage = {"index": "v", "path": "embedding", "queryVector": [0.1, 0.2],
             "limit": limit, **extra}
    if candidates is not None:
        stage["numCandidates"] = candidates
    return {"aggregate": "notes", "$db": "app",
            "pipeline": [{"$vectorSearch": stage}, *rest], "cursor": {}}


def hits(n: int, dead: set[int]) -> list[dict]:
    """``n`` hits in score order; the ones in ``dead`` are expired."""
    return [{"_id": i, "score": 1 - i / 1000,
             "expire_at": PAST if i in dead else FUTURE} for i in range(n)]


def reply(docs, cursor_id=0, first=True, resp_to=1) -> bytes:
    key = "firstBatch" if first else "nextBatch"
    return encode_op_msg(9, resp_to, 0, {
        "cursor": {"id": cursor_id, "ns": "app.notes", key: docs}, "ok": 1.0})


def ids(raw: bytes) -> list:
    decoded = decode_op_msg(raw)
    assert decoded is not None
    cursor = decoded[1]["cursor"]
    return [d["_id"] for d in cursor.get("firstBatch", cursor.get("nextBatch"))]


def through(guards, page: Backfill, raw: bytes, resp_to=1) -> list:
    """The reply path: the check, then the cut -- in that order."""
    judged = enforce(raw, 9, resp_to, guards, verbose=False)
    return ids(page.settle(judged, 9, resp_to))


# ---- it fills ----------------------------------------------------------

def test_eight_refused_of_ten_still_returns_ten():
    guards = notes()
    page = Backfill()
    widened = page.widen(search(limit=10), guards, req_id=1)
    assert widened is not None
    stage = widened["pipeline"][0]["$vectorSearch"]
    assert stage["limit"] == 40 and stage["numCandidates"] == 400

    served = through(guards, page, reply(hits(40, dead=set(range(8)))))
    assert served == list(range(8, 18))


def test_without_backfill_the_same_page_comes_back_with_two():
    guards = notes(backfill=1)
    assert Backfill().widen(search(limit=10), guards, req_id=1) is None
    judged = enforce(reply(hits(10, dead=set(range(8)))), 9, 1, guards, False)
    assert ids(judged) == [8, 9]


def test_a_page_the_widened_fetch_cannot_fill_is_short_and_says_nothing_else():
    # Bounded means bounded: thirty-five of forty refused leaves five.
    guards = notes()
    page = Backfill()
    page.widen(search(limit=10), guards, req_id=1)
    assert through(guards, page,
                   reply(hits(40, dead=set(range(35))))) == [35, 36, 37, 38, 39]


# ---- it cannot widen ---------------------------------------------------

def test_nothing_refused_is_served_and_no_page_is_longer_than_asked():
    guards = notes()
    page = Backfill()
    page.widen(search(limit=3), guards, req_id=1)
    dead = {1, 4, 5}
    served = through(guards, page, reply(hits(12, dead)))
    assert served == [0, 2, 3]
    assert not set(served) & dead


def test_a_transform_that_puts_the_refused_rows_back_still_cannot_widen():
    # The cut runs on the output of the terminal check, which runs after
    # the transform. A transform handed forty candidates is still not a
    # way to put an expired one on the wire.
    everything = hits(40, dead=set(range(0, 40, 2)))

    class Exfiltrate:
        name = "exfiltrate"

        def on_egress(self, docs, *, request):
            return list(everything)

    guards = notes(transforms=(Exfiltrate(),))
    page = Backfill()
    page.widen(search(limit=10), guards, req_id=1)
    served = through(guards, page, reply(everything))
    assert served == list(range(1, 20, 2))


def test_a_reply_nobody_widened_is_never_cut():
    guards = notes()
    raw = enforce(reply(hits(50, dead=set())), 9, 1, guards, False)
    assert Backfill().settle(raw, 9, 1) is raw


# ---- it keeps order, across batches -------------------------------------

def test_a_small_batch_size_gets_the_same_page_over_get_more():
    guards = notes()
    page = Backfill()
    page.widen(search(limit=5), guards, req_id=1)
    dead = {0, 2, 3}
    first = through(guards, page, reply(hits(4, dead), cursor_id=77))
    page.continuing(77, req_id=2)
    rest = [{"_id": i, "expire_at": PAST if i in dead else FUTURE}
            for i in range(4, 12)]
    second = through(guards, page, reply(rest, cursor_id=77, first=False,
                                         resp_to=2), resp_to=2)
    assert first + second == [1, 4, 5, 6, 7]
    # And once the page is full, a further `getMore` hands back nothing.
    page.continuing(77, req_id=3)
    tail = [{"_id": 99, "expire_at": FUTURE}]
    assert through(guards, page, reply(tail, cursor_id=0, first=False,
                                       resp_to=3), resp_to=3) == []


def test_a_killed_cursor_is_forgotten():
    guards = notes()
    page = Backfill()
    page.widen(search(limit=5), guards, req_id=1)
    through(guards, page, reply(hits(2, set()), cursor_id=77))
    page.forget([77])
    page.continuing(77, req_id=2)
    raw = reply(hits(9, set()), cursor_id=0, first=False, resp_to=2)
    assert page.settle(raw, 9, 2) is raw


# ---- it is bounded -----------------------------------------------------

def test_the_widened_search_never_exceeds_what_atlas_accepts():
    made = overfetch(search(limit=3000, candidates=9000), notes())
    assert made is not None
    stage = made[0]["pipeline"][0]["$vectorSearch"]
    assert stage["limit"] == CEILING and stage["numCandidates"] == CEILING
    assert made[1] == 3000
    assert overfetch(search(limit=CEILING, candidates=CEILING), notes()) is None


def test_an_exact_search_is_widened_without_inventing_candidates():
    made = overfetch(search(limit=5, candidates=None, exact=True), notes())
    assert made is not None
    stage = made[0]["pipeline"][0]["$vectorSearch"]
    assert stage["limit"] == 20 and "numCandidates" not in stage


@pytest.mark.parametrize("body", [
    search(limit=True),
    search(limit=0),
    search(limit="10"),
    search(candidates=None),
    {"aggregate": "elsewhere", "pipeline": search()["pipeline"]},
    {"find": "notes", "filter": {}},
])
def test_a_shape_it_does_not_understand_goes_out_as_sent(body):
    assert overfetch(body, notes()) is None


@pytest.fixture
def _clean_registry():
    for table in (REGISTRY, OPTIONS, TRANSFORMS):
        table.clear()
    yield
    for table in (REGISTRY, OPTIONS, TRANSFORMS):
        table.clear()


@pytest.mark.usefixtures("_clean_registry")
def test_the_factor_is_declared_in_the_policy_file_and_checked_at_load():
    @guard("notes", backfill=8)
    class Notes:
        expire_at = deadline()
        forgotten = revocable()

    assert OPTIONS["notes"]["backfill"] == 8
    for bad in (0, 21, 2.5, True):
        with pytest.raises(ValueError, match="backfill"):
            guard("notes", backfill=bad)


# ---- it knows its lane -------------------------------------------------

@pytest.mark.parametrize("after", [
    {"$match": {"kind": "memo"}},
    {"$sort": {"created": -1}},
    {"$skip": 5},
    {"$limit": 3},
    {"$sample": {"size": 2}},
    {"$group": {"_id": "$kind", "n": {"$sum": 1}}},
    {"$project": {"score": {"$meta": "vectorSearchScore"}}},
])
def test_a_stage_after_the_search_leaves_the_query_alone(after):
    # Every one of these means something different over forty candidates
    # than over ten, so over-fetching would change the answer rather than
    # fill it.
    assert overfetch(search(10, 100, after), notes()) is None
