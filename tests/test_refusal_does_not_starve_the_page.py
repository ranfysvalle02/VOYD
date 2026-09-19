"""Refusing a hit must not silently shorten the answer.

The deadline is enforced on the way out, which means expired hits are fetched
and then dropped -- they spend part of the fetch budget. Both read paths knew
this and both bought the same insurance: fetch ``limit * 2``, admit, slice to
``limit``. That is a guess, and the docstrings said so:

    In the worst case -- more than ``limit`` of the top ``2 * limit`` hits
    expired -- recall returns fewer live memories than asked for while more
    exist further down the ranking.

Which is the failure shape this repository blocks startup to avoid, arriving
by a different road: **fewer rows rather than an error**. A caller asking for
five and getting one cannot tell "only one matched" from "twenty-four of the
top twenty-five were forgotten and nobody went back for more". Refusal is
supposed to cost the *forgotten* document its place, not the page.

So the fetch budget is no longer a constant. ``Admission.saturate()`` refills
until the page is full or the candidates are genuinely exhausted, and when it
cannot fill the page it says so -- ``page.starved`` -- rather than returning a
short list as if it were the whole truth.
"""

from __future__ import annotations

import random
from datetime import timedelta

import pytest

from voyd.engine import now
from voyd.engine.admission import Admission, AdmissionSpec

DIMS = 8
SCOPE = "sess-starve"
LIVE = 6
DOOMED = 40


def vec(seed: int) -> list[float]:
    random.seed(seed)
    return [random.random() for _ in range(DIMS)]


# --------------------------------------------------------------------------
# the refill loop itself. no database: this is arithmetic and honesty.
# --------------------------------------------------------------------------

async def _page(docs, *, limit, rounds=4):
    """Saturate over a fixed candidate list, recording what was asked for."""
    asked: list[int] = []

    async def fetch(n: int) -> list[dict]:
        asked.append(n)
        return docs[:n]

    handle = Admission(None, AdmissionSpec("notes"))
    page = await handle.saturate(fetch, limit=limit, rounds=rounds)
    return page, asked


def _doc(i: int, *, expired=False):
    d = {"_id": i, "expire_at": None}
    if expired:
        d["expire_at"] = now() - timedelta(minutes=5)
    return d


async def test_a_page_of_refusals_is_refilled_not_truncated():
    """24 forgotten facts ahead of 5 live ones still yields 5."""
    docs = [_doc(i, expired=True) for i in range(24)] + \
           [_doc(100 + i) for i in range(5)]

    page, asked = await _page(docs, limit=5)

    assert len(page) == 5, (
        f"asked for 5, got {len(page)} -- refusal shortened the page instead "
        f"of costing the refused documents their place (fetches: {asked})")
    assert not page.starved
    assert page.refused == {"deadline": 24}
    assert asked[0] == 10, "the first fetch is still the cheap one"
    assert len(asked) > 1, "and it went back for more"


async def test_a_short_page_over_exhausted_candidates_is_not_starved():
    """Short is not the same as incomplete, and conflating them costs the flag.

    One live document exists and five were asked for. The page is short and
    it is also the *whole truth* -- there is nothing further down the ranking
    being withheld, however many refusals it took to establish that. This
    was the first definition of ``starved`` and it was wrong: a check
    flagged exactly this shape on a healthy deployment, and a warning that
    fires when nothing is wrong is a warning people learn to ignore.
    """
    docs = [_doc(i, expired=True) for i in range(8)] + [_doc(100)]

    page, asked = await _page(docs, limit=5)

    assert len(page) == 1
    assert page.refused == {"deadline": 8}, "the cost is still reported"
    assert not page.starved, (
        "a complete answer was flagged as partial; starvation means "
        "candidates remained, not merely that the page is short")
    # The candidate list is 9 long, so a fetch for more than 9 comes back
    # short -- proof there is nothing further down, and the loop must stop.
    assert asked[-1] > len(docs)


async def test_a_full_page_costs_exactly_one_fetch():
    """The refill is insurance, not a tax: nothing refused, nothing re-asked."""
    page, asked = await _page([_doc(i) for i in range(20)], limit=5)

    assert len(page) == 5
    assert asked == [10], f"a clean page must not re-query: {asked}"
    assert not page.refused


async def test_the_refill_is_bounded():
    """A collection where everything is forgotten must not query forever."""
    page, asked = await _page([_doc(i, expired=True) for i in range(5_000)],
                              limit=5, rounds=3)

    assert len(page) == 0
    assert page.starved, (
        "the loop gave up with candidates still unexamined, which is the one "
        "case where the caller was told less than the truth")
    assert len(asked) == 3, f"rounds must cap the work: {asked}"
    assert asked == sorted(asked), "and each round must ask for more, not less"


async def test_a_page_is_a_list_so_no_caller_has_to_know_about_this():
    """``Page`` carries the metadata and still *is* the list of hits.

    Every existing caller compares it to ``[]``, iterates it, or slices it.
    A guarantee that forces a return-type migration on its own read paths is
    a guarantee that gets reverted.
    """
    page, _ = await _page([_doc(1), _doc(2)], limit=5)

    assert isinstance(page, list)
    assert page == [{"_id": 1, "expire_at": None},
                    {"_id": 2, "expire_at": None}]
    assert [d["_id"] for d in page] == [1, 2]


async def test_an_empty_page_reports_why_it_is_empty():
    """Nothing found and everything refused are different facts.

    This is the one a model needs, and the distinction is carried by
    ``refused`` rather than by ``starved``: an agent told "three facts
    matched and are being withheld" asks a human, while an agent handed an
    empty list invents an answer. Both pages below are complete -- neither is
    starved -- and they are not the same answer.
    """
    empty, _ = await _page([], limit=5)
    assert empty.refused == {}
    assert not empty.starved

    refused, _ = await _page([_doc(i, expired=True) for i in range(3)], limit=5)
    assert refused.refused == {"deadline": 3}, (
        "an empty result that is empty *because of refusal* must say so, or "
        "the caller reports an empty scope")
    assert not refused.starved, "the candidates were exhausted; this is complete"


# --------------------------------------------------------------------------
# and the same property through the real search path
# --------------------------------------------------------------------------

async def test_recall_refills_against_a_real_index(core):
    """The property that matters, through mongot rather than a fake fetch."""
    engine, db = core
    mem = engine.model("memories", tenant="scope").memory(
        default_ttl=timedelta(hours=1), dimensions=DIMS)
    await engine.ensure(search_wait_s=60)

    # Enough doomed rows to swamp any fixed multiple of the limit.
    for i in range(DOOMED):
        await mem.remember(SCOPE, f"doomed {i}", vec(1))
    for i in range(LIVE):
        await mem.remember(SCOPE, f"live {i}", vec(1), pinned=True)

    await _wait_indexed(mem, DOOMED + LIVE)

    await db.memories.update_many(
        {"text": {"$regex": "^doomed"}},
        {"$set": {"expire_at": now() - timedelta(minutes=5)}})

    # Still on disk, every one of them: the reaper is uninvolved.
    assert await db.memories.count_documents({}) == DOOMED + LIVE

    hits = await mem.recall(SCOPE, vec(1), limit=5)
    assert len(hits) == 5, (
        f"{DOOMED} forgotten rows outranked the live ones and the page came "
        f"back with {len(hits)} of 5")
    assert all(h["text"].startswith("live") for h in hits)


async def _wait_indexed(mem, n: int):
    import asyncio
    loop = asyncio.get_running_loop()
    deadline = loop.time() + 60
    while loop.time() < deadline:
        if len(await mem.recall(SCOPE, vec(1), limit=100)) >= n:
            return
        await asyncio.sleep(0.5)
    pytest.fail(f"mongot did not index {n} memories within 60s")
