"""A token budget is a refusal reason, which is the point of the protocol.

`Rule` answers *may this reach a prompt?* Erasure is one answer; a context
budget is another -- ``over_budget``, once the room is gone. If the rule
protocol only ever held compliance reasons it would be a compliance feature
with extra indirection; a reason with nothing to do with erasure, expressed in
the same shape, is the evidence it is a primitive.

``Budget`` is also the first *cumulative* rule: it charges a ``Tab`` scoped to
one read, so it forces two things this file pins down --

1. cumulative rules are asked **last**, so a budget never charges a document a
   deadline was going to refuse anyway (``test_budget_first_...``); and
2. a page cut short by a spent budget is **complete, not starved**, and does
   not trigger the refill loop (``test_a_spent_budget_...``).

Most of these need no database: ``saturate`` takes a ``fetch`` callable, so a
fixed candidate list in ranking order is enough to exercise the arithmetic.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from voyd.engine import now
from voyd.engine.admission import (Admission, AdmissionSpec, Budget, Deadline,
                                   OVER_BUDGET, UNCOSTED)


def _doc(i: int, tokens) -> dict:
    return {"_id": i, "tokens": tokens}


async def _saturate(rules, docs, *, limit, rounds=4):
    """Saturate over a fixed candidate list, recording what was asked for."""
    asked: list[int] = []

    async def fetch(n: int) -> list[dict]:
        asked.append(n)
        return docs[:n]

    handle = Admission(None, AdmissionSpec("notes", rules=tuple(rules)))
    page = await handle.saturate(fetch, limit=limit, rounds=rounds)
    return page, asked


# ---- the Tab, as arithmetic --------------------------------------------

def test_the_tab_is_all_or_nothing_and_latches():
    """A cost that does not fit is not partially spent, and the tab stays
    closed afterwards -- the strict prefix lives here."""
    from voyd.engine.admission.rules import Tab

    tab = Tab(limit=100)
    assert tab.charge(60) is True and tab.spent == 60
    assert tab.charge(60) is False, "120 does not fit in 100"
    assert tab.exhausted is True
    assert tab.spent == 60, "the overflowing charge is not partially spent"
    assert tab.charge(1) is False, "and the tab stays closed for a later fit"


@pytest.mark.parametrize("cost", [-1, 1.5, True])
def test_the_tab_itself_rejects_ambiguous_costs(cost):
    """Tab is extension-point vocabulary, not only Budget's implementation,
    so it defends the integer contract even when a third-party rule charges
    it directly."""
    from voyd.engine.admission.rules import Tab

    with pytest.raises(ValueError):
        Tab(limit=10).charge(cost)


# ---- the reason, on a page ---------------------------------------------

async def test_hits_are_refused_once_the_budget_is_spent():
    """Two 40-token hits fit in 100; the first overflow closes the prefix."""
    docs = [_doc(i, 40) for i in range(10)]
    page, asked = await _saturate([Budget(limit=100)], docs, limit=5)

    assert [d["_id"] for d in page] == [0, 1]
    assert page.spent == 80
    assert page.refused == {OVER_BUDGET: 8}, (
        "the first overflow closed the strict prefix; every lower-ranked "
        "candidate fetched for this page was withheld without being charged")


async def test_a_spent_budget_is_complete_not_starved_and_does_not_refill():
    """The failure this rule must not reintroduce.

    Two of ten candidates fit the budget, so the page is short of the five
    asked for. Without the budget being a first-class stop, ``saturate`` would
    read "short, candidates remain" and refill -- fetching lower-ranked hits
    the budget has no room for, round after round, then flag ``starved``. A
    budget-complete page is neither partial nor worth retrying.
    """
    docs = [_doc(i, 40) for i in range(10)]
    page, asked = await _saturate([Budget(limit=100)], docs, limit=5)

    assert len(page) == 2 and not page.starved
    assert asked == [10], f"a budget-complete page must not refill: {asked}"


async def test_a_cheap_hit_after_an_over_budget_one_is_not_slipped_in():
    """Strict prefix: admitting a smaller later hit would reorder by size.

    The first document costs more than the whole budget. It is refused, the
    prefix closes, and the two tiny hits behind it -- which would each fit --
    are refused too. The budget cuts the ranking at a point; it does not
    repack it by size, which would be the silent reordering ``search.py``
    warns about.
    """
    docs = [_doc(0, 120), _doc(1, 5), _doc(2, 5)]
    page, _ = await _saturate([Budget(limit=100)], docs, limit=5)

    assert len(page) == 0
    assert page.spent == 0, "the overflowing document was not partially charged"
    assert page.refused == {OVER_BUDGET: 3}
    assert not page.starved


async def test_overfetch_below_a_full_page_does_not_spend_prompt_budget():
    """Search asks for ``limit * 2`` as refill insurance. The five returned
    hits cost 50; the five extra candidates fetched beneath them cost zero.

    Charging all ten would make a database optimisation consume context the
    prompt never sees -- a plausible number and the wrong contract.
    """
    docs = [_doc(i, 10) for i in range(20)]
    page, asked = await _saturate([Budget(limit=100)], docs, limit=5)

    assert [d["_id"] for d in page] == [0, 1, 2, 3, 4]
    assert asked == [10], "the query still over-fetched once"
    assert page.examined == 10, "examined is the database fetch cost"
    assert page.spent == 50, "spent is the prompt prefix, not the fetched tail"
    assert page.refused == {}


async def test_an_unreadable_cost_fails_closed_as_uncosted():
    """A missing or non-numeric cost refuses, but does not close the page.

    ``uncosted`` fails closed like an unreadable deadline -- a hit whose size
    cannot be established has no business silently taking room -- but one
    uncostable document says nothing about the budget, so admission continues.
    """
    docs = [{"_id": 0},                        # no tokens field
            {"_id": 1, "tokens": "lots"},      # not a number
            _doc(2, 10), _doc(3, 10)]
    page, _ = await _saturate([Budget(limit=100)], docs, limit=5)

    assert [d["_id"] for d in page] == [2, 3], "costable hits still admitted"
    assert page.spent == 20
    assert page.refused == {UNCOSTED: 2}
    assert not page.starved


async def test_budget_first_does_not_charge_what_a_deadline_refuses():
    """Cumulative rules are asked last, whatever the declared order.

    ``Budget`` is declared *before* ``Deadline`` here, and the three expired
    documents cost 1000 tokens each -- enough to blow a 100-token budget on
    the first one if it were charged. It is not: a deadline refuses them
    before the budget sees them, so the three live 30-token hits all fit.
    Spending exactly 90 is the proof the expired rows never touched the tab.
    """
    expired = [{"_id": i, "tokens": 1000,
                "expire_at": now() - timedelta(minutes=5)} for i in range(3)]
    live = [_doc(100 + i, 30) for i in range(3)]

    page, _ = await _saturate([Budget(limit=100), Deadline()],
                              expired + live, limit=5)

    assert [d["_id"] for d in page] == [100, 101, 102]
    assert page.spent == 90
    assert page.refused == {"deadline": 3}


async def test_reason_precedence_is_the_same_after_budget_exhaustion():
    """The fetched tail still runs pure rules first. Saturate must not call an
    expired row over_budget merely because an earlier row closed the prefix."""
    docs = [
        _doc(0, 120),  # closes the budget
        {"_id": 1, "tokens": 5,
         "expire_at": now() - timedelta(minutes=5)},
        _doc(2, 5),
    ]
    page, _ = await _saturate(
        [Budget(limit=100), Deadline()], docs, limit=5)

    assert page == []
    assert page.refused == {OVER_BUDGET: 2, "deadline": 1}


# ---- the two halves, and where a budget does not apply ------------------

async def test_the_budget_has_no_query_half_but_find_still_enforces_it(core):
    """``clause()`` is None -- a running total is not a query -- so ``find``
    cannot prune server-side and must refuse per document instead. All three
    rows pass the (budget-free) query; the egress check keeps only what fits.
    """
    assert Budget(limit=100).clause() is None

    engine, db = core
    docs = engine.model("notes").admitting(Deadline(), Budget(limit=100))
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_many([{"tokens": 40}, {"tokens": 40}, {"tokens": 40}])

    got = await docs.find({}, sort=("_id", 1))
    assert len(got) == 2, "two 40-token rows fit in 100; the third is over"
    assert await db.notes.count_documents({}) == 3, "and all three are on disk"


async def test_find_limit_applies_after_refusal(core):
    """The limit is on the answer, not raw candidates. An uncosted first row
    must not hide the fitting row behind it."""
    engine, db = core
    docs = engine.model("notes").admitting(Budget(limit=100))
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_many([
        {"order": 1},                       # uncosted: refused, prefix stays open
        {"order": 2, "tokens": 40},
    ])

    got = await docs.find({}, sort=("order", 1), limit=1)
    assert [d["order"] for d in got] == [2]


async def test_find_one_is_still_prompt_content_and_gets_a_budget(core):
    engine, db = core
    docs = engine.model("notes").admitting(Budget(limit=1))
    await engine.ensure(search_wait_s=0)
    row = (await db.notes.insert_one({"tokens": 1000})).inserted_id

    assert await docs.find_one({"_id": row}) is None
    assert await docs.exists({"_id": row}) is True, (
        "exists is a policy/cardinality question, not a content page")


async def test_a_caller_supplied_cost_function_is_honoured(core):
    """The cost is the caller's to define; the default field is a convenience."""
    engine, db = core
    docs = engine.model("notes").admitting(
        Budget(limit=10, cost=lambda d: len(d["text"])))
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_many([{"text": "hello"}, {"text": "world"},
                                {"text": "again"}])

    got = await docs.find({}, sort=("_id", 1))
    assert len(got) == 2, "two 5-char strings fit in 10; the third is over"


@pytest.mark.parametrize("limit, error", [
    (-1, ValueError),
    (1.5, TypeError),
    (True, TypeError),
])
def test_an_invalid_limit_fails_at_construction(limit, error):
    """Configuration errors are cheap before the first read and dangerous
    inside one: a negative or lossy limit must not turn every result into a
    plausible empty page."""
    with pytest.raises(error):
        Budget(limit=limit)


def test_the_constructor_cannot_disable_cumulative_enforcement():
    """Protocol markers are class contracts, not caller-controlled fields.
    Otherwise ``Budget(1, needs_tab=False)`` quietly opens the gate."""
    with pytest.raises(TypeError):
        Budget(limit=1, needs_tab=False)


@pytest.mark.parametrize("cost", [True, 1.5, "2", -1, None])
async def test_a_non_integer_cost_fails_closed_as_uncosted(cost):
    """No ``int(...)`` coercion: truncating 1.9 to 1 or accepting ``True`` as
    one token would let a prompt exceed its budget while receipts looked exact."""
    page, _ = await _saturate([Budget(limit=10)], [_doc(1, cost)], limit=1)
    assert page == []
    assert page.refused == {UNCOSTED: 1}
    assert page.spent == 0


async def test_a_cost_callable_that_raises_fails_closed_as_uncosted():
    """Third-party costing is an extension point, so its exception must not
    become ``over_budget`` (a lie) or open the gate. It is an uncosted hit."""
    def broken(_doc):
        raise RuntimeError("tokenizer offline")

    page, _ = await _saturate(
        [Budget(limit=10, cost=broken)], [{"_id": 1}], limit=1)
    assert page == []
    assert page.refused == {UNCOSTED: 1}
    assert page.spent == 0


async def test_two_cumulative_rules_each_keep_their_own_running_total():
    """Two limits, two tabs, and the tighter one decides -- which is what a
    caller who declared both meant.

    This test used to assert the opposite: declaring two cumulative rules was
    a construction error, because there was one ``Tab`` per read and the
    first rule's limit would silently govern the second. That was an honest
    response to a real hazard and the wrong fix for it -- the hazard was
    *shared* state, not *several* rules, and refusing the declaration meant a
    token budget and a de-duplicator could never appear on one handle even
    though they have nothing to say to each other.

    ``Tabs`` keys state by ``id(rule)``, so the sharing is gone and the
    restriction with it. Two equal-but-distinct ``Budget`` objects are the
    sharpest case: they compare equal as frozen dataclasses, so anything
    keyed by value would merge them back into the bug.
    """
    tight, loose = Budget(limit=10), Budget(limit=1000)
    docs = [{"_id": 1, "tokens": 8}, {"_id": 2, "tokens": 8}]

    page, _ = await _saturate([loose, tight], docs, limit=2)
    # 8 fits in both. 16 fits in `loose` and not in `tight`, so the tighter
    # limit closes the page -- and it could only do that with its own total.
    assert [d["_id"] for d in page] == [1]
    assert page.refused == {OVER_BUDGET: 1}


def test_a_cumulative_rule_must_still_bring_its_own_state():
    """Lifting the two-rule restriction did not lift this one: `needs_tab`
    without `new_tab()` is still a boot error, because the rule would be
    handed ``None`` and quietly stop enforcing."""
    class Broken:
        reason = "broken_cumulative"
        needs_tab = True

        def refuses(self, doc, **kw):
            return False

        def clause(self):
            return None

    with pytest.raises(TypeError, match="new_tab"):
        Admission(None, AdmissionSpec("notes", rules=(Broken(),)))


def test_a_cumulative_rule_without_a_tab_factory_is_refused_at_construction():
    """Declaring needs_tab without a way to make per-read state is a boot
    error, not a rule that silently receives None and stops enforcing."""
    class Broken:
        reason = "broken_cumulative"
        needs_tab = True

        def refuses(self, doc, *, when=None, tab=None):
            return False

        def clause(self):
            return None

    with pytest.raises(TypeError, match="new_tab"):
        Admission(None, AdmissionSpec("notes", rules=(Broken(),)))


def test_budget_and_sealing_fail_loudly_until_ordering_is_supported():
    """Decrypting can refuse after selection; Budget must not call ciphertext
    'spent prompt tokens'. The unsupported composition fails at construction
    rather than publishing false Page.spent precision."""
    docs = Admission(None, AdmissionSpec(
        "notes", rules=(Budget(limit=10),)))
    with pytest.raises(ValueError, match="decryption must happen before"):
        docs.sealed_by(object())


async def test_count_is_policy_reachable_not_budgeted(core):
    """A count has no ranking or page, so a cumulative budget is undefined.
    It reports documents eligible for consideration; the ordered read says
    how many fit."""
    engine, db = core
    docs = engine.model("notes").admitting(Budget(limit=100))
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_many([{"tokens": 40}, {"tokens": 40}, {"tokens": 40}])

    assert await docs.count({}) == 3
    assert len(await docs.find({}, sort=("_id", 1))) == 2


async def test_reachability_at_cannot_report_over_budget(core):
    """A budget is a property of a page, not of a fact.

    ``reachability_at`` asks the rules with no tab, so ``Budget`` -- which has
    nothing to say without a running total -- returns None. A document larger
    than the entire budget is still *reachable*: whether it fits a prompt is a
    question about a read, not about the document.
    """
    engine, db = core
    docs = engine.model("notes").admitting(Deadline(), Budget(limit=1))
    await engine.ensure(search_wait_s=0)
    r = await db.notes.insert_one({"tokens": 1000})

    verdict, _ = await docs.reachability_at({"_id": r.inserted_id}, when=now())
    assert verdict == "reachable"


async def test_a_budget_read_ignores_it_under_break_glass(core):
    """``including_refused()`` is not assembling a prompt, so the budget --
    which is bypassable -- does not apply, and every row comes back."""
    engine, db = core
    docs = engine.model("notes").admitting(Budget(limit=1))
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_many([{"tokens": 1000}, {"tokens": 1000}])

    assert len(await docs.find({}, sort=("_id", 1))) == 0, \
        "both are over a budget of 1"
    assert len(await docs.including_refused().find({})) == 2, "audit sees all"


async def test_budgeted_find_requires_a_deterministic_prefix(core):
    """MongoDB natural order is not a policy. A strict-prefix budget over an
    unstable cursor would admit different facts after compaction or failover."""
    engine, db = core
    docs = engine.model("notes").admitting(Budget(limit=100))
    await engine.ensure(search_wait_s=0)
    await db.notes.insert_one({"tokens": 40})

    with pytest.raises(ValueError, match="deterministic find order"):
        await docs.find({})
