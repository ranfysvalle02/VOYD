"""`AHA.md` step 5 calls set-relative rules a category. Two members is thin.

The step 5 argument is the one that closes the whole thesis: a rule that
refuses a document because of the *other* documents on the page cannot be an
index filter and cannot be a policy rule, so egress is not the safer of two
enforcement points but the only one where every reason can live. Its evidence
was `Budget` and `Distinct` -- both shipped by this package, both written by
the same person who wrote the argument.

That is a category asserted from two examples it chose. This file supplies
three more, written the way a stranger writes them: against the public
protocol, in `examples/portfolio.py`, with **nothing added to `voyd`** -- a
provenance quota, a per-source ceiling, and a mixed-tier cost budget. If they
work, the category is real and step 5 is not resting on the two rules that
happen to be in the box.

The load-bearing assertion is the last one. A rule is set-relative exactly
when the same document gets two answers depending on its company, and that is
the property `$vectorSearch` and `enforce(subject, object, action)` cannot
produce -- one decides each candidate before the page exists, the other is a
pure function of a pair.
"""

from __future__ import annotations

import pytest

import voyd.engine as engine_module
from examples.portfolio import AtMostPerSource, ProvenanceQuota, TieredCost

CORPUS = [
    {"_id": 0, "text": "a", "verified": True,  "publisher": "acme",   "tier": "standard"},
    {"_id": 1, "text": "b", "verified": True,  "publisher": "acme",   "tier": "standard"},
    {"_id": 2, "text": "c", "verified": True,  "publisher": "acme",   "tier": "standard"},
    {"_id": 3, "text": "d", "verified": False, "publisher": "forum",  "tier": "standard"},
    {"_id": 4, "text": "e", "verified": False, "publisher": "forum",  "tier": "standard"},
    {"_id": 5, "text": "f", "verified": True,  "publisher": "vendor", "tier": "premium"},
    {"_id": 6, "text": "g", "verified": True,  "publisher": "vendor", "tier": "premium"},
]


def _admit(core, rules, docs, collection):
    engine, _ = core
    handle = engine.model(collection).admitting(*rules)
    return handle, handle.reachable([dict(d) for d in docs])


def test_a_provenance_quota_caps_what_the_page_may_be_made_of(core):
    """The question a compliance team asks and no retrieval stack answers:
    how much of what you showed the model came from something we trust?

    Unanswerable per document -- one unverified note is fine in a page of ten
    and is the whole story in a page of one.
    """
    handle, page = _admit(core, [ProvenanceQuota(share=0.3)], CORPUS, "quota")
    unverified = [d for d in page if not d["verified"]]
    assert len(unverified) / len(page) <= 0.3
    assert handle.receipts()["refused_by_reason"] == {"over_unverified_quota": 1}


def test_a_per_source_ceiling_refuses_the_third_document_from_one_publisher(core):
    """Ten hits from one publisher is what a ranker produces when that
    publisher writes well and often, and it reads to a model as ten
    independent corroborations of one house view."""
    handle, page = _admit(core, [AtMostPerSource(cap=2)], CORPUS, "sources")
    counts: dict[str, int] = {}
    for d in page:
        counts[d["publisher"]] = counts.get(d["publisher"], 0) + 1
    assert max(counts.values()) <= 2
    assert handle.receipts()["refused_by_reason"] == {"source_over_represented": 1}


def test_one_budget_can_price_two_tiers_differently(core):
    """Two budgets give you a page that satisfies both and blows the one that
    matters. A single tab with a per-tier price is the constraint people
    actually mean."""
    handle, page = _admit(core, [TieredCost(limit=100)], CORPUS, "tiers")
    spend = sum(40 if d["tier"] == "premium" else 10 for d in page)
    assert spend <= 100
    assert handle.receipts()["refused_by_reason"] == {"over_tiered_budget": 1}


def test_three_third_party_set_relative_rules_compose_on_one_handle(core):
    """Each keeps its own per-read memory and reports its own reason.

    Composition is the part that makes this a category rather than three
    special cases: nothing here coordinates them, and `Tabs` hands each rule
    state by identity precisely so a quota's ratio never touches a budget's
    running total.
    """
    handle, page = _admit(
        core, [ProvenanceQuota(share=0.3), AtMostPerSource(cap=2),
               TieredCost(limit=100)], CORPUS, "composed")
    assert set(handle.receipts()["refused_by_reason"]) == {
        "over_unverified_quota", "source_over_represented", "over_tiered_budget"}
    assert 0 < len(page) < len(CORPUS), "a rule that refuses everything proves nothing"


def test_the_same_document_is_admitted_alone_and_refused_in_company(core):
    """The definition of the category, as an assertion.

    This is the shape no index filter can produce and no policy engine can
    express. `$vectorSearch` decides each candidate before the page exists;
    `enforce(subject, object, action)` is a pure function of a pair, so for a
    fixed pair it returns one answer forever. Here the answer for document 2
    depends on whether documents 0 and 1 came with it.
    """
    third = [d for d in CORPUS if d["_id"] == 2]
    _, alone = _admit(core, [AtMostPerSource(cap=2)], third, "alone")
    _, crowd = _admit(core, [AtMostPerSource(cap=2)], CORPUS, "crowd")

    assert len(alone) == 1, "admitted on its own"
    assert 2 not in {d["_id"] for d in crowd}, "refused in company"


@pytest.mark.parametrize("rule", [ProvenanceQuota, AtMostPerSource, TieredCost],
                         ids=lambda r: r.__name__)
def test_none_of_this_needed_a_line_added_to_the_package(rule):
    """The freeze in `docs/STATE.md` is the reason this file is shaped this way.

    The identity is the handle, and nothing gets built until a stranger keeps
    it. A demonstration that costs a module would be the thing the freeze
    forbids; one that costs an example, a test and a paragraph is the
    precedent the policy compiler set. So the rules live in `examples/`, and
    this asserts they stayed there.
    """
    assert rule.__name__ not in engine_module.__all__, (
        f"{rule.__name__} moved into the package. If that was deliberate, the "
        f"freeze in docs/STATE.md is what it has to argue with")
    assert rule.__module__.startswith("examples."), (
        "these must stay third-party, or they stop being evidence that a "
        "stranger can write one")
