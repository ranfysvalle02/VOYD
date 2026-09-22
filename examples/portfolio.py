"""A prompt is a regulated set, not a ranked list.

    docker compose up -d
    uv run python examples/portfolio.py   # ~5 seconds, no API key, no vendor

`rosetta.py` shows five *per-document* mechanisms as five rules on one handle.
This shows the other half of the protocol, and the half nobody else can
express at all: rules that are about the **page**, not the document.

`AHA.md` step 5 names two of them -- a token `Budget` and `Distinct` -- and
calls them a category rather than two awkward examples. Two members is thin
evidence for a category. So here are three more, written the way a stranger
writes them: against the public protocol, in this file, with nothing added to
`voyd`. If they work, the category is real and the claim is not resting on
the two rules that happen to ship.

    ProvenanceQuota   at most 30% of this context from unverified sources
    AtMostPerSource   no more than two documents from any one publisher
    TieredCost        a mixed cost budget where a premium source costs more

Each is a *portfolio constraint on the context window*: the same document is
admitted alone and refused in company, which is precisely what an index
filter and a policy engine structurally cannot say. `$vectorSearch` decides
each candidate before the page exists; `enforce(subject, object, action)` has
no argument for the rest of the set.

**What this cannot do, said here rather than discovered later.** Admission is
a veto. It can refuse a document for what is already on the page; it cannot
*require* that something be on it. So "must include a dissenting document" --
a diversity floor -- is not expressible here, and saying it were would be the
kind of overreach this protocol is supposed to make unnecessary. A floor is a
retrieval objective, which is the ranker's job; a ceiling is an admission
rule, which is this one's. `AtMostPerSource` is the ceiling that gets you the
anti-echo-chamber behaviour a floor was reaching for, and it is honest about
being a different thing.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from dataclasses import dataclass, field
from typing import Any, ClassVar

from pymongo import AsyncMongoClient

from voyd.engine import Deadline, revoked
from voyd.engine.admission import Admission, AdmissionSpec

# The examples all read the same variable, so one export points every
# one of them at Atlas instead of the local container.
URI = os.getenv("VOYD_MONGO_URI",
                "mongodb://localhost:27018/?directConnection=true")


# ---- three set-relative rules, none of them shipped by this package ------

@dataclass
class _Ratio:
    """Per-read memory for a quota: how much of the page is each kind."""
    ok: int = 0
    not_ok: int = 0

    @property
    def total(self) -> int:
        return self.ok + self.not_ok


@dataclass(frozen=True)
class ProvenanceQuota:
    """At most ``share`` of the admitted page may be unverified.

    The rule a compliance team actually asks for and no retrieval stack can
    answer: *how much of what you showed the model came from something we
    trust?* It is unanswerable per document -- one unverified note is fine in
    a page of ten and is the whole story in a page of one.

    Refuses the unverified document that *would* push the page over the line,
    which means the answer depends on admission order, which is relevance.
    That is the correct dependency: the best-ranked unverified documents are
    the ones worth spending the quota on.
    """

    field_name: str = "verified"
    share: float = 0.3
    reason: str = "over_unverified_quota"
    needs_tab: ClassVar[bool] = True
    charges: ClassVar[bool] = True      # it spends the quota
    bypassable: ClassVar[bool] = True   # not a forgetting reason

    def new_tab(self) -> _Ratio:
        return _Ratio()

    def clause(self) -> dict | None:
        return None                     # no query half, and there cannot be one

    def why(self, doc: dict, *, when=None, tab: Any = None) -> str | None:
        verified = bool(doc.get(self.field_name))
        if verified:
            tab.ok += 1
            return None
        if (tab.not_ok + 1) > self.share * (tab.total + 1):
            return self.reason
        tab.not_ok += 1
        return None


@dataclass(frozen=True)
class AtMostPerSource:
    """No more than ``cap`` documents from any single source.

    The ceiling that does the work a "diversity floor" was reaching for. Ten
    hits from one publisher is what a ranker produces when that publisher
    writes well and often, and it reads to a model as ten independent
    corroborations of one house view.
    """

    field_name: str = "publisher"
    cap: int = 2
    reason: str = "source_over_represented"
    needs_tab: ClassVar[bool] = True
    charges: ClassVar[bool] = True
    bypassable: ClassVar[bool] = True

    def new_tab(self) -> dict:
        return {}

    def clause(self) -> dict | None:
        return None

    def why(self, doc: dict, *, when=None, tab: Any = None) -> str | None:
        key = doc.get(self.field_name)
        if key is None:
            return None                 # no source named: not this rule's call
        if tab.get(key, 0) >= self.cap:
            return self.reason
        tab[key] = tab.get(key, 0) + 1
        return None


@dataclass(frozen=True)
class TieredCost:
    """One budget, but a document from a premium tier costs more of it.

    A retrieval stack that mixes a cheap local index with a metered vendor has
    two currencies and one context window. Expressing that as two budgets
    gives you a page that satisfies both and blows the one that matters; a
    single tab with a per-tier multiplier is the constraint people mean.
    """

    limit: int = 100
    field_name: str = "tier"
    prices: dict = field(default_factory=lambda: {"premium": 40, "standard": 10})
    reason: str = "over_tiered_budget"
    needs_tab: ClassVar[bool] = True
    charges: ClassVar[bool] = True
    bypassable: ClassVar[bool] = True

    def new_tab(self) -> _Ratio:
        return _Ratio()

    def clause(self) -> dict | None:
        return None

    def why(self, doc: dict, *, when=None, tab: Any = None) -> str | None:
        price = self.prices.get(doc.get(self.field_name), 10)
        if tab.ok + price > self.limit:
            return self.reason
        tab.ok += price
        return None


CORPUS = [
    # text                     verified  publisher   tier
    ("the fault code is P0301", True,  "acme",    "standard"),
    ("acme follow-up note",     True,  "acme",    "standard"),
    ("acme third opinion",      True,  "acme",    "standard"),
    ("a rumour from a forum",   False, "forum",   "standard"),
    ("a second forum rumour",   False, "forum",   "standard"),
    ("vendor teardown report",  True,  "vendor",  "premium"),
    ("vendor addendum",         True,  "vendor",  "premium"),
]


def _handle(db, collection: str, *rules) -> Admission:
    """One collection, one rule set, built from the parts.

    A handle per rule set rather than a collection per rule set. Two rule
    sets over one corpus are two objects over one collection, so the
    scenario needs no `notes0`, `notes1`, `notes2` to keep them apart.
    """
    return Admission(db, AdmissionSpec(
        collection, rules=rules).with_defaults())


async def main() -> None:
    client = AsyncMongoClient(URI)
    name = f"voyd_example_portfolio_{uuid.uuid4().hex[:8]}"
    db = client[name]
    try:
        await db.notes.insert_many(
            [{"text": t, "verified": v, "publisher": p, "tier": ti, "n": i}
             for i, (t, v, p, ti) in enumerate(CORPUS)])

        async def corpus() -> list:
            return [d async for d in db.notes.find({}).sort("n", 1)]

        print("\n  Seven documents, every one of them relevant and live.")
        print("  A ranker returns all seven. Three rules disagree, and none of")
        print("  them is about any single document.\n")

        for rule, note in (
            (ProvenanceQuota(share=0.3),
             "at most 30% of the page may be unverified"),
            (AtMostPerSource(cap=2),
             "at most 2 documents from one publisher"),
            (TieredCost(limit=100),
             "premium costs 40, standard costs 10, budget 100"),
        ):
            docs = _handle(db, "notes", Deadline(), revoked(), rule)
            kept = [d["text"] for d in docs.reachable(await corpus())]
            print(f"  {type(rule).__name__:17} {note}")
            print(f"    admitted {len(kept)} of 7: {kept}")
            print(f"    refused  {docs.receipts()['refused_by_reason']}\n")
            assert len(kept) < 7, "a rule that refuses nothing proves nothing"

        print("  And all three at once, on one handle, with the deadline and")
        print("  the revocation mark still enforced beside them:\n")
        docs = _handle(db, "notes", Deadline(), revoked(),
                       ProvenanceQuota(share=0.3), AtMostPerSource(cap=2),
                       TieredCost(limit=100))
        page = docs.reachable(await corpus())
        print(f"    admitted {len(page)} of 7: {[d['text'] for d in page]}")
        print(f"    refused  {docs.receipts()['refused_by_reason']}")

        print("\n  The same document, admitted alone and refused in company:")
        third = [d for d in await corpus() if d["text"] == "acme third opinion"]
        alone = _handle(db, "notes", AtMostPerSource(cap=2))
        print(f"    alone       -> {len(alone.reachable(third))} admitted")
        assert len(alone.reachable(third)) == 1

        crowd = _handle(db, "notes", AtMostPerSource(cap=2))
        kept_texts = {d["text"] for d in crowd.reachable(await corpus())}
        in_company = int("acme third opinion" in kept_texts)
        print(f"    in company  -> {in_company} admitted")
        assert in_company == 0, (
            "the whole argument is that these two numbers differ")
        print("\n  That is the whole argument. No index filter can produce two")
        print("  answers for one document, and enforce(subject, object, action)")
        print("  has nowhere to put the rest of the page.\n")

    finally:
        await client.drop_database(name)
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
