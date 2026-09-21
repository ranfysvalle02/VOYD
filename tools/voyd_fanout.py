#!/usr/bin/env python3
"""Rank on a secondary, take permission from the primary.

Fan-out is the last thing the wire boundary could not do: every read landed
on one upstream, so a retrieval workload paid for its `$vectorSearch` scan on
the same node serving writes. Spreading those reads across secondaries is the
standard MongoDB cost lever, and this is the module that does it.

It is also the one feature in this repository that cannot be added by making
the boundary faster, because a naive version **reintroduces the exact failure
the project is named after**.

## Why the obvious version is unsafe

Refusal is a function of the marks on the document it is shown --
``doc.get("expire_at")``, ``doc.get("forgotten")``. A secondary that has not
yet replicated a revocation hands the boundary a document that still looks
live, and the boundary admits it, confidently, with a receipt saying it was
allowed. Replication lag becomes a second delete-is-a-wish window, opened by
the thing that exists to close the first one.

So the split: the **secondary ranks** and the **primary permits**. The
expensive part of a vector read is the `numCandidates` scan across the whole
corpus, and that runs on the secondary. Before the batch is released, the
marks for the handful of ``_id``s it returned are re-read from the primary
and the verdict is taken from *those*. Ten documents out of a hundred
thousand: the scan moves off the primary, and what stays is one small
projected lookup.

Ranking is not permission. That is the whole README, and here it is a routing
rule.

## What this costs, stated plainly

- **One extra round trip per guarded batch.** Unguarded collections fan out
  with no verification and no round trip, because there is no verdict to be
  wrong about.
- **A projection, when the rules allow one.** ``verdict_fields`` works out
  which fields the verdict actually reads. When every rule declares them,
  the lookup fetches those and ``_id``. When any rule reads the document as
  a whole -- ``Distinct`` hashing content, a ``Budget`` with a custom cost
  callable, any third-party rule this module has never heard of -- it
  returns ``None`` and the caller fetches whole documents. Unknown means
  expensive, never means skipped.
- **Correlation needs ``_id``.** A batch whose documents dropped it cannot
  be matched against the primary's answer, so those reads are never routed
  off the primary in the first place -- decided before the query is sent,
  not discovered after the answer comes back.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping


# Attributes on a builtin rule that name a *document field* the verdict
# reads. Every rule in `voyd.engine.admission.rules` spells it one of these
# three ways, which is a property of that file worth not relying on silently:
# a rule that grows a fourth and is not added here reads a field this module
# will not fetch, and the verdict would be taken on a missing value.
# `unknown_rule` below is what stops that being silent.
FIELD_ATTRS = ("at_field", "field", "cost_field")

# Rules whose verdict is a function of the document as a whole rather than of
# named fields. Not a blocklist of things that are wrong -- a list of things
# a projection cannot express.
WHOLE_DOCUMENT = ("Distinct",)


def unknown_rule(rule: Any) -> bool:
    """Does this rule read something a projection cannot name?

    Conservative by construction. A rule is projectable only if it names at
    least one field through a known attribute and is not one of the
    content-addressed ones. Anything else -- including every third-party
    rule, which is the case that matters, because this module cannot have
    been written with it in mind -- answers True and costs a whole-document
    fetch rather than a wrong verdict.
    """
    name = type(rule).__name__
    if name in WHOLE_DOCUMENT:
        # `Distinct(on="url")` is projectable; `Distinct()` hashes content.
        return not isinstance(getattr(rule, "on", None), str)
    if name == "Budget" and getattr(rule, "cost", None) is not None:
        # A caller-supplied cost callable may read anything at all.
        return True
    return not any(isinstance(getattr(rule, a, None), str) for a in FIELD_ATTRS)


def verdict_fields(guard: Any) -> set[str] | None:
    """The fields this guard's verdict reads, or ``None`` for "all of them".

    ``None`` is not a failure. It is the honest answer for a rule set this
    module cannot introspect, and the caller turns it into a whole-document
    fetch -- slower, always correct.
    """
    spec = guard.spec
    fields = {"_id"}
    if getattr(spec, "tenant", None):
        fields.add(spec.tenant)
    for attr in ("lineage_field", "subject_key"):
        value = getattr(spec, attr, None)
        if isinstance(value, str):
            fields.add(value)
    for rule in spec.rules:
        if unknown_rule(rule):
            return None
        if isinstance(getattr(rule, "on", None), str):
            fields.add(rule.on)
        for attr in FIELD_ATTRS:
            value = getattr(rule, attr, None)
            if isinstance(value, str):
                fields.add(value)
    return fields


# Aggregation stages that cannot remove or rewrite `_id`, and so leave a
# batch correlatable against the primary. Deliberately short: the question is
# not "is this stage safe to run on a secondary" -- they all are -- but "can
# this module still prove which document is which afterwards". `$vectorSearch`
# and `$search` are on the list because they are the entire point.
ID_PRESERVING_STAGES = frozenset({
    "$match", "$sort", "$limit", "$skip", "$vectorSearch", "$search",
    "$searchMeta", "$geoNear", "$sample", "$rankFusion",
})

# Commands that read. `getMore` is absent on purpose: it is not routed by
# this table but by cursor affinity, because a cursor id only exists on the
# server that issued it.
READ_COMMANDS = frozenset({"find", "aggregate", "count", "distinct"})

# A command carrying any of these is part of something that must not move off
# the primary: a transaction, a retryable write's session bookkeeping, or a
# causally consistent read whose guarantees this module does not implement.
PINS_TO_PRIMARY = ("txnNumber", "startTransaction", "autocommit")


def _drops_id(projection: Any) -> bool:
    """Would this projection leave documents without an ``_id``?"""
    if not isinstance(projection, Mapping):
        return False
    spec = projection.get("_id")
    return spec is not None and spec in (0, False)


def correlatable(body: Mapping) -> bool:
    """Will the documents coming back still carry an ``_id``?

    Decided from the *request*, before it is sent. Discovering it from the
    reply would be too late: the batch would already have been served by a
    secondary whose marks nobody could check, leaving a choice between
    refusing a whole page and admitting it unverified.
    """
    if "find" in body:
        return not _drops_id(body.get("projection") or body.get("fields"))
    if "aggregate" in body:
        pipeline = body.get("pipeline")
        if not isinstance(pipeline, list):
            return False
        for stage in pipeline:
            if not isinstance(stage, Mapping) or len(stage) != 1:
                return False
            name = next(iter(stage))
            if name not in ID_PRESERVING_STAGES:
                return False
        return True
    return False


def read_preference_of(body: Mapping) -> str | None:
    pref = body.get("$readPreference")
    if isinstance(pref, Mapping):
        mode = pref.get("mode")
        if isinstance(mode, str):
            return mode
    return None


# Stages that mean the secondary is about to do a lot of work for a small
# answer -- the shape fan-out exists for.
SEARCH_STAGES = frozenset({"$vectorSearch", "$search", "$searchMeta",
                           "$rankFusion"})


def read_shape(body: Mapping, name: str, collection: str
               ) -> tuple[str, str, int]:
    """``(collection, kind, size)`` -- what sort of read this is.

    The unit the payoff measurement is keyed by, and keying it on the
    collection alone was a real defect rather than a simplification. A RAG
    deployment runs `$vectorSearch` and ordinary `find`s against the *same*
    collection: the finds are cheap to rank and expensive to confirm, so
    they withdraw the collection, and the vector search -- the only reason
    fan-out was turned on -- never fans out again. Measured on a 301
    document collection, a selective read went from ranking on a secondary
    5 times out of 5 to 0 out of 5 after twelve full-collection finds
    against the same collection.

    Two axes, both readable from the *request*, because the routing
    decision has to be made before any answer exists:

    - **kind** -- a search stage means a big scan for a small answer.
    - **size** -- the requested `limit` or `batchSize`, rounded up to a
      power of two, because the cost of confirming is proportional to how
      many documents come back. A read asking for 10 and one asking for
      1,000 are different propositions against the same collection.

    A read that requests neither buckets at 0, which is its own bucket:
    "as many as there are" is a distinct proposition from any bounded one.
    """
    kind = name
    pipeline = body.get("pipeline")
    if isinstance(pipeline, list):
        for stage in pipeline:
            if isinstance(stage, Mapping) and SEARCH_STAGES & set(stage):
                kind = "search"
                break
    asked = body.get("limit")
    if not isinstance(asked, int) or asked <= 0:
        asked = body.get("batchSize")
    size = (1 << int(asked).bit_length()) if isinstance(asked, int) and asked > 0 else 0
    return collection, kind, size


def routes_to_secondary(body: Mapping, guards: Mapping[str, Any],
                        withdrawn: frozenset = frozenset()
                        ) -> tuple[str, str, int] | None:
    """Should this be ranked on a secondary? Its shape, or ``None``.

    Returning the shape rather than a bool is not decoration: it is the key
    the payoff measurement is recorded under, so the decision and the
    accounting cannot drift apart into two different ideas of what this
    read was.
    """
    for pin in PINS_TO_PRIMARY:
        if pin in body:
            return None
    mode = read_preference_of(body)
    if mode in ("primary", "primaryPreferred"):
        # The client asked, explicitly, and an operator flag does not get to
        # overrule an application that said what it needed.
        return None
    name = next((c for c in READ_COMMANDS if c in body), None)
    if name is None:
        return None
    collection = body.get(name)
    if not isinstance(collection, str):
        return None
    if "$out" in str(body.get("pipeline", "")) or "$merge" in str(
            body.get("pipeline", "")):
        return None                      # a write wearing a read's name
    if collection in guards and not correlatable(body):
        # Guarded and unverifiable is the one combination that must stay put.
        return None
    shape = read_shape(body, name, collection)
    if shape in withdrawn:
        # Measured, on this deployment, as not worth the round trip -- for
        # reads of *this shape*, which is not the same as this collection.
        return None
    return shape


def needed_ids(batch: Iterable[Mapping]) -> list[Any] | None:
    """The ``_id``s of a batch, or ``None`` if any document lacks one.

    ``None`` means the batch cannot be verified. The caller refuses it whole
    rather than serving documents whose marks nobody checked -- which should
    be unreachable, because `correlatable` declined to route it, and is
    checked anyway because "should be unreachable" is how the other bugs in
    this repository were described before they happened.
    """
    ids = []
    for doc in batch:
        if "_id" not in doc:
            return None
        ids.append(doc["_id"])
    return ids


def merge_marks(batch: list, authoritative: Mapping[Any, Mapping],
                fields: set[str] | None) -> tuple[list, list]:
    """Rebuild a secondary's batch with the primary's marks on it.

    Returns ``(judgeable, originals)`` -- two lists in the same order. The
    first is what the verdict is taken on; the second is what is actually
    served. They are separate because the client asked the secondary for its
    documents and is entitled to those bytes; the primary was consulted about
    *permission*, not content.

    A document the primary does not return is dropped from both. That is the
    conservative reading of an absence: it may have been deleted on the
    primary and not yet on the secondary, which is precisely the window this
    whole module exists to close.
    """
    judgeable, originals = [], []
    for doc in batch:
        fresh = authoritative.get(doc["_id"])
        if fresh is None:
            continue
        if fields is None:
            judgeable.append(dict(fresh))     # whole document from the primary
        else:
            merged = dict(doc)
            for field in fields:
                if field == "_id":
                    continue
                if field in fresh:
                    merged[field] = fresh[field]
                else:
                    # Absent on the primary means absent, not unchanged. A
                    # mark that was *lifted* has to be able to travel too, or
                    # a document stays refused forever on a stale copy.
                    merged.pop(field, None)
            judgeable.append(merged)
        originals.append(doc)
    return judgeable, originals


class Payoff:
    """Whether the rank/permit split is actually paying, per collection.

    Fan-out is worth doing when the work it moves off the primary is larger
    than the work it adds back. For a `$vectorSearch` scanning 100,000
    candidates to return ten, that is overwhelmingly true. For a `find`
    returning most of a small collection it is false: the primary is asked
    for marks on nearly every document it would have served anyway, so it
    does comparable work and the client pays an extra round trip for the
    privilege.

    Nothing about the request says which of those it is. The collection
    size is unknown, the selectivity of a filter is unknown, and an
    operator flag naming a threshold would be asking somebody to guess a
    number this process can measure.

    So it is measured, per collection, from the two things that are already
    being timed:

    - **ranked** -- how long the secondary took to answer. A proxy for the
      work the primary did *not* do.
    - **verified** -- how long the primary took to confirm the marks. The
      work the primary does instead.

    When `verified` stops being comfortably smaller than `ranked`, the
    primary is doing about as much as it would have without any of this and
    the split has become pure latency. That collection is withdrawn from
    fan-out and says so once.

    **It only ever withdraws.** There is no path back to fanning out a
    collection inside one process, and that is deliberate rather than
    unfinished: re-admitting on a favourable sample is how a boundary
    oscillates, and the cost of staying on the primary is a slower read
    rather than a wrong one. A restart re-decides.
    """

    def __init__(self, ratio: float = 1.0, warmup: int = 8,
                 alpha: float = 0.3):
        # Keyed by *shape* -- see `read_shape`. Keyed by collection, one
        # cheap query pattern withdrew the expensive one it shared a
        # collection with, which is the pairing every RAG deployment has.
        self.ratio = ratio
        self.warmup = warmup
        self.alpha = alpha
        self._seen: dict[tuple, int] = {}
        self._ranked: dict[tuple, float] = {}
        self._verified: dict[tuple, float] = {}
        self._withdrawn: set[tuple] = set()

    def withdrawn(self) -> frozenset:
        return frozenset(self._withdrawn)

    def _blend(self, table: dict, key: str, value: float) -> float:
        current = table.get(key)
        table[key] = (value if current is None
                      else current * (1 - self.alpha) + value * self.alpha)
        return table[key]

    def record(self, shape, ranked: float,
               verified: float) -> str | None:
        """Fold in one batch. Returns a reason if this just withdrew.

        ``ratio <= 0`` disables withdrawal entirely, which is the escape
        hatch for an operator who has measured their own workload and
        disagrees -- the measurement keeps running and the metrics keep
        reporting, only the acting stops.
        """
        if self.ratio <= 0 or shape in self._withdrawn:
            return None
        rank_avg = self._blend(self._ranked, shape, ranked)
        verify_avg = self._blend(self._verified, shape, verified)
        self._seen[shape] = self._seen.get(shape, 0) + 1
        if self._seen[shape] < self.warmup:
            return None
        if verify_avg < rank_avg * self.ratio:
            return None
        self._withdrawn.add(shape)
        return (f"confirming marks on the primary is costing "
                f"{verify_avg * 1000:.1f}ms against {rank_avg * 1000:.1f}ms "
                f"to rank on a secondary, so the split is paying for "
                f"nothing")
