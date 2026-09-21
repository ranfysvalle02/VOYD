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


def routes_to_secondary(body: Mapping, guards: Mapping[str, Any]) -> str | None:
    """Should this command be ranked on a secondary? The reason, or ``None``.

    Returning a reason rather than a bool is not decoration: it is what the
    metrics count and what ``--verbose`` prints, and a routing decision
    nobody can see the reasoning for is the kind this file is careful about.
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
    return name


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
