"""The rules, asked of mongot before ranking. Opt-in, and never the guarantee.

A `$vectorSearch` hit passes through no query this boundary narrows, so the
refusal happens on the way out: the index ranks `limit` documents, the
boundary removes the expired and the revoked, and the caller gets fewer
than they asked for. For a collection whose corpus is mostly dead rows
that is a page of nearly nothing. `prefilter=True` on a `@guard` asks the
index to leave those rows out of the ranking instead.

It is off unless declared, for the reasons in `voyd/engine/search.py`: the
filter fields have to be in the vector index definition, and a
vectorSearch definition cannot be updated in place. Turning this on for an
index that already exists is a rebuild, not a migration.

What this rewrite does and does not do:

- **It only narrows.** The rule clauses are ANDed with whatever filter the
  client sent. The client's clauses are kept as written.
- **All or nothing.** Every rule has to come back from
  `expressible_clauses` as a clause the `$vectorSearch` filter language
  accepts, or the stage is forwarded byte for byte. Half the rules in the
  index and half on the way out is the same result as none in the index,
  with a harder explanation.
- **Only when the index is known to declare the fields.** The proxy holds
  no connection to ask, so `Guard.prefilter_index` is set at startup by
  `--ensure` or `--verify`, from the live definition. A drifted or missing
  index leaves it `None` and the stage goes upstream unchanged.
- **Only a leading `$vectorSearch` on the guarded collection.** One inside
  `$rankFusion` is not rewritten: a pipeline with `$rankFusion` is already
  a reduction to `reads.py`, which pushes one `$match` over the fused
  result, and rewriting the vector leg alone would leave the two legs
  disagreeing about which documents exist. `$unionWith` is refused by
  `reads.py` before this is reached.
- **The clock is the request's.** A deadline clause carries the instant
  the request was rewritten. A row that expires between that instant and
  the reply is ranked, returned, and refused by the egress pass, which
  re-reads the clock and is still what decides.

The reply is judged on the way out exactly as before. Nothing here marks
the request as reduced.
"""

from __future__ import annotations

from typing import Any, Mapping

from ..codec import LAZY, decode_op_msg, encode_op_msg
from .guarding import Guard, guard_for
from .reads import expressible_clauses

# The operators a `$vectorSearch.filter` accepts. A clause using anything
# else would be rejected by mongot, and a rejected query is a failed read
# the client did not cause -- so such a rule makes the prefilter `None`.
VECTOR_FILTER_OPERATORS = frozenset({
    "$eq", "$ne", "$gt", "$gte", "$lt", "$lte", "$in", "$nin",
    "$exists", "$not", "$nor", "$and", "$or",
})

# The value types a filter field indexes. A clause comparing against
# anything else (a subdocument, a regex) cannot be answered by the index.
_SCALARS = (bool, int, float, str, type(None))


def _filterable_value(value: Any) -> bool:
    from datetime import datetime

    from bson import ObjectId
    if isinstance(value, list):
        return all(_filterable_value(v) for v in value)
    return isinstance(value, (*_SCALARS, datetime, ObjectId))


def clause_paths(clause: Any) -> set[str] | None:
    """The document paths a clause reads, or `None` if mongot cannot ask it."""
    paths: set[str] = set()
    if isinstance(clause, list):
        for part in clause:
            got = clause_paths(part)
            if got is None:
                return None
            paths |= got
        return paths
    if not isinstance(clause, Mapping):
        return None
    for key, value in clause.items():
        if key.startswith("$"):
            if key not in VECTOR_FILTER_OPERATORS:
                return None
            got = clause_paths(value) if key in ("$and", "$or", "$nor") \
                else set()
            if got is None:
                return None
            paths |= got
            continue
        paths.add(key)
        if isinstance(value, Mapping):
            for op, operand in value.items():
                if op not in VECTOR_FILTER_OPERATORS or op in (
                        "$and", "$or", "$nor"):
                    return None
                if op == "$not":
                    if clause_paths({key: operand}) is None:
                        return None
                elif not _filterable_value(operand):
                    return None
        elif not _filterable_value(value):
            return None
    return paths


def prefilter_clauses(guard: Guard,
                      caller: dict | None = None) -> list[dict] | None:
    """This guard's rules as `$vectorSearch.filter` clauses, or `None`."""
    clauses = expressible_clauses(guard, caller)
    if not clauses:
        return None
    if any(clause_paths(c) is None for c in clauses):
        return None
    return clauses


def prefilter_fields(guard: Guard) -> tuple[str, ...] | None:
    """The filter fields a vector index must declare for the prefilter.

    Asked without a caller, so a caller-aware rule makes this `None` and
    the collection cannot opt in: which fields it reads depends on who is
    asking, and an index definition is written once.
    """
    clauses = prefilter_clauses(guard)
    if clauses is None:
        return None
    paths: set[str] = set()
    for c in clauses:
        paths |= clause_paths(c) or set()
    return tuple(sorted(paths))


def index_declares(definition: Mapping | None, fields: tuple[str, ...]) -> bool:
    """Does this live vector definition carry every field as a `filter`?"""
    if not isinstance(definition, Mapping):
        return False
    declared = {f.get("path") for f in definition.get("fields", [])
                if isinstance(f, Mapping) and f.get("type") == "filter"}
    return set(fields) <= declared


def _narrowed(existing: Any, clauses: list[dict]) -> dict:
    if isinstance(existing, Mapping) and existing:
        return {"$and": [dict(existing), *clauses]}
    return {"$and": list(clauses)}


def rewrite_vector_search(raw: bytes, req_id: int, resp_to: int,
                          guards: dict[str, Guard], verbose: bool = False,
                          caller: dict | None = None) -> bytes | None:
    """The request with the rules in its `$vectorSearch.filter`, or `None`.

    `None` means forward the original bytes. Every path out of here that is
    not a confident rewrite is `None`.
    """
    guard = guard_for(guards, _peek(raw) or {}, "aggregate")
    if guard is None or not getattr(guard, "prefilter_index", None):
        return None
    decoded = decode_op_msg(raw)
    if decoded is None:
        return None
    flags, body = decoded
    pipeline = body.get("pipeline")
    if not isinstance(pipeline, list) or not pipeline:
        return None
    lead = pipeline[0]
    if not isinstance(lead, Mapping) or list(lead) != ["$vectorSearch"]:
        return None
    stage = lead["$vectorSearch"]
    if not isinstance(stage, Mapping) or \
            stage.get("index") != guard.prefilter_index:
        return None
    clauses = prefilter_clauses(guard, caller)
    if clauses is None:
        return None
    patched_stage = dict(stage)
    patched_stage["filter"] = _narrowed(stage.get("filter"), clauses)
    patched = dict(body)
    patched["pipeline"] = [{"$vectorSearch": patched_stage}, *pipeline[1:]]
    if verbose:
        print(f"  voyd: {guard.collection}: the rules went into "
              f"$vectorSearch.filter; the reply is still judged on the "
              f"way out", flush=True)
    return encode_op_msg(req_id, resp_to, flags, patched)


def _peek(raw: bytes) -> Mapping | None:
    got = decode_op_msg(raw, LAZY)
    return got[1] if got else None
