"""Fail closed, fail loud.

A missing tenant filter is a data leak that arrives as an answer. A
cosine fallback that loads the whole collection is an OOM that arrives
as latency. Neither is a ranking bug.

Presence is not the whole check. A tenant id that is *there* but is a
``dict`` is a query operator, and every tier interpolates filter values
straight into a query: ``$vectorSearch``'s ``filter`` accepts ``$ne`` and
``$gt``, the cosine fallback is a plain ``find``, and the lexical leg's
``equals`` rejects a non-scalar loudly enough to trigger the degrade path --
which then serves the same unbounded query. ``{"tenant": {"$ne": "x"}}``
therefore matched every tenant on all three tiers. So shape is checked
where presence is, and the declared type is the contract.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from bson import Binary, ObjectId

# What an id is allowed to be. Deliberately a closed list of scalars rather
# than "not a dict": a list is ``$in`` by another name on the ``find`` path,
# and Atlas's ``equals`` accepts exactly this shape anyway. Anything that can
# carry an operator is not an id.
SCALAR_ID = (str, ObjectId, int, float, bool, bytes, Binary, datetime, UUID)


class ScopeError(ValueError):
    """Base: the tenant boundary could not be established for this query.

    Caught as one thing by the query path, which counts it and refuses,
    because both subclasses have the same blast radius if served.
    """


class ScopeRequired(ScopeError):
    """A scoped primitive was queried without its tenant field.

    Returning rows would leak every tenant into the caller. Raise instead.
    """

    def __init__(self, collection: str, field: str):
        self.collection = collection
        self.field = field
        super().__init__(
            f"{collection} is scoped by {field!r}; pass it in filters "
            f"or every tenant leaks"
        )


class ScopeInvalid(ScopeError):
    """The tenant field was present, but its value was not a scalar id.

    This is the dangerous one, because it passes a presence check. A dict in
    the tenant position is an operator: ``{"$ne": "nobody"}`` matches every
    tenant, on the vector leg, the lexical leg and the cosine fallback alike.
    """

    def __init__(self, collection: str, field: str, value: object):
        self.collection = collection
        self.field = field
        self.value = value
        super().__init__(
            f"{collection} is scoped by {field!r}, which must be a scalar id, "
            f"not {type(value).__name__}: a non-scalar is a query operator "
            f"and matches every tenant"
        )


class FilterInvalid(ValueError):
    """A declared filter field was given a non-scalar value.

    Not a tenant breach -- the tenant clause still binds -- but the lexical
    leg's ``equals`` cannot express it, so it would fail the query and hand
    the caller the cosine fallback instead, silently widening the filter to
    whatever the operator means. Refused for the same reason: the three tiers
    must agree about which documents exist.
    """

    def __init__(self, collection: str, field: str, value: object):
        self.collection = collection
        self.field = field
        self.value = value
        super().__init__(
            f"{collection}: filter {field!r} must be a scalar, not "
            f"{type(value).__name__}; operators are not pushable into the "
            f"search index and would change tier behaviour"
        )


def require_tenant(collection: str, field: str | None,
                   filters: dict | None) -> dict:
    """The tenant half of ``require_scope``, for callers that query the
    collection directly.

    A plain ``find`` can express operators perfectly well -- ``doc_id:
    {"$in": [...]}`` is how you forget a batch -- so the blanket scalar rule
    that protects the *search* path would be wrong here. What still holds,
    and holds everywhere, is the tenant: present, and a scalar, because a
    dict in that position is an operator that matches every tenant.

    Learned the hard way: reusing ``require_scope`` here refused
    ``forget(doc_ids=[...])``, which is a legitimate batched write. One rule
    per hazard, rather than one rule reused past its reason.
    """
    flt = dict(filters or {})
    if not field:
        return flt
    if field not in flt or flt[field] is None:
        raise ScopeRequired(collection, field)
    if not isinstance(flt[field], SCALAR_ID):
        raise ScopeInvalid(collection, field, flt[field])
    return flt


def require_scope(collection: str, field: str | None,
                  filters: dict | None) -> dict:
    """Return a copy of ``filters``, or raise if the tenant is missing or unsafe.

    The search path's rule: ``require_tenant`` plus the stricter condition
    that *every* filter value is a scalar. That extra clause is about the
    index rather than the tenant -- the lexical leg's ``equals`` cannot
    express an operator, so one would fail the query and hand the caller the
    cosine fallback with a silently wider filter.

    Raises ``ScopeRequired`` / ``ScopeInvalid`` for the tenant, and
    ``FilterInvalid`` for anything else that is not a scalar.
    """
    flt = require_tenant(collection, field, filters)

    for key, value in flt.items():
        if key == field or value is None:
            continue
        if not isinstance(value, SCALAR_ID):
            raise FilterInvalid(collection, key, value)

    return flt
