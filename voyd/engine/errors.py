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


def require_scope(collection: str, field: str | None,
                  filters: dict | None) -> dict:
    """Return a copy of ``filters``, or raise if the tenant is missing or unsafe.

    Raises ``ScopeRequired`` when the declared tenant field is absent or
    ``None``, and ``ScopeInvalid`` when it is present but not a scalar id.
    Every other filter value is checked for the same scalar shape and raises
    ``FilterInvalid``, so no tier can be handed an operator it would
    interpret differently from the others.
    """
    flt = dict(filters or {})

    if field:
        if field not in flt or flt[field] is None:
            raise ScopeRequired(collection, field)
        if not isinstance(flt[field], SCALAR_ID):
            raise ScopeInvalid(collection, field, flt[field])

    for key, value in flt.items():
        if key == field or value is None:
            continue
        if not isinstance(value, SCALAR_ID):
            raise FilterInvalid(collection, key, value)

    return flt
