"""The engine's clock.

BSON Date is an instant. It has no zone. PyMongo will decode it naive unless
the client asked otherwise -- and a default client does not ask. This
project's own web layer happened to pass ``tz_aware=True``. An agent runtime
will not. Comparing
that naive value to ``datetime.now(timezone.utc)`` raises. A forgotten fact
then either crashes recall or, worse, skips the filter and reaches a prompt.

Every leak we have paid for is this shape: a setting the caller happened to
have. URI heuristics. Index readiness. Tenant field type. ``tz_aware``.
So the engine does not inherit the caller's environment. It pins these
settings on its own database handle and reports them on ``health()``.

Thin on purpose:

- ``bind(db)`` -- same database, UTC-aware codecs. The caller's client is
  not mutated.
- ``now()`` / ``aware()`` -- one clock, one coerce.
- ``live()`` / ``living()`` -- a deadline is a janitor, not a guarantee, so
  the read path has to check it too. ``live()`` is the predicate the retrieval
  path applies to each hit; ``living()`` is the same rule as a query fragment,
  for callers that can push it into the server. Garbage deadlines fail closed.

``point(lat=, lng=)`` is the same class of magic: the silent default is
how you index a location in the ocean. Time is how you leak a memory.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

log = logging.getLogger("engine.time")

UTC = timezone.utc


def now() -> datetime:
    """This process's idea of the present, as UTC-aware."""
    return datetime.now(UTC)


def aware(dt: datetime | None) -> datetime | None:
    """Coerce to UTC-aware. Naive is UTC, because that is what BSON stored.

    ``None`` stays ``None`` -- a missing deadline is pinned, not epoch.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def deadline(ttl: timedelta | None) -> datetime | None:
    """``None`` ttl is pinned (no deadline). Anything else is now plus ttl."""
    return None if ttl is None else now() + ttl


def live(doc: dict, at_field: str = "expire_at", *, when: datetime | None = None) -> bool:
    """May this document reach a prompt?

    A missing or null deadline is pinned. An unreadable deadline is dead --
    fail closed. Never raise: a TypeError here is how a forgotten fact
    used to skip the filter.

    ``OverflowError`` is in that list because a datetime can be a *valid*
    datetime and still be unreadable: ``datetime.max`` carrying a negative
    UTC offset overflows when shifted to UTC, as does ``datetime.min`` with
    a positive one. Stored BSON is always UTC millis so this does not arrive
    from the database, but ``live()`` is public and callers apply it to dicts
    they built themselves. "Never raise" has to mean never.
    """
    exp = doc.get(at_field)
    if exp is None:
        return True
    if not isinstance(exp, datetime):
        return False
    try:
        return aware(exp) > (when or now())
    except (TypeError, ValueError, OverflowError):
        return False


def living(at_field: str = "expire_at", *, when: datetime | None = None) -> dict:
    """Query fragment: not yet expired. Null / missing is pinned.

    MongoDB's TTL monitor runs about once a minute. Put this in the query
    even when a TTL index exists.
    """
    instant = aware(when) or now()
    return {"$or": [
        {at_field: None},
        {at_field: {"$exists": False}},
        {at_field: {"$gt": instant}},
    ]}


def bind(db):
    """Same database, clock pinned.

    Copies the caller's codec options and sets ``tz_aware=True, tzinfo=UTC``.
    Does not mutate the client or the original database object. Idempotent
    on options: calling it twice gives two handles with identical codecs.
    """
    bound = db.client.get_database(
        db.name,
        codec_options=db.codec_options.with_options(tz_aware=True, tzinfo=UTC),
    )
    log.debug("bound %s tz_aware UTC", db.name)
    return bound
