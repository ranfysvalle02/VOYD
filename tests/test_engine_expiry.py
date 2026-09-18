"""The deadline, as an engine primitive.

Same rule as ``test_engine_standalone``: nothing from ``voyd`` except
``voyd.engine``. Expiry is the substrate the product is built on -- a void, its
files and their vectors all die together -- so it is tested the way a different
app would use it, not through the HTTP service.
"""

from __future__ import annotations

from datetime import timedelta

from voyd.engine import ExpirySpec, SearchSpec


async def test_ttl_indexes_are_declared_not_scattered(core):
    e, db = core
    e.expiring(ExpirySpec("sessions", at_field="expire_at"))
    e.expiring(ExpirySpec("logs", at_field="created_at", after=timedelta(hours=6)))
    report = await e.ensure(search_wait_s=0)
    assert report["ttl"] == 2

    idx = await db.sessions.index_information()
    assert idx["expire_at_1"]["expireAfterSeconds"] == 0, "per-document deadline"
    idx = await db.logs.index_information()
    assert idx["created_at_1"]["expireAfterSeconds"] == 6 * 3600


async def test_ensure_is_idempotent_and_reports_what_it_built(core):
    """It runs on every boot, so running twice must be a no-op, not an error."""
    e, _ = core
    q = e.model("calls").queue(when={"indexed": False})
    e.expiring(ExpirySpec("sessions"))

    first = await e.ensure(search_wait_s=0)
    second = await e.ensure(search_wait_s=0)
    assert first["queue"] == second["queue"] == [q.collection]
    assert second["ttl"] == 1


async def test_health_lists_everything_declared(core):
    e, _ = core
    e.searchable(SearchSpec("docs", text_paths=("body",)))
    e.expiring(ExpirySpec("sessions"))
    e.model("calls").queue(when={"indexed": False})
    await e.ensure(search_wait_s=0)

    declared = e.health()["declared"]
    assert declared["searchable"] == ["docs"]
    assert declared["expiring"] == ["sessions"]
    assert declared["queue"] == ["calls"]
