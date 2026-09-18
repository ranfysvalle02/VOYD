"""A third-party trait is a first-class primitive.

If this file has to import anything from the app extra, or patch Engine, the
extension point has failed. The contract is ``kind``, ``collection``,
``async ensure()``.
"""

from __future__ import annotations

import uuid

import pytest

from tests.conftest import TEST_MONGO_URI, _mongo_available
from voyd.engine import Engine, collection_of, kind_of
from voyd.engine.trait import Trait


class Outbox:
    """Stand-in for a primitive this repo does not ship."""

    kind = "outbox"

    def __init__(self, db, collection, *, tenant=None, field: str = "published"):
        self.db = db
        self.collection = collection
        self.tenant = tenant
        self.field = field
        self.ensured = 0

    async def ensure(self) -> bool:
        await self.db[self.collection].create_index(self.field)
        self.ensured += 1
        return True


def test_kind_of_falls_back_to_the_type_name():
    class Nameless:
        collection = "x"

        async def ensure(self):
            return True

    assert kind_of(Nameless()) == "nameless"
    assert kind_of(Outbox(None, "events")) == "outbox"


def test_collection_of_reads_spec_when_needed():
    class Wrapped:
        kind = "wrapped"

        def __init__(self):
            self.spec = type("S", (), {"collection": "from_spec"})()

        async def ensure(self):
            return True

    assert collection_of(Wrapped()) == "from_spec"
    with pytest.raises(ValueError, match="collection"):
        collection_of(object())


def test_outbox_satisfies_the_trait_protocol():
    assert isinstance(Outbox(None, "events"), Trait)


@pytest.fixture
async def app():
    if not await _mongo_available(TEST_MONGO_URI):
        pytest.skip(f"no MongoDB at {TEST_MONGO_URI}")

    from pymongo import AsyncMongoClient

    raw = AsyncMongoClient(TEST_MONGO_URI)
    # core_ so conftest's leaked-database sweep covers it.
    name = f"core_{uuid.uuid4().hex[:10]}"
    engine = Engine(raw, raw[name])
    await engine.connect()
    try:
        yield engine
    finally:
        await raw.drop_database(name)
        await raw.close()


async def test_model_use_constructs_with_collection_and_tenant(app):
    events = app.model("events", tenant="tenant_id")
    box = events.use(Outbox, field="done")
    assert box.collection == "events"
    assert box.tenant == "tenant_id"
    assert box.field == "done"
    assert app.installed("outbox")["events"] is box


async def test_use_replaces_the_same_kind_on_the_same_collection(app):
    first = app.model("events").use(Outbox, field="a")
    second = app.model("events").use(Outbox, field="b")
    assert first is not second
    assert app.installed("outbox")["events"] is second
    assert second.field == "b"


async def test_ensure_builds_third_party_traits_and_health_lists_them(app):
    box = app.model("events", tenant="shop").use(Outbox)
    report = await app.ensure(search_wait_s=0)
    assert report["outbox"] == ["events"]
    assert box.ensured == 1
    await app.ensure(search_wait_s=0)
    assert box.ensured == 2, "ensure is idempotent and safe every boot"

    declared = app.health()["declared"]
    assert declared["outbox"] == ["events"]
    indexes = await app.db.events.index_information()
    assert "done_1" not in indexes  # field default is published
    assert any(v.get("key") == [("published", 1)] for v in indexes.values())


async def test_builtins_are_the_same_objects_as_use(app):
    """The queue goes through use(). Accessors still work."""
    q = app.model("calls").queue(when={"indexed": False})
    assert app.installed("queue")["calls"] is q
    report = await app.ensure(search_wait_s=0)
    assert "calls" in report["queue"]
