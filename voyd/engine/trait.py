"""A primitive is a trait. That is the extension point.

The five builtins are not a closed set. They are objects with a ``kind``,
a ``collection``, and ``async ensure()`` -- schema the replica set should
maintain. ``voyd-wire --ensure`` builds every trait a policy file
declares: the collection, TTL behind each deadline, an index leading with
each tenant, and a vector index the server embeds.

Duck typing. Inherit nothing. This module is the contract, not a framework:

    class Outbox:
        kind = "outbox"
        def __init__(self, db, collection, *, tenant=None):
            self.db = db
            self.collection = collection
            self.tenant = tenant
        async def ensure(self):
            await self.db[self.collection].create_index("published")
            return True

    events = engine.model("events", tenant="tenant_id")
    events.use(Outbox)

Pinned settings (clock, codecs, tenant field type) are the other half of the
picture: the engine fixes them on its own handle rather than inheriting
whatever the caller's client happened to be configured with. A trait is what
you *add*; a pinned setting is what the engine *refuses to guess*.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class Trait(Protocol):
    """Anything provisioning can install.

    ``ensure()`` should be idempotent and safe on every boot. Return a
    truthy value when the schema was applied (or already in place).
    """

    kind: str
    collection: str

    async def ensure(self) -> Any: ...


def kind_of(trait: Any) -> str:
    kind = getattr(trait, "kind", None)
    if isinstance(kind, str) and kind:
        return kind
    return type(trait).__name__.lower()


def collection_of(trait: Any) -> str:
    coll = getattr(trait, "collection", None)
    if isinstance(coll, str) and coll:
        return coll
    spec = getattr(trait, "spec", None)
    coll = getattr(spec, "collection", None) if spec is not None else None
    if isinstance(coll, str) and coll:
        return coll
    raise ValueError(
        f"{type(trait).__name__} needs .collection or .spec.collection"
    )
