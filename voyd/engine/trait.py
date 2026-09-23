"""The shape of a thing that can be provisioned: ``ensure()``, idempotent.

    class Outbox:
        kind = "outbox"
        collection = "outbox"
        async def ensure(self):
            await db[self.collection].create_index("published")
            return True

**What this is, and what it is not, stated plainly because the two got
confused here once.** It is a *protocol*: a name for the shape the
provisioning helpers already have, so ``Expiry`` and the index builders
can be described in one word and type-checked against one thing.

It is **not** a registry, and ``voyd-wire --ensure`` does not discover
traits. ``ensure.provision`` builds what a policy file declares --
collections, a TTL behind each deadline, an index leading with each
tenant, a server-embedded vector index -- by naming those things
concretely. A class of your own with this shape is not picked up by
anything today.

This docstring used to say the opposite: that ``--ensure`` built every
trait a policy declared and a stranger's was built "with no privileged
path". That was a design intention written in the present tense, and it
was accompanied by two helper functions nothing ever called. Both are
gone. If third-party provisioning is worth having, it is worth a
registry, a declaration syntax and a test -- and until it has those, a
reader is owed the shorter true sentence rather than the longer one.
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
