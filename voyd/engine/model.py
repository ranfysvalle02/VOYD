"""A model is one collection of documents.

The traits in this package are not five products. They are traits of a
collection, and this is the handle you chain them onto: a **model** (the
documents, with the tenant field threaded through) plus a **controller** (probe,
wait, retry, resume, announce). Those controller behaviours are what a service
mesh is usually bought for; here they are properties of the documents, on one
replica set.

    docs = engine.model("docs", tenant="tenant_id")
    docs.searchable(vector_path="embedding", text_paths=("title", "body"))
    docs.expiring()

    jobs = engine.model("files").queue(when={"indexed": False})
    events.use(Outbox)                  # any trait: kind + collection + ensure()
    await engine.connect()
    await engine.ensure()
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any, Callable, TypeVar

from .expiry import ExpirySpec
from .admission import Admission
from .jobs import JobQueue
from .memory import Memory, MemorySpec
from .search import SearchSpec

if TYPE_CHECKING:
    from . import Engine

T = TypeVar("T")


class Model:
    """One collection, tenant-threaded, traits optional.

    Declaring twice is idempotent: the engine's ``ensure()`` is. This object
    is a handle, not a wrapper type around your documents. ``engine.db[name]``
    is still the collection.
    """

    def __init__(self, engine: Engine, collection: str, *,
                 tenant: str | None = None, tenant_type: str = "token"):
        self.engine = engine
        self.collection = collection
        self.tenant = tenant
        self.tenant_type = tenant_type

    def _tenant_kw(self, kw: dict[str, Any], field: str = "tenant_field") -> dict[str, Any]:
        out = dict(kw)
        if self.tenant and field not in out:
            out[field] = self.tenant
        return out

    def searchable(self, **kw) -> Model:
        """Hybrid search over this collection. Tenant is pushed into the index."""
        spec_kw = self._tenant_kw(kw)
        if self.tenant:
            spec_kw.setdefault("tenant_type", self.tenant_type)
        spec_kw.setdefault("vector_index", f"{self.collection}_vector")
        spec_kw.setdefault("text_index", f"{self.collection}_text")
        self.engine.searchable(SearchSpec(self.collection, **spec_kw))
        return self

    def expiring(self, *, at_field: str = "expire_at",
                 after: timedelta | None = None) -> Model:
        """TTL on this collection. Per-document deadline unless ``after`` is set."""
        self.engine.expiring(ExpirySpec(
            self.collection, at_field=at_field, after=after))
        return self

    def forgettable(self, *, at_field: str = "expire_at",
                    mark_field: str = "forgotten") -> Admission:
        """A read handle that cannot return a forgotten fact.

        Declares the TTL as well, because a deadline you refuse on read and
        never collect is a storage leak, and a deadline you collect but do not
        refuse is the bug this exists to remove. They are one policy.
        """
        self.expiring(at_field=at_field)
        return self.engine.admission(
            self.collection, at_field=at_field, mark_field=mark_field,
            tenant=self.tenant)

    def admitting(self, *rules, at_field: str = "expire_at") -> Admission:
        """A read handle with an explicit list of reasons to refuse.

        ``forgettable()`` is this with the two defaults. Naming the rules is
        for when a collection has more:

            notes.admitting(Deadline(), revoked(), quarantined())

        Each rule is asked on every read, in order, and the *first* refusal
        is what gets reported -- an operator needs to know a document was
        quarantined rather than merely expired, because the responses
        differ. The TTL is still declared, because a deadline refused on
        read and never collected is a storage leak.
        """
        self.expiring(at_field=at_field)
        return self.engine.admission(
            self.collection, at_field=at_field, tenant=self.tenant,
            rules=tuple(rules))

    def memory(self, **kw) -> Memory:
        """Recall with decay: search plus TTL, one collection."""
        spec_kw = dict(kw)
        spec_kw.setdefault("collection", self.collection)
        if self.tenant:
            spec_kw.setdefault("scope_field", self.tenant)
            spec_kw.setdefault("scope_type", self.tenant_type)
        return self.engine.memory(MemorySpec(**spec_kw))

    def queue(self, *, when: dict, **kw) -> JobQueue:
        """The document is the job. Safe across replicas; retry is a policy."""
        return self.engine.queue(self.collection, when=when, **kw)

    def use(self, make: Callable[..., T] | T, /, **kw) -> T:
        """Install any trait on this collection.

        A class or factory is called as ``make(db, collection, **kw)``.
        An instance is installed as-is. Tenant is supplied when this model
        has one and the caller did not override it.

            events.use(Outbox)
            events.use(Outbox, retain=timedelta(days=7))
            events.use(already_built)
        """
        if self.tenant is not None:
            kw.setdefault("tenant", self.tenant)
        if isinstance(make, type) or (
            callable(make) and not hasattr(make, "ensure")
        ):
            trait = make(self.engine.db, self.collection, **kw)  # type: ignore[operator]
        else:
            trait = make  # type: ignore[assignment]
        return self.engine.use(trait)
