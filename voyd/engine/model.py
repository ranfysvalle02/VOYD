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
from .trait import Trait
from .admission import Admission
from .search import SearchSpec

if TYPE_CHECKING:
    from . import Engine

# Bound to the trait protocol, like `Engine.use`'s. A trait installed
# through a model is still a trait, and leaving this unbound is what let a
# `use()` call typed as `Any` flow through untouched -- surfaced the moment
# `Engine.use` stopped accepting anything at all.
T = TypeVar("T", bound=Trait)


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

    def admitting(self, *rules, at_field: str = "expire_at",
                  lineage_field: str | None = None,
                  policy_revision: str | None = None,
                  subjects: str | None = None,
                  subject_key: str | None = None) -> Admission:
        """A read handle with an explicit list of reasons to refuse.

        ``forgettable()`` is this with the two defaults. Naming the rules is
        for when a collection has more:

            notes.admitting(Deadline(), revoked(), quarantined())

        Each rule is asked on every read, in order, and the *first* refusal
        is what gets reported -- an operator needs to know a document was
        quarantined rather than merely expired, because the responses
        differ. The TTL is still declared, because a deadline refused on
        read and never collected is a storage leak.

        ``subjects`` names an array whose elements carry their own marks and
        deadlines -- chapters in a book, comments on a ticket. Without it the
        document is the only subject, which is what every collection here
        meant before the embedded-document pattern made that assumption
        silently wrong: a chapter carrying the mark ``revoke()`` writes
        reaches a prompt with its parent and is counted nowhere. With it,
        refused elements are dropped from the document and counted on
        ``Page.redacted``. ``subject_key`` names the field that identifies
        one, which is what makes ``revoke_subject()`` possible: without it a
        subject can be refused but never addressed, and an element that does
        not carry the declared key is refused as ``unnamed`` rather than
        admitted.

        ``lineage_field`` opts the collection into derivation tracking, so
        ``derive()`` can record what a document was made out of and a
        refusal travels to everything downstream of it. Off by default: a
        collection of source facts has no lineage and should not pay a
        field and an index for one.
        """
        self.expiring(at_field=at_field)
        return self.engine.admission(
            self.collection, at_field=at_field, tenant=self.tenant,
            lineage_field=lineage_field, policy_revision=policy_revision,
            subjects=subjects, subject_key=subject_key, rules=tuple(rules))

    def sealed(self, *fields: str, keyring=None, scope: str | None = None,
               custody=None, **kw) -> Admission:
        """Encrypt these fields at rest, with a key per scope. One line.

            notes = engine.model("notes", tenant="tenant_id").sealed("text")

            await notes.seal({"tenant_id": "alice", "text": secret})
            await notes.find({"tenant_id": "alice"})     # decrypted
            await notes.shred("alice")                   # unreadable, everywhere

        **The scope is the tenant, and that is the whole design.** A
        per-scope key needs a field naming the key; a multi-tenant
        collection already has one. Tying them together means no second
        field, no second lookup, and nothing to keep in step -- and it
        means per-tenant crypto erasure falls out of a declaration the
        model already made, rather than being a feature somebody wires up.

        Everything this returns is the ordinary refusing handle, so
        ``revoke()``, ``quarantine()``, ``derive()`` and the rest keep
        working and keep composing: a revoked document is refused by its
        mark before anything is decrypted, and a shredded one is refused
        as ``unrecoverable`` beside it.

        On a collection with no tenant, pass ``scope=`` to name the field.
        There is no default beyond the tenant on purpose -- inventing one
        would put every document in one scope, which is the configuration
        where shredding erases everybody.
        """
        from .keyring import KeyringSpec, Sealed, Sealing

        at = scope or self.tenant
        if not at:
            raise ValueError(
                f"{self.collection}: sealing needs a scope field, and this "
                f"model has no tenant. Either declare one -- "
                f"model({self.collection!r}, tenant='...') -- or pass "
                f"scope='field'. Defaulting would put every document under "
                f"one key, and then one erasure request erases everybody")
        if not fields:
            raise ValueError(
                f"{self.collection}: sealed() needs at least one field. A "
                f"collection that seals nothing is an unencrypted "
                f"collection with a key vault attached")

        mode = Sealed(tuple(fields))
        if keyring is None:
            keyring = self.engine.keyring(
                spec=KeyringSpec(pointer_field=at,
                                 protect={self.collection: mode}),
                custody=custody)
        else:
            keyring.spec.protect[self.collection] = mode
        handle = self.admitting(*kw.pop("rules", ()), **kw) if kw.get("rules") \
            else self.forgettable()
        return handle.sealed_by(Sealing(keyring, tuple(fields), at))

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
            trait = make(self.engine.db, self.collection, **kw)
        else:
            trait = make
        return self.engine.use(trait)
