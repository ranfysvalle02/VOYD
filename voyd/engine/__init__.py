"""The engine: ModelController over one MongoDB.

Which interface sits on top -- HTTP, MCP, a script -- is the caller's concern,
not the engine's. What the engine is, is a **model** (one collection of
documents, and the traits the replica set maintains) plus a **controller**
(probe, wait, retry, resume, announce -- the behaviours people buy a service
mesh for once their data plane is spread across four systems).

No Redis, no Celery, no Elasticsearch, no vector database, no PostGIS, no Neo4j,
no Influx, no cron. One connection string. Operational resiliency is a
property of the document, not a sidecar.

    engine = Engine(client, db)
    await engine.connect()          # probe: what can this replica set do?
                                    # engine.db is UTC-aware even if the
                                    # caller's client is not.

    docs = engine.model("docs", tenant="tenant_id")
    docs.searchable(text_paths=("title", "body"))
    engine.model("sessions").expiring()
    mem = engine.model("memories", tenant="session").memory(
        default_ttl=timedelta(hours=1))

    await engine.ensure()           # wait until indexes are queryable
    engine.health()                 # degraded is a first-class state

Five traits ship, all of which chain onto a model: ``searchable``,
``expiring``, ``forgettable``, ``memory`` and ``queue``. Each is usable on
its own if a single one is all you need.

``forgettable`` is the one worth knowing about. It returns a read handle
with no unfiltered ``find`` on it -- and no unfiltered ``search`` either, so
a document that may not reach a prompt cannot come back from either: a rule
enforced by convention is enforced exactly as reliably as it is remembered.
It installs two reasons to refuse, a deadline and a revocation;
``admitting(*rules)`` is the same trait with the list written out, for a
collection that has more of them.

Two of the shipped rules compare the document against *who is asking* rather
than against the clock, which makes the handle the place the third question
gets answered -- not "may this caller read the scope" and not "may this
document reach a prompt", but the pair:

    docs = engine.model("docs", tenant="t").admitting(
        Deadline(), revoked(), Clearance(order=("public", "internal", "secret")))

    await docs.for_caller(claims).search(vector, filters={"t": t})

``for_caller`` returns a new handle rather than setting a field, because
handles are deduplicated per collection and every request is holding the same
one.

``model()`` is the main entry point: one collection, tenant threaded, traits
chained, ``use()`` for anything this package does not ship. ``ensure()``
builds what you declared.

This package is deliberately free of application vocabulary. It knows about
collections, fields and filters, never about namespaces or voids.
"""

from __future__ import annotations

from .capabilities import Capabilities, detect
from .errors import (
    BlastRadius,
    CallerRequired,
    DerivationBroken,
    FilterInvalid,
    Irreversible,
    ScopeError,
    ScopeInvalid,
    ScopeRequired,
    UnboundedForgetting,
    UnknownReason,
)
from .expiry import Expiry, ExpirySpec
from .admission import (DEADLINE, KEY_UNAVAILABLE, LIFTED, NOT_CLEARED,
                        QUARANTINED,
                        REACHABLE, REFUSED, REVOKED, UNKNOWN, UNREADABLE,
                        UNRECOVERABLE, WRONG_MODEL,
                        Clearance, Deadline, EmbeddedWith, Page, Restricted,
                         Admission, AdmissionSpec, Marked, Rule, Unrecoverable,
                         quarantined, revoked, why_refused)
from .jobs import JobQueue, PermanentFailure, backoff
from .custody import (Aws, Azure, Custody, Ephemeral, Gcp, Kmip,
                      LocalFile)
from .keyring import Keyring, KeyringSpec, Queryable, Sealed
from .ledger import GENESIS, Ledger, LedgerSpec, canonical, digest
from .memory import Memory, MemorySpec
from .policy import Denies, PolicyInvalid, compile_policy
from .perimeter import (DERIVED, OWNED, SEALED, Acknowledgement,
                        Perimeter, PerimeterLog, Sink, sink)
from .model import Model
from .search import SearchEngine, SearchSpec, cosine
from .time import UTC, aware, bind, deadline, live, living, now
from .trait import Trait, collection_of, kind_of


class Engine:
    """The controller. Models are collections you declare on it.

    Operational resiliency is not a sidecar mesh. It is ``connect`` (probe),
    ``ensure`` (wait, never query a building index), ``queue`` (retry the
    world, not the document), ``admission`` (refuse what may not reach a prompt),
    ``health`` (say the tier out loud), and the clock (UTC-aware on
    ``engine.db``, never inherited from the caller). Replica set plus these
    policies is the data-plane mesh. The documents never left.
    """

    def __init__(self, client, db):
        self.client = client
        # Pin the clock on our handle. The caller's client is not mutated --
        # a default AsyncMongoClient decodes Date naive, and that is how a
        # forgotten memory crashed recall.
        self.db = bind(db)
        self.capabilities = Capabilities()
        self.search_engine = SearchEngine(db=self.db, capabilities=self.capabilities)
        self.expiry = Expiry(self.db)
        # kind -> collection -> trait. Builtins and third-party share this.
        self._installed: dict[str, dict[str, object]] = {}
        self._memory: dict[str, Memory] = {}
        self._models: dict[str, Model] = {}

    async def connect(self) -> Capabilities:
        self.capabilities = await detect(self.client, self.db)
        self.search_engine.capabilities = self.capabilities
        return self.capabilities

    # ---- declaration ---------------------------------------------------

    def model(self, collection: str, *, tenant: str | None = None,
              tenant_type: str = "token") -> Model:
        """Declare a collection: optional tenant, traits chained on the handle.

        ``engine.searchable(SearchSpec(...))`` still works. This is the same
        declaration with the collection and tenant written once.
        """
        m = Model(self, collection, tenant=tenant, tenant_type=tenant_type)
        self._models[collection] = m
        return m

    def use(self, trait):
        """Install a primitive. Anything with ``kind``, ``collection``,
        ``async ensure()``. Replaces a previous trait of the same kind on
        the same collection. Returns the trait so the caller has a handle.
        """
        kind = kind_of(trait)
        coll = collection_of(trait)
        self._installed.setdefault(kind, {})[coll] = trait
        return trait

    def installed(self, kind: str | None = None) -> dict:
        """Installed traits. One kind, or every kind keyed by kind."""
        if kind is None:
            return {k: dict(v) for k, v in self._installed.items()}
        return dict(self._installed.get(kind, {}))

    def searchable(self, spec: SearchSpec) -> None:
        self.search_engine.register(spec)

    def expiring(self, spec: ExpirySpec) -> None:
        self.expiry.register(spec)

    def memory(self, spec: MemorySpec | None = None) -> Memory:
        """Declare a memory store: hybrid recall plus decay.

        A composition of two primitives already declared above, not a new
        subsystem -- which is the point.
        """
        spec = spec or MemorySpec()
        self.searchable(spec.search_spec())
        self.expiring(spec.expiry_spec())
        m = self._memory[spec.collection] = Memory(self, spec)
        return m

    # ---- one call builds everything declared ---------------------------

    async def ensure(self, *, search_wait_s: float = 90.0) -> dict:
        """Build every declared schema. Safe to call on every boot.

        Installed traits first, in declaration order. TTL next. Search last
        because it is the only step that *waits* -- indexes build
        asynchronously and querying one that is not ready returns zero rows
        rather than raising.
        """
        report: dict = {}
        for kind, items in self._installed.items():
            report[kind] = [
                coll for coll, trait in items.items() if await trait.ensure()
            ]
        report["ttl"] = await self.expiry.ensure()
        # After the traits: a sealing validator is applied to a collection
        # the keyring's own ensure() may have just created, and before
        # search, which is the step that waits.
        report["search_ready"] = await self.search_engine.ensure_indexes(
            wait_s=search_wait_s)
        return report

    # ---- access --------------------------------------------------------

    async def search(self, collection: str, vector, *, text=None,
                     limit: int = 5, filters=None) -> list[dict]:
        """Rank documents. **This is the primitive, not a read path.**

        It returns what the index ranked, which on a collection that refuses
        things is not the same as what may be returned: deadlines are
        deliberately not pushed into the vector index -- see ``search.py``
        for the measurements -- so a ``$vectorSearch`` hit has never been
        filtered by one.

        If the collection has an ``Admission`` handle, search *through it*:

            docs = engine.model("docs", tenant="t").forgettable()
            await docs.search(vector, text="P0301", limit=5)

        That applies the rules and refills the page. Calling this method
        directly is correct only when the collection has no admission policy,
        or when you are deliberately looking at what the index holds --
        ``tests/test_no_module_reaches_past_the_handle.py`` asserts no module
        in this package does the former by accident.
        """
        return await self.search_engine.query(
            collection, vector, text=text, limit=limit, filters=filters)

    @property
    def search_tier(self) -> str:
        return self.search_engine.tier

    # ---- work ----------------------------------------------------------

    def keyring(self, spec=None, *, custody=None, **kw):
        """The key vault for this engine. Idempotent, like every trait.

        One keyring per engine by default, because the key vault is a
        namespace and two of them would mean a scope's key depending on
        which handle asked. A second is possible by passing a spec with a
        different collection -- an explicit choice, which is the right
        weight for "this data is protected by different keys".

        Declaring more sealed collections merges into the existing spec
        rather than replacing it: ``model(...).sealed(...)`` twice on one
        engine is two collections under one vault, not the second quietly
        winning.
        """
        from .keyring import Keyring, KeyringSpec

        spec = spec or KeyringSpec()
        existing = self._installed.get("keyring", {}).get(spec.collection)
        if existing is not None:
            existing.spec.protect.update(spec.protect)
            return existing
        return self.use(Keyring(self.db, spec, custody=custody, **kw))

    def queue(self, collection: str, *, when: dict, **kw) -> JobQueue:
        return self.use(JobQueue(db=self.db, collection=collection, when=when, **kw))

    def admission(self, collection: str, *, at_field: str = "expire_at",
                   mark_field: str = "forgotten",
                   tenant: str | None = None,
                   lineage_field: str | None = None,
                   rules: tuple = ()) -> Admission:
        """A read handle for ``collection`` that refuses forgotten facts.

        Installed as a trait, so ``ensure()`` indexes the mark field and
        ``health()`` can report what it has refused.

        Idempotent per collection. ``use()`` replaces a trait of the same kind
        on the same collection, so handing out a second handle would orphan the
        first -- its refusals would still happen and would stop being counted,
        which is the one thing this primitive exists to prevent. A caller
        asking twice gets the same object.
        """
        # Normalised before comparison: the handle fills in the default
        # rules, so an un-defaulted spec would never equal a live one and
        # every second declaration would look like a conflict.
        spec = AdmissionSpec(collection, at_field=at_field,
                              mark_field=mark_field, tenant=tenant,
                              lineage_field=lineage_field,
                              rules=tuple(rules or ())).with_defaults()
        existing = self._installed.get("admission", {}).get(collection)
        if existing is not None:
            if existing.spec != spec:
                raise ValueError(
                    f"{collection} is already forgettable as "
                    f"{existing.spec.describe()}; refusing to redeclare it "
                    f"as {spec.describe()}. Two rules for one collection is "
                    f"how they drift -- and when they disagree about the "
                    f"tenant, whichever was declared first would silently "
                    f"decide whether the boundary is enforced at all")
            return existing
        return self.use(Admission(self.db, spec, engine=self))

    def ledger(self, collection: str = "refusals", *,
               tenant: str | None = None,
               key: bytes | str | None = None) -> Ledger:
        """An append-only hash chain of refusal events.

        Idempotent per collection, for the same reason ``admission()`` is: two
        handles on one chain is two writers who each believe they know where
        the head is.

        Attach it to a handle with ``Admission.witnessed_by()``. It is not
        installed automatically, because a ledger is a retention decision --
        this collection is the one thing here that deliberately never
        expires, and that is not a default anybody should get by accident.
        """
        existing = self._installed.get("ledger", {}).get(collection)
        if existing is not None:
            return existing
        return self.use(Ledger(self.db, LedgerSpec(collection, tenant=tenant),
                               key=key))

    # ---- introspection -------------------------------------------------

    async def aclose(self) -> None:
        """Release anything this engine opened on the caller's behalf.

        Only the keyring's encrypting client, today. It exists because the
        convenience of "the keyring owns the writer" has to come with a way
        to put it down -- a library that opens a connection you cannot
        close has traded one chore for a worse one.
        """
        for trait in self._installed.get("keyring", {}).values():
            await trait.aclose()

    def health(self) -> dict:
        """What a health endpoint should say, so a degraded deployment is
        visible to a probe instead of only showing up as worse results."""
        return {
            "mongodb": ".".join(str(p) for p in self.capabilities.version),
            "search": {
                "tier": self.search_tier,
                "indexes_ready": self.search_engine.ready,
                "degraded_searches": self.search_engine.degraded,
                "scope_refused": self.search_engine.scope_refused,
                "cosine_capped": self.search_engine.cosine_capped,
                # Indexes whose live definition stopped matching the spec and
                # could not be corrected. Non-empty means queries are running
                # against a definition the application no longer declares.
                "stale_indexes": list(self.search_engine.stale),
                # Who computes the vectors. `declined` means the deployment
                # could not, so the application still must -- the difference
                # between the two is a deployment fact, not a code path.
                "embedding_owner": {
                    "server": list(self.search_engine.auto_embed_active),
                    "client": list(self.search_engine.auto_embed_declined),
                },
            },
            # Refusal is a guarantee, so it is reported like one. A climbing
            # `revoked` count with no erasure requests behind it, or any
            # `unreadable` at all, is a question worth asking.
            "admission": [t.receipts()
                           for t in self._installed.get("admission", {}).values()],
            "change_streams": self.capabilities.change_streams,
            "time": {"tz": "UTC", "aware": True},
            "declared": {
                "models": sorted(self._models),
                "searchable": sorted(self.search_engine.specs),
                "expiring": sorted(s.collection for s in self.expiry.specs),
                "memory": sorted(self._memory),
                **{kind: sorted(items) for kind, items in self._installed.items()},
            },
        }


__all__ = [
    "Engine", "Capabilities", "detect",
    "SearchEngine", "SearchSpec", "cosine",
    "Expiry", "ExpirySpec",
    "Admission", "AdmissionSpec", "why_refused",
    "Rule", "Deadline", "Marked", "revoked", "quarantined",
    "DEADLINE", "REVOKED", "UNREADABLE", "QUARANTINED", "WRONG_MODEL",
    "LIFTED", "UNRECOVERABLE", "Unrecoverable",
    "REACHABLE", "REFUSED", "UNKNOWN", "KEY_UNAVAILABLE",
    "Keyring", "KeyringSpec", "Sealed", "Queryable",
    "Custody", "Ephemeral", "LocalFile", "Aws", "Azure", "Gcp", "Kmip",
    "NOT_CLEARED", "EmbeddedWith", "Clearance", "Restricted", "Page",
    "Memory", "MemorySpec",
    "Perimeter", "PerimeterLog", "Sink", "sink", "Acknowledgement",
    "compile_policy", "Denies", "PolicyInvalid",
    "SEALED", "OWNED", "DERIVED",
    "Model",
    "JobQueue", "PermanentFailure", "backoff",
    "Ledger", "LedgerSpec", "canonical", "digest", "GENESIS",
    "ScopeRequired", "ScopeInvalid", "ScopeError", "FilterInvalid",
    "CallerRequired", "Irreversible", "UnknownReason", "BlastRadius",
    "DerivationBroken",
    "UnboundedForgetting",
    "Trait", "kind_of", "collection_of",
    "now", "aware", "live", "living", "deadline", "bind", "UTC",
]
