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

from typing import Any

from .authority import AuthorityRequired, Anyone, Grants, NotAuthorised
# Only ``report_assumptions`` -- it is called in ``describe()`` below. ``WORLD``
# and ``Assumption`` are deliberately not re-exported here: they are the
# vocabulary of the assumptions registry, and per
# ``tests/test_the_public_surface_is_deliberate.py`` a name that is not a
# promise should be imported from the module that owns it
# (``.assumptions``), which is what every caller already does.
from .capabilities import Capabilities, detect
from .errors import (
    BlastRadius,
    CallerRequired,
    ContextIncomplete,
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
                        OFF_SCOPE, UNNAMED,
                        OVER_BUDGET, QUARANTINED, REDUNDANT,
                        REACHABLE, REFUSED, REVOKED, UNCOSTED, UNKNOWN,
                        UNREADABLE, UNRECOVERABLE, WRONG_MODEL,
                        Budget, Clearance, Deadline, Distinct,
                        EmbeddedWith, Page,
                         Restricted,
                         Admission, AdmissionSpec, Marked, Unrecoverable,
                         quarantined, revoked, why_refused)
from .custody import Aws, Azure, Ephemeral, Gcp, Kmip, LocalFile
from .keyring import Keyring, KeyringSpec, Queryable, Sealed
from .model import Model
from .search import SearchEngine, SearchSpec, cosine
from .time import UTC, aware, bind, deadline, live, living, now
from .trait import collection_of, kind_of


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
        # Heterogeneous by construction: one sub-dict per trait kind, and an
        # Admission, a Ledger and a Keyring have almost nothing in common.
        # `object` was the strict-looking choice and the useless one -- it
        # made every read out of this registry an error at the point of use,
        # while proving nothing at the point of write. The type is re-
        # established by the accessor that knows which kind it asked for.
        self._installed: dict[str, dict[str, Any]] = {}
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
        self._refuse_sealed_autoembed()
        self._refuse_ungoverned_nesting()
        # After the traits: a sealing validator is applied to a collection
        # the keyring's own ensure() may have just created, and before
        # search, which is the step that waits.
        report["search_ready"] = await self.search_engine.ensure_indexes(
            wait_s=search_wait_s)
        return report

    # ---- access --------------------------------------------------------

    async def search(self, collection: str, vector, *, text=None,
                     limit: int = 5, filters=None,
                     candidates: int | None = None) -> list[dict]:
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
            collection, vector, text=text, limit=limit, filters=filters, candidates=candidates)

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

    def admission(self, collection: str, *, at_field: str = "expire_at",
                   mark_field: str = "forgotten",
                   tenant: str | None = None,
                   lineage_field: str | None = None,
                   policy_revision: str | None = None,
                   subjects: str | None = None,
                   subject_key: str | None = None,
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
                              policy_revision=policy_revision,
                              subjects=subjects, subject_key=subject_key,
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

    def _refuse_ungoverned_nesting(self) -> None:
        """A nested vector index on a collection that never named its subjects.

        Nested embeddings rank a **child** and return its **parent**, which
        quietly separates two things this package had always been able to
        treat as one: the unit of relevance and the unit of refusal. The
        boundary is handed the parent. A refused chapter inside an admitted
        book therefore reaches the prompt, is counted nowhere, and --
        the part that makes this worth failing a boot over -- is attested as
        *nothing was refused* by ``receipt_for``.

        Declaring ``subjects`` is what makes the boundary able to see
        children. Without it, indexing a nested path is asking for
        parent-granularity retrieval over child-granularity data, on a
        collection whose whole purpose is deciding what may reach a prompt.
        There is no safe default available here: admitting the parent whole
        is the bug, and withholding it for one child is not this library's
        choice to make silently. So it refuses, and names both declarations.

        Note it refuses at ``ensure()`` rather than on the read. By then the
        index is built and the erasure has already been answered wrongly
        once, and this is a *declaration* mistake -- two specs that do not
        agree about what a fact is -- which is exactly the class of thing
        that belongs at boot.
        """
        governed = self._installed.get("admission", {})
        for spec in self.search_engine.specs.values():
            paths = [p for p in (spec.vector_path, *spec.text_paths) if p]
            nested = [p for p in paths if "." in p]
            if not nested:
                continue
            handle = governed.get(spec.collection)
            if handle is None:
                continue          # no admission policy: nothing to disagree
            subjects = handle.spec.subjects
            if subjects is None:
                raise ValueError(
                    f"{spec.collection}: indexes a nested path "
                    f"({', '.join(nested)}) and refuses on read, but never "
                    f"declared subjects=. Nested retrieval ranks a child and "
                    f"returns its parent, so the boundary would be handed "
                    f"the parent and a refused child would reach the prompt "
                    f"inside it -- counted nowhere, and attested as 'nothing "
                    f"was refused'. Declare subjects='<array>' so the "
                    f"boundary can see them, or index a top-level path")
            wrong = [p for p in nested if p.split(".")[0] != subjects]
            if wrong:
                raise ValueError(
                    f"{spec.collection}: declares subjects={subjects!r} but "
                    f"indexes {', '.join(wrong)}. Retrieval would rank "
                    f"elements of one array while refusal governed another, "
                    f"and the two would disagree without either being wrong "
                    f"on its own terms")

    def _refuse_sealed_autoembed(self) -> None:
        """A field cannot be both hidden from the server and embedded by it.

        ``sealed()`` says: this field is ciphertext at rest and the server
        never holds the plaintext. ``auto_embed`` says: the server reads this
        field, sends it to an embedding endpoint over the network, and stores
        a vector derived from it. Declared together on the same path, those
        are not a trade-off, they are a contradiction, and both of its
        resolutions are bad:

        - mongot reads the CSFLE ``Binary`` and embeds *ciphertext*, so every
          vector is noise and retrieval silently returns nothing useful. The
          failure looks like bad relevance, which is the hardest kind to
          attribute.
        - or the field is not really sealed, and plaintext that a deployment
          chose this library to protect is shipped to a third-party endpoint
          -- a custody event that ``Perimeter.describe()`` cannot print,
          because the embedding provider was never registered as a holder.

        There is no third outcome, so this refuses at declaration rather than
        picking one. It is the same argument ``derive()`` makes about a
        refused parent: every available answer is wrong, so choose none and
        say why.

        Note what is *not* refused -- sealing a collection that auto-embeds a
        **different** field. Sealing the notes and embedding the title is a
        legitimate, if lossy, design, and this has no business forbidding it.
        """
        sealed: dict[str, set[str]] = {}
        for keyring in self._installed.get("keyring", {}).values():
            for collection, mode in getattr(keyring.spec, "protect", {}).items():
                sealed.setdefault(collection, set()).update(
                    getattr(mode, "fields", ()) or ())
        for spec in self.search_engine.specs.values():
            if not (spec.auto_embed and spec.text_paths):
                continue
            path = spec.text_paths[0]
            if path in sealed.get(spec.collection, ()):
                raise ValueError(
                    f"{spec.collection}: field {path!r} is sealed and also "
                    f"declared auto_embed={spec.auto_embed!r}. The server "
                    f"cannot both be denied this field and be asked to embed "
                    f"it: it would either embed the ciphertext -- vectors of "
                    f"noise, and a relevance failure nobody attributes -- or "
                    f"be handed the plaintext this deployment sealed it "
                    f"against, and ship it to an embedding endpoint no "
                    f"perimeter has registered. Embed a different field, or "
                    f"compute the vector in this process and drop "
                    f"auto_embed")

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
            # Uses recorded, and -- the number worth an alert -- uses that
            # happened and were not. A best-effort index dropping records is
            # an erasure worklist that will be quietly short.
            "context": [t.describe()
                        for t in self._installed.get("context", {}).values()],
            "change_streams": self.capabilities.change_streams,
            # What this engine believes about software it does not ship, and
            # how long ago anybody checked. Reported even when nothing is
            # stale: a deployment whose assumptions are fresh and one whose
            # assumptions have never been looked at are indistinguishable
            # unless the absence is printed.
            "time": {"tz": "UTC", "aware": True},
            "declared": {
                "models": sorted(self._models),
                "searchable": sorted(self.search_engine.specs),
                "expiring": sorted(s.collection for s in self.expiry.specs),
                **{kind: sorted(items) for kind, items in self._installed.items()},
            },
        }


# What this package promises, grouped by what a reader is trying to do.
#
# It is a promise rather than an inventory, and the difference is the point:
# a name here has to keep working, so putting one here is a decision and
# not a consequence of having written a class. Everything else in this
# package is still importable from the module that owns it -- the
# extension-point vocabulary lives in ``.authority`` and ``.trait``,
# internals in ``.capabilities``, ``.search`` and ``.jobs`` -- and is
# reachable without being guaranteed.
#
# ``tests/test_the_public_surface_is_deliberate.py`` pins this list, so
# growing it is a line in a diff somebody has to justify rather than a
# thing that happens.
__all__ = [
    # ---- the engine, and the clock it pins ----
    "Engine", "now", "deadline", "live", "living", "aware", "UTC", "cosine",

    # ---- declaring a collection ----
    "Admission", "AdmissionSpec", "Page", "why_refused",
    "SearchSpec", "ExpirySpec",

    # ---- reasons a fact may not reach a prompt: the rules you construct ----
    "Deadline", "Marked", "revoked", "quarantined",
    "Clearance", "Restricted", "EmbeddedWith", "Unrecoverable", "Budget",
    "Distinct",
    # ---- and the reasons you read back out of receipts() ----
    "DEADLINE", "REVOKED", "UNREADABLE", "QUARANTINED", "WRONG_MODEL",
    "NOT_CLEARED", "OFF_SCOPE", "UNRECOVERABLE", "KEY_UNAVAILABLE", "LIFTED",
    "REACHABLE", "REFUSED", "UNKNOWN", "OVER_BUDGET", "UNCOSTED", "UNNAMED",
    "REDUNDANT",

    # ---- proof ----
    # ---- what was said because of a fact ----
    # ---- encryption, and who holds the key that wraps the keys ----
    "Keyring", "KeyringSpec", "Sealed", "Queryable",
    "Ephemeral", "LocalFile", "Aws", "Azure", "Gcp", "Kmip",

    # ---- who may do this ----
    "Grants", "Anyone",

    # ---- who else holds a copy ----
    # ---- what you catch ----
    "ScopeError", "ScopeRequired", "ScopeInvalid", "FilterInvalid",
    "CallerRequired", "Irreversible", "UnknownReason", "BlastRadius",
    "ContextIncomplete",
    "UnboundedForgetting", "DerivationBroken", "NotAuthorised", "AuthorityRequired",
]
