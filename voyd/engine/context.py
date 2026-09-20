"""Which answers were made out of which facts, so an erasure can find them.

``Admission`` refuses a fact on the way out, and ``lineage`` carries that
refusal to the documents made out of it. Both of those live *inside this
database*. The thing an erasure request actually has to reach usually does
not: a summary in a ticket, a paragraph in an email, an embedding shipped to
a fine-tune, an answer already sitting in a customer's inbox.

    ``lineage``   a fact was used to write another fact **here**. The mark
                  travels, because the derived row is subject to the same
                  read path.
    ``context``   a fact was used to produce a consequence **out there**.
                  Nothing here can un-send it. What this can do is *name*
                  it, in the one place somebody will look.

So this is an index, not an enforcement point, and the distinction is the
whole design. Recording a use revokes nothing; revoking a fact writes
nothing here. Wiring the two together is tempting and wrong in both
directions: an erasure that has to update a use index cannot complete while
the index is down, and a use index that is maintained by the erasure path
only knows about facts that have already been erased. Refusal stays
immediate and local; this stays a lookup that is correct whenever it is
asked. ``affected_by()`` is the question -- *"we just erased document 7;
what did we already say because of it?"* -- and the answer is a worklist for
a human, not an action this package takes.

**What a record contains, and what it must never contain.** Ids, hashes, a
policy revision, two instants. No text, ever -- not the document's, not the
consequence's. The argument is the ledger's, one layer up: an index that
quotes the paragraph it was asked to forget is a *new copy* of that
paragraph, living in a collection whose whole purpose is to outlive the
one it came from. ``_only_ids`` enforces that rather than trusting it.

**Retention is explicit, because this collection is the awkward one.** A
use index is most valuable exactly when it is oldest, and it is a record of
processing that a subject can ask about. Neither argument obviously wins,
which is precisely why this does not pick: ``ContextIndexSpec`` has no
default ``retain`` and construction fails without one. Somebody types out
how long they keep it, and that line is the decision.

**Failure is loud by default.** ``record()`` raises when it cannot write,
because a use that was not recorded is a consequence that ``affected_by()``
will silently fail to name -- and silence from this index reads exactly like
"nothing was affected". A deployment that would rather serve the request
than record the use can say so with ``best_effort=True``, and then the
number of records it dropped is on ``describe()`` where a probe can see it.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Iterable

from .errors import SCALAR_ID, ScopeRequired
from .ledger import canonical
from .time import aware, now

log = logging.getLogger("engine.context")

# What a ref says about *how* a fact reached the consequence. Two kinds,
# and they are not interchangeable to whoever reads the answer:
#
#   direct  the document was on the page. It was admitted, at a named
#           instant, under a named policy, and the consequence was produced
#           from that page.
#   source  the document is an ancestor of something on the page -- it is
#           in a hit's ``lineage``. It was not itself read here, and it is
#           still upstream of what was said.
#
# Collapsing them would make "this fact was in the prompt" and "this fact is
# somewhere behind something that was in the prompt" the same claim, and the
# first one is the one an incident review can act on.
DIRECT = "direct"
SOURCE = "source"


@dataclass(frozen=True)
class ContextRef:
    """One fact, and how it reached the consequence.

    Typed rather than a bare id because the kind is load-bearing and a
    two-element tuple is how it gets dropped. Compared by value, so
    deduplicating a page's refs is a ``set``.
    """

    kind: str
    id: str

    def __post_init__(self) -> None:
        if self.kind not in (DIRECT, SOURCE):
            raise ValueError(
                f"a context ref is {DIRECT!r} or {SOURCE!r}, not "
                f"{self.kind!r}. 'it was read' and 'it is upstream of "
                f"something that was read' are different claims")

    def as_dict(self) -> dict:
        return {"kind": self.kind, "id": self.id}

    @classmethod
    def of(cls, value: Any) -> ContextRef:
        """Accept what a receipt carries -- a dict -- or an already-typed ref."""
        if isinstance(value, ContextRef):
            return value
        if isinstance(value, dict) and set(value) == {"kind", "id"}:
            return cls(str(value["kind"]), str(value["id"]))
        raise TypeError(
            f"a context ref is {{'kind': ..., 'id': ...}}, got {value!r}")


@dataclass(frozen=True)
class ContextUse:
    """One consequence, and the facts it was made out of.

    Frozen and hashed by its own content: ``use_id`` is a digest over every
    field below, so recording the same use twice is the same document and
    the second write is a no-op. That is not an optimisation. A retry after
    a timeout is the ordinary case -- the write may well have landed -- and
    an index that counted it twice would answer "how many things did we say
    because of this fact" with a number that grows on network weather.
    """

    collection: str
    consequence_kind: str
    consequence_id: str
    refs: tuple[ContextRef, ...]
    policy_revision: str
    evaluated_at: datetime
    receipt: str
    tenant: Any = None
    recorded_at: datetime = field(default_factory=now)

    @property
    def use_id(self) -> str:
        """The record's identity, and the reason recording is idempotent.

        Hashed over the same canonical form the ledger uses, for the reason
        stated there: two nearly-identical hashing schemes in one package is
        two ways to compute a value that has to agree.

        ``recorded_at`` is deliberately **not** in it. It is when we wrote
        the record, not anything about the use, and including it would make
        every retry a new identity -- which is the entire failure this
        property exists to prevent.
        """
        return hashlib.sha256(canonical({
            "collection": self.collection,
            "tenant": self.tenant,
            "consequence": [self.consequence_kind, self.consequence_id],
            "refs": [[r.kind, r.id] for r in self.refs],
            "policy_revision": self.policy_revision,
            "evaluated_at": self.evaluated_at,
            "receipt": self.receipt,
        }).encode("utf-8")).hexdigest()

    def as_dict(self) -> dict:
        return {
            "use_id": self.use_id,
            "collection": self.collection,
            "consequence": {"kind": self.consequence_kind,
                            "id": self.consequence_id},
            "refs": [r.as_dict() for r in self.refs],
            "policy_revision": self.policy_revision,
            "evaluated_at": self.evaluated_at.isoformat(),
            "receipt": self.receipt,
            "recorded_at": self.recorded_at.isoformat(),
        }


@dataclass(frozen=True)
class ContextIndexSpec:
    """Where uses are kept, for how long, and under whose boundary.

    ``retain`` has no default on purpose -- see the module docstring. It is
    the one field here that is a policy rather than a layout, and a default
    would mean nobody ever decided.
    """

    retain: timedelta
    collection: str = "context_uses"
    tenant: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.retain, timedelta) or \
                self.retain <= timedelta(0):
            raise ValueError(
                f"{self.collection}: retain= must be a positive timedelta. "
                f"How long a record of 'we said this because of that' is "
                f"kept is a retention decision, and this package does not "
                f"get to make it quietly -- type it out")

    def describe(self) -> str:
        scope = f", scoped by {self.tenant}" if self.tenant else ""
        return (f"{self.collection}: keeps uses for {self.retain}{scope}")


class ContextIndex:
    """Which consequences were made out of which facts. A trait.

    ``ensure()`` builds three indexes and a TTL, and each is load-bearing
    rather than an optimisation -- see the method.

    Attach it to a handle with ``Admission.contextualized_by()``. Not
    installed automatically, because keeping a record of every use is a
    retention decision and retention decisions get typed out.
    """

    kind = "context"

    def __init__(self, db, spec: ContextIndexSpec, *,
                 best_effort: bool = False):
        self.db = db
        self.spec = spec
        self.collection = spec.collection
        self.tenant = spec.tenant
        # Loud by default. See the module docstring for why silence from
        # this index is the dangerous failure.
        self.best_effort = best_effort
        self.recorded = 0
        self.duplicates = 0
        self.dropped = 0

    # ---- schema --------------------------------------------------------

    async def ensure(self) -> bool:
        """The reverse lookup, the forward lookup, and the deadline.

        ``ref_ids`` is a flattened multikey copy of ``refs``. Storing the
        ids twice is deliberate: a multikey index on an array of
        *subdocuments* cannot serve ``{"refs.id": {"$in": [...]}}`` as
        cheaply, and ``affected_by()`` is one ``$in`` per hop. An index that
        is a scan is an index somebody stops using, and the thing they would
        stop using is the answer to "what did we already say about this".

        The TTL is the spec's ``retain``, expressed as a per-document
        ``expire_at`` rather than a collection-wide ``expireAfterSeconds``:
        the rest of this engine puts the deadline on the document, and one
        collection reasoning about retention differently is how the two
        drift.
        """
        scope = [self.tenant] if self.tenant else []
        await self.db[self.collection].create_index(
            [(f, 1) for f in scope] + [("ref_ids", 1)], name="uses_of_source")
        await self.db[self.collection].create_index(
            [(f, 1) for f in scope] + [("consequence.id", 1)],
            name="uses_by_consequence")
        await self.db[self.collection].create_index(
            "expire_at", expireAfterSeconds=0, name="context_retention")
        return True

    # ---- recording -----------------------------------------------------

    def _scope(self, tenant: Any) -> dict:
        if not self.tenant:
            return {}
        if tenant is None:
            raise ScopeRequired(self.collection, self.tenant)
        return {self.tenant: tenant}

    @staticmethod
    def _only_ids(use: ContextUse) -> None:
        """Refuse anything that is not an id, a hash or an instant.

        The check this module would be worthless without, and the one it
        would be easiest to leave as a comment. A consequence id is supplied
        by the caller, and the convenient thing for a caller to pass is the
        answer itself -- so the guard is here, at the write, rather than in
        the docstring where it started.
        """
        suspects: list[tuple[str, Any]] = [
            ("consequence.id", use.consequence_id),
            ("consequence.kind", use.consequence_kind),
            *((f"refs[{i}].id", r.id) for i, r in enumerate(use.refs)),
        ]
        for name, value in suspects:
            if not isinstance(value, SCALAR_ID):
                raise ValueError(
                    f"{name} is a {type(value).__name__}; a context record "
                    f"holds ids, not content")
            if isinstance(value, str) and ("\n" in value or len(value) > 256):
                raise ValueError(
                    f"{name} is {len(value)} characters and looks like text, "
                    f"not an id. This index must never become a second copy "
                    f"of the thing it was asked to help forget -- name the "
                    f"consequence (a ticket, a message id, a run id) and "
                    f"keep its body where it already lives")

    async def record(self, use: ContextUse) -> ContextUse | None:
        """Write one use. Idempotent, and loud unless told otherwise.

        Returns the use on success -- including when it was already there,
        because "already recorded" is success -- and ``None`` only when a
        ``best_effort`` index swallowed a failure. A caller that checks the
        return value therefore sees exactly the case it needs to see.
        """
        self._only_ids(use)
        scope = self._scope(use.tenant)
        row = {
            "_id": use.use_id,
            **scope,
            "collection": use.collection,
            "consequence": {"kind": use.consequence_kind,
                            "id": use.consequence_id},
            "refs": [r.as_dict() for r in use.refs],
            # Flattened for the reverse lookup. See ``ensure``.
            "ref_ids": sorted({r.id for r in use.refs}),
            "policy_revision": use.policy_revision,
            "evaluated_at": aware(use.evaluated_at),
            "receipt": use.receipt,
            "recorded_at": aware(use.recorded_at),
            "expire_at": aware(use.recorded_at) + self.spec.retain,
        }
        try:
            await self.db[self.collection].insert_one(row)
        except Exception as exc:  # noqa: BLE001 - classified below
            if _is_duplicate(exc):
                # The same use, written twice. Not a failure: the identity
                # is the content, so the record already on disk is this one.
                self.duplicates += 1
                return use
            self.dropped += 1
            if not self.best_effort:
                raise
            log.warning("context use %s not recorded (best effort): %s",
                        use.use_id[:12], exc)
            return None
        self.recorded += 1
        return use

    # ---- lookup --------------------------------------------------------

    async def uses_of(self, ids: Iterable, *, tenant: Any = None) -> list[dict]:
        """Every use naming one of these ids, directly or as a source.

        One query, whatever the size of the list -- which is what makes the
        walk in ``affected_by`` affordable.
        """
        ids = sorted({str(i) for i in ids})
        if not ids:
            return []
        query = {**self._scope(tenant), "ref_ids": {"$in": ids}}
        return [d async for d in self.db[self.collection].find(query)]

    async def affected_by(self, source: Any, *, tenant: Any = None,
                          max_depth: int = 8) -> list[dict]:
        """What was said because of this fact -- directly and downstream.

        Breadth-first, because a consequence becomes a source: an agent
        summarises document 7 into ticket A, and next week writes reply B
        after reading ticket A. Erasing 7 has to reach B, and B names only A.
        So each hop takes the consequence ids found so far and asks again.

        ``max_depth`` is a stop, not a tuning knob. Derivation here is a DAG
        the same way ``lineage`` is -- a consequence is recorded after the
        facts it was made from -- so the walk terminates on its own. The
        bound exists because this index accepts consequence ids from outside
        this database, and a caller that records a cycle should get a
        truncated worklist rather than a hung erasure request. It is
        reported, not swallowed: see ``truncated`` on each hop's rows.

        Returns the use records, most direct first, deduplicated by id.
        Ordinary dicts rather than ``ContextUse`` objects: this is a
        worklist somebody serialises into a ticket, and rehydrating the
        typed form to immediately call ``as_dict`` on it would be ceremony.
        """
        frontier = {str(source)}
        seen_refs: set[str] = set()
        found: dict[str, dict] = {}
        for depth in range(max_depth):
            frontier -= seen_refs
            if not frontier:
                break
            seen_refs |= frontier
            rows = await self.uses_of(frontier, tenant=tenant)
            next_frontier: set[str] = set()
            for row in rows:
                row = {**row, "depth": depth}
                found.setdefault(row["_id"], row)
                next_frontier.add(str(row["consequence"]["id"]))
            frontier = next_frontier
        else:
            if frontier - seen_refs:
                log.warning("affected_by(%s) stopped at depth %d with %d "
                            "unexplored id(s)", source, max_depth,
                            len(frontier - seen_refs))
        return sorted(found.values(), key=lambda r: (r["depth"], r["_id"]))

    # ---- introspection -------------------------------------------------

    def describe(self) -> dict:
        """What a health endpoint should say about this index.

        ``dropped`` is the number worth an alert, and it is only ever
        non-zero on a ``best_effort`` index: it counts uses that happened
        and were not recorded, which is precisely the set of consequences
        ``affected_by()`` will not name.
        """
        return {
            "collection": self.collection,
            "policy": self.spec.describe(),
            "recorded": self.recorded,
            "duplicates": self.duplicates,
            "best_effort": self.best_effort,
            "dropped": self.dropped,
        }


def _is_duplicate(exc: Exception) -> bool:
    """A duplicate ``_id``, however the driver chose to report it.

    Matched on the server's error code rather than the exception class,
    because ``insert_one`` and a bulk write raise different types for the
    same condition and this has to be right for both -- a misclassified
    duplicate is either a spurious raise on a retry, or a real write error
    counted as a success.
    """
    code = getattr(exc, "code", None)
    if code == 11000:
        return True
    details = getattr(exc, "details", None) or {}
    if details.get("code") == 11000:
        return True
    return any(e.get("code") == 11000
               for e in details.get("writeErrors", []) or [])
