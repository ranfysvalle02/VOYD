"""What the model was allowed to see, and what this handle has refused.

The chain proves a revocation happened. It cannot prove that the model call
which produced a given answer respected one -- and only the second is the
question an incident review asks. ``receipt_for`` commits to the policy state
that produced a context; ``receipts`` is the operational counter beside it.

Both are careful about what they do *not* claim, and those paragraphs are the
load-bearing part of this module.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any

from ..context import DIRECT, SOURCE, ContextRef, ContextUse
from ..errors import ContextIncomplete, ScopeInvalid, ScopeRequired
from ..ledger import GENESIS
from ..time import now


def _digest_of(body: dict) -> str:
    """The hash a context receipt commits to.

    Deliberately the *same* canonical form the ledger uses, rather than a
    second one that is nearly identical: two hashing schemes in one package
    is two ways to compute a value that must agree, and they will disagree
    the first time somebody adds a field to one.
    """
    from ..ledger import canonical
    return hashlib.sha256(canonical(body).encode("utf-8")).hexdigest()


class Attestation:
    """What the model was allowed to see, and what this handle has refused.

    Both methods are careful about what they do *not* prove, and those
    paragraphs are the point of the module.
    """

    # ---- what the model was allowed to see -----------------------------

    async def receipt_for(self, page, *, tenant: Any = None,
                          when: datetime | None = None) -> dict:
        """A hash over the policy state that produced this context.

        The chain proves a *revocation* happened. It cannot prove that the
        model call which produced a given answer respected one, and only
        the second is the question an incident review asks: **what did the
        model see when it said that?**

        Today the honest answer is a log line, and the party holding the
        log is the party being asked. So this commits to the four things
        that decide whether a context was legitimate:

        ``admitted``  the ids that reached the prompt.
        ``rules``     which reasons were in force, in order. A policy that
                      changed after the fact is otherwise invisible.
        ``chain``     the ledger head at read time, which dates the context
                      relative to every revocation ever recorded.
        ``at``        the instant the deadlines were evaluated against.

        Attach the hash to the inference. Recomputing it later needs no
        secret and no cooperation from this database -- which is the same
        property that makes the chain worth having, applied one layer up.

        **What it does not prove.** That the model was *given* this
        context, or only this context. Nothing on this side of the wire can
        establish that; the receipt binds a context to a policy, and the
        caller binds it to a generation by carrying it. Overstating that
        boundary would make this the kind of proof `ledger.py` spends forty
        lines refusing to claim.
        """
        head = None
        if self.ledger is not None:
            # The chain is per tenant, and the handle knows the tenant
            # *field* while only the documents know its value -- so it is
            # read off them rather than asking the caller to repeat
            # something the page already contains. An empty page with a
            # scoped ledger is the one case that cannot be resolved, and
            # it asks rather than guessing: a receipt naming the wrong
            # chain is worse than one that could not be issued.
            at_tenant = tenant
            if at_tenant is None and self.tenant:
                seen = {d.get(self.tenant) for d in page}
                seen.discard(None)
                if len(seen) > 1:
                    raise ScopeInvalid(self.collection, self.tenant,
                                       sorted(map(str, seen)))
                if not seen:
                    raise ScopeRequired(self.collection, self.tenant)
                at_tenant = seen.pop()
            entry = await self.ledger.head_entry(tenant=at_tenant)
            head = (entry or {}).get("hash", GENESIS)
        at = when or getattr(page, "evaluated_at", None) or now()
        body = {
            "collection": self.collection,
            "admitted": sorted((str(d.get("_id")) for d in page), key=str),
            "refs": [r.as_dict() for r in self._refs_of(page)],
            "rules": [r.reason for r in self.rules],
            "policy_revision": getattr(page, "policy_revision", None),
            "chain": head,
            "at": at.isoformat(),
            "refused": dict(getattr(page, "refused", {}) or {}),
            "snapshot_complete": bool(
                getattr(page, "snapshot_complete", False)),
        }
        return {**body, "hash": _digest_of(body)}

    def _refs_of(self, page) -> list[ContextRef]:
        """Every fact behind this page, typed by how it got there.

        ``direct`` is what was admitted. ``source`` is what those hits were
        made out of -- their ``lineage``, which is transitively closed at
        write time, so one pass over the page reaches every ancestor at any
        depth without a second query.

        Both kinds, and kept apart, because the two answer different
        questions after an incident. *Was this document in the prompt?* is
        the one that decides whether an answer has to be retracted. *Is this
        document upstream of something that was?* is the one that decides
        how far to look. A single flat list of ids would make the first
        question unanswerable from the record.

        A hit that is itself an ancestor of another hit stays ``direct``:
        it was read, and the weaker claim must not overwrite the stronger
        one.
        """
        direct = {str(d.get("_id")) for d in page}
        sources: set[str] = set()
        field = self.spec.lineage_field
        if field:
            for doc in page:
                sources.update(str(a) for a in (doc.get(field) or []))
        return [ContextRef(DIRECT, i) for i in sorted(direct)] + \
               [ContextRef(SOURCE, i) for i in sorted(sources - direct)]

    # ---- what was said because of it -----------------------------------

    async def record_use(self, page, *, consequence, tenant: Any = None,
                         when: datetime | None = None) -> ContextUse | None:
        """Record that this page produced a consequence outside this database.

        ``lineage`` already carries a refusal to the documents made out of a
        fact. This is the other half: the summary that left, the reply that
        was sent, the ticket that was filed. Nothing here can recall one --
        what this does is make it *findable*, so ``affected_by()`` can answer
        "we erased document 7; what did we already say because of it?" with a
        worklist instead of a shrug.

        ``consequence`` names the thing that was produced, as
        ``{"kind": ..., "id": ...}`` -- a ticket, a message id, a run id.
        Typed rather than a bare string because a worklist of forty opaque
        ids with no indication of *where* they are is not a worklist.

        **It refuses to persist a record it cannot stand behind**, and the
        four things it insists on are the four that make the record mean
        anything later:

        ``snapshot_complete``  the page has to be one this handle produced.
                               A plain ``list`` handed in from somewhere else
                               cannot say what instant it was admitted at, and
                               a use stamped with the wrong instant is worse
                               than an absent one -- it will exonerate a
                               context that was never checked.
        ``policy_revision``    ``over_budget`` does not say whether the budget
                               was 100 or 10000, and ``revoked`` does not say
                               which rule set was live. Declare one on the
                               model.
        the tenant             a use recorded outside the boundary is a use
                               the wrong subject can find.
        the consequence        a record of "something was produced" names
                               nothing and cannot be acted on.

        It is deliberately not silent about any of them. Every available
        fallback here is a record that reads as evidence and is not one, so
        this raises for the same reason ``derive()`` does.

        Recording a use **revokes nothing**, and revoking writes nothing
        here. See ``context.py`` for why the two stay apart.
        """
        if self.context is None:
            raise ContextIncomplete(
                self.collection, ("a context index",),
                "attach one with contextualized_by(engine.context_index(...))")
        missing = []
        if not getattr(page, "snapshot_complete", False):
            missing.append("a read snapshot")
        revision = getattr(page, "policy_revision", None)
        if not revision:
            missing.append("policy_revision")
        kind, subject = _named(consequence)
        if not (kind and subject):
            missing.append("a named consequence")
        if missing:
            raise ContextIncomplete(self.collection, tuple(missing))

        at_tenant = tenant
        if self.context.tenant and at_tenant is None:
            at_tenant = self._tenant_of(page)
        receipt = await self.receipt_for(page, tenant=at_tenant, when=when)
        return await self.context.record(ContextUse(
            collection=self.collection,
            consequence_kind=kind,
            consequence_id=subject,
            refs=tuple(ContextRef.of(r) for r in receipt["refs"]),
            policy_revision=revision,
            evaluated_at=page.evaluated_at,
            receipt=receipt["hash"],
            tenant=at_tenant))

    async def affected_by(self, source: Any, *, tenant: Any = None,
                          max_depth: int = 8) -> list[dict]:
        """What was already said because of this fact. The erasure worklist.

        Direct uses and everything downstream of them -- a consequence
        becomes a source the moment somebody works from it. See
        ``ContextIndex.affected_by`` for the walk.

        This is a *read*, and it does not refuse anything: the whole point
        is to ask it about a document that has just been revoked, and a
        lookup that applied the admission rules would answer "nothing" for
        exactly the fact somebody is investigating. It returns ids and
        hashes, never content, so there is nothing here to leak.
        """
        if self.context is None:
            raise ContextIncomplete(
                self.collection, ("a context index",),
                "attach one with contextualized_by(engine.context_index(...))")
        at_tenant = tenant
        if self.context.tenant and at_tenant is None and self.tenant:
            raise ScopeRequired(self.collection, self.tenant)
        return await self.context.affected_by(source, tenant=at_tenant,
                                              max_depth=max_depth)

    def _tenant_of(self, page) -> Any:
        """The one tenant this page belongs to, read off the documents.

        The same resolution ``receipt_for`` does, and for the same reason:
        the handle knows the tenant *field* and only the rows know the
        value. An empty page cannot answer, and asks rather than guessing.
        """
        if not self.tenant:
            return None
        seen = {d.get(self.tenant) for d in page}
        seen.discard(None)
        if len(seen) > 1:
            raise ScopeInvalid(self.collection, self.tenant,
                               sorted(map(str, seen)))
        if not seen:
            raise ScopeRequired(self.collection, self.tenant)
        return seen.pop()

    # ---- proof ---------------------------------------------------------

    def receipts(self) -> dict:
        """What this handle has refused, and why.

        Two numbers with different strengths, and the difference is the
        honest part. ``revoked_total`` is exact. ``refused_at_boundary`` is a
        lower bound -- the same rule runs inside the query, so most forgotten
        facts are dropped by MongoDB and never counted here. Counting them
        would mean issuing every read twice.

        Read them as signals: a climbing ``unreadable`` means something is
        writing deadlines it should not, and a ``revoked_total`` with no
        erasure request behind it is worth a question.
        """
        return {"collection": self.collection,
                "policy": self.spec.describe(),
                **self.receipts_log.as_dict()}


def _named(consequence: Any) -> tuple[str | None, str | None]:
    """The (kind, id) out of whatever the caller passed, or ``(None, None)``.

    Tolerant about the container -- a dict, or anything with the two
    attributes -- and strict about the contents, because the caller-facing
    error is better raised once in ``record_use`` with the other three
    missing pieces beside it than three times here.
    """
    if isinstance(consequence, dict):
        kind, subject = consequence.get("kind"), consequence.get("id")
    else:
        kind = getattr(consequence, "kind", None)
        subject = getattr(consequence, "id", None)
    if not isinstance(kind, str) or not kind.strip():
        return None, None
    if subject is None or (isinstance(subject, str) and not subject.strip()):
        return None, None
    return kind, str(subject)
