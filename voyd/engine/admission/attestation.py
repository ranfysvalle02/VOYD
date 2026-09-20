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

from ..errors import ScopeInvalid, ScopeRequired
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
        body = {
            "collection": self.collection,
            "admitted": sorted((str(d.get("_id")) for d in page), key=str),
            "rules": [r.reason for r in self.rules],
            "chain": head,
            "at": (when or now()).isoformat(),
            "refused": dict(getattr(page, "refused", {}) or {}),
        }
        return {**body, "hash": _digest_of(body)}

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
