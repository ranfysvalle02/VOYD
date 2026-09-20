"""What a read cost, and what a handle has refused.

Two objects with deliberately different strengths, and keeping them together
is the point: ``Page`` is exact for one read, ``Receipts`` is a lower bound
across a handle's life. Each says so in its own docstring, because a number
whose limits are not written down is a number somebody will put on a
compliance slide.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable

from ..time import now

@dataclass
class Receipts:
    """What was refused and revoked. The audit artifact, with its limits.

    ``refused`` counts documents this handle rejected *on the way out* -- the
    authoritative per-document check. It is deliberately a **lower bound**,
    and it is worth knowing why: most forgotten facts never reach the handle
    at all, because the same rule is pushed into the query and MongoDB drops
    them server-side. Counting those too would mean running every read twice.

    So this is a signal, not a ledger. A non-zero ``refused`` means documents
    are arriving at the boundary already forgotten -- which is normal for
    search hits (the vector index has no deadline filter) and suspicious for
    anything else. ``revoked`` is exact: every fact this handle made
    unreachable, counted at the moment it happened.
    """

    refused: dict[str, int] = field(default_factory=dict)
    revoked: int = 0
    # Counted apart from ``revoked``, because they mean opposite things to
    # whoever is reading the dashboard. A climbing ``revoked`` is erasure
    # working. A climbing ``held`` is a detector firing. A climbing
    # ``lifted`` is *people overruling the detector*, which is the number
    # that says a quarantine rule is mistuned -- and it is invisible if
    # every mark-shaped write lands in one counter.
    held: int = 0
    lifted: int = 0
    last_reason: str | None = None
    last_at: datetime | None = None

    def record(self, reason: str) -> None:
        self.refused[reason] = self.refused.get(reason, 0) + 1
        self.last_reason = reason
        self.last_at = now()

    def record_many(self, tally: dict[str, int]) -> None:
        """Commit one page's refusals.

        A refill re-admits a *superset* of the candidates it already saw, so
        recording as it goes would count the same forgotten document once per
        round -- inflating a number this class documents as a lower bound, in
        the one direction that makes a lower bound a lie. So a page is tallied
        locally and committed here, once, from the round that produced it.
        """
        for reason, n in tally.items():
            if n <= 0:
                continue
            self.refused[reason] = self.refused.get(reason, 0) + n
            self.last_reason = reason
            self.last_at = now()

    def record_write(self, kind: str, n: int, reason: str) -> None:
        """One forgetting write, counted under the outcome it produced.

        ``kind`` is ``revoked``, ``held`` or ``lifted`` -- the three state
        transitions a mark can undergo, rather than the rule that caused
        one. A third-party reversible reason therefore lands in ``held`` and
        ``lifted`` alongside quarantine, which is right: an operator reading
        this wants to know how much is being withheld and how much is being
        let back through, not which class implemented it.
        """
        if not n:
            return
        setattr(self, kind, getattr(self, kind) + n)
        self.last_reason = reason
        self.last_at = now()

    @property
    def total(self) -> int:
        return sum(self.refused.values())

    def as_dict(self) -> dict:
        return {
            # A lower bound: the query prunes most of these server-side.
            "refused_at_boundary": self.total,
            "refused_by_reason": dict(self.refused),
            # Exact: counted when it happened.
            "revoked_total": self.revoked,
            # Also exact, and deliberately three numbers rather than one:
            # erasing, withholding and re-admitting are different events
            # and a dashboard that adds them up says nothing.
            "held_total": self.held,
            "lifted_total": self.lifted,
            "last_reason": self.last_reason,
            "last_at": self.last_at.isoformat() if self.last_at else None,
        }


class Page(list):
    """The hits, and what it cost to get them.

    A ``list`` first, because every read path in this package already treats a
    result as one -- iterates it, compares it to ``[]``, slices it. A
    guarantee that forces a return-type migration on its own callers is a
    guarantee that gets reverted. The metadata rides along:

    ``refused``   what was dropped on the way out, by reason. Exact *for this
                  page*, unlike the handle-wide lower bound in ``receipts()``:
                  here the candidates were counted as they went past.
    ``examined``  how many candidates it took to fill the page. The cost of
                  enforcing on read rather than in the index, as a number.
    ``starved``   the page is short and the search **gave up before running
                  out of candidates**. That is the only state in which the
                  caller was told less than the truth.

    ``starved`` is the field worth wiring to an alert, and its definition is
    narrower than it first looks. It is not "short", and it is not "short and
    something was refused" -- that was the first definition here and it was
    wrong, and the deployment check shipped alongside it caught the mistake
    within the hour: it flagged a page that asked for 50, got 1, and was *complete*: one live document existed, the rest were
    expired, and nothing further down the ranking was being withheld. A short
    answer over an exhausted candidate list is the whole truth, however many
    refusals it took to establish. Flagging it would have trained whoever
    reads the field to ignore it, which costs more than not having it.

    So ``starved`` means: ``rounds`` ran out, or the search tier's own
    ceiling did, while candidates remained. There is more, and this page
    could not reach it -- the one thing a bare list cannot say.
    """

    __slots__ = ("refused", "examined", "starved")

    def __init__(self, hits: Iterable[dict] = (), *, refused: dict | None = None,
                 examined: int = 0, starved: bool = False):
        super().__init__(hits)
        self.refused: dict[str, int] = dict(refused or {})
        self.examined = examined
        self.starved = starved

    @property
    def refused_total(self) -> int:
        return sum(self.refused.values())

    def as_dict(self) -> dict:
        """The part of this a caller -- or a model -- should be told.

        Shaped for an answer, not a dashboard: ``refused`` as a list of
        ``{reason, count}`` because that is what reads out loud. An agent told
        "three facts exist and are quarantined" asks a human; an agent handed
        silence invents an answer.
        """
        return {
            "refused": [{"reason": r, "count": n}
                        for r, n in sorted(self.refused.items())],
            "refused_total": self.refused_total,
            "examined": self.examined,
            "starved": self.starved,
        }
