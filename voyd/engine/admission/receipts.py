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
    # Counted apart again, because it is a different kind of event: not a
    # fact being withheld or let back, but the guarantee itself being set
    # aside. ``including_refused()`` is break-glass, and a break-glass read
    # that logs nothing is a break-glass read nobody reviews.
    bypassed: int = 0
    # What the search path actually threw away, and the only place in this
    # package where the refusal count is *exact* rather than a floor: a
    # `$vectorSearch` hit passes through no query, so every candidate is
    # counted here or admitted.
    #
    # Kept apart from ``refused`` because these two numbers answer different
    # questions. ``refused`` is "is something wrong?". These are "how much
    # does this collection over-fetch?", which is the input to sizing the
    # candidate pool -- see ``over_fetch()``.
    examined: int = 0
    admitted: int = 0
    last_bypass_actor: str | None = None
    last_bypass_at: datetime | None = None
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

    def record_bypass(self, *, actor: str | None = None) -> None:
        """One terminal read through an ``including_refused()`` handle.

        Counted once per read, not once per document and not once per handle
        construction -- the question a dashboard has is "how often was the
        guarantee set aside", and a cached handle must not turn one event into
        unlimited reads. Exact, because unlike ``refused`` there is no
        server-side half that gets away uncounted. Actor/time ride beside the
        count so the alarm names the last hand on the door when an authority
        knows it.
        """
        self.bypassed += 1
        self.last_bypass_actor = actor
        self.last_bypass_at = now()

    @property
    def total(self) -> int:
        return sum(self.refused.values())

    def observe(self, examined: int, admitted: int) -> None:
        """Record one search's arithmetic. Called by the read path only."""
        self.examined += max(0, int(examined))
        self.admitted += max(0, int(admitted))

    def over_fetch(self, *, floor: float = 1.0, ceiling: float = 12.0,
                   minimum_sample: int = 50) -> float:
        """How many candidates to ask for per document you want back.

        The number nobody else can compute. An index cannot: it does not know
        your deadline, so it cannot know what fraction of what it ranks is
        already gone. A driver cannot. The **only** component that knows how
        many candidates get thrown away is the one throwing them away, which
        makes sizing the candidate pool a boundary concern rather than a
        tuning parameter somebody guesses in a config file.

        Refuse half of what arrives and you must ask for twice as many to
        come back with a full page -- so the factor is ``1 / (1 - rate)``,
        which is the expected over-fetch exactly and not an approximation.

        Three guards, each against a way this could make things worse:

        - **a minimum sample**, because one refusal in the first read would
          otherwise triple the pool for a collection that is perfectly
          healthy;
        - **a ceiling**, because a scope where almost everything is forgotten
          would otherwise ask for a pool the size of the collection, turning
          a cheap wrong answer into an expensive one;
        - **a floor of 1.0**, because this may only ever *raise* the ask. It
          is an optimisation on top of refill, never a replacement for it:
          refill is what makes the page correct, and this is what stops it
          needing three round trips to get there.
        """
        if self.examined < minimum_sample or self.admitted <= 0:
            return floor
        rate = 1.0 - (self.admitted / self.examined)
        if rate <= 0:
            return floor
        return max(floor, min(ceiling, 1.0 / (1.0 - rate)))

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
            # Exact: how many times the guarantee was deliberately set aside
            # through ``including_refused()``. Not prevented, but visible.
            "including_refused_total": self.bypassed,
            # The search path's own arithmetic, and the input to sizing the
            # candidate pool. Exposed because a caller who sees a climbing
            # over-fetch is looking at the cost of their own refusal rate,
            # which is a tuning conversation rather than a bug.
            "search_examined": self.examined,
            "search_admitted": self.admitted,
            "over_fetch": round(self.over_fetch(), 2),
            "last_including_refused_actor": self.last_bypass_actor,
            "last_including_refused_at": (
                self.last_bypass_at.isoformat()
                if self.last_bypass_at else None),
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
    ``spent``     budget charged to the selected page prefix when a ``Budget``
                  rule is in force (``0`` otherwise). Over-fetched candidates
                  below a full page are never charged. A selected document
                  whose key later proves unrecoverable may still have reserved
                  room, deliberately conservative: decryption happens after
                  selection and a missing key does not make the prompt budget
                  available to a lower-ranked hit retroactively.
    ``redacted``  how many *embedded subjects* were removed from documents on
                  this page -- a chapter inside an admitted book, a comment
                  inside an admitted ticket. Zero unless the collection
                  declared ``subjects``. It is reported separately from
                  ``refused`` because the two are different events with the
                  same reason attached: a document that never arrived, versus
                  a document that arrived shorter than it is on disk. Only the
                  second one changes what a caller is holding without changing
                  the length of the page, which is exactly the kind of quiet
                  edit that has to be counted out loud.
    ``starved``   the page is short and the search **gave up before running
                  out of candidates**. That is the only state in which the
                  caller was told less than the truth. A page cut short by a
                  spent budget is *not* starved: it is complete, because
                  nothing further down the ranking had room anyway.

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

    Three more fields exist for one reason: a use recorded against this page
    (see ``record_use``) has to commit to *when* the policy was evaluated and
    *which* policy it was, and it must refuse to persist a page that cannot
    say. So a read stamps them, and a plain ``list`` handed in from somewhere
    else has none of them and cannot be recorded as a use.

    ``evaluated_at``       the single instant this whole page was admitted
                           against -- frozen once at the start of the read, not
                           re-read per candidate, so every hit on the page
                           agrees about what "now" was.
    ``policy_revision``    the revision string the handle was declared with, or
                           ``None``. ``over_budget`` does not say whether the
                           budget was 100 or 10000; a revision does.
    ``snapshot_complete``  whether this page carries a read snapshot at all. A
                           bare ``list`` degrades to ``False``, which is what
                           makes "incomplete pages cannot be persisted" a check
                           rather than a hope.
    """

    __slots__ = ("refused", "examined", "starved", "spent", "redacted",
                 "evaluated_at", "policy_revision", "snapshot_complete")

    def __init__(self, hits: Iterable[dict] = (), *, refused: dict | None = None,
                 examined: int = 0, starved: bool = False, spent: int = 0,
                 redacted: int = 0,
                 evaluated_at: datetime | None = None,
                 policy_revision: str | None = None,
                 snapshot_complete: bool = False):
        super().__init__(hits)
        self.refused: dict[str, int] = dict(refused or {})
        self.examined = examined
        self.starved = starved
        self.spent = spent
        self.redacted = redacted
        self.evaluated_at = evaluated_at
        self.policy_revision = policy_revision
        self.snapshot_complete = snapshot_complete

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
            "spent": self.spent,
            "redacted": self.redacted,
            "starved": self.starved,
        }
