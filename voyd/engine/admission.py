"""Admission as a retrieval guarantee, not a storage event.

Every database can delete. None of them can *refuse*. That distinction is the
whole point of this module:

    deletion  is a storage operation -- eventually consistent, by nature.
              A TTL monitor sweeps about once a minute. An object lifecycle
              rule runs about once a day. A cron runs when it last worked.

    refusal   is a retrieval guarantee -- immediate, by construction.
              "This fact may not reach a prompt", answered on every read,
              before anything is returned.

Nobody ships the second one, so the honest answer to "when was this
forgotten?" is really "when did the sweeper get to it?" -- and in the gap
between those two, a deleted document is still being returned as a
well-scored result.

Re-checking a deadline on the way out is not hard, and an application that
knows to do it will do it correctly in the read path it was thinking about
when it learned the lesson. Then it grows a second read path, and a fifth,
and the rule is only as good as the next author's memory. A guarantee that
must be remembered is not enforced, it is suggested.

So this makes refusal structural. ``Admission`` is a read handle, and every
read through it refuses forgotten facts. There is no "remember to filter"
step, because there is no unfiltered ``find`` to reach for. Seeing everything
remains possible -- audit and administration need it -- but it has a name a
reviewer can grep for:

    await docs.find({"owner": who})                        # reachable only
    await docs.including_refused().find({"owner": who})  # deliberate

The failure mode is inverted. Before, you had to remember to be safe. Now you
have to declare that you want the unsafe thing.

**Two enforcement points, always both.** The rule is pushed into the query
where the query can express it (cheap: the database does the work) *and*
re-checked per document on the way out (authoritative). That is not
belt-and-braces paranoia. A vector index cannot filter on a deadline without
an unmigratable index change -- see ``search.py`` for the measurements -- so
hits arriving from ``$vectorSearch`` have never been filtered by anything.
``reachable()`` is what a search path calls, and it is the guarantee; the
query clause is the optimisation.

**More than one reason to forget.** A deadline is only the common one:

- ``deadline``    -- the expiry field has passed. Pinning is its absence.
- ``revoked``     -- somebody said forget this, now. A subject erasure
  request, a leaked credential, a retracted document. Unreachable on the next
  read, whatever the sweeper is doing, and without waiting for it.
- ``unreadable``  -- a deadline that is not a date, or cannot be compared.
  Fails closed: a fact whose lifetime cannot be established has no business
  in a prompt.

Plus pinning, the absence of all three. Every case collapses to one question
-- *may this reach a prompt?* -- answered in one place.

**Refusals are counted, with their limits stated.** ``receipts()`` reports
what was refused and why. ``revoked_total`` is exact. ``refused_at_boundary``
is a lower bound and is named so, because the same rule runs inside the query
and the database drops most forgotten facts server-side; counting those would
mean issuing every read twice. A signal, not a ledger.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Any, Iterable, Protocol

from .errors import (BlastRadius, CallerRequired, DerivationBroken,
                     Irreversible, ScopeRequired, UnboundedForgetting,
                     UnknownReason, require_tenant)
from .time import aware, living, now

log = logging.getLogger("engine.admission")

# Why a fact was refused. Stable strings: they are counted, logged, and end up
# in an operator's dashboard.
DEADLINE = "deadline"
REVOKED = "revoked"
UNREADABLE = "unreadable"
QUARANTINED = "quarantined"
WRONG_MODEL = "wrong_model"
# Not a reason a fact was *forgotten* -- a reason this caller may not have it.
# Counted separately for that reason: a climbing `not_cleared` is somebody
# probing, while a climbing `deadline` is the system working.
NOT_CLEARED = "not_cleared"
# The key that encrypted this document was destroyed, so there is no read
# path anywhere -- here, in a replica, or in a backup restored next year --
# that can produce the plaintext. Reported apart from ``revoked`` because it
# is a strictly stronger statement: revoked says this application will not
# serve it, unrecoverable says nobody can.
UNRECOVERABLE = "unrecoverable"

# Not a reason at all -- the chain event for the inverse of one. Every
# imposition is recorded under the reason imposed ("revoked", "quarantined"),
# so a single event name for every removal is what lets an auditor ask the
# question they actually have -- *did anything get un-refused?* -- with one
# scan instead of one per reason. Which rule was lifted rides in ``detail``.
LIFTED = "lifted"

# How many ids ``lift()`` unsets per round trip. It materialises ids rather
# than issuing one filter-wide update -- see ``Admission.lift`` for why the
# per-document check is not optional on that particular write -- and an id
# list is a query, so it is chunked rather than trusted to stay small.
LIFT_BATCH = 1000


# ---- rules -------------------------------------------------------------
#
# A rule answers one question about one document: is there a reason this may
# not reach a prompt? The handle owns *that* there is an answer on every
# read; a rule owns *what* the answer is. Adding a reason is therefore a new
# rule rather than a new branch in a predicate that keeps growing.
#
# Two halves, and both are optional to get right in the same way:
#
#   refuses(doc)  the authoritative check, per document, on the way out.
#                 Must never raise: an exception inside a filter is how the
#                 filter gets skipped.
#   clause()      the same rule as a query fragment, or None when it cannot
#                 be expressed server-side. An optimisation, never the
#                 guarantee -- search hits never went through a query.


class Rule(Protocol):
    """One reason a document may not reach a prompt.

    Three optional class attributes change how a rule is treated, and all
    three default to the behaviour of the original rules:

    ``needs_caller``  the rule compares the document against *who is asking*,
                      so it is handed the caller's claims. A rule without it
                      is never passed them, which keeps the ordinary rules
                      free of a parameter they have no use for.
    ``bypassable``    whether ``including_refused()`` sets this rule aside.
                      True for reasons a fact is *forgotten* -- audit and
                      administration exist to see those. False for reasons a
                      *caller* may not see it, which are not this handle's to
                      waive: an auditor is entitled to read what was
                      forgotten, and entitled to nothing above their own
                      clearance.
    ``reversible``    present *at all* means somebody imposes this reason
                      with a verb -- it reads a mark on ``field`` that an
                      operator sets. Its value says whether that verb has an
                      inverse. Rules that are simply true of a document --
                      a passed deadline, an unrecognised clearance label, a
                      vector from the wrong model -- do not declare it, and
                      ``impose()``/``lift()`` will not target them.

    That last one carries the reversibility policy of the whole system, so
    it is worth saying why it lives on the rule rather than on the verb.

    ``Marked`` is one class serving two operationally opposite jobs. A
    *revocation* is an instruction about the world -- erase this -- and must
    not be undoable. A *quarantine* is a hypothesis -- hold this while
    somebody looks -- and must be, or the feature is a graveyard. Those two
    also want opposite treatment of the bytes: a revocation stamps the erase
    deadline so the reaper collects the row, a quarantine must not, because
    the row is the evidence.

    That coupling used to live in the caller of ``revoke()``, which meant the
    next ``Marked`` reason somebody added got whichever half its author
    happened to remember. This module's own complaint, two hundred lines up,
    is that a guarantee which must be remembered is not enforced but
    suggested. So the reason declares its own reversibility, the verb reads
    it, and "can this be taken back?" is answerable by looking at the rule
    instead of by reading the method that writes it.
    """

    reason: str
    needs_caller: bool
    bypassable: bool
    reversible: bool

    def refuses(self, doc: dict, *, when: datetime | None = None) -> bool: ...

    def clause(self) -> dict | None: ...


@dataclass(frozen=True)
class Deadline:
    """Expired, or carrying a deadline that cannot be read.

    Fails closed on an unreadable one: a fact whose lifetime cannot be
    established has no business in a prompt. Reported separately from an
    ordinary expiry, because a climbing ``unreadable`` count means something
    is writing deadlines it should not.
    """

    at_field: str = "expire_at"
    reason: str = DEADLINE

    def refuses(self, doc: dict, *, when: datetime | None = None) -> bool:
        return self.why(doc, when=when) is not None

    def why(self, doc: dict, *, when: datetime | None = None) -> str | None:
        exp = doc.get(self.at_field)
        if exp is None:
            return None                  # pinned: the absence of a deadline
        if not isinstance(exp, datetime):
            return UNREADABLE
        try:
            return None if aware(exp) > (when or now()) else DEADLINE
        except (TypeError, ValueError, OverflowError):
            return UNREADABLE

    def clause(self) -> dict | None:
        return living(self.at_field)


@dataclass(frozen=True)
class Marked:
    """Refused because somebody said so, and said why.

    The general form of "a field whose presence means no". ``revoked`` is an
    erasure request; ``quarantined`` is a document held back from models
    while kept for forensics. Same mechanics, different verb and different
    operational meaning, which is exactly why they are two rules and not one
    boolean -- and why ``reversible`` is a field here rather than a constant.

    ``reversible`` is the whole difference between the two, and it decides
    three things at once, which is the point of putting it on the rule:

    - whether ``lift()`` will take the mark off, or raise ``Irreversible``.
    - whether imposing it also stamps the erase deadline. An irreversible
      reason is an erasure instruction, so the bytes should go; a reversible
      one is a hold, and the row is evidence somebody is going to want.
    - what the chain records on the way back out, since a reversible reason
      is the only one that has a way back out to record.

    A third-party reason is declared the same way -- ``Marked(field=...,
    reason=..., reversible=...)`` -- and gets all three behaviours from that
    one word, rather than from remembering to mirror what ``revoke()`` does.
    """

    field: str
    reason: str
    reversible: bool = False

    def refuses(self, doc: dict, *, when: datetime | None = None) -> bool:
        return doc.get(self.field) is not None

    def clause(self) -> dict | None:
        return {"$or": [{self.field: None}, {self.field: {"$exists": False}}]}


def _is_ciphertext(value: Any) -> bool:
    """A BSON Binary with subtype 6 is an encrypted value.

    Checked by shape rather than by asking whether encryption is configured:
    a document written while sealing was on and read after somebody turned
    it off is exactly the case that must not come back as a blob of bytes
    pretending to be a string.
    """
    from bson.binary import Binary
    return isinstance(value, Binary) and value.subtype == 6


@dataclass(frozen=True)
class Unrecoverable:
    """Refused because the field is still ciphertext at the point of use.

    A safety net rather than the mechanism: ``unseal()`` is what decrypts
    and what refuses a destroyed key. This rule catches the case where a
    sealed document reaches a read path that never called it -- so the
    failure is a refusal with a name, rather than a ``Binary`` serialised
    into a prompt as if it were text.
    """

    field: str = "text"
    reason: str = UNRECOVERABLE

    def refuses(self, doc: dict, *, when: datetime | None = None) -> bool:
        return _is_ciphertext(doc.get(self.field))

    def clause(self) -> dict | None:
        # Not expressible: "is this value encrypted" is a BSON subtype
        # question, and ``$type: "binData"`` cannot distinguish subtype 6
        # from a thumbnail. The per-document check is the guarantee anyway.
        return None


@dataclass(frozen=True)
class EmbeddedWith:
    """Refused because a different model produced this vector.

    An embedding is not a vector, it is a (vector, model) pair, and a vector
    without its model is an orphan. Comparing orphans does not fail -- it
    returns a number between -1 and 1, which is the whole problem.

    Measured against a real embedding API, same text, both 1024-wide, two
    generations of one vendor's model:

        identical text, old model vs new       cosine -0.053
        unrelated text, both on the new one    cosine +0.301

    A model swap does not degrade ranking, it inverts it: unrelated text
    scores five times higher than the document actually being looked for.
    And when two models share a width -- which a whole generation of them
    does -- the check that catches a 512-in-1024 mistake catches none of
    this. Same width, different meaning, no error, no log, and a
    healthy-looking ``describe()``.

    So the model is part of what a document *is*, and a row embedded by
    anything else is refused rather than ranked. Refused, not deleted: it
    needs re-embedding, not erasure, and the embed worker will take it.
    """

    model: str
    field: str = "embedded_with"
    reason: str = WRONG_MODEL

    def refuses(self, doc: dict, *, when: datetime | None = None) -> bool:
        if doc.get("embedding") is None:
            return False        # nothing to compare yet; pending, not wrong
        return doc.get(self.field) != self.model

    def clause(self) -> dict | None:
        # A row with no vector is pending, not wrong -- it must stay visible
        # to describe() and to the embed worker.
        return {"$or": [{self.field: self.model}, {"embedding": None}]}


@dataclass(frozen=True)
class Clearance:
    """Refused because the caller is not cleared for this document.

    ``Guard`` asks *may this caller read the scope*. ``Admission`` asks *may
    this document reach a prompt*. Neither asks the question that actually
    leaks, which is the pair of them: *may this document reach **this**
    caller's prompt*. A scope-level lock is all-or-nothing, so the moment one
    document in a scope is more sensitive than another, the only available
    answers are "give everyone everything" and "split the scope" -- and
    splitting the scope means one retrieval boundary per sensitivity level,
    which is four owners of one deadline again.

    So sensitivity is a field on the document and clearance is a claim on the
    caller, compared per hit, in the layer that already refuses things:

        docs = engine.model("docs", tenant="t").admitting(
            Deadline(), revoked(),
            Clearance(order=("public", "internal", "secret")))

        await docs.for_caller({"clearance": "internal"}).search(vector)
        # "secret" documents are not lower-ranked. They are not returned.

    **It fails closed in three directions**, which is the whole reason this
    is a rule object rather than a comparison somebody writes at a call site:

    - a caller with no clearance claim gets the *lowest* level, not a pass.
      The tempting default is to treat a missing claim as "unrestricted",
      and it is tempting because that is what makes the tests pass first.
    - a document whose level is not in ``order`` is refused. An unrecognised
      classification is not a low one: it is a document somebody labelled
      with something this deployment does not understand.
    - a document with no level field at all is refused unless ``default`` is
      set. Untagged is not public. Getting this backwards means every
      document written before the policy existed is world-readable, which is
      exactly the population most likely to be sensitive.

    Not bypassable. ``including_refused()`` exists so an operator can see
    what was forgotten; clearance is not a forgetting reason and no handle
    here is entitled to waive it.
    """

    order: tuple[str, ...]
    field: str = "classification"
    claim: str = "clearance"
    default: str | None = None
    reason: str = NOT_CLEARED
    needs_caller: bool = True
    bypassable: bool = False

    def _rank(self, level: Any) -> int | None:
        """Position in the ordering, or ``None`` for anything unrecognised."""
        try:
            return self.order.index(level)
        except (ValueError, TypeError):
            return None

    def refuses(self, doc: dict, *, when: datetime | None = None,
                caller: dict | None = None) -> bool:
        level = doc.get(self.field, self.default)
        needed = self._rank(level)
        if needed is None:
            return True                      # unlabelled, or a label we do not know
        held = self._rank((caller or {}).get(self.claim))
        if held is None:
            return True                      # no claim is the lowest, not the highest
        return held < needed

    def clause(self) -> dict | None:
        # Not expressible without the caller, and ``clause()`` is called
        # without one -- the per-document check is the guarantee anyway. See
        # ``clause_for`` below, which the handle uses when it has the claims.
        return None

    def clause_for(self, caller: dict | None) -> dict | None:
        """The same rule as a query fragment, once the caller is known.

        An optimisation, like every other clause here: it lets MongoDB drop
        the rows this caller may not see instead of shipping them to be
        refused. It cannot express the "unknown label" case -- ``$in`` on the
        permitted levels does that implicitly, by matching nothing else --
        which is fine, because ``refuses`` above is what holds.
        """
        held = self._rank((caller or {}).get(self.claim))
        if held is None:
            # Cleared for nothing. An impossible clause is the honest
            # translation, and cheaper than fetching everything to refuse it.
            return {self.field: {"$in": []}}
        return {self.field: {"$in": list(self.order[:held + 1])}}


@dataclass(frozen=True)
class Restricted:
    """Refused because the document names who may see it, and it is not you.

    The complement of ``Clearance``: no ordering, just a list on the document
    of audiences allowed to receive it. The shape access control actually
    takes outside the military metaphor -- a support ticket visible to the
    filing team, a contract visible to legal and the deal desk.

    An empty or absent list is refused, on the same reasoning as an untagged
    document above: a restriction nobody filled in is not an absent
    restriction.
    """

    field: str = "audience"
    claim: str = "groups"
    reason: str = NOT_CLEARED
    needs_caller: bool = True
    bypassable: bool = False

    @staticmethod
    def _set(value: Any) -> set:
        if value is None:
            return set()
        if isinstance(value, (str, bytes)):
            return {value}
        try:
            return set(value)
        except TypeError:
            return set()

    def refuses(self, doc: dict, *, when: datetime | None = None,
                caller: dict | None = None) -> bool:
        allowed = self._set(doc.get(self.field))
        if not allowed:
            return True
        return not (allowed & self._set((caller or {}).get(self.claim)))

    def clause(self) -> dict | None:
        return None

    def clause_for(self, caller: dict | None) -> dict | None:
        held = sorted(self._set((caller or {}).get(self.claim)))
        return {self.field: {"$in": held}}


def revoked(field: str = "forgotten") -> Marked:
    """Forgotten on request: unreachable now, erased by the deadline.

    **Not reversible, on purpose.** The reasons this exists for -- a subject
    erasure request, a leaked credential, a retracted document -- are things
    that happened, not hypotheses that might be withdrawn. ``lift()`` raises
    ``Irreversible`` rather than offering an undo that the reaper would
    quietly take away a minute later. See that class for the full argument.
    """
    return Marked(field=field, reason=REVOKED, reversible=False)


def quarantined(field: str = "quarantined") -> Marked:
    """Held back from models, deliberately still on disk.

    The row is evidence. A document flagged by an injection detector, or by
    a human, must stop reaching prompts *without* being destroyed -- you
    cannot investigate what you deleted. Refusal already had exactly this
    shape, so this is a rule rather than a feature.

    **Reversible, equally on purpose**, and that is what makes it a
    different reason rather than a second flavour of revocation. A hold
    exists to be resolved: ``quarantine()`` imposes it, ``release()`` lifts
    it, both go on the chain, and no erase deadline is stamped, because a
    document destroyed on a schedule is not available to the investigation
    it was being held for.
    """
    return Marked(field=field, reason=QUARANTINED, reversible=True)



@dataclass(frozen=True)
class AdmissionSpec:
    """Where a collection keeps the two facts that make a document forgettable."""

    collection: str
    at_field: str = "expire_at"
    # Set by revoke(). Present means "refuse this", independently of the
    # deadline, so an erasure request does not have to wait for a sweeper and
    # does not depend on the TTL index existing at all.
    mark_field: str = "forgotten"
    # Where a document records what it was made out of, and ``None`` when
    # this collection does not track derivation at all. Opt-in, because a
    # collection of source facts has no lineage and should not pay a field
    # or an index for one.
    lineage_field: str | None = None
    # Part of the spec, and therefore part of identity, because handles are
    # deduplicated per collection by spec equality. It was not, and the
    # consequence was that declaration order silently decided whether the
    # tenant was enforced at all: a Memory builds an unscoped handle for its
    # collection, and a later ``model(tenant=...).forgettable()`` got that
    # same unscoped object back. Two declarations disagreeing about the
    # boundary must collide loudly, not resolve to whichever ran first.
    tenant: str | None = None
    # The reasons this collection refuses, in the order they are asked.
    # Empty means the two defaults -- a deadline and an explicit revocation
    # -- which is what ``forgettable()`` installs. Anything else is declared
    # by the application through ``admitting()``.
    rules: tuple[Rule, ...] = ()

    def with_defaults(self) -> AdmissionSpec:
        if self.rules:
            return self
        return replace(self, rules=(Deadline(self.at_field),
                                    revoked(self.mark_field)))

    def describe(self) -> str:
        scope = f", scoped by {self.tenant}" if self.tenant else ""
        reasons = ", ".join(r.reason for r in self.rules) or "deadline, revoked"
        return f"{self.collection}: refuses on [{reasons}]{scope}"


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
    wrong, and the falsifier shipped alongside it caught the mistake within
    the hour: it flagged a page that asked for 50, got 1, and was *complete*: one live document existed, the rest were
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


def why_refused(doc: dict, spec: AdmissionSpec,
                    *, when: datetime | None = None,
                    caller: dict | None = None,
                    only_unbypassable: bool = False) -> str | None:
    """The first reason this document may not reach a prompt, or ``None``.

    Asks each declared rule in order and returns the first refusal. Order is
    the declared order and it is reported, not merged: an operator needs to
    know a document was *quarantined* rather than merely expired, because
    the two demand different responses.

    Never raises, whatever a rule does. A rule that throws is treated as a
    refusal and named, because an exception inside a filter is how the
    filter gets skipped -- the failure this module exists to prevent, and it
    must not come back through a third-party rule.
    """
    for rule in spec.with_defaults().rules:
        if only_unbypassable and getattr(rule, "bypassable", True):
            continue
        try:
            if isinstance(rule, Deadline):
                why = rule.why(doc, when=when)
                if why is not None:
                    return why
            elif getattr(rule, "needs_caller", False):
                # Only rules that declared they compare against the caller
                # are handed the claims, so the ordinary three keep a
                # signature with nothing irrelevant in it.
                if rule.refuses(doc, when=when, caller=caller):
                    return rule.reason
            elif rule.refuses(doc, when=when):
                return rule.reason
        except Exception:  # noqa: BLE001 - a rule must not be able to open
            # the gate by failing. Refuse, and say which rule did it.
            log.exception("rule %r raised; refusing the document", rule.reason)
            return rule.reason
    return None


class Admission:
    """A read handle that cannot return a forgotten fact.

    Install it on a model (``.forgettable()``) or build it directly. It is a
    trait, so ``ensure()`` gives the mark field an index -- revocation has to
    be cheap to filter on, or it will be skipped at scale.
    """

    kind = "admission"

    def __init__(self, db, spec: AdmissionSpec, *, engine=None):
        self.db = db
        # Optional, and only so ``search()`` below can exist. A handle built
        # by hand (tests, a script) keeps working without one and raises a
        # sentence rather than an AttributeError if asked to search.
        self.engine = engine
        self.spec = spec.with_defaults()
        spec = self.spec
        self.rules: tuple[Rule, ...] = spec.rules
        self.collection = spec.collection
        self.tenant = spec.tenant
        self.receipts_log = Receipts()
        self._include = False
        self.ledger = None
        self._caller: dict | None = None
        # Set by ``sealed_by()`` when the model declares encrypted fields.
        # ``None`` is the ordinary case and costs nothing: every read below
        # checks it once and skips the whole path.
        self.sealing = None
        # Bound and holding no claims is not the same as never bound: the
        # first is a caller entitled to nothing, the second is a code path
        # that forgot to say who is asking. Conflating them is how a read
        # returns empty and a write silently matches nothing.
        self._bound = False

    # ---- proof ---------------------------------------------------------

    def witnessed_by(self, ledger) -> Admission:
        """Record every revocation on a hash chain. Returns ``self``.

        Counters answer "how much has this process refused"; a chain answers
        "show me that this fact stopped being reachable at 14:02, and that
        the record has not been edited since". Only the second one survives
        contact with an auditor, and only revocations go on it -- see
        ``ledger.py`` for why ledgering reads is the wrong trade.

        Attached rather than built in, because a chain that never expires is
        a retention decision and retention decisions should be typed out.
        """
        self.ledger = ledger
        return self

    # ---- schema --------------------------------------------------------

    async def ensure(self) -> bool:
        """Index every field a rule filters on.

        One index per marked field, sparse because the mark is the exception.
        A rule whose field is unindexed still *works* -- it is checked on the
        way out either way -- but its server-side clause becomes a scan, and
        a guarantee that gets expensive is a guarantee somebody eventually
        turns off.
        """
        for rule in self.rules:
            field_name = getattr(rule, "field", None)
            if field_name:
                await self.db[self.collection].create_index(field_name,
                                                            sparse=True)
        if self.spec.lineage_field:
            # Multikey, and the reason it is not optional: propagation is
            # one ``$in`` over this field on every revocation. Unindexed,
            # an erasure request becomes a collection scan, and the first
            # thing anybody does with a slow erasure path is stop calling
            # it.
            await self.db[self.collection].create_index(
                self.spec.lineage_field, sparse=True)
        return True

    # ---- who is asking -------------------------------------------------

    def for_caller(self, claims: dict | None) -> Admission:
        """Bind this handle to one caller's claims. Returns a new handle.

        A clone, not a setting, and that is load-bearing rather than
        stylistic: ``engine.admission()`` deduplicates handles per collection
        and hands every caller *the same object*. A ``for_caller`` that
        mutated would make the last request's identity the current one, under
        concurrency, in an access-control check -- the kind of bug that does
        not reproduce and does not error and shows the wrong tenant's
        documents to whoever asked second.

        Rules that declared ``needs_caller`` see these claims. The rest do
        not, so binding a caller onto a collection with no caller-aware rule
        changes nothing, which is the behaviour that makes it safe to call
        unconditionally in a request handler.

        Claims come from whatever already authenticated the caller. This
        method does not verify them and cannot: a handle that believed
        ``{"clearance": "secret"}`` because it was passed one would be an
        authorisation system whose only input is the attacker's.
        """
        clone = self._clone()
        clone._caller = dict(claims) if claims else {}
        clone._bound = True
        return clone

    def _clone(self) -> Admission:
        clone = Admission(self.db, self.spec, engine=self.engine)
        # Receipts are shared: a refusal is a refusal whichever derived
        # handle saw it, and a per-request clone with its own counters would
        # report nothing on /healthz.
        clone.receipts_log = self.receipts_log
        clone.ledger = self.ledger
        clone._include = self._include
        clone._caller = self._caller
        clone._bound = self._bound
        clone.sealing = self.sealing
        return clone

    # ---- the escape hatch, deliberately named --------------------------

    def including_refused(self) -> Admission:
        """A handle that returns everything, including what was forgotten.

        Audit, administration and the reaper itself need this. It is a
        separate object rather than a flag on every call so that a review can
        grep for the phrase and find every place the guarantee was set aside.

        Note what it does *not* set aside. The tenant, first: seeing
        forgotten rows is an operational need, seeing another tenant's
        forgotten rows is a breach with a nicer name. And second, any rule
        that marks itself unbypassable -- which is how the caller-aware rules
        are declared.

        That distinction is the one worth stating, because the naive version
        of this method is "skip every rule", and it was. The reasons in this
        module are not one kind of thing. A *deadline* and a *revocation* say
        the fact is forgotten, and auditing what was forgotten is precisely
        the job this handle exists for. A *clearance* says this caller may
        not have it, which is not a forgetting reason and not this handle's
        to waive: an auditor is entitled to see what was erased, and entitled
        to nothing above their own clearance. One method waiving both would
        make "let me see the deleted rows" a privilege escalation.
        """
        clone = self._clone()
        clone._include = True
        return clone

    # ---- the rule ------------------------------------------------------

    def _needs_a_caller(self) -> tuple:
        """The reasons on this handle that cannot be decided without a caller."""
        return tuple(r.reason for r in self.rules
                     if getattr(r, "needs_caller", False))

    def _require_caller(self) -> None:
        if self._bound:
            return
        reasons = self._needs_a_caller()
        if reasons:
            raise CallerRequired(self.collection, reasons)

    def _query(self, filters: dict | None) -> dict:
        """Push refusal *and* the tenant into the query.

        The tenant check is the same ``require_scope`` the search path uses,
        deliberately: this handle once accepted a ``tenant`` and ignored it,
        so ``model(tenant="t").forgettable().find({})`` returned every
        tenant's rows while ``engine.search`` on the same model refused the
        same query. One declaration, two primitives, two answers -- which is
        the drift this module was written to remove, reappearing inside it.

        It shares the tenant rule but not the search path's blanket
        "every filter must be scalar": this handle queries the collection,
        where ``doc_id: {"$in": [...]}`` is how a batch is forgotten. The
        hazards differ, so the rules do.
        """
        self._require_caller()
        q = require_tenant(self.collection, self.tenant, filters)
        # Only the rules that *can* be expressed server-side. A rule with no
        # clause is not skipped -- it is simply enforced on the way out
        # instead, by _admit, which is the authoritative half anyway.
        #
        # Under ``including_refused()`` the forgetting rules drop out and the
        # unbypassable ones stay, so an audit read is still bounded by who is
        # asking.
        usable = [r for r in self.rules
                  if not self._include or not getattr(r, "bypassable", True)]
        clauses = [c for c in (self._clause_of(r) for r in usable) if c]
        if not clauses:
            return q
        existing = q.pop("$and", [])
        q["$and"] = [*existing, *clauses] if existing else clauses
        return q

    def _clause_of(self, rule) -> dict | None:
        """A rule's query fragment, handing over the caller when it wants one."""
        if getattr(rule, "needs_caller", False):
            for_caller = getattr(rule, "clause_for", None)
            return for_caller(self._caller) if for_caller else None
        return rule.clause()

    def _admit(self, doc: dict | None, *, when: datetime | None = None,
               tally: dict[str, int] | None = None):
        """The authoritative check, on the way out.

        The query above is an optimisation. *This* is the guarantee, and it is
        the only one that holds for documents that never went through a query
        -- every hit from ``$vectorSearch``, where the deadline is deliberately
        not an index filter.
        """
        if doc is None:
            return doc
        # Loud on the per-document path as well. A handle that refused every
        # hit for want of a caller would look exactly like a scope where
        # everything is forgotten -- and that is the one diagnosis this whole
        # module exists to make impossible to reach by accident.
        self._require_caller()
        reason = why_refused(doc, self.spec, when=when, caller=self._caller,
                             only_unbypassable=self._include)
        if reason is None:
            return doc
        if tally is None:
            self.receipts_log.record(reason)
        else:
            # Counted for this page; committed by the caller once the page is
            # final, so a refill does not count the same document twice.
            tally[reason] = tally.get(reason, 0) + 1
        log.debug("refused a %s document from %s", reason, self.collection)
        return None

    def reachable(self, docs: Iterable[dict], *,
                  when: datetime | None = None) -> list[dict]:
        """Filter documents that arrived from somewhere else.

        This is the search path's entry point: ``$vectorSearch`` and
        ``$rankFusion`` hits have not been through ``_query`` and never will
        be, so they are admitted one at a time, here.
        """
        return [d for d in docs if self._admit(d, when=when) is not None]

    def _classify(self, docs: list[dict], *, when: datetime | None = None
                  ) -> tuple[list[dict], dict[str, int]]:
        """Admit a candidate set without recording anything yet."""
        tally: dict[str, int] = {}
        kept = [d for d in docs
                if self._admit(d, when=when, tally=tally) is not None]
        return kept, tally

    async def search(self, vector, *, text: str | None = None,
                     limit: int = 5, filters: dict | None = None,
                     when: datetime | None = None,
                     rounds: int = 3) -> Page:
        """Search this collection and admit the hits. The whole read, one call.

        This exists because the engine's own ``search()`` is a **primitive,
        not a read path**: it returns what the index ranked. Deadlines are
        deliberately not pushed into the vector index -- the measurements are
        in ``search.py`` -- so a hit arriving from ``$vectorSearch`` has never
        been filtered by anything, and admitting it is the caller's job.

        Which is precisely the shape this module was written to abolish. The
        original sin was six read paths that each had to remember a deadline
        filter; replacing it with two read paths that each had to remember to
        wrap a search is the same bug with a smaller number. Both of them did
        remember, and both wrote out their own fetch-budget guess, and the
        two guesses were the same wrong constant -- which is what a
        convention looks like just before it fails a third time.

        So the handle owns the query as well as the rule. There is now one
        named way to search a collection that refuses things, and reaching
        past it means naming the primitive on the engine, which a review can
        grep for and CI asserts no module in this package does.
        """
        if self.engine is None:
            raise RuntimeError(
                f"this {self.collection} handle was built without an engine, "
                "so it cannot search. Build it with engine.admission(...) / "
                "model(...).forgettable(), or call saturate() with your own "
                "fetch")

        async def fetch(n: int) -> list[dict]:
            return await self.engine.search(self.collection, vector,
                                            text=text, limit=n,
                                            filters=filters)

        return await self.saturate(fetch, limit=limit, when=when,
                                   rounds=rounds)

    async def saturate(self, fetch, *, limit: int,
                       when: datetime | None = None,
                       rounds: int = 3) -> Page:
        """Fill a page of ``limit`` reachable documents, refusal notwithstanding.

        Enforcing the deadline on read -- rather than in the vector index,
        for the reasons measured in ``search.py`` -- means forgotten
        documents are fetched and then dropped. They spend the fetch budget.
        Both read paths in this package knew that and both bought the same
        fixed insurance: ask for ``limit * 2``, admit, slice. Which is a
        guess, and a guess that fails in the direction this repository
        otherwise refuses to fail in:

            40 expired rows outranking 6 live ones, limit=5  ->  0 hits

        Zero. Not "fewer". The live documents were indexed, queryable and
        present, and the caller was handed an empty list that is
        indistinguishable from "nothing matched" -- the same
        fewer-rows-instead-of-an-error shape that this codebase blocks
        startup over and refuses to let a rebuilding index produce. Refusal
        is supposed to cost the *forgotten* document its place, not the page.

        So the budget is not a constant. ``fetch(n)`` is asked for candidates
        in ranking order; each round re-asks for more and re-admits the
        superset, until the page is full or the candidates run out. The next
        size is derived from the refusal rate just observed rather than
        doubled blindly -- at a 90% refusal rate, doubling takes four rounds
        to find what one round of arithmetic gets in one.

        Three things end the loop, and all three are honest:

        1. the page is full;
        2. ``fetch`` returned fewer rows than asked for -- there is nothing
           further down the ranking. This also covers the search tier's own
           ceiling (``MAX_LIMIT``): a request past it comes back short, which
           is the truth from where this sits, since no more are reachable;
        3. ``rounds`` is spent. A scope where *everything* is forgotten must
           not turn one query into an unbounded sequence of them.

        Only case 3 sets ``page.starved``, and the distinction is the
        interesting part. Case 2 can also leave the page short, and that
        short page is *complete*: the candidates are exhausted, so nothing is
        being withheld and there is nothing to go back for, however many
        refusals it took to establish. Case 3 is the opposite -- candidates
        remained and this page could not reach them -- and it is the only
        state a caller needs to treat as partial.

        Case 2 does swallow one thing worth naming: a request past the search
        tier's ``MAX_LIMIT`` comes back clamped, which is indistinguishable
        here from "that is all there is". It is reported as complete because
        from this layer it is -- no further document is reachable by any
        query this engine will issue. A deployment that needs to see past
        that ceiling needs a bigger ceiling, not a different flag.
        """
        want = max(1, int(limit))
        rounds = max(1, int(rounds))
        asked = want * 2          # the cheap first guess, unchanged
        kept: list[dict] = []
        tally: dict[str, int] = {}
        examined = 0
        exhausted = False

        for attempt in range(rounds):
            candidates = list(await fetch(asked))
            examined = len(candidates)
            kept, tally = self._classify(candidates, when=when)
            # Fewer rows than asked for: there is nothing further down the
            # ranking, so whatever the page holds is the whole answer.
            exhausted = examined < asked
            if len(kept) >= want or exhausted:
                break
            if attempt + 1 < rounds:
                asked = self._next_ask(asked, want, kept=len(kept),
                                       examined=examined)

        hits = kept[:want]
        if self.seals:
            # Decrypted after the page is chosen, so a document whose key is
            # gone costs one refusal rather than a wasted round of refill --
            # and it is counted in the same tally, under `unrecoverable`,
            # beside the deadline and the revocation.
            hits, sealed_tally = await self._unsealed(hits)
            for reason, n in sealed_tally.items():
                tally[reason] = tally.get(reason, 0) + n
        self.receipts_log.record_many(tally)
        page = Page(hits, refused=tally, examined=examined,
                    starved=len(kept) < want and not exhausted)
        if page.starved:
            # Worth a line at WARNING: it means a caller was told less than
            # the truth, which no amount of correct filtering makes fine. And
            # only here -- a short-but-complete page used to log this too,
            # which is how a useful warning becomes one people filter out.
            log.warning(
                "page starved on %s: wanted %d, admitted %d of %d examined, "
                "refused %s", self.collection, want, len(kept), examined, tally)
        return page

    @staticmethod
    def _next_ask(asked: int, want: int, *, kept: int, examined: int) -> int:
        """How many candidates to ask for next, from the rate just measured.

        The observed hit rate is the best available estimate of the one
        further down the ranking, so aim at the size that *would* have filled
        the page, with headroom. A round that admitted nothing has no rate to
        extrapolate from, so it falls back to growing hard -- that case is
        either a wholly forgotten scope (ends on ``rounds``) or a deep run of
        expired rows (ends when it clears them).
        """
        if kept == 0:
            return asked * 4
        needed = want / (kept / max(examined, 1))
        # Never shrink, and always ask for strictly more than last time, or
        # the loop re-issues an identical query and calls it progress.
        return max(asked + want, int(needed * 1.5) + 1)

    # ---- reads: refusal is the default ---------------------------------

    async def find_one(self, filters: dict | None = None, *args, **kw):
        doc = await self.db[self.collection].find_one(self._query(filters),
                                                      *args, **kw)
        admitted = self._admit(doc)
        if admitted is None or not self.seals:
            return admitted
        kept, tally = await self._unsealed([admitted])
        self.receipts_log.record_many(tally)
        return kept[0] if kept else None

    async def find(self, filters: dict | None = None, *args,
                   limit: int = 0, sort: Any = None, **kw) -> list[dict]:
        cur = self.db[self.collection].find(self._query(filters), *args, **kw)
        if sort is not None:
            cur = cur.sort(*sort) if isinstance(sort, tuple) else cur.sort(sort)
        if limit:
            cur = cur.limit(limit)
        admitted = [d async for d in cur if self._admit(d) is not None]
        if not self.seals:
            return admitted
        # Admitted first, then decrypted. A revoked or expired document is
        # refused by its mark without anybody paying for a key lookup, and
        # only the survivors reach the KMS -- which matters because the
        # refusal rate on a live scope is most of the page.
        kept, tally = await self._unsealed(admitted)
        self.receipts_log.record_many(tally)
        return kept

    def match(self, filters: dict | None = None) -> dict:
        """The refusing filter, for a pipeline that cannot use ``find``.

        An aggregation is the one read shape this handle cannot wrap, so it
        gets the rule as a value instead of a method: ``{"$match":
        docs.match({...})}``. Still one source of truth -- if the definition
        of "forgotten" changes, this changes with it.

        Note what it is *not*: the per-document check. A pipeline that emits
        whole documents should pass them through ``reachable()`` too. This is
        the right tool for counting and grouping, where there is no document
        to hand back.
        """
        return self._query(filters)

    async def count(self, filters: dict | None = None) -> int:
        """How many facts are *reachable*, which is the number a caller means.

        Counted with the same query the reads use, so a count and a find
        cannot disagree about what exists.
        """
        return await self.db[self.collection].count_documents(
            self._query(filters))

    async def exists(self, filters: dict | None = None) -> bool:
        return await self.find_one(filters) is not None

    # ---- forgetting, and the one reason that can be taken back ---------
    #
    # Two verbs, not one, and the asymmetry between them is deliberate:
    #
    #   impose(reason, ...)   applies a mark. Available for every reason
    #                         whose rule declares `reversible` at all.
    #   lift(reason, ...)     removes one. Available only where that
    #                         declaration said True, and raises otherwise.
    #
    # `revoke`, `quarantine` and `release` are named front doors onto those
    # two, because the builtin reasons deserve a verb that reads like the
    # thing it does. A third-party `Marked` reason gets the general form and
    # exactly the same guarantees -- there is no privileged path.

    def _imposable(self) -> tuple:
        """The reasons on this handle that a verb can apply.

        Two things make a rule imposable, and it needs both: a ``field``,
        which is the mark, and a declared ``reversible``, which is the rule
        saying an operator sets that mark rather than the world doing it.
        A ``Deadline`` has neither -- a document is expired because time
        passed, and "imposing" that is just writing a date. ``Clearance``
        has a field but declares nothing, because the field is a label the
        document came with, not a mark this handle puts on it.
        """
        return tuple(r for r in self.rules
                     if isinstance(getattr(r, "reversible", None), bool)
                     and isinstance(getattr(r, "field", None), str))

    def _rule_for(self, reason: str):
        imposable = self._imposable()
        for rule in imposable:
            if rule.reason == reason:
                return rule
        raise UnknownReason(self.collection, reason,
                            tuple(r.reason for r in imposable))

    @staticmethod
    def _marked(rule, present: bool) -> dict:
        """Whether this rule's mark is on a document, as a query fragment.

        Both verbs need it and they need opposite halves, which is the whole
        reason it is here rather than inlined twice:

        ``impose`` must skip documents *already* carrying the mark. Without
        that it re-stamps them -- and on an irreversible reason it re-stamps
        ``expire_at`` too, so re-running an erasure would push the row's
        deletion further into the future. A retry that extends the life of
        an erased document is the worst available outcome for the one
        operation with no undo.

        ``lift`` must target only documents that *do* carry it. Without
        that, ``expect`` counts every document the filter touches rather
        than every document actually held, so the interlock guards a number
        the caller never meant.
        """
        f = rule.field
        if present:
            return {f: {"$ne": None}}
        return {"$or": [{f: None}, {f: {"$exists": False}}]}

    def _write_query(self, rule, filters: dict | None, *,
                     present: bool) -> dict:
        """The query a forgetting write runs against.

        Built from the **audit** handle, which is the correction to a
        silent no-op that predates the reversible/irreversible split and
        survived it. Refusal reasons are not mutually exclusive, and the
        ordinary read query drops every already-refused document -- so:

        - revoking a *quarantined* document matched nothing. An
          investigation concluding "this is malicious, erase it" returned 0
          and left the row carrying only the reversible mark, so the next
          ``release()`` made it reachable again.
        - revoking a document whose deadline passed thirty seconds ago
          matched nothing either. A subject erasure request for a fact that
          is still on disk, and will be for up to a sweep, was answered
          "no such document" -- with no mark, no receipt and no chain entry.

        Both are the failure this package is named after, reached through
        its own write path. The audit handle still carries the tenant and
        every unbypassable rule, so widening the write here does not widen
        who may perform it.
        """
        query = self.including_refused()._query(filters)
        clause = self._marked(rule, present)
        query["$and"] = [*query.pop("$and", []), clause]
        return query

    async def _guard(self, verb: str, filters: dict | None, query: dict, *,
                     expect: int | None, everything: bool) -> None:
        """Everything that must be true before a forgetting write happens.

        Both checks are pre-flight and both refuse rather than proceed,
        because this is the one family of calls in the package whose damage
        is done before the caller reads the return value.

        ``query`` is passed in rather than rebuilt here, and that is not a
        style choice: ``lift()`` has to count through the audit handle,
        since the rows it acts on are refused by the very rule it is
        removing. A guard that built its own query would count zero, refuse
        every ``expect``, and be indistinguishable from a broken filter.
        """
        # "Unbounded" means *narrows nothing beyond the tenant*, which is
        # not the same as an empty dict and the difference is the whole
        # value of the check. On a scoped collection an empty filter never
        # reaches here -- ``require_tenant`` rejects it first -- so a rule
        # written against ``not filters`` would fire only on the unscoped
        # case and miss every deployment that actually has tenants. The
        # dangerous call is ``revoke({"tenant": t})``: legal, scoped,
        # correct-looking, and it erases the tenant.
        narrowing = {k: v for k, v in (filters or {}).items()
                     if k != self.tenant}
        if not narrowing and not everything:
            raise UnboundedForgetting(self.collection, verb)
        if expect is None:
            return
        matched = await self.db[self.collection].count_documents(query)
        if matched != expect:
            log.warning("%s() on %s refused: matched %d, expected %d",
                        verb, self.collection, matched, expect)
            raise BlastRadius(self.collection, expect, matched)

    async def revoke(self, filters: dict | None = None, *,
                     reason: str = "revoked",
                     erase_after: timedelta | None = None,
                     expect: int | None = None,
                     everything: bool = False) -> int:
        """Make matching facts unreachable now. Bytes leave on their own time.

        This is the part no vector database has. ``delete_many`` is a storage
        operation whose effect on retrieval is "eventually"; this is a
        retrieval operation whose effect is "next read". The row is also given
        a deadline so the reaper collects it -- unreachable first, erased
        shortly after, in that order, because the reverse order is the bug.

        **There is no undo, and that is a designed property rather than a
        missing feature** -- ``Irreversible`` in ``errors.py`` carries the
        argument. Which is exactly why the two interlocks below exist: when a
        call cannot be taken back, the only place to be careful is in front
        of it.

        ``expect`` refuses the write unless the filter matches that many
        documents. ``everything=True`` is required to revoke a whole scope.
        Both are opt-in and cost nothing when unused: no extra round trip is
        issued unless ``expect`` is given.

        ``erase_after`` keeps the tombstone readable for a while through
        ``including_refused()``, for cases where you must prove *when* a fact
        stopped being reachable. The default erases as soon as the reaper
        runs.

        It is a **cap, not an extension**: up to that long, or until the
        row's existing deadline, whichever comes first. A revocation only
        ever moves a deadline earlier. Otherwise erasing a fact due in an
        hour would keep it on disk for a week, and retention that *grows*
        because somebody asked for erasure is the opposite of the request.
        When the row goes sooner than you wanted the proof to last, the
        proof was in the wrong place: the ledger has no TTL index, on
        purpose, and that is the tombstone that outlives everything.

        Note also what ``erase_after`` is not: the window in which a
        revocation could be reversed. Reversal is out of contract in it, and
        a reader who assumed otherwise would be building on the sweeper's
        schedule.
        """
        n, _ = await self.impose(REVOKED, filters, reason=reason,
                                 erase_after=erase_after, expect=expect,
                                 everything=everything)
        return n

    async def witness(self, filters: dict | None = None, *, reason: str,
                      erase_after: timedelta | None = None,
                      expect: int | None = None,
                      everything: bool = False) -> dict:
        """``revoke()``, returning the chain entry instead of the count.

        The entry is the receipt, and handing it to whoever asked for the
        erasure is the point: their copy of the hash was taken before any
        dispute existed, so a chain that later does not contain it is
        falsified by a record this database's operator never held. Without
        that, a hash chain is only evidence against people who cannot edit
        it.
        """
        n, receipt = await self.impose(REVOKED, filters, reason=reason,
                                       erase_after=erase_after, expect=expect,
                                       everything=everything)
        out = dict(receipt or {})
        out.setdefault("count", n)
        return out

    async def quarantine(self, filters: dict | None = None, *,
                         reason: str = "quarantined",
                         expect: int | None = None,
                         everything: bool = False) -> int:
        """Hold facts back from prompts without destroying them.

        The other half of ``quarantined()``, which until now was a reason
        with no verb: the rule could refuse a mark, and nothing in the
        package could put one there. A reason that only an external writer
        can set is not a feature, it is a convention -- and the response to
        a convention is the whole argument of this module.

        Unlike ``revoke()`` this stamps **no erase deadline**. The row is the
        evidence; a hold that schedules its own subject for deletion is an
        investigation with a countdown on it. Lift it with ``release()``.
        """
        n, _ = await self.impose(QUARANTINED, filters, reason=reason,
                                 expect=expect, everything=everything)
        return n

    async def release(self, filters: dict | None = None, *,
                      reason: str, expect: int | None = None,
                      everything: bool = False) -> int:
        """Lift a quarantine: these facts may reach prompts again.

        ``reason`` is required and has no default, unlike every other verb
        here. Re-admitting a document that an injection detector flagged is
        a decision somebody made, and a decision with no stated reason is
        indistinguishable on the chain from a mistake -- which is precisely
        what an auditor reading this entry is trying to tell apart.
        """
        n, _ = await self.lift(QUARANTINED, filters, reason=reason,
                               expect=expect, everything=everything)
        return n

    # ---- what a fact was made out of -----------------------------------
    #
    # Refusal stops a *document* reaching a prompt. It says nothing about
    # the paragraph an agent wrote after reading it, and that paragraph is
    # written back into the same collection and keeps scoring well forever.
    # So the erasure request is honoured against the source and defeated by
    # the summary, which is the failure the whole package exists to prevent,
    # arriving through the one door it left open.
    #
    # The fix costs no new read-path rule, and that is the interesting part.
    # ``revoked()`` already refuses any document carrying the mark. What was
    # missing is that the mark did not *travel*. So:
    #
    #   derive()   writes a document with a transitively-closed ``lineage``,
    #              and refuses to write it at all if a parent is already
    #              refused -- you cannot legitimately derive a new fact from
    #              one that may not reach a prompt.
    #   impose()   marks the matched documents *and* everything carrying one
    #              of their ids in ``lineage``, in one extra query.
    #   lift()     un-marks the same set, so a released hold releases the
    #              work that was held with it.
    #
    # Transitive closure at write time is what makes propagation O(1)
    # queries instead of a recursive walk: a child's lineage is its parent's
    # lineage plus the parent, so a grandchild already names the
    # grandparent and one ``$in`` reaches the whole subtree at any depth.
    # Derivation is a DAG that only ever grows forwards, so the closure
    # cannot go stale -- a document's ancestry is fixed the moment it is
    # written.

    async def derive(self, documents, *, parents: Iterable,
                     when: datetime | None = None) -> list:
        """Write documents that were made out of other documents.

        ``parents`` are ids in this collection. Each new document gets a
        ``lineage`` naming every ancestor, transitively, and inherits the
        *earliest* deadline among its parents -- a summary of a fact that
        expires on Tuesday has no business outliving it, and picking the
        earliest is the only choice that cannot extend anything.

        **It refuses rather than writes when a parent is already refused.**
        Not because the write is unsafe in itself, but because the only
        ways to reach here are a race and a bug: something read a document
        it should not have been given, or is deriving from a handle that
        never checked. Writing the child and marking it in the same breath
        would paper over both. ``CallerRequired`` is the family
        resemblance -- every available answer is wrong, so this picks none.

        Returns the inserted ids.
        """
        field = self._require_lineage("derive")
        docs = [documents] if isinstance(documents, dict) else list(documents)
        if not docs:
            return []
        parents = list(parents)
        if not parents:
            raise ValueError(
                f"{self.collection}: derive() needs at least one parent. A "
                f"document made out of nothing is an ordinary insert")

        self._require_caller()
        scope = self._scope_of(docs)
        found = [d async for d in self.db[self.collection].find(
            self._query_by_id(parents, scope))]
        if len(found) != len(set(parents)):
            missing = set(parents) - {d["_id"] for d in found}
            raise DerivationBroken(self.collection, sorted(map(str, missing)),
                                   "not in this scope")
        audit = self.including_refused()
        for parent in found:
            reason = why_refused(parent, self.spec, when=when,
                                 caller=self._caller)
            if reason is not None:
                raise DerivationBroken(
                    self.collection, [str(parent["_id"])], reason)
            if audit._admit(parent, when=when) is None:
                # Refused by an *unbypassable* rule: the caller may not read
                # this parent, so they may not launder it into a new
                # document either.
                raise DerivationBroken(
                    self.collection, [str(parent["_id"])], NOT_CLEARED)

        lineage = sorted({*parents, *(a for p in found
                                      for a in (p.get(field) or []))},
                         key=str)
        deadlines = [p[self.spec.at_field] for p in found
                     if isinstance(p.get(self.spec.at_field), datetime)]
        prepared = []
        for doc in docs:
            row = dict(doc)
            row[field] = lineage
            if deadlines:
                # Inherit the earliest, and never overwrite a shorter one
                # the caller set deliberately.
                own = row.get(self.spec.at_field)
                soonest = min(deadlines)
                row[self.spec.at_field] = (
                    min(own, soonest) if isinstance(own, datetime) else soonest)
            prepared.append(row)

        result = await self.db[self.collection].insert_many(prepared)
        log.info("derived %d document(s) in %s from %d parent(s), lineage %d "
                 "deep", len(prepared), self.collection, len(parents),
                 len(lineage))
        return list(result.inserted_ids)

    def _require_lineage(self, verb: str) -> str:
        field = self.spec.lineage_field
        if not field:
            raise UnknownReason(
                self.collection, verb,
                ("declare lineage_field on the model to track derivation",))
        return field

    def _scope_of(self, docs: list) -> dict:
        """Which tenant these new documents belong to, taken from them.

        The handle knows the tenant *field*; only the documents know the
        value. Reading it off them rather than adding a parameter also
        enforces the thing that would otherwise be a convention: a derived
        document that did not carry the tenant would be written
        unreadable, since every read path requires it.

        All of them must agree. A batch spanning two tenants has no single
        correct parent lookup, and picking the first document's answer
        would silently let one tenant's parents authorise another's child.
        """
        if not self.tenant:
            return {}
        values = {d.get(self.tenant) for d in docs}
        if len(values) != 1 or None in values:
            raise ScopeRequired(self.collection, self.tenant)
        return {self.tenant: values.pop()}

    def _query_by_id(self, ids: list, scope: dict) -> dict:
        """Ids, but still inside the tenant and still refusing nothing.

        Built through the audit query on purpose: ``derive`` has to *see* a
        refused parent in order to reject it, and a query that hid one would
        turn "this parent may not be used" into "this parent does not
        exist" -- two very different things to report.
        """
        return self.including_refused()._query(
            {**scope, "_id": {"$in": ids}})

    async def _descendants(self, query: dict) -> tuple[list, int]:
        """Everything downstream of whatever this query matched.

        One extra ``find`` for the ids and one ``$in`` for the subtree, at
        any depth, because ``lineage`` is transitively closed when it is
        written. Returns the matched ids and how many descendants carry
        them, so the chain can record the two counts separately -- "you
        asked to erase 2 facts and 7 things made out of them went too" is
        the sentence an auditor needs, and a single total cannot say it.
        """
        field = self.spec.lineage_field
        if not field:
            return [], 0
        ids = [d["_id"] async for d in
               self.db[self.collection].find(query, {"_id": 1})]
        if not ids:
            return [], 0
        n = await self.db[self.collection].count_documents(
            {field: {"$in": ids}})
        return ids, n

    def _with_descendants(self, query: dict, filters: dict | None,
                          ids: list) -> dict:
        """The matched documents, plus everything downstream of them.

        The ``$or`` replaces the caller's *filter* -- a descendant does not
        match it, which is the whole point -- but it must not replace the
        **boundary**. The first version of this returned the bare ``$or``
        and propagation walked straight out of the tenant: a row in another
        namespace naming one of these ids would have been marked, by a
        caller who cannot even read it.

        So the guard clauses are rebuilt and kept: the tenant, and every
        unbypassable rule, which is how clearance survives the trip down
        the edge. Only the bypassable ones drop, because a descendant that
        is already expired or already held is exactly what this is here to
        reach.
        """
        field = self.spec.lineage_field
        if not (field and ids):
            return query
        scope = {self.tenant: (filters or {}).get(self.tenant)} \
            if self.tenant else {}
        guard = self.including_refused()._query(scope)
        reach = {"$or": [{"_id": {"$in": ids}}, {field: {"$in": ids}}]}
        guard["$and"] = [*guard.pop("$and", []), reach]
        return guard

    # ---- ciphertext, both ways -----------------------------------------
    #
    # Sealing is something a collection *has*, like a tenant or a rule, so
    # it lives on this handle rather than in a parallel object the caller
    # has to carry alongside it. Three things follow from that, and each
    # one removes something a caller would otherwise have to remember:
    #
    #   seal()      mints the scope's key if it is new, then writes through
    #               the encrypting client. There is no step where you have
    #               a key but no document, or a document but no key.
    #   find()/search()
    #               decrypt on the way out and refuse what they cannot,
    #               so no read site passes a keyring and a field list.
    #   shred()     the scope's key, by the same name the documents use.
    #
    # And the writer that skips all of this -- a migration script, a shell,
    # a second service holding the plain client -- is refused by the
    # *server*, because ``Keyring.enforce()`` puts a binData validator on
    # the collection. See its docstring: that is the difference between
    # encryption as a convention and encryption as a guarantee.

    def sealed_by(self, sealing) -> Admission:
        """Attach a resolved ``Sealing``. Returns ``self``."""
        self.sealing = sealing
        return self

    @property
    def seals(self) -> bool:
        return self.sealing is not None

    def _require_sealing(self, verb: str):
        if self.sealing is None:
            raise UnknownReason(
                self.collection, verb,
                ("declare .sealed(...) on the model to encrypt fields",))
        return self.sealing

    async def seal(self, documents, *, scope: str | None = None) -> list:
        """Write documents with their sealed fields encrypted.

        The scope defaults to the document's own tenant value, which is the
        point of tying the two together: a per-tenant key needs no second
        field, no second lookup and no second thing to keep in step. One
        declaration -- ``model(tenant="t").sealed("text")`` -- and erasure
        is per tenant because the key already was.

        The key is minted here if the scope is new. Requiring a separate
        ``key_for()`` first would make "wrote a document, forgot the key" a
        reachable state, and the driver's answer to that state is an
        exception on the *write* -- which is safe, and is still a step the
        caller can only get wrong.
        """
        sealing = self._require_sealing("seal")
        docs = [documents] if isinstance(documents, dict) else list(documents)
        if not docs:
            return []
        self._require_caller()

        prepared, scopes = [], set()
        for doc in docs:
            row = dict(doc)
            at = scope or row.get(sealing.scope_field)
            if at is None:
                raise ScopeRequired(self.collection, sealing.scope_field)
            row[sealing.scope_field] = at
            scopes.add(at)
            prepared.append(row)

        ring = sealing.keyring
        ce = await ring.encryption()
        try:
            for at in sorted(scopes):
                await ring.key_for(at, encryption=ce)
        finally:
            await ce.close()

        collection = await ring.writer(self.collection)
        result = await collection.insert_many(prepared)
        log.info("sealed %d document(s) into %s under %d scope key(s)",
                 len(prepared), self.collection, len(scopes))
        return list(result.inserted_ids)

    async def shred(self, scope: str) -> int:
        """Destroy one scope's key. Its ciphertext is noise, everywhere.

        Named on the handle as well as on the keyring because this is where
        the caller already is, and because the scope is the tenant they
        already have. An erasure request should not require knowing that a
        key vault exists.
        """
        return await self._require_sealing("shred").keyring.shred(scope)

    async def _unsealed(self, documents: list[dict]) -> tuple[list, dict]:
        """Decrypt, refusing per document. ``(kept, tally)``."""
        if self.sealing is None or not documents:
            return list(documents), {}
        page = await self.unseal(documents, fields=self.sealing.fields,
                                 keyring=self.sealing.keyring, count=False)
        return list(page), dict(page.refused)

    async def unseal(self, documents, *, fields: Iterable[str],
                     keyring, encryption=None, count: bool = True) -> Page:
        """Decrypt sealed fields, and refuse the documents whose key is gone.

        The read half of ``keyring.py``, and it is explicit for a reason
        that is stated at length there and worth one line here: automatic
        decryption raises ``EncryptionError`` for the whole batch when a
        single key is missing, so one crypto-erased document would turn a
        page of fifty into a 500. "Fewer rows, or an error" is the shape
        this codebase refuses everywhere else, and a crypto-erased document
        is a *normal, expected* state -- it is the feature working.

        So a missing key is a refusal, counted under ``unrecoverable``,
        beside the deadline and the revocation. Three reasons a fact may
        not reach a prompt, one question, one place that answers it.
        """
        ce = encryption or await keyring.encryption()
        fields = tuple(fields)
        # Materialised once. ``documents`` is an Iterable, and the count
        # below used to re-walk it -- which is 0 for a generator, so
        # ``examined`` silently under-reported on exactly the callers that
        # stream. A cost figure that reads 0 under load is worse than no
        # cost figure.
        documents = list(documents)
        kept, tally = [], {}
        for doc in documents:
            out = dict(doc)
            for name in fields:
                value = out.get(name)
                if not _is_ciphertext(value):
                    continue
                try:
                    out[name] = await ce.decrypt(value)
                except Exception:  # noqa: BLE001 - the whole point: a key
                    # that is gone is an answer, not an incident.
                    out = None
                    break
            if out is None:
                tally[UNRECOVERABLE] = tally.get(UNRECOVERABLE, 0) + 1
                continue
            kept.append(out)
        if count:
            # A caller that folds this into a page commits the tally once,
            # with the rest of that page's refusals -- counting here as
            # well would double it, in the one direction that makes a lower
            # bound a lie.
            self.receipts_log.record_many(tally)
        if tally:
            log.info("%s: %d document(s) are unrecoverable -- their key was "
                     "destroyed, so no read path anywhere can produce the "
                     "plaintext", self.collection, tally[UNRECOVERABLE])
        return Page(kept, refused=tally, examined=len(documents))

    # ---- the general forms ---------------------------------------------

    async def impose(self, on: str, filters: dict | None = None, *,
                     reason: str | None = None,
                     erase_after: timedelta | None = None,
                     expect: int | None = None,
                     everything: bool = False) -> tuple[int, dict | None]:
        """Apply one reason's mark to matching documents.

        Returns ``(count, receipt)`` -- both of the things callers want from
        it, from one call rather than the count coming back and the receipt
        being stashed on the handle for a second method to collect. That is
        not tidiness: handles are deduplicated per collection, so a
        ``_last_receipt`` attribute was shared mutable state on an object
        every request holds, and two concurrent revocations could hand each
        caller the other's hash. Which is the same defect ``for_caller``
        returning a clone exists to prevent, reintroduced two hundred lines
        below the comment explaining it.

        Whether the erase deadline is stamped is read off the rule, not
        passed in: irreversible reasons erase, reversible ones preserve. A
        caller cannot ask for a quarantine that deletes its own evidence,
        and cannot forget to make a revocation collectable.
        """
        rule = self._rule_for(on)
        # Checked deliberately before anything else: on a write, the caller
        # check has to happen before the collection handle is even touched,
        # or the failure mode depends on which line raises first.
        self._require_caller()
        verb = "quarantine" if rule.reversible else "revoke"
        query = self._write_query(rule, filters, present=False)
        await self._guard(verb, filters, query, expect=expect,
                          everything=everything)

        stamp = now()
        why = reason or rule.reason
        # ``$literal``, because in the pipeline form below a bare string is
        # an expression -- and ``reason`` is caller-supplied, so a value
        # beginning with ``$`` would be read as a field path and silently
        # write something else entirely.
        mark = {"$literal": {"at": stamp, "reason": why}}
        update: Any = {"$set": {rule.field: mark["$literal"]}}
        if not rule.reversible:
            # An erasure instruction, so the bytes are scheduled to go. A
            # reversible hold deliberately does not touch the deadline: the
            # row has to outlive the investigation it was held for.
            #
            # And the deadline only ever moves *earlier*. A pipeline update
            # rather than a plain ``$set`` because that invariant needs to
            # read the existing value: a row due in an hour, revoked with
            # ``erase_after=7d``, must not have its erasure pushed out to
            # seven days. Retention that grows because somebody asked for
            # erasure is the opposite of the thing being asked for.
            at = self.spec.at_field
            due = stamp + (erase_after or timedelta(0))
            update = [{"$set": {
                rule.field: mark,
                # A missing or null deadline is a *pinned* row, not an
                # early one -- ``$min`` against null would keep the null
                # and leave an erased fact pinned forever, so the two
                # cases are separated rather than folded together.
                at: {"$cond": [{"$eq": [{"$type": f"${at}"}, "date"]},
                               {"$min": [f"${at}", due]}, due]},
            }}]

        # Everything made out of what this matched goes with it. Resolved
        # before the write, because afterwards the matched documents carry
        # the mark and the query that found them no longer does.
        ids, inherited = await self._descendants(query)
        result = await self.db[self.collection].update_many(
            self._with_descendants(query, filters, ids), update)
        n = result.modified_count
        self.receipts_log.record_write(
            "held" if rule.reversible else "revoked", n, why)
        if n:
            log.info("%s %d fact(s) in %s (%s)%s; unreachable as of %s",
                     rule.reason, n, self.collection, why,
                     f", {inherited} inherited" if inherited else "",
                     stamp.isoformat())
        receipt = await self._witness(
            filters or {}, event=rule.reason, reason=why, count=n, at=stamp,
            detail={"direct": len(ids), "inherited": inherited}
            if inherited else None)
        return n, receipt

    async def lift(self, off: str, filters: dict | None = None, *,
                   reason: str, expect: int | None = None,
                   everything: bool = False) -> tuple[int, dict | None]:
        """Remove one reason's mark, if that reason has an inverse.

        Raises ``Irreversible`` when it does not, and the check is on the
        rule rather than on a list of verb names here -- so a third-party
        reason gets the same answer as a builtin, decided by the same word
        in the same place.

        The mark is ``$unset``, not set to null. Both refuse identically
        under ``Marked.refuses`` -- it tests ``is not None`` -- so the
        difference is entirely about the sparse index ``ensure()`` builds on
        the mark field: a null keeps the row in the index forever, so a
        collection that quarantines and releases in a loop would grow an
        index of documents that are not held. The rule is unaffected either
        way; the cost is not.

        **This is the only verb here that grants reachability, and it gets
        both enforcement points because of it.** Everywhere else the query
        is the optimisation and the per-document check is the guarantee;
        this is the one write where that distinction has teeth. A
        ``Clearance`` clause is an ``$in`` over the levels the caller holds,
        and its own docstring says what it cannot express: a document
        carrying a label this deployment does not recognise. On a read that
        gap is harmless -- ``refuses()`` catches it on the way out and the
        document is withheld. On a *lift* the same gap would let a caller
        re-admit a document they are not cleared to read, which is the one
        direction where "the query missed it" is a privilege escalation
        rather than a slower query.

        So candidates are admitted one at a time through the audit handle
        first, and only their ids are unset. Batched, because an id list is
        a query and a query has a size limit -- and the alternative, one
        ``update_many`` over a filter nobody checked per document, is how
        the two halves come to disagree in the direction that matters.
        """
        rule = self._rule_for(off)
        if not rule.reversible:
            raise Irreversible(
                self.collection, rule.reason,
                tuple(r.reason for r in self._imposable() if r.reversible))
        self._require_caller()
        query = self._write_query(rule, filters, present=True)
        await self._guard("release", filters, query, expect=expect,
                          everything=everything)

        stamp = now()
        audit = self.including_refused()
        # Released with the thing they were held with. A review that clears
        # a document and leaves its summaries withheld has not finished.
        ids, inherited = await self._descendants(query)
        query = self._with_descendants(query, filters, ids)
        n = 0
        batch: list = []
        cursor = self.db[self.collection].find(query, {"_id": 1, **{
            f: 1 for f in self._caller_aware_fields()}})
        async for doc in cursor:
            if audit._admit(doc) is None:
                continue
            batch.append(doc["_id"])
            if len(batch) >= LIFT_BATCH:
                n += await self._unset(rule.field, batch)
                batch = []
        if batch:
            n += await self._unset(rule.field, batch)
        self.receipts_log.record_write("lifted", n, reason)
        if n:
            log.info("lifted %s from %d fact(s) in %s (%s)",
                     rule.reason, n, self.collection, reason)
        # The chain has to record this or it is a record of one direction of
        # a two-direction transition -- intact, verifiable, and wrong about
        # whether the fact is reachable. See ledger.py.
        detail: dict = {"lifted": rule.reason}
        if inherited:
            detail |= {"direct": len(ids), "inherited": inherited}
        receipt = await self._witness(filters or {}, event=LIFTED,
                                      reason=reason, count=n, at=stamp,
                                      detail=detail)
        return n, receipt

    def _caller_aware_fields(self) -> tuple:
        """The document fields the unbypassable rules compare against.

        Projected into ``lift()``'s candidate scan so the per-document check
        has what it needs, and *only* that: the text of a quarantined
        document has no business crossing this boundary to answer a question
        about who may release it.
        """
        return tuple(f for f in (getattr(r, "field", None) for r in self.rules
                                 if not getattr(r, "bypassable", True)) if f)

    async def _unset(self, field_name: str, ids: list) -> int:
        result = await self.db[self.collection].update_many(
            {"_id": {"$in": ids}}, {"$unset": {field_name: ""}})
        return result.modified_count

    async def _witness(self, filters: dict, *, event: str, reason: str,
                       count: int, at: datetime,
                       detail: dict | None = None) -> dict | None:
        """Append to the chain, and never fail the write over it.

        Order matters and this is the unintuitive half: the rows are already
        unreachable before this runs. If appending fails, the *safe* outcome
        is the one that already happened -- the fact is refused -- and the
        loud thing to do is log it, not raise and let a caller conclude the
        revocation did not take and retry it. An unrecorded refusal is an
        audit gap; an un-refused fact is a breach. They are not the same
        size, so they do not get the same handling.

        The subject is the filter, canonicalised -- ids and a reason, never
        document text. An audit record that quotes the secret it was asked to
        forget is a fresh copy of it, exempt from every deadline here.
        """
        if self.ledger is None:
            return None
        try:
            return await self.ledger.append(
                event, tenant=self.tenant and filters.get(self.tenant),
                reason=reason, subject=filters, count=count, at=at,
                detail=detail)
        except Exception:  # noqa: BLE001 - see docstring: the write already
            # happened, and this must not undo it.
            log.exception(
                "%s %d fact(s) in %s but could not record it on the chain -- "
                "the write DID happen; the audit trail has a gap at %s",
                event, count, self.collection, at.isoformat())
            return None

    async def pin(self, filters: dict) -> int:
        """Remove a deadline. Pinning is the absence of one, not a flag."""
        return (await self.db[self.collection].update_many(
            filters, {"$set": {self.spec.at_field: None}})).modified_count

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
