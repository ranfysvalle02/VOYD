"""What the answer is, for one document.

The handle owns *that* there is an answer on every read. A rule owns *what*
the answer is. Adding a reason is therefore a new class in this file rather
than a new branch in a predicate that keeps growing -- and a third-party rule
is the same kind of object as a builtin one, with no privileged path.

There are two kinds of rule, and the difference is the only subtlety in this
file:

- **pure** -- a function of one document (and, for some, the caller): a
  deadline, a revocation, a clearance. Order-independent, side-effect-free,
  testable as pure functions.
- **cumulative** -- a function of one document *and a running total across
  the read*: a token budget. It declares ``needs_tab`` and is handed a
  ``Tab`` scoped to that one read, which it charges as a side effect.

That side effect is why cumulative rules are asked **last**, after every pure
rule has had its say -- ``spec.why_refused`` enforces the order so a budget
never charges a document that a deadline was going to refuse anyway. A rule
author does not arrange this; declaring ``needs_tab`` is the whole contract.

Nothing here touches a database, a caller or a receipt. That is what makes
the pure reasons testable as pure functions, and it is why this module sits
at the bottom of the package with only the vocabulary beneath it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, ClassVar, Protocol

from ..time import aware, living, now
from .reasons import (DEADLINE, NOT_CLEARED, OVER_BUDGET, QUARANTINED,
                      REVOKED, UNCOSTED, UNREADABLE, UNRECOVERABLE,
                      WRONG_MODEL)


log = logging.getLogger("engine.admission")

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
#                 guarantee -- search hits do not pass through that clause.


class Rule(Protocol):
    """One reason a document may not reach a prompt.

    Four optional class attributes change how a rule is treated, and all
    four default to the behaviour of the original rules:

    ``needs_caller``  the rule compares the document against *who is asking*,
                      so it is handed the caller's claims. A rule without it
                      is never passed them, which keeps the ordinary rules
                      free of a parameter they have no use for.
    ``needs_tab``     the rule is *cumulative*: it compares the document
                      against a running total for the read, so it is handed
                      a ``Tab`` and is asked only after every pure rule has
                      admitted the document. A budget is the one built-in.
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

    The four attributes above and ``why()`` below are optional extensions
    discovered with ``getattr``. They are deliberately *not* members of this
    protocol: putting an optional method on a Python ``Protocol`` makes it
    required to static type checkers and would falsely reject ordinary
    third-party rules.
    """

    reason: str
    def refuses(self, doc: dict, *, when: datetime | None = None) -> bool: ...

    def clause(self) -> dict | None: ...


@dataclass
class Tab:
    """One read's running budget. Mutable, and scoped to a single read.

    It is *not* stored on the rule or the handle, and that is the whole point.
    A handle is deduplicated per collection and cloned per caller, so a
    running total living on it would bleed one request's spend into another's
    under concurrency -- the same reason ``for_caller`` returns a new handle
    rather than assigning to ``self``. So the core opens a fresh ``Tab`` for
    each read and hands it to the cumulative rules; nothing survives the call.

    ``charge`` is all-or-nothing per document: a cost that does not fit is not
    partially spent, and the tab latches ``exhausted`` so the *first* document
    that overflows ends admission for the read (a strict prefix -- see
    ``Budget`` for why "skip the whale and take the next small one" is
    rejected).
    """

    limit: int
    spent: int = 0
    exhausted: bool = False

    def charge(self, cost: int) -> bool:
        """Spend ``cost`` if it fits. Returns whether it did.

        A cost that does not fit latches ``exhausted`` and is not spent, so
        ``spent`` is always the sum of what was actually admitted. Once
        latched the tab stays closed: a later, smaller cost is refused too,
        because the prefix ended at the first overflow -- the strict-prefix
        guarantee lives here, not only in ``Budget``, so any cumulative rule
        that charges a tab inherits it.
        """
        if isinstance(cost, bool) or not isinstance(cost, int) or cost < 0:
            raise ValueError("Tab.cost must be a non-negative integer")
        if self.exhausted or self.spent + cost > self.limit:
            self.exhausted = True
            return False
        self.spent += cost
        return True


class CumulativeRule(Rule, Protocol):
    """The documented shape of the one cumulative rule a spec may declare.

    Present for authors and type checkers, not used for runtime dispatch and
    not exported from the engine. ``needs_tab`` is a class contract (not a
    constructor switch), ``new_tab`` creates per-read state, and ``why`` may
    return a sub-reason such as ``uncosted``.
    """

    needs_tab: ClassVar[bool]

    def new_tab(self) -> Tab: ...

    def why(self, doc: dict, *, when: datetime | None = None,
            tab: Tab | None = None) -> str | None: ...


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

    def clause_at(self, when: datetime) -> dict:
        """The same rule, evaluated at an instant rather than at now."""
        return living(self.at_field, when=when)


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
        """Present means no -- *as of* ``when``, not unconditionally.

        The mark has always carried an ``at``, and this always ignored it,
        which was invisible until ``as_of()`` existed and then wrong in
        the one direction that matters: a document revoked at 14:05 would
        have reported as unreachable at 14:02, so a system reconstructing
        what a model was allowed to see would place the erasure *before*
        the answer that quoted the fact. That is an exoneration built out
        of a bug.

        Read defensively, because a mark is operator-written and this runs
        inside a filter: a mark with no readable ``at`` refuses at every
        instant, which is the same fail-closed direction ``Deadline``
        takes for a deadline it cannot parse.
        """
        mark = doc.get(self.field)
        if mark is None:
            return False
        if when is None:
            return True
        at = mark.get("at") if isinstance(mark, dict) else None
        if not isinstance(at, datetime):
            return True
        try:
            return aware(at) <= aware(when)
        except (TypeError, ValueError, OverflowError):
            return True

    def clause(self) -> dict | None:
        return {"$or": [{self.field: None}, {self.field: {"$exists": False}}]}

    def clause_at(self, when: datetime) -> dict:
        """The same rule, at an instant, as a query fragment."""
        return {"$or": [{self.field: None},
                        {self.field: {"$exists": False}},
                        {f"{self.field}.at": {"$gt": when}}]}


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


@dataclass(frozen=True)
class Budget:
    """Refused because the read's context-token budget was spent.

    The first *cumulative* rule, and the reason the protocol grew a ``Tab``.
    ``Rule`` answers *may this reach a prompt?*; a budget is the same question
    with a different reason -- ``over_budget`` -- asked once the room is gone.
    It is evidence the rule protocol is a primitive rather than a compliance
    feature: a reason with nothing to do with erasure, expressed in the same
    shape as one that is.

        docs = engine.model("notes").admitting(Deadline(), Budget(limit=8000))
        page = await docs.search(vector, limit=20)   # stops at ~8000 tokens

    **Cost is the caller's to define, never guessed.** ``cost`` is a callable
    over the document; by default it reads an integer ``cost_field`` (a
    ``tokens`` a pipeline already computed). This package ships no tokenizer,
    because a number that pretends to match a vendor's counting is exactly the
    fabricated precision it refuses everywhere else. A missing or non-numeric
    cost is ``uncosted`` -- refused, failing closed like an unreadable
    deadline, but it does *not* close the page: one uncostable document says
    nothing about the room left.

    **A strict prefix, on purpose.** The first document that does not fit ends
    admission for the read; a later, smaller hit is not slipped in ahead of
    it. Admitting by size would reorder results by how big they are rather
    than by how relevant -- the same silent reordering ``search.py`` documents
    for a rule in ``compound.must`` -- so the budget cuts the ranking at a
    point, it does not repack it. ``search`` already has a relevance order;
    budgeted ``find`` therefore requires an explicit ``sort`` rather than
    pretending MongoDB's natural order is a stable policy.

    **No query half, and there never can be one.** ``clause()`` is ``None``: a
    running total is not something a per-document query can express. Per
    ``docs/AHA.md`` that is the safe asymmetry -- per-document-only is slower, not a
    hole; a clause-only rule would be the hole -- and ``Unrecoverable`` is the
    existing precedent for a rule that lives entirely on egress.

    Bypassable, because the audit handle is not assembling a prompt and has no
    budget to keep. Not reversible: nobody imposes a budget with a verb, so
    ``impose()``/``lift()`` correctly never target it. It applies to reads that
    return prompt content -- ``search``/``saturate``, ``find``, ``find_one``
    and ``reachable``. A singleton gets a fresh tab of its own. Cardinality
    and reconstruction operations (``count``, ``exists``, ``reachability_at``)
    return no content page and deliberately do not apply it.
    """

    limit: int
    cost: Callable[[dict], Any] | None = None
    cost_field: str = "tokens"
    reason: str = OVER_BUDGET
    needs_tab: ClassVar[bool] = True
    bypassable: ClassVar[bool] = True

    def __post_init__(self) -> None:
        """Reject a configuration whose arithmetic would be ambiguous.

        Token counts are non-negative integers. Accepting ``3.7`` and silently
        truncating it to ``3`` would let a page exceed the budget while every
        receipt still looked exact; accepting ``True`` as ``1`` is the same
        Python footgun in a different coat. Configuration errors are cheap at
        construction, so the limit fails there rather than making every
        document ``over_budget`` at runtime.
        """
        if isinstance(self.limit, bool) or not isinstance(self.limit, int):
            raise TypeError("Budget.limit must be a non-negative integer")
        if self.limit < 0:
            raise ValueError("Budget.limit must be a non-negative integer")
        if not isinstance(self.cost_field, str) or not self.cost_field:
            raise ValueError("Budget.cost_field must be a non-empty string")
        if self.cost is not None and not callable(self.cost):
            raise TypeError("Budget.cost must be callable or None")

    def new_tab(self) -> Tab:
        """A fresh budget for one read. The core calls this per read."""
        return Tab(limit=self.limit)

    def _cost_of(self, doc: dict) -> Any:
        return self.cost(doc) if self.cost is not None else doc.get(self.cost_field)

    def why(self, doc: dict, *, when: datetime | None = None,
            tab: Tab | None = None) -> str | None:
        """The reason, charging the tab as a side effect.

        Returns ``None`` (admit and charge), ``over_budget`` (no room), or
        ``uncosted`` (cannot tell how big it is). Read defensively, because
        the cost may come from a document field or third-party callable and
        this runs inside the filter that must never raise.
        """
        if tab is None:
            return None                       # not a set read: nothing to say
        if tab.exhausted:
            return self.reason                # the prefix is already closed
        try:
            cost = self._cost_of(doc)
        except Exception:  # noqa: BLE001 - third-party costing must fail closed
            log.exception("budget cost failed; refusing the document as uncosted")
            return UNCOSTED
        if (isinstance(cost, bool) or not isinstance(cost, int)
                or cost < 0):
            return UNCOSTED
        return None if tab.charge(cost) else self.reason

    def refuses(self, doc: dict, *, when: datetime | None = None,
                tab: Tab | None = None) -> bool:
        return self.why(doc, when=when, tab=tab) is not None

    def clause(self) -> dict | None:
        return None


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
