"""Where a collection keeps the facts that make a document forgettable.

A declaration, not a mechanism: which fields carry the deadline and the mark,
which reasons are in force, whether there is a tenant. It is frozen and it is
compared by value, because handles are deduplicated per collection by spec
equality -- see the note on ``tenant`` below for what that cost when the
tenant was left out of it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, replace
from datetime import datetime

from .rules import CumulativeRule, Deadline, Rule, revoked

log = logging.getLogger("engine.admission")

@dataclass(frozen=True)
class AdmissionSpec:
    """Where a collection keeps the two facts that make a document forgettable."""

    collection: str
    at_field: str = "expire_at"
    # Set by revoke(). Present means "refuse this", independently of the
    # deadline, so an erasure request does not have to wait for a sweeper and
    # does not depend on the TTL index existing at all.
    mark_field: str = "forgotten"
    # Fields that are lossy encodings of the document's content, and must
    # be destroyed when it is erased rather than merely refused. An
    # embedding is the case that matters -- see ``Admission.impose``.
    derived_fields: tuple[str, ...] = ("embedding",)
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
    # The path to an array whose elements are subjects in their own right.
    # ``None`` -- the default, and what every collection here meant until the
    # document model stopped agreeing -- says the document is the only
    # subject, so a mark on the root is the whole answer.
    #
    # It exists because that assumption is now wrong in a way that is silent.
    # A book with chapters, a ticket with comments, a case file with notes:
    # the embedded-document pattern MongoDB recommends, and increasingly the
    # shape retrieval works over. Every rule in this package reads *top-level*
    # fields, so a chapter carrying the exact mark ``revoke()`` writes is
    # admitted with its parent, counted nowhere, and attested as "nothing was
    # refused" by ``receipt_for``. That is not a nested-index problem -- it
    # reproduces on an ordinary ``find()`` -- and the fix is to say which
    # thing is the subject instead of assuming.
    #
    # Declaring it makes ``_admit`` ask the rules of each element and drop the
    # refused ones from the document it returns, counting each by reason. See
    # ``AdmissionCore._admit`` for why redaction rather than refusing the
    # parent whole, and ``Page.redacted`` for why it can never be silent.
    subjects: str | None = None
    # The field on each embedded subject that names it. ``None`` says the
    # elements are anonymous, which is honest but limited: an anonymous
    # subject can be refused on read and can never be *addressed*.
    #
    # It is the answer to the question ``subjects`` alone leaves open. A
    # subdocument has no ``_id``, so there are only three ways to name one and
    # two of them are bad. Position -- ``chapters.3`` -- is wrong the first
    # time anybody ``$pull``s an element, and wrong silently, which on an
    # erasure path is the worst available property. Promoting every subject to
    # its own document restores every invariant and gives up the embedded
    # pattern that nested retrieval exists to serve. So the name is a field
    # the application already has or can add.
    #
    # That would ordinarily make it a convention, and this package's whole
    # complaint is about guarantees that depend on somebody remembering a
    # convention. It is not one, because it is **enforced**: with
    # ``subject_key`` declared, an element that does not carry it is refused
    # as ``unnamed`` rather than admitted. The tenant works exactly this way
    # -- application-supplied, non-optional, loud when missing -- and for the
    # same reason.
    subject_key: str | None = None
    # A stable label for *this* configuration of rules, carried into a stored
    # ``record_use`` so a consequence can be tied to the policy that produced
    # it. Part of identity on purpose: ``Budget(100)`` and ``Budget(10000)``
    # both report ``over_budget``, so a reason name is not enough to tell two
    # policies apart after the fact -- a revision is. ``None`` until a
    # deployment names one; ``record_use`` requires it, ordinary reads do not.
    policy_revision: str | None = None

    def with_defaults(self) -> AdmissionSpec:
        spec = self if self.rules else replace(
            self, rules=(Deadline(self.at_field), revoked(self.mark_field)))
        cumulative = [r for r in spec.rules
                      if getattr(r, "needs_tab", False)]
        if len(cumulative) > 1:
            names = [getattr(r, "reason", type(r).__name__) for r in cumulative]
            raise ValueError(
                f"{self.collection}: one read may declare one cumulative rule, "
                f"got {names}. They cannot share a running total: the first "
                f"rule's limit would silently govern the rest")
        if spec.subjects is not None and not spec.subjects.strip():
            raise ValueError(
                f"{self.collection}: subjects= must name a field, not an "
                f"empty string. Omit it to say the document is the subject")
        if spec.subject_key and not spec.subjects:
            raise ValueError(
                f"{self.collection}: subject_key="
                f"{spec.subject_key!r} names the field that identifies an "
                f"embedded subject, but no subjects= array was declared. "
                f"There is nothing for it to name")
        if spec.subjects and "." in spec.subjects:
            # One level, deliberately. A dotted path would mean walking into
            # arrays of arrays, and a redaction whose depth nobody can state
            # is worse than one that refuses to start: the caller cannot tell
            # what was removed from where.
            raise ValueError(
                f"{self.collection}: subjects={spec.subjects!r} is a dotted "
                f"path. Only one level of embedded subjects is supported -- "
                f"nest deeper and neither the redaction nor its accounting "
                f"can be stated in one number")
        cumulative_rule: CumulativeRule | None = (
            cumulative[0] if cumulative else None)
        if (cumulative_rule is not None
                and not callable(getattr(cumulative_rule, "new_tab", None))):
            raise TypeError(
                f"{self.collection}: cumulative rule "
                f"{getattr(cumulative_rule, 'reason', cumulative_rule)!r} "
                "declares "
                "needs_tab but has no callable new_tab()")
        return spec

    def describe(self) -> str:
        scope = f", scoped by {self.tenant}" if self.tenant else ""
        reasons = ", ".join(r.reason for r in self.rules) or "deadline, revoked"
        within = (f", per {self.subjects}[] keyed by {self.subject_key}"
                  if self.subjects and self.subject_key
                  else f", per {self.subjects}[]" if self.subjects else "")
        return f"{self.collection}: refuses on [{reasons}]{scope}{within}"


def _ask(rule, doc: dict, *, when: datetime | None,
         caller: dict | None, tab) -> str | None:
    """Ask one rule for its reason, handing it only what it declared it needs.

    A rule that exposes ``why`` returns the reason string directly, so it can
    name more than one (``Deadline`` separates expiry from unreadable,
    ``Budget`` separates over-budget from uncosted). A rule with only
    ``refuses`` returns a bool, and its single ``reason`` is the name. Claims
    are passed only to ``needs_caller`` rules and the ``Tab`` only to
    ``needs_tab`` ones, so the ordinary rules keep a signature with nothing
    irrelevant in it.
    """
    kwargs: dict = {"when": when}
    if getattr(rule, "needs_caller", False):
        kwargs["caller"] = caller
    if getattr(rule, "needs_tab", False):
        kwargs["tab"] = tab
    why = getattr(rule, "why", None)
    if callable(why):
        return why(doc, **kwargs)
    return rule.reason if rule.refuses(doc, **kwargs) else None


def why_refused(doc: dict, spec: AdmissionSpec,
                    *, when: datetime | None = None,
                    caller: dict | None = None,
                    tab=None,
                    only_unbypassable: bool = False) -> str | None:
    """The first reason this document may not reach a prompt, or ``None``.

    Asks each declared rule and returns the first refusal. Among the *pure*
    rules order is the declared order and it is reported, not merged: an
    operator needs to know a document was *quarantined* rather than merely
    expired, because the two demand different responses.

    **Cumulative rules (``needs_tab``) are asked last, whatever the declared
    order.** A budget charges its ``Tab`` as a side effect, so asking it before
    a deadline would spend room on a document that was going to be refused
    anyway -- and it must be asked only for documents every pure rule already
    admitted. Ordering that correctly is not the rule author's job to
    remember (this package's whole complaint about conventions), so it is done
    here: ``sorted`` is stable, so pure rules keep their declared order and
    the cumulative ones follow.

    Never raises, whatever a rule does. A rule that throws is treated as a
    refusal and named, because an exception inside a filter is how the
    filter gets skipped -- the failure this module exists to prevent, and it
    must not come back through a third-party rule.
    """
    rules = sorted(spec.with_defaults().rules,
                   key=lambda r: getattr(r, "needs_tab", False))
    for rule in rules:
        if only_unbypassable and getattr(rule, "bypassable", True):
            continue
        try:
            reason = _ask(rule, doc, when=when, caller=caller, tab=tab)
        except Exception:  # noqa: BLE001 - a rule must not be able to open
            # the gate by failing. Refuse, and say which rule did it.
            log.exception("rule %r raised; refusing the document", rule.reason)
            return rule.reason
        if reason is not None:
            return reason
    return None
