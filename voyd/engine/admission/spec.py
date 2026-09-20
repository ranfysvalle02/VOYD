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

from .rules import Deadline, Rule, revoked

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

    def with_defaults(self) -> AdmissionSpec:
        if self.rules:
            return self
        return replace(self, rules=(Deadline(self.at_field),
                                    revoked(self.mark_field)))

    def describe(self) -> str:
        scope = f", scoped by {self.tenant}" if self.tenant else ""
        reasons = ", ".join(r.reason for r in self.rules) or "deadline, revoked"
        return f"{self.collection}: refuses on [{reasons}]{scope}"


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
