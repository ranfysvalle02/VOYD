"""What a policy change would let through, before it is deployed.

Every other module here answers *may this fact reach a prompt?* about one
document under one policy. This one asks it twice -- under the policy in
force and under the policy somebody is proposing -- and reports the
difference.

It exists because the per-document check is **pure**. ``why_refused`` takes
a document, a spec and a clock, touches no database and holds no state, so
nothing stops it being asked about a policy that is not deployed, or about
an instant that is not now. A boundary whose enforcement lived inside the
query could not have this file at all: there would be nowhere to stand to
ask the question except the production cluster, and no way to ask it about
a policy the cluster has never seen.

The asymmetry from the README runs through everything below. A change that
**refuses more** is visible the moment it ships -- somebody's result set
gets shorter and they say so. A change that **admits more** is silent, and
on a retrieval workload it reads as better recall. So the two directions
are not weighted equally here: ``newly_reachable`` is the finding, and
everything else is context around it.

What this file will not do is guess. Three kinds of question cannot be
answered per document, and each is set aside **by name** rather than
folded into a total:

    set-relative rules   ``budget``/``distinct`` refuse a document because
                         of the *other* documents on the page. A sample is
                         not a page, so a per-document answer about one is
                         not a weaker answer -- it is a different question.
    caller-dependent     ``clearance``/``restricted_to`` decide by who is
    rules                asking. Planned only against a caller you name.
    the tenant           enforced by the handle against the scope a read is
                         bound to, not by a rule. Structural here: a plan
                         reports that the boundary moved, not which rows
                         crossed it.

A plan that quietly dropped any of those would be this package's own
complaint, one level up: a guarantee that looks total and has a hole in it
that nothing announces.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any, Callable, Iterable, Mapping, Sequence

from .admission.spec import AdmissionSpec, why_refused


# Why a rule could not be planned. Stable strings, for the same reason the
# reasons in ``admission.reasons`` are: they are rendered, counted and
# asserted against.
SET_RELATIVE = "set-relative"
NEEDS_CALLER = "caller-dependent"

# What a structural change does to the boundary. ``fails_open`` is not a
# severity -- it is the direction, and it is the only thing that decides an
# exit code.
GUARD_REMOVED = "guard_removed"
GUARD_ADDED = "guard_added"
TENANT_REMOVED = "tenant_removed"
TENANT_ADDED = "tenant_added"
TENANT_CHANGED = "tenant_changed"
SUBJECTS_REMOVED = "subjects_removed"
SUBJECTS_ADDED = "subjects_added"


@dataclass(frozen=True)
class SetAside:
    """A rule this plan did not evaluate, and why not.

    Carried rather than logged, because the caller has to be able to render
    it beside the counts. A number presented without the rules that were
    excluded from it is a number that overstates its own coverage.
    """

    collection: str
    rule: str
    why: str


@dataclass(frozen=True)
class Structural:
    """A change to the shape of the boundary, not to what one rule decides.

    Separate from the per-document counts because it does not depend on a
    sample and is not weakened by one. A collection that loses its ``@guard``
    is unguarded for every document that will ever be written to it, not for
    the 500 this plan happened to look at -- so it is stated as a fact about
    the policy rather than an estimate from the data.
    """

    collection: str
    kind: str
    detail: str
    fails_open: bool


@dataclass
class CollectionPlan:
    """The difference two policies make to one collection's documents.

    Four buckets, and they partition the sample. ``newly_reachable`` is
    keyed by the reason the *current* policy gave, because the useful
    question about a document that is about to become visible is what was
    keeping it hidden.
    """

    collection: str
    sampled: int = 0
    newly_reachable: dict[str, int] = field(default_factory=dict)
    newly_refused: dict[str, int] = field(default_factory=dict)
    reason_changed: dict[tuple[str, str], int] = field(default_factory=dict)
    unchanged_admitted: int = 0
    unchanged_refused: int = 0
    set_aside: tuple[SetAside, ...] = ()
    # True when every rule on one side or the other was set aside, so the
    # counts above describe a comparison that did not really happen. Reported
    # rather than silently returning zeroes, which would read as "no change".
    not_compared: bool = False

    @property
    def newly_reachable_total(self) -> int:
        return sum(self.newly_reachable.values())

    @property
    def newly_refused_total(self) -> int:
        return sum(self.newly_refused.values())

    @property
    def changed(self) -> bool:
        return bool(self.newly_reachable or self.newly_refused
                    or self.reason_changed)


@dataclass
class Plan:
    """Everything two policies disagree about, and everything they did not say.

    ``fails_open`` is the whole output compressed to one bit, and it is the
    bit a CI gate reads. It is true when the proposed policy would admit a
    document the current one refused, or when the boundary itself moved in
    the admitting direction. It is deliberately *not* true for a change that
    refuses more: that is a decision somebody made and will hear about, and
    a tool that blocked it would teach people to pass ``--force``.
    """

    collections: list[CollectionPlan] = field(default_factory=list)
    structural: list[Structural] = field(default_factory=list)
    when: datetime | None = None
    caller: dict | None = None
    # Total documents looked at, across collections. Named ``sampled``
    # rather than ``scanned`` because it usually is one.
    sampled: int = 0
    # Whether every document was read, rather than a sample of them. It
    # changes no count and it changes the only sentence that matters: a
    # sample supports a statement about the sample, and "nothing becomes
    # reachable" is a statement about the collection. Only a full read
    # earns it, so only a full read is allowed to say it.
    exhaustive: bool = False

    @property
    def fails_open(self) -> bool:
        return (any(c.newly_reachable for c in self.collections)
                or any(s.fails_open for s in self.structural))

    @property
    def newly_reachable_total(self) -> int:
        return sum(c.newly_reachable_total for c in self.collections)

    @property
    def set_aside(self) -> tuple[SetAside, ...]:
        return tuple(s for c in self.collections for s in c.set_aside)

    @property
    def changed(self) -> bool:
        return bool(self.structural) or any(c.changed for c in self.collections)


# ---- making a spec answerable per document -----------------------------

def _unplannable(rule: Any, *, with_caller: bool) -> str | None:
    """Why this rule cannot be asked about one document, or ``None``.

    Order matters by one case: a rule that is both cumulative and
    caller-aware is reported as set-relative, because supplying a caller
    would not make it plannable and offering that as the fix would be
    advice that does not work.
    """
    if getattr(rule, "needs_tab", False):
        return SET_RELATIVE
    if getattr(rule, "needs_caller", False) and not with_caller:
        return NEEDS_CALLER
    return None


def plannable(spec: AdmissionSpec | None, *,
              with_caller: bool) -> tuple[AdmissionSpec | None,
                                          tuple[SetAside, ...]]:
    """This spec with the unanswerable rules removed, and their names.

    ``None`` in means the collection is not guarded at all by that policy,
    and ``None`` comes back out: an absent guard is not an empty one. The
    difference is the whole point of the ``guard_removed`` finding, and
    running a bare ``AdmissionSpec`` through ``with_defaults()`` would
    manufacture a deadline and a revocation the policy never declared.

    ``None`` also comes back when *every* rule was set aside, and for a
    reason that is easy to get wrong: ``with_defaults()`` installs the two
    default rules whenever ``rules`` is empty. A spec stripped down to
    nothing would therefore come back guarded by a deadline and a mark that
    the operator did not write, and the plan would report a difference
    manufactured entirely by this function.
    """
    if spec is None:
        return None, ()
    spec = spec.with_defaults()
    keep, aside = [], []
    for rule in spec.rules:
        why = _unplannable(rule, with_caller=with_caller)
        if why is None:
            keep.append(rule)
        else:
            aside.append(SetAside(spec.collection,
                                  getattr(rule, "reason", repr(rule)), why))
    if not keep:
        return None, tuple(aside)
    return replace(spec, rules=tuple(keep)), tuple(aside)


def _reason(spec: AdmissionSpec | None, doc: Mapping, *,
            when: datetime | None, caller: dict | None) -> str | None:
    """Why this policy refuses this document, or ``None`` for admitted.

    An unguarded collection admits everything, which is not a quirk of this
    function -- it is what deleting a ``@guard`` means, and stating it here
    is what makes ``guard_removed`` show up in the per-document counts as
    well as in the structural list.
    """
    if spec is None:
        return None
    return why_refused(dict(doc), spec, when=when, caller=caller)


# ---- the comparison ----------------------------------------------------

def compare(collection: str,
            current: AdmissionSpec | None,
            proposed: AdmissionSpec | None,
            docs: Iterable[Mapping],
            *,
            when: datetime | None = None,
            caller: dict | None = None) -> CollectionPlan:
    """Ask both policies about every document, and bucket the disagreements.

    Pure: no database, no connection, no clock unless one is handed in. The
    documents arrive as an iterable so a caller can stream a whole
    collection through without holding it, and are counted as they pass
    rather than measured up front.
    """
    cur, cur_aside = plannable(current, with_caller=caller is not None)
    new, new_aside = plannable(proposed, with_caller=caller is not None)
    out = CollectionPlan(collection, set_aside=cur_aside + new_aside)
    # Both sides unplannable means the only rules either policy declared are
    # ones this file will not guess about. Counting zero differences would
    # be indistinguishable from "these policies agree", which is the one
    # thing it must not be mistaken for.
    out.not_compared = (cur is None and current is not None
                        and new is None and proposed is not None)
    if out.not_compared:
        return out
    for doc in docs:
        out.sampled += 1
        before = _reason(cur, doc, when=when, caller=caller)
        after = _reason(new, doc, when=when, caller=caller)
        if before == after:
            if before is None:
                out.unchanged_admitted += 1
            else:
                out.unchanged_refused += 1
        elif after is None and before is not None:
            out.newly_reachable[before] = out.newly_reachable.get(before, 0) + 1
        elif before is None and after is not None:
            out.newly_refused[after] = out.newly_refused.get(after, 0) + 1
        elif before is not None and after is not None:
            key = (before, after)
            out.reason_changed[key] = out.reason_changed.get(key, 0) + 1
    return out


def structural(current: Mapping[str, AdmissionSpec],
               proposed: Mapping[str, AdmissionSpec]) -> list[Structural]:
    """Changes to the shape of the boundary, independent of any document.

    These are the findings a sample cannot strengthen and an empty
    collection cannot hide. They are computed from the two policy files
    alone, which means a plan run against a cluster that happens to hold no
    data still reports every one of them.
    """
    found: list[Structural] = []
    for name in sorted(set(current) | set(proposed)):
        was, now = current.get(name), proposed.get(name)
        if was is not None and now is None:
            found.append(Structural(
                name, GUARD_REMOVED,
                "the collection is no longer guarded: every document in it "
                "becomes reachable, including ones written after this change",
                True))
            continue
        if was is None or now is None:
            found.append(Structural(
                name, GUARD_ADDED, "newly guarded by this policy", False))
            continue
        if was.tenant and not now.tenant:
            found.append(Structural(
                name, TENANT_REMOVED,
                f"reads were scoped by {was.tenant!r} and no longer are: "
                f"a read can return documents belonging to any tenant",
                True))
        elif now.tenant and not was.tenant:
            found.append(Structural(
                name, TENANT_ADDED,
                f"reads become scoped by {now.tenant!r}", False))
        elif was.tenant and now.tenant and was.tenant != now.tenant:
            # Not fail-open by construction and not safe either: the new
            # field may be absent from every document, in which case the
            # scope matches nothing, or present and wrong, in which case it
            # scopes to the wrong thing. Neither is decidable from the
            # policy files, so this says so instead of picking.
            found.append(Structural(
                name, TENANT_CHANGED,
                f"the tenant moves from {was.tenant!r} to {now.tenant!r}; "
                f"whether documents carry the new field is not a question "
                f"the policy files can answer",
                True))
        if was.subjects and not now.subjects:
            found.append(Structural(
                name, SUBJECTS_REMOVED,
                f"{was.subjects}[] elements stop being subjects: a mark on "
                f"one is no longer read, and the parent is admitted whole",
                True))
        elif now.subjects and not was.subjects:
            found.append(Structural(
                name, SUBJECTS_ADDED,
                f"{now.subjects}[] elements become subjects in their own "
                f"right", False))
    return found


def plan(current: Mapping[str, AdmissionSpec],
         proposed: Mapping[str, AdmissionSpec],
         sample: Callable[[str], Iterable[Mapping]],
         *,
         when: datetime | None = None,
         caller: dict | None = None,
         collections: Sequence[str] | None = None,
         exhaustive: bool = False) -> Plan:
    """The whole difference: structural findings plus per-document counts.

    ``sample`` is a function from a collection name to documents, which is
    where every trace of I/O in this feature lives. A test hands in a list;
    the CLI hands in a ``$sample`` against a cluster; a future replay hands
    in an oplog reader. None of them changes a line below.
    """
    names = sorted(set(current) | set(proposed))
    if collections is not None:
        wanted = set(collections)
        names = [n for n in names if n in wanted]
    out = Plan(when=when, caller=dict(caller) if caller else None,
               exhaustive=exhaustive)
    out.structural = [s for s in structural(current, proposed)
                      if collections is None or s.collection in names]
    for name in names:
        one = compare(name, current.get(name), proposed.get(name),
                      sample(name), when=when, caller=caller)
        out.collections.append(one)
        out.sampled += one.sampled
    return out
