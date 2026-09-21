"""Fail closed, fail loud.

A missing tenant filter is a data leak that arrives as an answer. A
cosine fallback that loads the whole collection is an OOM that arrives
as latency. Neither is a ranking bug.

Presence is not the whole check. A tenant id that is *there* but is a
``dict`` is a query operator, and every tier interpolates filter values
straight into a query: ``$vectorSearch``'s ``filter`` accepts ``$ne`` and
``$gt``, the cosine fallback is a plain ``find``, and the lexical leg's
``equals`` rejects a non-scalar loudly enough to trigger the degrade path --
which then serves the same unbounded query. ``{"tenant": {"$ne": "x"}}``
therefore matched every tenant on all three tiers. So shape is checked
where presence is, and the declared type is the contract.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from bson import Binary, ObjectId

# What an id is allowed to be. Deliberately a closed list of scalars rather
# than "not a dict": a list is ``$in`` by another name on the ``find`` path,
# and Atlas's ``equals`` accepts exactly this shape anyway. Anything that can
# carry an operator is not an id.
SCALAR_ID = (str, ObjectId, int, float, bool, bytes, Binary, datetime, UUID)


class ScopeError(ValueError):
    """Base: the tenant boundary could not be established for this query.

    Caught as one thing by the query path, which counts it and refuses,
    because both subclasses have the same blast radius if served.
    """


class CallerRequired(ScopeError):
    """A collection with a caller-aware rule was read without a caller.

    Neither available answer is acceptable, which is why this raises rather
    than picking one. Returning everything is the breach the rule exists to
    prevent. Returning nothing -- which is what the query clause does on its
    own, since an unknown clearance permits no level -- is worse in a
    different way: reads come back empty and *writes silently match no rows*,
    so a revocation reports success having done nothing at all. That was a
    real bug here, found by an example rather than a test, which is the usual
    way a silent no-op is found.

    Binding an authenticated caller with no clearance claim is a different
    thing and does not raise: that caller is entitled to nothing, which is a
    real answer. ``for_caller({})`` says it.
    """

    def __init__(self, collection: str, reasons: tuple):
        self.collection = collection
        self.reasons = reasons
        super().__init__(
            f"{collection} refuses on {', '.join(reasons)}, which depends on "
            f"who is asking; call .for_caller(claims) first. Use "
            f"for_caller({{}}) for an authenticated caller holding no claims"
        )


class ScopeRequired(ScopeError):
    """A scoped primitive was queried without its tenant field.

    Returning rows would leak every tenant into the caller. Raise instead.
    """

    def __init__(self, collection: str, field: str, hint: str | None = None):
        self.collection = collection
        self.field = field
        # The egress path raises this too, and there the remedy is a different
        # verb -- there are no filters to put the tenant in. A message that
        # named only the query half would send that caller looking for an
        # argument the method does not take.
        super().__init__(
            f"{collection} is scoped by {field!r}; "
            + (hint or "pass it in filters or every tenant leaks")
        )


class ScopeInvalid(ScopeError):
    """The tenant field was present, but its value was not a scalar id.

    This is the dangerous one, because it passes a presence check. A dict in
    the tenant position is an operator: ``{"$ne": "nobody"}`` matches every
    tenant, on the vector leg, the lexical leg and the cosine fallback alike.
    """

    def __init__(self, collection: str, field: str, value: object):
        self.collection = collection
        self.field = field
        self.value = value
        super().__init__(
            f"{collection} is scoped by {field!r}, which must be a scalar id, "
            f"not {type(value).__name__}: a non-scalar is a query operator "
            f"and matches every tenant"
        )


class FilterInvalid(ValueError):
    """A declared filter field was given a non-scalar value.

    Not a tenant breach -- the tenant clause still binds -- but the lexical
    leg's ``equals`` cannot express it, so it would fail the query and hand
    the caller the cosine fallback instead, silently widening the filter to
    whatever the operator means. Refused for the same reason: the three tiers
    must agree about which documents exist.
    """

    def __init__(self, collection: str, field: str, value: object):
        self.collection = collection
        self.field = field
        self.value = value
        super().__init__(
            f"{collection}: filter {field!r} must be a scalar, not "
            f"{type(value).__name__}; operators are not pushable into the "
            f"search index and would change tier behaviour"
        )


def require_tenant(collection: str, field: str | None,
                   filters: dict | None) -> dict:
    """The tenant half of ``require_scope``, for callers that query the
    collection directly.

    A plain ``find`` can express operators perfectly well -- ``doc_id:
    {"$in": [...]}`` is how you forget a batch -- so the blanket scalar rule
    that protects the *search* path would be wrong here. What still holds,
    and holds everywhere, is the tenant: present, and a scalar, because a
    dict in that position is an operator that matches every tenant.

    Learned the hard way: reusing ``require_scope`` here refused
    ``forget(doc_ids=[...])``, which is a legitimate batched write. One rule
    per hazard, rather than one rule reused past its reason.
    """
    flt = dict(filters or {})
    if not field:
        return flt
    if field not in flt or flt[field] is None:
        raise ScopeRequired(collection, field)
    if not isinstance(flt[field], SCALAR_ID):
        raise ScopeInvalid(collection, field, flt[field])
    return flt


def require_scope(collection: str, field: str | None,
                  filters: dict | None) -> dict:
    """Return a copy of ``filters``, or raise if the tenant is missing or unsafe.

    The search path's rule: ``require_tenant`` plus the stricter condition
    that *every* filter value is a scalar. That extra clause is about the
    index rather than the tenant -- the lexical leg's ``equals`` cannot
    express an operator, so one would fail the query and hand the caller the
    cosine fallback with a silently wider filter.

    Raises ``ScopeRequired`` / ``ScopeInvalid`` for the tenant, and
    ``FilterInvalid`` for anything else that is not a scalar.
    """
    flt = require_tenant(collection, field, filters)

    for key, value in flt.items():
        if key == field or value is None:
            continue
        if not isinstance(value, SCALAR_ID):
            raise FilterInvalid(collection, key, value)

    return flt


class Irreversible(ValueError):
    """A lift was asked for on a reason that has no inverse.

    The family resemblance is to ``CallerRequired`` above: both are
    operations where every available answer is wrong, so neither picks one.

    Refusal reasons are not one kind of thing, and the difference is not
    stylistic. A *quarantine* is a hypothesis -- this document looks
    poisoned, hold it while somebody looks -- and a hypothesis that cannot be
    withdrawn is not an investigation, it is a graveyard. A *revocation* is
    an instruction about the world that got worse: an erasure request, a
    leaked credential, a retracted document. None of those turn out to be
    false, and the honest response to "the subject re-consented" is a new
    document with a new id and a new consent record, not the resurrection of
    a row that still carries the mark saying it was erased.

    The harder reason: **an undo would be a lie about its own
    availability.** Imposing an irreversible reason also stamps the erase
    deadline, so the reaper takes the row on its next sweep. A lift would
    therefore work, and work, and then silently stop working, according to
    ``ttlMonitorSleepSecs`` -- an API whose window is a storage event, in
    the one codebase written to argue that retrieval guarantees must not
    depend on sweepers.
    """

    def __init__(self, collection: str, reason: str, reversible: tuple):
        self.collection = collection
        self.reason = reason
        self.reversible = reversible
        offer = (f"reversible here: {', '.join(reversible)}" if reversible
                 else "no reason on this collection is reversible")
        super().__init__(
            f"{collection}: {reason!r} cannot be lifted. An erasure is not a "
            f"hypothesis, and the row is already scheduled for the reaper, so "
            f"an undo would depend on the sweeper it was written to avoid. "
            f"To re-admit the information, write it again as a new document "
            f"with its own provenance ({offer})"
        )


class UnknownReason(ValueError):
    """A verb named a reason this collection does not refuse on.

    Silence would be worse than it looks. ``lift("quarantined")`` against a
    collection that never installed the rule would find no mark, modify no
    rows, and report success -- so an investigation would close on a document
    that is still being held, or still being served, depending on which way
    the mistake ran. A verb naming a reason that is not installed is a
    declaration bug, and declaration bugs should be loud at the call site.
    """

    def __init__(self, collection: str, reason: str, known: tuple):
        self.collection = collection
        self.reason = reason
        self.known = known
        super().__init__(
            f"{collection} has no imposable reason {reason!r}; it refuses on "
            f"[{', '.join(known) or 'nothing imposable'}]. A reason is "
            f"imposable when its rule declares `reversible`"
        )


class BlastRadius(ValueError):
    """A write that forgets things matched a different number than expected.

    ``revoke()`` has no undo and the reaper collects its rows within a
    sweep, which makes it the one call in this package where the damage is
    done before anybody reads the return value. Everywhere else, this
    codebase's rule is that you have to *declare* you want the unsafe thing
    -- ``including_refused()`` is a named method for exactly that reason --
    and a filter that silently matched forty thousand documents instead of
    one declared nothing.

    So the interlock is opt-in and pre-flight: pass ``expect=`` and the count
    is taken, compared, and the write is skipped on a mismatch. Best effort
    by construction, and worth stating plainly rather than implying
    otherwise: a document inserted between the count and the update is not
    covered. It catches the mistake that actually happens -- a filter that
    was wrong when it was typed -- not a concurrent writer.
    """

    def __init__(self, collection: str, expected: int, matched: int):
        self.collection = collection
        self.expected = expected
        self.matched = matched
        super().__init__(
            f"{collection}: filter matched {matched} document(s), expected "
            f"{expected}; nothing was written. This call has no undo, so the "
            f"count is checked before the write, not reported after it"
        )


class UnboundedForgetting(ValueError):
    """A forgetting write was handed a filter that matches the whole scope.

    Reading everything is a normal thing to want. *Forgetting* everything is
    not, and the two must not be one keystroke apart: ``revoke({})`` is a
    plausible typo for ``revoke({"doc_id": x})`` with the argument dropped,
    and it erases a tenant.

    Naming it costs one keyword and follows the pattern already established
    by ``including_refused()``: the safe thing is what you get by default,
    and the dangerous thing exists but has to be said out loud, in a word a
    reviewer can grep for.
    """

    def __init__(self, collection: str, verb: str):
        self.collection = collection
        self.verb = verb
        super().__init__(
            f"{collection}: {verb}() with no filter would apply to every "
            f"document in the scope. If that is the intent, say so: "
            f"{verb}(..., everything=True)"
        )


class DerivationBroken(ValueError):
    """A document was about to be made out of one that may not be used.

    Refusal stops a *document* reaching a prompt. It says nothing about the
    paragraph an agent wrote after reading it -- and that paragraph goes
    back into the same collection and keeps scoring well forever. So the
    erasure request is honoured against the source and defeated by the
    summary, which is this package's own failure arriving through the one
    door it left open.

    ``derive()`` closes that door from the write side, and it refuses rather
    than writing-and-marking because the two available explanations for
    getting here are both bugs worth surfacing:

    - something read a document it should not have been handed, and is now
      laundering it into a new one. Writing the child and immediately
      marking it would hide the read that should not have happened.
    - the caller derived from a handle that never checked -- a raw
      collection read, or an ``including_refused()`` audit handle used as
      an ordinary one. That is a mistake in the calling code, and it should
      fail at the line that made it.

    The parent may also simply be outside the caller's scope or clearance,
    which reports the same way on purpose: "you may not build on this" is
    one answer, and splitting it into "gone" and "forbidden" would tell an
    unprivileged caller which ids exist.
    """

    def __init__(self, collection: str, parents: list, reason: str):
        self.collection = collection
        self.parents = parents
        self.reason = reason
        super().__init__(
            f"{collection}: cannot derive from {', '.join(parents)} "
            f"({reason}). A fact made out of a refused fact is how an "
            f"erasure gets defeated by a summary -- if the source may not "
            f"reach a prompt, neither may anything built on it"
        )


class ContextIncomplete(ValueError):
    """A use was about to be recorded that could not be stood behind.

    ``record_use`` writes the record an incident review reads a year later:
    *this answer was produced from these facts, under this policy, at this
    instant.* Every part of that sentence has to be true, and the parts are
    not independently optional -- a record missing the instant does not say
    less than a complete one, it says something that cannot be checked, in a
    collection whose entire purpose is to be checkable.

    The tempting alternative is to fill the gaps: stamp ``now()`` when the
    page cannot say when it was read, write ``"unknown"`` where a policy
    revision should be. Both produce a record that *looks* like evidence and
    exonerates a context nobody ever verified, which is worse than the
    absence it replaces. So this refuses, the same way ``derive()`` refuses
    a parent it should never have been handed: every available answer is
    wrong, so it picks none.

    ``missing`` names what was absent, all of it at once, because fixing
    these one raise at a time is three deploys.
    """

    def __init__(self, collection: str, missing: tuple,
                 remedy: str | None = None):
        self.collection = collection
        self.missing = tuple(missing)
        super().__init__(
            f"{collection}: cannot record this use without "
            f"{', '.join(self.missing)}. "
            + (remedy or
               "A page from this handle carries the instant it was admitted "
               "at and the policy revision it was admitted under; a bare "
               "list carries neither. Read through the handle, declare "
               "policy_revision on the model, and name the consequence")
        )
