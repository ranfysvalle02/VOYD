"""The vocabulary: every reason a fact may not reach a prompt.

Stable strings, and that is the whole contract of this module. They are
counted, logged, put on the chain and rendered on an operator's dashboard, so
renaming one is a breaking change to somebody's alert -- which is why they
live in the one file with no imports and no behaviour. A reason is a name
before it is a rule.
"""

from __future__ import annotations

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

# This document belongs to a different tenant than the read was scoped to.
# Counted apart from ``not_cleared`` on purpose: that one is a caller reaching
# above their clearance, which is somebody probing. This one is a document
# arriving at a boundary from outside the scope the read declared -- which,
# on the search path, means an index filter and a per-document check have
# disagreed, and exactly one of them is authoritative. A climbing
# ``off_scope`` is worth a page.
OFF_SCOPE = "off_scope"

# The context-token budget for this read was spent before this hit could be
# admitted. Not a reason the fact is *forgotten* -- a reason there was no room
# for it in the prompt being assembled. Counted apart so a climbing
# ``over_budget`` reads as "raise the budget or tighten retrieval", not "the
# system is forgetting things".
OVER_BUDGET = "over_budget"
# The budget could not be charged for this document: its cost field is missing
# or not a non-negative number. Fails closed like an unreadable deadline -- a
# hit whose size cannot be established has no business silently taking room --
# but, unlike being over budget, it does not close the page: one uncostable
# document says nothing about how much room is left.
UNCOSTED = "uncosted"
# A near-identical document was already admitted to this same read. The second
# *set*-relative reason, and it is worth saying how it differs from the first:
# ``over_budget`` is about how much room is left, ``redundant`` is about what
# is already in the room. Neither is a property of the document -- both are
# properties of the page it is joining -- which is why no index filter and no
# per-object policy engine can express either. Counted apart from everything
# above because a climbing ``redundant`` is a *chunking* problem, not a
# forgetting one: the same passage was indexed several times.
REDUNDANT = "redundant"

# The three answers ``reachability_at`` can give. ``unknown`` is the one
# worth having: a row the reaper took leaves nothing to answer from, and
# reporting that as "not reachable" would let a deployment clear itself
# by pointing at the absence of the evidence.
# The key still exists and could not be fetched. Counted apart from
# ``unrecoverable`` because they are opposite events that fail identically:
# one is somebody's erasure request being honoured, the other is an outage
# during which a dashboard reporting erasures is reporting a lie.
KEY_UNAVAILABLE = "key_unavailable"

# An embedded subject that cannot be named. Declared ``subject_key`` and no
# value for it, so there is no stable way to refer to this element -- which
# means no erasure request can ever target it, no lineage can name it, and no
# receipt can attest to it. Fails closed for the same reason ``unreadable``
# does: a fact whose lifetime cannot be established has no business in a
# prompt, and neither has one that cannot be addressed. It is the only
# refusal here that is a statement about the *schema* rather than the fact,
# and it is counted apart so it reads as "fix the writer", not "the system is
# forgetting things".
UNNAMED = "unnamed"

REACHABLE = "reachable"
REFUSED = "refused"
UNKNOWN = "unknown"

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
