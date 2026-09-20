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

# The three answers ``reachability_at`` can give. ``unknown`` is the one
# worth having: a row the reaper took leaves nothing to answer from, and
# reporting that as "not reachable" would let a deployment clear itself
# by pointing at the absence of the evidence.
# The key still exists and could not be fetched. Counted apart from
# ``unrecoverable`` because they are opposite events that fail identically:
# one is somebody's erasure request being honoured, the other is an outage
# during which a dashboard reporting erasures is reporting a lie.
KEY_UNAVAILABLE = "key_unavailable"

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
