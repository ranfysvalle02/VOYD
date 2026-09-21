"""Admission as a retrieval guarantee, not a storage event.

Ranking is not permission. An index decides what is *relevant*; nothing in the
ordinary read path is asked whether a fact may *reach a prompt*. This module
adds that second, missing check -- and the distinction it turns on is deletion
versus refusal:

    deletion  is a storage operation -- eventually consistent, by nature.
              A TTL monitor sweeps about once a minute. An object lifecycle
              rule runs about once a day. A cron runs when it last worked.

    refusal   is a retrieval guarantee -- immediate, by construction.
              "This fact may not reach a prompt", answered on every read,
              before anything is returned.

Ordinary stacks do not make the second one structural, so the honest answer
to "when was this forgotten?" is really "when did the sweeper get to it?" --
and in the gap between those two, a deleted document is still being returned
as a well-scored result.

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
belt-and-braces paranoia. Adding a deadline filter to an existing vector index
requires an unmigratable index change -- see ``search.py`` for the
measurements -- and a ``$vectorSearch`` hit does not pass through the
collection query. ``reachable()`` is what every search path calls, including
the index-free cosine fallback, so it is the guarantee; either pushed-down
filter is the optimisation.

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

----

**Where things are.** This was one 2,393-line module until the guarantee got
hard to find inside it. The split is by *job*, and the order below is the
dependency order -- each layer may only reach the ones above it:

    reasons.py      the vocabulary. Stable strings, no behaviour, no imports.
    rules.py        what the answer is, for one document. Pure functions.
    spec.py         where a collection keeps its deadline and its mark.
    receipts.py     what a read cost, and what a handle has refused.
    core.py         the state, and the two enforcement points.
    reads.py        every way out, all of them ending at ``_admit``.
    marks.py        imposing a reason, and lifting one where it inverts.
    lineage.py      making a refusal travel to what was made of it.
    sealing.py      the erasure refusal cannot perform.
    attestation.py  what the model was allowed to see.
    handle.py       the one object a caller holds, composed of the above.

Import from the package, not from the modules: ``from voyd.engine.admission
import Admission, AdmissionSpec``. The layout above is an implementation
detail and the names below are not.
"""

from __future__ import annotations

# Re-exported for the tests and callers that already import them from
# here. ``Rule`` and ``AdmissionCore`` are deliberately *not* in
# ``__all__``: see test_the_extension_point_protocols_are_documentation
# _not_imports -- advertising a protocol suggests a base class to
# inherit, and there is none.
from .core import AdmissionCore  # noqa: F401
from .handle import Admission
from .reasons import (DEADLINE, KEY_UNAVAILABLE, LIFTED, LIFT_BATCH,
                      NOT_CLEARED, OFF_SCOPE, OVER_BUDGET, QUARANTINED, REACHABLE,
                      REDUNDANT,
                      REFUSED, REVOKED, UNCOSTED, UNKNOWN, UNNAMED,
                      UNREADABLE, UNRECOVERABLE, WRONG_MODEL)
from .receipts import Page, Receipts
from .rules import (Budget, Clearance, Deadline, Distinct, EmbeddedWith,
                    Marked, Restricted,
                    Rule,  # noqa: F401
                    Unrecoverable, quarantined, revoked)
from .spec import AdmissionSpec, why_refused

__all__ = [
    "Admission", "AdmissionSpec", "Page", "Receipts", "why_refused",
    "Deadline", "Marked", "Unrecoverable", "EmbeddedWith", "Clearance",
    "Restricted", "Budget", "Distinct", "revoked", "quarantined",
    "DEADLINE", "REVOKED", "UNREADABLE", "QUARANTINED", "WRONG_MODEL",
    "NOT_CLEARED", "OFF_SCOPE", "UNRECOVERABLE", "KEY_UNAVAILABLE", "REACHABLE",
    "REFUSED", "UNKNOWN", "LIFTED", "LIFT_BATCH", "OVER_BUDGET", "UNCOSTED",
    "REDUNDANT",
    "UNNAMED",
]
