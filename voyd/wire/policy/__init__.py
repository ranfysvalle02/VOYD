"""Every decision this boundary makes about a message. One import.

The question a reviewer actually has is *can this be bypassed?*, and the
honest answer is only as good as the number of places they have to look.
That argument used to be served by one 1,629-line file, which answers it
in principle and not in practice: nobody holds sixteen hundred lines in
their head, and "it is all in one file" stops being a property a reader
can use somewhere around four hundred.

So the count that matters is kept at one and moved up a level. Everything
below is a decision about a message; nothing outside this package is.
`__all__` is the whole list, the modules are grouped by the *kind* of
decision, and a reviewer can check a category is complete instead of
trusting that a scroll was thorough.

    guarding    refuse a document -- `Guard` judging a batch on the way
                out, whatever produced it, plus the per-read state a
                cumulative rule needs and the two entry points a reply
                arrives at
    verbs       rewrite a command -- a `delete` becoming the revocation
                it should have been, in both of its wire spellings
    reads       what a read may see -- the refusal pushed into a query,
                and the projections that would leave no verdict to take
    refusals    refuse a command outright -- the verbs no rewrite is
                narrow enough to cover, and the error a client raises
    handshake   the two rewrites that are about the connection itself
    erasure     the three that open a connection of their own, and the
                two orderings that make them safe

Two properties hold across all of it, and both are asserted by
`tests/test_every_decision_the_boundary_makes.py` rather than promised
here: every name below is reachable from `voyd.wire.policy`, and
`proxy.py` names none of the verbs that are this package's to refuse. A
second copy of "should this be refused", living in the transport, is the
drift this layout exists to prevent -- and it would fail no other test in
the suite.

Nothing here owns a socket, and almost nothing here is async; the three
that are say so in `erasure`.
"""

from __future__ import annotations

from .erasure import cascade_first, cascade_first_for_one, erase_first
from .guarding import SUPPLIABLE_CLAIMS, Budgets, Guard, enforce
from .guarding import _wants_a_caller as _wants_a_caller
from .guarding import guard_for, judge, unsuppliable_claims
from .handshake import TOPOLOGY_FIELDS, rewrite_topology, strip_compression
from .reads import (DERIVED_COMMANDS, FOREIGN_STAGES, LEADING_STAGES,
                    PRESERVING_STAGES, blinded_find, blinds_a_subject,
                    deciding_fields, expressible_clauses, pins_the_tenant,
                    projection_blinds, reducing_stage, rewrite_derived_read)
from .reads import _was_reduced as _was_reduced
from .refusals import (EXFILTRATING_STAGES, UNREWRITABLE,
                       client_vector_on_server_index, refuse_client_vector,
                       refuse_unrewritable, seal_refusal, writes_elsewhere)
from .verbs import (delete_reply, derive_on_insert,
                    revoke_instead_of_delete,
                    revoke_instead_of_find_and_delete)

__all__ = [
    # ---- refuse a document ----
    "Guard", "Budgets", "enforce", "judge", "guard_for",
    "unsuppliable_claims", "SUPPLIABLE_CLAIMS",

    # ---- rewrite a command ----
    "revoke_instead_of_delete", "revoke_instead_of_find_and_delete",
    "derive_on_insert", "delete_reply",

    # ---- what a read may see ----
    "rewrite_derived_read", "expressible_clauses", "pins_the_tenant",
    "deciding_fields", "projection_blinds", "blinds_a_subject",
    "blinded_find", "reducing_stage", "DERIVED_COMMANDS",
    "PRESERVING_STAGES", "LEADING_STAGES", "FOREIGN_STAGES",

    # ---- refuse a command outright ----
    "refuse_unrewritable", "refuse_client_vector", "seal_refusal",
    "writes_elsewhere", "client_vector_on_server_index", "UNREWRITABLE",
    "EXFILTRATING_STAGES",

    # ---- the connection itself ----
    "rewrite_topology", "strip_compression", "TOPOLOGY_FIELDS",

    # ---- the three that open a connection of their own ----
    "erase_first", "cascade_first", "cascade_first_for_one",
]

# The whole of what the transport reaches past `__all__` for, so "what
# does `proxy.py` know about this package that a policy file does not?"
# is answerable from this file rather than by grepping it. Private
# because a policy file has no use for them, re-exported because
# something outside this package does -- and the list is exactly that
# long, which a test holds it to. Everything else private here is used
# by its own siblings and stays where it is defined.
_INTERNAL = ("_wants_a_caller", "_was_reduced")
