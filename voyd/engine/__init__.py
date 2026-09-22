"""The parts a boundary is assembled from.

    AdmissionSpec   where a collection keeps the facts that make a document
                    forgettable -- the deadline, the mark, the tenant, the
                    rules. A declaration, compared by value.
    Admission       the verdict. ``reachable(docs)`` is pure: no database,
                    no connection, no I/O. That is the property that lets
                    the same check run inside a wire proxy and hold for a
                    driver in any language.
    Keyring         a key per scope, so an erasure request is a key
                    deletion rather than a search-and-replace across every
                    copy of a document.
    SearchEngine    index lifecycle. ``ensure_indexes`` is what
                    ``voyd-wire --ensure`` calls; provisioning is an
                    operator step, not an application one.
    Expiry          the TTL index behind a ``deadline()``.
    detect          what this deployment can actually do, asked rather
                    than assumed.

Nothing here is application-facing. What an application gets is a
``voydfile.py`` and a connection string; see ``voyd/__init__.py``.

This package is deliberately free of application vocabulary. It knows about
collections, fields and filters, never about namespaces or voids.
"""

from __future__ import annotations

from .authority import AuthorityRequired, Anyone, Grants, NotAuthorised
from .capabilities import detect
from .errors import (
    BlastRadius,
    CallerRequired,
    ContextIncomplete,
    DerivationBroken,
    FilterInvalid,
    Irreversible,
    ScopeError,
    ScopeInvalid,
    ScopeRequired,
    UnboundedForgetting,
    UnknownReason,
)
from .expiry import Expiry, ExpirySpec
from .admission import (DEADLINE, KEY_UNAVAILABLE, LIFTED, NOT_CLEARED,
                        OFF_SCOPE, UNNAMED,
                        OVER_BUDGET, QUARANTINED, REDUNDANT,
                        REACHABLE, REFUSED, REVOKED, UNCOSTED, UNKNOWN,
                        UNREADABLE, UNRECOVERABLE, WRONG_MODEL,
                        Budget, Clearance, Deadline, Distinct,
                        EmbeddedWith, Page,
                         Restricted,
                         Admission, AdmissionSpec, Marked, Unrecoverable,
                         quarantined, revoked, why_refused)
from .custody import Aws, Azure, Ephemeral, Gcp, Kmip, LocalFile
from .keyring import Keyring, KeyringSpec, Queryable, Sealed
from .search import SearchEngine, SearchSpec
from .time import UTC, aware, deadline, live, living, now
from .trait import Trait

# What this package promises, grouped by what a reader is trying to do.
#
# It is a promise rather than an inventory, and the difference is the point:
# a name here has to keep working, so putting one here is a decision and
# not a consequence of having written a class. Everything else in this
# package is still importable from the module that owns it -- the
# extension-point vocabulary lives in ``.authority`` and ``.trait``,
# internals in ``.capabilities``, ``.search`` and ``.jobs`` -- and is
# reachable without being guaranteed.
#
# ``tests/test_the_codebase_tells_the_truth_about_itself.py`` pins this
# list, so
# growing it is a line in a diff somebody has to justify rather than a
# thing that happens.
__all__ = [
    # ---- the clock it pins ----
    "now", "deadline", "live", "living", "aware", "UTC",

    # ---- declaring a collection ----
    "Admission", "AdmissionSpec", "Page", "why_refused",
    "SearchSpec", "ExpirySpec",

    # ---- what `--ensure` and `--verify` provision with ----
    "SearchEngine", "Expiry", "detect", "Trait",

    # ---- reasons a fact may not reach a prompt: the rules you construct ----
    "Deadline", "Marked", "revoked", "quarantined",
    "Clearance", "Restricted", "EmbeddedWith", "Unrecoverable", "Budget",
    "Distinct",
    # ---- and the reasons you read back out of receipts() ----
    "DEADLINE", "REVOKED", "UNREADABLE", "QUARANTINED", "WRONG_MODEL",
    "NOT_CLEARED", "OFF_SCOPE", "UNRECOVERABLE", "KEY_UNAVAILABLE", "LIFTED",
    "REACHABLE", "REFUSED", "UNKNOWN", "OVER_BUDGET", "UNCOSTED", "UNNAMED",
    "REDUNDANT",

    # ---- proof ----
    # ---- what was said because of a fact ----
    # ---- encryption, and who holds the key that wraps the keys ----
    "Keyring", "KeyringSpec", "Sealed", "Queryable",
    "Ephemeral", "LocalFile", "Aws", "Azure", "Gcp", "Kmip",

    # ---- who may do this ----
    "Grants", "Anyone",

    # ---- who else holds a copy ----
    # ---- what you catch ----
    "ScopeError", "ScopeRequired", "ScopeInvalid", "FilterInvalid",
    "CallerRequired", "Irreversible", "UnknownReason", "BlastRadius",
    "ContextIncomplete",
    "UnboundedForgetting", "DerivationBroken", "NotAuthorised", "AuthorityRequired",
]
