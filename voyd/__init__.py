"""VOYD: a retrieval read path that refuses what it has forgotten.

Ranking is not permission. A vector index ranks by relevance and is never
asked the other question -- may this fact reach a prompt? -- so a retrieval
answers with a confident score and no idea whether the hit was allowed to be
there: an expired row the sweeper has not reached, a fact somebody revoked, a
vector from a model that was swapped.

VOYD answers that question at the one place every read passes through on the
way out.

**There is one way to use it, and it is not an import.** VOYD is a proxy.
Declare the rules once, in a file that is not your application::

    # voydfile.py
    from voyd import guard, deadline, revocable, tenant

    @guard("notes")
    class Notes:
        expire_at = deadline()
        forgotten = revocable()
        tenant_id = tenant()

    # then: voyd-wire --config voydfile.py --target localhost:27017

No code. Any driver in any language pointed at that port cannot read a
forgotten fact, because the boundary is not something a caller can forget
to use -- there is nothing to reach past.

What this package exports is the vocabulary above -- ``guard``,
``deadline``, ``revocable`` and the rest -- because the proxy loads your
policy file, and the parts ``--ensure`` and ``--verify`` provision with.
There is nothing here for an application to import and no handle for it to
hold: a boundary you can forget to route a read through is not one.

The check itself is pure -- no database, no connection, no I/O -- which is
what lets it run inside a proxy at all. The proxy opens a connection of
its own only when a policy asks for one: ``lineage_field``, because making
a refusal reach what was derived from a fact is a write the caller did not
issue, and ``@stage``/``@operator``, whose native follow-on steps run on
temporary collections the caller is never allowed to address.

The pieces, and everything else is mechanics:

**Deadline** -- one ``expire_at``, inherited by every row in the scope and
collected by one TTL index. Enforced in the *read path* as well as by the
reaper: MongoDB's TTL monitor runs about once a minute (measured: 60.0s), so
an expired document lives on disk for a window afterwards, and serving it
during that window is the whole bug class.

**Refusal** -- not a convention each call site remembers, because a rule you
have to remember to apply is not enforced. ``revoke()`` makes a fact
unreachable on the next read while its row is still on disk: deletion is a
storage event, refusal is a retrieval guarantee, and only the second can be
immediate. Not every refusal is an erasure, and the difference is declared on
the reason rather than decided by the verb -- one word, ``reversible``, says
whether ``lift()`` works and whether imposing it schedules the reaper. See
``examples/refuse.py``.

**A rule is a protocol, not a list.** ``reason`` + ``refuses(doc)`` +
``clause()``, and a stranger's rule is a first-class one. That is what makes
the set-relative reasons possible -- a de-duplicator, a provenance quota
-- which refuse a document because of the *other* documents
on the page, and which no index filter and no policy engine can express. See
``examples/rosetta.py`` and ``examples/portfolio.py``.

**Refusal travels.** A collection declaring ``lineage_field`` records what
each document was made out of, so revoking a source reaches the summary, the
answer and the embedding built on it -- children marked first, then the
source, because a crash the other way round leaves a summary of an erased
fact still answering prompts. The boundary closes a document's ancestry
transitively when it is written, which is what makes the cascade one query
at any depth, and refuses an insert that claims a parent it may not reach.
``find({"lineage": id})`` answers the question from the other end.

**And refusal is not the whole answer, which is said here rather than
discovered later.** Refusal binds a read path, and a restored snapshot does
not run it. That is what ``sealed()`` and ``--key-vault`` are for -- a key
per scope, so destroying it makes every copy unreadable at once, and the
boundary revokes the documents *first* so the key cache is not a second
window. See ``examples/shred.py``.

Every claim above is asserted by the test suite against a real MongoDB --
no mock tier, on purpose, because these properties are only true if the
*queries* are right.
"""

from __future__ import annotations

from .declare import (auto_embed, clearance, deadline, distinct,
                      embedded_with, guard, holdable, issuer, mask,
                      restricted_to,
                      operator, recipe, rerank, revocable, sanitized,
                      sealed, stage, subjects, tenant, transform)

__version__ = "0.4.0"

__all__ = [
    # The declarative policy surface -- everything `voydfile.py` needs.
    "guard", "deadline", "revocable", "holdable", "tenant",
    "restricted_to", "clearance", "embedded_with", "distinct",
    "sealed", "auto_embed", "subjects", "sanitized", "mask",
    # Page-shaping, which is not a rule and is exported beside them
    # anyway: it is declared in the same file, and a vocabulary split
    # across two imports is a vocabulary people get wrong.
    "transform", "rerank",
    # Pipeline vocabulary mongod does not have, run by the boundary on
    # admitted documents only. Not rules either. See `policy/stages.py`.
    "stage", "operator",
    # A named, governed pipeline a client calls by name. Not a rule: its
    # expansion meets the rules like any pipeline. See `policy/recipes.py`.
    "recipe",
    # Whose delegated tokens the boundary believes. Not a rule: it says
    # who a read may be judged as. See `voyd/engine/delegation.py`.
    "issuer",
    "__version__",
]
