"""VOYD: a retrieval read path that refuses what it has forgotten.

Ranking is not permission. A vector index ranks by relevance and is never
asked the other question -- may this fact reach a prompt? -- so a retrieval
answers with a confident score and no idea whether the hit was allowed to be
there: an expired row the sweeper has not reached, a fact somebody revoked, a
vector from a model that was swapped.

VOYD answers that question at the one place every read passes through on the
way out.

**In your process**, a handle with no unfiltered read on it::

    from voyd import Engine

    engine = Engine(client, db)
    await engine.connect()
    docs = engine.model("notes").forgettable()
    await engine.ensure(search_wait_s=0)

    await docs.find({})                       # cannot return a forgotten fact
    await docs.including_refused().find({})   # break-glass: gated, and counted
    await docs.revoke({"_id": x}, reason="credential leaked")

**Or on the wire**, where it binds the connection instead of the import::

    python tools/voyd_wire.py --listen 27099 --target localhost:27017 \\
        --guard notes

Same check, no code. Any driver in any language pointed at that port cannot
read a forgotten fact, because the boundary is not something a caller can
forget to use -- there is nothing to reach past. The proxy holds no database
connection of its own: ``reachable()`` is pure, which is what makes it
movable at all.

The pieces, and everything else is mechanics:

**Deadline** -- one ``expire_at``, inherited by every row in the scope and
collected by one TTL index. Enforced in the *read path* as well as by the
reaper: MongoDB's TTL monitor runs about once a minute (measured: 60.0s), so
an expired document lives on disk for a window afterwards, and serving it
during that window is the whole bug class. See ``examples/forget.py``.

**Refusal** -- not a convention each call site remembers, because a rule you
have to remember to apply is not enforced. ``revoke()`` makes a fact
unreachable on the next read while its row is still on disk: deletion is a
storage event, refusal is a retrieval guarantee, and only the second can be
immediate. Not every refusal is an erasure, and the difference is declared on
the reason rather than decided by the verb -- one word, ``reversible``, says
whether ``lift()`` works and whether imposing it schedules the reaper. See
``examples/refuse.py`` and ``examples/hold.py``.

**A rule is a protocol, not a list.** ``reason`` + ``refuses(doc)`` +
``clause()``, and a stranger's rule is a first-class one. That is what makes
the set-relative reasons possible -- a token budget, a de-duplicator, a
provenance quota -- which refuse a document because of the *other* documents
on the page, and which no index filter and no policy engine can express. See
``examples/rosetta.py`` and ``examples/portfolio.py``.

**Refusal travels.** ``derive()`` records what a document was made out of, so
revoking a source reaches the summary, the answer and the embedding built on
it -- and ``find({"lineage": id})`` answers the question from the other end.
See ``examples/lineage.py``.

**And it is provable.** Every revocation is a link in an append-only hash
chain, ``as_of(t)`` replays the scope as it stood, and ``receipt_for(page)``
hashes what reached a prompt. What lies outside this process is enumerated
rather than claimed: see ``engine.perimeter``. Refusal binds a read path and a
restored snapshot does not run it, which is what ``engine.keyring`` is for --
a key per scope, destroyed on the same deadline, so every copy becomes
unreadable at once. See ``examples/shred.py``.

Every claim above is asserted by the test suite against a real MongoDB --
no mock tier, on purpose, because these properties are only true if the
*queries* are right.
"""

from __future__ import annotations

from .engine import Engine, PermanentFailure

__version__ = "0.1.0"

__all__ = ["Engine", "PermanentFailure", "__version__"]
