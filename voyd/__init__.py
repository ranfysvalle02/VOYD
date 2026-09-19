"""VOYD: a retrieval scope that expires, and refuses what it has forgotten.

Every database can delete. None of them can refuse. Deletion is a storage
event and it is eventually consistent, so between deleting a document and it
being gone, a vector index keeps returning it. A **void** is a scope that
closes both halves: open it with a deadline, put documents in, query them, and
stop thinking about it.

The deadline is trustworthy because one thing owns it. Split across Postgres
for metadata, Pinecone for vectors, S3 for blobs and a cron for cleanup, and
you have four clocks and four ways to drift -- the vector outliving the
document is the bug class, and nothing is ever wrong enough to page you. Here
it is one ``expire_at``, inherited by every row in the scope, collected by one
TTL index. There is no fourth clock and no second store: the text is a field on
the document, so a collected row leaves nothing behind to reclaim.

Four primitives, and everything else is mechanics:

**Scope** -- a namespace selected by the HTTP Host header. Every query is
filtered by
it, and the filter is pushed into the search index rather than remembered by a
caller, because a leak here is a breach that arrives as an answer.

**Deadline** -- one ``expire_at``, inherited by every row in the scope and
collected by one TTL index. Enforced in the *read path* as well as by the
reaper: MongoDB's TTL monitor runs about once a minute (measured: 60.0s), so
an expired document lives on disk for a window afterwards, and serving it
during that window is the whole bug class. See ``examples/forget.py``, which
watches it happen.

**Refusal** -- the read-path half of that deadline is not a convention each
call site remembers, because a rule you have to remember to apply is not
enforced. ``engine.model(...).forgettable()`` returns a handle with no
unfiltered read on it: expired, revoked and unreadable facts are refused on
the way out, and seeing everything requires saying ``including_refused()``
where a reviewer can grep for it. ``revoke()`` makes a fact unreachable on the
next read while its row is still on disk -- deletion is a storage event,
refusal is a retrieval guarantee, and only the second one can be immediate.
See ``examples/refuse.py``.

Not every refusal is an erasure, and the difference is declared on the reason
rather than decided by the verb. ``revoked()`` is an instruction about the
world and cannot be taken back; ``quarantined()`` is a hypothesis, so
``quarantine()`` holds a document without giving its row a deadline -- the row
is the evidence -- and ``release()`` lifts it. One word on the rule,
``reversible``, decides whether ``lift()`` works, whether imposing it schedules
the reaper, and what the chain records on the way back out. See
``examples/hold.py``.

**Guard** -- an access policy on the *scope*: a passcode, enforced on the
read path. ``Guard`` asks whether this caller may read the
scope and ``Admission`` asks whether this document may reach a prompt; the
pair of them is a third question, and ``for_caller(claims)`` is where it is
answered -- a ``Clearance`` rule compares what a document is classified
against what its reader is cleared for, per hit. There is one door: gating
queries and leaving another way in would make search the way around the lock.

Refusal answers *may this reach a prompt*, which is not the same question as
*and your backups?* -- refusal binds this application's read path, and a
restored snapshot does not run it. ``engine.keyring`` closes that: a key per
scope, ciphertext at rest, and the scope's deadline destroying the key, so
every copy becomes unreadable at once. The key vault is a collection, so the
key expires by the same TTL index the documents do. Neither mechanism is
sufficient alone -- the key cache is a window refusal has already closed, and
refusal is local in a way the missing key is not. See ``examples/shred.py``,
which measures both.

Refusal is also **provable**. Every revocation is a link in an append-only
hash chain, so "this fact stopped being reachable at 14:02" is a claim
somebody can check rather than one they have to take -- and the receipt handed
back is the half that holds against whoever owns the database. See
``engine.ledger`` and ``GET /v1/voids/{token}/proof``.

    from datetime import timedelta
    from voyd import Engine

    engine = Engine(client, db)
    await engine.connect()
    mem = engine.model("memories", tenant="session").memory(
        default_ttl=timedelta(hours=1))
    await engine.ensure()

    await mem.remember(session, "prefers concise answers", vec)
    hits = await mem.recall(session, qvec, text="E_QUOTA_429")

``Engine`` is the core -- ``pip install voyd`` is Engine and a MongoDB driver,
and importing it does not load FastAPI or Voyage. ``Voyd`` is the HTTP
service built on it, and needs the ``app`` extra. :mod:`voyd.mcp` is the same
API as five agent tools, none of which is a delete -- ``forget`` changes
reachability and hands the agent no cleanup obligation, which is why it costs
nothing to offer.

``voyd verify`` is the falsifier: it attacks these guarantees on a live
deployment and exits non-zero if any read path answers with something it
should have refused.
"""

from __future__ import annotations

from importlib import import_module

from .engine import Engine, PermanentFailure

__version__ = "0.1.0"

# Everything above Engine is an optional extra, imported on first attribute
# access so that `from voyd import Engine` never pulls in FastAPI.
_LAZY_EXPORTS = {
    "Voyd": (".app", "Voyd"),
    "Guard": (".guards", "Guard"),
    "Intelligence": (".intelligence", "Intelligence"),
    "Store": (".store", "Store"),
}


def __getattr__(name: str):
    spec = _LAZY_EXPORTS.get(name)
    if spec is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(spec[0], __name__), spec[1])
    globals()[name] = value
    return value


def __dir__():
    return sorted({*globals(), *_LAZY_EXPORTS, "__all__", "__version__"})


__all__ = [
    "Engine", "PermanentFailure",
    "Voyd", "Store", "Intelligence", "Guard",
    "__version__",
]
