"""An agent is a caller, not a thing we are.

VOYD does not run agents -- that market has AgentCore, Vertex and Claude
managed agents in it. It is where agent output *lands*. So the agent shows up
here as an ordinary client of two primitives, and if the AI framing needed new
machinery to be true it would be marketing:

    memory  = scoped hybrid search + a deadline   (recall that forgets)
    tools   = the job queue's retry policy        (LLM APIs fail like this)
"""

from __future__ import annotations

import asyncio
import random
from datetime import datetime, timedelta, timezone

import pytest

from voyd.engine import JobQueue, MemorySpec, PermanentFailure

DIMS = 8


def vec(seed: int) -> list[float]:
    random.seed(seed)
    return [random.random() for _ in range(DIMS)]


def utc(**kw) -> datetime:
    return datetime.now(timezone.utc) - timedelta(**kw)


@pytest.fixture
async def agent(core):
    """The memory trait as a caller uses it: scoped recall that refuses.

    Built on ``core`` -- a bare Engine on a vanilla client -- so the view
    is proven against the caller an agent actually is, not the HTTP service's
    pre-configured store."""
    e, db = core
    mem = e.memory(MemorySpec(collection="memories", dimensions=DIMS,
                              default_ttl=timedelta(hours=1)))
    await e.ensure(search_wait_s=60)
    yield e, mem, db


async def recall_when_indexed(mem, scope, vector, *, expect=1, timeout=25.0, **kw):
    deadline = asyncio.get_running_loop().time() + timeout
    hits: list = []
    while asyncio.get_running_loop().time() < deadline:
        hits = await mem.recall(scope, vector, **kw)
        if len(hits) >= expect:
            return hits
        await asyncio.sleep(0.5)
    return hits


# ---- memory that forgets ------------------------------------------------

async def test_memory_is_recalled_by_meaning_and_by_exact_token(agent):
    """The RAG-quality argument, at agent scale. Identifiers are most of what an
    agent needs to recall -- error codes, config keys, function names -- and
    they are exactly what embeddings are worst at."""
    e, mem, _ = agent
    await mem.remember("agent-1", "the deploy failed with error E_QUOTA_429",
                       vec(2), kind="observation")
    await mem.remember("agent-1", "user prefers concise answers", vec(1),
                       kind="preference")

    # Query vector points at the *preference*, so only the lexical half can
    # surface the error code.
    hits = await recall_when_indexed(mem, "agent-1", vec(1),
                                     text="E_QUOTA_429", expect=1)
    assert hits, "nothing recalled"
    assert "E_QUOTA_429" in hits[0]["text"], [h["text"] for h in hits]


async def test_memory_is_scoped_so_agents_cannot_read_each_other(agent):
    """Cross-scope recall is not a ranking bug, it is a data leak that arrives
    as an LLM answer -- the retrieval-layer version of a tenancy breach."""
    e, mem, _ = agent
    await mem.remember("agent-1", "the API key is in vault/prod", vec(3))
    await recall_when_indexed(mem, "agent-1", vec(3))

    leaked = await mem.recall("agent-2", vec(3))
    assert leaked == [], "another agent's memory reached the context window"


async def test_an_expired_memory_never_reaches_a_context_window(agent):
    """TTL alone is not enough. MongoDB's TTL monitor runs about once a minute,
    so an expired document stays readable for a window -- which for a forgotten
    fact is exactly the wrong behaviour. So recall re-checks the deadline on
    every hit and drops it before returning."""
    e, mem, db = agent
    await mem.remember("agent-1", "stale: use the old endpoint", vec(4))
    await recall_when_indexed(mem, "agent-1", vec(4))

    # Backdate the deadline: still physically present, must not be recalled.
    await db.memories.update_one({"text": {"$regex": "^stale"}},
                                 {"$set": {"expire_at": utc(minutes=5)}})
    assert await db.memories.count_documents({}) == 1, "still stored"
    assert await mem.recall("agent-1", vec(4)) == [], "but must not be recalled"


async def test_recall_survives_a_naive_utc_client(agent):
    """Default PyMongo clients are not tz_aware. The web layer's store is.
    The engine is used without it, so a naive deadline must not
    crash recall and must not leak a forgotten fact into a prompt."""
    e, mem, db = agent
    await mem.remember("agent-1", "still good", vec(9))
    await recall_when_indexed(mem, "agent-1", vec(9))

    naive_future = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=1)
    naive_past = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=5)
    await db.memories.update_one({"text": "still good"},
                                 {"$set": {"expire_at": naive_future}})
    assert await mem.recall("agent-1", vec(9)), "fresh naive deadline must recall"

    await db.memories.update_one({"text": "still good"},
                                 {"$set": {"expire_at": naive_past}})
    assert await mem.recall("agent-1", vec(9)) == [], "expired naive must not"


async def test_pinning_is_the_absence_of_a_deadline(agent):
    """Permanent and ephemeral memories share one collection, because a null
    deadline already means 'keep forever'. No second storage path."""
    e, mem, _ = agent
    ephemeral = await mem.remember("agent-1", "scratch note", vec(5))
    pinned = await mem.remember("agent-1", "the user's name is Dana", vec(6),
                                pinned=True)

    assert ephemeral["expire_at"] is not None
    assert pinned["expire_at"] is None

    await mem.pin(ephemeral["_id"])
    await mem.extend(pinned["_id"], timedelta(minutes=5))


async def test_forget_is_a_first_class_operation(agent):
    """'This session is over' and 'the user asked to be forgotten' are the same
    call, and neither should wait on a TTL sweep."""
    e, mem, db = agent
    await mem.remember("session-x", "a", vec(7))
    await mem.remember("session-x", "b", vec(8), kind="preference")
    await mem.remember("session-y", "c", vec(7))

    assert await mem.forget("session-x", kind="preference") == 1
    assert await mem.forget("session-x") == 1
    assert await db.memories.count_documents({}) == 1, "other session untouched"


async def test_memory_declares_no_embedding_provider(agent):
    """The anti-handcuff test. Vectors are arguments, so the application owns
    the model, the cost and the re-embedding policy."""
    e, mem, _ = agent
    import inspect

    src = inspect.getsource(type(mem))
    for vendor in ("openai", "voyage", "cohere", "sentence_transformers"):
        assert vendor not in src.lower(), f"memory should not know about {vendor}"
    assert "vector" in inspect.signature(mem.remember).parameters


# ---- tool calls fail the way the job queue expects ---------------------

async def test_tool_calls_use_the_same_retry_taxonomy_as_embeddings(agent):
    """An LLM or tool API fails in exactly two ways, and conflating them is the
    bug this engine already paid for: a rate limit is the *world* being broken
    and must be retried; a malformed argument is the *call* being broken and
    must not be."""
    e, _, db = agent
    await db.tool_calls.insert_many([
        {"state": False, "tool": "search", "args": {"q": "ok"}},
        {"state": False, "tool": "search", "args": None},
    ])
    q = JobQueue(db=db, collection="tool_calls", when={"state": False},
                 status_field="state", attempts_field="tries", max_attempts=3)

    transient = await q.claim()
    assert await q.fail(transient, RuntimeError("429 rate limited")) is False
    requeued = await q.claim()
    assert requeued["tries"] == 1, "retried, counted"

    await q.complete(requeued, {"result": "ok"})

    bad = await q.claim()
    assert await q.fail(bad, PermanentFailure("args must be an object")) is True
    assert await q.claim() is None, "a malformed call is not retried"



async def test_a_memory_can_carry_the_callers_own_fields(core):
    """``meta`` is the escape hatch that keeps this from being a cage.

    Untested it read as a parameter nobody wanted; it is the difference
    between a trait and a trait that decides your schema.
    """
    engine, db = core
    mem = engine.model("memories", tenant="session").memory(dimensions=8)
    await engine.ensure(search_wait_s=0)

    await mem.remember("s1", "the fault code is P0301", [0.1] * 8,
                       meta={"source": "ticket-7781", "confidence": 0.9})

    row = await db.memories.find_one({"session": "s1"})
    assert row["source"] == "ticket-7781"
    assert row["confidence"] == 0.9
