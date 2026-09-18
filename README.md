# VOYD

**Every database can delete. None of them can refuse.**

Deletion is a storage event, and storage events are eventually consistent. A
TTL monitor sweeps about once a minute (measured here: 60.0s). An S3 lifecycle
rule runs about once a day. A cleanup cron runs whenever it last worked. So
between the moment you delete something and the moment it is gone, your vector
index keeps returning it — as a normal, well-scored result, with nothing
logged and nothing to page on.

Retrieval does not need a faster sweeper. It needs a different guarantee:

> **this fact may not reach a prompt** — answered on every read, immediately,
> whatever the sweeper is doing.

That is *refusal*, and nobody ships it. VOYD is that guarantee, made
structural:

```python
docs = engine.model("notes").forgettable()

await docs.find({})                        # cannot return a forgotten fact
await docs.including_forgotten().find({})  # the unsafe thing, named out loud

await docs.revoke({"_id": x}, reason="credential leaked")
# unreachable on the next read. The row is still on disk. That is the proof.
```

There is no unfiltered `find` on that handle, so refusal does not depend on
the next author remembering it. And because one document owns the deadline —
one `expire_at`, inherited by every row in the scope, collected by one TTL
index — there is no second system holding a stale copy of it. Those are the
two halves: [one owner](#why-the-deadline-is-trustworthy) so nothing drifts,
[refusal](#deletion-is-a-storage-event-forgetting-is-a-retrieval-guarantee) so
the gap before deletion is not a window in which anything is served.

A **void** is a retrieval scope built on both: it expires, and it refuses.
`pip install voyd` is the library; the service on top is five HTTP calls.

## See it forget

```bash
docker compose up -d
uv run python examples/forget.py     # ~10 seconds, no API key, no vendor
```

```
  t+  0.0s  remembered 2: one expiring in 8s, one pinned
  t+  1.0s  recall -> ['the fault code is P0301', "the user's name is Dana"]
  t+  1.0s  on disk: 2 rows, 2 vectors

  t+  8.1s  DEADLINE PASSED
  t+  8.1s  recall -> ["the user's name is Dana"]   <- expired memory is already unreachable
  t+  8.1s  on disk: 2 rows                     <- but the row is still here
  t+  8.1s        retrieval enforces the deadline; it does not wait for the janitor.

  t+  9.3s  reaper ran: 1 row, 1 vector
  t+  9.3s  recall -> ["the user's name is Dana"]   <- pinned memory untouched

  delete calls issued by this program: 0
```

Read `t+8.1s` again, because it is the part nobody else does. The row is
**still on disk** and already unreachable: recall refuses it on the way out,
so the minute-long window above is not a window in which anything is served.
The reaper is the second line, not the only one.

Then `t+9.3s`: the row and its embedding leave together, because they were never
two things. The pinned memory beside it is untouched — the deadline is per
document, not a collection-wide wipe.

## Five calls

```bash
# open a scope that lives for an hour
curl -X POST http://acme.voyd.com/v1/voids \
  -H "Authorization: Bearer $VOYD_KEY" \
  -d '{"ttl_seconds": 3600}'
# -> {"token": "k6kC2pJz", "expires": "2026-09-18T15:02:11+00:00"}

# text straight in -- the only way in, and the only one worth having
curl -X POST http://acme.voyd.com/v1/voids/k6kC2pJz/documents \
  -H "Authorization: Bearer $VOYD_KEY" \
  -d '{"documents": [{"text": "fault code P0301 on cylinder 1", "name": "scan.md"}]}'

# query inside the boundary, and only the boundary
curl -X POST http://acme.voyd.com/v1/voids/k6kC2pJz/search \
  -H "Authorization: Bearer $VOYD_KEY" \
  -d '{"query": "misfire"}'

# what is in it, and how much of it is searchable yet
curl http://acme.voyd.com/v1/voids/k6kC2pJz \
  -H "Authorization: Bearer $VOYD_KEY"
# -> "index": { "total": 1, "indexed": 0, "pending": 1, "failed": 0 }

# forget something now -- the fifth call, and it deletes nothing
curl -X POST http://acme.voyd.com/v1/voids/k6kC2pJz/forget \
  -H "Authorization: Bearer $VOYD_KEY" \
  -d '{"reason": "user retracted it"}'
# -> {"forgotten": 1, "unreachable_since": "...", "note": "the rows are
#     still on disk and are erased by the scope's deadline, not by this call"}
```

Embedding is asynchronous, so `GET /v1/voids/{token}` is not an afterthought:
"added" and "searchable" are different facts, and an index that is still
building must never be mistaken for an empty scope.

An hour later the documents and their embeddings are gone together, because
they were always one row. You did not schedule that. There is no delete call
in the happy path — and `forget` is not one either: it moves a deadline into
the past so the same TTL index does the same work sooner.

## Why the deadline is trustworthy

Anyone can expire *something*. The hard part is expiring **all of it**, and
that is an architecture problem, not a feature:

| | Owns the expiry | Granularity |
|---|---|---|
| Postgres row | your code | whenever the cron runs |
| Pinecone namespace | **nothing** | never |
| S3 object | a lifecycle rule | ~a day, per prefix |
| the cleanup cron | whoever wrote it | whenever it last worked |

Four owners, four clocks, four ways to drift — and the drift *is* the bug. The
vector outlives the document. The bytes outlive the row. The lifecycle rule was
never applied to the new prefix. Now a deleted document is still answering
queries, and nothing anywhere is wrong enough to page you.

VOYD is one document with one `expire_at`, inherited by every row in the
scope, collected by one TTL index. One thing owns the deadline, so there is
nothing to drift — and the bottom row of that table does not exist here at
all, because the text is a field on the document rather than an object in a
bucket. There is no second store to keep in step, which is a stronger answer
than keeping it in step well.

That fixes *who* owns the deadline. It does not fix *when* it takes effect,
because deletion is eventually consistent no matter who owns it — which is the
next section.

That is the entire argument, and it is why this is MongoDB and not a wrapper
over four services.

It is also the one claim here that is an *architecture* opinion, so it does not
get to stay prose. `drift/` stands the four owners up as four real services and
runs the scenario:

```bash
docker compose -f drift/docker-compose.drift.yml up -d --wait
uv run --extra drift python drift/exhibit.py
```

```
  4. So the cron runs. It deletes expired rows, which is exactly
     what it was written to do -- and all it was written to do.
    [ok  ] the cron deleted the expired row -- Postgres is now correct
    [ok  ] the document is gone from the system of record

  5. Now ask the retrieval system a question.
     -> returned 1 hit(s). Top hit:
        score   1.0000
        text    'the 2019 acquisition fell through because of the pension liability'
        pg_id   1 <- this row no longer exists
    [ok  ] THE DELETED DOCUMENT ANSWERED THE QUERY
    [ok  ] and S3 still serves the bytes -- the lifecycle rule cannot fire for ~a day
```

Every service gets its real mechanism — Postgres a cron `DELETE`, S3 a real
lifecycle rule (whose real granularity is `Days: 1`, against a 5-second
deadline), Qdrant its real delete API. Nothing is stubbed and nothing is
sabotaged; the exhibit's last step shows that one more delete call fixes it,
which is exactly the point — that call is application code, it is not
transactional with the first delete, and forgetting it produces an answer
rather than an error. Details in [`drift/README.md`](drift/README.md).

## Deletion is a storage event. Forgetting is a retrieval guarantee.

The headline again, with the mechanism this time:

| | what it is | when it takes effect |
|---|---|---|
| **delete** | a storage operation | eventually — a TTL sweep (measured: 60.0s), a lifecycle rule (~a day), a cron (when it last worked) |
| **refuse** | a retrieval guarantee | the next read |

So every system's honest answer to *"when was this forgotten?"* is *"whenever
the sweeper got to it"* — a timestamp nobody can defend to an auditor, and a
window nobody is watching.

VOYD had the right instinct in two places: `Memory.recall` and the void search
path both re-checked the deadline per hit. But that was a **convention** — one
line each call site had to remember — and this repository's own history records
what conventions are worth:

> `get_void`, `list_voids`, `get_document`, `list_documents`, `count_indexed`,
> `vector_search` — six read paths, every one of them going to MongoDB with a
> tenant filter and no deadline.

Those six are now the six that go through the handle, and the `_unexpired()`
helper they called by hand is deleted. A rule you have to remember to apply
is not enforced, it is suggested. `store/mongo.py` came out six lines
*shorter* for the change.

So refusal is structural. `Forgetting` is a read handle, and there is no
unfiltered `find` to reach for:

```python
docs = engine.model("notes").forgettable()

await docs.find({})                        # reachable only — no flag, no filter
await docs.including_forgotten().find({})  # deliberate, and greppable

await docs.revoke({"_id": x}, reason="credential leaked")
```

The failure mode is inverted. Before, you had to remember to be safe. Now you
have to *declare* that you want the unsafe thing.

### revoke(): forget it now, delete it whenever

```bash
uv run python examples/refuse.py     # ~5 seconds, no API key, no vendor
```

```
  Now somebody says: forget that first one. Right now.
    revoke() marked 1 fact(s) unreachable

    recall  -> ['the fault code is P0301']
    on disk -> 2 rows        <- the secret is STILL HERE
       and it is already unreachable. No sweeper ran. Nothing
       was deleted. The next read simply refused it.

  The same query, straight at the collection, for contrast --
  this is what every other system's read path looks like:
    find() -> ['the admin password is hunter2', 'the fault code is P0301']
       ^ the revoked fact, returned as a normal result.
```

That row is deliberately still on disk. It isn't a failure to clean up — it's
the proof. **Unreachable first, erased second**, because the reverse order is
the bug.

Four reasons a fact may not reach a prompt, one question, one place that
answers it: a **deadline** passed, it was **revoked**, its deadline is
**unreadable** (fails closed), or — the absence of all three — it is **pinned**.

Two enforcement points, always both: the rule is pushed into the query where
the query can express it, *and* re-checked per document on the way out. That
second one is the guarantee rather than an optimisation, because
`$vectorSearch` hits never went through a query — the deadline is deliberately
not in the vector index, for the reasons measured in `search.py`.

### What the receipts can and cannot tell you

```bash
curl -s localhost:8000/healthz | jq '.forgetting[0]'
# { "revoked_total": 3,          # exact: counted when it happened
#   "refused_at_boundary": 41,   # a LOWER BOUND, on purpose
#   "refused_by_reason": {"deadline": 39, "unreadable": 2} }
```

`refused_at_boundary` undercounts, and the field name says so. Most forgotten
facts never reach the handle — the same rule runs inside the query and MongoDB
drops them server-side. Counting those would mean issuing every read twice. It
is a signal, not a ledger: any `unreadable` at all means something is writing
deadlines it shouldn't.

## Three primitives

**Scope.** A namespace the Host header selects — `{slug}.voyd.com` — and a void
inside it. Every query is filtered by `voyd_id`, and the filter is pushed *into*
the search index, not applied afterwards in Python. Cross-scope recall is a data
breach that arrives as an answer.

**Deadline.** One `expire_at` on one document, inherited by every row in the
scope, collected by one TTL index, and enforced by a handle with no unfiltered
read on it. The substrate, not a feature — see above for both halves.

**Guard.** A passcode on the scope, enforced on the read path. There used to
be two doors — query and download — and gating one without the other would
have made search the way around the lock. There is one door now.

## For agents

Agent runtimes are the channel, not the competition. AgentCore, Vertex and
Claude managed agents all run agents and all hand the result back with nowhere
to put it. VOYD is the somewhere, reachable as four MCP tools:

```bash
VOYD_URL=http://acme.localhost:8000 VOYD_API_KEY=voyd_... \
  uv run --extra mcp python -m voyd.mcp
```

| Tool | Does |
|---|---|
| `open_scope(ttl_seconds)` | a vector index that expires |
| `add(documents)` | text straight in, up to 100 per call |
| `search(query)` | hybrid query inside the boundary |
| `describe()` | what is in it, and how much is queryable yet |
| `forget(doc_ids, reason)` | make facts unreachable now — and *not* a delete |

**There is deliberately no `delete` tool**, and `forget` is not one wearing a
different name. A delete tool hands the agent a cleanup obligation, and an
agent that has to remember to clean up is the failure this exists to remove.
`forget` hands it none: nothing is removed, nothing is scheduled, no
follow-up call exists. It changes reachability, and erasure stays on the
scope's deadline — which is why it costs nothing to offer.

CI asserts the property rather than the headcount: no tool may be named for
reclaiming anything, and `forget` must be present. The old gate froze the
surface at exactly four names, which made keeping the principle look like
breaking it.

Embedding is asynchronous, so `add` reports how much is indexed and `describe`
tells you when it has caught up. An index that is still building must never
look like an empty one.

## Quickstart

```bash
# Atlas Local: mongod + mongot. Vector search, $rankFusion, TTL.
# No Atlas account.
docker compose up -d
cp .env.example .env

uv sync --all-extras
uv run python -m voyd

# the first owner is open; after that minting one needs an existing key
curl -X POST localhost:8000/v1/owners -d '{"email": "you@example.com"}'
# -> {"api_key": "voyd_...", "note": "Store this key now; it will not be shown again."}

curl -X POST localhost:8000/v1/voyds -H "Authorization: Bearer $VOYD_KEY" \
  -d '{"slug": "acme", "name": "Acme"}'
```

There is no sign-in page, because there is nothing to sign in to: the
surfaces are the JSON API, the MCP tools, and `import voyd`. An API key is
the only credential. `*.localhost` resolves to `127.0.0.1` on macOS and most
Linux with no `/etc/hosts` edits; otherwise send `-H 'X-Voyd: acme'`.

Voyage is only needed to compute embeddings, and only until a deployment
can do it server-side — see `auto_embed`.

## Examples, in order

All but the last in this first table need only `docker compose up -d` — no API
key, no embedding vendor, no running server. The vectors in them are fake on
purpose: the point being demonstrated is the database, not the model.

| | |
|---|---|
| `examples/forget.py` | **Start here.** Ten seconds: a memory expires, becomes unreachable while its row is still on disk, then the reaper takes the row and its vector together. A pinned memory beside it is untouched. |
| `examples/refuse.py` | Forget a fact *now*, without deleting it — the operation no vector database has. The revoked row is still on disk at the end, which is the proof, not an oversight. |
| `examples/why_this_belongs_in_the_database.py` | The exhibit. Parks the TTL monitor, runs the query *as it was written before the deadline check existed* — an expired document comes back as a confident, scored, well-formed hit — then the same search refusing it. Self-checking. |
| `examples/worker.py` | A queue with no queue. The document *is* the job; `fail()` decides whether the failure was the world (retry) or the document (park). |
| `examples/agent.py` | Memory that forgets: hybrid recall + TTL, pinning as the absence of a deadline. What an agent backend actually needs. |
| `examples/scope.py` | The HTTP product end to end, through the same client the MCP server wraps. Needs a running server and an API key. |

Two more that need something extra, and say so:

| | |
|---|---|
| `drift/exhibit.py` | The four-owners argument, run against real Postgres + Qdrant + MinIO. Needs `drift/docker-compose.drift.yml` and the `drift` extra. |
| `bench/measure.py` | The numbers above: expiry lag, the cosine cliff, per-tier latency. Verifies which tier actually served each query before reporting it. |

Run them one at a time: `forget.py` and the exhibit both park
`ttlMonitorSleepSecs`, which is a server-global, and the test suite has a
reaper test that does the same.

## The engine

`import voyd` is `Engine` and a MongoDB driver — that is the whole install.
Everything else is an extra: `app`, `voyage`, `r2`, `mcp`. CI asserts that
importing `Engine` does not load FastAPI.

```python
from voyd import Engine, PermanentFailure

engine = Engine(client, db)
await engine.connect()

docs = engine.model("documents", tenant="voyd_id")
docs.searchable(text_paths=("name", "text"), filter_fields=("token",))
engine.model("voids").expiring()
embeds = engine.model("documents").queue(when={"indexed": False})
await engine.ensure()

job = await embeds.claim()
await embeds.fail(job, RuntimeError("429"))            # the world — retry
await embeds.fail(job, PermanentFailure("malformed"))  # the call — park
```

`engine.db` is still a PyMongo database. It picks no vendor: search takes a
vector, not an API key.

The clock is pinned on that handle. A default PyMongo client decodes BSON Date
naive; comparing it to UTC-aware `now()` raises, and an expired row skips the
filter. `Engine` binds `engine.db` with `tz_aware=True, tzinfo=UTC` without
mutating the caller's client.

Capability is probed, never URI-guessed. `"mongodb.net" in uri` called Atlas
Local "not Atlas", so `$vectorSearch` never ran locally, for months, silently.
`detect()` asks `$listSearchIndexes`. Every fallback is logged, counted, and on
`/healthz`:

```bash
curl -s localhost:8000/healthz | jq .search
# {
#   "tier": "hybrid",
#   "indexes_ready": true,
#   "degraded_searches": 0,
#   "scope_refused": 0,      # queries refused for having no tenant filter
#   "cosine_capped": 0,      # times the fallback hit its ceiling
#   "stale_indexes": []      # indexes no longer matching their declared spec
# }
```

Startup blocks until indexes are queryable, because a `$vectorSearch` against a
building index returns **zero rows instead of raising** — indistinguishable from
an empty scope.

Hybrid exists because `P0301` has no useful embedding. Semantic search is bad at
identifiers, and the things agents put in a scope are full of them. Fusion
happens in the database: one round trip, no hand-normalised scores.

Embedding has two owners, and which one is a deployment fact rather than a
code path. `SearchSpec.auto_embed="voyage-4"` asks mongot to produce the
vectors: the index holds text, the query is text, and nothing in this process
ever computes an embedding — so a client-side embedder cannot drift from the
index's model, because there is only one of them. A deployment that cannot
do it refuses at index creation and the engine falls back to a
client-supplied vector index, logged and reported as
`embedding_owner` on `/healthz`. Declaring it is therefore safe before
every deployment supports it.

**Verified against Atlas** (mongod 9.0.1, `voyage-4`): documents stored with
no vector field, text queries returning the right rows, the tenant boundary
intact on the autoEmbed index shape, and `forget` still refusing a document
whose vector this process never computed. **Not available on Atlas Local**,
which registers no models — see [`BUG.md`](BUG.md). The models the cluster
offered were `voyage-4`, `voyage-4-large`, `voyage-4-lite`, `voyage-code-4`
and `voyage-code-3`; the voyage-3 family is not among them.

| Tier | Requires | Used for |
|---|---|---|
| `hybrid` | MongoDB 8.1+ with Atlas Search | `$rankFusion` over both legs |
| `vector` | Atlas Search | `$vectorSearch` only |
| `cosine` | anything | exact in-process fallback, capped |

Deadlines are the one filter deliberately *not* pushed into the index. Both
legs can express it — `living()` works verbatim as a `$vectorSearch` filter,
and the lexical leg says the same thing with `range` + `equals: null` +
`mustNot: exists`, which belongs in `compound.filter` because in
`compound.must` it moves relevance scores. What rules the push out is that a
`vectorSearch` definition **cannot be updated in place**, so it would be a
drop-and-rebuild on every existing deployment — and a rebuilding index returns
zero rows rather than erroring. So the deadline is enforced on read: the layer
that cannot drift, and the only one that also works on the cosine fallback.
Measurements are in `voyd/engine/search.py`.

An index that already exists is not automatically the right index, either.
Change a spec and `ensure()` notices: a lexical definition is corrected in
place, a vector one can only be reported, loudly, and named in
`stale_indexes` above.

### Runbook: a drifted vector index

Detecting something you cannot fix is an alert with nowhere to go, so here is
the procedure. `stale_indexes: ["documents.voyd_vector_index"]` means queries
are running against a definition the application no longer declares.

**Do not drop it in place.** Dropping rebuilds, and a rebuilding vector index
returns *zero rows instead of raising* — the same property this codebase blocks
startup over. You would trade a stale index for a silently empty one.

Rename instead, and let the readiness gate do the work:

1. Declare a new index name on the spec, leaving the old one alone:
   `docs.searchable(..., vector_index="voyd_vector_index_v2")`.
2. Deploy. `ensure()` runs inside the app's lifespan **before** it serves a
   request, and blocks until the new index is queryable. A replica therefore
   never answers a query against a half-built index; old replicas keep serving
   the old index until they are replaced.
3. This only holds if your orchestrator's readiness probe is tied to startup
   completing. If it routes traffic to a process whose lifespan has not
   finished, you have a rebuilding-index window and step 2 buys you nothing.
   That dependency is the whole reason this is written down.
4. Once every replica reports the new name and `stale_indexes` is empty, drop
   the old index to stop paying mongot to maintain it:
   `await db.documents.drop_search_index("voyd_vector_index")`.

If you can take the downtime, dropping and rebuilding is simpler and fine —
just do it knowing that search answers "nothing found" rather than erroring
while it rebuilds.

## What MongoDB is doing

| Primitive | Replaces | Where |
|---|---|---|
| TTL indexes | a lifecycle rule + a cron reaper | `engine.expiry` |
| `$rankFusion` (8.1+) | a reranker + score glue | `engine.search` |
| `$vectorSearch` + `$search` | Pinecone + Elasticsearch | same index |
| `find_one_and_update` | Celery + Redis | `engine.jobs` |
| Search index filters | scope checks you remember to write | both `$rankFusion` legs |

No Redis. No Kafka. No Elasticsearch. No vector database. No object storage.
One connection string.

That last one used to be untrue. Documents could arrive as presigned uploads
to R2, which meant bytes to reclaim when a deadline passed, which meant a
change stream over deletes to reclaim them, which meant pre-images, resume
tokens, and a reactor that had to survive primary elections. All of it was
machinery for keeping a second store in step with the first. Text is a field
on the row now, so a deleted document leaves nothing behind and the TTL
reaper is the whole of garbage collection.

## Numbers

Three claims in this README used to have no figure attached. `bench/measure.py`
attaches them. Laptop, single-node Atlas Local, 1024 dimensions — relative
comparison and order of magnitude, not a capacity plan.

```bash
docker compose up -d --wait mongo
uv run python bench/measure.py
```

**How long does an expired document stay on disk?** This is the number the
read-path check exists for, so "about once a minute" is not good enough.
Inserting a row already past its deadline and waiting for the reaper:

```
n=20   min=9.4s   p50=60.0s   p99=60.2s   max=60.2s   mean=57.5s
```

Nineteen of the twenty sit at 60.0s, and that is the method, not the world:
each sample starts immediately after the previous sweep finished, so it waits
a full period. Only the first — landing at a random phase — shows 9.4s. So
this measures the **ceiling**, and pins it precisely: the sweep interval is
60.0s. A document expiring at a random moment waits uniformly somewhere in
[0, 60], averaging ~30s.

The ceiling is the number a security argument needs. **For up to a full
minute** after its deadline, an expired document is still on disk, and a
system that trusts only its TTL index will serve it. VOYD's read path closes
that window; the reaper is the second line, not the only one.

**Where is the cosine cliff?** `COSINE_CAP = 10_000` was asserted, not derived.
It is linear, as advertised, and now on the record:

| rows | hybrid p50 | vector p50 | cosine p50 |
|---|---|---|---|
| 100 | 2.1 ms | 1.5 ms | 6.4 ms |
| 1,000 | 1.7 ms | 1.2 ms | 66.5 ms |
| 5,000 | 5.0 ms | 2.3 ms | 346.4 ms |
| 10,000 | 3.9 ms | 2.8 ms | 699.5 ms |

The indexed tiers are flat in collection size; cosine is 108x its 100-row cost
by 10,000 rows. So the cap is a decision about a ceiling you can state: at
`COSINE_CAP` a degraded query costs about **0.7s p50**. That is survivable as a
fallback and indefensible as a steady state, which is why it is logged at ERROR
and counted on `/healthz` rather than quietly absorbed.

The benchmark verifies which tier actually served each query, via the
`degraded_searches` counter, and refuses to label a measurement `hybrid` if it
degraded. The first draft did not, and duly reported three identical numbers
for three tiers — an unready index returns rows rather than raising, which is
the same trap the engine blocks startup to avoid.

## Tests

```bash
docker compose up -d --wait mongo
uv run pytest
```

Pure logic (slugs, host, guards, rate limits, the MCP surface) needs no I/O. The
claims that are only true if the *queries* are right run against Atlas Local.
They skip, not fail, when MongoDB is unreachable. Point them elsewhere with
`VOYD_TEST_MONGO_URI`.

| Claim | How |
|---|---|
| The engine works with no VOYD | `test_engine_*` import only `voyd.engine` |
| Documents inherit the scope's deadline | one `expire_at`, asserted equal on both rows |
| Nothing can be left holding a vector | both collections TTL on the same field, zero grace |
| An expired void answers nothing | search, describe and ingest 404 while its rows are still on disk |
| An expired document cannot reach a prompt | its row is still on disk and `recall` refuses it, with the reaper uninvolved |
| A read path written in ignorance is still safe | a naive `find({})` through the handle returns neither expired nor revoked rows |
| Forgetting does not wait for deletion | `revoke()` is unreachable on the next read, with the row still on disk |
| Setting the guarantee aside has a name | `including_forgotten()` is the only way, and it does not mutate the handle |
| A garbage deadline fails closed | a string, int or list `expire_at` reads as expired, and never raises |
| An unreadable deadline fails closed too | a `datetime.max` that cannot be shifted to UTC is dead, not an exception |
| The embedding leaves with the document | after the reaper runs, no vector survives its row |
| Pinning is the absence of a deadline | a null `expire_at` sibling survives in the same collection |
| The void is the retrieval boundary | a sibling scope's doc is not a hit, on both `$rankFusion` legs |
| A tenant id cannot be an operator | `{"$ne": ...}` in the tenant position is refused on all three tiers, not served |
| Search cannot walk around the lock | a passcode-gated scope refuses to be queried |
| A read limit cannot be raced | twelve concurrent readers against a limit of three are served three |
| "Added" is not "searchable" | `describe` reports pending vs indexed separately |
| A wrong-width vector is not "indexed" | a 512-wide vector in a 1024 index is parked as `failed`, not counted as searchable |
| The server can own the embedding | verified on Atlas: text in, no vector field stored, text query returns the right row |
| Asking for it is safe where it is unavailable | Atlas Local refuses, the engine falls back to a client vector index, loudly |
| Forgetting survives the server owning the vector | `revoke()` still refuses a row this process never embedded |
| A cold index cannot look empty | unready indexes route to cosine, logged and counted |
| A lost oplog window is not silent | `windows_lost` on `health()`, separate from routine `resumes` |
| A 500 is not input validation | an unrepresentable `ttl_seconds` and an oversized `metadata` are 422s |
| A 429 is not a bad document | failed embeds retry; a later valid key backfills |
| There is no way to leak a cleanup chore | no tool is named for reclaiming anything, and `forget` reclaims nothing |
| Forgetting is reachable from the product | `POST /v1/voids/{token}/forget` and a `forget` tool, not engine-only |
| Forgetting is not deletion renamed | after `forget`, `describe` reports 0 and the rows are still on disk |
| A stale index cannot pass for a current one | a changed spec is corrected, or named in `stale_indexes` |
| Atlas filling in its own index defaults is not drift | or every start-up would rewrite every index |

## Security

- A tenant id must be a scalar. A dict in that position is a query operator,
  and `{"$ne": "nobody"}` used to match every tenant on all three search
  tiers — presence was checked, shape was not.
- Forgetting is enforced on read, not by the sweeper: an expired or revoked
  document is refused by the handle every read goes through, so the minute
  before a TTL sweep is not a minute of serving it. `revoke()` is the
  immediate erasure path; the row it leaves on disk is evidence, and
  `including_forgotten()` is the only way to see it.
- Passwords and passcodes argon2; sessions and API keys stored only as SHA-256.
- The passcode hash is stripped from every API response. Verified across every
  endpoint, not just the obvious one.
- One credential, and it is an API key: `voyd_` + 32 random bytes, stored only
  as a SHA-256 hash. There are no passwords and no sessions, because there is
  no browser surface left to have them for.
- Passcode attempts on a guarded void are rate limited per IP *and* per void
  (10 / 5 min), before the argon2 verify runs — a slow hash is a cost ceiling,
  not a bound. In-process, therefore per-replica: the honest trade for not
  needing Redis, and the first thing to fix on more than one process.
- CORS is wildcard-open on `/v1`, which is the whole public surface.
- There is no byte path and no object storage, so there are no presigned URLs
  to leak, no bucket policy to get wrong, and nothing to reclaim out of band
  when a scope expires.

## License

MIT © 2026 Fabian Valle
