# The application is a document

*The View did not leave. It became the experience.*

Fabian Valle · 17 September 2026

---

You can tell an architecture is lying by counting the logos.

A thing that calls itself an agent in 2026 is a Python process, a vector
database, a lexical search, a queue, a broker, a tracing SaaS, and a cron job
that was supposed to delete yesterday's memories and did not. The README says
*simple*. The invoice says otherwise. Five services, five failure modes, five
ways to be down at 3am because a fact that should have died is still ranking
into a prompt.

Ask a question that sounds too small: **why does a new product require a new
deploy?**

Not a new *version*. A new product. A new tenant. A new workspace. A new
conversation that needs its own memory, its own retrieval, its own tools, its
own deadline. Why is that a pipeline?

Because we decided, around 1979 and then again around 2005, that **the
application is the code**. Models, views, controllers: files in a repo. The
database is a drawer the code opens. To ship a new application you ship new
files. That was reasonable when an application was a company. It is a category
error when an application is a namespace you minted at 2pm.

Watch what happens if you refuse the error.

---

## The controller freezes. The View keeps moving.

There is a process. It is already running. It stamps every query with a
tenant id. It does not know your trade. It does not know what an agent is.
It will not know what you build next. It does not know whether the person
on the other side is holding a phone, a watch, a headset, or a pair of
glasses. That is not its job.

A *voyd* is the gap that process opens onto — a namespace, every MongoDB
query scoped by `voyd_id`. Creating one is an insert, and nothing else. The
voids, the documents, the deadlines, the embeddings, the guards: rows. Not
packages. Not a second database. Not a second process.

HTTP is how we proved it the first time. `{slug}.voyd.com`, a Host header,
a slug that scopes every query. The routing and the handlers are the same
functions they were before the insert. That is one modality. It is not the
View.

```
Host: auto.voyd.com  →  slug "auto"  →  every query {voyd_id: ...}
POST /v1/voyds       →  insert          →  live
```

The View never left. 1979's View was pixels in a window. 2005's was a
template in a repo you deployed. 2026's is the *experience* — however
this namespace is met, on whatever surface is in front of the person.
Phone, VR headset, AR glasses, a watch that only has a glance: those are
not new applications. They are new ways to consume the same Model and
the same Controller. Swap the surface and the voyd does not move.

MVC still describes the meeting. It just no longer describes the
*product*.

| | Classic MVC | This |
|---|---|---|
| Controller | new code per app | one process, already up |
| View | templates in the repo you deploy | the experience, for this modality, now |
| Model | schema you migrate | documents you insert, stamped with a tenant |
| A new app | a deploy | an insert |

**MVC put the application in the codebase. This puts it in a document. The
View is how you meet that document. The process is already running.**

That is the trick that freezes the body. It is not yet the trick that
scales. The rest of this essay is why the document has to live in
MongoDB — and why Atlas already does most of the magic that used to be
five logos.

---

## You cannot ship a namespace with no shape

A document that is "an application" still has to do *something*. An empty
namespace is a 404 with extra steps. So the first shape is the void: an
expiring, guarded retrieval scope, four calls wide — open one, put text in
it, search inside it, ask what is in it. Pick a name in the console, watch
the address appear, hit launch. Ten seconds later `{slug}.localhost` is
answering those four calls.

That surface is not the product. It is the first *experience* the inversion
needed in order to be true — a browser, a `curl`, an agent holding the same
four calls as MCP tools. A food truck or a clinic would be the same write
with a different experience on top. An agent workspace would be the same
write. A headset would be a different View onto the same rows. The frozen
controller does not notice. That is the test that the seam is real:
**the experience can change and the voyd does not.**

If this still sounds like a CMS, keep reading. WordPress already did "sites
are rows." It stopped at pages. The interesting behaviour leaked into plugins,
cron, Elasticsearch, Redis, a queue named after a vegetable. The application
was data. The *operating system* was still a pile of services.

The move is not "put HTML in MongoDB." The move is **put the operating system
in the same documents as the application.**

---

## A vector is a field

Here is the sentence the last three years of "AI infrastructure" have been
dancing around and not saying:

A vector is a field on a document. A deadline is a field on a document. A
claim is a document. A change is an event the database already emitted. A
tenant boundary is a filter the index can enforce.

None of that is a product. It is the document model, taken seriously.

Watch the five things every agent actually needs, and what they are when you
stop assembling them from logos:

| An agent needs | The usual stack | What it actually is |
|---|---|---|
| Retrieval that works on identifiers | vector DB + BM25 + a reranker | `$rankFusion` over one collection |
| Memory that doesn't rot | vector DB + a cleanup cron | **vector search + TTL** |
| Tool calls that survive a 429 | Celery + Redis | a claim with a retry policy |
| Triggers on state change | Kafka or a webhook mesh | a change stream |
| Trace trees and token spend | a tracing SaaS | `$graphLookup` + a time series |

Five services, five failure modes, five bills — or one connection string. VOYD
carries the first four; the fifth is MongoDB's and not something this codebase
ships, which is why you will not find `$graphLookup` in it.

The one nobody packages is the second row, and it is the one that makes the
inversion load-bearing instead of cute.

Bolt a vector store onto an agent and it only grows. Yesterday's decision, the
retracted fact, the stale config: all still score well, forever. Retrieval
quality decays while the bill climbs. The usual fixes are a cron nobody
maintains and a relevance hack nobody trusts.

But if the embedding lives *on the document*, the document can carry its own
deadline. MongoDB's TTL monitor drops the row. The vector goes with it. No
orphaned embeddings, no reaper process, no second collection for "the
memories we meant to forget." Pinning is the absence of a deadline, so
permanent and ephemeral facts share one collection instead of two subsystems.

```python
mem = engine.model("memories", tenant="session").memory(
    default_ttl=timedelta(hours=1))

await mem.remember(session, "user prefers concise answers", vec)          # decays
await mem.remember(session, "the user's name is Dana", vec, pinned=True)  # forever
hits = await mem.recall(session, qvec, text="E_QUOTA_429")                # hybrid
```

Hybrid, because identifiers have no useful embedding. `P0301`, a VIN, a
ticket code, an order id: the lexical half exists so the vector half is not
asked to do a job it cannot do. `$rankFusion` fuses both legs server-side —
mongot, over fields that never left the document. One round trip. No
reranker service. No hand-normalised scores.

This is not a feature list. It is a consequence of the same decision: **the
application is a document, so the document must be allowed to do everything
the application needs.** If it cannot, you are back to five logos.

---

## Three correctness problems wearing an AI costume

Most of what people call "AI reliability" is data-plane correctness that
presents as a model problem.

**Cross-scope recall is a data breach that arrives as an answer.** One
tenant's documents in another tenant's context window is not a ranking bug.
It is isolation failing at the one place your tenant boundary leaves your
process: search. `find()` with a `voyd_id` filter is table stakes.
`$vectorSearch` and `$rankFusion` will happily ignore it unless the tenant
field is in the index itself — both legs, including `compound.must` on the
lexical side. A library that scopes `find()` and not search is a library that
has not met an agent.

**An expired memory must never reach a prompt.** MongoDB's TTL monitor runs
about once a minute, so a "forgotten" fact stays readable for a window.
`recall()` has to re-check the deadline itself, on every hit, before it
returns one. A TTL index is a cleanup mechanism, not a guarantee. If your
forgetting is a cron, you have a race. If your forgetting is the read path,
you have a contract.

We can be precise about that because we got it wrong here, in this repository,
after writing the paragraph above. `Memory.recall()` was right from the first
commit. The void API was not: `get_void`, `list_voids`, `get_document`,
`list_documents`, `count_indexed`, `vector_search` — six read paths, every one
of them going to MongoDB with a tenant filter and no deadline. So for the
sixty-odd seconds between a void's deadline and the TTL monitor collecting it,
an expired scope was fully alive. Void-scoped search returned its documents.
Namespace-wide search returned them. `GET /v1/voids` listed it. Ingest would
add more rows to a scope that was already over.

Nothing failed, and that is the entire point. No exception, no warning, no
elevated error rate, no slow query, no degraded tier — a well-formed,
confidently scored hit, carrying an `expire_at` five minutes in the past that
nobody reads. The suite was green. The scope the user was told had expired
answered a question. `examples/why_this_belongs_in_the_database.py` parks the
TTL monitor and reproduces it in about two seconds, because a claim like this
one should be runnable and not merely asserted.

Which is the argument for where the primitive belongs, paid for instead of
assumed. A deadline enforced by remembering to write a clause is enforced
exactly as reliably as it is remembered, and the number of places to remember
it grows with every read path anyone adds. Six, in a codebase this small,
written by the people making the argument. A database that owned the deadline
— that made an expired scope unreadable one layer below every query, the way
an unauthorised read is unreadable — would not make that mistake cheaper to
avoid. It would make it unavailable.

So that is what the deadline became. `Forgetting` is a read handle with no
unfiltered `find` on it: every read through it refuses expired, revoked and
unreadable facts, and seeing everything requires saying
`including_forgotten()` out loud, where a reviewer can grep for it. The two
hand-written copies of the rule — one in `recall()`, one in the void search
path — are gone; one object answers the question now, and the test that
matters writes the *naive* read path on purpose and asserts it is still safe.

It also separates two things every other system conflates. Deletion is a
storage event, eventually consistent by nature. Refusal is a retrieval
guarantee, and it can be immediate. `revoke()` is the second one: a fact is
unreachable on the next read while its row is still on disk, which is not a
failure to clean up but the proof. Unreachable first, erased second, because
the reverse order is the bug this whole essay is about.

**Tool failures have exactly two kinds, and conflating them is fatal.** A 429
is the *world* being broken and must be retried. A malformed argument is the
*call* being broken and must not be. Mark the second kind the same way as the
first and a bad API key permanently poisons every job in the queue; a later
valid key backfills nothing. Silent, permanent, invisible. The document that
is the job has to know the difference, or the namespace that is the
application quietly dies.

These are not model-vendor problems. They are what you pay for when the
application is code and the memory is a sidecar. They go away — not the
engineering, the *class* of bug — when the application, the memory, and the
deadline are the same row.

---

## The hole where the answer used to be

On 30 September 2025, MongoDB ended Atlas App Services. Not just Device Sync.
The EOL took auth, Functions, HTTPS Endpoints, the Data API, GraphQL, and
Static Hosting. Database Triggers survived.

For a year there has been a hole exactly where "build your backend on Atlas"
used to be. They removed the convenience layer and did not replace it. Anyone
building a serious app on Atlas today writes the same five things by hand:
sessions, HTTP, rules, a worker, a stream listener.

App Services was a platform. A platform can be switched off. Everyone who
built on Functions and the Data API found that out on one day with one
deprecation notice.

A library cannot be taken away from you. It is a dependency you pin, on a
database you already run. That is not a detail. It is the reason this should
be Python you import, not a service you rent.

The lesson of App Services is also the argument for the inversion. They
already sold "an application is configuration on Atlas." They were right
about the shape and wrong about the ownership. **The application is a
document in *your* database. The runtime is *your* process. MongoDB is the
operating layer, not the landlord.**

---

## Why MongoDB, specifically

This is the part that has to be inevitable, so it has to be honest.

You can approximate every row of that table on Postgres. `pgvector`,
`tsvector`, `LISTEN/NOTIFY`, `SKIP LOCKED`, `cron`, a graph extension, a
hypertables extension. You will. People do. What you will not get is **one
document that is simultaneously the record, the vector, the deadline, the
claim, and the event.** You will get five extensions, five syntaxes, five
ways the backup story diverges, and a search index that is not the same
engine as the transactional one.

You can approximate it with the logo pile too. Pinecone plus Elasticsearch
plus Redis plus Celery plus Kafka plus a TTL cron. That is the current
default. It works until it is 3am and the fact you expired in the database is
still live in the vector store because they do not share a row.

MongoDB is the one mainstream database where that row can be all of it.
TTL, change streams, atomic claims, `$graphLookup`, time series, the vector
as a field: those run on `mongod`. They are not Atlas-only.

Hybrid ranking is the exception, and it is a real one. `$search`,
`$vectorSearch`, and `$rankFusion` run in **mongot** — Atlas Search — a
companion process. A plain `mongod` still *holds* the vectors; it cannot
rank them server-side. That is operational surface. Pretending it isn't is
how we spent months on the cosine fallback without a log line. The
accounting is in the appendix. The short version: mongot indexes the same
row. It does not copy it into another product.

The agent age does not need a new database. It needs the application to live
where the data already lives, and it needs that place to be allowed to
forget, to search, to claim, and to isolate. MongoDB already does those
things — mongod always, mongot when you have it, loudly when you don't.
Atlas already addresses a huge part of the magic: the vector as a field,
the deadline as a field, the claim as a document, the change as an event,
the tenant as a filter the index can enforce. The missing piece is not
another database. It is a thin layer of manners on top of the one you
already run — so a namespace is an insert, a forgotten fact cannot reach
a prompt, and a 429 is the world, not the document. That layer is what
this repo calls VOYD. The name of the body it sits on, once you stop
counting primitives, is ModelController.

---

## ModelController

MVC was a three-body problem. 1979 had windows. 2026 has tenants, and
six ways to meet one. The View was never a leftover. It was how the
Model reached a human. It still is. What changed is the surface: a
phone, a headset, glasses, a watch, a speaker that has no screen at all.
Those are not new backends. They are new experiences of the same
document.

What cannot change with the surface, today, is everything the Controller
was supposed to do after the meeting ended: remember, forget, retry, wake
up, refuse to leak into the next namespace. So the industry built a second
MVC in the basement, out of logos, and called it a platform. It is a
divorce. Redis got memory. Elasticsearch got find. Celery got retry.
Kafka got wake-up. Pinecone got the vector that used to live on the row.
Istio got the therapy bill.

A service mesh is couples counselling for a data plane that moved out.

**ModelController is the marriage.** Two letters. One replica set. The
View is the experience — modality in front, voyd underneath. Atlas does
most of the physics. VOYD is the thin layer of primitives so you can
build the next surface without assembling the logo pile first.

| The basement MVC | The logo | ModelController |
|---|---|---|
| Find | Elasticsearch + a vector DB | mongot, over the same row |
| Forget | a cron you do not maintain | TTL, plus a read path that re-checks so a prompt cannot cheat |
| Claim | Celery + Redis | the document *is* the job |
| Wake | Kafka | a change stream you resume, not a process you bury |
| Survive Tuesday | hope | a replica set, a resume token, a probe that tells the truth |

Eight primitives was a mesh with better names. Two nouns is an architecture.

**Model** is a collection of documents. The document is the record, the
vector, the deadline, the claim, the event. Traits are optional —
searchable, expiring, memory, queue, reactor, and `use()` for one this
package does not ship. The document is not. Tenant is a field you write
once and the index is not allowed to forget.

**Controller** is what the runtime does when the world is broken, which
is the world on a replica set: a primary will step down, an index will
build, a 429 will happen, mongot will be missing on a laptop. Probe.
Wait until a search index is a catalog and not a lie. Retry the *world*,
not the document. Resume after the election. Say the tier out loud.
Degraded is a first-class state, not a vibe.

That is operational resiliency as a property of the document, not a
product you install next to it. MongoDB already ships the physics —
elections, oplog, TTL, `find_one_and_update`, mongot-or-not. The
controller is the manners: never silent, never URI-guessed, never a
zero-row index dressed up as "no results."

The vow is short, because vows that last are:

```python
engine = Engine(client, db)
await engine.connect()     # what can this replica set actually do?

docs = engine.model("docs", tenant="tenant_id")
docs.searchable(text_paths=("title", "body"))
engine.model("sessions").expiring()
mem = engine.model("memories", tenant="session").memory(
    default_ttl=timedelta(hours=1))

await engine.ensure()      # indexes queryable, or we wait
engine.health()            # the tier, out loud
```

MapReduce was a paper. REST was a dissertation. The patterns that
survive are the ones you can import *or* recreate in an afternoon once
you have seen them. This is that kind. `engine.db` is still PyMongo. If
a trait is in your way you step past it in one line, on documents with
no wrapper type. We are not replacing your event loop. We are refusing
to shatter Model and Controller across five vendors so you can spend the
decade putting them back.

The next generation of apps will not be compiled per tenant. They will
be inserted. They will not subscribe to five clocks. They will marry
find, forget, claim, and wake on the row they already have. An agent, a
workspace, a storefront, a clinic, a thing you only see through glasses —
those are experiences. The voyd is the gap they all open onto.
ModelController is the body. Atlas is most of the magic. VOYD is the
rest: a layer of primitives, small enough to import, honest enough to
say when mongot is missing.

---

## What we actually built

VOYD is not the platform. Atlas is closer to that. VOYD is a layer of
magic and primitives on top of a database that already knows how to
forget, search, claim, and wake — so the apps of the next decade can be
documents, and the experience can keep changing without a second deploy.

The proof is one Python process, Host-header tenancy, a first experience
that happens to be an expiring retrieval scope with four calls on it,
because you have to meet someone *somewhere*. The engine underneath —
`voyd/engine/` — has no idea VOYD exists. Collections, fields, filters. Never storefronts, never headsets.
`health()` will not even say the word.

The vow is in the previous section. Given `mem` from it:

```python
await mem.remember(session, "prefers concise answers", vec)
hits  = await mem.recall(session, qvec, text="E_QUOTA_429")
job   = await engine.queue("runs", when={"kind": "embed"}).claim()
```

It declares. It does not intercept. `engine.db` is PyMongo. If a trait is
in your way, step past it in one line. It picks no embedding vendor —
`memory` takes vectors, not an API key. A test asserts `openai`, `voyage`,
and `cohere` appear nowhere in it. A memory layer that chooses your model
is a cage wearing a convenience label.

Capability is detected, never guessed from the URI. The opposite bit us: a
`"mongodb.net" in uri` heuristic meant `$vectorSearch` never ran against
Atlas Local, for months, silently. Every other primitive degrades along the
same spine: best-available, announced, counted, never quiet. A
`$vectorSearch` against an index that is still building returns *zero rows
instead of raising*. It looks exactly like an empty catalog. Startup waits.

**199 tests.** Fifty of them drive the engine from applications VOYD knows
nothing about: a recipes app, an agent runtime, and a kitchen that speaks
only `engine.model()`. That second set is the deliverable. If the agent story had needed new machinery it would be
marketing. It needed one composition — memory as vector search plus TTL —
and no new subsystems. If ModelController had needed a framework it would
be a cage. It needed a handle on a collection.

Limits, named, because overselling is how this dies:

- Change streams are not Kafka. No consumer groups, no fan-out, no replay
  past the oplog window, at-least-once with ordering caveats.
- Mongo as a job queue has a ceiling. Polling latency, no priorities,
  `find_one_and_update` contention under load. The long tail of apps that
  will never need Celery, not the ones that do.
- Hybrid search wants mongot. On a plain `mongod` you get a worse tier, and
  the process says so. That split is not a footnote; it is the appendix.

The measure of success is not how much of your app runs through this. It is
how little of it you notice.

---

## Going live is an insert

The unit of software in 2026 is not a company. It is a namespace: a tenant,
a session, a workspace, a storefront, an agent run. Namespaces that are
*code* cannot be minted at 2pm. Namespaces that are *documents* can.

A namespace that is a document still has to retrieve, forget, retry, react,
and refuse to leak into its neighbour. Those are not five products. They are
operations on a row that is allowed to hold a vector, a deadline, a claim,
and a tenant field the index will honour.

MongoDB is the database where that row is not a metaphor.

The process that hosts it does not change when you insert another one.
**Going live is a write.** The View is however you meet that write —
phone, headset, glasses, watch, whatever comes next. The voyd is the
gap underneath. ModelController is the body. Atlas is most of the
magic. VOYD is the thin layer of primitives so the next experience does
not require the next mesh. One connection string. A process that
refuses to lie about Tuesday.

You can keep assembling the logo pile. It will keep working, at 3am, in the
way that five clocks almost agree. Or you can marry Model to Controller on
the database you already run, let the next tenant be an insert, and let
the View keep evolving.

The process is already running. Insert the next one. Meet it however
you want.

---

## Appendix: mongot is a process, not a product

If you read the last sections and thought *that's Atlas Search, not
MongoDB*, you were right. This appendix exists so the essay does not get
to win an argument it did not earn.

`$vectorSearch` and `$rankFusion` do not run inside `mongod`. They run in
**mongot**, a companion process Atlas calls Search. A community `mongo:7`
container will store your embeddings as fields, honour your TTL, emit your
change streams, and then cosine in Python if you ask it to rank. Hybrid
fusion is Atlas, or Atlas Local, which is mongod and mongot in one image.
That is a second process. It has a build, a readiness story, and failure
modes that look like empty results instead of exceptions. We hit all three.

Naming it is the point. The enemy of this essay is not "a process." It is a
*product* that took a copy of the row and left. Three ways people add
search to a database, and only one of them keeps the document as the
application:

| | Extra moving part | What it does to the row | Query language | When it is missing |
|---|---|---|---|---|
| **Postgres + extensions** | in-process plugins | the row stays; syntax multiplies | SQL + `pgvector` + `tsvector` + whatever fuses them | you don't have vectors, or you don't have BM25, or you fuse in the app |
| **The logo pile** | other companies | **the row is copied** | each product's API | 3am: expired in one place, live in the other |
| **mongod + mongot** | a companion process | **the row is indexed in place** | the same aggregation pipeline | cosine over the same fields, announced |

Postgres extensions are the honest nearest neighbour. They keep the row.
They also keep five syntaxes, five version matrices, five backup stories,
and — for anything that looks like `$rankFusion` — usually a sixth moving
part anyway, because in-tree `tsvector` is not a lexical search engine in
the sense mongot is. Plenty of serious Postgres shops still add
Elasticsearch or ParadeDB for the half this essay cares about. At that
moment they have joined the logo pile while remaining a Postgres shop.

mongot is the other nearest neighbour: it is, bluntly, a search sidecar.
The difference that is load-bearing for the inversion is what the sidecar
is *allowed to see*. Pinecone is a copy of the vector. Elasticsearch is a
copy of the text. mongot reads the document MongoDB already has. A TTL
drop deletes the memory from ranking because there is nothing left to
index. Tenant isolation can be pushed into the search index because the
index is of the same tenant field `find()` already uses. `$rankFusion`
is a stage in the same pipeline as `$match`, not a score you fetch from
another HTTP host and renormalise in Python.

That is why "a vector is a field" survives contact with mongot. The field
lives on `mongod`. mongot is how you *ask* it. When you cannot ask it, the
field is still there, and in-process cosine is still correct — just
linear, and loud. The logo pile cannot say this. An expired Pinecone
vector is a second delete you remembered to issue.

The operational nuances are not theoretical. They are the engine's
keystone, paid for:

- **Presence is a probe, never a URI.** `"mongodb.net" in uri` called Atlas
  Local — `mongodb://localhost` — "not Atlas." `$listSearchIndexes` is the
  honest question. A plain `mongod` raises `Unrecognized pipeline stage
  name`. Atlas and Atlas Local answer.
- **A building index is indistinguishable from an empty catalog.**
  `$vectorSearch` against a mongot index that is not yet queryable returns
  **zero rows instead of raising**. Startup blocks until `indexes_ready`.
  Skipping that wait is how a cold boot looks like you have no data.
- **The tenant field type in the index must match the stored value**, or
  the query is rejected. Isolation that is "in the index" is only as true
  as the index definition.
- **An index that exists is not automatically the right index.** Skipping
  any index whose *name* you recognise leaves the old definition in place
  after a spec changes, and every later query runs against it — silently,
  and forever. A lexical definition can be corrected in place; a
  `vectorSearch` definition cannot, so that one can only be reported.

Atlas Local is the laptop claim, qualified: `docker compose up` starts
mongod and mongot together, no Atlas account, no network. A laptop running
`mongo:7` is a real environment for TTL, claims, and streams, and a
degraded one for search, and the health endpoint says `cosine`. That is
the positioning already chosen — Atlas is the best path, not the only
one — and it only stays honest if the runtime refuses to pretend.

So the claim, restated without the gloss:

Not "MongoDB has no sidecar."
Not "hybrid search is free on any `mongod`."
Not "Postgres cannot do this."

**The document is the application. mongot is how that document gets ranked
without becoming someone else's row.** When mongot is there, `$rankFusion`
is one round trip and isolation can hold where ranking happens. When it is
not, the same documents still expire, still claim, still stream, and
search says so out loud. That is the opposite of five clocks that almost
agree. It is also the opposite of the URI heuristic. An essay that
attacked silent degradation does not get to smuggle mongot past the reader
as "just MongoDB."

It is a process. It is not a product. The row never left.
