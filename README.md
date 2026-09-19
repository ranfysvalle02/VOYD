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
await docs.search(vector, text="P0301")  # nor can the search path
await docs.including_refused().find({})  # the unsafe thing, named out loud

await docs.revoke({"_id": x}, reason="credential leaked")
# unreachable on the next read. The row is still on disk. That is the proof.
```

There is no unfiltered read on that handle — no `find`, and no `search` —
so refusal does not depend on the next author remembering it. And because one
document owns the deadline — one `expire_at`, inherited by every row in the
scope, collected by one TTL index — there is no second system holding a stale
copy of it. Those are the two halves:
[one owner](#why-the-deadline-is-trustworthy) so nothing drifts,
[refusal](#deletion-is-a-storage-event-refusal-is-a-retrieval-guarantee) so
the gap before deletion is not a window in which anything is served.

Taking that seriously past the first commit turned out to mean three more
things, each of which is a section below. A refusal has to be **legible** —
`admission.refused` on every answer, because a model handed a short list
describes it as the whole truth. It has to be **provable** — an append-only
hash chain, and a receipt you keep, because the party holding the log is the
party being audited. And it has to know **who is asking** — clearance is a
claim on the caller compared against a field on the document, since a
scope-level lock has only two settings and neither one is right.

A **void** is a retrieval scope built on those two halves: it expires, and it
refuses. `pip install voyd` is the library; the service on top is five HTTP
calls.

Two documents beside this one. [**blog.md**](blog.md) is the argument at
length — the four-owners exhibit, the same bug arriving three times in
different clothes, the two bugs in the audit chain that made it worthless
while it looked healthy — and every number in it is re-runnable from `bench/`
and `drift/`. [**ideas.md**](ideas.md) is what is worth building next, in
order and with the reasoning, including what is deliberately *not* being
built.

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

There is a sixth, and it is deliberately not in that list because nothing in
the working loop needs it: `GET /v1/voids/{token}/proof` returns the
tamper-evident record of every refusal in the namespace. Five calls to use the
thing; the sixth is for the conversation afterwards. See
[the ledger](#the-ledger-is-the-part-that-is-a-ledger).

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

## Deletion is a storage event. Refusal is a retrieval guarantee.

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

So refusal is structural. `Admission` is a read handle, and there is no
unfiltered `find` to reach for — nor an unfiltered `search`, which took two
more passes to get right, because the same bug came back twice wearing
different clothes.

The second time, six read paths became two that each had to *remember to wrap*
the search primitive — and each wrote out its own fetch-budget guess, the same
wrong constant twice. A convention with two instances is a convention about to
fail a third time. So the handle owns the query as well as the rule:

```python
await docs.search(vector, text="P0301", limit=5, filters={"tenant": t})
```

`engine.search` is still there and still unfiltered, because it is the
*primitive*: the deadline is deliberately not in the vector index, so a
`$vectorSearch` hit has never been filtered by anything. That makes it the one
genuine footgun in the engine, so reaching for it is no longer a matter of
having read the docstring —
`tests/test_no_module_reaches_past_the_handle.py` walks the AST of every module
in the package and asserts none does. Two files are exempt, each for a stated
reason: `admission.py`, which is where the wrapping lives, and `verify.py`,
which calls it deliberately to assert the unwrapped version really does leak.

Refusal is the guarantee; the reasons are rules, asked in order, reported by
name. Forgetting is not the whole idea — it is the first two rules:

| rule | refuses because | waivable by `including_refused()` | reversible |
|---|---|---|---|
| `Deadline()` | the deadline passed, or cannot be read (fails closed) | yes | — |
| `revoked()` | somebody said forget this, now | yes | **no** |
| `quarantined()` | held back from models, deliberately still on disk | yes | yes |
| `EmbeddedWith(m)` | a different model produced this vector | yes | — |
| `Clearance(order=…)` | the caller is not cleared for this document | **no** | — |
| `Restricted()` | the document names who may see it, and it is not this caller | **no** | — |

The third column is the load-bearing one. The first four say a fact is
*forgotten*, and seeing what was forgotten is exactly the job the audit handle
exists for. The last two say *this caller* may not have it, which is not a
forgetting reason and not that handle's to waive — or "let me see the deleted
rows" becomes a privilege escalation. A rule declares which kind it is.

`forgettable()` is shorthand for the first two, which is why the name is
still honest. `admitting(...)` names them yourself:

```python
notes = engine.model("notes", tenant="t").admitting(
    Deadline(), revoked(), quarantined())
```

A flagged document stops reaching prompts and **stays on disk** — you cannot
investigate what you deleted. Adding that was one entry in a list, which is
the argument for rules over branches.

### A hold is not an erasure, and the reason knows which it is

The fourth column is the other half, and it decides three things at once.

Two of these reasons are operationally opposite. A **revocation** is an
instruction about the world — erase this — and the things behind it (a subject
erasure request, a leaked credential, a retracted document) are not hypotheses
that get withdrawn. A **quarantine** is a hypothesis: hold this while somebody
looks. A hold that cannot be lifted is not an investigation, it is a graveyard,
and a graveyard is indistinguishable from a leak nobody looked at.

```python
await docs.quarantine({"doc_id": "d1"}, reason="injection detector")
await docs.release({"doc_id": "d1"}, reason="reviewed, benign")

await docs.revoke({"doc_id": "d2"}, reason="credential leaked")
await docs.lift("revoked", {"doc_id": "d2"}, reason="...")
# Irreversible: 'revoked' cannot be lifted. An erasure is not a hypothesis,
# and the row is already scheduled for the reaper, so an undo would depend
# on the sweeper it was written to avoid.
```

One word on the rule — `reversible` — decides all three of:

- whether `lift()` removes the mark or raises;
- whether imposing it **stamps the erase deadline**. An erasure schedules its
  row for the reaper; a hold must not, because the row is the evidence;
- what the chain records on the way back out.

That coupling used to live in the caller of `revoke()`, which meant the next
`Marked` reason anybody added got whichever half its author remembered. This
is the same complaint the whole project makes about conventions, so the
reason carries it and the verbs read it off — including a reason this package
has never seen:

```python
review = Marked(field="under_review", reason="under_review", reversible=True)
await docs.impose("under_review", {"doc_id": "d3"})
await docs.lift("under_review", {"doc_id": "d3"}, reason="dispute closed")
```

**Reasons stack, and the write path knows it.** A document held for
investigation can still be erased when the investigation concludes it was
malicious; a subject erasure request still lands on a document whose deadline
passed thirty seconds ago and whose row is therefore still on disk. Both used
to match nothing and report success — the ordinary read query drops every
already-refused document, which is right for a read and was quietly wrong for
a write. Forgetting writes run against the audit query (still tenant-scoped,
still clearance-bound) plus one clause: *this mark is not already there*, so a
retry cannot re-stamp an erased row and buy it another lease.

**Both directions reach the ledger.** A chain that records only the imposing
half has a failure worse than having no chain: it attests that a fact stopped
being reachable at 14:02, the fact is reachable, and `verify()` still passes.
Nothing about a hash chain detects an event never written to it.

**And because `revoke()` has no undo, the interlocks are in front of it.**
This is the one family of calls here whose damage is done before you read the
return value, so both checks are pre-flight and both refuse rather than
proceed:

```python
await docs.revoke({"tenant": t}, reason="typo")
# UnboundedForgetting: narrows nothing beyond the tenant. Say it out loud:
#   revoke(..., everything=True)

await docs.revoke({"batch": "b7"}, reason="recalled", expect=12)
# BlastRadius if the filter matches anything other than 12 — counted first,
# nothing written.
```

Neither costs anything when unused: no extra round trip is issued unless
`expect` is given. `everything=True` follows `including_refused()` — the safe
thing is the default, the dangerous thing exists and has a word a reviewer can
grep for.

```bash
uv run python examples/hold.py       # ~5 seconds, no API key, no vendor
```

**Scope, stated plainly:** holds are an engine primitive and are deliberately
not on the HTTP or MCP surface yet. Deciding *who may release* is an
authorisation question this service does not have an answer for — the passcode
gates a scope, not a review workflow — and shipping `release` before that
answer exists would put "re-admit a document a detector flagged" behind the
same credential as "read the scope". The reviewer queue is the next piece;
`engine.queue(when=…)` already exists and the document is already the job.

### Forgetting has to survive being summarised

This is the hole that defeats the guarantee using the guarantee's own storage,
and it is the one worth fixing before cryptographic erasure.

An agent retrieves a document, summarises it, and writes the summary back into
the same collection. Later somebody asks for the source to be erased.
`revoke()` honours that request perfectly — against the source. The summary,
which quotes it, keeps scoring well forever. The erasure is satisfied, the
information is not gone, and every receipt in the system says it worked.

```python
notes = engine.model("notes").admitting(
    Deadline(), revoked(), lineage_field="lineage")

summary,  = await notes.derive({"text": "patient summary"}, parents=[diagnosis])
briefing, = await notes.derive({"text": "ward briefing"},   parents=[summary])

await notes.revoke({"_id": diagnosis}, reason="subject erasure request")
# 3 marked. A summary of a summary is still the fact somebody asked to erase.
```

**It cost no new read-path rule**, which is the part worth noticing. `revoked()`
already refuses any document carrying the mark — what was missing is that the
mark did not *travel*. Three properties make that cheap and hard to get wrong:

- **Transitive closure at write time.** A child's lineage is its parent's
  lineage plus the parent, so a grandchild already names the grandparent and
  one indexed `$in` reaches the whole subtree at any depth. Derivation only
  grows forwards, so the closure cannot go stale.
- **Either parent is enough.** A synthesis of two facts is refused when either
  source is erased — the alternative is a document surviving by having been
  made out of two things.
- **You cannot build on a refused fact.** `derive()` raises `DerivationBroken`
  if a parent is already revoked, held, out of scope, or above your clearance.
  Without that the race is trivial: revoke at 14:02, summarise at 14:03, and
  the contamination is clean. It refuses rather than writing-and-marking,
  because both ways of reaching there are bugs worth surfacing.

A derived fact also inherits the **earliest** deadline among its parents — a
summary of a fact that expires on Tuesday has no business outliving it — and
the whole subtree is scheduled for the reaper, not just the source. Holds
travel too, and so does releasing them: a review that clears a document and
leaves its summaries withheld has not finished. The chain records `direct` and
`inherited` counts separately, because *"you asked to erase 1 fact and 2
things made out of it went too"* is the sentence an auditor needs and one
total cannot say it.

### An embedding is a (vector, model) pair

`EmbeddedWith` is the rule that justifies the whole shape, because the bug it
closes is invisible to every other check. A 512-wide vector in a 1024 index
fails on width. A vector from a **different model of the same width** passes
everything — and a whole generation of one vendor's models is 1024
dimensions, so that is the normal case for anyone who upgrades.

Measured against the real API, same text, both 1024-wide:

| | cosine |
|---|---|
| identical text, old model vs new | **−0.053** |
| unrelated text, both on the new model | **+0.301** |

A model swap does not degrade ranking, it **inverts** it: unrelated text
outranks the document you were looking for, by five times. Nothing errors,
`indexed: true` is recorded, and `describe()` reports a healthy scope.

So the model is written in the same `$set` as the vector and cleared with
it — they are one fact — and a vector whose model is unrecorded is an orphan,
refused because nothing can say what it may be compared against. A row with
no vector *yet* stays reachable: that one is pending, not wrong, and refusing
it would hide the embed queue from `describe()`.

Which collapses the migration too. Change the model and every row is refused,
so nothing is searchable, so the embed worker re-embeds them and
`describe()`'s pending count is the progress bar. **A model change is a
document that needs embedding** — there is no migration subsystem because
there is nothing left for one to do.

```python
docs = engine.model("notes").forgettable()

await docs.find({})                        # reachable only — no flag, no filter
await docs.including_refused().find({})  # deliberate, and greppable

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

Four answers to one question, from one place: a **deadline** passed, it was
**revoked**, its deadline is **unreadable** (fails closed), or — the absence
of all three — it is **pinned**. Reasons beyond those are rules you add, and
[they compose](#a-hold-is-not-an-erasure-and-the-reason-knows-which-it-is):
a held document can still be erased.

Two enforcement points, always both: the rule is pushed into the query where
the query can express it, *and* re-checked per document on the way out. That
second one is the guarantee rather than an optimisation, because
`$vectorSearch` hits never went through a query — the deadline is deliberately
not in the vector index, for the reasons measured in `search.py`.

### What the receipts can and cannot tell you

```bash
curl -s localhost:8000/healthz | jq '.admission[0]'
# { "revoked_total": 3,          # exact: counted when it happened
#   "held_total": 2,             # also exact — and deliberately not added
#   "lifted_total": 1,           #   to the line above: a climbing `lifted`
#                                #   means a detector is being overruled
#   "refused_at_boundary": 41,   # a LOWER BOUND, on purpose
#   "refused_by_reason": {"deadline": 39, "unreadable": 2} }
```

`refused_at_boundary` undercounts, and the field name says so. Most forgotten
facts never reach the handle — the same rule runs inside the query and MongoDB
drops them server-side. Counting those would mean issuing every read twice. It
is a signal, not a ledger: any `unreadable` at all means something is writing
deadlines it shouldn't.

### The ledger is the part that is a ledger

Counters answer *how much has this process refused*. An auditor asks something
narrower: *show me that this fact stopped being reachable at 14:02, and show me
the record has not been edited since*. So every revocation is a link in an
append-only hash chain — `sha256(seq || prev || entry)` — and each link commits
to its predecessor, so no entry can be removed, reordered or backdated without
breaking every hash after it.

```bash
curl -X POST .../forget -d '{"doc_ids": ["d1"], "reason": "credential leaked"}'
# -> "receipt": {"seq": 0, "hash": "9cd69b1b...", "prev": "0000..."}

curl .../v1/voids/k6kC2pJz/proof
# -> "chain": {"intact": true, "entries": 2, "head": "4d71cc06...", "signed": false}
```

**Keep the receipt.** That is the design, not a nicety. A hash chain is
evidence against somebody who cannot rewrite it, and the operator of this
database can: wipe the collection, rebuild it without the awkward entry, and
what remains verifies perfectly. What falsifies that is the hash the caller was
handed *before the dispute existed*. Verification itself needs no key —
`intact` is arithmetic over data you are being given — and the HMAC on the head
is reported as `signed` because it is an attestation to whoever trusts the key
holder, not a public proof.

The response also states what it does **not** prove, in the payload rather than
only here: not that any row was deleted (they deliberately stay on disk), and
not that individual reads were refused — that is enforced on every read, and
recording it would cost a write per refused hit. Two further properties fall
out of taking this seriously:

- **The chain never expires.** Every other collection here inherits one
  deadline from one document. A proof collected by the same TTL index as the
  thing it proves is a coincidence with a short life, so this collection has no
  TTL index and a test asserts the absence.
- **An entry never carries the document's text.** It is the one collection with
  no deadline, so a quoted secret would outlive every mechanism built to forget
  it. Ids and reasons only, also asserted.

### Refusal is part of the answer

A read that refuses returns a shorter list, and a shorter list is ambiguous:
"nothing else matched" and "four more matched and were forgotten" are the same
three hits. The caller is usually a model, which will describe what it got as
what exists.

```bash
curl -X POST .../search -d '{"query": "pension liability"}'
# -> "matches": [],
#    "admission": {"refused": [{"reason": "quarantined", "count": 3}],
#                  "starved": false}
```

Three facts matched and are being withheld — a reason to say so, or to ask, and
not a reason to answer as though the scope were empty. The MCP `search` tool
documents the field to the model for exactly that reason. No other vector
database can offer this, because none of them know *why* a row is missing.

### A page of refusals is refilled, not truncated

Enforcing the deadline on read means forgotten documents are fetched and then
dropped — they spend the fetch budget. That budget was a fixed `limit * 2` in
both read paths, with a docstring admitting the worst case. The worst case was
worse than the docstring:

```
40 expired rows ahead of 6 live ones, limit=5  ->  0 hits
```

Zero. All six live rows indexed, queryable and on disk, and the caller got an
empty list indistinguishable from an empty scope — the same
fewer-rows-instead-of-an-error shape this codebase blocks startup over.

`Admission.saturate()` owns the budget now: it re-asks for candidates, sizing
each round from the refusal rate it just measured, until the page is full or the
candidates are genuinely exhausted. It returns a `Page` — a `list`, so no caller
had to change — carrying `refused`, `examined` and `starved`.

`starved` is narrow on purpose: the page is short **and** the search gave up
while candidates remained. A short answer over an exhausted candidate list is
the whole truth, however many refusals it took to establish. The first
definition here flagged those too, and `voyd verify` caught it doing so on a
healthy deployment — a warning that fires when nothing is wrong is a warning
people learn to ignore.

## Who is asking is part of the question

`Guard` asks *may this caller read the scope*. `Admission` asks *may this
document reach a prompt*. Neither asks the one that actually leaks: *may this
document reach **this** caller's prompt*.

A scope-level lock is all-or-nothing, so the moment one document in a scope is
more sensitive than the rest, the available answers are "everyone gets
everything" and "split the scope" — and one retrieval boundary per sensitivity
level is four owners of one deadline all over again. So sensitivity is a field
on the document, clearance is a claim on the caller, and they are compared per
hit by the layer that already refuses things:

```python
docs = engine.model("docs", tenant="t").admitting(
    Deadline(), revoked(), Clearance(order=("public", "internal", "secret")))

await docs.for_caller({"clearance": "internal"}).search(vector, filters={"t": t})
# "secret" documents are not lower-ranked. They are not returned.
```

`for_caller` returns a **new handle**, and that is load-bearing rather than
stylistic: `engine.admission()` deduplicates per collection and hands every
request the same object, so a version that assigned to it would make the last
request's identity the current one, under concurrency, inside an access check.
That bug does not error and does not reproduce. There is a test that
interleaves twelve requests specifically because it is the only place it would
ever be caught.

`Clearance` fails closed in four directions, which is the argument for a rule
object over a comparison written at a call site:

| | and it is refused, because |
|---|---|
| the caller has no clearance claim | absence is the lowest level, not a pass |
| the document's label is not in `order` | an unrecognised classification is not a low one |
| the document has no label at all | untagged is not public — or every row predating the policy is world-readable |
| **no caller is bound at all** | *raises.* Both answers are wrong: everything is the breach, nothing looks like an empty scope |

The last row is the one that came from writing the example rather than the
tests. Unbound, the query clause permits no level — so reads came back empty
and `revoke()` matched zero rows and **reported success**, telling the caller a
fact was unreachable when it was not. A silent no-op on the forget path is the
worst failure available here, so it raises `CallerRequired` instead of picking
an answer. `for_caller({})` is the distinct, legitimate case: authenticated,
holding no claims, entitled to nothing.

`including_refused()` cannot waive any of this — that is the last column of the
[rules table](#deletion-is-a-storage-event-refusal-is-a-retrieval-guarantee)
above, and the reason rules declare which kind they are.

This is engine-only on purpose. The HTTP product has one credential and no
claims worth trusting — a handle that believed `{"clearance": "secret"}`
because a request said so would be an authorisation system whose only input is
the attacker's. Claims come from whatever already authenticated the caller.

## May this caller *do* this?

There were three questions and only two had an answer:

| | asks | answered by |
|---|---|---|
| `Guard` | may this caller read the scope? | a passcode |
| `Admission` | may this document reach a prompt? | rules, per document |
| **`Authority`** | **may this caller perform this operation?** | **— nothing** |

The gap was invisible because the first two are carefully separated and
both are about *reading*. Every verb that changes reachability was
available to anyone holding a handle — which in practice means anyone
holding the scope's passcode. So "re-admit a document an injection detector
flagged" sat behind the same credential as "search this scope", and three
separate features had to stay off the HTTP surface because of it.

```python
docs = engine.model("notes", tenant="t").admitting(...)            .authorised_by(Grants.withholding_only())

pipeline = docs.for_caller({"sub": "indexer"})
await pipeline.quarantine(...)     # fine — at 3am, unattended
await pipeline.release(...)        # NotAuthorised

reviewer = docs.for_caller({"sub": "alice@acme", "may": ["release"]})
await reviewer.release(..., reason="reviewed, benign")
```

**The asymmetry is the design.** *Withholding* (revoke, quarantine, shred)
and *granting* (release) are not equally dangerous and must not be equally
available — a mistake in the second direction is the breach the detector
fired about. `Grants.withholding_only()` is the shape most services want.

Not attached means unchanged: by default the caller of a library *is* the
application, and demanding an authority from a script would be theatre.
Once attached, an **unbound caller raises** — same reasoning as
`CallerRequired`, where permitting makes the authority decorative and
refusing silently makes a revocation report success having done nothing.

### And the chain learned who

It could say what stopped being reachable, when, and on what instruction —
and not by whom. The strongest sentence available to an auditor was
*"somebody released the document the detector flagged."*

```
seq 0  quarantined  injection detector     by indexer
seq 1  lifted       reviewed, benign       by alice@acme
```

`actor` is hashed with the rest of the entry, so it cannot be attached
afterwards, and it is `None` where nothing knows — an unattributed entry
says so rather than naming a service account nobody checked.

## Verify it on your own deployment

Every retrieval system's README makes claims; this one ships the experiment
that would disprove them. That asymmetry matters because the failure is *silent
by construction* — a forgotten document answering a query, scored and
well-formed, with nothing logged — and a property whose violation is invisible
cannot be checked by looking at it.

```bash
voyd verify --uri "$MONGO_URI"    # exit 0 = the guarantee held here
```

It plants documents that must not be reachable, asks for them through every
read path that carries the guarantee, and fails if any of them answers — against
your indexes, your MongoDB version, and whatever tier your deployment actually
degraded to.

```
  mongodb 8.2.11  tier=hybrid  search=True

  [ok  ] deadline: an expired document is unreachable while its row is on disk
         the row is still on disk (TTL monitor parked), so every refusal below
         is the read path and not the sweeper
  [ok  ] revocation: a revoked fact is refused on the next read, and its row stays
  [ok  ] starvation: a page of refusals is refilled, not truncated
         filled 5 of 5 after examining 46 candidates, refusing 40
  [ok  ] clearance: a document above the caller's clearance is absent, not ranked
  [ok  ] reversal: a hold can be lifted, an erasure cannot, and both reach the chain
         held, unreachable, and no deadline on the evidence
         an erasure refused to be lifted, as it must
  [ok  ] inheritance: forgetting a fact forgets what was written out of it
         the source, its summary and the summary's summary all went, in one query
         and a new derivation from an erased parent is refused
  [ok  ] shredding: destroying a scope's key makes its ciphertext unreadable
         everywhere, not just here
         custody: a file at ./master.key (durable=True, audited=False)
         ciphertext at rest: a client with no key sees subtype 6
         a plaintext write is refused by the server, so bypassing the
         encrypting client fails loudly
         key destroyed; a cold client can no longer read it, and no restored
         backup ever will either
         and the master key rotated without rewriting a single document
  [ok  ] chain: the refusal ledger recomputes intact
```

It parks `ttlMonitorSleepSecs` so "still on disk" is a fact rather than a race,
and restores it on the way out including on failure — that is a server global,
so do not run it beside anything else that cares. It works on a bare `pip
install voyd`: no app extra, no running server, and it only ever touches a
scratch database it creates and drops.

CI runs it on every commit, and `tests/test_the_falsifier_can_fail.py` breaks
the guarantee thirteen different ways to prove each check bites — one per
check, and two checks that have more than one way to break. A checker that
cannot fail is worse than no checker — it turns an unknown into a false
assurance somebody then makes a promise on.

## Three primitives

**Scope.** A namespace the Host header selects — `{slug}.voyd.com` — and a void
inside it. Every query is filtered by `voyd_id`, and the filter is pushed *into*
the search index, not applied afterwards in Python. Cross-scope recall is a data
breach that arrives as an answer.

**Deadline.** One `expire_at` on one document, inherited by every row in the
scope, collected by one TTL index, and enforced by a handle with no unfiltered
read on it. The substrate, not a feature — see above for both halves.

**Guard.** A passcode on the scope, enforced on the read path. `Guard` asks
*may this caller read the scope*; `Admission` asks *may this document reach a
prompt*. Caller and document — two questions, two layers, deliberately not
one. The pair of them is a third question, and `for_caller()` is where it is
answered: [who is asking is part of the
question](#who-is-asking-is-part-of-the-question). There used to
be two doors — query and download — and gating one without the other would
have made search the way around the lock. There is one door now.

## For agents

Agent runtimes are the channel, not the competition. AgentCore, Vertex and
Claude managed agents all run agents and all hand the result back with nowhere
to put it. VOYD is the somewhere, reachable as five MCP tools:

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
| `examples/hold.py` | The asymmetry, end to end: a detector flags a document, it is held without a deadline, reviewed and released — then a second one is held, escalated to an erasure, and refuses to be taken back. Both directions on the chain, three counters that mean different things, and a reason this package has never seen behaving identically. |
| `examples/lineage.py` | Forgetting that survives summarisation. An agent reads a fact, writes a summary, then a briefing off the summary — one erasure request takes all three, at depth, in one query. And the write side: deriving from an already-erased source raises rather than laundering it. |
| `examples/shred.py` | The question refusal cannot answer. A key per scope, ciphertext at rest read back by a client with no key, one scope shredded and the other untouched — then it *measures* the key-cache window in which a crypto-erased fact is still readable, and the reaper takes the row while it waits. All three layers in one run. |
| `examples/clearance.py` | The same query, three callers, one scope. What a document is classified plus what a caller is cleared for, compared per hit — and the audit handle that can waive a revocation but not a clearance. |
| `examples/scope.py` | The HTTP product end to end, through the same client the MCP server wraps. Needs a running server and an API key. |

Two more that need something extra, and one that is not an example at all:

| | |
|---|---|
| `drift/exhibit.py` | The four-owners argument, run against real Postgres + Qdrant + MinIO. Needs `drift/docker-compose.drift.yml` and the `drift` extra. |
| `bench/measure.py` | The numbers above: expiry lag, the cosine cliff, per-tier latency. Verifies which tier actually served each query before reporting it. |
| `voyd verify` | Not an example — the falsifier, pointed at your deployment. Parks the TTL monitor, plants documents that must not be reachable, and exits non-zero if any read path answers. |

Run them one at a time. `forget.py`, the exhibit and `voyd verify` all park
`ttlMonitorSleepSecs`, which is a server-global, and the test suite has a
reaper test that does the same — so two of them at once is one of them
measuring the other's setting.

## The engine

`import voyd` is `Engine` and a MongoDB driver — that is the whole install.
Everything else is an extra: `app`, `voyage`, `mcp`, `crypto` (and `drift`,
for the exhibit's argument-by-counterexample). Refusal, inherited refusal,
holds, the chain, policies, `as_of` and the perimeter all work on the bare
install — `crypto` buys the erasure that survives a backup, and nothing
else depends on it. CI asserts that importing `Engine` does
not load FastAPI. There is no `r2` extra any more, which is the object-storage
section below arriving in the install list: text is a field on the row, so
there is no second store to add a dependency for.

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

## Extending it

Two extension points, and neither needs a fork. Both are duck-typed protocols
— inherit nothing, patch nothing, import nothing from the app extra.

**A new primitive is a trait.** Anything with a `kind`, a `collection` and an
`async ensure()` is something `Engine` will build and `health()` will report:

```python
class Outbox:
    kind = "outbox"
    def __init__(self, db, collection, *, tenant=None):
        self.db, self.collection, self.tenant = db, collection, tenant
    async def ensure(self):
        await self.db[self.collection].create_index("published")
        return True

engine.model("events", tenant="tenant_id").use(Outbox)
```

**A new reason to refuse is a rule.** This is the more interesting one,
because the two access rules this package ships — `Clearance` and
`Restricted` — were written against exactly the interface you get, and that is
checked rather than claimed:

| you provide | and the handle will |
|---|---|
| `reason` | report it by name, in `receipts()` and on `/healthz` |
| `refuses(doc, *, when=None)` | ask it per document on the way out — the half that holds for `$vectorSearch` hits |
| `clause()` | push it into the query when it can be expressed, so the database does the work |
| `needs_caller = True` *(optional)* | hand it the claims from `for_caller(...)`, plus `clause_for(caller)` for pushdown |
| `bypassable = False` *(optional)* | refuse to let `including_refused()` waive it |
| `reversible = True/False` *(optional)* | declaring it **at all** says an operator imposes this reason with a verb; the value says whether `lift()` can take it back, and whether imposing it stamps the erase deadline |

Derivation is orthogonal to rules — `lineage_field="lineage"` on `admitting()`
opts a collection into it, and every imposable reason then travels down the
edge without knowing derivation exists.

```python
class Unreviewed:
    reason = "unreviewed"
    def refuses(self, doc, *, when=None):
        return not doc.get("reviewed_by")
    def clause(self):
        return {"reviewed_by": {"$nin": [None, "", False]}}

notes = engine.model("notes", tenant="t").admitting(
    Deadline(), revoked(), Unreviewed())
```

`ensure()` indexes the field your rule filters on — a rule whose clause is a
collection scan is a guarantee somebody eventually turns off. A rule that
raises is a refusal named after itself, because an exception inside a filter is
how the filter gets skipped.

What makes this a claim rather than a hope is that a *stranger's* rule is
tested through the whole loop:
`tests/test_a_third_party_rule_is_a_first_class_reason.py` installs two rules
this package does not ship — one plain, one caller-aware — and asserts they
survive `ensure()`, are enforced on both halves with the two halves *agreeing*,
are counted under their own name, can decline to be waived by the audit
handle, and cannot open the gate by throwing. If that interface were not
enough to write `Clearance`, those tests could not exist.

## And the backups? Cryptographic erasure

The question a security reviewer asks four minutes in, and the one refusal
cannot answer. "The row is deliberately still on disk" is proof to an engineer
and a **finding** to a reviewer, and the reviewer is right: refusal is a
property of *this application's read path*, and a restored snapshot does not
run this application's read path.

So a key per scope, sensitive fields as ciphertext at rest, and destroying the
key makes every copy unreadable at once — the row, the replica, the snapshot,
the export somebody took in March — without any of them being visited.

```python
notes = engine.model("notes", tenant="patient").sealed("text")
await engine.ensure()

await notes.seal({"patient": "alice", "text": diagnosis})
await notes.find({"patient": "alice"})    # decrypted, and refuses what it can't
await notes.shred("alice")                # every copy of that ciphertext is noise
```

**The scope is the tenant, and that is the whole design.** A per-scope key
needs a field naming the key; a multi-tenant collection already has one.
Tying them together means no second field, no second lookup, nothing to keep
in step — and per-tenant crypto erasure falls out of a declaration the model
already made. `seal()` mints the key for a new tenant on the way past, so
"wrote a document, forgot the key" is not a reachable state.

Everything it returns is the ordinary refusing handle, so `revoke()`,
`quarantine()`, `derive()` and the rest keep composing. The ordering is the
efficient one: a revoked document is refused by its **mark** before anything
is decrypted, so only survivors reach the KMS.

### The plaintext write is rejected by the database

This is the half that makes it a guarantee rather than a convention, and it
closes the worst failure available here.

Automatic encryption protects every writer that goes through the encrypting
client. It does nothing about one that doesn't — a migration script, a shell,
a second service, this application holding the plain handle by accident. That
write **succeeds**, stores plaintext, and raises nothing. Silent, permanent,
and in a backup before anyone notices.

Measured, because it is the whole argument:

```
plain client, plaintext string  ->  WriteError (rejected)
encrypting client, same call    ->  stored, subtype 6
```

So `ensure()` puts a `$jsonSchema` validator on the collection requiring the
sealed fields to be `binData`. The driver encrypts client-side, so what
reaches the server is already binary and passes. Forgetting to encrypt is not
discouraged — it is **impossible**. Same move as `Admission` having no
unfiltered `find`, one layer down.

The engine also owns exactly one encrypting client and hands out collections
from it (`engine.aclose()` puts it down), so the caller never holds two
clients and never picks the wrong one.

Four decisions carry this, and each one had an easier wrong answer:

- **`keyId` is a JSON pointer (`/key_scope`), not a key id.** A literal id in
  the schema binds one key to the whole collection, so a single erasure
  request would crypto-shred every other tenant. Per-document key resolution
  is what makes the blast radius one scope.
- **The key vault is a MongoDB collection, so the key carries the same
  `expire_at` and is collected by the same TTL index.** One owner — the
  repo's first claim, applied to the thing that enforces the second. And a
  key's deadline moves earlier or not at all, for the reason a document's
  does: renewing a key extends the readability of everything it protects.
- **Automatic on write, explicit on read.** Forgetting to encrypt is silent,
  permanent and unrecoverable — the plaintext is in a backup no later fix
  reaches — so the driver does it below the application, for every writer,
  including next year's. Forgetting to *decrypt* hands you an obviously-wrong
  `Binary`: loud, harmless, self-correcting. And automatic decryption raises
  `EncryptionError` for the **whole batch** when one key is missing, so one
  crypto-erased document would turn a page of fifty into a 500 — the "fewer
  rows, or an error" shape refused everywhere else here.
- **A destroyed key is therefore a refusal, not an exception.** `unseal()`
  decrypts per document and refuses what it cannot, under `unrecoverable`,
  beside `deadline` and `revoked`. A crypto-erased document is a normal,
  expected state: it is the feature working.

### It is eventually consistent too, and we measured it

```bash
uv run --extra crypto python examples/shred.py     # ~2 minutes
```

libmongocrypt caches data keys, so a client that decrypted a document before
the shred keeps decrypting it afterwards. Measured here at **~60s in one
shape and past 120s in another** — the turnover is not a contract and not a
constant. Anybody who tells you crypto erasure is instant has not measured it.

Which is the argument for having all three rather than picking one:

| | when | where | result |
|---|---|---|---|
| **refusal** | immediate | this read path only | unreachable *now* |
| **crypto erasure** | eventual (key cache) | every copy, everywhere | unreadable *soon* |
| **the TTL reaper** | ~60s | this deployment only | gone *eventually* |

The key cache is a window in which the ciphertext is still readable — and
refusal already refused the document, on the first read after the request,
with no window at all. Refusal in turn binds only this application — and the
key is gone from all of them, including the backup nobody has restored yet.
Neither is the answer. Both is. (`examples/shred.py` shows all three firing in
one run: the reaper takes the row while step 4 is still waiting on the cache.)

### Two modes, and the tradeoff is measured

`Sealed` and `Queryable` are not preferences. The constraint that separates
them was checked against MongoDB 8.2, not recalled from a doc page:

| | the encrypted field is | shred granularity |
|---|---|---|
| **`Sealed`** (CSFLE, pointer `keyId`) | not queryable | **per scope** |
| **`Queryable`** (QE, equality 7.0+ / range 8.0+) | **queryable** | the whole collection |

QE **rejects a JSON-pointer `keyId`** — `BSON field
'create.encryptedFields.fields.keyId' is the wrong type 'string'` — so a QE
key is bound per field per collection at creation. Shredding it erases that
field for *everybody*. `Sealed` uses the pointer, which is exactly what makes
per-subject erasure possible.

So: **if erasure must be per-subject, use `Sealed`; if the ciphertext must be
searchable, use `Queryable` and accept that your shred granularity is the
collection.** Wanting both means one collection per subject, which is a
sharding decision wearing an encryption costume. A keyring can hold both
modes at once, and `describe()` prints the granularity, because this is the
kind of tradeoff that gets made once and misremembered forever.

```python
KeyringSpec(protect={
    "notes":  Sealed(("text",)),                      # per-subject erasure
    "people": Queryable(("ssn",), query_type="equality"),  # searchable
})
```

QE collections cannot be created by inserting into them — they need
`enxcol_.*` metadata collections that only `create_encrypted_collection`
makes, and writing to a namespace that skipped it does not fail loudly, it
writes **plaintext**. `ring.create_queryable(client, "people")` is the door.

### Key custody is a declared thing, not a dict

The whole claim rests on who holds the key that wraps the data keys, and a
crypto claim that is vague there is marketing. So it is typed, and it is a
ladder — a proof of concept must not need an AWS account, and production must
not accidentally inherit a proof of concept's custody:

```python
Ephemeral()                      # demo. Nothing survives a restart, and it says so
LocalFile(path="master.key")     # durable. Custody is a file permission
Aws(key="arn:aws:kms:...")       # audited. Destroying the CMK is somebody else's op
Azure(...) / Gcp(...) / Kmip(...)
```

Same code path throughout — a provider name and a master-key document. Three
things this fixes that a raw `kms_providers` dict does not:

- **`create_data_key` needs the provider *name* and a provider-shaped
  `master_key`.** Hardcoding `"local"` means an AWS-configured deployment
  wraps its data keys with a process-local secret and never finds out —
  there is no error, only a belief. (That bug was live in the first version
  of this; `test_custody_is_a_declared_thing.py` exists because of it.)
- **`durable` and `audited` are attributes**, so `describe()` and `voyd
  verify` can *print* the custody story instead of a reader inferring it
  from an absence. The weak rungs warn at `ensure()` — losing an ephemeral
  master key is indistinguishable from having shredded every key in the
  vault.
- **Omitting AWS credentials selects the credential chain**, which is the
  correct production shape: baking an access key into a config file in
  order to encrypt something is a net loss.

`from_env("VOYD_KMS")` reads the ladder from the environment and falls back
to `Ephemeral` *loudly*. A raw `kms_providers=` dict is still accepted — the
driver's vocabulary is the real interface — and is reported as **unknown**
custody rather than assumed safe.

**Rotation**, because a key that cannot be re-wrapped is a key that gets
copied instead, and a copied key cannot be destroyed — so "we shredded it"
stops being true without anybody doing anything wrong. `ring.rotate()`
re-wraps the data keys under a new CMK and **rewrites no documents**: the DEK
does not change, so nothing loses readability. That asymmetry is why rotating
a CMK is cheap and re-encrypting a collection is not.

**Automatic encryption also needs `crypt_shared` or `mongocryptd`**, which is
a MongoDB Enterprise download and not on PyPI. `voyd.engine.keyring.available()`
reports which half is missing, the tests skip with that reason attached, and
CI downloads the library and then *asserts it is present* — because a skipped
correctness test looks exactly like a passing one in a green run. Every other
guarantee in this package works without any of it.

## Where refusal stops, and what is honestly outside it

Refusal is enforced at one handle. Everything downstream holds copies that
handle cannot reach — and this is the first question a customer's
architecture diagram asks, because nobody's retrieval stack is one database.

The answer is three different verbs, kept separate on purpose. Collapsing
them into one mechanism is how a guarantee starts overstating itself.

| the copy is | example | what actually happens |
|---|---|---|
| **ciphertext** | a mirrored index, a cache holding sealed values | **erased.** Shred the key; every copy is noise, with no call to make |
| **plaintext you own** | Redis, an embedding cache, a second service | **told**, best effort, with the acknowledgement recorded — never enforced |
| **a consequence** | a Slack message quoting it, a fine-tune, a vendor prompt cache | **found**, not recalled. See the context receipt below |

```python
docs.bounded_by(Perimeter()
    .register(mirror)      # holds=SEALED   -> never called; the key erases it
    .register(cache)       # holds=OWNED    -> told, best effort
    .register(slack))      # holds=DERIVED  -> listed, because it cannot be recalled
```

**The obvious design does not work, and it is worth saying why.** Register
sinks, require an acknowledgement, and make an unacked sink mean the fact is
"refused everywhere until it acks" — that is theatre. The fact is *already*
refused locally; marking it refused again changes nothing, and the unacked
sink is still serving its copy. Worse, if an unreachable cache can block a
revocation then erasure depends on cache uptime. So:

> You cannot enforce refusal in a system you do not control. You can
> propagate, observe, and report.

A broken sink therefore **cannot fail an erasure** — every exception and
timeout becomes an unacknowledged receipt entry and a loud warning, and the
row was already unreachable before any of it ran. `describe()` enumerating
who holds what is the most valuable part: most teams cannot answer that
question at all.

### The copy that is not stored as text

An embedding is a lossy encoding of the field it came from, and it sits
right next to it — unencrypted, because encrypting it would kill search.

Measured here before it was fixed: after `revoke()`, the surviving vector
still separated its own topic from another by **0.9988 against 0.7992**
cosine. That is a working membership oracle over somebody who asked to be
forgotten, and it needs no inversion model — you ask the index whether a
document about X is in there and it says yes. (Text reconstruction from
embeddings is a live research area on top of that; the membership answer is
just the floor, and the floor is already a breach.)

So an irreversible reason destroys the derived encodings **in the same
write** as the mark — not on the reaper's schedule, because a guarantee that
waits for a sweeper is the thing this package exists to argue against. A
*reversible* one does not: a quarantined document is evidence, and its
vector is how an investigator finds the others like it. Same `reversible`
switch that already decides who stamps the deadline. Declare more via
`AdmissionSpec(derived_fields=("embedding", "gist"))`.

### The context receipt — what the model was allowed to see

The chain proves a *revocation* happened. It cannot prove that the model call
which produced a given answer respected one, and only the second is the
question asked after an incident.

```python
page = await docs.search(vector, text="...")
receipt = await docs.receipt_for(page)
# {"admitted": [...], "rules": ["deadline", "revoked"], "chain": "5a69...",
#  "at": "...", "refused": {...}, "hash": "..."}
```

A hash over the ids that reached the prompt, the reasons in force, the ledger
head at read time, and the instant deadlines were evaluated against. Attach
it to the inference and *"what did the model see when it said that?"* becomes
a value anyone can recompute — no secret, no cooperation from this database.

It also does not claim the model was *given* that context, or only that
context; nothing on this side of the wire can establish it. The receipt binds
a context to a policy, and the caller binds it to a generation by carrying
it. And a receipt will not guess which chain it belongs to — one naming the
wrong chain is worse than one that could not be issued.

### `as_of(t)` — and the answer that has to be "unknown"

```python
await docs.as_of(when).find({...})                    # the scope as it stood
await docs.reachability_at({"_id": x}, when)          # ("refused", "revoked")
```

Building this surfaced the defect that made it necessary. `Marked` — the
rule behind every revocation — carried an `at` and **ignored it**, so a
document revoked at 14:05 reported as unreachable at 14:02. A system
reconstructing what a model was allowed to see would have placed the
erasure *before* the answer that quoted the fact: an exoneration built out
of a bug, and an existing test asserted it in a comment that said so out
loud.

Both halves are time-aware, because the naive version disagrees with
itself: the per-document check compares the mark's `at` while the query
drops every marked row unconditionally, server-side — so `as_of` would
return an empty page and read as a scope where nothing was ever reachable.

`reachability_at()` returns **`reachable` / `refused` / `unknown`**, not a
bool. A row the reaper has taken leaves nothing to answer from, and
reporting that as "not reachable" would let a deployment clear itself by
pointing at the absence of the evidence. A bool has nowhere to put
`unknown`, and every caller would default it to the flattering one.

### Rules as data

A rule is a Python object, so a per-tenant policy is a deploy — which puts
the people who get audited on the wrong side of the release process.

```python
policy = [{"deny": {"field": "classification", "not_in": "$caller.clearances"}}]
docs = engine.model("docs", tenant="t").admitting(
    Deadline(), revoked(), *compile_policy(policy))
```

Compiled into rules indistinguishable from hand-written ones — same
protocol, same two halves, same tests.

**The compiler's hard rule is negative: both halves or nothing.** A policy
that compiles to a query clause but not a per-document check is not a
slower rule, it is a **silent hole** — `$vectorSearch` hits never went
through a query, so exactly the documents the clause would have dropped
walk into a prompt. So it raises at compile time, which is boot, which is
the one moment a policy error is cheap. Not "fall back to per-document
only" (safe but silent); not "fall back to the clause" (the hole).

Operators are a closed list with hand-written pairs, and nine of them are
checked against a live server for the two halves returning the same set.
A `$`-prefixed field name is refused rather than passed through — that is
the injection surface this package already refuses elsewhere — and a
value like `"$scope.id"` raises rather than being quietly compared as a
literal string.

## This is not a MongoDB argument

"You should use MongoDB" and "retrieval is missing a guarantee" are different
claims, and only the second is interesting. If a reader thinks this is the
first, they are right to dismiss it — so the thesis is ported, in full, to a
stack with no MongoDB in it:

```bash
docker compose -f drift/docker-compose.drift.yml up -d --wait drift-postgres
uv run --extra drift python drift/refusal_on_postgres.py
```

pgvector, one table, four acts: the same silent bug (an expired row answering
a vector query while the cleanup job has not run — Postgres has no TTL, so
"not yet" can mean any length of time); refusal in the read path; then the
structural part, because a filtered query is a *convention* that holds until
somebody writes the second query. So the table is revoked and only a view is
granted — the database itself refuses to serve the unfiltered rows to that
role, and the naive read raises `permission denied` instead of leaking. That
is Postgres's version of "there is no unfiltered read on the handle". Act IV
does inherited refusal with a recursive CTE.

It also states **what is harder there**, because an argument that lists only
its wins is marketing. Postgres has no TTL, so the moment you need rows
actually *gone* the deadline has two owners again — VOYD's one-owner claim
really is stronger on MongoDB, and that is a property of the engine, not of
the argument. The view costs a role and a grant, and holds exactly as long as
nobody runs the app as the owning role.

What carries over completely is the whole thesis: deletion is a storage event
and refusal is a retrieval guarantee; a rule you have to remember to apply is
not enforced, so the unfiltered read must be unavailable rather than
discouraged; and a refusal that does not travel to what was made out of the
fact is defeated by a summary. None of those is a MongoDB feature.

## What MongoDB is doing

| Primitive | Replaces | Where |
|---|---|---|
| TTL indexes | a lifecycle rule + a cron reaper | `engine.expiry` |
| `$rankFusion` (8.1+) | a reranker + score glue | `engine.search` |
| `$vectorSearch` + `$search` | Pinecone + Elasticsearch | same index |
| `find_one_and_update` | Celery + Redis | `engine.jobs` |
| Search index filters | scope checks you remember to write | both `$rankFusion` legs |
| A unique compound index | a lock service, to keep an audit chain linear | `engine.ledger` |

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

A suite that cannot fail is the same defect as a proof that cannot fail, so the
core guarantees have been checked by breaking them on purpose: making
`why_refused()` refuse nothing fails **31 tests**, removing the page refill
fails the starvation tests, and stopping the ledger from linking fails 8 proof
tests. That is not automated — it is a thing to redo when the shape of the
guarantee changes, and the numbers above are what it produced.

Do not run `voyd verify` or `examples/forget.py` beside the suite. They park
`ttlMonitorSleepSecs` and build their own search indexes, and mongot is one
process for the whole server — the symptom is an index-lag timeout in a test
that has nothing to do with either of them.

| Claim | How |
|---|---|
| The engine works with no VOYD | `test_engine_*` import only `voyd.engine` |
| Documents inherit the scope's deadline | one `expire_at`, asserted equal on both rows |
| Nothing can be left holding a vector | both collections TTL on the same field, zero grace |
| An expired void answers nothing | search, describe and ingest 404 while its rows are still on disk |
| An expired document cannot reach a prompt | its row is still on disk and `recall` refuses it, with the reaper uninvolved |
| A read path written in ignorance is still safe | a naive `find({})` through the handle returns neither expired nor revoked rows |
| Admission does not wait for deletion | `revoke()` is unreachable on the next read, with the row still on disk |
| Setting the guarantee aside has a name | `including_refused()` is the only way, and it does not mutate the handle |
| A garbage deadline fails closed | a string, int or list `expire_at` reads as expired, and never raises |
| An unreadable deadline fails closed too | a `datetime.max` that cannot be shifted to UTC is dead, not an exception |
| The embedding leaves with the document | after the reaper runs, no vector survives its row |
| Pinning is the absence of a deadline | a null `expire_at` sibling survives in the same collection |
| The void is the retrieval boundary | a sibling scope's doc is not a hit, on both `$rankFusion` legs |
| A tenant id cannot be an operator | `{"$ne": ...}` in the tenant position is refused on all three tiers, not served |
| Search cannot walk around the lock | a passcode-gated scope refuses to be queried |
| "Added" is not "searchable" | `describe` reports pending vs indexed separately |
| A wrong-width vector is not "indexed" | a 512-wide vector in a 1024 index is parked as `failed`, not counted as searchable |
| A same-width vector from another model is refused | measured: a model swap inverts ranking, and every width check passes |
| A document awaiting its first vector is pending, not wrong | or the embed queue would vanish from `describe()` |
| A rule cannot open the gate by raising | a rule that throws is a refusal, named after itself |
| Quarantine holds without destroying | flagged rows stop reaching prompts and stay on disk for the investigation |
| The server can own the embedding | verified on Atlas: text in, no vector field stored, text query returns the right row |
| Asking for it is safe where it is unavailable | Atlas Local refuses, the engine falls back to a client vector index, loudly |
| Admission survives the server owning the vector | `revoke()` still refuses a row this process never embedded |
| A cold index cannot look empty | unready indexes route to cosine, logged and counted |
| A 500 is not input validation | an unrepresentable `ttl_seconds` and an oversized `metadata` are 422s |
| A 429 is not a bad document | failed embeds retry; a later valid key backfills |
| There is no way to leak a cleanup chore | no tool is named for reclaiming anything, and `forget` reclaims nothing |
| Admission is reachable from the product | `POST /v1/voids/{token}/forget` and a `forget` tool, not engine-only |
| Admission is not deletion renamed | after `forget`, `describe` reports 0 and the rows are still on disk |
| A stale index cannot pass for a current one | a changed spec is corrected, or named in `stale_indexes` |
| Refusal costs the refused document its place, not the page | 40 expired rows ahead of 6 live ones still fills a page of 5 |
| A short page is not silently passed off as a complete one | `starved` when the search gave up with candidates left, and *not* when they ran out |
| An empty result says whether refusal is why it is empty | `admission.refused` on every search response, present when empty too |
| A revocation cannot be quietly un-recorded | deleting, reordering or editing a chain entry is reported as `gap`, `broken` or `forged` |
| A re-hashed forgery is still caught | the next entry commits to the old hash, so the edit has to reach the head |
| A rewritten chain is falsified by a receipt | the hash handed to the caller at the time is absent from the rebuilt one |
| The proof outlives what it proves | no TTL index on the chain, asserted by its absence |
| The audit record is not a new copy of the secret | a chain entry carries ids and reasons, never document text |
| A chain cannot fork under concurrency | twelve concurrent revocations produce twelve linear links |
| A hash survives its own round trip | the stored entry hashes to the receipt handed out, field by field |
| An unrecordable refusal still refuses | a broken ledger cannot turn a completed revocation into an error |
| The falsifier can fail | thirteen ways of breaking the guarantee, each caught by the check that claims it |
| An erasure cannot be taken back | `lift()` raises on an irreversible reason, and `release()` is not a way around it |
| A hold can be | imposed, lifted, and counted apart from erasure, because overruling a detector is its own number |
| A hold does not destroy its own evidence | imposing a reversible reason stamps no erase deadline |
| Reasons stack | a quarantined document can still be erased; an expired one can still answer an erasure request |
| A revocation never extends a row's life | the deadline moves earlier or not at all, so `erase_after` is a cap |
| A retry cannot buy an erased row a new lease | already-marked documents are excluded from the write, not re-stamped |
| Re-admitting is not a way past clearance | `lift()` runs the per-document check, because it is the only verb that *grants* reachability |
| Un-refusing reaches the chain too | a record of one direction of a two-direction transition is intact and false |
| Forgetting the whole scope has to be said out loud | a filter that narrows nothing beyond the tenant raises unless `everything=True` |
| A write with no undo checks its blast radius first | `expect=n` counts before it writes, and writes nothing on a mismatch |
| A caller-supplied reason cannot be an expression | `$`-prefixed reasons are stored verbatim, not read as a field path |
| Forgetting survives being summarised | erasing a source erases its summary, and the summary's summary, in one query |
| Lineage is closed at write time | a grandchild names the grandparent, so propagation is `$in` rather than a recursive walk |
| Either parent is enough | a synthesis of two facts is refused when *either* source is erased |
| You cannot build on a refused fact | `derive()` raises on a parent that is revoked, held, foreign, or above your clearance |
| A derived fact cannot outlive its source | the earliest parent deadline is inherited, and a shorter one set deliberately stands |
| Propagation does not cross the tenant | the boundary and every unbypassable rule are rebuilt on the way down the edge |
| The thesis is not MongoDB-shaped | the whole argument re-executed on pgvector, with what is harder there stated |
| The plaintext never reaches the disk | checked by reading with a client that holds no key, which is the only check that means anything |
| Shredding a key erases one scope | `keyId` is a JSON pointer, so one subject's erasure is not everybody's |
| The key expires with the documents | a TTL index on the key vault, and a key's deadline moves earlier or not at all |
| A destroyed key is a refusal, not a 500 | one crypto-erased document must not fail a page of fifty |
| Ciphertext cannot be served as text | `Unrecoverable` refuses a `Binary` that reached a read path unsealed |
| A plaintext write is refused by MongoDB | a `binData` validator, so bypassing the encrypting client fails loudly instead of silently |
| Sealing adds no bookkeeping to the document | the scope is the tenant; the stored row gains no field |
| Sealing composes with refusal | a revoked document is refused by its mark before any key is fetched |
| Sealing without a scope refuses to default | one key for everybody means one erasure request erases everybody |
| Durable custody survives a restart | a second engine, a new keyring, the same key file, yesterday's ciphertext |
| An erased document keeps no vector | the embedding went with the text; a held one keeps it, because evidence |
| A broken sink cannot fail an erasure | a raising or hanging cache is recorded unacknowledged, and the row is still refused |
| A sink must declare which claim applies | sealed, owned or derived — picking wrong is the only way the perimeter lies |
| A context receipt recomputes without a secret | over the admitted ids, the rules in force and the ledger head |
| A receipt will not guess its chain | naming the wrong one is worse than not being issued |
| A mark refuses from its own timestamp | a revocation stamped today did not apply in 2020 |
| Both halves agree under `as_of` too | or a replayed scope reads as one where nothing was reachable |
| Reachability is three-valued | a reaped row is `unknown`, never a flattering "no" |
| A policy compiles to both halves or neither | half-enforcement is a hole `$vectorSearch` walks through |
| A compiled policy matches hand-written behaviour | nine operators, query vs per-document, against a live server |
| A sealed sink is checked, not trusted | `audit()` catches one that still serves plaintext, and reports an unchecked claim as unchecked |
| A retry has a horizon | past it the row is closed *unconfirmed*, because a false success is worse than an honest gap |
| Granting reachability is gated apart from withholding it | a pipeline may quarantine and may not release |
| An authority with no caller raises | permitting makes it decorative; refusing silently is a no-op on a write |
| An unknown operation is denied | a new verb is not retroactively granted to old tokens |
| The chain names who | and hashes it, so attribution cannot be attached afterwards |
| A stale audit does not read as a current one | `never verified` / `verified` / `verified, 400d ago (stale)` |
| The queue reports what was given up on | `unconfirmed`, because draining by expiry looks healthy otherwise |
| A KMS custody carries its provider and master key | hardcoding `"local"` wraps an AWS deployment's keys with a process secret, silently |
| Custody declares durability and audit | and the weak rungs warn; a lost ephemeral key is indistinguishable from a full shred |
| A local key file is created once and reused | including base64, because secrets arrive text-shaped; a wrong length refuses rather than guesses |
| QE buys queryability and costs per-subject erasure | asserted against a live server, not recalled from a doc page |
| Rotation costs no document its readability | `rewrap_many_data_key` changes the wrapping, not the data key |
| A missing crypto stack is loud | the probe says which half is absent, and CI asserts it is present |
| No module reaches past the handle | the AST of every module in the package, not a review comment |
| A caller with no clearance claim gets nothing | absence is the lowest level, asserted for four shapes of missing |
| An unrecognised classification is refused, not ranked low | a renamed level cannot become world-readable |
| Untagged is not public | a document with no label is refused unless a default is declared |
| Two concurrent callers cannot see each other's documents | twelve interleaved requests against one shared handle |
| The audit handle cannot waive clearance | `including_refused()` shows forgotten rows, never rows above the caller |
| Both enforcement points agree about access | the query and the per-document check return the same set, per clearance |
| An unbound read raises rather than guessing | and an unbound `revoke()` cannot report success having matched nothing |
| A caller holding no claims is a real answer | `for_caller({})` returns nothing; never binding raises |
| The image cannot ship a credential | `.dockerignore` excludes `.env`, and `.env.example` is asserted to survive |
| The documented first run is a run that works | the file the Quickstart copies exists, parses, and covers every setting |
| Nothing in the package is orphaned | the AST of `voyd/`, with a two-part allowlist that is itself checked |
| The README cannot promise what is gone | every backticked identifier in this table must still exist in the source |
| A third party can add a primitive | a trait this package does not ship is built by `ensure()` and listed by `health()` |
| A third party can add a reason to refuse | a stranger's rule, enforced on both halves, counted by name, and unwaivable if it says so |
| Atlas filling in its own index defaults is not drift | or every start-up would rewrite every index |

## Security

- A tenant id must be a scalar. A dict in that position is a query operator,
  and `{"$ne": "nobody"}` used to match every tenant on all three search
  tiers — presence was checked, shape was not.
- Admission is enforced on read, not by the sweeper: an expired or revoked
  document is refused by the handle every read goes through, so the minute
  before a TTL sweep is not a minute of serving it. `revoke()` is the
  immediate erasure path; the row it leaves on disk is evidence, and
  `including_refused()` is the only way to see it.
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
- Every revocation is recorded on an append-only hash chain, and the record is
  tamper-evident rather than trusted: `GET /v1/voids/{token}/proof` recomputes
  it with no key required. The chain's signature is HMAC, so it authenticates
  the head to a verifier who trusts the key holder and is not a public proof —
  the response says `signed: false` when no key is configured rather than
  implying an attestation nobody made. Against the operator of the database
  itself, the load is carried by the receipt handed back from `forget`.
- `Clearance` and `Restricted` fail closed in four directions: a missing
  caller claim is the lowest level rather than a pass, an unrecognised label
  is refused rather than sorted low, an untagged document is refused unless a
  default is declared, and a handle with no caller bound raises instead of
  returning either everything or nothing. `including_refused()` cannot waive
  any of them — it waives forgetting, not access, or "let me see the deleted
  rows" would be a privilege escalation.
- The refusal chain is the one collection with no deadline, so it deliberately
  never holds document text — an audit record that quoted the secret would
  outlive every mechanism built to forget it.
- The container image excludes `.env`, `.venv` and `.git`. It did not, for a
  while: there was no `.dockerignore`, so the Dockerfile's final `COPY . .`
  baked the developer's real credentials into a layer anyone pulling the image
  could read — and a 248MB host-built `.venv` on top of the one `uv sync` had
  just created. Both are invisible locally, because the build succeeds and the
  container starts. The exclusions are asserted by a test now, including the
  one that must *not* apply: `.env.example` stays, because the Quickstart
  tells you to copy it.
- CORS is wildcard-open on `/v1`, which is the whole public surface.
- There is no byte path and no object storage, so there are no presigned URLs
  to leak, no bucket policy to get wrong, and nothing to reclaim out of band
  when a scope expires.

## The public surface is a promise

`import voyd` is seven names. `voyd.engine` is the advanced namespace, and
it reached a hundred exports the way these things always do: one justified
addition at a time, each obviously fine, nobody ever reading the list from
the top. Forty-eight of them appeared in neither this README, nor the blog,
nor any example.

It is seventy-five now, grouped by what a reader is trying to do, and
`tests/test_the_public_surface_is_deliberate.py` pins the list — so adding
a public name is a line in a diff somebody has to justify rather than a
consequence of having written a class. The same mechanism as
`including_refused()`: the safe thing is the default, the other thing is
said out loud.

**Nothing was deleted.** What was cut went from *promised* to *present* —
still importable from the module that owns it, no longer guaranteed:

| cut | why | where it lives |
|---|---|---|
| `Rule`, `Trait`, `Sink`, `Authority`, `Custody` | `runtime_checkable` protocols that nothing ever `isinstance`-checks, whose own docstrings say **inherit nothing** — so `__all__` was advertising a base class that does not exist | their own modules |
| `REVOKE`, `RELEASE`, `SHRED`, … | vocabulary you only touch when writing an `Authority` | `voyd.engine.authority` |
| `Model`, `Capabilities`, `Acknowledgement`, `Denies` | return types — you receive them, you do not construct them | their own modules |
| `SearchEngine`, `Expiry`, `detect`, `bind`, `backoff`, `kind_of` | internals reachable as `engine.search_engine`, `engine.expiry`, … | their own modules |

One name was genuinely deleted: `POLICY`, a constant referenced nowhere but
its own definition. The only kind of export that costs nothing to remove is
the one nobody was ever going to type.

## Known issues

Defects, unproven claims and imprecisions in what already ships are in
[`ISSUES.md`](ISSUES.md), with what would close each one. A project that
argues you should ship the experiment which would falsify you cannot keep
its own defects in a commit message.

[`ideas.md`](ideas.md) is the other half: what is worth *building* next,
as opposed to what is wrong with what exists.

## License

MIT © 2026 Fabian Valle
