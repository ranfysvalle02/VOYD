# The Right of Refusal

### or: what every parent knows and no vector index does

---

Delete a document. Then ask your vector index about it.

For up to a full minute, it answers. Not with an error, not with a
stale-cache warning — with a normal, well-scored, well-formed hit, ranked
among the living, indistinguishable from a document that still exists.
Nothing is logged. No counter moves. There is nothing to page on, because
from the database's point of view nothing is wrong: the delete was accepted,
the sweeper is scheduled, the system is behaving exactly as designed.

That minute is measured, not estimated. Insert a row already past its
deadline, wait for MongoDB's TTL monitor, twenty times:

```
n=20   min=9.4s   p50=60.0s   p99=60.2s   max=60.2s
```

A minute is the *good* case. It is the fastest sweeper in the stack. An S3
lifecycle rule has a minimum granularity of one day. A cleanup cron runs
whenever it last worked. A Pinecone namespace has no expiry mechanism at all
— nothing in it owns a deadline, so nothing in it ever expires.

Now attach that to the thing everyone is building. A retrieval scope holds
what a model is about to read. "Deleted" is not a storage state anybody cares
about there. The question is whether a fact can **reach a prompt**. And in
that window it can, with a confident score attached.

---

## Ranking is not permission

Here is the whole problem in five words, and the reason it stays invisible:
**an index answers the wrong question.**

`$vectorSearch` is asked *what is relevant?* It is never asked *what is
allowed?* Those are different questions with different answers, and one of
them has been quietly standing in for the other since the first RAG demo.
Relevance has no opinion about whether a fact was revoked this morning. It
cannot have one. It was not asked.

Every retrieval stack has a permission story, and in almost all of them the
story is a filter somebody remembered to write. That is not a guarantee. It
is a **convention**, and conventions have a well-known failure mode: they
hold until the day they do not, and the day they do not looks exactly like
every other day.

Which brings us to parenting.

---

## The right of refusal

A child asks for something. A parent says no. Note what the parent does
*not* do: they do not delete the request from the universe, schedule its
removal for Tuesday, or file a ticket with the sweeper. They refuse, now, at
the moment of asking, and the refusal is total and immediate even though the
thing being refused continues to exist.

That is the operation missing from every retrieval stack in production.

| | what it is | when it takes effect |
|---|---|---|
| **delete** | a storage operation | eventually — a TTL sweep, a lifecycle rule, a cron |
| **refuse** | a retrieval guarantee | the next read |

Delete is a wish. Refuse is a contract.

And like any decent parent, the interesting part is not the *no*. It is that
the no is enforced at the door rather than written on a list somebody is
supposed to consult. A house rule that depends on everyone remembering it is
not a rule. It is a hope with good PR.

---

## VOYD, and the one idea underneath it

VOYD is an admission boundary for retrieval. One sentence:

> A retrieval rule has one authoritative form: a **per-document check on the
> way out**. Any query or index clause is an optional optimisation and must
> agree with it.

Everything follows from that, including the part that sounds like a
limitation and is actually the thesis: a rule that can express itself in a
query but *not* per document is not a slower rule. **It is a silent hole.**

Because a `find` goes through a collection query, the database can drop
forgotten rows server-side. A `$vectorSearch` hit does not pass through that
query. It arrives from an index that ranked it, having been filtered by
nothing. Put your deadline only in the query and you have built a system
where one read path prunes correctly and another serves the same row to the
wrong customer, and nothing anywhere is wrong enough to notice.

So: check every document on the way out. Every one, every path, every time.
About a microsecond each, in front of a five-hundred-millisecond model call.

---

## The part that took three tries

The instinct is easy and it is not enough.

Version one: re-check the deadline at each call site. Correct, and a
convention — one line each read path had to remember. The repository's own
history records how that went: six read paths, five of them remembered.

Version two: put the check behind a handle. `docs.find(...)` refuses;
`db.notes.find(...)` does not. Better — the guarantee is structural *within*
the handle — but now you need a CI gate to stop your own team reaching past
it, a source scanner to find the ones who already did, and a test asserting
no module in the package does it either. Three compensating controls, all
guarding one import somebody might forget.

Version three is the one that feels like cheating.

**Move the boundary to the wire.**

```bash
voyd-wire --config voydfile.py --target "mongodb+srv://…"
```

It speaks the MongoDB protocol. It sits between any driver and any cluster.
It applies the same per-document check to everything on the way back. And
then:

- there is nothing to import, so nothing to forget;
- it works from Node, Go, Compass and `mongosh`, none of which know it
  exists;
- the CI gate stopping your own team reaching past a handle becomes
  unnecessary, because **there is no raw read** and no handle to reach
  past.

An abstraction that deletes its own guardrails was in the right place. That
is the tell.

---

## Four acts, and a connection string

### Act one: reads refuse

Five documents. One expired, one revoked, one belonging to another tenant.

```
straight at the database   5 documents
through the boundary       ['a note somebody deletes', 'the fault code is P0301']
```

Nothing was deleted to achieve that. The expired row and the revoked one are
still on disk. They are simply not reachable — which is the entire point, and
the reason a credential you need *out of prompts now* and *on disk for the
investigation* stops being a contradiction.

### Act two: deletes become contracts

Here is the move I did not expect to be the best one.

Every codebase already contains `deleteOne`. It is written, reviewed, shipped
and forgotten. So the boundary gives it a better meaning:

```
db.notes.delete_one({'text': 'a note somebody deletes'})
  -> deleted_count=1          the driver is satisfied

reachable now     ['the fault code is P0301']
rows on disk      5           nothing destroyed
the mark          'deleted on the wire'
the deadline      set -> the reaper collects the bytes
```

They asked for the wish and got the contract, and the bytes still go, on the
deadline they already had. Every existing delete call site becomes provable,
immediate, evidence-preserving forgetting, and the diff is zero lines.

This is opt-in, because silently redefining `delete` for an operator who did
not ask is precisely the sort of surprise this whole project exists to
abolish. But when you *do* ask, you get it everywhere at once.

A caveat worth the ink, because it nearly shipped as a hole: `deleteOne` and
`findOneAndDelete` are **different wire commands**. Intercepting one and not
the other gives a team the guarantee for one delete verb and silently not the
other — which is worse than covering neither, because now they trust it. Both
are covered. And the verbs that *cannot* be a revocation — `drop`,
`dropDatabase`, `renameCollection` — are refused with a reason, because a
drop takes the marks with it and afterwards there is not even evidence that
anything was ever forgotten.

### Act three: auto-encryption, or the question refusal cannot answer

Refusal binds *this read path*. A restored snapshot does not run it. Neither
does a DBA with a shell, or a replica in another region, or the backup nobody
has opened since March.

So: encrypt the field, and put the key on the same deadline as the fact.

```python
kms = {"local": {"key": os.urandom(96)}}
```

That is the whole ceremony. Ninety-six bytes of randomness is a master key.
No cloud account, no KMS, no Enterprise download — and the same one line
becomes AWS, Azure, GCP or KMIP later by changing the dict.

```
on disk                    Binary(subtype=6), 130 bytes
contains the plaintext?    False
through the key            'alice was treated for a stress fracture in March'

Alice asks to be forgotten. Destroy the key, not the row:
  -> EncryptionError: not all keys requested were satisfied
```

Refusal is local. **A destroyed key is not.** The ciphertext in every
replica and every backup became noise at the same instant, including the
copies you cannot reach and the ones you have forgotten you have. That is a
strictly stronger sentence than "this application will not serve it," and it
is why the two mechanisms are not redundant: refusal covers the window
before erasure, and shredding covers the copies refusal cannot reach.

### Act four: auto-embedding, or the path with no query on it

Atlas can embed your text itself. You declare a model, you insert text, and
the index owns the vector:

```json
{"type": "autoEmbed", "path": "text", "model": "voyage-4", "modality": "text"}
```

No embedding code. No API call from your process. **No vector stored on your
documents at all** — which quietly removes an entire class of bug, because a
client-side embedder can drift from the index's model and a vector from last
quarter is not a worse hit, it is a hit in a different space.

It also produces the purest version of the whole argument. Watch:

```
$vectorSearch returned      ['the fault code is P0301 on cylinder one']
the expired row is on disk  True
client-side vectors stored  False
```

The application never computed a vector. It never issued a query with a
filter. The hit arrived from an index that ranked it. There was **nothing
this application held that could have filtered it** — and the expired
document was still refused, on the way out, one microsecond before it would
have become context.

That is the thesis with the training wheels removed.

---

## What this is not

It is not a driver. It picks one node and forwards bytes; it does not
load-balance reads, honour read preference, or retry a write the client
already saw fail.

It is not a policy engine. `enforce(subject, object, action)` is a pure
function of two arguments, which is why it structurally cannot express the
most interesting rules here — see the appendix on set-relative refusal.

And it is not finished. It is a boundary that is correct before it is
operable, and the README says which is which, because the failure this
project is named after is a system that is confidently wrong and quiet about
it. Being that system while complaining about it would be a poor look.

---

## The one sentence

If you take nothing else:

> **An index decides what is relevant. Nothing in your read path was asked
> whether it was allowed.** Put a check on the way out, put it somewhere
> nobody can forget, and "when did this stop being reachable?" becomes a
> timestamp you can defend instead of a shrug about a sweeper.

Delete is a wish. Refuse is a contract. Say no at the door.

---
---

# Appendix

## A. Running the demo

Four acts, one dependency, and the boundary is a command rather than a
file to copy.

```bash
pip install "voyd[crypto]"
voyd-wire --config voydfile.py --target localhost:27017

# and the acts, one file each, against a throwaway database
python examples/refuse.py           # act one and two
python examples/shred.py            # act three
python examples/clearance.py        # act four (needs an authenticated set)
```

| act | needs |
|---|---|
| 1 — reads refuse | any `mongod` |
| 2 — deletes become contracts | any `mongod` |
| 3 — auto-encryption | `pymongo[encryption]`. No KMS, no `crypt_shared` |
| 4 — auto-embedding | a real Atlas cluster in `VOYD_ATLAS_URI` |

Act four skips on Atlas Local, and the reason is worth knowing: Atlas Local
registers no embedding models, so it **declines** an `autoEmbed` declaration
and silently falls back to a client-supplied vector. A demo that accepted the
fallback would be proving the opposite of what it claims.

## B. The wire protocol, briefly

Every message is a 16-byte header and a body:

```
 0         4          8           12        16
 ┌─────────┬──────────┬───────────┬─────────┐
 │ length  │ requestId│ responseTo│ opCode  │
 └─────────┴──────────┴───────────┴─────────┘
```

`OP_MSG` (2013) is the only opcode that matters now. Its body is a flags word
followed by **sections**:

- **kind 0** — the command document. `{"find": "notes", "filter": {…}}`
- **kind 1** — a named sequence of documents beside it

Reads are one section. **Writes are two**, and this is where the one genuinely
nasty bug lives:

```
body  {"delete": "notes", "ordered": true, "$db": "app"}
seq   deletes: [{"q": {"_id": 1}, "limit": 1}]
```

A decoder that assumes a single section slices to the end of the payload,
swallows the sequence into the body's BSON, and fails. Mine returned `None`
there. The caller read `None` as "not a delete." Every delete was forwarded
and really deleted, the driver was told `deleted_count=1`, the demo printed
a perfect result, and the only thing that gave it away was a row count of 1
where the assertion said 2.

**Parse the sections. All of them.** And when you rewrite a message, clear the
checksum bit — a stale CRC over a body you just changed is worse than no CRC,
and the protocol makes it optional for exactly this reason.

## C. Turning a delete into a revocation

The rewrite is a pipeline rather than a `$set`, and each clause is a bug
somebody hit:

```python
[{"$set": {
    "forgotten": {"$literal": {"at": stamp, "reason": "deleted on the wire"}},
    "expire_at": {"$cond": [
        {"$eq": [{"$type": "$expire_at"}, "date"]},
        {"$min": ["$expire_at", stamp]},    # only ever earlier
        stamp]},                            # a pinned row gets a deadline
    "embedding": None,                      # the vector goes now
}}]
```

- **`$literal`** because a caller-supplied reason beginning with `$` would
  otherwise be read as a field path and write something else entirely.
- **`$min`** because retention that *grows* when somebody asks for erasure is
  the opposite of the request.
- **the `$cond`** because a missing deadline is a *pinned* row, not an early
  one, and `$min` against null would keep the null — pinning an erased fact
  forever.
- **`embedding: None`** because a vector is a lossy copy of the text in a
  coat, and it should not wait for the reaper.

## D. Set-relative refusal: the rules nobody else can express

Most access control answers *may this subject do this thing to this object?*
— one document at a time, statelessly. Some retrieval rules are not about the
document at all. They are about the **page**:

- *the prompt has no room left* — a token budget
- *this is the fourth copy of a passage already here* — de-duplication
- *at most 30% of this context may be unverified* — a provenance quota
- *no more than two documents from one publisher* — an anti-echo-chamber
  ceiling
- *a premium source costs more of one shared budget* — mixed-tier cost

Each refuses a document because of the **other** documents beside it. The
same document is admitted alone and refused in company.

An index filter cannot produce that: it decides each candidate before the
page exists. A policy engine cannot either: `enforce(subject, object,
action)` has nowhere to put the rest of the set, so for a fixed pair it
returns one answer forever.

The reframe is the most interesting idea in this whole area, and it is free
once the check runs on the way out:

> **A prompt is a regulated set, not a ranked list.** Relevance orders
> candidates. Admission decides what the assembled set is allowed to *be*.

One honest boundary on that: admission is a **veto**. It can refuse a
document for what is already on the page; it cannot *require* that something
be on it. So "must include a dissenting source" — a diversity floor — is not
expressible as a refusal. A floor is a retrieval objective and belongs to the
ranker. A ceiling is an admission rule and belongs here.

## E. Refusal that travels

An agent reads a document, summarises it, writes the summary back, and
embeds the summary. Now erase the source. You have deleted one copy of four.

If a derived document records what it was made from — transitively closed at
write time, so a grandchild already names the grandparent — then revoking the
source reaches the summary, the answer and the embedding in **one indexed
update**. And the same field read from the other end answers the question
people actually have:

```python
db.notes.find({"lineage": source_id})   # what was built on this fact?
```

For anything written back into the collection — which is what a RAG cache
*is* — the archaeology project is a query. What remains genuinely missing is
the artefact that **left**: a Slack message, a fine-tune, an answer you served
and kept only a receipt for.

## F. Where refusal stops

Four limits, each stated because discovering them later is worse.

**It binds a read, not a value.** Once a caller holds the fields, they are
outside the boundary. A copy taken before a mark was written is not the
document — it is what the document used to say — and `reachable()` admits it,
correctly, because it refuses what it is *shown*. For a long-running agent
this matters: a fact revoked at turn 40 does not vanish from the context the
agent carried forward itself. The fix is not a cleverer boundary; it is
re-reading the carried ids at the top of each turn, because that context is a
cache and this is the cache invalidating.

**It binds this application, not your data.** Another service with its own
connection is unaffected — which is exactly why the wire version matters, and
exactly why crypto-shredding exists beside it.

**A rule with no query half is invisible to every static analyser.** You can
scan a repository for reads that forget a deadline filter. You cannot scan it
for a token budget, because the reads it refuses look identical to the reads
it admits. Semgrep and CodeQL have the same nothing to work with.

**Partial enforcement is worse than none.** Covering `deleteOne` and not
`findOneAndDelete` does not give you half a guarantee. It gives you a false
one, which is the only kind that gets trusted.

## G. Field notes

Things that cost time and are cheap to inherit:

- **`.primary` is `None` on an undiscovered topology.** pymongo connects
  lazily. Ping first, or you will silently select the first node DNS returned
  — which, on a three-node replica set, reads perfectly and rejects every
  write with `NotWritablePrimary`.
- **Learn about failover from the error, not a timer.** `NotWritablePrimary`,
  `PrimarySteppedDown` and friends arrive on the reply the client was getting
  anyway. A health check is a guess about the future; that error describes
  the present. Check inside `writeErrors` too — that is where it hides on a
  batch, which is to say on exactly the command a boundary like this
  rewrites.
- **Negotiate compression away in the handshake.** Strip `compression` from
  `hello` and replies arrive readable. Recompressing every rewritten batch is
  a lot of work to avoid a demo's worth of bandwidth.
- **`mongodb+srv` means three things a raw TCP dial cannot do**: hosts in DNS
  SRV records, mandatory TLS, and no port in the string. Skip this and your
  proxy fronts a container on localhost and nothing anybody runs in
  production.
- **Atlas dropped `voyage-3`.** The supported set is reported by the server in
  its own error, which is the most useful error message in this entire story.
- **A collection must exist before you can index it.** Atlas answers "Error
  retrieving collection UUID," which reads like a permissions problem and is
  not one.
- **Don't pool upstream connections.** A MongoDB connection carries
  authentication, sessions, cursors and transactions. Share one and you hand
  a cursor to whoever asked second. Bound the *number* instead, and close
  past the limit rather than queueing — a driver retries, and an unbounded
  backlog is how a proxy turns a busy minute into an outage.
- **Bind loopback unless you terminate TLS.** A plaintext boundary reachable
  from the network would carry in the clear every document it just refused to
  serve, which is a worse failure than having no boundary at all.

## H. The measurements

Split by whether *you* can reproduce them from the demo in this post, because
a number nobody can re-run is a claim wearing a lab coat.

**Reproducible from `examples/`:**

| claim | number | how |
|---|---|---|
| per-document check | **128ns** p50, 140ns p99 | 30 × 1000 documents, `refuses()` alone, this laptop |
| ciphertext on disk | **130 bytes**, BSON subtype 6 | `examples/shred.py` prints it; plaintext absent, checked in the bytes |
| key destroyed → unreachable | refused, immediately | `examples/shred.py`, after one `delete_one` on the key vault -- the boundary revokes the documents *before* the key dies, so there is no cache window to wait out |
| autoembed models on Atlas | `voyage-4`, `voyage-4-lite`, `voyage-code-4`, `voyage-code-3`, `voyage-4-large` | the server reports the set in its own error |
| refusal on the `$vectorSearch` path | ranked hit refused, **0** client-side vectors stored | `tests/test_search_refuses_on_the_path_that_bypasses_the_query.py`, against a live Atlas cluster |

Put that 128ns beside a model call. A five-hundred-millisecond generation is
roughly **four million times** the cost of asking whether the document was
allowed to be there. The check has never been the expensive part; not asking
has.

**Measured previously, and archived rather than deleted.** These came from
benchmarks in this repository's history, which the rewrite cut. They are
reported with that caveat rather than dropped, because they are the numbers
the argument rests on — but if you want them, re-run them yourself:

| claim | number | where it came from |
|---|---|---|
| TTL sweep interval | p50 **60.0s**, p99 60.2s | 20 expired inserts, timed against Atlas Local |
| over-fetch at 50% refused | ~**2×** | refused hits are fetched and then dropped, so a page over-reads |

The first is the one worth repeating for yourself, because it is the whole
premise: insert a row already past its deadline, wait, and time how long
MongoDB keeps serving it. Everything in this post is an argument about what
to do with that window.
