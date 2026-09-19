# Every database can delete. None of them can refuse.

Delete a document. Then ask your vector index about it.

For up to a full minute, it answers. Not with an error, not with a stale-cache
warning — with a normal, well-scored, well-formed hit, ranked among the live
results, indistinguishable from a document that still exists. Nothing is
logged. No counter moves. There is nothing to page on, because from the
database's point of view nothing is wrong: the delete was accepted, the
sweeper is scheduled, the system is behaving exactly as designed.

That minute is measured, not estimated. Inserting a row already past its
deadline and waiting for MongoDB's TTL monitor, twenty times:

```
n=20   min=9.4s   p50=60.0s   p99=60.2s   max=60.2s   mean=57.5s
```

Nineteen of the twenty sit at 60.0s, and that is the method rather than the
world: each sample starts immediately after the previous sweep finishes, so it
waits a full period. Only the first — landing at a random phase — shows 9.4s.
So this measures the **ceiling**, and pins it precisely. The sweep interval is
60.0 seconds. A document expiring at a random moment waits uniformly somewhere
in [0, 60].

A minute is the *good* case, because MongoDB's TTL monitor is the fastest
sweeper in the stack. An S3 lifecycle rule has a minimum granularity of one
day. A cleanup cron runs whenever it last worked. And a Pinecone namespace has
no expiry mechanism at all — nothing in it owns a deadline, so nothing in it
ever expires.

Now attach that to the thing everybody is building. A retrieval scope holds
what a model is about to read. "Deleted" is not a storage state anybody cares
about there; the question is whether a fact can **reach a prompt**. And in the
window above, it can, and the answer arrives with a confident score attached.

## Retrieval does not need a faster sweeper

It needs a different guarantee.

> **this fact may not reach a prompt** — answered on every read, immediately,
> whatever the sweeper is doing.

Call it *refusal*. It is not deletion done faster; it is a different kind of
operation entirely, and the distinction is the whole argument:

| | what it is | when it takes effect |
|---|---|---|
| **delete** | a storage operation | eventually — a TTL sweep (60.0s), a lifecycle rule (~a day), a cron (when it last worked) |
| **refuse** | a retrieval guarantee | the next read |

Every system's honest answer to *"when was this forgotten?"* is *"whenever the
sweeper got to it"* — a timestamp nobody can defend to an auditor, describing
a window nobody is watching.

Nobody ships the second row. VOYD is an attempt to, and this is what that took.
Not the pitch: the three times the same bug came back, the two bugs in the
proof I built to prevent bugs, and the number that turned out to be worse than
I had written down.

## Whose problem this is

Four situations, and if none of them is yours then the rest of this is just an
argument about databases.

**A session ends.** An agent has been accumulating memories against a
conversation, and the conversation is over. "This session is forgotten" has to
be true of the next retrieval, not of the next sweep — otherwise the following
session inherits context nobody intended it to have, with a good score
attached.

**Somebody asks to be erased.** A subject erasure request whose effective
timestamp is *"whenever the cron ran"* is not a timestamp you can defend. And
the artifact the requester should walk away with is not a 200 — it is something
that proves, later, what happened and when, and that the record has not been
edited since.

**A credential leaks into a scope.** You need it out of prompts immediately and
you need the row for the investigation. Those are contradictory requirements
for `DELETE` and the same requirement for refusal: unreachable now, on disk
until the deadline, with `including_refused()` as the only way to look at it
and a name a reviewer can grep for.

**One scope, documents of different sensitivity.** The moment that is true, a
scope-level passcode has two settings and neither is right — and splitting the
scope by sensitivity level means one retrieval boundary per level, which is the
drift problem below with extra steps.

All four are the same question asked at different volumes: *may this fact reach
this prompt, right now?* None of them is a question about storage.

## Why nobody ships it

Because refusal is not a feature you add. It is a shape, and almost every
retrieval stack has the wrong one.

Consider what owns the deadline in a normal build:

| | owns the expiry | granularity |
|---|---|---|
| Postgres row | your code | whenever the cron runs |
| Pinecone namespace | **nothing** | never |
| S3 object | a lifecycle rule | ~a day, per prefix |
| the cleanup cron | whoever wrote it | whenever it last worked |

Four owners, four clocks, four ways to drift — and the drift *is* the bug. The
vector outlives the document. The bytes outlive the row. The lifecycle rule was
never applied to the new prefix. Now a deleted document is still answering
queries, and nothing anywhere is wrong enough to notice.

That claim is an architecture opinion, so it does not get to stay prose.
`drift/` stands the four owners up as four real services — Postgres, Qdrant,
MinIO — and runs the scenario. Every service gets its real mechanism: Postgres
a cron `DELETE`, S3 a real lifecycle rule (whose real minimum granularity is
`Days: 1`, against a 5-second deadline), Qdrant its real delete API. Nothing is
stubbed and nothing is sabotaged:

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

Score 1.0000. The system of record is *correct* — the row is genuinely gone —
and the answer is a leak. The exhibit's last step shows that one more delete
call fixes it, which is precisely the point: that call is application code, it
is not transactional with the first delete, and forgetting it produces an
answer rather than an error.

So the first move is not a feature. It is collapsing four owners into one: one
document with one `expire_at`, inherited by every row in the scope, collected
by one TTL index. Nothing to drift, because there is nothing to keep in step.
The bottom row of that table does not exist here at all — text is a field on
the document rather than an object in a bucket, so there is no second store.
That is a stronger answer than keeping two stores in step well.

Which fixes *who* owns the deadline. It does not fix *when* it takes effect,
because deletion is eventually consistent no matter who owns it. That is the
other half, and it is the interesting one.

## Refusal, made structural

The instinct is easy and it is not enough. Two read paths in this codebase
re-checked the deadline per hit from the very first version. Both were correct.
Both were a **convention** — one line each call site had to remember — and the
repository's own history records what conventions are worth:

> `get_void`, `list_voids`, `get_document`, `list_documents`, `count_indexed`,
> `vector_search` — six read paths, every one of them going to MongoDB with a
> tenant filter and no deadline.

Six. Not one forgotten by a newcomer: six, written by someone who knew the
rule, in a codebase whose entire thesis is the rule. That is what a convention
decays to, and it decays silently, because a read path that forgets to filter
does not error. It returns more rows.

So the rule stopped being a line to remember and became an object you cannot
read around. `Admission` is a read handle with **no unfiltered read on it**:

```python
docs = engine.model("notes").forgettable()

await docs.find({})                        # cannot return a forgotten fact
await docs.search(vector, text="P0301")  # nor can the search path
await docs.including_refused().find({})  # the unsafe thing, named out loud

await docs.revoke({"_id": x}, reason="credential leaked")
# unreachable on the next read. The row is still on disk. That is the proof.
```

The failure mode is inverted. Before, you had to remember to be safe. Now you
have to *declare* that you want the unsafe thing — and the declaration has a
name a reviewer can grep for.

Two enforcement points, always both. The rule is pushed into the query where
the query can express it, *and* re-checked per document on the way out. That
second one is the guarantee rather than an optimisation, because
`$vectorSearch` hits never went through a query at all: deadlines are
deliberately not pushed into the vector index, for reasons I will come back to.

And `revoke()` is the operation no vector database has:

```
  Now somebody says: forget that first one. Right now.
    revoke() marked 1 fact(s) unreachable

    recall  -> ['the fault code is P0301']
    on disk -> 2 rows        <- the secret is STILL HERE
       and it is already unreachable. No sweeper ran. Nothing
       was deleted. The next read simply refused it.
```

That row is deliberately still on disk. It is not a failure to clean up — it is
the proof. **Unreachable first, erased second**, because the reverse order is
the bug. Erasure stays on the scope's deadline: `revoke()` moves a deadline
into the past, so the same TTL index that collects expired scopes collects
these too. There is no erasure subsystem, because an erasure request *is* a
deadline that has already passed.

## The same bug, three times

Here is the part I would want to read, and the part most write-ups leave out.

Making refusal structural did not take one fix. It took three passes, and each
time the job looked finished. Each time, the same bug came back wearing
different clothes — and the tell was always identical: **a rule
that had to be remembered, by a smaller number of people, in a place that
looked too small to matter.**

**First disguise: six read paths.** Fixed by the handle above. The
hand-written `_unexpired()` helper is deleted; `store/mongo.py` came out six
lines *shorter* for the change. A rule you have to remember to apply is not
enforced, it is suggested.

**Second disguise: two read paths, each remembering to wrap a search.** The
handle refused documents, but it did not own the *query*. So the two search
paths each called the search primitive themselves and each passed the hits
through the handle afterwards. Both remembered. Both were correct. And both
wrote out their own fetch budget, because enforcing the deadline on read means
expired hits are fetched and then dropped — they spend the budget:

```python
# Memory.recall
hits = await self.engine.search(..., limit=limit * 2, ...)

# MongoStore.vector_search, independently
hits = await self.engine.search(..., limit=min(limit * 2, MAX_LIMIT), ...)
```

The same guess, twice, with a docstring in each admitting the worst case. The
worst case turned out to be worse than the docstring. Against real mongot:

```
40 expired rows ahead of 6 live ones, limit=5  ->  0 hits
```

Zero. Not "fewer". Six live documents, indexed, queryable, sitting on disk, and
the caller handed an empty list — indistinguishable from an empty scope. Which
is the exact failure shape this codebase blocks startup to avoid elsewhere: a
rebuilding vector index returns zero rows instead of raising, and that
ambiguity is considered serious enough to hold the process closed until the
index is ready. Here the same ambiguity had walked in through the front door.

The fix is that the handle owns the fetch budget: `saturate()` re-asks for
candidates, sizing each round from the refusal rate it just measured, until the
page is full or the candidates are genuinely exhausted. Refusal costs the
*refused document* its place, not the page.

**Third disguise: the primitive itself.** `engine.search` is a public method
that returns what the index ranked. On a collection that refuses things, that
is an unfiltered read sitting one import away from anybody who has not read its
docstring. Two read paths remembering to wrap it is a convention with two
instances, which is a convention about to fail a third time.

So the handle owns the query as well as the rule:

```python
await docs.search(vector, text="P0301", limit=5, filters={"tenant": t})
```

And this time the enforcement is not prose.
`tests/test_no_module_reaches_past_the_handle.py` walks the AST of every module
in the package and asserts none of them calls the primitive. AST rather than a
regex, because `.search(` appears in strings and comments all over the package —
including inside the docstring explaining the rule — and a guard that fires on
prose is a guard somebody deletes. Two files are exempt, each for a stated
reason: `admission.py`, which is where the wrapping lives, and `verify.py`,
which calls it deliberately to assert that the unwrapped version really does
leak.

A grep does not need anybody to be paying attention. That is the only property
that distinguishes it from the two conventions it replaced.

## What a guarantee owes its caller

A read that refuses returns a shorter list. A shorter list is ambiguous:
"nothing else matched" and "four more matched and were forgotten" are the same
three hits.

For a human that is a minor annoyance. For the caller this API actually has —
a model — it is a fabrication engine. Hand an LLM two results where there were
six and it will describe the two as what exists. Silence reads as absence.

So refusal is part of the answer:

```bash
curl -X POST .../search -d '{"query": "pension liability"}'
# -> "matches": [],
#    "admission": {"refused": [{"reason": "quarantined", "count": 3}],
#                  "starved": false}
```

Three facts matched and are being withheld. That is a reason to say so, or to
ask a human, and it is not a reason to answer as though the scope were empty.
The MCP `search` tool documents the field to the model for exactly that
purpose, because the tool description is the only documentation a model reads.

Nothing else in the retrieval stack reports this, and the reason is structural
rather than an oversight. A payload filter in a vector database does know it
excluded something — it could tell you if it were asked. A *deadline* that the
sweeper has not reached yet excluded nothing, because as far as the index is
concerned the row is live and correctly ranked. There is no reason to report,
because nothing decided anything. Knowing why a row is missing is a side
effect of refusing rather than deleting, which is the same reason `forget`
can report a count at all.

The `starved` flag next to it is narrower than it looks, and getting it wrong
taught me something. The first definition was "the page is short and something
was refused" — which fires on a perfectly healthy scope whose candidate list is
simply short. A short answer over an exhausted candidate list is the **whole
truth**, however many refusals it took to establish. Flagging those would train
whoever reads the field to ignore it, which costs more than not having the
field. So `starved` now means: the search gave up while candidates remained.
There is more, and this page could not reach it.

I did not work that out by thinking. The falsifier told me, on its first run,
about the feature I had shipped alongside it.

## What a guarantee owes an auditor

Refusal being *true* is not the same as refusal being *provable*, and those are
different products.

The counters were the honest version of getting this wrong. `/healthz` reports
what the read path has refused and why, which answers *how much has this
process refused since it started*. That is a dashboard. The question an auditor
asks is narrower and much harder:

> show me that this fact stopped being reachable at 14:02, and show me the
> record has not been edited since.

Counters have nothing to say to that. Neither does a log line, because the
party holding the log is the party being audited.

So every revocation is a link in an append-only hash chain —
`sha256(seq || prev || canonical(entry))` — where each link commits to its
predecessor. You cannot remove an entry, reorder two, or backdate one without
breaking every hash after it. Verification is arithmetic over public data:
`verify()` needs no secret and recomputes the whole chain, reporting the first
break and distinguishing three failures that mean different things — `gap` (an
entry was deleted), `broken` (the order changed, or one was inserted), `forged`
(an entry was edited in place).

**Then the interesting objection.** A hash chain is evidence against somebody
who cannot rewrite it. The operator of this database can: wipe the collection,
rebuild it without the awkward entry, and what remains verifies perfectly. A
chain held entirely by the auditee proves nothing about the auditee.

That is why the API shape matters more than the cryptography. Every `forget`
hands back a receipt:

```bash
curl -X POST .../forget -d '{"doc_ids": ["d1"], "reason": "credential leaked"}'
# -> "receipt": {"seq": 0, "hash": "9cd69b1b...", "prev": "0000..."}
```

Keep it. The caller who asked for the erasure walks away with a hash computed
*before any dispute existed*, so a later chain that does not contain it is
falsified by a record the auditee never held. The HMAC signature on the chain
head is the weaker half and is labelled as such — it is symmetric, so it
authenticates the head to a verifier who trusts the key holder and is not a
public proof. When no key is configured the response says `signed: false`
rather than implying an attestation nobody made.

And the endpoint states what it does **not** prove, in the payload rather than
only in the docs:

- not that any row was deleted — they deliberately stay on disk;
- not that individual *reads* were refused, which is enforced on every read and
  would cost a write per refused hit to record;
- not anything to a third party who does not hold the key, on its own.

A proof that overstates itself is worse than no proof, because somebody makes a
retention promise on the strength of it.

Two properties fall out of taking this seriously, and both are the opposite of
what the rest of the system does:

**The chain never expires.** Every other collection here inherits one deadline
from one document — that is the argument of the whole project. A proof
collected by the same TTL index as the thing it proves is a coincidence with a
short life. So this collection has no TTL index, and a test asserts the
*absence*.

**An entry never carries the document's text.** It is the one collection with no
deadline, so a quoted secret would outlive every mechanism built to forget it.
Ids and reasons only — also asserted, because that is the kind of field
somebody adds helpfully.

### Two bugs in the proof, and why I am telling you

The chain is the component whose entire value is being trustworthy. It arrived
with two bugs, both of the kind that would have been discovered by whoever was
relying on it.

**The first made every entry verify as forged.** BSON dates are milliseconds.
`now()` is microseconds. So an entry hashed on the way in and re-hashed on the
way out disagreed about its own timestamp, and the chain was 100% internally
consistent and 100% unverifiable — the worst of the available outcomes. The fix
is to truncate *before hashing and before storing*, so the bytes in the
database are the bytes that were hashed. Rounding at verify time would have
meant the stored value is not the value that was signed, and a verifier
reconstructing the hash would have to know to apply the same rounding: a rule
that has to be remembered, in the one place that cannot afford another one.

**The second made the hash depend on the auditor's timezone.** The
canonicaliser called `astimezone(tz=None)` on naive datetimes, which assumes
*local* time — so a chain written by a default (non-`tz_aware`) client would
hash differently in London and in New York. The docstring directly above it
claimed to rule out exactly this. The engine already had the correct rule —
naive means UTC, because that is what BSON stored — it simply was not the one
being used.

Same failure, twice, arriving once by codec and once by geography: **the value
you hashed and the value the database kept are not automatically the same
value.** Anything hashed through a database needs its round trip asserted field
by field, which is now a test.

A third, found during what was meant to be a cleanup pass: the receipt was
returned by stashing it on the handle for a second method to collect. Handles
are deduplicated per collection, so that was shared mutable state on an object
every request holds — two concurrent erasure requests could hand each caller
the *other's* hash. The receipt's entire value is that it belongs to a specific
caller. That bug was the same species as one I had fixed two hundred lines
above and written a comment about.

## Who is asking is part of the question

There were two access questions in the system, and between them they missed the
one that leaks.

`Guard` asks *may this caller read the scope*. `Admission` asks *may this
document reach a prompt*. Neither asks: *may this document reach **this**
caller's prompt*.

A scope-level lock is all-or-nothing, so the moment one document in a scope is
more sensitive than the rest, the available answers are "everyone gets
everything" and "split the scope" — and one retrieval boundary per sensitivity
level is four owners of one deadline all over again.

So sensitivity is a field on the document, clearance is a claim on the caller,
and they are compared per hit by the layer that already refuses things:

```python
docs = engine.model("docs", tenant="t").admitting(
    Deadline(), revoked(), Clearance(order=("public", "internal", "secret")))

await docs.for_caller({"clearance": "internal"}).search(vector, filters={"t": t})
# "secret" documents are not lower-ranked. They are not returned.
```

The access-control content of that feature is not the comparison. It is the
four ways it refuses:

| | and it is refused, because |
|---|---|
| the caller has no clearance claim | absence is the lowest level, not a pass |
| the document's label is not in `order` | an unrecognised classification is not a low one |
| the document has no label at all | untagged is not public — or every row predating the policy is world-readable |
| **no caller is bound at all** | *raises.* Both answers are wrong |

The first is the one that makes tests pass. A missing claim reading as
"unrestricted" is how datasets become world-readable on the single code path
nobody threaded the claim through. The third is the one that matters most in
practice: the documents written before anybody thought about sensitivity are
the population most likely to be sensitive.

The fourth came from writing the example rather than the tests. Unbound, the
query clause permits no level — so reads came back empty, and `revoke()`
matched zero rows and **reported success**, telling the caller a fact was
unreachable when it was not. A silent no-op on the forget path is the worst
failure available in this system. It raises now, because both available answers
are wrong: returning everything is the breach, and returning nothing looks
exactly like an empty scope.

`for_caller` returns a **new handle**, which is load-bearing rather than
stylistic. Handles are deduplicated per collection and every request holds the
same object, so a version that assigned to it would make the last request's
identity the current one, under concurrency, inside an access check. That bug
does not error and does not reproduce. There is a test interleaving twelve
requests specifically because it is the only place it would ever be caught.

And the structural consequence, which is the part I did not anticipate:
**`including_refused()` could not stay a blanket waiver.** It skipped every
rule, which is the naive reading and was the implementation. That is right for
forgetting reasons — auditing what was forgotten is the entire job of that
handle — and wrong the instant a rule encodes who may see what. An auditor is
entitled to read what was erased, and entitled to nothing above their own
clearance. One method waiving both makes "let me see the deleted rows" a
privilege escalation.

So the reasons in the module are not one kind of thing, and a rule now declares
which kind it is:

| rule | refuses because | waivable by the audit handle | reversible |
|---|---|---|---|
| `Deadline()` | the deadline passed, or cannot be read | yes | — |
| `revoked()` | somebody said forget this, now | yes | **no** |
| `quarantined()` | held back from models, deliberately still on disk | yes | yes |
| `EmbeddedWith(m)` | a different model produced this vector | yes | — |
| `Clearance(order=…)` | the caller is not cleared for this document | **no** | — |
| `Restricted()` | the document names who may see it, and it is not this caller | **no** | — |

Each of those columns is a one-word answer to a question the system did not
know it had, and the second one took longer to find.

Two of these reasons are operationally opposite and were one class. A
**revocation** is an instruction about the world — erase this — and the things
behind it do not get withdrawn. A **quarantine** is a hypothesis: hold this
while somebody looks. A hold that cannot be lifted is not an investigation,
it is a graveyard, and a graveyard is indistinguishable from a leak nobody
looked at.

Which means they want opposite treatment of the bytes, too. A revocation
stamps the erase deadline so the reaper collects the row. A quarantine must
not — the row is the evidence, and a hold that schedules its own subject for
deletion surfaces nothing until the evidence is gone.

That coupling lived in the caller of `revoke()`. So the next `Marked` reason
anybody added would have got whichever half its author happened to remember,
which is this project's own complaint about conventions, reappearing inside
the module written to remove them. It is one word on the rule now, and it
decides all three of: whether `lift()` works or raises, whether imposing it
erases, and what the chain records on the way back out.

And `revoke()` has no inverse, on purpose. Two reasons, either sufficient. The
row is already scheduled for the reaper, so an undo would work, and work, and
then silently stop working according to `ttlMonitorSleepSecs` — an API whose
window is a storage event, in the codebase written to argue that retrieval
guarantees must not depend on sweepers. And it would make the ledger *intact
and false*: the chain attests a fact stopped being reachable at 14:02, the
fact is reachable, and `verify()` still passes. Nothing about a hash chain
detects an event that was never written to it. Re-admitting erased information
is a new document with new provenance — a different operation, with a
different audit story.

## Ship the experiment that would disprove you

Every retrieval system's README makes claims. None of them hands you the thing
that would falsify the claims, and that asymmetry is worst precisely here:
this failure is **silent by construction**. A forgotten document answering a
query looks like a working system. A property whose violation is invisible
cannot be checked by looking at it. It has to be attacked.

```bash
voyd verify --uri "$MONGO_URI"    # exit 0 = the guarantee held here
```

It parks the TTL monitor so "still on disk" is a fact rather than a race,
plants documents that must not be reachable, asks for them through every read
path that carries the guarantee, and exits non-zero if any of them answers —
against your indexes, your MongoDB version, and whatever tier your deployment
actually degraded to.

```
  mongodb 8.2.11  tier=hybrid  search=True

  [ok  ] deadline: an expired document is unreachable while its row is on disk
         the row is still on disk (TTL monitor parked), so every refusal below
         is the read path and not the sweeper
  [ok  ] revocation: a revoked fact is refused on the next read, and its row stays
  [ok  ] starvation: a page of refusals is refilled, not truncated
         filled 5 of 5 after examining 46 candidates, refusing 40
  [ok  ] clearance: a document above the caller's clearance is absent, not ranked
  [ok  ] shredding: destroying a scope's key makes its ciphertext unreadable
         everywhere, not just here
  [ok  ] inheritance: forgetting a fact forgets what was written out of it
         the source, its summary and the summary's summary all went, in one
         query, at any depth
  [ok  ] reversal: a hold can be lifted, an erasure cannot, and both reach the chain
         held, unreachable, and no deadline on the evidence
         an erasure refused to be lifted, as it must
         a hold can escalate to an erasure; reasons stack
  [ok  ] chain: the refusal ledger recomputes intact
```

Six of the eight checks are worth reading closely for what they refuse to
accept as a pass:

- **revocation** asserts the row is *still there* afterwards. A version that
  deleted on `forget` would pass any check asking only "is it unreachable" and
  would break the actual promise — you cannot investigate what you erased.
- **clearance** compares *both enforcement points against each other* per
  level, because the failure that matters is them disagreeing. The
  `$vectorSearch` path only ever uses one of the two.
- **reversal** attacks the asymmetry from both sides, because a deployment
  that has it backwards looks completely healthy. The 3am "support needs to
  un-forget a document" patch passes every other check in the suite. So does
  quarantine implemented as revoke-with-a-different-field-name — right reads,
  right mark, right chain, and the evidence gone in a minute.
- **inheritance** is the one that found a hole rather than guarding one. An
  agent summarises a document and writes the summary back; the erasure
  request arrives; `revoke()` honours it against the source and the summary
  keeps scoring well forever. The erasure is satisfied, the information is
  not gone, and every receipt says the system worked. It checks both halves,
  because either alone is decoration: the mark must travel down the
  derivation edge to work already written, *and* a new derivation from an
  erased parent must be refused — otherwise you revoke at 14:02, summarise
  at 14:03, and the contamination is clean.
- **chain** refuses to accept `intact` alone, because an empty chain verifies
  vacuously. A deployment recording nothing at all would have passed.
- **deadline** reports that the unwrapped primitive *does* still leak. A
  falsified expectation is worth knowing too: if that stopped being true, the
  read-path check would have quietly become a tautology and would keep passing
  after somebody removed the thing it tests.

CI runs it on every commit. And `tests/test_the_falsifier_can_fail.py` breaks
the guarantee thirteen different ways to prove each check bites — because a checker
that cannot fail is worse than no checker. It converts an unknown into a false
assurance, and then somebody makes a promise on it.

The best argument for building this is the first thing it did: it flagged a
healthy deployment, because my definition of `starved` was wrong. The tool
found the feature it shipped with.

## Why MongoDB, specifically — and what that does not mean

The honest version of this section is shorter than the marketing version.

**One document owns the deadline.** One `expire_at`, inherited by every row in
the scope, collected by one TTL index. That is the entire architectural claim,
and it is why this is a database rather than a wrapper over four services. The
four-owners table has no MongoDB row because there is only one owner.

**The embedding leaves with the document**, because they were never two things.
A vector is a field. There is no second store to keep in step, which is a
stronger property than keeping it in step well.

**Hybrid ranking happens in the database.** `$rankFusion` (8.1+) fuses a
`$vectorSearch` leg and a `$search` leg in one round trip, with no
hand-normalised scores. That matters because semantic search is bad at
identifiers, and the things agents put in a scope are full of them — `P0301`
has no useful embedding.

**The tenant filter is pushed into the index**, including inside both
`$rankFusion` legs, where a miss leaks every tenant's data.

**A unique compound index replaces a lock service** for keeping the audit chain
linear. Appending is inherently serial — an entry cannot exist before its
predecessor's hash — so concurrent writers cannot cooperate, only retry. Unique
`(tenant, seq)` makes the loser re-read the head and re-link instead of
silently overwriting. A chain that can fork under load is not a chain.

No Redis. No Kafka. No Elasticsearch. No vector database. No object storage.
One connection string.

**And now the part that keeps the rest honest.** "Just MongoDB" is doing work
in that sentence that it has not earned. `$vectorSearch` and `$search` are
served by **mongot**, a separate process. It is a process, not a product —
Atlas Local runs it next to `mongod` in one container, with no Atlas account —
but an essay that attacks silent degradation does not get to smuggle it past
you. When mongot is there, fusion is one round trip and the boundary is
enforced where ranking happens. When it is not, the same documents still
expire, still refuse, still claim jobs, and search says so out loud:

| Tier | Requires | Used for |
|---|---|---|
| `hybrid` | MongoDB 8.1+ with Atlas Search | `$rankFusion` over both legs |
| `vector` | Atlas Search | `$vectorSearch` only |
| `cosine` | anything | exact in-process fallback, capped |

Degrading is loud. Every fallback is logged at ERROR, counted, and on
`/healthz`. The cosine cap is not asserted, it is derived:

| rows | hybrid p50 | vector p50 | cosine p50 |
|---|---|---|---|
| 100 | 2.1 ms | 1.5 ms | 6.4 ms |
| 1,000 | 1.7 ms | 1.2 ms | 66.5 ms |
| 5,000 | 5.0 ms | 2.3 ms | 346.4 ms |
| 10,000 | 3.9 ms | 2.8 ms | 699.5 ms |

The indexed tiers are flat in collection size; cosine is over a hundred times
its 100-row cost by 10,000 rows. So the cap is a decision about a ceiling you can state: at
`COSINE_CAP` a degraded query costs about **0.7s p50**. Survivable as a
fallback, indefensible as a steady state — which is why it is logged at ERROR
rather than quietly absorbed.

Capability is probed, never guessed from the URI. `"mongodb.net" in uri` once
called Atlas Local "not Atlas", so `$vectorSearch` never ran locally, for
months, silently. That is the same failure as everything else in this essay: a
wrong answer that looks like a working system.

### The two things that cost the most to learn

**A search index that is missing or still building returns zero rows instead of
raising.** It is indistinguishable from "nothing matched". So startup blocks
until the indexes are queryable, and queries refuse the Atlas path until they
are. Without that, a cold start silently reports an empty database. This is
also why the starvation bug was serious rather than cosmetic: it produced the
same ambiguity the startup gate exists to prevent.

**An embedding is not a vector. It is a (vector, model) pair.** A 512-wide
vector in a 1024 index fails on width. A vector from a *different model of the
same width* passes every check — and a whole generation of one vendor's models
is 1024 dimensions, so that is the normal case for anyone who upgrades.
Measured against the real API, same text, both 1024-wide:

| | cosine |
|---|---|
| identical text, old model vs new | **−0.053** |
| unrelated text, both on the new model | **+0.301** |

A model swap does not degrade ranking, it **inverts** it: unrelated text
outranks the document you were looking for, by five times. Nothing errors,
`indexed: true` is recorded, and `describe()` reports a healthy scope. So the
model is written in the same `$set` as the vector and cleared with it, and a
vector whose model is unrecorded is refused rather than ranked.

Which collapses the migration, too. Change the model and every row is refused,
so nothing is searchable, so the embed worker re-embeds them and the pending
count is the progress bar. **A model change is a document that needs
embedding.** There is no migration subsystem because there is nothing left for
one to do.

## What it costs, stated plainly

Refusal is enforced on read, which is not free.

Deadlines are the one filter deliberately *not* pushed into the vector index.
Both legs can express it — `living()` works verbatim as a `$vectorSearch`
filter, and the lexical leg says the same thing with `range` + `equals: null` +
`mustNot: exists` — so this is a decision, not an omission. What rules it out
is that a `vectorSearch` definition **cannot be updated in place**, so pushing
it down would be a drop-and-rebuild on every existing deployment, and a
rebuilding index returns zero rows rather than erroring. Trading a correct
filter for a silently empty index is not a trade.

So: expired hits are fetched and then dropped, and they spend part of the fetch
budget. The handle refills rather than guessing, and reports `examined` per
query so the over-fetch factor is a number rather than a belief. In the
pathological case above — 40 expired rows ahead of 6 live ones — filling a page
of 5 examined 46 candidates. The per-hit CPU cost of the admission check itself
is still unmeasured, and I would rather say that than estimate it.

The read path is also the only layer that works on the cosine fallback, where
there is no index to push anything into. A guarantee that holds on two of three
tiers is not one.

## What is not done

Four things, in the order I would do them, and the first is the one that
matters.

**Refusal has a perimeter and does not know where it is.** Refusal governs
this read path. It does not govern the copies made downstream of it — an
embedding cache, a rerank cache, a provider-side prompt cache, a vector
index in another service populated from here, a message a bot posted last
week. Revoke a fact and every one of those keeps serving it.

Inherited refusal solved exactly this shape one layer in: a summary written
back into the collection now goes with its source. The same argument applies
one layer *out*, where I have not made it. Nobody's retrieval stack is one
database, so this is the question a customer's architecture diagram asks
immediately, and right now the honest answer is that the guarantee stops at
the edge of the process.

The shape I would try: downstream holders register as sinks, and a
revocation must be *acknowledged* — a sink that has not acked makes the fact
refused everywhere until it does, rather than the revocation optimistically
reporting success. The hard part is that an unreachable sink must not become
an outage that blocks erasure requests, and must not become a checkbox
either. I do not have a clean answer to that yet, which is why this is in
this section rather than in the repository.

**Rules as data.** A rule is still a Python object, so a per-tenant policy is a
release. The protocol is ready for it — a rule already declares whether it
needs the caller, whether it can be waived, and whether it can be taken back,
and carries its own query fragment — but the policy itself should live on the
scope document, versioned with it, editable by the people who get audited.

**The admission overhead as a published number.** p50/p99 per hit. The obvious
reviewer objection is "so you pay on every read, forever," and the answer
should be a figure.

**The two small sharp ones.** Passcode rate limiting is in-process, therefore
per-replica — the honest trade for not needing Redis, and the first thing to
fix on more than one process. CORS is wildcard-open on `/v1`, which is the whole
public surface.

## "And your backups?"

That is the question four minutes into any conversation with a security
reviewer, and refusal has nothing to say to it. Refusal is a property of
*this application's read path*, and a restored snapshot does not run this
application's read path. "The row is deliberately still on disk" is proof to
an engineer and a finding to a reviewer, and the reviewer is right.

So: a key per scope, the sensitive field as ciphertext at rest, and
destroying the key makes every copy unreadable at once — the row, the
replica, the snapshot, the export somebody took in March — without any of
them being visited. That is the one operation in this package where deleting
is the right verb, and it is worth being precise about why, since the rest of
the argument says the opposite. Deleting a *document* is a storage event:
eventual, local, unprovable. Deleting a *key* is a storage event whose effect
is total.

The enabling detail is smaller than it sounds. Under MongoDB's automatic
encryption the schema's `keyId` can be a **JSON pointer** — `/key_scope` —
rather than a literal key id, so the driver resolves a different key per
document. A literal id binds one key to the whole collection, and then one
subject's erasure request crypto-shreds every other tenant. That is not a
tradeoff, it is a different product.

Two more decisions that had easier wrong answers. The key vault is an
ordinary MongoDB collection, so the key carries the same `expire_at` its
documents carry and dies by the same TTL index — one owner, which is this
essay's first claim applied to the mechanism that enforces its second. And
encryption is automatic on *write* but explicit on *read*, because the two
mistakes are not the same size: forgetting to encrypt is silent, permanent
and already in a backup, while forgetting to decrypt hands you an obviously
wrong `Binary`. Automatic decryption also raises for the entire batch when
one key is missing — so a single crypto-erased document would turn a page of
fifty into a 500, which is the "fewer rows, or an error" shape this whole
system refuses. A destroyed key is a refusal with a name, `unrecoverable`,
sitting beside the deadline and the revocation.

### And it is eventually consistent too

This is the part everybody overstates, including me until I measured it.
libmongocrypt caches data keys. A client that decrypted a document before the
shred keeps decrypting it afterwards — **~60s in one shape, past 120s in
another**. The turnover is not a contract and it is not a constant.

Which turns out to be the best argument for the whole design, because the
three mechanisms cover each other's gaps exactly:

| | when | where | result |
|---|---|---|---|
| refusal | immediate | this read path only | unreachable *now* |
| crypto erasure | eventual | every copy, everywhere | unreadable *soon* |
| the TTL reaper | ~60s | this deployment only | gone *eventually* |

The key cache is a window in which the ciphertext is still readable — and
refusal already refused the document, on the first read after the request,
with no window at all. Refusal binds only this application — and the key is
gone from all of them. `examples/shred.py` runs all three in one go, and the
reaper takes the row while the program is still waiting on the key cache,
which was not staged.

### The tradeoff nobody tells you about

MongoDB has two ways to do this and they are not interchangeable. Queryable
Encryption indexes the ciphertext, so you can run an equality match against
a field you cannot read. CSFLE cannot — but CSFLE lets `keyId` be a **JSON
pointer** into the document, so the driver resolves a different key per row.

That one difference decides everything, and I checked it rather than
recalling it: QE *rejects* a pointer `keyId` — `BSON field
'create.encryptedFields.fields.keyId' is the wrong type 'string'`. A QE key
is bound per field per collection at creation time. Destroy it and you erase
that field for every subject in the collection.

So it is a straight trade. Per-subject erasure, or a searchable ciphertext.
Pick the one your regulator is asking about, and if the answer is "both",
what you actually need is a collection per subject — a sharding decision
wearing an encryption costume. The library ships both modes and prints which
granularity is in force, because this is the kind of thing a team decides
once and misremembers for two years.

### And on custody, which is where the whole claim lives

A crypto claim that is vague about who holds the master key is marketing. My
first version of this hardcoded `"local"` in the call that creates a data
key — which means an AWS-configured deployment would have wrapped its data
keys with a secret generated in the process that just started, and nothing
would have raised. Not a crash. A belief.

So custody is typed and it is a ladder: `Ephemeral` (demo; nothing survives
a restart, and it warns) → `LocalFile` (durable; custody is a file
permission) → `Aws`/`Azure`/`Gcp`/`Kmip` (destroying the CMK is somebody
else's audited operation). `durable` and `audited` are attributes rather
than prose, so `voyd verify` *prints* the custody story instead of leaving a
reader to infer it — and on the weak rungs it says, in the same output as
the passing check, that "the key was destroyed" is still this deployment's
own word.

The last piece is rotation, which is the half that makes destruction
credible over time: a key that cannot be re-wrapped is a key that gets
copied instead, and a copied key cannot be destroyed. `rewrap_many_data_key`
changes the wrapping without touching the data key, so a CMK rotation costs
zero documents their readability — which is why rotating a master key is
cheap and re-encrypting a collection is not.

## Is this just a MongoDB argument?

A fair question, and the answer has to be executable or it is a press
release. `drift/refusal_on_postgres.py` runs the whole thesis on pgvector
with no MongoDB in the file.

The interesting act is the third one. Putting the deadline in the `WHERE`
clause is the easy half and everybody already knows it — and it is a
*convention*, which holds until somebody writes the second query. So the
table's `SELECT` is revoked and only a view is granted. The naive read, the
one written by someone who never heard of the deadline, does not leak; it
raises `permission denied for table facts`. That is Postgres's version of
"there is no unfiltered read on the handle": different mechanism, identical
property, and the failure mode is inverted the same way.

It also says what is **harder** there, because an argument that lists only
its wins is marketing. Postgres has no TTL. There is no handing the deadline
to the storage engine, so the moment you need rows actually gone it has two
owners again and keeping them agreeing is your problem. That half of the
claim really is stronger on MongoDB — and that is a property of the engine,
not of the argument. Conflating the two is exactly what makes this sound
like advocacy.

What carries over is all of it: deletion is a storage event and refusal is a
retrieval guarantee; a rule you have to remember is not enforced; a refusal
that does not travel to what was made out of the fact is defeated by a
summary. Refusal is missing from retrieval everywhere. This is one
implementation, on the engine where the deadline can have a single owner.

## The claim, restated without the gloss

Not "MongoDB is faster." Not "vector databases are bad." Not "we solved
deletion."

**Deletion is a storage event. Refusal is a retrieval guarantee. They are not
the same operation, and retrieval needs the second one.**

Everything else here is consequence. One document owns the deadline, so
nothing drifts. The read path refuses, so the minute before the sweeper is not
a minute of serving forgotten facts. The handle owns the query, so the rule
cannot be forgotten by the next author. The answer reports what it refused, so
a model cannot mistake withheld for absent. The revocation is a link in a
chain, and you keep the receipt, so the record is evidence rather than
testimony. And the caller's claims are part of the question, so one scope can
hold documents of different sensitivity without becoming four boundaries. And
a reason declares whether it can be taken back, so a hold is an investigation
rather than a graveyard, and an erasure stays an erasure.

480 tests, six skipped. A falsifier that has failed on purpose thirteen ways and
caught one real bug on its first run. Three bugs found in the proof, one found
by writing an example, and three silent no-ops found by asking whether a
refusal should be undoable. Every number in this essay is in `bench/` or
`drift/` and re-runnable on a laptop.

The row is still on disk. That is not the part that went wrong.

```bash
docker compose up -d
uv run python examples/forget.py     # ~10 seconds, no API key, no vendor
voyd verify                          # then point it at your own deployment
```
