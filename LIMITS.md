# Limits

What this cannot do, what it costs, and what will surprise you. Present
tense throughout: how any of it came to be is in the git history, which is
where that belongs.

---

## 1. The one that actually matters

**Nobody has used this but its author.** Zero external users, zero pilots,
every claim verified by the person who wrote it.

That is not a coverage problem and more tests do not fix it. The suite is
good at holding claims somebody thought to state. It has never been the
thing that caught a problem a *user* hit, because there have been no
users — and the defects that do get found are not found by it going red.
They come from running something, or from somebody asking why a paragraph
says what it says.

A recent day produced roughly a dozen, all in code already written,
tested and documented. The three worth knowing about, because they are the
shape to expect:

- a token `budget()` any client could switch off by asking for a smaller
  `batchSize`, since the running total was per batch and the client picks
  the batch size;
- a `SIGTERM` that never returned while a single connection was open, so
  every rolling deploy waited out its grace period and took the `SIGKILL`
  that draining exists to avoid;
- an embedded-subject redaction that was correct in every test and a
  complete no-op in production, because one `isinstance` said `dict` where
  the wire's lazy codec hands you a `Mapping`.

The pattern is the same each time: **an optimisation that assumed the
common case, and a test that built its input by hand.** Expect more of
them in the corners nobody has exercised.

One team, two weeks, their own corpus is worth more than anything else
that could be built next, and `examples/shadow.py` is the cheapest way to
get there: it counts how many documents an existing read path serves that
the database has already marked as gone, changing nothing while it does.
**If that number is zero across the first few repositories it is pointed
at, stop.** Not reposition — stop. It would mean the window this project
closes is not one teams fall into.

## 2. What refusal structurally cannot do

**It binds a read, not a value.** A document refused on the way out has
not been erased. If it reached a prompt yesterday, it reached a prompt.
Refusal makes the next read honest; it does not reach backwards.

**It binds this deployment, not your data.** A restored snapshot does not
run this boundary. That is what `sealed()` and `--key-vault` are for (§5),
and why the two mechanisms are worth having together rather than choosing.

**Admission is a veto, not a constructor.** It can refuse a document for
what is already on the page. It cannot *require* that something be on it.
"Must include a dissenting source" is a retrieval objective and belongs to
the ranker; a ceiling is an admission rule and belongs here.

**A rule with no query half is invisible to static analysis.** A
`budget()` cannot be expressed as a filter, so no amount of reading a
query tells you whether it is in force. The per-document check is the
guarantee and the boundary is the only place it is observable.

**Partial enforcement is worse than none.** A guarantee that holds for
three verbs out of four is the hole this package is named after, which is
why `drop`, `renameCollection`, `$out` and `$merge` are refused outright
rather than forwarded with a warning.

## 3. The wire boundary

Correct before it is operable. What is closed, then what is not.

### Closed

Aggregation stages that write elsewhere (`$out`, `$merge`) and the verbs
no rewrite can cover (`drop`, `renameCollection`) are refused with a
reason. TLS termination for clients (`--tls-cert`; without one the
listener binds loopback, because a plaintext boundary on a network would
carry in the clear everything it just refused). TLS and SRV upstream, so
it can front Atlas. Primary discovery, and failover read off the server's
own `NotWritablePrimary` rather than polled. Messages capped at MongoDB's
own `maxMessageSizeBytes`, because a length field is attacker-controlled
input. Compression negotiated away at the handshake, since a boundary that
cannot read the traffic cannot enforce anything.

**A cumulative rule spans the read, not the batch.** `budget()` and
`distinct()` judge a document against the running total so far, and a
cursor delivers one logical read in as many batches as the client asks
for. `Budgets` holds one tab per cursor id, per connection, dropped when
the server reports `id: 0` and when the client sends `killCursors`. A
policy with no cumulative rule allocates nothing.

**A blinding projection cannot turn the boundary off.** `find({}, {"text":
1})` is the most ordinary query anybody writes and it was enough: the
documents come back real with their marks projected away, and absent is
not refused. The refusal is pushed into the query instead, where a
projection cannot reach it — except for a subject array, where no query
can remove an element, so that read is refused outright (§6).

**A reduction cannot launder a refused fact.** `distinct`, `count` and any
`$group` hide the documents they summarise, so the rule goes into the
query, and where the push-down would be narrower than the guarantee the
read is refused instead.

**Deletes become revocations, on both verbs.** `delete` and
`findOneAndDelete` are separate wire commands and covering one is partial
enforcement. Both are rewritten under `on_delete="revoke"`.

### Open

**A cumulative rule's tab lives in one worker.** With `--workers N` a
client is served by one process, so a budget is correct per connection.
Two connections from the same application are two reads and two budgets,
which is the right answer for a prompt and the wrong one if you meant a
quota.

**A worker that is alive but wedged is a metrics problem.** The parent
replaces workers that *die*; it cannot detect one sitting in a syscall.
`voyd_worker_flush_age_seconds{worker="N"}` is the signal — one slot
climbing while the others stay flat. **Consider:** nothing acts on it. A
timeout that killed a worker mid-request would turn a slow upstream into
dropped connections.

**`--workers` orphans on `SIGKILL`.** Workers leave the parent's process
group so a terminal's `SIGINT` cannot reach a worker twice and kill it
mid-drain. The cost is the other direction: `kill -9` on the parent leaves
children accepting connections with nobody to drain them. **Consider:** a
supervisor that reaps by process group will not find them.

**`update` is not intercepted.** An `update` that overwrites a fact is a
write the policy has no opinion about. `revocable()` describes making a
fact unreachable, not editing it.

**A `$lookup` *from* an unguarded collection into a guarded one** is not
judged. The guarded-side case is closed; this direction would mean reading
the `from` of every pipeline on every collection.

**One upstream per client, not pooled.** Deliberate: a MongoDB connection
carries authentication, sessions, cursors and transactions, so sharing one
would hand a cursor to whoever asked second. The ceiling is upstream
sockets.

### What the read path costs

`enforce` reads a reply lazily (`RawBSONDocument`) and asks the cheap
questions first — is there a cursor, what collection, is it declared — so
a reply nobody guards is forwarded after four field reads. On a
100-document batch carrying 1536-dimension embeddings, 2.06MB on the wire:

| path | per batch |
|---|---|
| unguarded collection | 0.11ms |
| guarded, 10% refused | 3.93ms |
| guarded, nothing refused | 3.23ms |

End to end through a socket: 45,169 docs/s at a 10% refusal rate, 47,650
with nothing refused. It pays about 10% on the cheap case to buy 1.6x on
the case that does the work, which is the right trade for a boundary whose
job is refusing. The remaining cost is re-encoding a batch that changed,
which decoding lazily does not help.

## 4. Coverage

589 tests, ~9,900 lines, against 14,000 lines of `voyd/` — 7,300 of policy
and admission, 6,800 of boundary under `voyd/wire/`. Well-targeted rather
than thorough: coverage is by *claim*, which is the right axis, and it is
not line coverage.

**119 lines in one file are named by no test**, and it is defensible:
`composition.py` declares protocols a type checker reads and the runtime
never imports.

**Every claim is attached to a file, and the mapping is checked both
ways.** [CLAIMS.md](CLAIMS.md) names each guarantee and the test that would
go red;
`tests/test_every_claim_names_its_evidence.py` refuses a claim with no
test, a test no claim points at, and a citation it cannot parse. It also
checks **which door** each cited test drives: a claim about a connection
string held up by a test that calls a handle directly is a claim a reader
cannot check, so a cited file must drive the boundary or touch no database
at all, or sit on a short list with its reason written down.

**There is a no-database subset and it is smaller than the marker
suggests.** `needs_mongo` is applied per file and only to mixed ones, so
`-m "not needs_mongo"` over the whole suite still selects plenty that
starts a proxy. The honest set is the one CI names file by file: **310
tests in 20 seconds**, no `services:`, nothing listening. That step is the
evidence for the property the proxy rests on — the per-document check is
pure — so it names its files explicitly rather than trusting a label.

**What attachment is worth, narrowly.** It closes the gap between a README
sentence and a file that runs in CI. It does not know whether a test is any
good. One on this map had a docstring about a page of fifty and asserted a
page of one, and passed under sabotage. Attachment is a floor.

## 5. What `--key-vault` costs

Sealing is the half refusal cannot do: a restored snapshot does not run
this read path, and destroying a key binds every copy at once.

It costs the boundary three properties, and they are the reason it is
opt-in:

- **It holds KMS credentials.** With `--key-vault` this process is a
  custody holder. `--kms` names the rung, and unset is `Ephemeral`, which
  says so rather than letting a demo imply otherwise.
- **It holds a connection of its own** to the key vault.
- **A sealed read decrypts before it refuses**, so it is no longer 2.3µs
  per document, and a document refused by a deadline has still been
  decrypted by the time the deadline sees it. Wasted work, not a leak — it
  never leaves the process.

**Erasure is sequenced, and the order is the point.** libmongocrypt caches
data keys, so destroying a key leaves a reader decrypting for about a
minute — the same shape as the TTL window this project exists to complain
about. So the documents are revoked *first*, which makes them unreachable
on the very next read, and the key dies second. Unreachable now,
unreadable everywhere shortly.

**A write it cannot seal is refused, never forwarded.** No tenant to scope
a key to, a pipeline update that would assign a sealed field server-side,
`$inc` on ciphertext. There is no safe fallback: an error is loud,
harmless and fixable, and a forwarded plaintext row is none of those and
is already in the backup.

**Open:** `--key-vault` does not install a `binData` validator on the
collection, so a writer connecting straight to the cluster can still store
plaintext. `--verify` reports it. **Consider:** sealing protects writes
*through* the boundary; it does not make the collection refuse plaintext
from elsewhere.

**Queryable Encryption is the trade not taken.** QE rejects a pointer
`keyId`, so one key covers one field across the whole collection and
shredding it erases that field for everybody rather than for one subject.
Per-subject erasure is the entire point here.

## 6. Operational notes that will surprise somebody

**A readiness probe on the listen port lies.** Pointed at a deployment
that is unreachable, the boundary starts, accepts connections and fails
every read. `/health` on the metrics port asks whether the *upstream* is
reachable and answers 503 with the address it could not reach;
`voyd-wire-health` is the same question as a command, for an image with no
`curl`. **Consider:** readiness, not liveness. A boundary whose database
is down should leave rotation, not restart.

**The container is a sidecar, and that is the strongest shape.** Without
`--tls-cert` the listener binds loopback, so sharing a network namespace
with the application — a Kubernetes pod, `--network container:<app>` — is
what works: the application reaches the boundary on `localhost`, nothing
else on the network reaches it, and there is no route around it.
**Consider:** publishing 27099 with `-p` appears to work on Docker
Desktop, whose forwarder runs inside the namespace, and does not on Linux,
whose DNAT targets the container's own address. Cross a network with
`--tls-cert`.

**A vector index cannot serve a document that has been deleted.**
`$vectorSearch` scores candidates in `mongot` and materialises them from
the *collection*, so there is nothing to return for a row that is not
there. Measured by `examples/drift.py` against a real `mongot`: **5ms** to
stop being ranked after a delete, against ~1,000ms for the index's own
poll interval. What *is* real is one poll interval of staleness — change a
document's vector and for ~1s the index ranks by the vector the document
no longer has.

**And the window that matters is neither.** A row inserted already past
its deadline was **ranked for 40.8s with the row on disk the entire
time**. Search was not stale; it correctly returned a document that
existed. A faster index does not close that and a faster sweeper only
narrows it, on somebody else's schedule. Only a verdict on the read closes
it.

**Embedded subjects are judged element by element.** `subjects(key=...)`
declares an array whose elements are subjects in their own right, and a
refused element is removed from a document that is still served, because
a book is not erased by one retracted chapter. `key` is required in a
policy file and optional in the engine: an anonymous subject is refusable
on read and can never be *addressed*, and an erasure request names a
thing, so an element carrying no key is refused as `unnamed`. **Consider:**
a projection that hides an element's marks is refused rather than
rewritten — no query removes an array element, so the push-down that
rescues every other blinded projection is not equivalent here.

**A client talking to the boundary carries its own credentials.** It
forwards SCRAM and authenticates for nobody, so against a deployment that
requires auth an unauthenticated client gets `Unauthorized` *through* the
proxy. Correct, and it looks like a proxy bug the first time.

**A pinned `deleteOne` may not be `multi: true`.** The driver marks it
retryable and the server rejects the combination with code 72. It is why
the lineage cascade takes `multi` from the clause rather than from the
resolved set.

**A search index is not free and `mongot` is shared.** Abandoned test
databases carrying search indexes starve new index builds and make a
healthy test fail for an unrelated reason. Killing a pytest run leaks
them; the sweeper only runs at start-up:

```
docker exec voyd-mongo mongosh --quiet --eval 'const d=db.adminCommand({listDatabases:1,nameOnly:true}).databases.map(x=>x.name).filter(n=>n.startsWith("voyd_test")); for(const n of d) db.getSiblingDB(n).dropDatabase(); print(d.length)'
```

**Counts in prose go stale on every commit.** §4 here and `README.md` both
carry them. Re-measure rather than adjust:

```
uv run --no-sync pytest -q -m "" --collect-only tests/ | tail -1
grep -oE "tests/test_[a-z_]+\.py" CLAIMS.md | sort -u | wc -l
find voyd -name '*.py' | xargs wc -l | tail -1
```

**Do not report a caller count. Report the callers.** A count with no list
is an assertion about code nobody read, and it has cost twice.

## 6b. Who is asking, and what it still costs

`restricted_to()` and `clearance()` decide by who is calling, and the
question is not how to pass claims to the boundary — it is why the
boundary should believe any. A rule that accepted `{"clearance":
"secret"}` because a client sent it would be an authorisation system whose
only input is the attacker's.

So the boundary asks the deployment. `connectionStatus`, on the client's
own connection, reports the roles the server granted — an answer no client
can forge without forging the authentication. Asked once per connection,
lazily, and only for a collection whose rules ask.

**The four claims it can supply are `user`, `db`, `groups` and `roles`.** A
rule wanting anything else is announced at boot naming the collection and
the claim, because the alternative is correct and useless: no claim is the
lowest clearance, so every read of that collection is refused, and it
presents as "VOYD broke my reads" with nothing connecting it to a line in
a policy file.

**An ordered clearance needs a mapping, and that is the design rather than
a workaround.** A role says who somebody *is*, not how far up a ladder
they stand — nothing in `db.createRole({role: "analyst"})` carries a
level. So the policy file says which rung each role is on, the rule reads
`roles`, and a caller holding several gets the highest. A role the policy
never mapped clears nothing, because an unmapped role is an unanswered
question. A role mapped to a level outside the ladder is a **load** error:
it would otherwise clear its holders for nothing, silently, and the
collection would read as empty for exactly the people it was written for.

**Open:** a caller-aware rule costs one round trip per connection, and the
identity is the connection's. An application pooling one credential for
many end users gets one identity, which is the right answer for a service
account and the wrong one if you meant per-user clearance.

### Lineage

**A revocation reaches what was derived from the fact.** A collection
declaring `lineage_field` has its descendants marked first and the source
second. A crash between the two leaves the source reachable and the
derivations gone — a visible half-erasure the caller fixes by re-running
an idempotent delete. The reverse order leaves the source refused and the
summary of it still answering prompts, with nothing saying so.

The ids are resolved once and both halves pinned to them, because
`deleteOne` asks the server to pick one of the matches and does not say
which — a cascade computed from the filter and a revocation computed from
the filter can land on different rows.

**The write side carries it.** The cascade is one `$in` at any depth only
because each document's ancestry is transitively closed, so an insert
naming a parent has its ancestry closed, inherits the earliest deadline
among its parents, and is refused outright if a named parent is missing,
out of scope, or already refused.

**What it costs**, measured by `voyd-bench --cascade` against the same
policy with the declaration removed, four parents and forty derived
documents:

| | without | with | delta |
|---|---|---|---|
| insert naming a parent | 1,118µs | 1,380µs | **+262µs** |
| one erasure request | 2.53ms | 4.03ms | **+1.49ms** |

The erasure figure is flat in the size of the subtree — resolving the ids
and marking the descendants is two commands whatever they matched — so per
document reached it was +37µs and falls as the subtree grows. **The insert
figure is the one to watch:** it is on an ordinary write path, paid by
every application that records derivation.

**Open:** the cascade can reach a descendant the caller could not have
read. Caller-aware rules decide per document and no query expresses them,
so they are not rebuilt when the edge is walked. The tenant *is* carried
across — a cascade leaving the caller's namespace would be a cross-tenant
write dressed up as an erasure — so what remains is a clearance-gated
descendant marked by a caller who could not see it. In the direction of
refusing more.

## 7. Decisions waiting on evidence

Frozen because building them before somebody wants them adds surface that
has to be kept honest forever.

| | what it would take | what would unfreeze it |
|---|---|---|
| **`$lookup` into a guarded collection** | reading the `from` of every pipeline on every collection | somebody joins to a guarded collection and is surprised |
| **Revocation that propagates outward** | a sync protocol | who else holds a copy is auditable and never enforceable — true without a protocol, and false with one |
| **Reverse-indexed receipts** | a storage decision | *"which answers were built on this fact?"* is already a query for anything written back; what is missing is the artefact that **left** |
| **A second engine** | doubles the surface | a user who is not on MongoDB |
| **Intercepting `update`** | a verb the policy has no opinion about | somebody overwrites a fact and expects the boundary to notice |

## 8. Deliberately not doing

- **A delete verb of our own.** A delete hands the caller a cleanup
  obligation, and an agent that has to remember to clean up is the failure
  this exists to remove.
- **An undo for `revoke()`.** The row is already scheduled for the reaper,
  so the undo would work until `ttlMonitorSleepSecs` decided otherwise —
  an API whose window is a storage event, in a codebase written to argue
  that guarantees must not depend on sweepers. Re-admitting erased
  information is a new document with new provenance.
- **Pushing the deadline into the vector index.** A `vectorSearch`
  definition cannot be updated in place, so it is a drop-and-rebuild on
  every deployment, and a rebuilding index returns zero rows rather than
  erroring.
- **Ledgering reads.** A write per refused hit, for a property the read
  path enforces anyway.
- **Reading from a secondary.** Ranking reads on replicas and re-reading
  their marks from the primary works, and it needs a second request loop.
  Every enforcement entry point would have to be called from both, nothing
  holds them in step, and two front doors onto one guarantee is the gap
  this project exists to make visible. It also carried the only credential
  this process ever held, since a secondary connection cannot replay a
  client's SCRAM handshake. If ranking on a replica becomes a real
  requirement, the honest version is a routing decision *inside* the one
  loop, with the measurements that justify it first.
- **A hosted proxy.** It would hold every customer's database credentials
  and put every document they retrieve through somebody else's
  infrastructure. The sidecar shape in §6 is the strongest thing this can
  be, and it is strongest precisely because nobody else is in the path.

Two things are kept on purpose, so nobody re-derives "no callers" and
deletes them:

- **`including_refused()`** has no caller outside the package. It is the
  named, audit-gated break-glass read, and it is a separate object rather
  than a flag so a review can grep for every place the guarantee was
  waived.
- **`authority.py`** stays because four modules import its operation
  constants, so deleting it takes the write verbs along.

## 9. If you read one thing

The boundary is correct and unproven. Every mechanism on this page is
tested, sabotage-checked, and verified against a real deployment — and
every one of those tests was written by the person who wrote the
mechanism.

So the only number that matters is not on this page. It is how many
documents *your* retrieval serves that *your* database has already marked
as gone. `examples/shadow.py` measures it in three lines and changes
nothing while it does.
