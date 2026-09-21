# VOYD

**Ranking is not permission.**

A vector index ranks by relevance and is never asked the other question — *may
this fact reach a prompt?* So retrieval answers with a confident score and no
idea whether the hit was allowed to be there: an expired row the sweeper has
not reached, a fact somebody revoked, a vector from a model you swapped last
quarter.

Delete is a wish. MongoDB's TTL monitor runs about once a minute (measured
here: 60.0s); an S3 lifecycle rule runs about once a day. In that window your
index keeps returning the deleted document as a normal, well-scored result,
with nothing logged and nothing to page on.

**Refuse is a contract** — answered on every read, immediately, whatever the
sweeper is doing.

---

## No code

Declare the rules once, in a file that is not your application:

```python
# voydfile.py
from voyd import guard, deadline, revocable, tenant

@guard("notes", on_delete="revoke")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()
```

Point the boundary at your database:

```bash
# a local mongod
python tools/voyd_wire.py --config voydfile.py --target localhost:27017

# --advertise-self pins clients here instead of the cluster's own hosts
# or Atlas -- SRV is resolved, TLS is used, the primary is found
python tools/voyd_wire.py --config voydfile.py \
    --target "mongodb+srv://user:pass@cluster0.xxxxx.mongodb.net/"

# reachable across a network, with TLS terminated for clients too
python tools/voyd_wire.py --config voydfile.py --target "$ATLAS" \
    --tls-cert server.pem --tls-key server.key --max-connections 500
```

**Without `--tls-cert` it binds loopback only.** That is a decision, not a
default: a plaintext boundary reachable from the network would carry in the
clear every document it had just refused to serve.

**It follows a failover.** The upstream is resolved lazily and cached, and
invalidated by the server's own `NotWritablePrimary` — including the one
nested inside a batch's `writeErrors`, which is where it hides on exactly
the command this rewrites. The next connection re-resolves. A health check is
a guess about the future; that error is the server describing the present, on
the message that proves it, which the client was getting anyway.

Then change one connection string. **That is the whole integration.** No
import is added to your application, no handle replaces a collection, no read
path is rewritten, and nobody has to remember anything.

What your driver keeps, because this is the question that decides whether
the sentence above is true for *you*: sessions, multi-statement transactions
and retryable writes all cross the boundary intact, and every satisfiable
read preference is served and still refused. What it loses is fan-out --
every read lands on one upstream. The details, and the tests that hold them,
are [below](#known-gaps). Run it with `--advertise-self` or reach it with
`directConnection=true`; without one of the two your driver reads the
cluster's own host list and connects straight past the boundary.

### Reads refuse

```
direct, no boundary   5 documents
through the boundary  ['a note somebody will delete', 'the fault code is P0301']
                      the expired and the revoked are refused, and
                      globex was never in scope
```

That is a plain `pymongo` client with no VOYD import in it. It would be the
Node driver, or Compass, or a notebook — they all send the same bytes. The
boundary binds the *connection*, so there is nothing to reach past.

### Writes forget

And the verb already in everybody's code gets the better meaning:

```
  db.notes.delete_one({'text': 'a note somebody will delete'})
    -> deleted_count=1   (the driver is satisfied)

  reachable now         ['the fault code is P0301']
  rows on disk          5   <- nothing was destroyed
  the mark              'deleted via voyd-wire' at 2026-09-21T05:59:17
  the deadline          set, so the reaper collects the bytes
                        on the schedule they already had
```

**Both delete verbs**, because they are different wire commands and covering
one is worse than covering neither: `deleteOne`/`deleteMany` (`delete`) and
`findOneAndDelete` (`findAndModify`), which still hands the caller the
document back. And the verbs that *cannot* be a revocation — `drop`,
`dropDatabase`, `renameCollection` — are **refused with a reason** rather than
forwarded, because a drop takes the marks with it and leaves no evidence that
anything was ever forgotten.

Delete is a wish — eventually, best effort, unprovable. Refuse is a contract.
They asked for the wish and got the contract, and the bytes still go, on the
deadline they already had. A credential you need out of prompts *now* and on
disk *for the investigation* are contradictory requirements for `DELETE` and
the same requirement for this.

`on_delete="revoke"` is opt-in, because silently redefining `delete` for an
operator who did not ask is the kind of surprise this project exists to
remove — and because somebody, somewhere, means it. Left alone, a delete
really deletes. Declaring it without a `revocable()` field to write the mark
into is refused at load: there would be nowhere to record that the fact was
forgotten, and the delete would quietly do nothing.

The update it emits is the same pipeline `Admission.revoke()` writes — the
literal mark, the deadline moved *earlier only*, the derived encodings nulled
— so a fact forgotten through the wire and one forgotten through the library
are the same document afterwards. Two spellings producing different rows would
be the drift this whole package is about.

Run it: `uv run python examples/wire.py`.

The proxy holds no database connection of its own. The per-document check is
pure — handed documents, returns the ones a prompt may see — which is what
makes it movable to a wire at all. One flag spends that, deliberately and in
one place: [`--key-vault`](#the-erasure-refusal-cannot-perform).

## The vocabulary

| in a `voydfile` | means |
|---|---|
| `deadline()` | this field holds the instant after which the fact is gone |
| `revocable()` | a mark an operator sets to forget it *now*, irreversibly |
| `holdable()` | the reversible kind: a hypothesis, not an instruction |
| `tenant()` | the tenant id — required in every query *and* checked per document |
| `restricted_to(claim)` | admit only callers whose claim overlaps this audience |
| `embedded_with(model)` | refuse a vector from a different embedding model |
| `budget(n)` | refuse once the prompt has no room left |
| `distinct()` | refuse a repeat of content already on the page |
| `sealed()` | ciphertext at rest, under a key scoped to the tenant |

The last two are **set-relative**: they refuse a document because of the
*other* documents on the page, so the same document is admitted alone and
refused in company. No index filter and no policy engine can express that —
`$vectorSearch` decides each candidate before the page exists, and
`enforce(subject, object, action)` has nowhere to put the rest of the set.

A policy file that is wrong fails when it is *loaded*, not when a query comes
back with the wrong rows.

### It sizes its own fetch

`$vectorSearch` draws `numCandidates` and returns `limit`. Ask for a pool
sized for `limit` on a collection where half of what the index ranks is
already forgotten, and you get half a page back and pay for another round
trip to find out.

**No other component can compute the right number.** The index does not know
your deadline, so it cannot know what fraction of what it ranks is already
gone. The driver does not. The only thing that knows the refusal rate is the
thing doing the refusing — and on the search path its count is *exact*,
because a `$vectorSearch` hit passes through no query, so every candidate is
either admitted or counted.

So the boundary sizes the pool from measurement: `1 / (1 - refusal rate)`,
which is the expected over-fetch exactly rather than a heuristic. It only
ever raises the ask, it needs a minimum sample before it infers anything,
and it is capped — because a scope refusing 99% should not ask for a pool
the size of the collection. Refill still guarantees the page; this just
stops it needing three trips to get there. `receipts()["over_fetch"]` shows
the number.

## In-process, if you want it

The declarative form compiles to the same objects the library exposes, so
there is no cliff between declaring a rule and writing one:

```python
from voyd import Engine

engine = Engine(client, db)
await engine.connect()
docs = engine.model("notes").forgettable()

await docs.find({})                      # cannot return a forgotten fact
await docs.revoke({"_id": x}, reason="credential leaked")
```

`revoke()` makes a fact unreachable on the next read while its row is still on
disk. Unreachable first, erased second — the reverse order is the bug.

Also kept: **server-side embedding** (`auto_embed`, so the index owns the
vector and a client-side embedder cannot drift from it), which is reachable
only from the library today. Encryption is not on that list any more — see
below.

## The erasure refusal cannot perform

Refusal answers *may this fact reach a prompt* — immediately, on every read,
whatever the sweeper is doing. It has nothing to say about a replica, a
snapshot, or a backup somebody restores next year, because **none of those
run this read path**. That is the honest gap. It is in
[LIMITS.md](LIMITS.md) §2 and no amount of refusing closes it: the plaintext
is on disk and every copy of the disk has it.

Destroying a key closes it for every copy at once, without visiting any of
them. Declare which field:

```python
@guard("notes", on_delete="revoke")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()
    text      = sealed()          # ciphertext at rest, key per tenant
```

```bash
python tools/voyd_wire.py --config voydfile.py --target "$ATLAS" \
    --key-vault app --kms local:/etc/voyd/master.key
```

Then the same plain driver, with no encryption configured and no VOYD import
in it:

```
  db.notes.insert_one({"tenant_id": "alice", "text": SECRET})

  through the boundary  'alice was treated for a stress fracture in March'
  on disk               Binary(b'\x02\x06;\x8c4\xbc\xbfI\xba\x8b...', 6)
```

**`sealed()` requires `tenant()`, and that is the whole design.** The key is
the tenant's, so erasing one subject touches nobody else. A literal `keyId`
would give one key per collection, and honouring one person's erasure
request would make every other tenant's rows unreadable at the same instant.
Declaring `sealed()` with nothing to scope it to is refused when the policy
file is *loaded*.

### Erasure is two things, in one order

An erasure needs no new verb, because the key vault is an ordinary
collection:

```
  db["__keys"].delete_one({"keyAltNames": "alice"})

  alice, through the boundary   []          <- immediately
  bob,   through the boundary   ['the fault code is P0301']
  rows on disk                  2           <- nothing was destroyed
  alice's mark                  'key destroyed' at 2026-09-21T12:31:04
  alice's bytes                 Binary(...) <- noise, in every copy
```

The boundary **revokes the scope's documents, then destroys its key**, and
the order is the entire correctness of the feature rather than a nicety.
Destroying a key is not instant at the reader: libmongocrypt caches data
keys, so a process that decrypted a scope a moment ago keeps decrypting it
until that cache turns over — about 60 seconds, which is the same shape and
very nearly the same number as the TTL window this README opens by
complaining about.

A shred on its own therefore opens *a second delete-is-a-wish window, inside
the feature that exists to close the first one*. The first working version
of this did exactly that, and served a shredded tenant's plaintext for
thirty seconds while reporting the erasure as done. **Unreachable first,
erased second.** The two halves cover each other exactly:

```
  the key cache is a window where the ciphertext still reads
      -> refusal already refused the document, on the first read
         after the revocation, with no window at all
  refusal only binds this application's read path
      -> the key is gone, so a backup restored next year is noise
```

### It says what it did

Sealing is invisible unless it is counted, and a boundary that silently
stopped encrypting looks exactly like one that is encrypting. So the read
half arrives in the refusal series an operator is already watching, and the
write half got four of its own (`--metrics PORT`):

```
voyd_sealed_writes_total 5              <- if this is flat, plaintext is landing
voyd_sealed_reads_total 10
voyd_seal_refused_writes_total 1        <- writes it could not seal
voyd_erasures_total 1                   <- erasure requests sequenced
voyd_erasure_revocations_total 5        <- documents revoked ahead of the key
```

**The last two are a pair, and the pair is the point.** `erasures_total`
climbing while `erasure_revocations_total` stays flat *is* the ordering being
lost — a key destroyed with nothing marked, readable for as long as somebody
keeps it cached. It is the defect above, as a graph.

They also answer a question the per-reason series cannot. A revocation writes
the mark *and* pulls the deadline in, so an erased subject is refused under
`deadline` — the same reason a document that merely expired reports. Nothing
in `refused_by_reason_total` can separate the two, because the boundary wrote
the same marks for both. These two can.

### What this costs, stated rather than discovered

This is the one flag that spends the property the rest of this README leads
with, so it says so at startup rather than in a footnote:

```
voyd-wire: key vault app.__keys; custody is LocalFile -- /etc/voyd/master.key
voyd-wire: sealing notes.{text} under a key per tenant_id; shred one and
           every copy of that tenant's ciphertext is noise
voyd-wire: THIS BOUNDARY NOW HOLDS KEYS. It has a database connection of its
           own and is a custody holder; sealed reads decrypt before they
           refuse. See LIMITS.md §5
```

- **A connection of its own**, one per worker, to the key vault. Every other
  upstream connection this proxy makes is the client's.
- **A credential of its own.** `--kms local:/path` keeps the master key in a
  file; `--kms env:PREFIX` reaches the rungs where destroying it is somebody
  else's audited operation. The default is ephemeral, does not survive a
  restart, and says so in capitals.
- **A sealed read costs ~8.1µs per document instead of 2.3µs**, because it
  decrypts before it refuses — which is the order the library uses, and the
  two must agree or the same document would be admitted one way and refused
  the other. Measured, not estimated: `python tools/voyd_bench.py --seal`
  reports **5.8µs** to decrypt (stable to a hundredth across passes) and
  **~8.7µs** to encrypt once the key cache is warm, against a real key
  vault. The first encrypting pass costs ~26µs while that cache fills,
  which is why the benchmark prints a spread rather than one draw.
  Unsealed collections still take the pure path untouched at 2.3µs.
- **A write it cannot seal is refused, never forwarded.** No tenant in the
  document, a pipeline update that may assign a sealed field, `$inc` on
  ciphertext: the error goes straight back and the server never sees the
  command. There is no safe fallback — forwarding puts plaintext on the
  disk, the replica and the backup, permanently, and no later fix reaches
  the copy that already has it.
- **A sealed collection is never ranked on a secondary.** Fan-out takes the
  marks from the primary and the documents from a replica, which is right
  for a verdict that reads marks and wrong for one that must decrypt what it
  was handed.

**What it buys is the sentence the library version cannot say.** In-process,
`schema_map` encrypts below the *application*, so no writer in that Python
process can forget. On the wire it encrypts below the *driver*, so no writer
in any language can — not the Node service, not the migration script, not
the shell, not the notebook, not the one written next year by somebody who
has not read this file. That is the same upgrade the wire gave `delete`,
applied to the stronger guarantee.

Run it: `uv run python examples/seal.py`. The full trade, including what is
still open, is [LIMITS.md](LIMITS.md) §5.

## Status

**Mid-rewrite, and honest about it.** This repository was just cut hard: the
HTTP service, the MCP server, the store layer, the job queue, the perimeter,
the hash-chain ledger and the context index are gone, along with ~817 tests
and ~35,000 words of documentation that described them. What is left is the
boundary, the policy file, and the wire.

The suite is **272 tests**, and it is the foundation rather than a census —
the smallest set of claims that, if any one broke, would make everything
above it a lie:

| | |
|---|---|
| the wire codec round-trips | including the document sequence that carries a write, where the one silent bug lived |
| the boundary refuses | expired, revoked, unreadable-deadline, off-tenant — **with no database anywhere near it** |
| a policy file compiles, or fails at *load* | five ways to be wrong, each refused by name |
| a plain driver gets all of it | real `mongod`, real proxy, real driver |
| the write path forgets without deleting | the deadline moves *earlier only*; a quarantine stays pinned; a revocation cannot be lifted |
| encryption is the answer refusal cannot give | plaintext is not on disk, shredding one tenant leaves the others readable |
| **the boundary seals and shreds** | a plain driver with no encryption configured writes ciphertext; an erasure is unreachable *immediately* and unreadable everywhere after |
| a refusal travels | revoke a source, the summary and the answer and the embedding go with it |
| the boundary sizes its own fetch | `numCandidates` from the measured refusal rate, not a constant |
| it is operable | TLS termination, a capped message size, keepalive, a draining `SIGTERM` |
| the suite does not leak databases | a stale search index starves the next index build |
| a client cannot walk past it | `hello` is rewritten, so the guarantee is not a connection-string option somebody remembers |
| **the server embeds and refusal still holds** | against a **live Atlas cluster**, because this one cannot run anywhere else |

That last row is worth its ninety seconds. Atlas Local registers no embedding
models, so it *declines* an `auto_embed` declaration and falls back to a
client-supplied vector — a test that accepted the fallback would assert the
opposite of what it claims. Against a real cluster the application never
computes a vector at all, the index owns the encoding, and the expired hit is
still refused on the way out. Point it at your own cluster with
`VOYD_ATLAS_URI` (or a `.env`, which is gitignored).

```bash
pytest              # 272 tests, 96 seconds -- the inner loop
pytest -m ""        # everything, including the real index builds
```

Most files need no MongoDB, and that is not a convenience. A
per-document check that cannot run without a database is one that cannot move
to a wire — so if that ever stops being true, the architecture has quietly
changed, and CI runs those three in a step with no database to make it
obvious.

The suite is checked against sabotage rather than trusted: disabling the
delete rewrite, the tenant egress check, the tenant *shape* check, cascade,
refusal itself, wire-side encryption, or the revocation that must precede a
shred each turns it red.

### Fan-out

`$vectorSearch` scans `numCandidates` across the corpus. Doing that on the
primary, beside every write, is the cost a read replica exists to remove:

```bash
python tools/voyd_wire.py --config voydfile.py --target "$RS" --fan-out "$RS"
```

**The obvious version of this is unsafe, and it is unsafe in exactly the way
this README opens with.** Refusal is a function of the marks on the document
it is shown. A secondary that has not yet replicated a revocation hands the
boundary a document that still looks live, and the boundary admits it —
confidently, with a receipt saying it was allowed. Replication lag becomes a
second delete-is-a-wish window, opened by the thing that exists to close the
first one.

So the read is split in half:

```
client --find--> boundary --> SECONDARY   numCandidates scan, 100k documents
                    |
                    |  returned _ids: [a, b, c ... j]   (10)
                    v
                 PRIMARY   projection {_id, expire_at, forgotten}
                    |
                    v
             refuse() on the authoritative marks --> client
```

**The secondary ranks. The primary permits.** The expensive part moves; the
verdict does not. Ranking is not permission — here that is a routing rule
rather than a slogan.

What it costs, stated rather than discovered:

- **One round trip per guarded batch.** Unguarded collections fan out with
  no verification, because there is no verdict to be wrong about.
- **A projection when the rules allow one.** `verdict_fields` works out
  which fields the verdict reads. A rule it cannot introspect — `Distinct`
  hashing content, a `Budget` with a custom cost callable, any third-party
  rule — costs a whole-document fetch. Unknown means expensive, never
  means skipped.
- **Reads that cannot be correlated never leave the primary.** Matching a
  batch against the primary's answer needs `_id`, so a `projection` that
  drops it, or an aggregation with a stage that could rewrite it, is
  decided *before* the query is sent.
- **If the primary cannot confirm a batch, the batch is refused whole.**
  `voyd_fanout_unverified_total` counts it. Failing closed is the only
  behaviour available: the alternative is serving documents whose
  permission nobody established.
- **It gives up on a collection that is not benefiting.** Fan-out pays when
  the work it moves off the primary exceeds the work it adds back — true
  for a `$vectorSearch` scanning 100,000 candidates to return ten, false
  for a `find` returning most of a small collection, and nothing about the
  request says which. So it is measured rather than guessed: the time the
  secondary took to rank against the time the primary took to confirm,
  per collection. When confirming stops being cheaper than the ranking it
  bought, that collection goes back to the primary and says so once.
  `--fan-out-give-up RATIO` tunes it (default `1.0`; `0` measures without
  acting), and `voyd_fanout_withdrawn_total` counts it. Withdrawal is
  one-way inside a process — re-admitting on a favourable sample is how a
  boundary oscillates — and keyed by the read's *shape*, not its
  collection, so ordinary `find`s cannot withdraw the `$vectorSearch` they
  share a collection with.
- **A secondary's error does not become yours.** The boundary picked that
  route, so it owns the retry: a read a secondary refuses is re-sent to
  the primary, fan-out goes off for that connection, and the retried read
  goes through ordinary enforcement.
  `voyd_fanout_retried_on_primary_total` counts it.

**It needs a credential of its own, and that is a real change.** Every other
upstream connection this proxy makes is the client's. A secondary connection
cannot be — authentication is per connection and SCRAM is a challenge-response
bound to a nonce, so the client's handshake cannot be replayed onto a second
socket without knowing the password, which this deliberately does not. The
boundary therefore authenticates that connection itself, driving *pymongo's*
SCRAM rather than a hand-written one: the client proof, the salting and the
server-signature check stay in the library, and what this file supplies is a
way to send a document and get one back.

Reads served from a secondary run as the `--fan-out` URI's identity, so:

- **A client authenticating as anyone else gets fan-out switched off for its
  connection**, and its reads stay on the primary. Serving them over a
  connection authenticated as somebody else is a privilege change wearing
  the shape of an optimisation.
- **It fails closed.** On a deployment whose secondaries need a credential,
  fan-out starts *off* and is enabled only by a client proving the matching
  identity. An authentication mechanism this boundary cannot read —
  X.509, AWS, OIDC — is "not us", never "probably fine".
- **A credential that does not work is not an outage.** Wrong password,
  unreachable secondary, a mechanism other than SCRAM: reads stay on the
  primary and the answers do not change.

See [LIMITS.md](LIMITS.md) §3.

### Known gaps

Stated rather than discovered:

- Messages are capped at MongoDB's own 48MB ceiling and malformed framing
  closes the connection. A length field arrives from the wire and this
  process allocates on it.
- TCP keepalive on both legs, and deliberately **no read timeout**: a
  MongoDB connection idles legitimately on an awaitData cursor, and a
  deadline would kill healthy connections and look like the cluster
  flapping.
- `SIGTERM` **drains**: stop accepting, let open connections finish, print
  what the process did. A second signal exits immediately.
- **`--fan-out URI` ranks reads on secondaries and takes permission from
  the primary.** See [below](#fan-out). Without it, reads land on one
  upstream. What survives the crossing either way is asserted in
  `tests/test_the_wire_is_the_front_door.py` rather than reasoned about:

  | a driver asks for | through the boundary |
  |---|---|
  | `primary`, `primaryPreferred`, `secondaryPreferred`, `nearest` | served, and still refused |
  | `secondaryPreferred` with a tag set matching nothing | falls back to the primary, per spec |
  | `secondary` (strict) | **`ServerSelectionTimeoutError`**, client-side |
  | retryable writes | armed — `txnNumber` attached, topology `ReplicaSetWithPrimary` |
  | sessions, multi-statement transactions | forwarded intact, and reads inside them refuse |

  Read preference is *honoured against a topology of one*, which is not the
  same as ignored: the `*Preferred` modes are correctly satisfied by the
  primary, and strict `secondary` — the only mode that could have quietly
  become a primary read — is an error before a byte leaves the client. The
  driver performs its own retries, which is why this does not and must not.
  Keeping `setName` in the rewritten `hello` is what buys the last two rows;
  a driver that thinks it is talking to a standalone turns retries off and
  tells nobody.
- An upstream connection is **per client**, not pooled, and deliberately: a
  MongoDB connection carries authentication, sessions, cursors and
  transactions, so sharing one would hand a cursor to whoever asked second.
  What is bounded is how many exist at once (`--max-connections`).
- **One coroutine pair per connection, `--workers N` across cores.** A
  connection costs a coroutine and a socket, not two OS thread stacks: 3,000
  idle connections are 19 threads and 92MB, where the threaded version was
  9,001 threads and 365MB. One event loop still saturates one core at
  100% of one core under load, because the per-message cost is BSON decode —
  `--workers N` pre-forks over one shared listening socket to use the rest,
  and scales 1.94x / 3.57x / 5.98x at 2 / 4 / 8 workers on fourteen cores.
  **Refusal costs ~2.3µs per document.** Counters are summed across workers
  and printed once. `python tools/voyd_bench.py` reproduces all of it, and
  checks the boundary was still refusing while it was being fast.
  `--seal` measures what `--key-vault` adds per document instead.
- **`--metrics PORT`** serves Prometheus text while it runs: documents
  admitted and refused per collection, refusals by reason, connections,
  upstream re-resolutions. Summed across workers through a slab of shared
  memory with one writer per slot, flushed on a timer so the message path
  pays nothing for it (2.50 → 2.51µs/doc, noise). Loopback only, with no
  flag to change it — a refusal count by reason describes what a corpus
  holds and who has been probing it.
- `on_delete="revoke"` covers both delete verbs and refuses the three that
  cannot be rewritten. An `update` that *overwrites* a fact is still an
  ordinary update — that is mutation rather than forgetting, and treating it
  otherwise would make every edit a revocation.
- **Automatic encryption and server-side embedding are library-only.** Both
  survive the trim and neither is reachable through the wire: decryption needs
  the application's key context, which a proxy deliberately does not hold.

MIT.
