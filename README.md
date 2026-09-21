# VOYD

**Retrieval is the only data path in a mature stack with no enforcement
point.**

Every other one has had this solved for years. HTTP has middleware. SQL has
views and row-level security. The filesystem has permission bits the kernel
checks whether or not you remembered to ask. Each of those is a place where
the answer to *may this caller see this?* is given once, below the
application, where no call site can forget it.

Vector retrieval has a ranking function and a hope. `$vectorSearch` scores
relevance and is never asked the other question, so the answer gets
reimplemented inside every query — a tenant filter here, an `expire_at`
clause there, one per call site, in each service, in each language, forever.

**And the failure is silent in the worst possible direction.** A missing
authorization filter returns *more* documents, not fewer. It does not raise,
it does not log, and on a retrieval workload it reads as **better recall**.
There is no error to page on and no test that naturally fails. Somebody's
revoked credential is in a prompt and the dashboard is green.

So: **ranking is not permission.** Delete does not help either — MongoDB's
TTL monitor runs about once a minute (measured here: 60.0s), an S3 lifecycle
rule about once a day, and in that window the index keeps returning the
deleted document as a normal, well-scored result. Delete is a wish.
**Refuse is a contract** — answered on every read, immediately, whatever the
sweeper is doing.

VOYD is that enforcement point, and it is placed where it cannot be
bypassed: **the wire**. One connection string, no import, no code. Which is
the whole design, because a boundary you can forget to use is not one.

---

## A statement of intent is not a guarantee

That is the thesis underneath all of it, and it is bigger than vector
search. Everything above is one instance of it, and so is every defect this
project has found in itself:

| the intent | the window it actually had | found in |
|---|---|---|
| `delete` removes the fact | ~60s of TTL monitor lag | the premise above |
| a destroyed key makes it unreadable | ~60s of libmongocrypt key cache | `voyd/wire/seal.py` |
| a replica's copy is current | unbounded replication lag | `voyd/wire/fanout.py` |
| the index embeds with the declared model | nobody had ever asked it | `voyd/wire/preflight.py` |
| this test proves the claim in its name | it asserted a page of one | `LIMITS.md` §1 |
| this counter is on a dashboard | it was never flushed | `voyd/wire/metrics.py` |

Three unrelated subsystems, three independent discoveries, one defect: a
*delete-is-a-wish window*. Then the same shape again in the configuration,
the test suite, and the metrics. The lesson generalises past data entirely —
**what did you verify, versus what did you declare and assume?**

So this repository applies it to itself, and not as a slogan:

- **[CLAIMS.md](CLAIMS.md)** maps every guarantee to the file that would go
  red if it stopped holding. The mapping is checked in both directions by
  `tests/test_every_claim_names_its_evidence.py` — a claim with no test, or
  a test no claim points at, fails the suite. Currently 29 claims across 28
  files — lineage is two of them, because the cascade on read and the
  ancestry closed on write fail separately.
- **[LIMITS.md](LIMITS.md)** counts this project's own defects, names its
  own bad numbers, and opens with the one that matters: nobody has used this
  but its author.
- Every performance figure comes from `voyd/wire/bench.py`, which checks
  the boundary was still refusing while it was being fast.

None of that makes the code correct. It makes the difference between *a
claim* and *an attached claim* visible, which is the only honest thing a
README can offer — and it is the floor, not the ceiling. One of the tests on
that map was a screenshot for two commits.

---

## Three ways to make a fact go away, and only one is immediate

The mechanics, in one table. Every claim below is a consequence of it, and
the last column is the part that decides which one you actually need:

| | when | reaches |
|---|---|---|
| **refusal** | immediately, on the next read | this application's read path |
| **crypto erasure** | ~60s (measured) | every copy that exists anywhere |
| the TTL reaper | ~60s (measured) | this deployment's disk |

Nothing here replaces your TTL index; the bottom row is MongoDB doing its
job. What the top two add is the two questions it cannot answer — *may this
reach a prompt **now***, and *what about the backup nobody has restored yet*.

**They cover each other exactly, which is the argument for having both rather
than choosing.** Refusal is instant and binds only this read path, so a
restored snapshot walks straight past it. A destroyed key binds every copy
and is *not* instant — a reader that decrypted a moment ago keeps decrypting
until its key cache turns over. So each one's window is the other's
guarantee, and the boundary orders them that way on purpose: **unreachable
first, unreadable second.**

---

## No code

```bash
pip install voyd        # or: uv add voyd
```

That gives you one command, `voyd-wire`, and the vocabulary to write the
file it reads. There is nothing here to import into an application.

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
voyd-wire --config voydfile.py --target localhost:27017

# --advertise-self pins clients here instead of the cluster's own hosts
# or Atlas -- SRV is resolved, TLS is used, the primary is found
voyd-wire --config voydfile.py \
    --target "mongodb+srv://user:pass@cluster0.xxxxx.mongodb.net/"

# reachable across a network, with TLS terminated for clients too
voyd-wire --config voydfile.py --target "$ATLAS" \
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
| `auto_embed(model)` | the *server* embeds this text; refuse a client's own vector |

`budget(n)` and `distinct()` are **set-relative**: they refuse a document
because of the *other* documents on the page, so the same document is
admitted alone and refused in company. No index filter and no policy engine
can express that —
`$vectorSearch` decides each candidate before the page exists, and
`enforce(subject, object, action)` has nowhere to put the rest of the set.

A policy file that is wrong fails when it is *loaded*, not when a query comes
back with the wrong rows.

### `restricted_to()` on the wire, and where the claims come from

The one rule that needs to know *who is asking*, which for a long time was
the one thing the library handle could do and the wire could not. The
handle is gone now and the wire does this; what it still cannot do is an
*ordered* clearance, and `LIMITS.md` section 6b says why. The
question is not how to pass claims to the boundary — it is why the
boundary should believe any. `for_caller` in `admission/core.py` puts it
bluntly: a handle that believed `{"clearance": "secret"}` because it was
handed one **would be an authorisation system whose only input is the
attacker's.** A proxy is worse off still, because the client is the only
thing talking to it.

So the boundary does not accept claims. It asks the deployment:

```
connectionStatus  ->  authenticatedUsers:     [{user: "lawyer", db: "app"}]
                      authenticatedUserRoles: [{role: "legal",  db: "app"}]
```

Run on the client's *own* connection, so the socket, the authentication
and the identity are all theirs — and the answer is the server's account
of who authenticated there, which no client can forge without forging the
authentication itself. A role **is** a group: `db.createRole({role:
"legal"})` is how a deployment already spells this, so

```python
audience = restricted_to("groups")
```

against a document listing `["legal", "deal-desk"]` needs nothing further.
Two credentials, one query, different rows:

```
lawyer  ->  find({})  ->  the memos whose audience names a role they hold
seller  ->  find({})  ->  a different set, same query, same proxy
```

Asked once per connection, lazily, and only for a collection whose rules
ask — an authenticated connection cannot become somebody else, and a
policy with no caller-aware rule never pays the round trip.

**What it cannot do, said here rather than discovered.** `Clearance` wants
an *ordered level*, and nothing in a MongoDB role says which level a role
corresponds to. It therefore finds no claim, and no claim is the lowest
rather than the highest, so it would refuse everything. The boundary says
so at boot with the collection named, instead of letting it look like
broken reads. See `LIMITS.md` §6b.

## It sizes its own fetch

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

## There is no in-process form

A boundary you can forget to route a read through is not a boundary, so
there is no handle to hold and no `find()` to call. `pip install voyd`
gives you `voyd-wire` and the vocabulary a `voydfile.py` is written in —
`guard`, `deadline`, `revocable`, `tenant`, `restricted_to`, `sealed`,
`auto_embed` — plus what `--ensure` and `--verify` provision with. Your
application imports nothing.

Two front doors onto one guarantee is the gap this project exists to make
visible, and having one would mean having it here: a claim that holds
through an import and not through the connection string is a claim a
reader cannot check. Everything in [CLAIMS.md](CLAIMS.md) holds through
the port.

The one thing you do run in your own process is a **measurement**, and
only because a boundary would defeat the point of it: `examples/shadow.py`
counts how many documents your existing read path serves that your own
database has already marked as gone, and changes nothing while it does.
When that number convinces somebody, the same rules become a policy file.

## The server owns the encoding

`embedded_with(model)` refuses a **document** whose stored vector came from
the wrong model, and the measurement behind it is the reason this matters at
all — two generations of one vendor's model, same width, same text:

```
  identical text, old model vs new       cosine -0.053
  unrelated text, both on the new one    cosine +0.301
```

A model swap does not degrade ranking, it **inverts** it: unrelated text
scores five times higher than the document you were looking for. No error,
no log, a healthy-looking `describe()`.

Nothing refused the **query**, and that is the same failure one level up.
`auto_embed` takes the embedder out of the application entirely — the index
holds the text, `mongot` embeds it on write, and embeds the query with the
same model at read time. Nothing in your process computes a vector, so
nothing in your process can drift:

```python
@guard("notes", on_delete="revoke")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()
    body      = auto_embed("voyage-4")     # mongot embeds this, both ways
```

A client that still sends its own `queryVector` has put the embedder back,
through a driver that never read that file — which is precisely the caller
this boundary exists for. So it is refused by name rather than ranked:

```
  db.notes.aggregate([{"$vectorSearch": {"queryVector": [...]}}])

  -> voyd-wire refuses a client-supplied queryVector on 'notes': this
     collection declares auto_embed='voyage-4', so the index holds text
     the server embedded and a vector computed anywhere else is a hit in
     a different space. Comparing them does not fail, it returns a
     confident score for the wrong documents. Send $vectorSearch.query
     with the query text instead.
```

**An error, because the alternative is a full page of plausible nonsense.**
A refusal is recoverable and names the form that works; a silently wrong
ranking hands the caller ten well-scored documents that have nothing to do
with the question, and nothing anywhere says so.

This one is **pure** — a `$vectorSearch` body and a dict decide it, with no
database, no Atlas and no index. Which is why almost all of
`tests/test_the_server_owns_the_encoding.py` runs in CI's no-database step,
beside the codec and the boundary itself. Run it:
`uv run python examples/embed.py`.

### Two declarations of one thing have to agree

`embedded_with("voyage-4")` beside `auto_embed("voyage-3.5")` is refused when
the file is **loaded**. One says *refuse any vector not from voyage-4*; the
other says *the server will produce them with voyage-3.5*. Every document the
index embedded would be refused by the rule sitting next to it, and the
collection would read as empty — which is the kind of wrong that looks like a
data problem for a week.

And a field cannot be both `sealed()` and `auto_embed()`, because the server
cannot be denied a field and also asked to embed it: it would either embed
the ciphertext (vectors of noise, and a relevance failure nobody attributes)
or be handed the plaintext you sealed it against. **In a policy file it cannot be written at all** — the path *is* the attribute name, so Python
binds it once and the second declaration wins. That is one more answer to
"why a class body rather than a dict": a shape where a contradiction has
nowhere to live beats a shape that detects it. Sealing one field and
embedding a *different* one is fine, and is allowed.

## The erasure refusal cannot perform

Row two of the table at the top. Refusal binds this application's read path,
so a replica, a snapshot, or a backup restored next year walks straight past
it — none of them run it, the plaintext is on their disk, and no amount of
refusing changes that ([LIMITS.md](LIMITS.md) §2). Destroying a key reaches
all of them at once without visiting any. Declare which field:

```python
@guard("notes", on_delete="revoke")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()
    text      = sealed()          # ciphertext at rest, key per tenant
```

```bash
voyd-wire --config voydfile.py --target "$ATLAS" \
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

The boundary **revokes the scope's documents, then destroys its key** — the
ordering the table at the top ends on, and the entire correctness of the
feature rather than a nicety. libmongocrypt caches data keys, so a shred on
its own leaves the ciphertext readable for as long as somebody holds one:
*a second delete-is-a-wish window, opened inside the feature that exists to
close the first one*.

Not theorised. The first working version of this did exactly that, and
served a shredded tenant's plaintext for thirty seconds while reporting the
erasure as done. It was found by pointing a driver at it, which is the
subject of [LIMITS.md](LIMITS.md) §1.

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

- **A connection and a credential of its own**, one per worker. Every other
  upstream connection this proxy makes is the client's. `--kms local:/path`
  keeps the master key in a file; `--kms env:PREFIX` reaches the rungs where
  destroying it is somebody else's audited operation. The default is
  ephemeral, does not survive a restart, and says so in capitals.
- **A sealed read costs ~8.1µs per document instead of 2.3µs**, because it
  decrypts before it refuses — the order the library uses, and the two must
  agree or the same document would be admitted one way and refused the
  other. Measured: `voyd/wire/bench.py --seal` reports **5.8µs** to
  decrypt, stable across passes, and **~8.7µs** to encrypt warm (~26µs on
  the first pass, while the key cache fills — which is why the benchmark
  prints a spread rather than one draw). Unsealed collections still take
  the pure path untouched.
- **A write it cannot seal is refused, never forwarded.** No tenant to scope
  a key to, a pipeline update that would assign a sealed field server-side,
  `$inc` on ciphertext. There is no safe fallback: an error is loud,
  harmless and fixable, and a forwarded plaintext row is none of those and
  is already in the backup.
- **A sealed collection is never ranked on a secondary**, because fan-out
  takes the marks from the primary and the documents from a replica — right
  for a verdict that reads marks, wrong for one that must decrypt what it
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

## The policy is checked against the cluster

A voydfile is a set of claims about a cluster this process does not own:
*there is a TTL index on `expire_at`*, *the vector index embeds `body` with
voyage-4*, *the server refuses plaintext in this sealed field*. Every one can
be false, and when one is false nothing says so — the boundary goes on
enforcing a policy the storage underneath it is not holding up.

`capabilities.py` exists because this engine used to *infer* what a
deployment could do, and both times it inferred it was wrong for months
without a log line. Its own conclusion is the argument: **a version floor is
a claim about software this package does not ship, with no expiry and nobody
responsible for it.** `auto_embed("voyage-4")` is exactly that. So it is
asked:

```bash
voyd-wire --config voydfile.py --target "$ATLAS" \
    --verify app --verify-only          # a deploy gate: exit 0, 3, or why not
```

```
voyd-wire: preflight FATAL [notes.auto_embed]: auto_embed('voyage-4') on
    'body' but no search index declares an 'autoEmbed' field on that path.
    The index present needs a client-supplied vector and the boundary
    refuses exactly those, so every vector read here is an error
    remedy: either add an autoEmbed field on 'body' to the search index, or
    remove auto_embed() from the policy

voyd-wire: preflight warning [notes.deadline]: deadline() names 'expire_at'
    and there is no TTL index on it. Refusal still works -- an expired fact
    is unreachable on the next read -- but nothing ever reclaims the bytes,
    so this collection grows without bound
    remedy: db.notes.createIndex({"expire_at": 1}, {expireAfterSeconds: 0})
```

Four claims, four checks, and **every one of them read-only** —
`listIndexes`, `$listSearchIndexes`, `listCollections`. It creates nothing.
That distinction is what took a while to see: *creating* an index from the
declaration is a schema change against somebody else's cluster and deserves
caution, but *reading one back* is a query, and the risk of the first is not
a reason to skip the second.

**Fatal means a contradiction; a warning means a missing layer.** A
declaration the index cannot satisfy is an outage discovered one query at a
time, so the boundary refuses to start and names the line. A deadline with no
TTL index, a tenant with no index leading with it, a sealed field the server
still accepts plaintext into — refusal keeps working in all three, so they
print and the boundary serves. A deployment that has run that way for a month
should not have its next restart blocked by this noticing.

**Unreachable is not misconfigured.** They look identical from here and mean
opposite things, so a probe that cannot run says why and the boundary starts
anyway. And a probe that failed never reports a clean bill — "preflight found
nothing" on a run where preflight never ran would be the confidently-wrong
shape this whole project is named after.

The connection is closed before the listener accepts anything, so this is not
`--key-vault`: nothing here is on the read path.

What is still *not* on the wire is **creating** an index from the
declaration. That one stays with the library, deliberately — the detection
half is a query and the creation half is a schema change against a cluster
this process does not own. [LIMITS.md](LIMITS.md) §5.

## Fan-out

`$vectorSearch` scans `numCandidates` across the corpus. Doing that on the
primary, beside every write, is the cost a read replica exists to remove:

```bash
voyd-wire --config voydfile.py --target "$RS" --fan-out "$RS"
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

## When you do not need this

The fastest way to understand what this is for is to know what it is not
for, and none of these is rare:

- **Your corpus has no deadline and nothing is ever revoked.** Then ranking
  really is the only question, an index filter is the right tool, and this
  is a proxy you would be running for nothing.
- **One tenant, one audience, no erasure requests.** `tenant()`,
  `restricted_to()` and `sealed()` are most of the value here. Without them
  you are left with the deadline, and a TTL index plus
  `{"expire_at": {"$gt": now}}` in the query is a smaller thing that
  closes the same window — *provided* the bullet below holds.
- **You can put that filter in every query and trust every call site to
  keep doing it.** Then do that; it is genuinely cheaper than a proxy. This
  exists because *remembering* is the failure mode — a rule you have to
  apply is not enforced — so the question is not whether the filter works
  but whether it is in the notebook, the migration script, and the service
  somebody adds next quarter. One read path that nobody else will touch is
  a real answer to that, and plenty of systems have one.
- **You need to query the sealed field itself.** Sealed values are opaque
  ciphertext under a Random algorithm. That is free here because what gets
  searched is the *embedding*, and the embedding is not the sensitive field
  — if that is not true of your data, Queryable Encryption is the trade to
  look at, and it costs you the thing this is for: QE rejects a pointer
  `keyId`, so one key covers one field across the whole collection and
  shredding it erases that field for everybody rather than for one subject.
  Stated once, with the error message, in `voyd/engine/keyring.py`. It is
  library-only and not reachable from the wire ([LIMITS.md](LIMITS.md) §5).

What is left, and it is a narrow, real shape: **retrieval over a corpus where
facts expire, get revoked, or belong to somebody** — and more than one thing
reads it.

## Known gaps

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
  Keeping `setName` in the rewritten `hello` is what buys the retryable-write
  and session rows;
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
  and printed once. `voyd-bench` reproduces all of it, and
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

## Status

**One thing, on purpose.** This repository used to also be an HTTP service, an
MCP server, a store layer, a job queue, a perimeter, a hash-chain ledger and
a context index. All of it was cut, along with ~817 tests and ~35,000 words
of documentation describing it. What is left is the boundary, the policy
file, and the wire — which is the part that was load-bearing, and the part
that is hard.

That is a decision rather than a state. The cut is finished; nothing above is
waiting on it.

**What would actually change this project** is in
[LIMITS.md](LIMITS.md) §1 and it is not on this page: nobody has used it but
its author. Zero external users, zero pilots, and every claim here verified
by the person who wrote the claim. Nineteen defects last month, and not one
of them was caught by the suite going red — they came from running it, or
from somebody asking why a paragraph said what it said. One
team, two weeks, their own corpus is worth more than anything else that
could be built next.

The suite is **477 tests**, and it is the foundation rather than a census —
the smallest set of claims that, if any one broke, would make everything
above it a lie. Each one and the file that holds it up is
**[CLAIMS.md](CLAIMS.md)**, and that mapping is itself checked: a claim with
no test, or a test file no claim points at, fails the suite.

Two of those rows are worth singling out. *A forgotten fact cannot reach a
prompt* is asserted **with no database anywhere near it**, because a
per-document check that cannot run without one is a check that could not
have moved to a wire. And *a `$vectorSearch` hit is refused on the path that
never passes through a query* runs against a **live Atlas cluster**, because
that one cannot run anywhere else.

That second one is worth its ninety seconds. Atlas Local registers no embedding
models, so it *declines* an `auto_embed` declaration and falls back to a
client-supplied vector — a test that accepted the fallback would assert the
opposite of what it claims. Against a real cluster the application never
computes a vector at all, the index owns the encoding, and the expired hit is
still refused on the way out. Point it at your own cluster with
`VOYD_ATLAS_URI` (or a `.env`, which is gitignored).

```bash
pytest              # 473 tests, ~150 seconds -- the inner loop
pytest -m ""        # everything, including the real index builds
```

Most files need no MongoDB, and that is not a convenience. A
per-document check that cannot run without a database is one that cannot move
to a wire — so if that ever stops being true, the architecture has quietly
changed, and CI runs those three in a step with no database to make it
obvious.

The suite is checked against sabotage rather than trusted: disabling the
delete rewrite, the tenant egress check, the tenant *shape* check, cascade,
refusal itself, wire-side encryption, the revocation that must precede a
shred, the refusal of a client-supplied query vector, or any of the
preflight's four checks each turns it red.
