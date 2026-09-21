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
makes it movable to a wire at all.

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

Also kept, and both are reachable only from the library today:
**automatic encryption** (a key per scope, destroyed on the same deadline, so
every copy becomes unreadable at once — the one question refusal cannot
answer) and **server-side embedding** (`auto_embed`, so the index owns the
vector and a client-side embedder cannot drift from it).

## Status

**Mid-rewrite, and honest about it.** This repository was just cut hard: the
HTTP service, the MCP server, the store layer, the job queue, the perimeter,
the hash-chain ledger and the context index are gone, along with ~817 tests
and ~35,000 words of documentation that described them. What is left is the
boundary, the policy file, and the wire.

The suite is **110 tests**, and it is the foundation rather than a census —
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
pytest              # 106 tests, 16 seconds -- the inner loop
pytest -m ""        # everything, including the real index builds
```

Most files need no MongoDB, and that is not a convenience. A
per-document check that cannot run without a database is one that cannot move
to a wire — so if that ever stops being true, the architecture has quietly
changed, and CI runs those three in a step with no database to make it
obvious.

The suite is checked against sabotage rather than trusted: disabling the
delete rewrite, the tenant egress check, the tenant *shape* check, cascade, or
refusal itself each turns it red.

Known gaps, stated rather than discovered:

- Messages are capped at MongoDB's own 48MB ceiling and malformed framing
  closes the connection. A length field arrives from the wire and this
  process allocates on it.
- TCP keepalive on both legs, and deliberately **no read timeout**: a
  MongoDB connection idles legitimately on an awaitData cursor, and a
  deadline would kill healthy connections and look like the cluster
  flapping.
- `SIGTERM` **drains**: stop accepting, let open connections finish, print
  what the process did. A second signal exits immediately.
- It picks **one node** and forwards bytes. It does not load-balance reads,
  honour read preference, or retry a write the client already saw fail —
  reach it with `directConnection=true` so your driver does not chase the
  hosts the cluster advertises straight past it.
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
