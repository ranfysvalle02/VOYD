# VOYD

**Ranking is not permission.**

A vector index scores relevance. Nothing in an ordinary retrieval path is
ever asked the other question — *may this fact reach a prompt?* — so a
search answers with a confident score and no opinion about whether the hit
was allowed to be there: an expired row the sweeper has not reached, a fact
somebody revoked this morning, a vector from a model that was swapped.

Every other data path in a mature stack solved this years ago. HTTP has
middleware. SQL has views and row-level security. The filesystem has
permission bits the kernel checks whether or not you remembered to ask.
Retrieval has a ranking function and a hope, so the missing answer gets
reimplemented inside every query — a tenant filter here, an `expire_at`
clause there, once per call site, per service, per language, forever.

**The failure is silent in the worst possible direction.** A missing
authorization filter returns *more* documents, not fewer. It does not raise,
it does not log, and on a retrieval workload it reads as better recall.
There is no error to page on and no test that naturally fails.

Deleting the row does not close it either. MongoDB's TTL monitor runs about
once a minute; an object-lifecycle rule runs about once a day. In that
window the document is genuinely still on disk and is returned, correctly,
as a well-scored result. A faster index does not help and a faster sweeper
only narrows it.

    deletion   a storage event      eventually consistent, by nature
    refusal    a retrieval promise  immediate, by construction

VOYD is the second one, placed where it cannot be bypassed: **the wire**.

---

## No code

```bash
pip install voyd        # or: uv add voyd
```

You get one command, `voyd-wire`, and the vocabulary to write the file it
reads. There is nothing here for an application to import.

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
voyd-wire --config voydfile.py --target localhost:27017
```

Then change one connection string. **That is the whole integration.** No
import is added to your application, no handle replaces a collection, no
read path is rewritten, and nobody has to remember anything. A driver in any
language — Python, Node, Compass, a notebook — cannot read a forgotten fact,
because the boundary binds the *connection* and there is nothing to reach
past.

Your credentials stay yours. The boundary forwards the handshake and then
asks the *deployment* who authenticated — it does not authenticate on your
behalf and does not believe a claim a client asserts, because a rule whose
only input is the caller's own assertion is not an authorisation system. So
a client connecting to the boundary carries exactly the credentials it would
have carried to the cluster.

Reach it with `directConnection=true`, or run it with `--advertise-self`;
without one of the two your driver reads the cluster's own host list and
connects straight around it. Without `--tls-cert` it binds loopback only,
which is a decision rather than a default: a plaintext boundary reachable
from a network would carry in the clear every document it had just refused
to serve.

---

## What a read gets

An expired document and a revoked one stay exactly where they are. The
boundary does not delete them and does not wait for anything to:

```
around the boundary   5 documents on disk
through the boundary  2 — the expired and the revoked are refused,
                          and the other tenant was never in scope
```

And the verb already in everybody's code gets the better meaning, if you ask
for it. `on_delete="revoke"` turns a client's `deleteOne` into a mark:

```
db.notes.delete_one(...)  -> deleted_count=1   (the driver is satisfied)
reachable now             the row is gone from every read
rows on disk              unchanged — nothing was destroyed
the deadline              pulled in, so the reaper collects the bytes
                          on the schedule they already had
```

A credential you need out of prompts *now* and on disk *for the
investigation* are contradictory requirements for `DELETE` and the same
requirement for this. It is opt-in, because silently redefining `delete` for
an operator who did not ask is the kind of surprise this project exists to
remove — and declaring it without a `revocable()` field is refused at load,
since there would be nowhere to record that the fact was forgotten.

---

## The vocabulary

| in a `voydfile` | means |
|---|---|
| `deadline()` | this field holds the instant after which the fact is gone |
| `revocable()` | a mark an operator sets to forget it *now*, irreversibly |
| `holdable()` | the reversible kind: a hypothesis, not an instruction |
| `tenant()` | the tenant id — required in a reduction *and* checked per document |
| `restricted_to(claim)` | admit only callers whose claim overlaps this audience |
| `clearance(order, roles)` | an ordered ladder, the caller's rung read from their roles |
| `subjects(key=...)` | an array whose elements are subjects in their own right |
| `embedded_with(model)` | refuse a vector produced by a different model |
| `budget(n)` | refuse once the prompt has no room left |
| `distinct()` | refuse a repeat of content already on the page |
| `sealed()` | ciphertext at rest, under a key scoped to the tenant |
| `auto_embed(model)` | the *server* embeds this text; refuse a client's own vector |

`budget(n)` and `distinct()` are **set-relative**: they refuse a document
because of the *other* documents on the page, so the same document is
admitted alone and refused in company. No index filter and no policy engine
can express that — `$vectorSearch` decides each candidate before the page
exists, and `enforce(subject, object, action)` has nowhere to put the rest
of the set.

**A rule is a protocol, not a list.** Three members — `reason`,
`refuses(doc)`, `clause()` — and a stranger's rule is a first-class one,
written directly in the policy file beside the builtins:

```python
@guard("notes")
class Notes:
    expire_at = deadline()
    region    = Jurisdiction(allowed="eu")     # your dataclass, not ours
```

Anything in a class body that is *half* a rule raises at load, by name. The
two ways to get the protocol wrong are to omit a member and to misspell one,
and from the loader they look identical — a skipped rule would mean a
boundary that comes up announcing what it refuses while serving everything
the rule was written to stop.

A policy file that is wrong fails when it is **loaded**, not when somebody's
query returns the wrong rows.

---

## Two enforcement points, and only one of them is the guarantee

Each rule is pushed into the query where a query can express it, and
re-checked per document on the way out.

The second one is the promise. A `$vectorSearch` hit **does not pass through
the collection query**, so every pushed-down clause in this package is an
optimisation — the database doing cheap work — and none of them is the
boundary. The per-document check is what every read path ends at, including
the search path, and it is pure: no database, no connection, no I/O. That
purity is not an aesthetic; it is what lets the same check run inside a wire
proxy at all.

The asymmetry only runs one way. A rule with no query half is slower. A rule
with *only* a query half would be a hole.

---

## The server owns the encoding

An embedding is not a vector, it is a `(vector, model)` pair, and a vector
without its model is an orphan. Comparing orphans does not fail — it returns
a number between -1 and 1. Measured against a real embedding API, the same
text, both 1024-wide, two generations of one vendor's model:

```
identical text, old model vs new       cosine -0.053
unrelated text, both on the new one    cosine +0.301
```

A model swap does not degrade ranking, it inverts it: unrelated text scores
five times higher than the document you were looking for, with no error and
no log. `embedded_with(model)` refuses the *document*. `auto_embed(model)`
removes the way it comes to be wrong — the index holds text, mongot embeds
it on write and embeds the query with the same model at read time, so
nothing in your process ever computes a vector and nothing can drift from
the index.

A client that sends its own `queryVector` at that collection has put the
embedder back, through a driver that never read the policy file. The
boundary refuses it by name and says which form works instead.

---

## The erasure refusal cannot perform

Refusal binds *this* read path, so it has nothing to say about a replica, a
snapshot, or the backup somebody restores next year — none of those run it.
`sealed()` is how a field opts into being destroyable instead: ciphertext at
rest under a key scoped to the tenant, so destroying the key makes every
copy unreadable at once.

    refusal          immediate            this application's read path
    crypto erasure   ~60s (key cache)     every copy that exists anywhere
    the TTL reaper   ~60s (measured)      this deployment's disk

Each one's window is the other's guarantee, which is the argument for having
both rather than choosing. The boundary orders them accordingly: unreachable
first, unreadable second.

`sealed()` without `tenant()` is refused at load. A scope with no name is
one key for the whole collection, and destroying it to forget one subject
would take every other tenant's rows with it.

---

## Running the tests

```bash
uv sync --all-extras
uv run pytest -q -m 'not needs_mongo'   # the pure half: no database, ~0.2s
uv run --extra crypto pytest -q         # including the erasure path
docker compose up -d mongo              # a real mongod and a real mongot
uv run pytest -q                        # everything except `slow`
uv run pytest -q -m ""                  # everything
```

The pure files — the per-document check, every decision in the policy
package, the wire codec, the custody rungs and the sweep below — need no
database at all, and CI runs them in a step with no `services:`. If that
step ever needs one, the boundary has stopped being pure.

The live files drive a real `voyd-wire` in front of a real deployment with a
plain `pymongo` client that has never heard of this package, because the
claims are about queries and bytes and a mock would only prove the mock was
filtered. One covers refusal — expired, revoked, off-scope, `delete` become
a revocation, across every batch of a cursor. The other covers what a driver
*keeps* when its connection string points here: sessions and causal
consistency, multi-statement transactions committed and aborted, several
cursors interleaved on one socket, eight clients paging at once, and a real
election caused with `replSetStepDown` and followed without a restart.

They need a cluster, which they find in `VOYD_TEST_MONGO_URI`,
`VOYD_MONGO_URI` or a `.env` beside the compose file; with none of those they
skip by name rather than passing quietly. The failover test needs the
three-node set — `docker compose up -d rs` — because Atlas Local is a single
node, so every routing assertion against it would pass by having nowhere
else to go.

Every live test works in a database named `voyd_test_<epoch>_<uuid>` and
drops it on the way out whatever happened — including the failures, since a
cleanup that only runs on the happy path stops running exactly when a test
starts leaving rows behind. The epoch in the name is what lets each run also
sweep databases abandoned by an earlier one, bounded to a two-hour window so
it can never reach a suite running concurrently on the same cluster.

The erasure tests destroy a real key and then try to read the ciphertext
back, so they need `pymongocrypt` and either `crypt_shared` or
`mongocryptd` — neither of which is on PyPI. `voyd.engine.keyring.
available()` is asked rather than assumed, and they skip by name when the
answer is no, because a suite that passed silently without encryption
would be reporting on the feature that matters most while testing none of
it.

`auto_embed` against a cluster that really embeds is marked `slow` and reads
`VOYD_ATLAS_URI`. Atlas Local registers no model, so it *declines* the
declaration and falls back to an ordinary vector index — a different
outcome, not a weaker one, and a test that accepted the fallback would
assert the opposite of what it claims.

---

## When you do not need this

- One service, one language, one read path, one person maintaining it. The
  filter in your query is the same guarantee and one fewer process.
- No deadlines, no revocation, no tenants — nothing to forget.
- A retrieval path that does not reach a model, where a wrong row is a bug
  rather than a disclosure.

The case for a boundary starts at the second read path, and it compounds at
the second language.

---

## Known gaps

- **Nobody has run this but its author.** Every number here comes from this
  repository's own benchmarks on one machine and one cluster.
- A boundary is a process, so it is a hop, a thing to deploy, and a thing
  that can be down. It follows a failover and re-resolves on the server's
  own `NotWritablePrimary`, but it is not a replacement for your driver's
  topology.
- A sealed read decrypts before it refuses, which costs the boundary its
  purity: holding keys makes it a custody holder.
- No policy file can see an index created somewhere else. `sealed()` on a
  field that an Atlas index auto-embeds is a contradiction nothing here can
  detect.

MIT.
