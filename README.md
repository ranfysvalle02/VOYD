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

## The part that surprised me

Once refusal is on the wire, it has to be **pure** — no database under it,
no I/O, documents in and the admissible ones out. That reads like a tax.
It turned out to be the most valuable property in the project, and it paid
twice.

**A policy change can be diffed before it ships.** A pure function can be
asked about a policy that is not deployed. `voyd-plan` asks it twice and
fails a pull request that widens the boundary — naming the documents, and
the role.

**Your reranker cannot leak.** Because the check is pure and cheap, it can
run *last*, always, after arbitrary page-shaping code:

```
pure rules  →  your transform  →  every rule, terminally  →  the wire
```

Reranking, de-duplication and caching have always lived *outside* the
boundary, and outside is what makes them dangerous — anything downstream
of a filter can undo it. Usually by accident: merging a cached list,
falling back to the unfiltered candidate pool because an empty page looked
like a bug. So they move inside, and the guarantee survives:

> **A transform cannot widen what a read returns.** Not because it was
> reviewed. Because the boundary is downstream of it.

There is a test that starts a real proxy with a policy whose transform
exists solely to inject forgotten facts, and reads through it with a
`pymongo` client that has never heard of this package. The transform is
not disabled, sandboxed or reviewed. It runs. It returns the documents.
They do not arrive.

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

Beside them, and deliberately not one of them:

| | |
|---|---|
| `@transform(collection)` | shape the page — rerank, de-duplicate, annotate — inside the boundary, where it cannot widen a read |

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

## Shaping the page, inside the boundary

A rule decides whether one document may reach a prompt. A **transform**
decides what the page looks like — what order, which of them, annotated
how. Reranking, de-duplication, a cache.

Those have always been a separate system, running after retrieval, and
that is what makes them dangerous rather than useful. A reranker
downstream of a filter can put back what the filter removed, and almost
never on purpose: it merges a cached list, or falls back to the
unfiltered candidate pool because an empty page looked like a bug, or
reorders a list it was handed by reference.

```python
# voydfile.py
rerank("notes", diversity=0.3)          # the one that ships

@transform("notes")                      # or your own, any code
class Diversify:
    name = "whatever you call it"

    def on_egress(self, docs, *, request):
        return my_reranker(docs)
```

`rerank()` is maximal marginal relevance. A vector index returns the most
similar documents, which on a real corpus means the most similar
documents *to each other* — ten chunks of one contract outranking one
chunk each from ten contracts:

```
index order        a0 a1 a2 a3 a4 a5    one cluster, six deep
diversity=0.0      a0 a1 a2 a3 a4 a5    exactly the index's order
diversity=0.7      a0 b0 c0 a1 a2 a3    one from each, then the rest
```

Relevance comes from **arrival order**, not from a query vector: a wire
boundary does not reliably have one, and every ranked page already
carries the index's own judgement. That makes this rank-based MMR rather
than the textbook form, which is a real technique and not the same one,
so it is named as what it is.

It runs **inside**:

```
pure rules  →  transform  →  every rule, terminally  →  the wire
```

The terminal pass is not a stage you compose. It is the last thing that
touches a document, always, and a transform cannot be placed after it
because there is nowhere after it. Everything a transform returns —
reordered, merged, restored from a cache, invented — is checked before it
leaves. So a transform may reorder, drop, annotate and even inject, and a
forgotten fact still cannot come out.

The first pass is a different argument: a transform is never *shown* a
forgotten fact. That is defence in depth, not the guarantee — code that
never receives a fact cannot mishandle it.

**A transform is not an enforcement point** and must never be written as
one. Dropping a document for a security reason here duplicates a rule
badly: the rule is what is re-asked terminally, and the rule is the half
`voyd-plan` can tell you about before you ship it. A transform gets no
credit and no attestation.

Two members, `name` and `on_egress`, checked at load the way a
half-written rule is. A transform that raises is skipped and its input
carried forward — the opposite of the decision for a rule, and for the
opposite reason: a rule that fails open is a leak, a transform that fails
open is impossible, and refusing a whole read over a broken reranker
would be an outage caused by an optimisation.

Cumulative rules are held back to the terminal pass, so a `budget()`
charges the page that is *served* rather than the one that was proposed
and then reranked down.

A collection with no transforms runs the loop it always ran.

**What it costs.** One laptop, 1024-dimension vectors, measured rather
than estimated:

```
                    page of 10   page of 50   page of 200
voyd[rerank]              ~2ms         ~2ms          ~9ms
pure Python               ~3ms        ~72ms      declines
```

NumPy is an accelerant, not a dependency. Without it the same arithmetic
runs in Python, and past a measured ceiling the transform **declines and
says so** rather than adding a second to every read — an optimisation is
not allowed to be the slow part.

---

## What a policy change would let through

Because the per-document check is pure — a function of a document, a spec
and a clock, with no database under it — it can be asked about a policy
that is not deployed. `voyd-plan` asks it twice and reports the difference:

```bash
voyd-plan --current voydfile.py --proposed voydfile.new.py \
          --target $URI --database app --all
```

```
the boundary moves, in the admitting direction
  notes  tenant_removed
    reads were scoped by 'tenant_id' and no longer are: a read can
    return documents belonging to any tenant

documents that become reachable
  notes  +9 of 200 read
           9  were refused as revoked

200 documents, read
newly reachable: 9
```

**The exit code is the product.** `1` when something becomes reachable, `0`
when nothing does — so a policy change that opens the boundary fails a pull
request and says which documents and why. A change that *closes* it exits
zero on purpose: a tool that blocked those would teach people to bypass it,
and a read path that got shorter is visible to whoever it refused.

Without `--target` it reports the structural half only, which needs no
cluster and no credentials: a `@guard` deleted, a `tenant()` dropped, a
`subjects()` array that stops being subjects. Those are facts about the
policy, so they are not weakened by a sample and do not disappear against
an empty collection.

**It refuses to answer three questions, by name.** `budget()` and
`distinct()` are set-relative — they refuse a document because of the other
documents on the page, and a sample is not a page — so they are set aside
and printed rather than evaluated one document at a time. `clearance()` and
`restricted_to()` decide by who is asking, so they are planned only against
a caller you name with `--as`. And the tenant is enforced by the handle
against the scope a read is bound to rather than by a rule, so a plan
reports that the boundary moved, not which rows crossed it. A plan that
quietly folded any of the three into a total would be this project's own
complaint, one level up.

`--at` runs the clock at another instant, which makes *"what would this
policy have refused last Tuesday?"* a real question — a deadline and a hold
are both functions of time. It moves the clock and not the data: nothing
here keeps history, and the documents are the ones on disk now.

### Before anything is installed

Two questions, two costs, and neither one is a deployment.

**"Where in my code is the hole?"** — costs nothing at all. The scanner
is a single stdlib file in its own distribution with no dependencies and
no import of this package, because the first thing a stranger runs must
cost them nothing:

```bash
python3 scanner/voyd_scan app/ services/
```

```
notes: `expire_at` (declared by a write or index); `forgotten` (declared by a write or index)

25 of 25 read(s) against them do not:
  refuse.py:79   notes  (filter does not name `expire_at`, `forgotten`)
  embed.py:163   notes  (filter does not name `expire_at`, `forgotten`)
```

It works out what the mark *is* rather than being told: a TTL index
names its own field, and beyond that, the fields most reads filter on
are the convention — so a field most reads name and some do not is a
deviation from your own spec. It gets **stronger on larger codebases**,
because the majority that establishes the convention is bigger.

**"How much is exposed right now?"** — costs a read-only URI. `--audit`
compares the cluster against *no policy at all*, so every document the
policy would refuse is a document reachable today:



The same arithmetic, asked about the present. `--audit` compares the
cluster against *no policy at all*, so every document the policy would
refuse is a document reachable right now:

```bash
voyd-plan --audit --proposed voydfile.py --target $READONLY_URI --all
```

```
reachable today, and refused by this policy

  records  1000 of 4100 read are reachable now and would be refused
         812  are past an expire_at the TTL monitor has not reached
         188  carry an erasure mark and are still being served
```

No proxy, no sidecar, no connection string changed, nothing in a query
path — a read-only credential and a batch job. That is only possible
because the check is a pure function: a boundary whose enforcement lives
inside a running process has nowhere to stand to ask this.

| what it costs you | what it tells you |
|---|---|
| nothing — one stdlib file | which reads in your code can serve a forgotten fact |
| a read-only URI | how many documents are reachable right now that should not be |
| one line in CI | what a policy change would let through, before it merges |
| one connection string | nothing gets out, in any language, ever again |

### In the place a policy is actually reviewed

A check nobody runs is a man page, so the plan ships as an action:

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }   # the policy in force is read out of git
- uses: ranfysvalle02/VOYD@main   # or a tag, which pins both halves
```

That is the whole configuration. The action installs `voyd` from its own
checkout rather than from PyPI, so pinning its ref pins the planner and
the policy vocabulary together — a voydfile that loads in the check has
to be one that loads at the boundary. It reads the voydfile at the pull
request's base, compares it to the one on the branch, posts the plan as a
comment it updates in place, and fails the job if the boundary opened. No
cluster and no secret: the structural findings are facts about the policy,
and they are the ones a reviewer is least equipped to see in a diff — a
`@guard` deleted is one removed line.

Add `target: ${{ secrets.MONGODB_URI }}` and the findings get document
counts beside them. `fail-on-open: false` makes it a reporter instead of a
gate, which is a reasonable way to adopt it and a bad way to keep it.

A plan that could not be *computed* — a voydfile that will not load — exits
2 and fails the job before anything is posted, whatever `fail-on-open`
says. A check that answered "nothing found" when it had not run is the one
failure this could have that would be worse than not existing.

### Whose access did it widen?

"The boundary widened" is the wrong granularity for a review. `--as-each`
takes a table of callers and plans the same change once for each:

```bash
voyd-plan --current voydfile.py --proposed voydfile.new.py \
          --target $URI --database app --all --as-each roles.json
```

```
per caller
  caller          newly reachable   examined
  tier1-support               412        824
  analyst                       0        824
  clinician                     0        824

what tier1-support gains
  records       412  were refused as not_cleared

newly reachable: 412 (worst caller: tier1-support)
```

The headline is the **worst** caller, not the sum: one document reachable
by four roles is one document that got out, not four, and a number that
grew when somebody added a read-only role to the JSON would be measuring
the role table. The data is read once however many callers there are —
not an optimisation, a correctness requirement, since a second role
handed an exhausted cursor reports zero and looks clean.

### A plan somebody can still believe next year

`--attest PATH` writes the result, the SHA-256 of **each policy file's
contents**, when it ran and what ran it. `--sign env:NAME` adds an
HMAC over the whole envelope.

```bash
voyd-plan --verify plan.att.json --sign env:VOYD_ATTEST_KEY \
          --current voydfile.py --proposed voydfile.new.py
```

```
intact:  digest and signature both check out
current: the attested policies are the ones on disk
attested 2026-09-22T13:38:39+00:00: fails_open=True, newly reachable=412
```

Four outcomes, and they are deliberately four rather than a boolean:

| | |
|---|---|
| **intact** | nothing has changed since it was produced |
| **edited** | the payload no longer matches its digest — caught with no key |
| **wrong key or altered** | the digest was recomputed; the signature was not |
| **stale** | intact, but a policy file has changed since. A different finding, and usually the more interesting one |

**What it proves.** That the envelope has not changed since something
holding the key produced it, and — via the digests — that it is a verdict
about the exact bytes of those two files.

**What it does not.** That the plan ran against a real cluster, that the
sample was representative, or who produced it. It is a symmetric MAC:
anyone who can verify can forge. Evidence of integrity, never of origin.
The key is taken as `env:NAME` or `file:/path` and never on the command
line, because `argv` reaches the process table and the build log.

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
package, the planner that asks it about a policy nobody deployed, the wire
codec, the custody rungs and the sweep below — need no
database at all, and CI runs them in a step with no `services:`. If that
step ever needs one, the boundary has stopped being pure.

The live tests drive a real `voyd-wire` in front of a real deployment with
a plain `pymongo` client that has never heard of this package, because the
claims are about queries and bytes and a mock would only prove the mock was
filtered. Between them they cover refusal (expired, revoked, off-scope, and
`delete` become a revocation, holding across every batch of a cursor); what
a driver *keeps* when its connection string points here (sessions and causal
consistency, transactions committed and aborted, several cursors interleaved
on one socket, eight clients paging at once, and a real election caused with
`replSetStepDown` and followed without a restart); the erasure a refusal
cannot perform (a key destroyed, and the ciphertext read back by a reader
that never held it); and a refusal travelling to what was made out of the
fact, children marked before the source.

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
back, so they need `pymongocrypt` — the `crypto` extra, and nothing else.
They deliberately do *not* need `crypt_shared` or `mongocryptd`: those are
for **automatic** encryption, where the driver must analyse a command to
learn which fields to encrypt, and this boundary has already parsed the
command and already knows. Gating them on the stricter question is how
they came to skip in CI, silently, on the claim this file leads with.

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
- `voyd-plan --at` replays the clock against today's documents. Answering
  it against the documents as they *were* needs history this package does
  not keep.
- A change stream over a guarded collection is **refused**, not
  filtered: a change event is not a document, and the rules read
  top-level fields. See [`docs/why-not-native.md`](docs/why-not-native.md).
- A transform cannot widen a read, and that is the only promise made
  about one. It can still be slow, wrong, or expensive, and nothing here
  bounds how long somebody's reranker runs inside the egress path.

MIT.
