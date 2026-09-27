# VOYD

[![PyPI](https://img.shields.io/pypi/v/voyd)](https://pypi.org/project/voyd/)
[![Python](https://img.shields.io/pypi/pyversions/voyd)](https://pypi.org/project/voyd/)
[![License](https://img.shields.io/pypi/l/voyd)](LICENSE)

----

a full MongoDB wire-protocol proxy implementing admission control, TTL/expiry, masking, sealing, delegation, attestation, and MCP recipe tooling 

----

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

Read [`Known gaps`](#known-gaps) first — it's the exact list of what
to check before you rely on it, and most of it is a command away from
verifying against your own cluster.

You get four commands — `voyd-wire`, `voyd-plan`, `voyd-wire-health`,
`voyd-verify` — and the vocabulary to write the file they read. There is
nothing here for an application to import; `voyd.attest` is for whoever
*checks* what an application was served.

New here? [`quickstart.md`](quickstart.md) is twenty minutes, and the
first step costs nothing at all.

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
| `distinct()` | refuse a repeat of content already on the page |
| `sealed()` | ciphertext at rest, under a key scoped to the tenant |
| `auto_embed(model)` | the *server* embeds this text; refuse a client's own vector |
| `sanitized(on_match=...)` | text for a model: invisible characters removed (exact), instruction-shaped signatures refused or cut (a tripwire, not a guarantee) |
| `mask(strip=, visible_to=)` | admit the document, serve this field as null (or not at all) |

Beside them, and deliberately not one of them:

| | |
|---|---|
| `@transform(collection)` | shape the page — rerank, de-duplicate, annotate — inside the boundary, where it cannot widen a read |
| `rerank(collection, ...)` | the built-in one: maximal marginal relevance, so ten chunks of one contract stop crowding out nine other contracts |
| `@stage(name)` | an aggregation stage mongod does not have, run by the boundary on admitted documents when a pipeline names it |
| `@operator(name)` | an expression operator mongod does not have, used as a whole field value of `$addFields`/`$set`, per admitted document |
| `@recipe(name, collection=)` | a named pipeline a client calls with `{$recipe: {name, params}}`; typed parameters are values, never names, and `@guard(..., recipes_only=True)` makes recipes the only way to read |
| `issuer(url, audience=, jwks=, connection_users=)` | whose delegated tokens the boundary believes: an agent's read carries one in `comment={"voyd": token}` and is judged as the user *and* the agent; `@guard(..., scope=, delegation=)` sets a collection's terms |

None of them is an enforcement point. A rule is what the terminal pass
re-asks and what `voyd-plan` can reason about; a transform gets no
credit for filtering and no attestation. See [`ethos.md`](ethos.md).

**`mask()` rewrites a value instead of refusing a document.** A contract
is readable and its counterparty's tax id is not:

```python
@guard("contracts")
class Contracts:
    expire_at = deadline()
    tenant_id = tenant()
    ssn       = mask()                      # served as null
    internal  = mask(strip=True)            # the key is removed
    salary    = mask(visible_to=("hr",))    # null unless the caller's roles hold hr
```

The field is rewritten in the reply bytes after every rule and after every
transform, so a transform cannot put a masked value back — whatever it
returns is masked again on the way out. A command that names a masked
field where a value can come from is refused before it is sent: a filter
(`{ssn: "..."}` is a yes/no about the value), a sort, `distinct("ssn")`, a
`$group` or `$project` that reads `"$ssn"`, `$$ROOT`, `$getField`, `$text`,
a server-side update that copies it, and an `explain` of any of those.
Excluding it — `{ssn: 0}`, `$unset` — is always allowed, and so is writing
it. `findAndModify` is allowed only with a `fields` projection that removes
it, because its reply is not a cursor. Masked values are counted as
`masked_total` in `/metrics` and in a handle's `receipts()`, apart from
refusals: nothing was refused. `visible_to` reads the caller's roles from
the server, never from the client, and an unidentified caller sees the mask.

Top-level fields only — the attribute name is the path. Mask the parent of
a nested value; elements of a `subjects()` array are not masked one by one.

`distinct()` is **set-relative**: it refuses a document because of the
*other* documents on the page, so the same document is
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

### Text that talks to the model

A stored chunk can carry instructions aimed at whatever reads it:
"ignore previous instructions" on a scraped page, a zero-width or
tag-block payload a reviewer cannot see, an HTML comment that vanishes
when rendered, a markdown image whose URL sends the conversation to
somebody else's server. `sanitized()` marks a field as text for a model:

```python
@guard("notes")
class Notes:
    text = sanitized()                                   # refuse on a match
    body = sanitized(on_match="neutralise",              # cut the match
                     patterns=[("wire_money", r"wire \$\d+ to")],
                     without=["html_comment"])
```

It makes two claims, and they are not equally strong.

**Invisible characters are removed, exactly.** Zero-width characters,
bidi overrides and the Unicode tag block are code points in known ranges,
so this is a fact about bytes. None of them leaves a declared field. The
cost is typographic: emoji joined with ZWJ come apart into their members,
and ZWNJ-shaped scripts render differently.

**Signatures are a tripwire, not a guarantee.** Five built-in patterns
catch the copy-pasted shapes, and your own are added in the voydfile. The
invariant is exact *about the list*: no text that leaves matches a declared
signature once invisibles are removed and the text is NFKC- and
case-folded. A paraphrase, another language, or an instruction split
across two chunks is not on the list and goes through. A document that
*quotes* an injection to discuss it is matched like one that carries it,
because a pattern cannot tell quotation from use.

Under `neutralise`, a match found only by folding (full-width letters) has
no exact span to cut, so that document is refused instead. It runs in the
terminal pass, after every transform. `distinct`, `count` and reducing
pipelines on the collection are refused, because they return the text
without the document it came from. Refusals count under
`injection_signature`; rewrites count in `neutralised_total`.

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

### A short page is filled from further down the ranking

Refusing on the way out has a cost the client can see: `limit: 10` over a
collection whose nearest rows are mostly expired comes back with two.
Deadlines are deliberately not pushed into the vector index (see
[`voyd/engine/search.py`](voyd/engine/search.py)), so the index cannot skip
them itself.

So a lone `$vectorSearch` on a guarded collection is over-fetched. The proxy
multiplies `limit` and `numCandidates` by the collection's `backfill`
factor, judges the wider page exactly as it judges any batch, and only then
cuts it back to the `limit` the client sent:

```
limit: 10, 8 of the 10 nearest expired
backfill=1          2 documents
backfill=4          10 documents, in the index's score order
```

```python
@guard("notes", backfill=4)     # the default; 1 is off, 20 is the ceiling
```

The cut runs after the terminal pass and only removes, so it cannot put a
refused document on the wire and no page is longer than the client asked
for. It spans `getMore`, so a small `batchSize` gets the same page. A
transform sees the wider page — a reranker choosing from forty candidates
rather than ten — and the cut keeps the first `limit` of its order.

Only the **lone** stage is widened. `$match`, `$sort`, `$skip`, `$limit`,
`$sample` or anything else after the search means something different over
forty candidates than over ten, so those pipelines go out as sent, and a
reduction (`$group`, `$project`, `$count`) has the refusal pushed into it
instead. Both are capped at 10,000, the most Atlas accepts. If more than
three quarters of a widened page is refused, the page is short, exactly as
it is without backfill; the factor is paid on every lone vector search,
refused rows or not.

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

Cumulative rules are held back to the terminal pass, so `distinct()`
keeps the first copy on the page that is *served* rather than on the one
that was proposed and then reranked.

A collection with no transforms runs the loop it always ran.

**What it costs.** One laptop, 1024-dimension vectors, measured rather
than estimated:

```
                    page of 10   page of 50   page of 200
voyd[rerank]              ~2ms         ~2ms          ~9ms
pure Python               ~3ms        ~72ms      declines
```

NumPy is an accelerant, not a dependency — `pip install voyd[rerank]`.
Without it the same arithmetic runs in Python, and past a measured
ceiling the transform **declines and says so** rather than adding a
second to every read: an optimisation is not allowed to be the slow
part.

---

## Stages mongod does not have, run on what was admitted

A policy file can add pipeline vocabulary. `@stage` declares a stage and
`@operator` an expression operator; any driver, `mongosh` or Compass then
uses them in an ordinary `aggregate`, mixed with native stages:

```python
# voydfile.py
@operator("$wordCount")
def word_count(doc, args, ctx):          # once per admitted document
    return len(str(args).split())

@stage("$stats")
def stats(args, docs, ctx):              # once, over the admitted set
    ctx.publish(args["as"], {"n": len(docs)})
    return docs
```

```js
db.manuals.aggregate([
  { $match: { tenant_id: "acme" } },                     // mongod
  { $addFields: { words: { $wordCount: "$text" } } },    // the boundary
  { $stats: { as: "corpus" } },                          // the boundary
  { $match: { $expr: { $gt: ["$words", 50] } } },        // mongod, on a temp
  { $sort: { words: -1 } },                              // mongod, on a temp
])
```

The pipeline is split at its virtual steps, and the order is the guarantee:

```
native prefix   →  the server, on the client's connection
                →  every rule, sanitized(), mask()       (the ordinary egress)
virtual step    →  the boundary, on admitted documents only
                →  every rule again, on what it returned
native suffix   →  mongod, on a temporary collection of that output
                →  every rule again, on what carries a source _id
                →  the client, as one batch
```

**A refused document never reaches a stage or an operator.** The prefix is
drained through the same check a `find` goes through, so a step is handed
what this caller would have been served, field for field — masked values
already null, `sanitized()` text already neutralised, and the expired,
revoked and cross-tenant rows simply absent.

**A step cannot widen a read.** It may add fields, drop documents and
reorder them. Every document it returns is traced by `_id` to one it was
handed, at most as many times as it was handed; the rest are dropped. What
survives is judged again with the fields the verdict reads put back from
the admitted source, so a step cannot erase a mark, move a deadline or
change a tenant on the way out.

**Earlier outputs are ordinary inputs to later steps.** A field an operator
sets is a field: a later operator reads it by path (`{"$redactEmails":
"$summary"}`), a native `$match`, `$sort` or `$group` on the temporary
collection filters on it. A stage can `ctx.publish(name, value)` — corpus
statistics, an idf table — and every later step reads it as
`$$name.field`: resolved in a virtual step's arguments, and passed as `let`
to the native suffix. It is computed over admitted documents, so a pipeline
variable carries nothing a refused row contributed. In virtual steps
`$$NOW` (and `ctx.now`) is one instant for the whole read; in the native
suffix it is the server's.

**Operator arguments** arrive resolved: `"$field"` is that document's
value, `"$$name"` a published value, `{"$literal": x}` is `x` untouched. An
operator runs only as the whole value of one field in `$addFields`/`$set`,
beside field paths, variables and literals. Anything richer that contains
a registered operator is refused; so is setting `_id` or a dotted field.

**The native steps after a virtual one run in mongod**, on a temporary
collection, because mongod is the only engine that runs `$group` or
`$setWindowFields` exactly. The prefix is never `$out` into one — that would
copy refused documents somewhere no policy guards. What is written is what
a virtual step produced from admitted documents and nothing else, stored
in arrival order so a ranking survives, and dropped in a `finally`. A
pipeline that ends in a virtual step creates nothing.

**Reductions after a virtual step are safe, and before one they are not.**
A `$group` *before* the first virtual step is refused, because its output
has nothing left on it to judge. After one, it runs over a collection
holding only admitted, masked, neutralised documents, so whatever it
counts is a function of what this caller was allowed to see — the
reduction a refused `aggregate` tells a client to do "on your side", done
on the client's side of the boundary.

**The temporary namespace is a database of its own**, `__voyd_tmp` by
default (`--virtual-db`). Collection names are
`t_<instance>_<unix seconds>_<uuid>`. Every proxy sweeps it at startup and
every so often, dropping any collection older than `--virtual-max-age`
(600 seconds) — its own and a crashed instance's alike — and drops nothing
whose name it did not make, and nothing in any other database. No command
naming that database is served through the boundary: not a `find`, an
`aggregate`, a write, a change stream, `listCollections`, or a
`renameCollection` out of it. `listDatabases` still shows its name, which
carries an instance id, a time and a uuid and nothing else.

**The connection it runs on is the boundary's own**, opened per worker
from the same `--target` URI and credentials. Not the client's session:
the client may address nothing in that database, and the boundary's
housekeeping has no business inside a transaction the client is running.

Refused outright, with an error the driver raises: `explain` of a pipeline
with a virtual step; `$lookup`, `$unionWith` and `$graphLookup` anywhere;
`$out` and `$merge`; after a virtual step, any stage that reads something
other than its input (`$collStats`, `$currentOp`, `$documents`,
`$vectorSearch`, …), because the suffix runs with the boundary's
credentials; a virtual step on an unguarded collection or on
`aggregate: 1`; on a `tenant()` collection, a pipeline whose prefix does not
`$match` one tenant. More than `--virtual-max-docs` (1000) documents at any
step is an error, never a truncation, and a step that raises fails the
read with no partial result. A pipeline naming no registered name is
forwarded untouched, and so is an unregistered `$foo`, which mongod
answers as it always would.

**VOYD never holds model credentials and never calls a model.** A stage is
local, deterministic code in your policy file — chunking, counting,
redacting, ranking. The boundary guarantees what context the client
*receives*; the client owns inference, with its own key, on what it was
served. [`examples/virtual_stages.py`](examples/virtual_stages.py) chains
all of the above against a live, an expired, a revoked and another
tenant's document, and then builds the prompt on the client side.

### A library of them, installed in one line

`voyd.contrib` ships ready-made operators and stages, all local,
deterministic, standard-library Python:

```python
# voydfile.py
from voyd import contrib
contrib.install()          # or: from voyd.contrib import rank; rank.install("$bm25")
```

- `voyd.contrib.text` — `$redactPII` (emails, Luhn-checked cards, SSNs,
  IPs, phones), `$chunk`, `$wordCount`, `$tokenEstimate`, `$truncate`,
  `$highlight`, `$normalizeWhitespace`
- `voyd.contrib.rank` — `$bm25`, `$mmr`, `$dedupe`, `$freshness`, `$rrf`
- `voyd.contrib.context` — `$contextPack` (a token budget), `$cite`,
  `$stats`

`install` registers through `stage` and `operator`, so a duplicate name
fails the load like any other. The catalogue, with a snippet for each,
the limits, and runnable scripts, is
[`examples/operators/README.md`](examples/operators/README.md).

---

## Recipes: a named pipeline, reviewed once, called by name

A SQL view for retrieval. The pipeline lives in the policy file, beside the
rules; the client names it and hands over values:

```python
# voydfile.py
@guard("tickets", recipes_only=True)
class Tickets:
    expire_at = deadline()
    tenant_id = tenant()

@recipe("support_context", collection="tickets")
def support_context(q: str = "refund", k: int = 8):
    return [
        {"$vectorSearch": {"index": "v", "path": "embedding", "query": q,
                           "numCandidates": k * 10, "limit": k}},
        {"$addFields": {"clean": {"$redactPII": "$text"}}},  # an @operator
    ]
```

```js
db.tickets.aggregate([{ $recipe: { name: "support_context",
                                   params: { q: "refund", k: 5 } } }])
```

**Expansion is the first thing the boundary does with the message.** Before
the masked-reference check, the virtual-stage split, the derived-read
push-down, the prefilter and the backfill. What reaches them is
byte-for-byte the aggregate a client would have sent had it written the
expansion by hand, so a recipe gets every guarantee that pipeline gets and
meets every refusal it would meet: a recipe that groups on a masked field is
refused, a recipe ending in `$count` has the rules pushed into it.

**Parameters are data, never code.** A value must match the function's
annotation — `str`, `int`, `float`, `bool`, `list[str]`, each optionally
`| None` — so a document such as `{"$where": ...}` cannot arrive as one. A
string beginning with `$` is refused outright, because in an expression it
would be a field path (`"$ssn"`) or a variable (`"$$ROOT"`); wrapping it in
`$literal` is right in an expression and wrong in a `$match`, and which one a
parameter lands in is a fact about the recipe's code the boundary does not
guess. Values reach the recipe only as keyword arguments. The returned
pipeline is then checked again: one-key stages, no `$out`, `$merge`,
`$changeStream`, `$where`, `$function` or `$accumulator`, and every key and
every `$`-string in it must already appear in an expansion declared at load.
A parameter may change a value and never a name, so `{field: q}` or
`"$" + field` built from a parameter is refused unless a declared sample
produced that exact name. Unknown, missing and mistyped parameters are
driver errors naming the parameter.

**Only `$limit` and `$skip` may follow `$recipe`**, and it must be the first
stage. The `aggregate` must name the recipe's collection, and may not carry
`let` or `explain`.

**`recipes_only=True`** makes the recipes the only way to read the
collection. `find` (by `_id` too), `aggregate`, `count`, `distinct`,
`mapReduce`, their `explain`, and any `$lookup`/`$unionWith`/`$graphLookup`
reaching it from another collection are refused unless they arrived as a
`$recipe`. An application that fetches by id declares that as a recipe too
— `{"$match": {"$expr": {"$eq": ["$_id", {"$toObjectId": id}]}}}` — and then
that read has one reviewed home as well. Writes, `getMore` and
`killCursors` are unaffected.

**Checked at load:** a duplicate name, a non-callable, a parameter that is
unannotated, `*args`, or of another type, a default or sample of the wrong
type, a required parameter with no value in `samples=`, an expansion that is
not a pipeline or names a stage neither MongoDB nor an `@stage` has, a
recipe on a collection with no `@guard` (refused: nothing would govern it),
and `recipes_only=True` with no recipe.

**A recipe is part of the policy.** `voyd-plan` compares recipes by name
and reports `recipe_added`, `recipe_removed` and `recipe_changed` with the
stage lists of the declared expansions; none of those fails open, since the
expansion still meets every rule. `recipes_only_removed` fails open.

**A recipe can be granted to agents.** `actors=` and `scopes=` make it
runnable only by a delegated identity (see the next section) whose actor's
mapped id is listed and whose token holds at least one listed scope; when
both are given, both must hold:

```python
@recipe("support_context", collection="tickets",
        actors=("support-bot",), scopes=("tickets:read",))
def support_context(q: str = "refund", k: int = 8): ...
```

A plain read of a granted recipe is refused, and so is an agent it does
not name, each with the condition that failed. With `recipes_only=True` a
collection's whole agent surface is a reviewed list of pipelines, each
granted to named agents. A grant written as one string, a grant with no
`issuer()` to verify the identity it names, and a grant on a
`delegation="forbidden"` collection are refused at load.
`voyd.wire.policy.recipes_for(identity, guards)` returns the recipes a
caller may run — the collection's `delegation=` and `scope=` and the
recipe's grant, asked by the same functions the wire asks — which is what
`voyd-mcp` lists as tools. `voyd-plan` reports `recipe_grant_widened` (an
actor or scope added, a condition or the whole grant dropped) as fail-open
and `recipe_grant_narrowed` as not; a change that does both reports both.

**Each recipe has a version**: twelve hex characters of a SHA-256 over its
name, collection, source and declared expansions, and its grant when it has
one. It is printed at startup
(`recipes [support_context@3f9c0a1b2d4e(q: str = 'refund', k: int = 8)]`),
in each verbose expansion line, and as the `version` label of
`voyd_recipe_reads_total{collection,recipe,version}`, so an audit can say
which revision of a pipeline served a read.
[`examples/recipes.py`](examples/recipes.py) runs one through pymongo and
shows an injection and an ad-hoc read refused.

---

## An agent reads as two callers at once

An agent reads *for* somebody. It runs as a service account that can see
everything, because it serves everyone, and the user it is acting for this
second is a fact the database never hears about. So the boundary hears it
instead: the agent passes the delegated token its runtime already holds,
in the one field every driver forwards verbatim.

```python
# voydfile.py
from voyd import guard, issuer, mask, restricted_to, tenant

issuer("https://login.example.com",
       audience="voyd://prod",
       jwks="https://login.example.com/.well-known/jwks.json",
       connection_users=("svc-agent",),       # who may present these tokens
       roles="https://example.com/roles", tenant="org",
       actor_roles="act.roles")

@guard("notes", scope="notes:read")
class Notes:
    org      = tenant()                 # the principal's, pinned into the query
    audience = restricted_to("roles")   # the user's roles AND the agent's
    salary   = mask(visible_to=("hr",)) # unmasked only if both are hr
```

```python
# the agent, on one pooled connection, for whichever user it serves
notes.find({"topic": "refund"}, comment={"voyd": token})
```

**Verified, not believed.** The token is a JWT signed with `RS256`,
`ES256` or `EdDSA`; `none` and every `HS*` are refused at load and on the
wire, and the key a `kid` names must be the kind of key the header's
algorithm uses, which closes the public-key-as-HMAC-secret confusion. `iss`,
`aud`, `exp`/`nbf` (with a declared `skew`) and — for
`delegation="required"` — the `act` claim are checked by a pure function,
`voyd.engine.delegation.verify(token, keys, now, expected)`. Keys come from a
JWKS file or an `https://` URL fetched at startup and every `refresh`
seconds off the request path; an unknown `kid` is a refusal, never a fetch,
and keys older than `max_age` refuse every delegated read until a refresh
succeeds.

**Stripped before it is forwarded.** The token is taken out of the command
(and out of an `explain`'s inner command and every `getMore`) before the
bytes go upstream, so it never reaches a server log, the profiler or
`currentOp`. The comment has to be exactly `{"voyd": token}`; a comment
that is a string or a document without `voyd` is the client's own and is
forwarded untouched.

**The intersection by default.** A rule that reads the caller asks both
sides of a delegated read:

| rule | a delegated read is admitted when |
|---|---|
| `restricted_to("roles")` | the principal's roles **and** the actor's each overlap the audience |
| `clearance(order, roles)` | the **lower** of the two rungs clears the label |
| `mask(visible_to=...)` | the principal **and** the actor are each in the audience |
| `tenant()` | the document is the principal's tenant, and an actor that carries a tenant carries the same one |

`via="principal"` or `via="actor"` asks one side on purpose
(`restricted_to("roles", via="principal")`, `mask(..., via="actor")`,
`tenant(via="principal")`), and `voyd-plan` reports it. Push-down uses the
intersected values, so a `count`, a `$group`, a blinded projection and a
prefilter keep working; the principal's tenant is pinned into the query
itself, and a query naming another tenant is refused.

**The connection is narrowed, never widened.** A plain connection is judged
exactly as before: its principal is the server-reported user and it has no
actor. A request-level identity is accepted only on a connection whose
server-reported user the issuer names in `connection_users` (`("*",)` is any
connection, written out). A cursor keeps the identity that opened it: a
`getMore` continues as that identity, and one presenting a different
principal or actor is refused.

**A collection sets its terms.** `@guard(..., scope="notes:read")` refuses a
delegated read whose token was not granted the scope, naming it.
`delegation="required"` refuses a plain read and a user's own token (no
`act`); `delegation="forbidden"` refuses every agent. Writes take no
delegated identity at all. `voyd-plan` reports `delegation_loosened`,
`scope_removed`, `scope_changed`, `via_narrowed_to_one_side` and
`issuer_added` as fail-open, and their narrowing counterparts as not.

### The connection can be the token: `MONGODB-OIDC`

A driver that authenticates with `MONGODB-OIDC` hands the boundary a token
in `saslStart`, and the application changes nothing but its connection
options:

```python
MongoClient("mongodb://voyd-wire:27099/?directConnection=true",
            authMechanism="MONGODB-OIDC",
            authMechanismProperties={"OIDC_CALLBACK": callback})
```

```
voyd-wire --config voydfile.py --oidc=terminate      # or --oidc=passthrough
```

The token is read out of the SASL payload (`{jwt: ...}`; a human flow's
`{n: ...}` principal step is answered with the issuer, when the policy
declares exactly one), verified with the same `verify`, and **binds the
connection**: every read on it is delegated as that identity, with no token
in the `comment`, and meets the collection's `delegation=`, `scope=` and
tenant pin exactly as a `comment` token would. A `comment` token on a bound
connection may only narrow it — the same issuer, principal, tenant, and
actor if the connection has one; roles, groups and scopes intersected —
and anything else is refused (`voyd.engine.delegation.narrow`). A token
that is not believed is `AuthenticationFailed` (18).

    terminate     the boundary answers the conversation itself; the
                  deployment never sees the token or the user. Upstream
                  it is itself: unauthenticated, or SCRAM-SHA-256 with the
                  credentials in --target, the server's signature checked.
                  Before authenticating, only the handshake, ping and
                  buildInfo are answered; after, a connection may read
                  (find, aggregate, count, distinct, getMore, killCursors,
                  explain, listCollections, listIndexes) and nothing else,
                  because anything else would run with the boundary's own
                  credentials. An expired token answers the next command
                  with ReauthenticationRequired (391), and the driver calls
                  its callback again.
    passthrough   the conversation continues to the deployment, which
                  validates the token too (Atlas workload identity). A token
                  the boundary does not believe is refused without being
                  forwarded. After the server accepts one, and before the
                  next command goes anywhere, connectionStatus must report
                  the user issuer(..., server_user="idp/{principal}") names
                  for the token's principal, in $external -- or the
                  connection is closed.

Speculative authentication is removed from the handshake in both modes, so
every token authenticates in a conversation the boundary reads. That costs
one round trip per new connection.

### Receipts name both sides

A stamp on a delegated read carries `principal`, `actor` and `token` beside
`caller`: domain-separated SHA-256 hashes of the principal's and the actor's
mapped ids, and the token's `jti` hash. `caller` stays the connection — the
server-reported user of the socket the read arrived on. All three are
signed, so an agent cannot relabel whom a chunk was served for, and none
names anybody. `voyd-verify --principal alice@example.com --actor
support-bot` recomputes the hashes and checks every document against them;
`attest.principal_hash` and `attest.actor_hash` do the same in code. This is
the audit sentence agent deployments cannot otherwise produce: *every chunk
agent A put in front of a model for user P was served under policy H, and
here are the signatures.*

[`examples/delegation.py`](examples/delegation.py) serves two users through
one service connection with the same query and different rows, shows the
mask staying on when the agent is narrower than its user, and refuses an
agent without the scope. `voyd.testing.TestIssuer` mints the tokens with no
network and no identity provider.

### Recipes as MCP tools

`voyd-mcp` serves a voydfile's recipes to any agent framework that speaks
the Model Context Protocol, and calls them through `voyd-wire`:

```bash
pip install 'voyd[mcp]'
voyd-mcp --policy voydfile.py \
         --wire 'mongodb://svc:pw@voyd-wire:27017/?directConnection=true' \
         --db support --transport http --port 8765
```

- **A tool is a recipe.** One per `@recipe`, named for it. Its description
  is the first paragraph of the recipe function's docstring and the
  collection it reads; its input schema is the recipe's typed parameters
  (`str`, `int`, `float`, `bool`, `list[str]`, `| None`, defaults), read
  from the same declarations the boundary checks a value against.
- **The caller is the bearer token.** Over streamable HTTP the MCP
  request's `Authorization: Bearer` token is the delegated identity,
  verified with the same `verify` against the voydfile's `issuer()`s. No
  believable token is a 401; `tools/list` shows only the recipes that
  identity may call — the collection's `delegation=` and `scope=`, and the
  recipe's own grants.
- **A call is one aggregate through the wire.**
  `aggregate([{"$recipe": {"name": ..., "params": ...}}],
  comment={"voyd": token})`, on a connection to `voyd-wire` as a service
  user the issuer names in `connection_users`. The result is the documents
  as relaxed extended JSON, `_voyd` stamps included, and their
  `voyd.attest.cite` citations, as structured content and as text. A
  refusal is a tool error carrying the wire's own message. A read over
  `--max-documents` or `--max-bytes` is an error, never a truncation.
- **The wire is the boundary; the listing is a convenience.** `voyd-mcp`
  enforces nothing. A tool it lists may still be refused, and a tool it
  hides would be refused by the wire if called anyway: the refusal is the
  guarantee, and there is one boundary to keep correct rather than two to
  keep in agreement.
- **stdio is local use.** `--transport stdio --token-env VAR` reads one
  token at startup and makes every call as it. The wire still verifies it,
  so the reach is exactly the token's — but it is the token of whoever set
  the variable, not of whichever agent attached.

No model is called and no prompt is written, and nothing is kept between
requests. [`examples/mcp_agent.py`](examples/mcp_agent.py) starts
`voyd-wire` with an attesting collection, lists and calls a tool with an
MCP client holding a `TestIssuer` token, verifies the stamps on what came
back, and prints the context an agent would hand its model.

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
`subjects()` array that stops being subjects, a `mask()` removed or
loosened — `strip=True` becoming a null, or `visible_to` gaining a
member. Those are facts about the
policy, so they are not weakened by a sample and do not disappear against
an empty collection.

**It refuses to answer three questions, by name.** `distinct()` is
set-relative — it refuses a document because of the other documents on the
page, and a sample is not a page — so it is set aside and printed rather than evaluated one document at a time. `clearance()` and
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

## A prompt that can prove where its chunks came from

A refusal leaves nothing behind, so "this prompt was built only from what
the boundary admitted" is a claim about a deployment rather than a
property of the prompt. `attest=True` makes it a property of each chunk:

```python
@guard("notes", attest=True)
class Notes:
    expire_at = deadline()
    ssn       = mask()
```

```
voyd-wire --attest-keygen attest.pem          # writes attest.pem, attest.pem.pub
voyd-wire --config voydfile.py --attest-key attest.pem   # or env:NAME
```

Every document served from `notes` carries a `_voyd` stamp, signed last —
after every rule, mask, sanitiser, transform, backfill cut and virtual
stage — over the document exactly as the client receives it:

    kid      first 16 hex of SHA-256 over the Ed25519 public key
    policy   SHA-256 of the policy file the boundary loaded
    ns, id   the namespace and _id
    digest   SHA-256 over a canonical encoding of the served document
    caller   SHA-256 of the server-reported user and auth db, or null
    principal, actor, token
             for a delegated read, hashes of the user it was for, the
             agent that read it, and the token's jti; null otherwise
    iat      when it was signed, by the proxy's clock
    read     one random id per read, stable across getMore
    pos      the document's place in the whole read
    prev     a hash of the stamp at pos-1, so a read is a chain
    sig      Ed25519 over all of the above

Verification needs a public key and nothing else — no proxy, no database:

```python
from voyd import attest

keys = attest.load_public_keys(open("attest.pem.pub", "rb").read())
attest.verify(doc, keys, policy=expected_hash)    # -> Verdict(ok, reason, ...)
attest.verify_all(window, keys)                   # the chain too
prompt = "\n".join(f"[{attest.cite(d)}] {attest.strip(d)['text']}" for d in window)
```

```
voyd-verify --keys attest.pem.pub --policy <sha256> < context.jsonl
voyd-verify --keys attest.pem.pub --principal alice --actor support-bot < context.jsonl
```

A stamp is version 2. Version 1 stamps, which predate `principal`, `actor`
and `token`, still verify; asking one about a principal or an actor fails,
because it cannot answer.

`verify` names which check failed: `unknown kid` (a key this verifier does
not hold), `bad signature` (the stamp was altered or relabelled), `digest
mismatch` (an authentic stamp on a document edited after the boundary),
`id mismatch`, `stale policy`. A masked value is stamped as the null it
left as, so putting it back fails verification — the stamp proves the
client never had it.

**The digest is over a type-tagged canonical JSON form, not BSON bytes**,
because a stamp has to survive a driver decoding it, an application holding
it and a JSON file for an auditor. Keys are sorted, every integer width is
one type, a whole double equals its integer, datetimes are epoch
milliseconds, and strings are compared by exact code point. Reordering keys
or widening an integer therefore verifies; every other edit does not. The
full table is in [`voyd/attest.py`](voyd/attest.py).

**A read is a hash chain rather than a Merkle tree.** A root needs a
finished set, a cursor is finished only when the client decides, and no
reply a driver hands an application could carry one. The chain needs no
end: the stamp at position *k* signs the link to *k-1*, so the last stamp of
a window commits to everything before it, and `verify_all` reports whether
each read's positions are contiguous from zero.

**Nothing upstream of the signer can mint or keep a stamp.** `_voyd` is
stripped from every document before any rule or transform sees it, and
again before signing, so a stamp stored in a row, saved back by a client,
or written by a `@transform` or `@stage` is replaced.

**What is not stamped:** `count`, `distinct`, and any pipeline with a stage
whose output is not one stored document (`$group`, `$bucket`, `$unwind`,
`$replaceRoot`, ...). There is no `(_id, content)` pair to attest to. A
projection is stamped as what it served.

**Key rotation** is a bundle: generate a new key, give verifiers a PEM file
holding both public keys, restart the boundary on the new private key, and
delete the old block once nothing signed under it still needs checking. A
stamp under a key not in the bundle is `unknown kid`, never a pass.
`voyd-plan` reports a guard that stops attesting as `attest_removed` — not
fail-open, because nothing becomes reachable, but every later prompt loses
its evidence. `voyd_stamped_total{collection}` counts what was signed.

[`examples/attest.py`](examples/attest.py) reads through the boundary,
verifies offline, edits one field and watches it fail, and builds a prompt
with citations.

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

- **Every number here is reproducible, not borrowed.** The benchmarks come
  from this repository's own machine and cluster; `voyd-bench` runs the same
  numbers against yours in minutes, which is the point — verify it rather
  than take it on faith.
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
- On the wire, `distinct()` judges one reply at a time. A copy that
  arrives in a later `getMore` batch of the same cursor is not compared
  with the ones already served.
- Backfill fills a lone `$vectorSearch` and nothing else. A pipeline with
  a stage after the search, a `$search`, or a `$rankFusion` still comes
  back short by whatever was refused, and a widened page that is mostly
  refused is short too.
- `sanitized()` catches the injections its signatures describe and no
  others. It reads strings and lists of strings; text nested deeper in a
  field is not examined. A collection declaring it cannot answer
  `distinct`, `count` or a reducing `aggregate`.
- A `mask()` closes the read paths this boundary can see. A write whose
  *count* depends on the value — `update({ssn: X}, ...)` answering
  `nModified: 1` — is refused like a read, but an index built on the field
  still exists on the server, and a caller with a direct connection is
  outside every guarantee here. A refused filter is strict on purpose: a
  bare key named `field`, `path` or `key` whose value is a masked field's
  name is refused as if it were a stage argument.
- A read with a virtual step does **not stream**. The whole set is drained,
  held in memory, bounded by `--virtual-max-docs`, and answered as one
  batch; a `$vectorSearch` prefix gets neither backfill nor `prefilter`.
- **Copies exist at rest.** A temporary collection holds a caller's
  admitted, masked output for the length of the read, and for up to
  `--virtual-max-age` if the proxy dies mid-read. It is refused through the
  boundary, but a direct connection with rights on that database, the
  server's profiler and logs, and `currentOp` all see it.
- Virtual steps run with no time bound but the client's own. A slow one
  holds its connection's request loop; nothing here cancels it.
- A `distinct()` rule is re-asked of what a step returns, so duplicate
  rows from an `$unwind` are judged as duplicates.
- The terminal pass after a step restores the fields the verdict reads
  from the admitted source, so a step cannot change them — even to a value
  the policy would accept.
- A recipe's version hashes its own source and its declared expansions. A
  helper function it calls is covered only as far as the declared
  expansions exercise it, and a recipe whose output depends on the clock or
  on anything outside its parameters has a version that does not describe
  that.
- A recipe's parameter cannot begin with `$`, so a query text such as
  `"$100 refund"` is refused rather than served; there is no escape for it.
  A name a parameter should be able to choose has to be produced by a
  declared sample first.
- `recipes_only=True` closes reads. `findAndModify` returns the document it
  wrote and is left alone as a write, and a direct connection is outside
  every guarantee here.
- **A stamp proves provenance, not truth.** It says the boundary served
  this document under this policy; it says nothing about whether the
  document was correct, or whether the policy was the right one.
- **Whoever holds the private key can mint stamps.** A compromised key
  signs forgeries indistinguishable from real stamps until it is dropped
  from every verifier's bundle, and nothing here revokes a key on its own
  or timestamps stamps against an outside clock. `iat` is the proxy's
  clock and is only as honest as it.
- The caller field is **pseudonymous**: anybody with a list of user names
  can hash each and match it. A verifier outside Python must reproduce the
  canonical form exactly, including Python's shortest float repr.
- A stamp costs an Ed25519 signature per document and a re-encoded reply;
  an attested collection never gets the byte-for-byte fast path.
- **`--oidc=passthrough` is tested against a simulated deployment only.**
  The conversation and the consistency check are exercised byte for byte,
  and `terminate` runs live against a real driver and a real replica set,
  but no suite here reaches a deployment that validates `MONGODB-OIDC`
  itself (Atlas workload identity, or Enterprise with an identity provider).
  Self-managed Community servers have no OIDC, so `terminate` is the only
  mode there.
- `--oidc=terminate` authenticates upstream with SCRAM-SHA-256 or not at
  all; X.509, AWS and LDAP credentials for the boundary itself are refused
  at startup. The boundary's upstream user is the ceiling of every token's
  reach, so give it read roles only. A client's own `connectionStatus` on a
  terminated connection reports that upstream user, not the token.
- A terminated connection with an expired token is asked to reauthenticate
  (391); a passthrough one is the deployment's to expire. Neither mode keeps
  a replay cache.
- The OIDC principal step is answered only when the policy declares one
  issuer; with several, a driver must use a callback that returns a token.
- Principal and actor hashes do not include the issuer: two identity
  providers naming the same `sub` produce the same `principal`. They are
  pseudonymous the way `caller` is.
- A recipe grant names actors by the mapped actor id and scopes by name. It
  is not a role check, and a grant has no `via=`: it always reads the
  delegated identity.
- **No replay cache.** A captured token is valid until its `exp`, on any
  connection its issuer's `connection_users` names, and as a
  `MONGODB-OIDC` credential. Keep `exp` short.
- **JWKS staleness is bounded, not zero.** A key the identity provider
  revokes is still believed until the next successful refresh, and a
  provider that is down leaves the last good keys in use for up to
  `max_age`.
- A pooled connection's own identity is the server's; the boundary cannot
  tell two agents sharing one service account apart except by their tokens.
- A lone `$vectorSearch` under delegation is not rewritten: its tenant is
  enforced per document on the way out, so a page can come back short by
  another tenant's hits.
- `voyd-mcp` reads the policy file itself to decide what to list, so a
  policy served by `voyd-wire` and a different one handed to `voyd-mcp`
  list tools the wire refuses, or hide tools it would serve. Refusal stays
  correct either way; the listing does not.
- `voyd-mcp` over HTTP is a resource server only: it verifies bearer tokens
  and advertises no authorization server of its own, so an MCP client has
  to obtain the token from the identity provider some other way. It has no
  TLS of its own either; put it behind a terminator.
- A tool result is the whole read, bounded and never streamed; a read over
  the bound fails rather than paging.
- There is **no observe-only mode**. `voyd-wire` enforces or it is not
  in the path; it cannot yet run alongside a read logging what it *would*
  have refused. `voyd-plan --audit` answers most of that question without
  a proxy at all, which is why this has not been urgent.

---

## Reading this repository

This file is the reference. The others are not the same argument
at different lengths — each answers a question this one does not:

| | |
|---|---|
| [`quickstart.md`](quickstart.md) | four steps, smallest first; the first costs nothing at all |
| [`use-cases.md`](use-cases.md) | twenty-two places a fact ranks well and must not reach the prompt, each with its voydfile and the edge where refusal stops |
| [`ethos.md`](ethos.md) | what a policy file is for, and the four tests that keep logic out of it. Read this before writing rules |
| [`blog.md`](blog.md) | the story: every failure in this domain is disguised as its own opposite, including one in this project's own CI |
| [`blog2.md`](blog2.md) | the sequel: the verbs after *refuse* — backfill, prefilter, mask, sanitize, stages, recipes, attest — and the one property they share |
| [`examples/operators/README.md`](examples/operators/README.md) | every `voyd.contrib` stage and operator, with a snippet you can paste into a pipeline today |
| [`whats-next.md`](whats-next.md) | the spec for delegated agent identity at the wire, and the decisions each milestone made: request-level tokens, `MONGODB-OIDC` in both modes, receipts naming both parties, recipe grants, and `voyd-mcp` |
| [`docs/why-not-native.md`](docs/why-not-native.md) | change streams, `$where`, views, `$$USER_ROLES`, TTL, RBAC, Queryable Encryption — what each one gives you and where the line is |
| [`docs/cosine.md`](docs/cosine.md) | the embedding-model failure, reproducible without an API key, with its provenance and its limits |
| [`docs/ranking-is-not-permission.md`](docs/ranking-is-not-permission.md) | the long-form design argument for putting a boundary on the wire |
| [`genius.md`](genius.md) | the commercial case: one property, three motions, and the corrections that keep it honest |

MIT.
