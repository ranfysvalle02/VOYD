# Refusal was the easy half

*What VOYD does now that it can rewrite a read instead of only shrinking it.*

---

The first version of this project had one verb. A document reached the
wire, the rules looked at it, and it either left or it did not. That is
a good verb. It is exact, it is pure, and it is the reason a transform
cannot widen a read: the boundary is downstream of everything, and all
it ever does is subtract.

It is also a blunt verb, and three things kept going wrong around it.
The page came back short. A whole contract was dropped for one field.
And a document that was perfectly entitled to be read turned out to be
talking to the model instead of informing it.

None of these is a hole in the guarantee. Each is the guarantee being
honoured in a way nobody wanted. So VOYD now has more verbs than
*refuse*, and the interesting part is that every one of them is built so
it still cannot widen a read.

## Ten neighbours means ten

Ask `$vectorSearch` for `limit: 10` on a collection where the sweeper is
behind, and mongot hands back the ten best candidates — eight of which
expired this morning. The boundary refuses eight. The client gets two.

That is correct and it is terrible. Safety paid for by recall is the
trade that makes people take the boundary out.

The obvious fix is to push the deadline into the vector index's
`filter`, and it is the wrong default for reasons worth spelling out: a
`vectorSearch` index definition cannot be updated in place, so adding
filter fields to an existing deployment is a rebuild, and mongot rejects
a filter on any path the index did not declare — so a boundary that
guesses wrong turns every query into an error.

So the default is **backfill**. A lone `$vectorSearch` on a guarded
collection is asked for more than the client wanted — four times as
many by default, `@guard("notes", backfill=N)` to tune it, capped at the
10,000 Atlas accepts. The reply is judged exactly as before: transforms,
then the terminal per-document check. *Then* it is cut back to the
client's `limit`, keeping the front of the list so the server's score
order survives.

The cut only removes. It cannot add a document, so it cannot return
more than was asked for and it cannot return anything the rules did
not admit. What is still owed carries across `getMore`, so a driver
with a small `batchSize` sees the same page as one without.

It is honest about where it stops. Only a `$vectorSearch` with nothing
after it is widened, because over-fetching in front of a `$sort` or a
`$skip` changes the answer instead of filling it. And if more than
three quarters of the widened page is refused, the page is still short —
at which point the problem is the sweeper, not the page size.

## Or ask the index, if you mean it

For the deployments that can pay for it, `@guard("notes",
prefilter=True)` does the thing the default declines to.

`voyd-wire --ensure` declares every field the rules read as a `filter`
field on the `auto_embed` index, and the drift check covers them. At
startup the proxy asks the live index whether it actually carries those
fields. Only if it does are the rules ANDed into each
`$vectorSearch.filter`, next to the client's own filter and never
instead of it.

The part that matters: the pre-filtered reply is **not** treated as
already judged. It goes through the same per-document check on the way
out as if the rewrite had never happened. The pre-filter is an
optimisation that narrows ranking. The egress pass is still the
guarantee. If the two ever disagree, the one that decides is the one
that was always deciding.

## A document can leave without all of itself

A fifty-page contract with one social security number in it is a
fifty-page contract you would like the model to read.

```python
@guard("contracts")
class Contracts:
    expire_at = deadline()
    tenant_id = tenant()
    ssn       = mask()                      # served as null
    internal  = mask(strip=True)            # the key is removed
    salary    = mask(visible_to=("hr",))    # null unless the server says hr
```

The document is admitted and the value is rewritten in the reply bytes
before the driver sees them. The audience in `visible_to` is checked
against the roles the *server* reports for the connection, never
against anything the client asserts, and a caller the boundary cannot
identify sees the mask.

Masking a value is easy. The work is that a value has more ways out
than the field it lives in:

    find({ssn: "123-45-6789"})          a yes/no about the value
    sort({ssn: 1})                      an order made of the value
    distinct("ssn")                     the values, as a list
    {$project: {x: "$ssn"}}             the value, under another name
    {$group: {_id: "$ssn"}}             the value, as a group key
    updateMany({}, [{$set: {n: "$ssn"}}])  the value, copied in the server

Each of those is refused before it is sent, `explain` of each of them
too, along with `$$ROOT`, `$function`, `$where` and the rest of the
ways a pipeline can reach a field without naming it. Excluding it —
`{ssn: 0}`, `$unset` — is always allowed.

And the ordering is the same one that made transforms safe: masking runs
after every rule and after every transform, on every pass. A reranker
that restores the SSN from a cache has it removed a second time on the
way out. `voyd-plan` reports a removed or loosened mask as a change
that fails open, next to a widened rule.

## Text that talks to the model

Some documents are allowed to be read and should not be believed.

A chunk that says *ignore previous instructions* is not expired, not
revoked and not somebody else's. Every rule admits it. Then it reaches a
prompt and does what it says.

```python
@guard("notes")
class Notes:
    text = sanitized()                              # refuse on a match
    body = sanitized(on_match="neutralise")         # cut the match, serve the rest
```

This is the one feature here that does not share the project's usual
kind of claim, and it says so. `sanitized()` does two things, and only
the first is exact:

- **Invisible characters are removed.** Zero-width spaces, bidi
  overrides, the Unicode tag block. Whether a string contains U+200B is
  a fact about its bytes, so this is a guarantee: nothing in the list
  reaches a prompt from a declared field.
- **Signatures are looked for.** Instruction overrides, fake system
  prompts, chat-template tokens, HTML comments, markdown images whose
  URL carries a query string. Matching runs on folded text — invisibles
  out, NFKC, case-folded — so `ig​nore` and full-width letters still
  match.

The second half is a **tripwire, not a guarantee**, and a test pins
exactly that: a paraphrase, an instruction in French, and an
instruction split across two chunks all go straight through. A document
that *quotes* an injection to discuss it is matched exactly like one
that carries it. The list is short, readable, and yours to extend in the
voydfile.

It still lives inside the boundary for the same reason everything else
does: it runs in the terminal pass, after your transforms, so nothing
upstream of the wire can hand the model text the sanitiser has not
seen.

## Stages mongod has never heard of

Once the boundary can rewrite a document, the next question is obvious:
can it run a step of the pipeline?

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

That runs from `pymongo`, from Mongoose, from `mongosh`, from Compass.
None of them has heard of `$wordCount`. None of them needs to, because
the proxy splits the pipeline at the first name mongod does not have.

The idea is not new — split a pipeline at the custom operator, park the
intermediate result in a temporary collection, keep going natively —
and the naive version of it is a leak. The obvious way to park the
native prefix is `$out`, and `$out` writes every row the prefix matched,
expired and revoked and somebody else's, into a fresh collection no
policy has ever heard of.

So the prefix is never `$out`. It comes back over the wire and is judged
exactly like a `find`: every rule, then `sanitized()`, then `mask()`. The
virtual step is handed what this caller would have been served, field
for field, and nothing else. **A refused document never reaches a stage
function** — there is a test with a stage that records everything it is
given, and the expired, revoked and cross-tenant rows are not in it.

Then the same rule as every other verb here. A step may add fields, drop
documents and reorder them. It may not invent one: every document it
returns is traced by `_id` to a document it was handed, at most as many
times as it was handed it, and judged again with the fields the verdict
reads put back from the admitted source. A stage cannot erase a
revocation mark on its way out.

### Using what came before

The part that makes it more than a plugin hook is that earlier steps
feed later ones:

- **A field a step adds is just a field.** A later operator reads it by
  path — `{"$redactEmails": "$summary"}` — and a native `$match`,
  `$sort` or `$group` after it filters on it, in mongod.
- **A stage can publish a value.** `ctx.publish("corpus", {...})` —
  an idf table, a mean length — and every later step reads it as
  `$$corpus.idf`, resolved in a virtual step's arguments and passed as
  `let` to the native suffix. It is computed over admitted documents
  only, and a test pins that a refused row cannot move it by a digit.
  A pipeline variable is a summary, and a summary of refused rows is
  the reduction leak this project exists to close.
- **`$$NOW` is one instant** for the whole read, in every virtual step.

### Temporary collections that clean up after themselves

The native steps *after* a virtual one run in mongod, because mongod is
the only engine that runs `$group` and `$setWindowFields` exactly — the
boundary does not reimplement MQL. They run on a temporary collection,
and temporary collections are where this idea usually rots:

- They live in their own database, `__voyd_tmp` by default, named for
  the proxy instance, the second they were created, and a uuid. Every
  client command that names that database is refused on the way in, so
  the only reader is the proxy.
- What is written is what a virtual step produced from admitted
  documents, stored in arrival order so a ranking survives.
- Each one is dropped in a `finally`. The database is also swept at
  startup and on a timer for anything past `--virtual-max-age` (ten
  minutes by default), from any proxy instance, so a crash leaves
  nothing behind for longer than that.
- The sweep drops only names this module creates, only in that
  database, and a test checks both halves.
- A pipeline that ends in a virtual step creates no temporary
  collection at all.

It is candid about where it stops. There is no streaming: the admitted
set is held in memory, bounded by `--virtual-max-docs`, and exceeding
the bound is an error, never a truncation. A crash leaves a masked,
admitted copy at rest until the next sweep, readable over a direct
connection. The prefix of a virtual read gets no backfill or
pre-filter. And `explain` of a pipeline with a virtual step is refused,
because a plan for half a pipeline describes a query nobody sent.

## Where the model call lives

VOYD never calls a model and never holds a model credential. There is no
provider key in the proxy's environment and no SDK in the voydfile.

That is not a gap waiting to be filled. The boundary makes one promise —
what context the client receives — and it can only make it because it
owns nothing else. The client owns inference: its own key, its own
prompt, its own provider. What it is handed to put in that prompt has
already been judged, masked and sanitised by a pure function that cannot
be talked out of it.

## The verbs, and the one rule they share

    refuse       the document does not leave
    backfill     the page is filled from further down the ranking
    prefilter    the index is asked to rank only what may be returned
    mask         the document leaves, one of its values does not
    sanitize     the document leaves, without the part aimed at the model
    stage        a step runs on what was admitted, and cannot add to it

Six verbs, one property. Each of them runs where the boundary already
was, and each can only make a read smaller than what the rules alone
would have allowed. Backfill cuts, it never adds. Pre-filtering narrows,
and is judged afterwards anyway. A mask and a sanitiser rewrite what was
admitted and cannot reach what was refused. A virtual stage is handed
only what was admitted, and everything it returns is judged again.

Ranking is still not permission. It turns out permission is not only
yes or no either.
