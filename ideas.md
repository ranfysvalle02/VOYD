# What is worth building next

Forward-looking only, and **verified against the code on 19 September 2026** —
where an item below says something does not exist yet, that was checked rather
than assumed. The date is here so a reader can tell how old the claims are;
a roadmap with no date is indistinguishable from a roadmap nobody maintains.

Four of these are also stated in [`blog.md`](blog.md#what-is-not-done), which
is the public commitment; this file is the working version, with the reasoning
and the order.

## Ranked

### 1. Cryptographic erasure — the one honest gap

*(Inherited refusal was ahead of this and shipped: see
`voyd/engine/admission.py` under "what a fact was made out of". It mattered
more because it was not a gap in the pitch, it was a gap in the guarantee —
an erasure request honoured against a source and defeated by the summary.)*

Per-scope data key, text encrypted at rest with it, the deadline destroys the
key. The row stays on disk and the plaintext is gone the instant the key is.

**Why first.** *"The row is still on disk"* is proof to an engineer and a
**finding** to a security reviewer, and a security reviewer is who decides
whether this gets adopted anywhere that matters. It is also the only item that
changes what the project can claim: refusal becomes unreachable *and*
unrecoverable, with no sweeper involved in either.

**Shape.** A key per scope, held wherever the deployment already keeps
secrets; `expire_at` passing destroys it; a row whose key is gone is refused
by a new rule (`Unrecoverable`) rather than by special-casing the read path —
the rule interface already fits. The hard part is not encryption, it is being
honest about key custody in the docs.

### 2. Rules as data, not Python

A rule is an object, so a per-tenant policy is a release. The protocol is
already shaped for this — a rule declares `needs_caller` and `bypassable` and
carries its own `clause()` — but the rule itself is code.

**Why.** It is what turns clearance from a feature into a product: the people
who get audited get to change the policy, and the policy is versioned with the
scope document that owns it. Today adding a reason requires a deploy, which
caps adoption at teams who can ship this service.

**Shape.** `{"deny": {"field": "clearance", "lt": "$caller.clearance"}}`
stored on the scope, compiled to the same two halves every rule has. The
compiler is the whole job, and it must refuse anything it cannot express on
*both* halves — a policy that filters in the query and not per document is a
silent hole, which is exactly what `$vectorSearch` would then walk through.

### 3. The admission overhead, as a published number

`bench/measure.py` measures expiry lag, the cosine cliff and per-tier latency.
It does not measure the thing being sold: p50/p99 CPU per admitted hit, and
the over-fetch factor under a realistic refusal rate.

**Why.** "So you pay on every read, forever" is the first question a reviewer
asks, and it currently gets prose. `Page.examined` already reports the
over-fetch per query, so half the instrumentation exists.

### 4. `as_of(t)` — what could have reached a prompt last Tuesday

Nearly free: every rule already takes `when=`, and thirteen signatures in
`admission.py` alone thread it through. What is missing is a public `as_of()` on the handle and a decision
about revocation, which is the interesting part — a revoked row's mark has an
`at`, so "was this reachable at 14:02" is answerable, but only until the
reaper takes the row.

**Why.** It answers *"what did the model see when it said that?"* — the
question after every AI incident. And it pairs with the refusal chain: the
chain says when a fact stopped being reachable, `as_of` shows what the scope
looked like on either side of that.

### 5. Quarantine as a workflow — the queue is what is left

**Half of this shipped.** The missing piece turned out to be worse than the
missing queue: `quarantined()` was a reason *no verb could impose*. The rule
could refuse a mark and nothing in the package could put one there, so every
test set the field by raw insert. It now has both halves —
`quarantine()` / `release()` — and reversibility is declared on the rule
(`Marked(reversible=...)`), which is also what decides whether imposing it
stamps the erase deadline. A hold that schedules its own evidence for
deletion is an investigation with a countdown on it.

What is still missing is the **reviewer**. `engine.queue(when=…)` already
exists and the document is already the job, so it is one
`queue(when={"quarantined": {"$ne": None}})` away.

**Why.** Quarantine without a review loop becomes a graveyard, and a graveyard
is indistinguishable from a leak that nobody looked at. Now that `lifted_total`
is counted separately from `revoked_total`, the queue also gets a number worth
watching: a climbing `lifted` means the detector is mistuned.

### 6. A TypeScript client

The API is five calls. The agent ecosystem is TypeScript-first and the only
client is Python.

**Why.** Cheapest reach-per-line on this list. It is also a genuine test of
whether "five calls" is true: a second implementation is where an API finds
out it has fourteen.

## Bigger bets, lower confidence

### Port the thesis to pgvector and Qdrant

**The demonstration shipped.** `drift/refusal_on_postgres.py` runs the whole
argument on pgvector with no MongoDB in the file: the same silent bug,
refusal in the read path, the structural version (revoke the table, grant
only a view, so the naive read raises `permission denied`), and inherited
refusal by recursive CTE. It states what is harder there too — no TTL, so
the deadline reacquires a second owner the moment you need rows gone.

What is still open is a **shipped adapter**, and the honest reason to hold
off is unchanged: it doubles the surface that has to hold, and the one-owner
property really is weaker elsewhere. The demonstration was the cheap 80% —
it removes the "this is just MongoDB advocacy" dismissal without taking on a
second engine to keep correct. Qdrant is the more interesting second target
than Postgres, because it has no rows at all: refusal there has to live in
the payload filter, and whether that is enforceable or merely conventional
is a real question this file does not answer.

### A leak detector for stacks that are not this one

Point a tool at a live Pinecone + Postgres and report how many currently
queryable vectors have no live row.

**Why.** Nobody buys a guarantee until they see their own number, and the
answer is never zero. It is `drift/exhibit.py` turned outward, and it is the
same move as `voyd verify` — ship the experiment rather than the claim.

**Why not yet.** It is a go-to-market artifact, not a foundation one, and it
needs read credentials for somebody else's production data. That is a
different kind of responsibility than anything here currently carries.

## Deliberately not doing

- **A delete tool or endpoint.** A delete hands the caller a cleanup
  obligation, and an agent that has to remember to clean up is the failure
  this exists to remove. CI asserts no tool is named for reclaiming anything.
- **A browser surface.** It was removed, and its residue kept turning up for
  months afterwards — orphaned store methods, a dead download counter, a slug
  derived from a business name nobody types any more. One credential, three
  surfaces: the JSON API, the MCP tools, `import voyd`.
- **Pushing the deadline into the vector index.** Measured and rejected: a
  `vectorSearch` definition cannot be updated in place, so it is a
  drop-and-rebuild on every existing deployment, and a rebuilding index
  returns zero rows rather than erroring. The reasoning is in
  `voyd/engine/search.py`.
- **Ledgering reads.** A write per refused hit, for a property the read path
  enforces anyway and the suite proves. The chain records *instructions* —
  revocations, holds, and the lifting of holds — because those are facts about
  the world.
- **An undo for `revoke()`.** Not an omission; see `Irreversible` in
  `voyd/engine/errors.py` for the argument. Two reasons either of which would
  be sufficient: the row is already scheduled for the reaper, so the undo
  would work until `ttlMonitorSleepSecs` decided otherwise — an API whose
  window is a storage event, in the codebase written to argue that guarantees
  must not depend on sweepers. And it would make the chain intact and false.
  The re-admission of erased information is a new document with new
  provenance, which is a different operation with a different audit story.

## Known and accepted

Not ideas; the honest caveats, so they are not rediscovered as surprises.

- Passcode rate limiting is in-process, therefore **per-replica**. The trade
  for not needing Redis, and the first thing to fix on more than one process.
- **CORS is wildcard-open on `/v1`**, which is the whole public surface.
- The refusal chain's signature is **HMAC**: an attestation to whoever trusts
  the key holder, not a public proof. Asymmetric signing would fix that and
  costs a dependency the engine does not have.
- `auto_embed` is **not available on Atlas Local** — see [`BUG.md`](BUG.md).
  The fallback is the normal path locally and in CI.
