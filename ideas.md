# What is worth building next

**Forward-looking only**, and verified against the code on **19 September
2026** — where something below says a thing does not exist, that was checked,
not assumed. The date is here because a roadmap with no date is
indistinguishable from a roadmap nobody maintains.

Nothing shipped is described here as if it were still open. What shipping
*left* open is folded into the items below, where it belongs, instead of
sitting under a heading marked SHIPPED that nobody rereads.

Three of these are also in [`blog.md`](blog.md#what-is-not-done), which is
the public commitment. This is the working version: the reasoning, the
shape, and — for each one — **how you would know it worked**, because an
item without that is a wish.

---

## The frontier

Things that change what the project can *claim*, not just what it can do.

### 1. The perimeter, past enumeration

The perimeter is defined now -- three classes, three verbs, and a
`Perimeter` that propagates without ever being able to fail an erasure. The
embedding hole inside it is closed, and the context receipt gives class C
(consequences) a way to be *found*.

What is left is the part enumeration does not solve.

**Sinks are still bespoke.** Each one is an integration, so the honest
question is whether the class ever gets shipped adapters or stays an
interface. The argument for staying an interface: a Redis adapter here
would be a Redis adapter somebody has to keep current, for a call that is
one `DEL` in the caller's own code. The argument against: a perimeter
nobody registers anything into is a `describe()` that prints an empty dict.
Worth deciding deliberately rather than by drift.

**A sealed sink is claimed, not verified.** A sink declaring `holds=SEALED`
is trusted about it, and if it actually caches plaintext the perimeter
reports an erasure that did not happen -- the one way this module can lie.
A `verify` hook on the protocol (hand it a known-shredded id, assert it
cannot produce the plaintext) would turn the declaration into a check. That
is the same move as the falsifier, applied to a claim the caller makes.

**Nothing re-drives the propagation.** A sink that was down during a
revocation stays unacknowledged forever; there is no retry, and
`engine.queue()` is sitting right there with the document already being the
job. The reason to think before building it: a retry that runs a week later
against a cache that has since evicted the key is noise, and noise in an
audit trail is worse than a gap that is honestly marked.

### 2. The context receipt, past the read path

Receipts exist and recompute without a secret. Two things would make them
load-bearing rather than available.

**Nothing consumes them.** There is no `voyd verify` check that a receipt
from before a revocation fails to validate after it, and no worked example
of the incident-review flow the feature is named for. A feature nobody
has walked through end to end is a feature whose ergonomics are unmeasured.

**They do not index the other way.** The question is *"which answers were
built on this fact?"* and today you can only check a receipt you already
have. Storing receipts, keyed by admitted id, turns an archaeology project
into a query -- and it is the only thing that helps with class C at all.
The cost is a collection whose retention policy is a genuine question: a
receipt naming ids is not document text, but it is a record of who saw
what, and that is its own sensitivity.

### 3. A failed KMS call must not look like a shredded key

Smaller than the others, and it is a correctness bug in something already
shipped, which is why it is here rather than in a backlog.

`unseal()` refuses a document whose key cannot be fetched. A destroyed key
and an unreachable KMS produce the same refusal — but one is the feature
working and the other is an outage, and a dashboard that cannot tell them
apart will report a successful erasure during a network partition.

**Shape.** Separate the reasons (`unrecoverable` vs something like
`key_unavailable`), fail closed on both, and count them apart — the same
move that separated `not_cleared` from `deadline`, and for the same reason:
a climbing count means different things.

**You would know it worked when** killing the KMS in a test produces a
different reason string than shredding a key, and both still refuse.

### 4. `as_of(t)` — what could have reached a prompt last Tuesday

Nearly free and still not done. Every rule already takes `when=`; eleven
call sites in `admission.py` thread it through. What is missing is a public
`as_of()` on the handle and one real decision.

**The decision, which is the actual work.** A revoked row's mark carries an
`at`, so "was this reachable at 14:02" is answerable — *until the reaper
takes the row*, after which the honest answer is "unknown" and the tempting
answer is "no". Returning "no" for a row that has been erased is exactly the
confident wrong answer this codebase exists to eliminate, so `as_of` has to
be able to say **unknown**, and the API has to make that impossible to
mistake for a negative.

**Why it is worth more now than it was.** The context receipt already
commits to an `at`, so a receipt plus `as_of` is a complete answer to
*"was this context legitimate at the time it was built?"* — which is the
question, and neither half answers it alone.

---

## Sharp and cheap

High value per line. None of these are research.

### 5. Rules as data, not Python

A rule is an object, so a per-tenant policy is a release. The protocol is
already shaped for it — a rule declares `needs_caller`, `bypassable` and
`reversible`, and carries its own `clause()` — but the rule is still code.

**Why.** It turns clearance from a feature into a product: the people who
get audited get to change the policy, and the policy is versioned with the
scope document that owns it. Today a new reason needs a deploy, which caps
adoption at teams who can ship this service.

**Shape.** `{"deny": {"field": "clearance", "lt": "$caller.clearance"}}` on
the scope, compiled into the same two halves every rule has. The compiler is
the whole job, and it **must refuse anything it cannot express on both
halves** — a policy that filters in the query but not per document is a
silent hole, and `$vectorSearch` is what walks through it.

### 6. The admission overhead, as a published number

`bench/measure.py` measures TTL lag, per-tier latency and the cosine cliff.
It does not measure the thing being sold: p50/p99 CPU per admitted hit, and
the over-fetch factor under a realistic refusal rate.

**Why.** *"So you pay on every read, forever"* is the first question a
reviewer asks and it currently gets prose. `Page.examined` already reports
over-fetch per query, so half the instrumentation exists.

Add the key-cache turnover while you are in there — measured at ~60s in one
shape and >120s in another, which is currently a sentence in a docstring
rather than a number in a table.

### 7. The quarantine reviewer

`quarantine()` and `release()` ship. The **queue** does not, and quarantine
without a review loop is a graveyard — which is indistinguishable from a
leak nobody looked at.

`engine.queue(when=…)` exists and the document is already the job, so this
is roughly one line plus a surface: `queue(when={"quarantined": {"$ne":
None}})`. `lifted_total` is already counted apart from `revoked_total`, so
the queue arrives with the metric that matters: a climbing `lifted` means
the detector is mistuned.

### 8. Budget as a refusal reason

`Rule` answers *may this reach a prompt?* A context-token budget is the same
question with a different reason: `over_budget`, refusing marginal hits once
the budget is spent.

**Why it is worth building even though nobody asked.** It is evidence the
abstraction is a *primitive* rather than a compliance feature. A rule
protocol that pays off in a domain with nothing to do with erasure has
earned its place; one that only ever holds compliance reasons is a
compliance feature with extra indirection.

### 9. A TypeScript client

The API is five calls. The agent ecosystem is TypeScript-first and the only
client is Python.

Cheapest reach-per-line here, and a genuine test of whether "five calls" is
true — a second implementation is where an API finds out it has fourteen.

---

## Bigger bets, lower confidence

### Qdrant, not Postgres, as the second engine

`drift/refusal_on_postgres.py` already runs the whole thesis on pgvector
with no MongoDB in it, which removed the "this is just MongoDB advocacy"
dismissal for the price of one file. A *shipped adapter* is still open, and
the honest reason to hold off is unchanged: it doubles the surface that has
to hold.

But **Qdrant is the more interesting target than Postgres**, and it is the
one that would teach us something. Postgres has rows, so refusal there is
recognisably the same shape — a view and a grant. Qdrant has no rows at all:
refusal has to live in the payload filter, and whether that is *enforceable*
or merely *conventional* is a genuinely open question. If it turns out to be
conventional, that is a finding worth publishing on its own — it would mean
a whole class of vector databases cannot express this guarantee structurally
at all, only politely.

### A leak detector for stacks that are not this one

Point a tool at a live Pinecone + Postgres and report how many currently
queryable vectors have no live row. `drift/exhibit.py` turned outward.

**Why.** Nobody buys a guarantee until they see their own number, and the
number is never zero.

**Why not yet.** It is a go-to-market artifact, not a foundation one, and it
needs read credentials for somebody else's production data — a different
kind of responsibility than anything here currently carries.

### Sealing on the HTTP path

The keyring is an engine primitive; nothing in the product encrypts
anything. Wiring it in needs an answer to *which fields a scope declares
sensitive*, and the vault API has no way to express a schema. That is a
product decision, not an encryption one, and doing it badly would put a
schema in a URL.

Same shape as the reason holds are not on the HTTP surface yet: the missing
piece is an authorisation story (who may release, who may shred), not a
mechanism.

---

## Deliberately not doing

Each of these was considered and rejected for a stated reason. They are here
so the reasoning is not relitigated every six months.

- **A delete tool or endpoint.** A delete hands the caller a cleanup
  obligation, and an agent that has to remember to clean up is the failure
  this exists to remove. CI asserts no tool is named for reclaiming
  anything.
- **An undo for `revoke()`.** See `Irreversible` in `voyd/engine/errors.py`.
  Two reasons, either sufficient: the row is already scheduled for the
  reaper, so the undo would work until `ttlMonitorSleepSecs` decided
  otherwise — an API whose window is a storage event, in the codebase
  written to argue guarantees must not depend on sweepers. And it would make
  the chain *intact and false*. Re-admitting erased information is a new
  document with new provenance: a different operation with a different audit
  story.
- **Per-subject erasure under Queryable Encryption.** Not a missing feature,
  a measured constraint: QE rejects a pointer `keyId`, so a key is bound per
  field per collection. Wanting per-subject shredding *and* a searchable
  ciphertext means one collection per subject, which is a sharding decision
  wearing an encryption costume. `Sealed` is the default for this reason.
- **Pushing the deadline into the vector index.** Measured and rejected: a
  `vectorSearch` definition cannot be updated in place, so it is a
  drop-and-rebuild on every existing deployment, and a rebuilding index
  returns zero rows rather than erroring. Reasoning in
  `voyd/engine/search.py`.
- **Ledgering reads.** A write per refused hit, for a property the read path
  enforces anyway and the suite proves. The chain records *instructions* —
  revocations, holds, and the lifting of holds — because those are facts
  about the world. (#2 above is the right version of what ledgering reads
  was reaching for.)
- **A browser surface.** Removed, and its residue kept surfacing for months
  — orphaned store methods, a dead download counter, a slug derived from a
  business name nobody types. One credential, three surfaces: the JSON API,
  the MCP tools, `import voyd`.

---

## Known and accepted

Not ideas — the honest caveats, written down so they are not rediscovered as
surprises.

- **Nothing has run against a cloud KMS.** The provider dicts and
  master-key shapes are unit-tested and share a code path with the local
  rung, but *"constructs the right `master_key` document"* and *"works
  against AWS"* are different claims and only the first is proven.
- **The key cache is not a contract.** ~60s in one shape, >120s in another.
  Crypto erasure is eventually consistent and the window is not specified
  anywhere. Refusal is what covers it; see #6 for making it a number.
- **QE range queries** (8.0+) are declared in the type and untested. Only
  equality is exercised.
- **Passcode rate limiting is per-replica.** In-process, the honest trade
  for not needing Redis, and the first thing to fix on more than one
  process.
- **CORS is wildcard-open on `/v1`**, which is the whole public surface.
- **The chain's signature is HMAC**: an attestation to whoever trusts the
  key holder, not a public proof. Asymmetric signing would fix it and costs
  a dependency the engine does not have. The chain itself needs no trust;
  only the signature does.
- **`auto_embed` is unavailable on Atlas Local** — see [`BUG.md`](BUG.md).
  The fallback is the normal path locally and in CI.
