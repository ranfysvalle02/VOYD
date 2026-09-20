# What is worth building next

**Forward-looking only**, and verified against the code on **20 September
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

## Frozen until a retained pilot

These are real and reasoned below, and none of them is the next thing to build.
The next thing is one retained Python + MongoDB pilot on the handle
([`PILOT.md`](../PILOT.md)); until that exists, each of these adds surface to a
project whose public surface has already overgrown once ([`ISSUES.md`](ISSUES.md)
item 8). Listed here so the reasoning below is not mistaken for a queue:

- **The HTTP namespace as the first surface** -- still owes an authorization
  story for the verbs that change reachability, which is the third time that
  one unanswered question has blocked something. It waits on a pilot
  promoting the surface, not on taste.
- **MCP as an identity** -- a channel a model calls, not the category. A demo,
  not a listing in an agent-memory marketplace.
- **A TypeScript client** (item 9) -- reach, not proof.
- **Qdrant as a second engine** and **the outward leak detector** -- both
  double the surface that has to hold.
- **The policy editor** (item 5) -- the compiler shipped; loading and an
  editing endpoint wait on the same authorization question as the HTTP surface.
- **Wiring `redrive()`** (item 1) -- a worker with credentials for every sink
  is a deployment decision, not a default.

The items below keep their reasoning. This section is the freeze: the identity
is the handle, and these wait on evidence that a stranger keeps it.

**One thing that passed the freeze, and why.** On 20 September 2026 the policy
compiler was measured against a live `casbin.Enforcer`: four classic Casbin
models decide identically, per caller, comparing sets of admitted documents,
and all four push fully into MongoDB -- which Casbin has no mechanism to do at
all. The reverse direction found a boundary rather than a gap: a cumulative
rule cannot be expressed by `enforce(subject, object, action)`, because the
same pair has two answers depending on what else is in the page. That is
written up in [`policy-engines.md`](policy-engines.md) and demonstrated in
[`examples/policy_engine.py`](../examples/policy_engine.py).

It got through the freeze because it is not surface: no module, no dependency
(`casbin` is a dev dependency so the test runs in CI, and `voyd` must never
import it -- "these are two layers" is the argument). It is one example, one
test file, and a doc. Anything here that needs more than that is still frozen.

---

## The frontier

Things that change what the project can *claim*, not just what it can do.

### 1. The perimeter, past propagation

Enumerated, propagated, audited and re-driven. `holds=SEALED` is a check
now rather than a claim, unanswered acknowledgements are retried within a
horizon and closed *unconfirmed* past it, and registering a sink costs
three lines — which is what makes "no shipped vendor adapters" a decision
rather than an excuse.

What is left is smaller and sharper than the shape of it was.

**Nothing drives `redrive()`.** It is a method, and `engine.queue()` is
the thing that would call it on a schedule. Deliberately not wired: a
worker that retries erasures is a worker with credentials for every
registered sink, and where that runs is a deployment decision this package
should not make quietly.

**`audit()` has no scheduled caller.** It needs a genuinely shredded id to
hand a sink, which makes it natural to run right after a shred — so a
deployment could be told "your mirror claims to hold ciphertext and caches
plaintext" at the moment the claim matters, rather than never.

**Class C is findable but not indexed.** See item 2.

### 2. Context receipts, stored and queryable

Receipts exist, recompute without a secret, and now compose with `as_of`:
a receipt commits to an instant and `as_of` reconstructs the scope at it,
so *"was this context legitimate at the time it was built?"* is answerable
in two calls. Neither half answers it alone.

What is missing is the **reverse index**. The question people actually
have is *"which answers were built on this fact?"*, and today you can only
check a receipt you already hold. Storing receipts keyed by admitted id
turns an archaeology project into a query, and it is the only thing that
helps with a consequence — the Slack message, the fine-tune — at all.

The cost is a retention decision worth making deliberately rather than by
default: a receipt names ids and not document text, but it is a record of
*who saw what*, and that has its own sensitivity and its own deadline.

### 3. A failed KMS call must not look like a shredded key — shipped

`unseal()` now discriminates: `unrecoverable` when the data key is gone,
`key_unavailable` when it still exists and could not be fetched. Counted
apart, logged apart, both fail closed. Decided by asking our own key vault
whether the key document exists, not by matching the driver's error text.

**What is left.** It is tested against a simulated failure, not a real KMS
outage. A dashboard that trusts the reason string is trusting that
simulation until someone kills a real vault in anger.

### 4. `as_of(t)` — shipped, and it found the bug it was for

`as_of(t)` and `reachability_at()` exist. Building them surfaced the
defect that made the feature necessary: `Marked` carried an `at` and
**ignored it**, so a document revoked at 14:05 reported as unreachable at
14:02 — a system reconstructing what a model was allowed to see would have
placed the erasure before the answer that quoted the fact. An exoneration
built out of a bug, and an existing test asserted it.

`reachability_at()` returns `reachable` / `refused` / `unknown`, because a
row the reaper took leaves nothing to answer from and a bool has nowhere
to put that.

**What is left.** `as_of` is a lower bound and says so, but nothing
*measures* the bound: a deployment cannot currently answer "how much of
last Tuesday is still reconstructible?" The ledger knows what was revoked
and when, so the gap between "revocations recorded" and "rows still
present" is computable, and it is the number that tells an auditor whether
an `as_of` answer is worth anything.

---

## Sharp and cheap

High value per line. None of these are research.

### 5. Rules as data — the compiler shipped, the product did not

`compile_policy()` turns `{"deny": {"field": ..., "not_in":
"$caller.clearances"}}` into a rule indistinguishable from a hand-written
one, refuses at boot anything it cannot express on **both** halves, and
nine operators are checked against a live server for the two halves
agreeing.

What is missing is the part that makes it a product rather than a
function:

- **Nothing loads a policy from anywhere.** A scope document can hold one
  and nothing reads it. Wiring that means deciding who may *edit* it,
  which is the same unanswered authorisation question that keeps holds and
  sealing off the HTTP surface — and it is the third time that question
  has blocked something, which is a signal about what to build next.
- **No versioning.** A policy that changes silently makes every receipt
  issued under the old one unexplainable. The receipt already commits to
  the rule *reasons*; committing to a policy version would close that.
- **Only `deny`.** Deliberate — an `allow` would have to mean "and refuse
  everything else", which no single rule can promise while other rules
  exist — but somebody will ask, and the answer should be written down
  before it is argued about.

### 6. The admission overhead, as a published number — shipped

`bench/measure.py` measures TTL lag, per-tier latency and the cosine cliff.
It did not measure the thing being sold: p50/p99 CPU per admitted hit, and
the over-fetch factor under a realistic refusal rate. `bench/admission.py`
now does, and writes `bench/results/admission.json` and `.md`.

**The numbers** (laptop, Darwin arm64, Python 3.12, reproducible): the
per-candidate classification check is ~1 µs p50 and under 2 µs p99, flat
across page sizes 1–100 and 2–3 rules. Over-fetch under an interleaved refusal
rate is ~2× to 50% refused, ~7.6× p50 at 80%, ~15× p50 at 90%, refilling to
the round cap rather than starving. *"So you pay on every read, forever"* now
has an answer that is a number rather than prose.

**Still open:** the key-cache turnover — measured at ~60s in one shape and
>120s in another — is a sentence in a docstring rather than a number in a
table. The Atlas end-to-end scenario in `bench/admission.py` reports
`examined/admitted` on a real server-embedded index, but its wall-clock is
dominated by cloud round-trips and is labelled as such, not as the overhead.

### 7. The quarantine reviewer

`quarantine()` and `release()` ship. The **queue** does not, and quarantine
without a review loop is a graveyard — which is indistinguishable from a
leak nobody looked at.

`engine.queue(when=…)` exists and the document is already the job, so this
is roughly one line plus a surface: `queue(when={"quarantined": {"$ne":
None}})`. `lifted_total` is already counted apart from `revoked_total`, so
the queue arrives with the metric that matters: a climbing `lifted` means
the detector is mistuned.

### 8. Budget as a refusal reason — shipped

`Rule` answers *may this reach a prompt?* A context-token budget is the same
question with a different reason: `over_budget`, refusing marginal hits once
the budget is spent. `Budget(limit=…)` ships, and it is the evidence the
abstraction is a *primitive* rather than a compliance feature — a reason with
nothing to do with erasure, expressed in the same shape as one that is.

Building it grew the protocol in the way that was the actual point: a rule may
now be **cumulative**, declaring `needs_tab` to be handed a `Tab` scoped to one
read. Cumulative rules are asked last, after every pure rule has admitted the
document, so a budget never charges a hit a deadline was going to refuse — and
`saturate()` learned that a page cut short by a spent budget is *complete*, not
`starved`. `why_refused` generalised too: a rule exposing `why()` names its own
sub-reason, so `over_budget` and `uncosted` are counted apart, the same way
`Deadline` separates an expiry from an unreadable one.

**Still open:** the cost is the caller's. `Budget` reads a `tokens` field or a
supplied callable and ships no tokenizer, because a number pretending to match
a vendor's counting is the fabricated precision this repo refuses. An
integration that needs *Voyage's* count computes it and hands it over.
Budget and sealing also fail at construction when combined until the read path
can decrypt before cumulative admission; [`ISSUES.md`](ISSUES.md) records why
shipping the opposite order would make `Page.spent` a precise-looking lie.

### 9. A TypeScript client

The API is five calls. The callers that matter are TypeScript-first (MCP
hosts, RAG services) and the only client is Python.

Cheapest reach-per-line here, and a genuine test of whether "five calls" is
true — a second implementation is where an API finds out it has fourteen.

---

## Bigger bets, lower confidence

### Qdrant, not Postgres, as the second engine — the finding shipped

`drift/refusal_on_postgres.py` already runs the whole thesis on pgvector
with no MongoDB in it, which removed the "this is just MongoDB advocacy"
dismissal for the price of one file. A *shipped adapter* is still frozen, and
the honest reason to hold off is unchanged: it doubles the surface that has
to hold.

But **Qdrant was the more interesting target than Postgres**, and the open
question — is refusal on a rowless engine *enforceable* or merely
*conventional*? — is now answered, measured against the real service in
`drift/refusal_on_qdrant.py`: **conventional**. The payload filter enforces
the deadline in the read path cleanly (its Act II), but Qdrant has no row, no
view and no GRANT, so nothing can make the *unfiltered* read fail — the next
caller who omits the filter is served the expired point. The structural third
act Postgres reaches (revoke the table, grant only a view, the naive read
*raises*) is not available on the stock image. That is the finding pre-agreed
to be worth publishing: a whole class of vector databases can express this
guarantee only politely. A shipped adapter remains a different, frozen thing —
a finding is not an adapter.

### A leak detector for stacks that are not this one — the code-scan half shipped

Nobody buys a guarantee until they see their own number, and the number is
never zero. There are two versions of that instrument, and the cheap one is
now built.

**Shipped: the source scan.** `scanner/voyd_scan/__init__.py` reads a repository with
`ast` — no database, no credentials, one stdlib file a stranger can copy — and
reports how many reads hit a collection its own code marks with a deadline or
soft-delete field *without* filtering on it. It is the AST walker in
`test_no_module_reaches_past_the_handle.py` turned outward, and it is honest
about being a floor: dynamically named collections and ORM layers are
invisible, and a filter it cannot read is called *indeterminate*, never a leak.

**Still deferred: the live scan.** Pointing a tool at a live Pinecone +
Postgres to report how many currently queryable vectors have no live row needs
read credentials for somebody else's production data — a different kind of
responsibility than anything here carries. The code scan is the version that
does not, which is why it went first.

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
  this exists to remove. CI asserts no MCP tool is named for reclaiming
  anything — and, since a purge pass found `DELETE /v1/voyds/{slug}` sitting
  on the HTTP surface the whole time, `tests/test_nothing_reclaims_out_of_band.py`
  now asserts the *endpoint* half too. The sentence had been half-enforced
  for months: the destructive path nobody exercised was also the one
  cascading through a hardcoded list of two collections, written before
  three more existed.
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

- **Nothing has run against a hosted KMS.** KMIP is proven — a real
  server over TLS, rotation, shredding, TLS options — and the hosted
  providers (`Aws`, `Azure`, `Gcp`) share that code path. What is
  unproven is vendor-specific: credential discovery, throttling, and
  AWS `ScheduleKeyDeletion`'s 7-day minimum. See [`ISSUES.md`](ISSUES.md)
  #1.
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
