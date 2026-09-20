# Appendix: the sell, the ceiling, and the vendors

Three things decide whether this gets adopted. None of them are engineering
problems.

The one constraint underneath all three:

> The guarantee is enforced at a handle, in one process, in one language,
> against one database. Everything about adoption follows from that sentence.

§2 is that constraint in full. §1 and §3 are what it costs.

---

## 1. The sell, decomposed

The pitch fails in a specific place, and it is worth being precise about
which place, because three different failures get blamed on "developers don't
care about compliance" and only one of them is real.

### 1.1 The four things a buyer must accept, in order

Every one of these must land. They are sequential — failing at step *n* means
steps *n+1* onward never get evaluated.

| # | claim | difficulty | why |
|---|---|---|---|
| 1 | The window exists | **easy** | Provable in 10 seconds. `drift/exhibit.py` does it. |
| 2 | The window is a *problem* | **hard** | Requires believing a stale read is a breach, not a lag. |
| 3 | The fix must be *structural* | **hardest** | Requires admitting you will not remember to filter. |
| 4 | The structure should be *this one* | **medium** | Ordinary technology selection. Solvable with docs and a demo. |

Almost everyone reads this project as a step-4 pitch — "another retrieval
library, how does it compare to X" — and almost all of its actual work is at
step 3. The mismatch is the sell problem in one line.

### 1.2 Step 2 is an incident-shaped belief

Nobody believes the window is a problem until it has cost them something.
Before that, the honest internal reasoning is:

> "The TTL sweeps in a minute. Who cares about a minute?"

And *usually they are right*. A stale product recommendation for sixty seconds
is not an incident. This is not developers being sloppy; it is correct
prioritisation given their actual data.

The window becomes a problem only when the fact is one of a small set:

- a credential or key that just leaked
- a document a court ordered retracted
- a record a subject exercised erasure over
- a person's data after they left the tenant
- a document a prompt-injection detector just flagged
- anything under a legal hold that was *just* imposed

The common structure: **the value of the fact inverts at a known instant, and
the instant is not scheduled.** Ordinary TTL handles scheduled irrelevance
perfectly well. It cannot handle the unscheduled inversion, because sweepers
run on their own clock and the whole point is that you do not control when the
bad moment arrives.

So the sell is not "your deletes are slow." It is:

> **When something goes wrong, how long does the wrong thing keep reaching
> your model?** Right now, your answer is a cron schedule.

That question is answerable by anyone, it has a number, and the number is
embarrassing. That is the wedge. "Refusal is a retrieval guarantee" is the
*explanation*, not the opener — it is a sentence for people who already
flinched at the number.

### 1.3 Step 3 is where it genuinely gets hard

Step 3 asks a developer to accept a claim about their own future behaviour:

> You will add a second read path. Then a fifth. The filter will be right in
> the one you were thinking about when you learned the lesson, and absent in
> the others.

Everyone knows this is true in general and nobody believes it about themselves
in particular. It is the same psychology as "you should write tests" and it
loses to the same counter: *I'll just be careful.*

The repo's answer is unusually strong and it is not an argument, it is a
demonstration — the `forgettable()` handle has **no unfiltered `find` and no
unfiltered `search` on it**. There is nothing to be careless with. The unsafe
path exists and is named `including_refused()`, which is greppable, reviewable,
and embarrassing to write.

The thing to lead with here is not the philosophy. It is:

```python
await docs.find({})                       # cannot return a forgotten fact
await docs.including_refused().find({})   # break-glass: gated, and counted
```

Two lines. They make the argument without making it. The correct demo order
is **API first, thesis second** — show the missing method, let them notice, and
only then explain why. Explaining first turns it into philosophy and
philosophy loses to `I'll just be careful`.

### 1.4 The three-hop problem

The deeper structural issue is that the *buyer*, the *payer*, and the *victim*
are three different people:

| role | who | what they want |
|---|---|---|
| **victim** | the data subject, the leaked credential's owner | for the fact to stop being served |
| **payer** | legal, compliance, the CISO | an answer to an auditor |
| **buyer** | the engineer who must route reads through `Admission` | to not refactor the read path |

The engineer bears 100% of the cost and receives roughly 0% of the benefit.
Compliance receives the benefit and cannot make the change. This is the
classic split-incentive problem, and it is why compliance tooling is sold
top-down even when it is technically bottom-up.

Two real strategies:

**(a) Sell the engineer something selfish.** The handle has to be *nicer* than
what they have, on some axis they already care about. Candidates present in
the repo: one connection string instead of four systems; `health()` with
degraded as a first-class state; `receipts()` as a dashboard they didn't have;
`Page.starved` as the missing-hits signal; `EmbeddedWith` as the model-swap
that inverted ranking. The `memory` trait is a *composition* of those, not
the product — a handle they wanted for recall, with refusal as a property of
it. This is the Stripe/Tailscale shape — win on ergonomics, deliver
correctness as a side effect. Do not sell the composition as "agent
memory": that comparison set is crowded and judged on recall.

**(b) Sell the auditor's sentence to the payer.** Not "we refuse on read" but
the artifact: *show me that this document stopped being reachable at 14:02, and
show me the record has not been edited since.* `ledger.py` produces exactly
that. Compliance buys the sentence; engineering gets handed the library.

Strategy (a) is better and slower. Strategy (b) is faster and produces
resentful adopters. The repo is built for (a) — the traits, the ergonomics,
the one-connection-string argument. The README now opens on (a)'s frame —
"ranking is not permission" and the two-line handle — with (b)'s auditor
sentence following rather than leading. That copy change is made. The
highest-value change left is not another pass at the first screen — it is a
retained integration, which [`PILOT.md`](PILOT.md) is for.

### 1.5 What makes this sell *unusually* hard, specifically

Four properties stack, and most hard sells only have one or two:

1. **The failure is invisible.** A refused document logs nothing, pages
   nothing, and looks exactly like a correct result. There is no incident to
   point at because the system does not know it failed. Compare a memory leak,
   which announces itself.
2. **The win is also invisible.** Success is "a thing that would have been
   embarrassing didn't happen." Nobody gets promoted for it. There is no
   dashboard that goes up.
3. **It requires touching the read path** — the highest-blast-radius,
   lowest-appetite-for-change part of any retrieval system.
4. **The honest version concedes a lot.** §2. The pitch cannot
   truthfully say "and now you are safe," and the project's own documentation
   refuses to say it.

Points 1 and 2 together mean the product's entire value is counterfactual. That
is the hardest category of thing to sell that exists — it is the insurance
problem, the backup problem, and the seatbelt problem. All three of those
industries are large, and all three are sold either by regulation or after an
incident. That is the realistic go-to-market and it is worth naming rather than
hoping for organic developer love.

---

## 2. The ceiling of the pitch

Nail this down before talking to anyone technical. A sharp listener finds it in
about ninety seconds, and if you haven't said it first, you've lost the room.

### 2.1 The exact statement

> Refusal binds **this handle, in this process**. Anything that reaches the
> collection another way is unaffected.

"Another way" is a real and populated list:

- `mongosh`, Compass, or a DBA with a shell
- a BI tool, an ETL job, a reverse-ETL sync into a warehouse
- a second service in another language against the same URI
- Atlas Data Federation / Online Archive / a change stream consumer
- a replica, a snapshot, a backup, a `mongodump` on someone's laptop
- the read path a teammate writes next month using the raw driver, because the
  handle was inconvenient that day

That last one is the important one. The guarantee is structural *within* the
handle and conventional *about using the handle at all*. VOYD converts
"remember to filter" into "remember to use `forgettable()`" — which is a
genuine and large improvement, because it moves the decision from thousands of
call sites to a handful of construction sites, where it is reviewable. But it
does not eliminate the class. It relocates it to a place where it is visible.

**Say it that way.** "We moved the failure from every call site to one
construction site" is a strong, true, defensible claim. "We made it impossible"
is false and a good engineer will catch it and then discount everything else
you said.

### 2.2 The ceiling is a *defended* one, though

Three things raise it meaningfully, and the project already has all three:

**Crypto erasure goes where refusal cannot.** `keyring.py` — destroy the scope
key and every copy, in every replica, snapshot, and unrestored backup, becomes
noise. The DBA with `mongosh` gets ciphertext. This is the actual answer to
2.1's list, and it is priced honestly: eventual, bounded by the key cache
window. The README's three-erasures table is the right frame — *refusal is
immediate but local, crypto erasure is global but eventual, and the reaper is
neither.* Neither alone is sufficient; both together cover each other's gap.
That composition is the real product and it deserves more prominence than the
single-word "refusal" headline currently gives it.

**The perimeter is at least enumerable.** `perimeter.py` is the most
intellectually honest file in the repo and states the governing rule outright:
*you cannot enforce refusal in a system you do not control; you can propagate,
observe, and report.* It then classifies every downstream holder as `sealed`
(holds ciphertext — already solved by the key), `owned` (plaintext you control
— propagate best-effort, record the attestation), or `derived` (a Slack
message, a fine-tune, a vendor prompt cache — unreachable, and say so). Most
teams cannot produce this list at all. `describe()` printing it is worth more
than a propagation mechanism that overstates itself, and the file says that
too.

**The HTTP/MCP surface closes the loop for non-Python callers.** §2.1's
"second service in another language" is answered by making the deployment the
enforcement point rather than the library — the `/v1` API and the MCP server
both sit *behind* the handle. A Go service that talks to the VOYD deployment
gets refusal; a Go service that talks to MongoDB directly does not. That is a
deployment-topology argument, not a code argument, and it should be stated as
one: **if you want the guarantee across languages, the collection is not your
API — the namespace is.**

### 2.3 The honest ceiling statement, for slides

> Refusal is enforced where reads go through VOYD. For copies outside that
> boundary, the key is the mechanism, not the filter — and for consequences
> outside *that* (a Slack quote, a fine-tune, a vendor's prompt cache) nothing
> can reach them and we will not pretend otherwise. What we offer there is that
> finding them is a query instead of an archaeology project.

Leading with this *gains* credibility. The instinct to bury it is wrong: the
listener is going to construct the objection anyway, and the only variable is
whether they hear the answer from you or invent a worse one themselves. The
repo's own instinct — `ledger.py` spending forty lines on what the chain does
not prove, including that the database operator could rewrite it from entry
zero — is exactly right and should be the house style everywhere.

### 2.4 The one hole in the escape hatch — since closed

`including_refused()` has to exist — audit and administration need unfiltered
reads — and it is named well. But naming a hole is not closing it: it still
turns the guarantee off, and for a long time it did so ungated and uncounted,
so the 2am bug-fix use needed no permission and left no trace.

All three mitigations once listed here as future work have shipped:

- **Gated.** Disclosing a forgotten fact is the *granting* direction, so it
  asks an `Authority` for an `AUDIT` grant — the same asymmetry `release` sits
  behind, `AUDIT` alongside `RELEASE` in `authority.py`. With no authority
  attached (the library default, where the caller is the application) it stays
  a no-op; a withholding-only pipeline is refused.
- **Counted and re-authorised.** Every terminal read asks again for `AUDIT`,
  increments `including_refused_total`, and records the actor/time in
  `receipts()`. A cached handle cannot turn one old grant into unlimited
  invisible reads; constructing one and never using it records nothing.
- **Fenced.** `tests/test_break_glass_is_named.py` walks the AST and fails the
  build if any module outside `admission/core.py` reaches for the public name.
  The engine's own writes use a private `_unfiltered()` hatch, because a
  `revoke` is a `REVOKE`, not an `AUDIT`, and routing it through the gate would
  break `Grants.withholding_only()`.

What is *not* fixed, and is not this package's to fix: a call site in
application code. The CI fence covers `voyd/`; a deployment polices its own.

---

## 3. Compliance vendors

### 3.1 What they will say

The objection arrives in one of four forms, roughly in order of frequency:

1. "We already have TTL indexes / lifecycle rules."
2. "Our DSAR tooling already handles erasure requests."
3. "This is a data-governance feature; OneTrust/Collibra/BigID covers it."
4. "Our vector DB has metadata filtering. We just filter on `deleted: false`."

Each is wrong in a *different* way, and conflating them loses the argument.

### 3.2 Answering each, precisely

**(1) TTL indexes.** TTL answers *scheduled* irrelevance. It runs on a sweeper
clock — measured in this repo at 60.0s — and cannot answer an unscheduled
inversion at all. The rebuttal is a question, not an assertion: *a credential
leaked thirty seconds ago. Is it in your next retrieval?* With TTL the answer
is "yes, probably, for up to a minute, and nothing will log it." Nobody has a
good response to that, because there isn't one.

**(2) DSAR tooling.** DSAR platforms orchestrate the *request* — intake,
routing, tracking, proof of completion. They are workflow over systems that do
the deleting. They issue an instruction and mark a ticket closed when a system
acknowledges. Crucially: the acknowledgement is that the *delete was issued*,
not that the *fact stopped being retrievable*. VOYD operates one layer below
and answers the question the DSAR tool assumes is already answered. These are
complementary, and saying so is more persuasive than competing — the natural
framing is *"your DSAR tool's tickets become true faster, and you get a hash
chain instead of a ticket status as evidence."*

**(3) Governance platforms** (OneTrust, Collibra, BigID, Securiti). These are
catalogue-and-policy layers: discover data, classify it, attach policies,
report posture. They describe and attest; they are almost never in the read
path. A governance platform can tell you a collection contains PII subject to
a 30-day retention policy. It cannot stop the retrieval that happens 45 days
later. **Description versus enforcement** is the whole distinction, and it is
the cleanest one in this section. `compile_policy(...)` — a `deny` clause
stored on the scope and compiled into the read path — is arguably the bridge:
it makes a governance policy into an executed rule rather than a documented
one, which is a genuinely interesting integration story rather than a
competitive one.

**(4) Vector DB metadata filtering.** This is the only technically serious
objection and deserves the most care, because on the surface it looks like a
complete answer. The rebuttals, in strength order:

- **It is a filter you must remember**, at every call site, forever, in every
  service. That is exactly the failure mode `Admission` is structured to
  remove. `deleted: false` is one `AND` away from being forgotten by the next
  author, and the failure is silent.
- **Filtering the ANN index is not free and sometimes not possible.**
  `search.py` carries the measurements on why deadlines are not pushed into the
  vector index: it requires an unmigratable index change. Pre-filter and
  post-filter have different recall characteristics, and aggressive filters
  degrade ANN recall in ways that are difficult to see and easy to ship.
- **Two enforcement points, not one.** VOYD pushes into the query *where the
  query can express it* and re-checks per document on egress. `$vectorSearch`
  hits do not pass through the collection query; an index filter reaches them
  only when that caller supplies the equivalent rule. The egress check is
  therefore the guarantee and either kind of pushed-down filter is the
  optimisation. Metadata filtering alone is only structural if every read
  path, fallback and future caller applies it.
- **The flag and the row disagree at exactly the wrong moment.** Setting
  `deleted: true` and having the index reflect it are two events with a gap
  between them — which is the original problem with extra steps.

### 3.3 The real competitive risk is not a vendor

It is **"we'll just add a filter."** Three lines, no dependency, no
procurement, ships this afternoon, and is *90% correct*. It fails only in the
paths somebody forgot, which is precisely the failure that is invisible until
it isn't.

You cannot beat this on features. It is beaten only in one of three ways:

1. **Ergonomics** — the handle is nicer to use than the filter is to maintain,
   so refusal comes along free with something they wanted anyway (§1.4a).
2. **An incident** — theirs or a well-publicised one belonging to someone else.
3. **An auditor asking for the sentence** the filter cannot produce: *prove it
   stopped being reachable at 14:02, and prove the record has not been edited.*

Note that (2) and (3) are not things a project controls. (1) is. That is a
strong argument for spending effort on the traits, the one-connection-string
story, and the demo — and comparatively less on sharpening the thesis prose,
which is already past the point of diminishing returns and is not what loses
the deal.

### 3.4 The regulatory tailwind worth naming

Erasure obligations are drifting from *"delete the record"* toward *"ensure the
data is not used"* — and retrieval-augmented generation is the case that makes
the difference legible, because a deleted record that still reaches a prompt is
visibly, demonstrably still in use. Regulators tend to arrive at the place where
the harm is easiest to show. "The row was deleted but the model still answered
with it" is about as showable as it gets.

This is a reason for the project to exist that does not depend on anyone
currently wanting it. Worth stating as a bet with its timing acknowledged,
rather than as a present-tense market claim — and worth distinguishing from the
weaker version of the argument, which is just gesturing at GDPR.

---

## 4. Open questions

Not criticisms — questions the repo has earned the right to be asked.

1. **What is the p50/p99 cost of the egress re-check** — answered.
   `bench/admission.py` measures it: ~1 µs p50 and under 2 µs p99 per
   candidate, flat from a 1-hit page to a 100-hit page, and over-fetch that
   stays near 2× up to a 50% refusal rate. Reproducible, written to
   `bench/results/admission.md`. The 60.0s TTL measurement was doing enormous
   persuasive work precisely because it was a number; this now has the same.

2. **What is the smallest possible adoption?** — answered for the part that
   decides the pitch. `examples/quickstart.py` gets refusal on one collection
   and one read path in under ten lines, with no HTTP surface and no extra
   traits, and `tests/test_the_quickstart_refuses.py` pins that body under ten
   lines so it cannot grow into a migration. It still constructs `Engine`;
   whether that too could be skipped for an even smaller footprint is
   pre-registered in [`DECISION.md`](DECISION.md), deliberately not done yet.

3. **What happens on the second process?** Two app replicas, one revokes. The
   other refuses on its next read because the rule is evaluated per-read
   against stored state, not cached — worth stating explicitly, because a
   reader will assume in-memory state and assume wrong. This is a strength
   currently going unclaimed.

4. **Is `including_refused()` counted and gated?** Both, now — see §2.4: it
   asks `AUDIT` again on every terminal read, increments
   `including_refused_total`, and records actor/time in `receipts()`. The
   entry stays as the question to ask of any system making the same claim.

5. **Which of the three erasures do people actually turn on?** If crypto
   erasure requires `crypt_shared` (Enterprise, off-PyPI), what fraction of
   users are running refusal alone — and is the three-part composition of §2.2
   therefore describing a configuration almost nobody has? That would be worth
   knowing, because the honest composite answer to the ceiling objection
   depends on it.

---

## 5. One-paragraph version

The window between delete and gone is real and measurable; ordinary stacks
answer it with a filter or a sweeper, not a structural read-path guarantee.
The hard part is getting anyone to agree it matters before it has cost them
something, because the failure is invisible, the win is counterfactual, and
the fix touches the read path. The guarantee binds one handle in one process,
which is a genuine ceiling — answered, not eliminated, by crypto erasure for
copies and by an enumerable perimeter for consequences — and the right move
is to state that ceiling first, since a sharp listener finds it in ninety
seconds anyway. Compliance vendors are not the competition: DSAR tooling
orchestrates requests, governance platforms describe and attest, and neither
is in the read path. The actual competitor is a developer adding
`deleted: false` to a filter this afternoon, and the only thing that reliably
beats that — the only one within the project's control — is being nicer to
use than the filter is to maintain.
