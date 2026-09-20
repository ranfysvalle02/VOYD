# VOYD

**Ranking is not permission.**

Your retrieval answers with a confident score and no idea whether that hit was
allowed to be there — an expired row the sweeper has not reached, a fact
somebody revoked, a vector from the embedding model you swapped last quarter, a
document a detector just flagged. An index decides what is *relevant*. Nothing
in the ordinary read path was asked the other question:

> **may this fact reach a prompt?** — answered on every read, immediately,
> whatever the sweeper is doing.

That question is the product. VOYD answers it at the one place every retrieval
path passes through on the way out: a read handle with no unfiltered read on it.

```python
docs = engine.model("notes").forgettable()

await docs.find({})                        # cannot return a forgotten fact
await docs.search(vector, text="P0301")    # nor can the search path
await docs.including_refused().find({})    # break-glass: gated, and counted

await docs.revoke({"_id": x}, reason="credential leaked")
# unreachable on the next read. The row is still on disk. That is the proof.
```

There is **no unfiltered `find` and no unfiltered `search`** on that handle, so
refusal doesn't depend on the next author remembering it. The failure mode is
inverted: you used to have to remember to be safe; now you have to declare that
you want the unsafe thing, in a word a reviewer can grep for — and that word is
not a free pass. `including_refused()` asks an `AUDIT` grant where an authority
is installed on every read, then increments `including_refused_total` and
records the actor/time in `receipts()`, so a cached break-glass handle is a
door with an alarm rather than a permanent pass.

Multi-tenant is one argument away — `model("notes", tenant="tenant_id")` — and
then the tenant field is required in every read, so `find({"tenant_id": t})`
rather than `find({})`. The [quickstart](examples/quickstart.py) runs both.

## Refusal is the product; the stack is around it

The sharpest instance is deletion. Deletion is a *storage* event, and storage
events are eventually consistent: a TTL monitor sweeps about once a minute
(measured here: 60.0s), an S3 lifecycle rule runs about once a day. In that
window your vector index keeps returning a deleted document as a normal,
well-scored result, with nothing logged and nothing to page on. **Delete is a
wish. Refuse is a contract** — but the contract is the point, not the sweeper.
The idea would still be true with an instant sweeper, because the index and the
row are different systems with different clocks.

So the erasure machinery is exactly that — machinery *around* refusal. A TTL
deadline collects the row; crypto-shredding makes the copies in backups and
replicas unreadable; refusal covers the window in between, on this read path,
now. Each is honest about what it does and does not reach — see
[three erasures](#three-erasures-each-honest-about-what-it-costs) below.

None of this is one vendor's idea. `drift/refusal_on_postgres.py` ports the
whole thesis to pgvector with no MongoDB in the file — a per-read predicate is
the relational cousin of row-level security, and the honest concession that
Postgres has no TTL is stated there rather than hidden. MongoDB is a good home
for the *assembly* — the row, the index, the embedding model and the key vault
under one deadline — not the identity of the idea.

---

## The one idea underneath it

> A retrieval rule has one authoritative form: a per-document check on the
> way **out**. Any query or index clause is an optional optimisation and must
> agree with it.

A `find` goes through a collection query, so the database can drop forgotten
rows server-side. A `$vectorSearch` hit does not pass through that query: it
arrives from an index that ranked it. An index filter can express the same
rule, but only if every read path, fallback and future caller supplies it.

Everything else here is downstream of that — including the invariant it
forces: **a rule that can express itself in a query or index filter but not per
document is not a slower rule, it is a silent hole.** [`AHA.md`](docs/AHA.md)
derives it in five steps, with the measurements.

---

## See it, in ten seconds

```bash
docker compose up -d mongo
uv run python examples/forget.py
```

A document expires, becomes unreachable *while its row is still on disk*, then
the reaper takes the row and its vector together. A pinned document beside it
is untouched. No API key, no vendor.

The smallest adoption — refusal on one collection, in the handful of lines a
team actually adds — is [`examples/quickstart.py`](examples/quickstart.py):
`find`-only on plain MongoDB first, then the same guarantee on the Atlas
`$vectorSearch` path where the server owns the embedding.

Then the counter-argument, which is also executable:

```bash
uv run --extra drift python drift/exhibit.py
```

Postgres holds the row, Qdrant holds the vector, MinIO holds the bytes, and a
cron is supposed to keep them agreeing. Four owners, four clocks, four ways to drift. The
deleted document answers the query.

Then the pilot, run on synthetic data against a real MongoDB, filling its own
report — a revoked credential still reaches a prompt through the raw read and
an unfiltered candidate producer, the handle refuses it on both, and so does
the summary an agent wrote from it. It does not run a vector index; it calls
`reachable()` directly to isolate the same per-hit egress boundary
`$vectorSearch` uses:

```bash
uv run python bench/pilot.py            # writes bench/results/pilot.md
```

Every line of the [`PILOT.md`](PILOT.md) report is filled from that run except
the one only a real team can answer: kept after two weeks. A proof of the
mechanism is not evidence of demand, and the report says so.

And before installing anything, run it against **your own** repository — one
stdlib file, no database, no credentials:

```bash
python scanner/voyd_scan path/to/your/repo
```

It reports your own floor: reads that hit a collection your code marks with a
deadline or soft-delete field, without filtering on it. Every one is a read
that can serve a document your own schema says is gone. The header is honest
about what a source scan cannot see.

And to see why this is more than a soft-delete flag, run
[`examples/rosetta.py`](examples/rosetta.py): soft-delete, TTL, a feature flag,
row-level security and a token budget written as five rules on **one** handle,
enforced together on both halves — `deleted=true` is the smallest of them.

```bash
uv run python examples/rosetta.py
```

---

## What it actually guarantees

A reason is a rule. Rules are asked in order, on every read, and reported by
name:

| rule | refuses because | waivable by the audit handle | reversible |
|---|---|---|---|
| `Deadline()` | the deadline passed, or cannot be read (fails closed) | yes | — |
| `revoked()` | somebody said forget this, now | yes | **no** |
| `quarantined()` | held back from models, deliberately still on disk | yes | yes |
| `EmbeddedWith(m)` | a different model produced this vector | yes | — |
| `Clearance(order=…)` | this caller is not cleared for this document | **no** | — |
| `Restricted()` | the document names who may see it, and it is not this caller | **no** | — |
| `compile_policy(…)` | a `deny` clause stored on the scope, compiled | **no** | — |
| `Budget(limit=…)` | the read's token budget is spent, or a hit's cost is unreadable | yes | — |

Two enforcement points, always both: the query clause and the per-document
check. That is also why `compile_policy(…)` refuses at boot anything it cannot
compile to *both* halves — falling back to the clause alone would be the silent
hole described above.

`Budget(…)` is the first rule with **no query half at all**, and that is sound
rather than a hole: a running per-read total is not something a per-document
query can express, so it lives entirely on the egress check. Per-document-only
is the *safe* asymmetry — slower, never a leak. It is a rule expressible only
as a clause that would be the hole, which is the one `compile_policy(…)`
refuses to compile. A budget is also the first *cumulative* rule: it is asked
after every other has admitted a hit, so it never spends the budget on a
document a deadline was going to refuse anyway.

The count is caller-owned, not guessed: by default each document supplies a
non-negative integer `tokens` field, or `cost=` supplies a callable. Missing,
fractional, negative and boolean costs fail closed as `uncosted`; VOYD does not
pretend `len(text) // 4` is Voyage's tokenizer. Several cumulative rules may be
declared on one handle; each gets its own state, keyed by *identity* rather
than by value, because two `Budget(limit=50)` declarations compare equal and
merging their totals would let one rule's limit silently govern the other. Budgeted `find()` requires an
explicit `sort`; strict-prefix admission over MongoDB's natural order would
change policy after compaction or failover. `Page.spent` is the amount
reserved by the selected prefix; over-fetched candidates below a full page do
not consume prompt budget. `find_one()` still returns prompt content and gets a
fresh one-item tab; `count()`, `exists()` and `reachability_at()` return
cardinality or reconstruction rather than content, so they deliberately do not
apply a cumulative budget. `Budget` and `.sealed(...)` currently fail at
construction when combined: decryption can refuse a selected hit, and charging
before that would call ciphertext "spent prompt tokens." The composition waits
until the read path decrypts before cumulative admission rather than shipping a
precise-looking lie.

The audit handle in that third column is not a free waiver. `including_refused()`
asks an `AUDIT` grant on every read where an authority is installed and is
counted in `receipts()` as `including_refused_total`, with actor/time, so
"waivable" means waivable through a door with an alarm — not by default.

**What the per-read check costs, measured.** The reviewer's first objection is
*"so you pay on every read, forever."* On a laptop the per-candidate egress
check is about **1 µs p50, under 2 µs p99**, flat from a 1-hit page to a
100-hit page. Because forgotten hits are fetched then dropped, a page can
over-fetch; under a realistic (interleaved) refusal rate that stays near **2×
up to 50% refused**, and the handle refills rather than returning a short page.
Run it: `uv run python bench/admission.py` writes
[`bench/results/admission.md`](bench/results/admission.md).

**Forget-me-now.** Forgetting composes, and it is the same word at every
tier:

```
revoke a fact       →  and what was derived from it, at any depth
shred a scope's key →  and every copy of its ciphertext, in every backup
forget a namespace  →  POST /v1/voyds/{slug}/forget, the same verb one tier up
```

### Three erasures, each honest about what it costs

| | when | where | result |
|---|---|---|---|
| **refusal** | immediate | this read path only | unreachable *now* |
| **crypto erasure** | eventual (key cache) | every copy, everywhere | unreadable *soon* |
| **the TTL reaper** | ~60s | this deployment only | gone *eventually* |

The key cache is a window in which the ciphertext is still readable — and
refusal already refused the document, with no window at all. Refusal in turn
binds only this application — and the key is gone from all of them. Neither is
the answer. Both is.

---

## Where the reasoning lives

This repository keeps its arguments **next to the code they justify**, not in
this file. Each module opens by stating what it is for and what it refuses to
claim:

| | |
|---|---|
| [`engine/admission/`](voyd/engine/admission) | refusal as a retrieval guarantee. Read [`core.py`](voyd/engine/admission/core.py) first — the state and the two enforcement points — then [`rules.py`](voyd/engine/admission/rules.py) for the rule protocol, [`lineage.py`](voyd/engine/admission/lineage.py) for inherited refusal, [`reads.py`](voyd/engine/admission/reads.py) for `as_of` |
| [`engine/keyring.py`](voyd/engine/keyring.py) | crypto-shredding, and why CSFLE and Queryable Encryption are a real trade |
| [`engine/custody.py`](voyd/engine/custody.py) | who holds the key that wraps the keys — `Ephemeral` → `LocalFile` → AWS/Azure/GCP/KMIP |
| [`engine/ledger.py`](voyd/engine/ledger.py) | the hash chain, and forty lines on what it does *not* prove |
| [`engine/perimeter.py`](voyd/engine/perimeter.py) | who else holds a copy, and why enforcing it is not on offer |
| [`engine/authority.py`](voyd/engine/authority.py) | may this caller *do* this — and why granting and withholding are asymmetric |
| [`engine/search.py`](voyd/engine/search.py) | the measurements behind *not* pushing deadlines into the vector index |

Start with `admission/core.py`; its own package docstring lists the other
twelve modules in dependency order. If the module docstrings and this README
ever disagree, the docstrings are right.

---

## How the claims are checked

Against a **real MongoDB**, on every commit. No mock tier — these properties
are only true if the *queries* are right, so CI stands up Atlas Local and runs
the suite against real `mongot`.

The tests are written as arguments. A few that carry more than their weight:

- **`test_admission_is_structural.py`** writes the naive read — the query a
  developer produces who has never heard of `expire_at` — and asserts it is
  still safe. It also asserts the *unwrapped primitive still leaks*, because if
  that stopped being true the other checks would quietly become tautologies.
- **`test_no_module_reaches_past_the_handle.py`** walks the AST of every module
  and fails if one calls the search primitive on a collection that refuses.
- **`test_a_third_party_rule_is_a_first_class_reason.py`** installs two rules
  this package does not ship and asserts both enforcement points agree.
- **`test_the_public_surface_is_deliberate.py`** pins `__all__`, so a new
  public name is a line somebody justifies.

Including the custody ladder's external rung: a **real KMIP server** runs in
the suite, so the data key is wrapped by a key the process does not hold, and
rotation and shredding are exercised against something that can refuse.
Enterprise key custody is not a synonym for one cloud vendor's managed
service, and the open standard for it can be started in a subprocess.

And [`ISSUES.md`](docs/ISSUES.md) lists what is wrong, unproven or imprecise in what
already ships — now narrowly: the three *hosted* providers share every line of
that code path, and what is unproven about them is vendor-specific.

---

## Install

**Not on an index yet.** `pip install voyd` is the intended install, and the
wheel already builds and installs clean on its own — CI builds it and imports
`Engine` from it in a fresh venv on every commit — but `0.1.0` has not been
pushed to PyPI. Until it is, install from a clone with `uv`:

```bash
git clone https://github.com/ranfysvalle02/VOYD && cd VOYD
uv sync                       # Engine + a MongoDB driver. That is the base.

# Later surfaces, not the on-ramp. The handle is the product; these are ways to
# reach it. Add one only when a pilot has kept the handle (see PILOT.md).
uv sync --extra app           # the HTTP service
uv sync --extra crypto        # cryptographic erasure
uv sync --extra mcp           # the same guarantee, as tools a model can call
```

Or build and install the wheel the way a stranger eventually will —
`uv build`, then `pip install dist/voyd-0.1.0-py3-none-any.whl` — which is
exactly what CI does before asserting the engine-only contract holds.

Running the HTTP service needs its settings file — `cp .env.example .env`,
then `docker compose up -d`. Every key in it is checked against the real
settings by a test, because a Quickstart that cannot be followed is the
entire first impression and it rots silently.

`import voyd` is seven names and one dependency. Importing `Engine` does not
load FastAPI, and CI asserts it — in the built wheel, not just the source tree.

```python
from voyd import Engine

engine = Engine(client, db)
await engine.connect()

notes = engine.model("notes", tenant="tenant").sealed("text")   # encrypted at rest
await engine.ensure()

await notes.seal({"tenant": "alice", "text": diagnosis})
await notes.find({"tenant": "alice"})    # decrypted, and refuses what it cannot
await notes.shred("alice")               # noise, in every copy that exists
```

---

## What is new here, and what is not

Worth stating plainly, because a reader is entitled to ask and the honest
answer is a stronger position than novelty would be.

**Not new.** Making an unsafe operation unnameable is object-capability
security, and it is from the 1960s. Filtering rows at read time is row-level
security. Views-and-grants is SQL 101. Checking at the endpoint rather than in
the pipe is the end-to-end argument (Saltzer, Reed and Clark, 1984). Every
component here is well known, and a design that needed a new primitive to work
would be a worse design.

**New, and load-bearing:**

- **The unification.** Expiry, revocation, quarantine, legal hold, erasure
  under GDPR Art. 17, a vector from a model you replaced, a spent token budget
  and a duplicate passage are treated everywhere else as eight features. They
  are one primitive — the same `refuses()` call, the same receipt, the same
  break-glass door. Collapsing apparently-unrelated things into one mechanism
  is the signature of an abstraction that is load-bearing rather than tidy.
- **The inversion of authority.** The instinct is that the query filter is the
  real enforcement and the per-document check is belt-and-braces. It is the
  other way round: the per-document check is authoritative and the clause is a
  discardable optimisation. The asymmetry behind that — egress-only is slower
  and safe, clause-only is a silent hole — is the whole argument, and
  [`AHA.md`](docs/AHA.md) derives it.
- **The placement.** Nobody had put a capability boundary on retrieval egress,
  which is the path that now feeds a model rather than a person who could
  notice a stale result.

[`gold.md`](docs/gold.md) argues that the second and third of those make the
*protocol* the thing worth owning, and that this repository currently markets
the object instead.

---

## Read more

Three shelves, in the order a new reader should take them. The root holds the
front door, the on-ramp and the pilot; everything else is reference material in
[`docs/`](docs), where each file has exactly one job.

**Start here** — the idea, and how to use it.

| | |
|---|---|
| [`AHA.md`](docs/AHA.md) | the one idea, derived in five steps with the measurements. Everything else is downstream |
| [`ADOPTING.md`](ADOPTING.md) | the first hour: one collection, one read path, under ten lines — and what you do *not* get by stopping there |
| [`PILOT.md`](PILOT.md) | the smallest honest trial: exit criteria and a report template — plus `bench/pilot.py`, the same flow against a real MongoDB with the report already filled |

**The argument** — why it is a real problem, at length and executable.

| | |
|---|---|
| [`blog.md`](docs/blog.md) | the long version: the three times the same bug came back, and the two bugs in the proof |
| [`policy-engines.md`](docs/policy-engines.md) | the converse of the one idea: a retrieval rule no index filter and no policy engine can express, checked against a live Casbin enforcer |
| [`gold.md`](docs/gold.md) | the handle is the demo; the protocol is the product — three members, five attributes, and a theory of set-relative rules |
| [`PORTABILITY.md`](docs/PORTABILITY.md) | the guarantee is portable; its *enforcement* is not. Three engines measured, and the rung most vector databases cannot reach |
| [`drift/`](drift/README.md) | the counter-argument, executable — including the whole thesis ported to pgvector with no MongoDB in the file |
| [`examples/`](examples/) | thirteen runnable programs, most in under ten seconds — start with [`quickstart.py`](examples/quickstart.py), then [`rosetta.py`](examples/rosetta.py) for the abstraction |
| [`scanner/`](scanner/README.md) | `voyd-scan`: one stdlib file, zero dependencies, pointed at *your* repository — the count this whole argument is about |

**What is wrong with it, and what happens next** — read this before trusting any of the above.

| | |
|---|---|
| [`ISSUES.md`](docs/ISSUES.md) | defects, unproven claims, and operational caveats |
| [`ideas.md`](docs/ideas.md) | what is worth building next, and what is deliberately not |
| [`opportunities.md`](docs/opportunities.md) | what is worth *doing*, ranked — mostly not code, and honest about the one number that is still zero |
| [`CONSIDERATIONS.md`](docs/CONSIDERATIONS.md) | what will bite you while working on it: the traps, what each cost, and which guard now catches it |
| [`BUG.md`](docs/BUG.md) | an upstream defect this repository found and filed, kept because a test still depends on the fallback it forced |

MIT.
