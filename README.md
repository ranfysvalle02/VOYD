# VOYD

**Your vector index is still serving documents you deleted.**

Admission control for retrieval: a read path that *cannot* return a fact it has
forgotten — expired, revoked, quarantined, legally held, or embedded by a model
you replaced last quarter. Built for RAG on MongoDB Atlas Vector Search, and
ported to pgvector and Qdrant to show the idea is not one vendor's feature.

---

## The incident

Six read paths against a collection with a deadline. One of them forgot the
filter.

Nothing broke. No error, no alert, no failed request — the read returned a
confident, well-scored, *expired* document, and a model wrote it into an answer
somebody believed. The defect was not that one filter was wrong. It was that
remembering the filter was a thing a person had to do, six times, forever,
including the next person to open the file.

It generalises past deadlines. A document you deleted, a credential somebody
revoked, a fact a customer asked you to erase under GDPR Art. 17 — your storage
layer agrees it is gone. Your index has not heard. A TTL monitor sweeps about
once a minute (measured here: 60.0s); an S3 lifecycle rule runs about once a
day. Until they catch up, ranking keeps answering a question nobody asked it:

> An index decides what is **relevant**. Nothing in the ordinary read path was
> asked the other question — **may this fact reach a prompt?**

Deletion is a storage event on a storage clock. Retrieval is a read on a
different one. **Delete is a wish. Refuse is a contract.**

---

## Do you have this bug? Find out before installing anything

One stdlib file. No database, no credentials, nothing to install — and you
point it at *your* repository, not this one:

```bash
python tools/leak_scan.py path/to/your/repo
```

```
scanned 1 file(s).
1 collection(s) carry a deadline or mark: notes
2 of 3 read(s) against them do not filter the mark:

  app/store.py:5  notes  (filter does not name the mark)
  app/store.py:8  notes  (filter does not name the mark)
```

A collection counts as deadline-bearing only when your own code says so — a
write or index that names a mark field, or a read that already filters on it.
Every hit is then a read that can serve a document your own schema calls gone.

The number is built to be defensible rather than alarming. It parses source
with `ast`, so ORM layers, dynamically named collections and filters assembled
by a helper are reported as *indeterminate*, never counted as leaks; the file's
header is specific about what it cannot see. It undercounts on purpose.

**Zero means you do not need this.** Anything else is the gap, and the rest of
this page is about closing it structurally instead of one filter at a time.

---

## The fix, in the diff you would actually write

```python
docs = engine.model("notes").forgettable()

await docs.find({})                        # cannot return a forgotten fact
await docs.search(vector, text="P0301")    # nor can the search path
await docs.including_refused().find({})    # break-glass: gated, and counted

await docs.revoke({"_id": x}, reason="credential leaked")
# unreachable on the next read. The row is still on disk. That is the proof.
```

That handle has **no unfiltered `find` and no unfiltered `search`**, which is
the entire trick. Safety stops being something the next author remembers and
becomes something they would have to actively ask for. The failure mode is
inverted: you used to have to remember to be safe; now you declare that you
want the unsafe thing, in a word a reviewer can grep for.

And that word is not a free pass. `including_refused()` asks an `AUDIT` grant
on every read where an authority is installed, increments
`including_refused_total`, and records actor and time in `receipts()` — so a
cached break-glass handle is a door with an alarm, not a permanent key.

Multi-tenancy is one argument away — `model("notes", tenant="tenant_id")` —
after which the tenant field is *required* in every read, so `find({"tenant_id":
t})` rather than `find({})`. The [quickstart](examples/quickstart.py) runs both.

**This is not a framework, and adopting it is not a migration.** One
collection, one read path, under ten substantive lines, your existing code left
alone — a limit that is enforced by a test rather than promised in prose.
[`ADOPTING.md`](ADOPTING.md) is the first hour, and is just as specific about
what you still do not get when you stop there.

---

## Watch it refuse

```bash
docker compose up -d mongo
uv run python examples/forget.py
```

A document expires and becomes unreachable *while its row is still on disk*;
then the reaper takes the row and its vector together. A pinned document beside
it is untouched. No API key, no vendor, no account. Call it five minutes with
the image pull — the ten-second version is the leak scan above, which needs
none of this.

<details>
<summary><b>More proofs, each executable</b> — the counter-argument, the pilot, the abstraction</summary>

**The counter-argument**, which is also runnable:

```bash
uv run --extra drift python drift/exhibit.py
```

Postgres holds the row, Qdrant holds the vector, MinIO holds the bytes, and a
cron is supposed to keep the three agreeing. Four clocks, three ways to drift.
The deleted document answers the query.

**The pilot**, on synthetic data against a real MongoDB, filling in its own
report. A revoked credential still reaches a prompt through the raw read and
through an unfiltered candidate producer; the handle refuses it on both, and so
does the summary an agent wrote from it. It runs no vector index — it calls
`reachable()` directly, to isolate the same per-hit egress boundary
`$vectorSearch` uses:

```bash
uv run python bench/pilot.py            # writes bench/results/pilot.md
```

Every line of the [`PILOT.md`](PILOT.md) report is filled from that run except
the one only a real team can answer: *kept after two weeks*. A proof of the
mechanism is not evidence of demand, and the report says so itself.

**The abstraction**, for anyone thinking this is a soft-delete flag with extra
steps. Soft-delete, a TTL, a feature flag, row-level security and a token
budget, written as five rules on **one** handle and enforced together on both
halves — `deleted=true` is the smallest of the five.

```bash
uv run python examples/rosetta.py
```

</details>

---

## Honest status

The mechanism is checked by 878 tests against real `mongod` and real `mongot`
on every commit, with no mock tier. That is evidence the mechanism works. It is
**not** evidence that anyone needs it: there are no production users yet, the
package is not on PyPI yet, and [`ISSUES.md`](docs/ISSUES.md) lists what is
wrong, unproven or imprecise in what already ships. Read that before trusting
anything above it.

---

## Refusal is the product; the stack is around it

*"So make the sweeper faster."* It would not help, and that is the part worth
sitting with. The contract is the point, not the latency: even with an
instantaneous reaper the index and the row are still different systems with
different clocks, and a hit that was ranked a moment ago is still a hit that
was never asked whether it was allowed. Shrinking the window is not the same
as having an answer inside it.

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

And the converse, which is what makes the egress check the *only* complete
place rather than the safer of two: **some rules cannot have a query half at
all.** A token budget refuses a document because of the other documents in the
same read, so no index filter and no `enforce(subject, object, action)` can
express it — the same pair has two answers.
[`policy-engines.md`](docs/policy-engines.md) proves it against a real Casbin
enforcer, and shows the division of labour that does work.

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
pretend `len(text) // 4` is Voyage's tokenizer. One cumulative rule is allowed
per collection — declaring two raises at construction rather than letting one
rule's running total silently govern the other. Budgeted `find()` requires an
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
ten modules in dependency order. If the module docstrings and this README
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

What remains unproven is narrow, and [`ISSUES.md`](docs/ISSUES.md) names it:
the three *hosted* key providers share every line of that code path, so what
is untested about them is vendor-specific rather than structural.

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

## Read more

Four shelves, in the order a new reader should take them. The reference
material lives in [`docs/`](docs); the root holds only the front door, the
on-ramp and the pilot.

**Start here** — how to use it, and why it is shaped this way.

| | |
|---|---|
| [`ADOPTING.md`](ADOPTING.md) | the first hour: one collection, one read path, under ten lines — and what you do *not* get by stopping there |
| [`AHA.md`](docs/AHA.md) | the one idea, derived in five steps with the measurements. Everything else is downstream |
| [`TLDR.md`](docs/TLDR.md) | the short versions, the pitches by room, and why the approach reads as strange |

**The argument** — why this is a real problem, at length and executable.

| | |
|---|---|
| [`pain.md`](docs/pain.md) | eight failures whose signature is a plausible answer. Mostly real incidents from this repository |
| [`blog.md`](docs/blog.md) | the long version: the three times the same bug came back, and the two bugs in the proof |
| [`policy-engines.md`](docs/policy-engines.md) | the converse of the one idea: a retrieval rule no index filter and no policy engine can express, checked against a live Casbin enforcer |
| [`drift/`](drift/README.md) | the counter-argument, executable — including the whole thesis ported to pgvector with no MongoDB in the file |
| [`examples/`](examples/) | thirteen runnable programs, most in under ten seconds — start with [`quickstart.py`](examples/quickstart.py), then [`rosetta.py`](examples/rosetta.py) for the abstraction |

**What is wrong with it** — read this before trusting any of the above.

| | |
|---|---|
| [`ISSUES.md`](docs/ISSUES.md) | defects, unproven claims, and operational caveats |
| [`ideas.md`](docs/ideas.md) | what is worth building next, and what is deliberately not |
| [`CONSIDERATIONS.md`](docs/CONSIDERATIONS.md) | what will bite you while working on it: the traps, what each one cost, and which guard now catches it |

**Whether anyone will use it** — positioning, not engineering.

| | |
|---|---|
| [`PROPOSAL.md`](docs/PROPOSAL.md) | three directions, ranked. **Direction 1 — admission for the prompt — is the live one**; the handle is the identity, the other two are frozen until a pilot |
| [`PILOT.md`](PILOT.md) | the smallest honest trial: refusal on one collection, exit criteria and a report template — plus `bench/pilot.py`, the same flow run against a real MongoDB with the report already filled |
| [`DECISION.md`](docs/DECISION.md) | what to build next, pre-registered — each API waits on pilot evidence |
| [`appendix.md`](docs/appendix.md) | the sell decomposed, the ceiling of the pitch, and the compliance vendors |

Working notes rather than landing-page copy, kept because they record how the
thinking went: [`copy.md`](docs/copy.md) (the family-court register — a
mnemonic for the team, not a public sell) and [`mongodb.md`](docs/mongodb.md)
(a memo for one MongoDB conversation, not the project's identity).

MIT.
