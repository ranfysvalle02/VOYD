# VOYD

**Every database can delete. None of them can refuse.**

Deletion is a *storage* event, and storage events are eventually consistent.
A TTL monitor sweeps about once a minute (measured here: 60.0s). An S3
lifecycle rule runs about once a day. So between the moment you delete
something and the moment it is gone, your vector index keeps returning it —
as a normal, well-scored result, with nothing logged and nothing to page on.

Retrieval doesn't need a faster sweeper. It needs a different guarantee:

> **this fact may not reach a prompt** — answered on every read, immediately,
> whatever the sweeper is doing.

That's *refusal*. Most stacks offer a filter you must remember; this makes the
filter structural. **Delete is a wish. Refuse is a contract.**

```python
docs = engine.model("notes").forgettable()

await docs.find({})                        # cannot return a forgotten fact
await docs.search(vector, text="P0301")    # nor can the search path
await docs.including_refused().find({})    # the unsafe thing, named out loud

await docs.revoke({"_id": x}, reason="credential leaked")
# unreachable on the next read. The row is still on disk. That is the proof.
```

Multi-tenant is one argument away — `model("notes", tenant="tenant_id")` — and
then the tenant field is required in every read, so `find({"tenant_id": t})`
rather than `find({})`. The [quickstart](examples/quickstart.py) runs both.

There is **no unfiltered read on that handle** — no `find`, no `search` — so
refusal doesn't depend on the next author remembering it. The failure mode is
inverted: you used to have to remember to be safe; now you have to declare
that you want the unsafe thing, in a word a reviewer can grep for.

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
document is not a slower rule, it is a silent hole.** [`AHA.md`](AHA.md)
derives it in four steps, with the measurements.

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
cron is supposed to keep them agreeing. Four clocks, three ways to drift. The
deleted document answers the query.

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
| `compile_policy(…)` | a `deny` clause stored on the scope, compiled | **no** | — |

Two enforcement points, always both: the query clause and the per-document
check. That is also why `compile_policy(…)` refuses at boot anything it cannot
compile to *both* halves — falling back to the clause alone would be the silent
hole described above.

**What the per-read check costs, measured.** The reviewer's first objection is
*"so you pay on every read, forever."* On a laptop the per-candidate egress
check is about **0.5 µs p50, under 0.8 µs p99**, flat from a 1-hit page to a
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
| [`engine/admission.py`](voyd/engine/admission.py) | refusal as a retrieval guarantee, the rule protocol, inherited refusal, `as_of` |
| [`engine/keyring.py`](voyd/engine/keyring.py) | crypto-shredding, and why CSFLE and Queryable Encryption are a real trade |
| [`engine/custody.py`](voyd/engine/custody.py) | who holds the key that wraps the keys — `Ephemeral` → `LocalFile` → AWS/Azure/GCP/KMIP |
| [`engine/ledger.py`](voyd/engine/ledger.py) | the hash chain, and forty lines on what it does *not* prove |
| [`engine/perimeter.py`](voyd/engine/perimeter.py) | who else holds a copy, and why enforcing it is not on offer |
| [`engine/authority.py`](voyd/engine/authority.py) | may this caller *do* this — and why granting and withholding are asymmetric |
| [`engine/search.py`](voyd/engine/search.py) | the measurements behind *not* pushing deadlines into the vector index |

Start with `admission.py`. If the module docstrings and this README ever
disagree, the docstrings are right.

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

And [`ISSUES.md`](ISSUES.md) lists what is wrong, unproven or imprecise in what
already ships — now narrowly: the three *hosted* providers share every line of
that code path, and what is unproven about them is vendor-specific.

---

## Install

```bash
pip install voyd              # Engine + a MongoDB driver. That is the install.
pip install 'voyd[app]'       # the HTTP service
pip install 'voyd[crypto]'    # cryptographic erasure
pip install 'voyd[mcp]'       # the same guarantee, as tools a model can call
```

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

Four shelves, in the order a new reader should take them.

**Start here** — the idea, in ninety seconds and in one page.

| | |
|---|---|
| [`AHA.md`](AHA.md) | the one idea, derived in four steps with the measurements. Everything else is downstream |
| [`TLDR.md`](TLDR.md) | the short versions, the pitches by room, and why the approach reads as strange |

**The argument** — why it is a real problem, at length and executable.

| | |
|---|---|
| [`pain.md`](pain.md) | eight failures whose signature is a plausible answer. Mostly real incidents from this repository |
| [`blog.md`](blog.md) | the long version: the three times the same bug came back, and the two bugs in the proof |
| [`drift/`](drift/README.md) | the counter-argument, executable — including the whole thesis ported to pgvector with no MongoDB in the file |
| [`examples/`](examples/) | eleven runnable programs, most in under ten seconds — start with [`quickstart.py`](examples/quickstart.py) |

**What is wrong with it** — read before trusting any of the above.

| | |
|---|---|
| [`ISSUES.md`](ISSUES.md) | defects, unproven claims, and operational caveats |
| [`ideas.md`](ideas.md) | what is worth building next, and what is deliberately not |

**Whether anyone will use it** — positioning, not engineering.

| | |
|---|---|
| [`PROPOSAL.md`](PROPOSAL.md) | three directions, ranked. Admission for the prompt, not a memory product |
| [`PILOT.md`](PILOT.md) | the smallest honest trial: refusal on one collection, with exit criteria and a report template |
| [`DECISION.md`](DECISION.md) | what to build next, pre-registered — each API waits on pilot evidence |
| [`appendix.md`](appendix.md) | the sell decomposed, the ceiling of the pitch, and the compliance vendors |
| [`copy.md`](copy.md) | the words: right of first refusal, permission slips, sole custody of the deadline |

MIT.
