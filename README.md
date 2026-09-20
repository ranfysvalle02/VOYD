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

That's *refusal*, and nobody ships it. **Delete is a wish. Refuse is a
contract.**

```python
docs = engine.model("notes", tenant="t").forgettable()

await docs.find({})                        # cannot return a forgotten fact
await docs.search(vector, text="P0301")    # nor can the search path
await docs.including_refused().find({})    # the unsafe thing, named out loud

await docs.revoke({"_id": x}, reason="credential leaked")
# unreachable on the next read. The row is still on disk. That is the proof.
```

There is **no unfiltered read on that handle** — no `find`, no `search` — so
refusal doesn't depend on the next author remembering it. The failure mode is
inverted: you used to have to remember to be safe; now you have to declare
that you want the unsafe thing, in a word a reviewer can grep for.

---

## See it, in ten seconds

```bash
docker compose up -d mongo
uv run python examples/forget.py
```

A memory expires, becomes unreachable *while its row is still on disk*, then
the reaper takes the row and its vector together. A pinned memory beside it is
untouched. No API key, no vendor.

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

Two enforcement points, always both: pushed into the query where the query can
express it, *and* re-checked per document on the way out. The second one is the
guarantee — `$vectorSearch` hits never went through a query.

**Forget-me-now.** Forgetting composes, and it is the same word at every
tier:

```
revoke a fact       →  and the summary an agent wrote from it, at any depth
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

And [`ISSUES.md`](ISSUES.md) lists what is wrong, unproven or imprecise in what
already ships — including the one that costs something: the enterprise KMS path
has never been run against a real KMS.

---

## Install

```bash
pip install voyd              # Engine + a MongoDB driver. That is the install.
pip install 'voyd[app]'       # the HTTP service
pip install 'voyd[crypto]'    # cryptographic erasure
pip install 'voyd[mcp]'       # the agent tools
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

| | |
|---|---|
| [`pain.md`](pain.md) | the pitch, as eight failures whose signature is a plausible answer. Mostly real incidents from this repository |
| [`blog.md`](blog.md) | the long argument, including what is not done |
| [`ISSUES.md`](ISSUES.md) | defects, unproven claims, and operational caveats |
| [`ideas.md`](ideas.md) | what is worth building next, and what is deliberately not |
| [`drift/`](drift/README.md) | the counter-argument, executable — including the whole thesis ported to pgvector with no MongoDB in the file |
| [`examples/`](examples/) | ten runnable programs, most in under ten seconds |

MIT.
