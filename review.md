# Review

What VOYD is, what it gets right, where it breaks, and what it could become.

---

## TL;DR

**8.5/10.** One genuinely novel idea, executed with unusual discipline, in a
codebase that argues with itself in public and usually wins.

*Reviewed against the tree on 20 September 2026: 666 tests green against real
mongot (Atlas Local), plus the five Atlas-gated tests green against a live
cluster with server-side Voyage embedding.*

The idea: *deletion is a storage event, retrieval needs a guarantee, and
ordinary stacks do not make the second one structural.* That's true, it's
measurable, and it's unclaimed.

The execution: the unsafe method **doesn't exist** on the handle. Not
discouraged — absent. You have to type `including_refused()` to get it back,
and that's a word a reviewer can grep.

The risk: it's counterfactual insurance for an invisible failure, sold to the
one person who pays all the cost and gets none of the benefit.

Best thing in the repo: `perimeter.py` states the rule that kills its own
feature — *you cannot enforce refusal in a system you do not control* — and
then ships the smaller honest version anyway.

---

## The why, in four lines

You delete a document. The TTL monitor sweeps in ~60s (measured here: 60.0s).
S3 lifecycle runs daily. Cron runs when it last worked.

In that gap your vector index returns the deleted document as a **normal,
well-scored result** — nothing logged, nothing to page on.

Usually that's fine. A stale recommendation for sixty seconds is not an
incident.

It stops being fine the moment the fact is a leaked credential, a retracted
document, a subject erasure request, or something an injection detector just
flagged. **The value of the fact inverted at an instant nobody scheduled** —
and sweepers only understand schedules.

---

## What's genuinely good

**The API makes the argument.** Two lines do what six paragraphs of
threat-modelling can't:

```python
await docs.find({})                       # cannot return a forgotten fact
await docs.including_refused().find({})   # the unsafe thing, named out loud
```

The failure mode is inverted. You used to have to remember to be safe. Now you
have to *declare* that you want the unsafe thing.

**Two enforcement points, for a measured reason.** Pushed into the query where
the query can express it, re-checked per document on the way out. Not paranoia:
`$vectorSearch` hits do not pass through the collection query, and an index
filter applies only when that path supplies it. The egress check is the
guarantee; either pushed-down filter is the optimisation. `search.py` carries
the measurements for why deadlines are deliberately not pushed into this
vector index. That's a correctness argument derived from how ANN indexes
actually work, not a preference.

**It ships its own counter-argument, executable.** `drift/exhibit.py` stands up
Postgres + Qdrant + MinIO + cron — four clocks, three ways to drift — and lets
the deleted document answer the query. `drift/refusal_on_postgres.py` concedes
the idea isn't MongoDB-only. Projects do not normally build a working demo of
the alternative that makes them look unnecessary.

**Honesty as a load-bearing constraint.** `ledger.py` spends forty lines on
what the hash chain does *not* prove — including that the operator of this
database could rewrite it from entry zero. Writing your own escape hatch into
your own security doc is not normal and it is why the rest of the claims are
believable.

**Irreversibility lives in the type system.** `revoke` has no inverse because
the row is already scheduled for the reaper — un-erasure would be a ledger
claim the data can't support. `quarantine` is reversible and logs *both*
directions, because a chain that records the impose and not the lift is intact
and wrong. That's a subtle failure mode, caught and designed around.

**The tests are the spec.** `test_the_deadline_is_enforced_twice.py`,
`test_a_tenant_id_cannot_be_an_operator.py`,
`test_the_claim_table_does_not_promise_what_is_gone.py`,
`test_the_docs_are_not_stale.py`. Tests named as the claims they defend,
including tests that police the README and the public surface.

**The layering is enforced, not described.** `admission` was a single
2,393-line module -- the one place in this repository where the guarantee had
become hard to *find*, which for a package whose whole argument is
"a guarantee that must be remembered is not enforced" is a pointed defect. It
is now eleven modules with a declared dependency order, and
[`tests/test_the_admission_layers_do_not_invert.py`](tests/test_the_admission_layers_do_not_invert.py)
fails the build if a module imports its own layer or below, or if two
capability mixins reach each other instead of going through
[`core.py`](voyd/engine/admission/core.py).

That second rule is the one carrying weight. The split only means something
if every capability still gets its documents past `_admit`; two mixins wired
directly together is that invariant quietly ceasing to hold, with nothing
failing. So the module graph now states the same thing the read path does.

The split paid for itself immediately in a way worth recording: the guard
that exempts one file from calling the search primitive used to name
`admission.py` and therefore excused **2,393 lines**. It now names
[`reads.py`](voyd/engine/admission/reads.py) and excuses 277. An exemption
that shrinks when code is reorganised is the only kind worth having.

**The commit log subtracts.** A 1,500-line self-verification command was
deleted because the suite already asserted every claim it made. A 1,790-line
README was cut because "that was a book." Deleting your own work on principle
is the rarest signal in any repo.

---

## What's actually weak

**1. The guarantee is one handle in one process.** `mongosh`, a BI tool, an
ETL job, a second service in Go, a snapshot on someone's laptop — none of them
go through `Admission`. Crypto erasure covers the copies and `perimeter.py` is
honest about the consequences, but the ceiling is real.

The right framing is *"we moved the failure from every call site to one
construction site"* — true, large, defensible. **Not** "we made it impossible."
A good engineer catches that in ninety seconds and then discounts everything
else you said.

**2. `including_refused()` is a hole with a good name.** It has to exist; audit
needs it. But someone will reach for it at 2am to fix a bug. It's not gated by
`Authority` (the machinery is *right there* in `authority.py`, built around
exactly this granting/withholding asymmetry) and it's not obviously counted in
`receipts()`. Cheapest fix: a CI rule failing the build on new call sites
outside a designated audit module — the repo already has this instinct in
`test_no_module_reaches_past_the_handle.py`.

**3. The prose is the best part and also the adoption tax.** The module
docstrings are genuinely excellent and a hurried engineer will read none of
them. The ten-second demo and the first-screen two-line API are the right
mitigation. What remains is volume: the idea is one page and the argument
around it is not.

**4. Positioning still shares a page between two buyers.** The repo is *built*
to win on ergonomics — traits, one connection string, `health()` with degraded
as a first-class state. The README's first sentence is still the auditor's
verb; the first code is now the engineer's handle. That pairing is deliberate.
Pretending the first sentence is not auditor-facing would be the dishonest
version of the fix. Selling the handle as a memory product would be worse.

**5. Crypto erasure needs `crypt_shared`** — MongoDB Enterprise, not on PyPI.
Handled gracefully (`keyring.available()` says which half is missing, and no
read path depends on it) but it means the honest three-part answer to the
ceiling objection describes a configuration many users won't have.

---

## The potential

**Realistic ceiling: admission control for what may reach a prompt.**

Three reasons to believe it:

- **The gap is structural, not a feature checklist.** Guardrails decide what
  a model may *say*. Vector DBs decide what *ranks* and offer filters callers
  must supply. Governance platforms describe and attest. The whitespace
  between them is an admission boundary that answers whether a fact may
  *enter* a prompt. Agent memory is the crowded room next door. Do not walk
  in.
- **The regulatory drift favours it.** Erasure obligations are sliding from
  "delete the record" toward "ensure the data is not used," and RAG is the case
  that makes the difference *visible* — a deleted record that still answers a
  prompt is about as showable as harm gets. Regulators arrive where harm is
  easiest to show.
- **Write-back made it worse.** Retrieval that stores what it just read —
  a summary, a chunk, an extract — defeats any erasure that only revokes
  the source. Inherited refusal is the least crowded part of this design,
  and it becomes load-bearing the moment the read path is also a write
  path. Which is now. Agents are one such caller. They are not the product.

**Realistic floor: a beautifully argued library nobody adopts**, because the
developer adds `deleted: false` to a filter this afternoon and is 90% correct.

The distance between floor and ceiling is almost entirely **ergonomics and
on-ramp**, not correctness. The correctness is done.

---

## The one question that decides it

> Can someone get refusal on **one** collection, in **one** read path, in under
> ten lines — without the extra traits or the HTTP surface?

**Answered: yes.** `examples/quickstart.py` is that path, and
`tests/test_the_quickstart_refuses.py` pins the body under ten lines so it
cannot grow into a migration. It still constructs `Engine`; skipping that too
is pre-registered in [`DECISION.md`](DECISION.md) and deliberately not done.
The bottom-up on-ramp exists and is the first runnable the README points at.
Read-path surgery on an existing app is still the cost a team weighs, but it
is no longer an unknown.

Everything else is a detail.

---

## Scorecard

| | |
|---|---|
| **Idea** | 9.5 — novel, true, unclaimed, and the demo proves it in ten seconds |
| **Execution** | 9 — the unsafe path doesn't exist; enforcement twice, for measured reasons |
| **Honesty** | 10 — documents its own escape hatches; ships its own counter-argument |
| **Tests** | 9.5 — named as claims; police the docs, the public surface, and now the package's own layering |
| **Structure** | 9 — eleven layered modules behind one handle, with the dependency order enforced rather than documented |
| **Docs** | 8 — opening now shows the handle; the reading cost around it is still high |
| **Adoption story** | 6 — on-ramp shipped (`examples/quickstart.py`) and overhead measured (`bench/admission.py`); read-path surgery and counterfactual value remain the real costs |
| **Overall** | **8.5** |

**The overall did not move, and that is deliberate.** Splitting a 2,393-line
module is a real improvement to a real defect, but this scorecard never
docked for it -- there was no structure row until today, which is itself the
finding. Fixing an unlisted weakness corrects the *list*, not the score. An
outside reviewer who *had* docked for module size moves 8 to 8.5 on the same
evidence; this document was already there for other reasons.

What still holds the number down is unchanged and is not correctness:
adoption at 6, and the reading cost around the idea. Nobody outside this
repository has used any of it.

The strongest thing here isn't any single file. It's that the argument, the
code, the tests, the counter-demo, and the commit messages all say the same
thing — and not one of them oversells it.
