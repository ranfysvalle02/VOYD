# Portability: the finding, and the pattern

**Nobody here was building for portability. The guarantee turned out to be
portable anyway — and the reason it happened by accident is a better argument
for the design than the portability is.**

Then, porting it, a second finding that is worth more than the first: *the
guarantee ports everywhere, but the **enforcement** of it does not.* On one
engine refusal is a property of the database; on another it is a property of
the caller's memory. Those are different products wearing the same API, and
almost nobody says which one they are selling.

This document is the measurement, the finding, and the pattern to build on if
you want the second kind.

---

## 1. The finding, in one table

Three engines, the same thesis, each given its real mechanism and nothing
stubbed. Every row is executed by a file in [`drift/`](../drift), which exits
non-zero if any claim stops holding.

| | MongoDB (`voyd/`) | Postgres + pgvector | Qdrant |
|---|---|---|---|
| The bug reproduces | yes | yes | yes |
| Refusal in the read path | yes | yes | yes |
| The *unfiltered* read can be made to **fail** | yes — no unfiltered read exists on the handle | yes — revoke the table, grant only a view | **no** |
| Inherited refusal reaches what was derived | yes | yes — recursive CTE | application must walk it |
| The deadline has one owner | yes — TTL index | no — `pg_cron` or an external job | no |

The third row is the finding. On Postgres, `REVOKE` on the table plus a
`GRANT` on a filtered view means the naive query raises `permission denied`:
the engine refuses, and no amount of forgetting by the next caller changes
that. On Qdrant, on the stock image, there is no row, no view, no `GRANT`, and
no collection-level default filter — so the payload filter is a **convention**.
[`drift/refusal_on_qdrant.py`](../drift/refusal_on_qdrant.py) does not assert
that; it issues the unfiltered query a second time and watches the expired
point come back with a confident score.

> **A whole class of vector databases can express this guarantee only
> politely.**

That is not a complaint about Qdrant, which is a good vector database. It is
the thing a buyer needs to know and is never told: "supports metadata
filtering" and "can refuse" are not the same sentence. The first is a feature.
The second is a guarantee, and it requires somewhere in the engine for the
*absence* of a filter to be an error.

### The enforcement ladder

Worth naming, because once you have the words you cannot un-see which rung a
system is on:

0. **Conventional** — the filter is correct when the caller writes it.
   Every read path is an opportunity to forget. This is where almost all
   retrieval lives today.
1. **Structural** — the unfiltered read is not *reachable*: it has no name on
   the object you were given. Forgetting is a compile-or-attribute error, not
   a silent wrong answer. (VOYD's handle; Postgres's view-only grant.)
2. **Engine-enforced** — the store itself refuses the unfiltered read to that
   principal, whatever the application does. (Postgres `REVOKE`/`GRANT`.)
3. **Cryptographic** — there is nothing to serve. The key is destroyed and
   every copy, in every replica and snapshot and backup, is noise. This is the
   only rung that answers *"and your backups?"*

Rung 0 is what the industry calls a solution. Rungs 1 and 2 are what this
repository is about. Rung 3 is the only one that survives a copy you do not
control, which is why [`voyd/engine/keyring.py`](../voyd/engine/keyring.py)
exists even though refusal does not depend on it.

---

## 2. Why it ported: the measurement

The claim, stated narrowly enough to be wrong:

> The decision layer of `voyd/engine/admission/` — the code that answers *may
> this fact reach a prompt?* — contains no database, no driver, and no query
> language. Everything MongoDB-shaped is the *optimisation* half and the
> *write* half, and both are small enough to inventory by hand.

Measured, not estimated:

```
pymongo imports in voyd/engine/admission/*.py  :  0
bson    imports at module level                :  0
bson    imports deferred inside a function     :  1   (rules.py, _is_ciphertext)
```

That one exception is named in full in §5, because a claim whose exception is
buried is marketing.

| module | lines | db call sites | distinct operators |
|---|---|---|---|
| `reasons.py` | 88 | 0 | 0 |
| `receipts.py` | 243 | 0 | 0 |
| `spec.py` | 234 | 0 | 0 |
| `rules.py` | 846 | 0 | 4 |
| `composition.py` | 116 | 0 | 0 |
| `attestation.py` | 314 | 0 | 0 |
| `handle.py` | 72 | 0 | 0 |
| `core.py` | 693 | 2 | 2 |
| `sealing.py` | 276 | 2 | 0 |
| `reads.py` | 395 | 4 | 1 |
| `lineage.py` | 247 | 4 | 3 |
| `marks.py` | 639 | 6 | **12** |

Six distinct driver methods across the whole package — `find`, `find_one`,
`insert_many`, `update_many`, `count_documents`, `create_index`. Fourteen
distinct query operators, twelve of them concentrated in one file.

**The guarantee is 487 executable lines**: `reasons.py` (19), `rules.py`
(294), `spec.py` (83), `receipts.py` (91), counted as statements rather than
file length, because the rest of those 1,411 lines is the argument for them.
Those 487 lines decide whether a fact may reach a prompt, and they would run
identically against a Postgres row, a Parquet shard, a dict from Redis, or a
list literal in a test — because they have never been shown a database.

---

## 3. The pattern: a rule declares itself twice

This is the part to copy, and it is the whole trick.

```python
class Rule(Protocol):
    @property
    def reason(self) -> str: ...

    # The guarantee. Authoritative, per document, no database.
    def refuses(self, doc: dict, *, when: datetime | None = None) -> bool: ...

    # The optimisation. Optional, best-effort, backend-specific.
    # `None` means "this backend cannot help" -- which is a valid answer.
    def clause(self) -> dict | None: ...
```

| rule | pure half | query half |
|---|---|---|
| `Deadline` | `refuses`, `why` | `clause`, `clause_at` |
| `Marked` | `refuses` | `clause`, `clause_at` |
| `Unrecoverable` | `refuses` | `clause` |
| `EmbeddedWith` | `refuses` | `clause` |
| `Clearance` | `refuses` | `clause`, `clause_for` |
| `Restricted` | `refuses` | `clause`, `clause_for` |
| `Distinct` | `refuses` (set-relative) | `clause` → **`None`** |
| `Budget` | `refuses`, `why` | `clause` → **`None`** |

### The asymmetry is the rule, and it is not about portability

- **egress only** — slower, completely safe. The per-document check is the
  guarantee, and a hit from a vector index reaches it whether or not any query
  clause exists.
- **clause only** — a *silent hole*. One read path prunes correctly and
  another admits the same document, with no error anywhere.

That split was argued on safety grounds, in [`AHA.md`](AHA.md), long before
anyone asked about a second backend: adding a deadline filter to a live vector
index is an unmigratable index change, and a `$vectorSearch` hit never passes
through the collection query at all. So the per-document check *had* to be
authoritative and the query fragment *had* to be demotable to an optimisation
that can be skipped without changing any answer.

**Demotable to an optimisation is the same shape as replaceable by a different
backend's optimisation.** The doctrine that made the guarantee trustworthy is
the doctrine that made it portable. These were never two decisions.

### `clause() -> None` is the load-bearing case

`Budget.clause()` returns `None` unconditionally, and that is not an omission.
A budget is a running total across a page, not a property of any single
document — there is no filter, in any query language, that expresses *"refuse
once the prompt is full."* It cannot be pushed down to MongoDB, and it could
not be pushed down to Postgres either.
[`policy-engines.md`](policy-engines.md) is the long version: some retrieval
rules have **no query half at all**, they are not exotic, and their existence
is why "push the filter down" is an incomplete architecture rather than a
faster one.

Which means the interface between the portable half and the backend half is
not merely *thin* — it has a documented, exercised representation for *"this
backend cannot help,"* and every read path already degrades to the pure path
correctly when it is used. That is the hard part of an adapter boundary, and
it was already built and already tested, because a token budget needed it.

### If you are building this on another store, the pattern is four rules

1. **The per-document check is the only authority.** Anything a query does is
   an accelerator you must be able to delete without changing an answer.
2. **A rule that can only be expressed as a query is a defect**, not an
   optimisation — it will be right on one read path and wrong on the next.
3. **Give the backend a way to say "I cannot help."** `None`, not an
   approximate clause. An approximate clause is the silent hole with better
   manners.
4. **Make the unfiltered read unreachable, then find your engine's highest
   rung.** A view and a `GRANT`, a stored procedure, a proxy — whatever your
   store offers above rung 0. If the answer is "nothing," say so out loud; the
   Qdrant result above is what saying so looks like.

---

## 4. It ported by accident, and the import graph is why

[`tests/test_the_admission_layers_do_not_invert.py`](../tests/test_the_admission_layers_do_not_invert.py)
parses the package's import statements and fails the build when a module
imports its own layer or below. It was written to keep thirteen files legible
after a large module was split up. It was **not** written to protect a
dependency boundary.

But the layer numbers it enforces draw the portability line exactly:

```
layer 0  reasons     no imports but __future__
layer 1  rules       imports ..time, .reasons
layer 2  spec        imports .rules
layer 2  receipts    imports ..time
---------------------------------------- everything above is driver-free
layer 3  core, composition       core imports ..errors  ->  bson
layer 4  reads, marks, lineage, sealing, attestation
layer 5  handle
layer 6  __init__
```

Nobody drew that line. It fell out of insisting that `reasons.py` be
vocabulary with no behaviour, that `rules.py` be pure functions, and that
`spec.py` be a declaration rather than a mechanism — each argued on legibility
grounds alone. The dependency graph those produce is the one an adapter
architecture would have been *designed* to produce.

**The layering test is already a portability test.** It does not know it yet,
and §6 is about making it know.

---

## 5. What this does not claim

The load-bearing section, and the one that keeps this document from being the
thing it is arguing against.

- **`voyd` has not been ported.** [`drift/`](../drift) contains two
  *exhibits* — standalone files that reproduce the thesis on other engines and
  measure where it breaks. There is no adapter interface, no second
  implementation of `clause()`, and no Postgres backend you could pass to
  `Engine`. The portability claim has executable evidence that the *pattern*
  travels, and zero evidence that *this package* does.

- **Structural purity is not runtime purity.** Those 487 lines cannot today be
  imported without `pymongo` installed, because importing anything under
  `voyd.engine.admission` executes the package `__init__`, which pulls
  `handle` → `core` → `errors` → `bson`. The decision layer's *own* import
  closure is clean; the package it lives in is not. Fixable, not yet fixed.

- **`Unrecoverable` does not port cleanly.** `rules.py` defers an import of
  `bson.binary.Binary` inside `_is_ciphertext` to detect BSON subtype 6, the
  marker for a client-side-encrypted field. That is a genuinely
  MongoDB-specific concept, and a port needs its own answer to *"is this value
  still ciphertext"* — there may not be one as crisp. The deferred import is
  why the other rules stay clean, not a trick to make a table look better.

- **The retrieval engine is out of scope and does not port.**
  [`voyd/engine/search.py`](../voyd/engine/search.py) is `$vectorSearch`,
  `$rankFusion` and `$search` — Atlas-specific, deliberately, with the
  measurements in that file explaining why. The admission *guarantee* is
  portable; the search tier around it is not, and on most backends the
  guarantee would be protecting a retrieval path somebody else built. That may
  be the more interesting product. It is a different one.

- **Atomicity has to be re-argued, not inherited.** Propagating a mark to
  descendants is not atomic on MongoDB either, and `marks.py` says so. A port
  makes that argument again against a different concurrency model.

- **Small numbers are not the same as easy.** Twelve operators in `marks.py`
  includes `$cond`/`$min`/`$literal` inside an aggregation-pipeline update,
  which is the most backend-specific construct in the package. Counting call
  sites measures surface area, not difficulty.

- **One-owner is genuinely stronger on MongoDB.** Postgres has no TTL, so the
  moment you need rows actually *gone* the deadline has two owners again. That
  is a property of the engine, not of the argument, and
  [`drift/refusal_on_postgres.py`](../drift/refusal_on_postgres.py) says so in
  its own header rather than leaving it for a reader to notice.

---

## 6. What to do about it

**Pin it, the way everything else here is pinned.** The claim in §2 is a
property of an import graph, so it is checkable by the technique already used
in the layering test: walk the transitive import closure of `reasons`,
`rules`, `spec` and `receipts`, and fail if `pymongo` or `bson` appears in it.
The one deferred import goes in an allowlist with its reason written out. Then
this document stops being an observation and becomes an invariant — and the
day somebody adds a convenient `ObjectId` check to `rules.py`, the build says
so. This is now
[`tests/test_the_guarantee_does_not_know_about_a_database.py`](../tests/test_the_guarantee_does_not_know_about_a_database.py).

**Make the purity real, not just structural.** Splitting the package
`__init__` so the decision layer can be imported without the handle would let
those 487 lines be exercised with no MongoDB installed at all — which is also
the fastest suite in the repository and the one a contributor could run before
reading anything. Not done.

**Stop under-claiming.** The README argues that refusal is a retrieval
guarantee rather than a storage event. Delivered welded to one database, that
lets a reader file it as a MongoDB feature and move on. It is not one. It is a
statement about *where in a system the check belongs*, and this repository
happens to contain a MongoDB implementation of it.
[`examples/rosetta.py`](../examples/rosetta.py) already makes the neighbouring
argument — five scattered filter conventions rewritten as five rules on one
handle, two of them by a stranger against the public protocol — and the
portability finding is the same argument one level up.

---

## The uncomfortable version

An engineer optimising for portability would have built an abstraction layer,
argued about the interface for a week, and produced something leakier than
this — because they would have been designing against an imagined second
backend instead of a real first one.

What produced the clean boundary here was refusing to let the query be the
guarantee. That refusal was made for safety reasons, documented for safety
reasons, and enforced by a test written for legibility reasons. Portability is
the residue.

Which is the general form of the thing this repository keeps finding: **the
structural fix for the problem you have tends to leave you somewhere useful
for the problem you have not met yet.** A convention would not have done this.
A convention would have put `deleted: false` in every read path, and there
would be nothing to port, because there would be nothing to point at.
