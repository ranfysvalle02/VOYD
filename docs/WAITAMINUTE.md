# Wait a minute

**Nobody here was building for portability. The guarantee is portable anyway
— and *why* that happened is a better argument for the design than the
portability itself.**

This document exists because a review asked a hostile question — *isn't this
just MongoDB-specific plumbing with an essay on top?* — and the answer, when
measured instead of asserted, came back the other way round. The measurement
is below, including the parts that do not flatter it.

---

## The claim, stated narrowly enough to be wrong

> The decision layer of `voyd/engine/admission/` — the code that answers
> *may this fact reach a prompt?* — contains no database, no driver, and no
> query language. It is pure functions over plain dicts. Everything
> MongoDB-shaped in the package is the *optimisation* half and the *write*
> half, and both are small enough to inventory by hand.

Here is the inventory. Measured, not estimated.

### Direct driver imports in the admission package

```
pymongo imports in voyd/engine/admission/*.py :  0
bson    imports at module level               :  0
bson    imports deferred inside a function    :  1   (rules.py, _is_ciphertext)
```

That one exception is named in full below, because it is the only place the
claim leaks and a claim whose exception is buried is marketing.

### Where the database actually appears

Every call site, all fifteen of them:

| module | lines | db call sites | query operators |
|---|---|---|---|
| `reasons.py` | 68 | 0 | 0 |
| `receipts.py` | 230 | 0 | 0 |
| `spec.py` | 150 | 0 | 0 |
| `rules.py` | 634 | 0 | 4 |
| `attestation.py` | 293 | 0 | 0 |
| `handle.py` | 48 | 0 | 0 |
| `core.py` | 552 | 2 | 2 |
| `reads.py` | 364 | 4 | 1 |
| `lineage.py` | 232 | 4 | 3 |
| `marks.py` | 536 | 5 | **12** |

Six distinct driver methods across the whole package — `find`, `find_one`,
`insert_many`, `update_many`, `count_documents`, `create_index`. Fourteen
distinct query operators, twelve of them concentrated in one file.

**The guarantee is 294 lines of executable Python.** `reasons.py` (15),
`rules.py` (145), `spec.py` (64), `receipts.py` (70) — the rest of those
1,082 lines is the argument for them. Those 294 lines are what decides
whether a fact may reach a prompt, and they would run identically against a
Postgres row, a Parquet shard, a dict from Redis, or a list literal in a
test, because they have never been shown a database.

---

## The trick is the rule protocol, and it was not built for this

Every shipped rule declares itself twice:

```python
def refuses(self, doc: dict, *, when=None) -> bool:   # the guarantee
def clause(self) -> dict | None:                       # the optimisation
```

| rule | pure half | query half |
|---|---|---|
| `Deadline` | `refuses`, `why` | `clause`, `clause_at` |
| `Marked` | `refuses` | `clause`, `clause_at` |
| `Unrecoverable` | `refuses` | `clause` |
| `EmbeddedWith` | `refuses` | `clause` |
| `Clearance` | `refuses` | `clause`, `clause_for` |
| `Restricted` | `refuses` | `clause`, `clause_for` |
| `Budget` | `refuses`, `why` | `clause` → **always `None`** |

That split exists for a reason stated all over this repository and having
nothing to do with portability: **a rule that can express itself in a query
but not per document is not a slower rule, it is a silent hole.** Adding a
deadline filter to a live vector index is an unmigratable index change, and
a `$vectorSearch` hit never passes through the collection query at all. So
the per-document check had to be authoritative, and the query fragment had
to be demotable to an optimisation that can be skipped without changing any
answer.

Demotable to an optimisation is the same shape as *replaceable by a
different backend's optimisation*. The doctrine that made the guarantee
trustworthy is the doctrine that made it portable. These were never two
decisions.

### `clause() -> None` is the load-bearing case

`Budget.clause()` returns `None` unconditionally, and that is not an
omission. A budget is a running total across a page, not a property of any
single document — there is no filter, in any query language, that expresses
"refuse once the prompt is full." It cannot be pushed down to MongoDB, and
it could not be pushed down to Postgres either.

The protocol already has a word for that, and every read path already honours
it. Which means the interface between the portable half and the backend half
is not merely *thin* — it has a documented, exercised representation for
"this backend cannot help," and the system degrades to the pure path
correctly when it is used. That is the hard part of an adapter boundary, and
it is already built and already tested, because a token budget needed it.

---

## Why it happened by accident

`tests/test_the_admission_layers_do_not_invert.py` parses the package's
import statements and fails the build when a module imports its own layer or
below. It was written to keep eleven files legible after a 2,393-line module
was split up. It was not written to protect a dependency boundary.

But the layer numbers it enforces turn out to draw the portability line
exactly:

```
layer 0  reasons     no imports but __future__
layer 1  rules       imports ..time, .reasons
layer 2  spec        imports .rules
layer 2  receipts    imports ..time
---------------------------------------- everything above is driver-free
layer 3  core        imports ..errors  ->  bson
layer 4  reads, marks, lineage, sealing
layer 4  attestation imports ..ledger  ->  pymongo
layer 5  handle
```

Nobody drew that line. It fell out of insisting that `reasons.py` be
vocabulary with no behaviour, that `rules.py` be pure functions, and that
`spec.py` be a declaration rather than a mechanism. Each of those was argued
on legibility grounds alone. The dependency graph they produce is the one an
adapter architecture would have been designed to produce.

This is the part worth internalising: **the layering test is already a
portability test.** It does not know it yet.

---

## What a port would actually be

Not a rewrite. A list:

1. **`marks.py` (165 lines of code, 12 operators).** The write paths —
   impose, lift, release — plus the aggregation-pipeline update that sets a
   mark without clobbering an earlier one. This is the bulk of the work and
   the only file where the operator density is real.
2. **`clause()` / `clause_at()` / `clause_for()` on seven rules.** Each is
   two to six lines. `Budget` needs nothing, because it already returns
   `None`.
3. **`core._query`** — the assembly that folds the clauses and the tenant
   guard into one filter. One function.
4. **`lineage.py`'s two queries** — the `$in` over the closure and the
   descendant count. The transitive-closure-at-write-time design means these
   stay two queries at any depth on any backend.
5. **`reads.py`'s four call sites** — `find`, `find_one`, `count_documents`.

What does *not* move: `why_refused`, every `refuses()`, `Page`, `Receipts`,
`AdmissionSpec`, the reason vocabulary, `receipt_for`'s hashing, the
ordering rule that asks cumulative rules last, the fail-closed behaviour when
a third-party rule raises. That is the product.

---

## What this does not claim

The load-bearing section, and the one that keeps this document from being
the thing it is arguing against.

- **Nothing has been ported.** There is no Postgres backend, no adapter
  interface, and no second implementation of `clause()`. This is an analysis
  of an import graph, not a working system. Every one of the 749 passing
  tests runs against a real MongoDB, so the portability claim currently has
  **zero** test evidence behind it on any other store.

- **Structural purity is not runtime purity.** Those 294 lines cannot today
  be imported without pymongo installed, because importing anything under
  `voyd.engine.admission` executes the package `__init__`, which pulls
  `handle` → `core` → `errors` → `bson`. The decision layer's *own* import
  closure is clean; the package it lives in is not. Fixable, and not yet
  fixed.

- **`Unrecoverable` does not port cleanly.** `rules.py` defers an import of
  `bson.binary.Binary` inside `_is_ciphertext`, to detect BSON subtype 6 —
  the marker for a client-side-encrypted field. That is a genuinely
  MongoDB-specific concept. A port needs its own answer to "is this value
  still ciphertext," and there may not be one as crisp. The deferred import
  is why the other six rules stay clean, not a trick to make a table look
  better.

- **The retrieval engine is not in scope and does not port.**
  `voyd/engine/search.py` is `$vectorSearch`, `$rankFusion`, `$search` —
  Atlas-specific, deliberately, with measurements in that file explaining
  why. The admission *guarantee* is portable. The search tier around it is
  not, and on most backends the guarantee would be protecting a retrieval
  path somebody else built. That may be the more interesting product, but it
  is a different one.

- **Atomicity would have to be re-argued.** Propagating a mark to
  descendants is not atomic on MongoDB either, and `marks.py` says so. A
  port does not inherit that argument; it has to make it again against a
  different concurrency model.

- **Small numbers are not the same as easy.** Twelve operators includes
  `$cond`/`$min`/`$literal` inside an aggregation-pipeline update, which is
  the most backend-specific construct in the package. Counting call sites
  measures surface area, not difficulty.

---

## What to do about it

Three things, in cost order.

**Pin it, the way everything else here is pinned.** The claim above is a
property of an import graph, which means it is checkable by the technique
already used in `tests/test_the_admission_layers_do_not_invert.py`: walk the
transitive import closure of `reasons`, `rules`, `spec` and `receipts`, and
fail if `pymongo` or `bson` appears in it. The one deferred import in
`_is_ciphertext` goes in an allowlist with its reason written out, exactly
like `FRAMEWORK_INVOKED` in
`tests/test_nothing_in_the_package_is_orphaned.py`. Then this document stops
being an observation and becomes an invariant — and the day somebody adds a
convenient `ObjectId` check to `rules.py`, the build says so.

**Make the purity real, not just structural.** Splitting the package
`__init__` so the decision layer can be imported without the handle would
let the 294 lines be exercised with no MongoDB installed at all — which is
also the fastest test suite in the repository, and the one a contributor
could run before reading anything.

**Stop under-claiming.** The README argues that refusal is a retrieval
guarantee rather than a storage event. That argument is currently delivered
welded to one database, which lets a reader file it as a MongoDB feature and
move on. It is not one. It is a statement about where in a system the check
belongs, and this repository happens to contain a MongoDB implementation of
it. `examples/rosetta.py` already makes the neighbouring argument — five
scattered filter conventions rewritten as five rules on one handle, two of
them by a stranger against the public protocol — and the portability finding
is the same argument one level up.

---

## The uncomfortable version

An engineer optimising for portability would have built an abstraction
layer, argued about the interface for a week, and produced something leakier
than this — because they would have been designing against an imagined
second backend instead of a real first one.

What produced the clean boundary here was refusing to let the query be the
guarantee. That refusal was made for safety reasons, documented for safety
reasons, and enforced by a test written for legibility reasons. Portability
is the residue.

Which is the general form of the thing this repository keeps finding: the
structural fix for the problem you *have* tends to be the one that leaves
you somewhere useful for the problem you have not met yet. A convention
would not have done this. A convention would have put `deleted=true` in
every read path, and there would be nothing to port, because there would be
nothing to point at.
