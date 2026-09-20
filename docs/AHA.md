# The one idea

Everything else in this repository is downstream of one sentence.

> **A retrieval rule has one authoritative form: a per-document check on
> the way out. Any query or index clause is an optional optimisation and
> must agree with it.**

That is the whole thing. If you read nothing else here, read the five
steps that make it true, because it is derived rather than asserted.

---

## Step 1 — a search hit may bypass your collection query

A `find` goes through a query, so the database can drop forgotten rows
server-side. A `$vectorSearch` hit does not pass through that query. It
arrives from an index that ranked it; unless the equivalent rule was
explicitly built into that index invocation, nothing in the path
consulted your deadline.

So a rule that exists only as a collection query clause does not govern
every retrieval path.

## Step 2 — pushing it into the index is possible, and still insufficient

This is the part that matters, because the easy version of the argument
("you can't") is false, and a reader will catch it.

You can. Measured against Atlas Local, MongoDB 8.x, in
[`voyd/engine/search.py`](../voyd/engine/search.py):

- `living()` works verbatim as a `$vectorSearch` filter. `$or` and
  `$exists` both behave, returning exactly the null/absent/future set.
- The lexical leg can express the same rule — but it belongs in
  `compound.filter`, not `compound.must`. In `must`, the clause
  contributes to relevance, so a row's score changes according to *how*
  it satisfied the deadline. That reorders results by a field with
  nothing to do with relevance.

Two things made it the wrong enforcement point for this project:

1. **A `vectorSearch` definition cannot be updated in place.**
   `update_search_index` validates it as a lexical definition and fails
   with `"mappings" is required`. So adding the filter to an existing
   deployment is a drop-and-rebuild — and a rebuilding index returns
   **zero rows rather than erroring**, which is the exact
   fewer-rows-instead-of-an-error failure this codebase blocks startup
   to avoid.
2. **Enforcing on one leg is worse than neither.** `$rankFusion` fuses a
   vector leg and a lexical leg. Filter one and the two legs disagree
   about which documents exist.

And one thing makes it insufficient as the *only* check even if you do
it: **the cosine fallback has no index at all.** There is nothing to
push anything into, and that is the tier a degraded deployment is
running on — which is also the moment you least want the rule to
quietly stop applying.

## Step 3 — therefore the egress check is the guarantee

Not belt-and-braces. Not defence in depth. The per-document check on the
way out is the *only* thing that holds for hits that did not pass through
the collection query clause. A pushed-down clause is a performance trick
that lets the database or index drop candidates early, and it is worth
having for exactly that reason and no other.

`_admit()` in [`voyd/engine/admission/core.py`](../voyd/engine/admission/core.py)
says so where it lives:

> The authoritative check, on the way out.
>
> The query above is an optimisation. *This* is the guarantee, and it is
> the only one that holds for documents that did not pass through that
> query clause — every hit from `$vectorSearch`, where the deadline is
> deliberately not an index filter.

## Step 4 — any pushed-down rule must also exist on egress

This is the invariant, and it is the sharpest thing in the repo.

If the guarantee lives on egress, then any rule that can express itself
in a query or index filter but **not** per document is not a slower
rule. It is a **silent hole**: one retrieval path prunes correctly and
another can admit the same document.

So `compile_policy()` refuses at boot anything it cannot compile to both
halves. Per-document only would be safe, but slower. Clause only is the
hole. This compiler promises both, so it raises rather than silently
changing that promise — at boot, which is the one moment a policy error
is cheap.

Every operator in [`voyd/engine/policy.py`](../voyd/engine/policy.py) is a
hand-written *pair* of implementations, checked against each other
against a live server. Both halves or the operator does not exist.

## Step 5 — and some rules have no query half at all

Step 4 rules out a clause without an egress check. This is the converse,
and it is the step that makes the argument closed rather than merely
cautious.

A **token budget** refuses a document because of the *other* documents in
the same read. So:

```
'small' asked for on its own   ->  admitted
'small' behind a 95-token row  ->  refused
```

Same document, same caller, same instant, two answers. An index filter
cannot produce that — it decides each candidate independently, before the
page exists. Neither can a policy engine: `enforce(subject, object,
action)` is a pure function of two arguments, with nowhere to put *the
rest of the page*, so for a fixed pair it returns one answer forever.
Checked against a live `casbin.Enforcer` in
[`tests/test_a_policy_engine_owns_the_subject_not_the_objects.py`](../tests/test_a_policy_engine_owns_the_subject_not_the_objects.py).

Once one such rule exists, egress is not the safer of two enforcement
points. It is the only one where every reason can live, and `clause()`
returning `None` stops being a degradation: it is a rule accurately
reporting it has no server-side form, enforced anyway, at the layer that
was always authoritative.

And there is more than one. `Distinct` refuses a near-duplicate of
something already in the page — `redundant` — which is set-relative for
the same reason and equally unpushable. The two compose on one handle,
each with its own per-read state, which makes this a **category** rather
than one awkward example:

| | decided by | has a query half |
|---|---|---|
| deadline, revoked, clearance, policy | the document | yes |
| `over_budget` | how much room is left | no |
| `redundant` | what is already in the room | no |

The long version, including what policy engines *are* good at and the
division of labour that follows, is
[`policy-engines.md`](policy-engines.md).

---

## What this buys, in one table

| | has a pushed-down half | has the egress half |
|---|---|---|
| `deleted: false` in your filter | yes | no |
| vector DB metadata filtering | yes, when supplied | no |
| a governance platform | no | no |
| this | yes, as the optimisation | **yes, as the guarantee** |

Metadata filtering gives you the optimisation half. It becomes a
guarantee only if every read path, every fallback and every future
caller supplies an equivalent rule. The egress predicate makes that
equivalence structural instead of conventional.

## What it costs, honestly

Enforcing on read means forgotten documents get fetched and then
dropped. They spend the fetch budget. Both read paths here originally
bought the same fixed insurance — ask for `limit * 2`, admit, slice —
and that guess failed in the direction this repo refuses to fail in:

```
40 expired rows outranking 6 live ones, limit=5  ->  0 hits
```

Zero. Not fewer. Six live, indexed, on-disk documents handed back as an
empty list, indistinguishable from "nothing matched" — and a model will
then answer *"I don't have information about that,"* confidently.

So the budget is not a constant. `saturate()` re-asks for candidates,
sizing each round from the refusal rate it just measured, until the page
is full or the candidates are genuinely exhausted. Refusal costs the
*forgotten document* its place, not the page. That empty-page bug is the
price of the idea, and paying it is what makes the idea shippable rather
than a blog post.

The CPU tax of the check itself is not where the time goes. Measured in
[`bench/admission.py`](../bench/admission.py): about **1 µs p50 per
candidate, under 2 µs p99**, flat from a 1-hit page to a 100-hit page.
Over-fetch under a realistic (interleaved) refusal rate stays near **2×
up to 50% refused**. The published table is
[`bench/results/admission.md`](../bench/results/admission.md).

---

## The three things this is not

**Not "your deletes are slow."** The TTL window (measured: 60.0s) is the
*symptom* that makes the problem visible. The idea would still be true
with an instant sweeper, because the index and the row are different
systems with different clocks.

**Not a philosophy about refusal.** "Refusal is a retrieval guarantee"
is the explanation you give someone *after* they have understood step 1.
Leading with it turns an engineering result into a manifesto, and
manifestos lose to *I'll just be careful*.

**Not a memory product.** Memory is one trait built on this. The idea is
about where a predicate is allowed to live.

---

## Everything downstream

Once you accept that the guarantee lives on egress, the rest of the
repository stops being a pile of features and becomes consequences:

- **the handle has no unfiltered `find` or `search`** — if the egress
  check is the guarantee, the guarantee cannot be optional, so the
  unsafe read gets a name instead of a default: `including_refused()`
- **reasons are plural** — the check is per document, so a deadline, a
  revocation, a clearance and a compiled policy are the same shape.
  [`examples/rosetta.py`](../examples/rosetta.py) is the executable form of this:
  soft-delete, TTL, a feature flag, row-level security and a token budget as
  five rules on one handle, with `deleted=true` the smallest member
- **erasure is a deadline that has already passed** — no erasure
  subsystem; `revoke()` stamps the mark and moves `expire_at` into the
  past, and the same TTL index collects both
- **refusal travels down a lineage edge** — a summary is a document, so
  it goes through the same check, and `derive()` makes the mark reach it
- **`as_of(t)`** — the check is evaluated per read against stored state,
  so it can be evaluated against a past instant too
- **crypto erasure** — refusal binds this read path only, so the copies
  outside it need a mechanism that is not a check at all
- **rules are a protocol, not a fixed list** — a new reason is a new object,
  not a new branch in a predicate; and because the check runs on a live read,
  a rule can even be *cumulative*: a token budget refusing `over_budget` once
  the prompt's room is spent is the same shape as a deadline, which is the
  evidence the protocol is a primitive rather than a compliance feature

Read [`TLDR.md`](TLDR.md) for the pitches, [`pain.md`](pain.md) for the
failures, [`policy-engines.md`](policy-engines.md) for the rule no index or
policy engine can express, [`blog.md`](blog.md) for the long argument, and
[`ISSUES.md`](ISSUES.md) for what is still wrong.
