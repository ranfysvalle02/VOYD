# A retrieval rule your policy engine cannot express

*A companion to [`AHA.md`](AHA.md), which derives why the guarantee lives on
egress. This is the part that argument implies and does not say: there are
retrieval rules that **only** have an egress half, they are not exotic, and
their existence is why "push the filter down" is an incomplete architecture
rather than a fast one.*

---

## The answer everybody gives

Ask how to stop a RAG system returning documents a caller may not see and you
get one of two answers, and they are the same answer.

**"Use metadata filtering."** Every vector database supports it. Tag the row,
filter at query time, the index prunes before it ranks. Fast, indexed, done.

**"Use a policy engine."** Casbin, OSO, Cedar, OPA. Write the rule once, call
`enforce(subject, object, action)`, and if your list endpoints are slow, reach
for the data-filtering feature that compiles the policy into a `WHERE` clause
so you filter in the database instead of in the application.

Both answers say: *the rule belongs in the query.* One puts it in an index
definition, the other generates it from a policy file. The shared premise is
that a rule is a predicate over one document, and a predicate over one
document can always be turned into a filter.

That premise is false, and the counterexample is boring.

## A token budget

Here is a rule any team building RAG eventually needs. The prompt has a
context window. The retrieval step returns candidates in relevance order. Once
the accumulated tokens reach the ceiling, the remaining candidates do not
reach the prompt.

Nothing clever — a running total and a comparison. It is in this repository
as [`Budget`](../voyd/engine/admission/rules.py), most of which is refusing to
guess (a non-integer limit fails at construction; a document whose size cannot
be read is `uncosted` rather than free), and it produces this:

```
'small' asked for on its own   ->  admitted
'small' behind a 95-token row  ->  refused
```

Same document. Same caller. Same instant. Two answers.

Run it: [`examples/policy_engine.py`](../examples/policy_engine.py), part B.

## Why that breaks the index

An index filter decides each candidate on its own, before the page exists.
`$vectorSearch` with a filter prunes the candidate set during graph traversal;
a `compound.filter` clause on the lexical leg does the same. Neither has any
notion of *how much room is left*, because room is a property of the result,
and the result is what they are in the middle of producing.

You cannot express a running total in a predicate that is evaluated once per
document with no memory between evaluations. Not slowly. At all.

## Why that breaks the policy engine

This is the part I did not expect to be so clean.

`enforce(sub, obj, act)` is a pure function of a subject and an object. There
is no third argument for *the rest of the page*. So for a fixed subject and a
fixed object it returns one answer, always — which means no matcher anyone can
write, in Polar or Casbin's expression language or Rego, returns both of the
two answers above.

This is not a missing feature. Adding it would mean changing what `enforce`
is: a per-object decision would have to become a fold over an ordered set,
carrying state, with the order mattering. That is a different function with a
different signature, and every policy engine's entire API surface — caching,
batching, the `enforce` contract itself — is built on it not being one.

It is checked, against a live `casbin.Enforcer`, in
[`tests/test_a_policy_engine_owns_the_subject_not_the_objects.py`](../tests/test_a_policy_engine_owns_the_subject_not_the_objects.py).

## So policy engines are bad?

No, and this is where the argument turns.

The same test file compares a compiled VOYD policy against a real Casbin
enforcer on four classic models — `abac_model.conf`'s owner match, a
multi-attribute department-and-level rule, a constant ceiling, department
equality — across three callers, comparing *sets of admitted documents* rather
than vibes. They agree on every pair. And each one also compiles to a MongoDB
query, so the whole policy runs server-side.

Casbin, meanwhile, has no data-filtering mechanism at all. OSO has one, and it
is their hardest feature and does not cover all of Polar.

So the honest summary is not *policy engines are weak*. It is that **policy
engines are subject-side reasoners**, and they are very good at it. Role
graphs, hierarchies, domains, inheritance — "a senior engineer is an engineer
is a reader" is a statement about people, it has nothing to do with documents,
and nothing in this repository has any vocabulary for it, on purpose.

What they are not is object-side filters. "Data filtering" is the name for
every policy engine's attempt to become one, and the reason it is the hardest
feature in all of them is that it is a layer violation wearing a feature's
clothes.

## The division that survives contact

Let each side do the thing it is shaped for. Casbin flattens the subject.
The retrieval layer filters the objects.

```python
roles = enforcer.get_implicit_roles_for_user("alice")
docs.for_caller({"groups": roles}).find({})
```

One call each. The first walks a role graph and touches no documents; the
second compiles to `{"acl": {"$in": [...]}}` and runs in the database:

```
alice
  casbin flattens -> ['senior_engineer', 'engineer', 'reader', 'alice']
  voyd filters    -> {'acl': {'$in': ['alice', 'engineer', 'reader', ...]}}
  reaches a prompt-> ['d1', 'd3']
```

The tempting alternative — wrapping `enforce()` in a rule and calling it per
candidate — works and is wrong twice: one Python matcher call per hit, and
nothing pushed into the database, so the read fetches everything and throws
most of it away. The integration that is worth having is the one where neither
engine does the other's job.

Whole thing: [`examples/policy_engine.py`](../examples/policy_engine.py).
VOYD does not depend on Casbin and will not; the argument is that these are
two layers, and a dependency would be the opposite claim.

## What the budget actually proves

[`AHA.md`](AHA.md) derives, from the fact that a `$vectorSearch` hit never
passes through your collection query, that the per-document check on the way
out is the guarantee and a pushed-down clause is an optimisation. Step 4 of
that argument says a rule with a clause but no egress half is a silent hole.

The budget is the converse, and it finishes the argument:

> Some rules have an egress half and **cannot** have a clause half.

Once one such rule exists, the egress check stops being the safer of two
places to enforce and becomes the only place where *all* the reasons can live.
A deadline, a revocation, a clearance, a compiled policy clause and a token
budget are then the same shape — `reason` + `refuses(doc)` +
`clause() -> dict | None` — and `clause()` returning `None` is not a
degradation. It is a rule honestly reporting that it has no server-side form,
enforced anyway, at the layer that was always authoritative.

[`examples/rosetta.py`](../examples/rosetta.py) is the executable version:
soft-delete, TTL, a feature flag, row-level security and a token budget as
five rules on one handle, four with both halves and one with only the half
that counts.

## The uncomfortable corollary

If your architecture has no egress check — if the filter lives only in the
index definition, or only in a generated `WHERE` clause — then the set of
retrieval rules you are able to express is not "most of them". It is exactly
the set that happens to be expressible as an independent per-document
predicate.

You will not get an error when you need one outside that set. You will get a
design meeting where somebody says the budget has to be enforced in
application code after retrieval, and everybody nods, and now there are two
places where a document is decided and only one of them is in the policy.

That is the same shape as the bug this whole project started from: six read
paths, one of them missing the filter, nothing wrong enough to page anyone.

---

**Further:** [`AHA.md`](AHA.md) for the derivation, [`blog.md`](blog.md) for
the long argument, [`pain.md`](pain.md) for the failures that motivated it.
