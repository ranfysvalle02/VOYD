# Cosine has no opinions

*Why swapping an embedding model does not degrade your search — it inverts
it — and why the check you think protects you does not.*

---

## The one-line version

> Swap your embedding model without reindexing and your search does not
> get worse. It **inverts**. Identical text scores **−0.053**. Unrelated
> text scores **+0.301**.

Unrelated text beats the document you were actually looking for by a
factor of five. No error. No log. A healthy-looking health check.

---

## Why it happens

An embedding is not a vector. **An embedding is a `(vector, model)`
pair**, and a vector without its model is an orphan.

The trouble is that comparing orphans *works*. Cosine similarity is a
total function over two float arrays of equal length. Hand it a vector
from model A and a vector from model B and it does not raise, does not
warn, and does not return `NaN`. It returns a number between −1 and 1,
promptly, like a professional.

Two models place meaning in different coordinate systems. "Dog" is
somewhere in model A's space and somewhere else entirely in model B's,
and the two spaces have no agreed axes to compare through. The angle
between them is not a weak signal. **It is not a signal.** It is the
angle between two arbitrary directions in a high-dimensional space,
which is very close to orthogonal, plus noise.

That noise is what gets ranked.

---

## The safety net that does not catch it

Ask most teams what protects them here and you get some version of *"the
dimension check."* A 512-wide vector in a 1024-wide index fails loudly;
the driver, the index, or your own assertion catches it.

That check is real, and it catches none of this.

**A whole generation of models shares a width.** 1024 is 1024 whether it
came from this year's model or last year's, from this vendor or that
one. The array is the right length. The index accepts it. Every
assertion you wrote passes.

The guard rail is real and the fall goes around it.

```
what changes when you swap models     is it detectable?
─────────────────────────────────────────────────────────
the dimension                          yes — loudly, if it changes
the dtype                              yes — usually
the coordinate system                  no. nothing looks at this.
```

---

## See it without an API key

This is the mechanism, simulated. Two "generations of one vendor's
model" are two different random projections of the same underlying
meaning — which is, for the purpose of this failure, exactly what two
independently trained models are.

```python
import math, random

def cos(a, b):
    d = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return d / (na * nb) if na and nb else 0.0

def basis(seed, width, meaning):
    r = random.Random(seed)
    return [[r.gauss(0, 1) for _ in range(meaning)] for _ in range(width)]

def embed(model, v):
    return [sum(row[i] * v[i] for i in range(len(v))) for row in model]

r, MEANING, WIDTH = random.Random(7), 64, 1024
A, B = basis(1, WIDTH, MEANING), basis(2, WIDTH, MEANING)   # two generations

topic       = [r.gauss(0, 1) for _ in range(MEANING)]
restatement = [x + r.gauss(0, 0.05) for x in topic]          # the same thing
unrelated   = [r.gauss(0, 1) for _ in range(MEANING)]        # something else

print(f"same text, A vs B         {cos(embed(A, topic), embed(B, topic)):+.3f}")
print(f"unrelated text, B vs B    {cos(embed(B, topic), embed(B, unrelated)):+.3f}")
print(f"restatement, B vs B       {cos(embed(B, topic), embed(B, restatement)):+.3f}")
print(f"widths                    {len(embed(A, topic))} and {len(embed(B, topic))}")
```

```
same text, A vs B         +0.025
unrelated text, B vs B    +0.142
restatement, B vs B       +0.998
widths                    1024 and 1024
```

Read the first two lines against each other. **The same document,
compared across models, is less similar than an unrelated document
compared within one.** The ordering is not degraded; it is reversed. And
the last line is why nothing told you.

The third line is the control, and it is the one that makes this
uncomfortable: within a single model the arithmetic is excellent. At
+0.998 it is doing precisely what you bought it for. Nothing about the
measurement is broken. Only the comparison is meaningless, and a
meaningless comparison looks exactly like a meaningful one.

---

## Where the numbers at the top came from

**Provenance, stated plainly, because this is the strongest empirical
claim in this repository.**

`−0.053` and `+0.301` were measured against a **real** commercial
embedding API: the same text, both outputs 1024-wide, two generations of
one vendor's model. They are recorded in
[`voyd/engine/admission/rules.py`](../voyd/engine/admission/rules.py) on
`EmbeddedWith`, and cited from
[`voyd/wire/policy/refusals.py`](../voyd/wire/policy/refusals.py) and
[`examples/embed.py`](../examples/embed.py).

What is **not** in this repository, and should be weighed accordingly:

- **The vendor and the two model names are not recorded.** They should
  be. A measurement whose subject is not named is an anecdote with a
  decimal point.
- **There is no committed script that reproduces them**, because doing
  so needs an API key and a paid account. Contrast
  [`examples/drift.py`](../examples/drift.py), which measures index
  staleness and *is* runnable against a local `mongod` in about thirty
  seconds — that is the standard, and this claim does not meet it.
- **It is one measurement from one afternoon.** This repository already
  insists elsewhere that "a single figure from a single run is a number
  about that afternoon's thermal state." That applies here too.

What the snippet above *does* establish, with no API key and no vendor,
is the **mechanism** — that cross-model cosine carries no semantic
signal while within-model cosine carries a great deal, and that the two
are indistinguishable by width. The mechanism is the argument. The
vendor numbers are an illustration of it, and if they turn out to be
−0.02 and +0.28 on a different pair of models, nothing in the argument
moves.

Treat the shape as established and the exact digits as one datum.

---

## What VOYD does about it

Three things, and they escalate.

**`embedded_with(model)` refuses the document.** The model becomes part
of what a document *is*, and a row whose vector came from anything else
is refused rather than ranked.

```python
@guard("notes")
class Notes:
    expire_at    = deadline()
    vector_model = embedded_with("text-embed-v3")
```

The attribute name is the field the rule reads, so `vector_model` is
where each document records which model produced its vector.

Refused, not deleted: a stale vector needs *re-embedding*, not erasure,
and the embed worker will get to it. A row with no vector at all is
pending rather than wrong, so it stays visible to `describe()` and to
the worker.

**`auto_embed(model)` removes the way it comes to be wrong.** The index
holds text; the server embeds it on write and embeds the query with the
same model at read time. Nothing in your process ever computes a vector,
so nothing can drift from the index. This is the real fix — the others
are detection.

**The query is refused too.** This is the half that is easy to miss and
is strictly worse than the document case, because it is one *message*
rather than one row. A client that sends its own `queryVector` against a
server-embedded index has put the client-side embedder back, through a
driver that never read your policy file — and every candidate on the
page is then scored against a vector from the wrong space. The page
comes back full, ranked, plausible and meaningless. That caller is
precisely who a wire boundary exists for, so it is refused by name and
told which form works.

---

## Why this belongs in a document about authorization

It looks like a relevance bug and it is filed here with the access
rules, on purpose.

This repository's argument is that the dangerous failures in retrieval
are the ones **disguised as their own opposite** — a missing
authorization filter that reads as better recall, a row the sweeper has
not reached that reads as a sweeper working fine. A model swap is the
same genre. It returns a full page of confidently ranked, entirely
arbitrary documents, and every signal you have says the system is
healthy.

The common defect is not vectors, or permissions, or expiry. It is **a
statement of intent doing the work of a guarantee**: the index *is*
embedded with the declared model, we *do* filter by tenant, the row *was*
deleted. Each one true when written, none of them checked since, and
declaring something is precisely what makes you stop checking it.

So the model is checked on every read, per document, at the boundary —
for the same reason and by the same mechanism as everything else here.

---

*Longer argument: [`ranking-is-not-permission.md`](ranking-is-not-permission.md).
The story, including the bug this project's own CI check hid inside an
infrastructure flake: [`../blog.md`](../blog.md).*
