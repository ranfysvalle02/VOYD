# Is MongoDB Atlas positioned to win this?

> **Internal BD memo, not the project's identity.** This argues MongoDB's
> position for a MongoDB conversation. The project's identity is the *portable*
> handle -- "ranking is not permission" -- and
> [`drift/refusal_on_postgres.py`](drift/refusal_on_postgres.py) is the file
> that proves it, and the one a vendor pitch must not undo. Use this in a room;
> do not make it page one. Frozen as a memo until a pilot keeps the handle
> ([PILOT.md](PILOT.md)).

Two questions, answered in order, with the uncomfortable half of each kept in.

> **Is this out-of-the-box thinking?** Partly. The *reframe* is genuinely
> unclaimed; the *mechanism* is a sharp recombination of things security
> engineering has known for thirty years. Both of those are worth saying.
>
> **Is Atlas uniquely positioned?** Not for the idea — the idea is portable and
> this repository proves it is, on purpose. Atlas is uniquely positioned for
> *one specific layer of it*, and that layer is the one nobody else can
> assemble: **the row, the index, the embedding model, and the key vault in a
> single product.**

The rest of this file is the evidence for both answers, including the three
counterarguments that will be raised in the first ten minutes of any internal
review, because a positioning document that only lists its wins is marketing.

---

## Part 1 — How novel is it, honestly

### What is genuinely unclaimed

The reframe. *Deletion is a storage event and therefore eventually consistent;
refusal is a retrieval guarantee and must be answered on every read.* Nobody
in this category has named that distinction and built the API around it. Vector
databases ship deletes and filters. Guardrail products decide what a model may
*say*. Governance platforms describe and attest. The whitespace between them is
a boundary that answers whether a fact may **enter** a prompt, and it is empty.

The second unclaimed piece is narrower and more technical, and it is the part
that generalises:

> A retrieval rule has exactly one authoritative form — a per-document check on
> the way out. Every query clause or index filter is an optional optimisation
> that must agree with it. A rule you can express in a query but **not** per
> document is not a slower rule, it is a silent hole.

That is falsifiable, it predicts something, and it is true of any system where
a ranked hit reaches the caller without passing through the caller's predicate.

### What is not new, and pretending otherwise would be the tell

Almost every *component* has prior art, and a reviewer who knows the field will
name it:

- **Egress filtering over ingress filtering** — decades old in access control.
- **Policy enforcement at the read path** — row-level security in Postgres,
  the PEP/PDP split in XACML, Oso/OPA-style authorisation.
- **"The unsafe call does not exist"** — capability-based security. Making the
  privileged operation a separate, nameable object is the whole discipline.
- **Visibility filters applied at rank time** — Vespa does a version of this.
- **Crypto-shredding as erasure** — standard practice in regulated storage.

So the honest sentence is: *the parts are known, the composition is not, and
the specific asymmetry it is aimed at — a vector-index hit never passed through
your query — has not been named as the thing that makes the composition
necessary.* That is a real contribution. It is not an invention out of nowhere,
and claiming it is would cost more credibility than the claim buys.

### Is it "oddly cool"?

Yes, and the oddness is load-bearing rather than decorative. The project's most
persuasive artifact is [`drift/refusal_on_postgres.py`](drift/refusal_on_postgres.py),
which ports the entire thesis to pgvector with no MongoDB anywhere in the file
and then names the two places Postgres is genuinely harder. A repository that
builds a working demo of the alternative that makes it look unnecessary is
doing something most projects structurally cannot do.

**That file is also the reason any MongoDB-flavoured pitch has to be careful.**
The credibility of the whole argument rests on it not being vendor advocacy. A
pitch that quietly undoes that is trading the asset for the sale.

---

## Part 2 — The Atlas case, ranked by how much weight it will bear

Five arguments. They are not equally good, and they are ordered strongest
first. Every one is grounded in something measured in this repository rather
than in a capability matrix.

### 1. On Atlas, the per-document check is not a preference — it is the only option

This is the strongest platform-specific fact here and it is measured in
[`voyd/engine/search.py`](voyd/engine/search.py):

- A `search` index definition **can** be updated in place.
- A `vectorSearch` definition **cannot**. `update_search_index` validates
  whatever it is handed as a lexical definition and fails with
  `"mappings" is required`.

Read what that means for an existing deployment. Pushing a deadline filter into
a live vector index is an **unmigratable index change**. The theoretical
alternative to a per-document check — "just put the policy in the index" — is
not available to any Atlas user who already has data. They would have to
rebuild the index.

So on Atlas, "enforce it on the way out" is not one design among several. It is
the design, and the platform chose it for you. That is a much better argument
than a preference, because it is a constraint the customer will hit themselves.

There is a second, subtler finding in the same file that no competitor
documentation will save a customer from: the lexical leg can express the same
rule, but it belongs in `compound.filter`, **not** `compound.must`. In `must`,
the clause contributes to relevance, so a document's score changes according to
*how* it satisfied the deadline — rows matching via `range` or `equals: null`
gain a full point while a row with no deadline field keeps its original score.
Your ranking is now partly determined by a field with nothing to do with
relevance, silently. In `filter`, scores come back byte-identical.

That is the kind of thing a vendor should be shipping as a guarantee rather
than leaving as a trap.

### 2. MongoDB owns all four layers, and nobody else owns more than two

This is the actual answer to "uniquely positioned," and it is specific:

| Layer | Atlas | pgvector | Pinecone / Qdrant / Weaviate | Elastic / Vespa |
|---|---|---|---|---|
| The row (operational DB) | yes | yes | no | partial |
| The search index | yes | yes | yes | yes |
| **The embedding model** | **yes (Voyage)** | no | partial | no |
| **Field-level encryption + key vault** | **yes (CSFLE/QE)** | no | no | no |
| A deadline the storage engine owns (TTL) | yes | **no** | varies | partial |

The two bold rows are the ones that matter, and here is why the embedding row
is not a footnote.

**A vector is a lossy copy of the text, and erasing the text does not erase
it.** Measured in this repository rather than asserted from the literature:
after `revoke()`, a surviving embedding still separates its own topic from
another at **0.9988 against 0.7992** cosine. That is a working
attribute-inference oracle over a subject who asked to be forgotten, and it
needs no inversion model — you ask the index whether a document about X is in
there and it says yes. A related measurement in the same codebase shows what
happens when the *model* changes underneath an index: identical text across two
generations of one vendor's model scores **-0.053**, while unrelated text on
the new model scores **+0.301**. A model swap does not degrade ranking, it
inverts it.

Now the positioning point. If the application computes the embedding, the
vector is application state and the database cannot govern it. If **the server**
computes it — Atlas `autoEmbed`, verified against a live cluster in
[`tests/test_atlas_autoembed.py`](tests/test_atlas_autoembed.py), where rows go
in as text, come back with no vector field, and the application genuinely never
holds one — then the derived encoding is **database state with the same
lifecycle as the row**. Erasure can cover it, because the database owns it.

No other vendor can make that statement, because no other vendor owns both the
index and the model. This is the acquisition paying off in a way that is not
"we have embeddings now."

### 3. Crypto-shredding answers the question refusal cannot

Refusal is a property of *one application's read path*. A security reviewer
asks the obvious follow-up about four minutes in: *what about replicas,
snapshots, the backup nobody has restored, the export on somebody's laptop?*

Refusal has nothing to say there. [`voyd/engine/keyring.py`](voyd/engine/keyring.py)
does: per-scope data keys, and destroying one makes every copy of that
ciphertext unreadable everywhere, with no sweeper visiting any of them.

MongoDB ships the primitives for this in the database — a key vault,
`rewrap_many_data_key`, and a server-side `binData` validator so a writer that
skips encryption is refused by the *server* rather than by convention. That is
genuinely rare.

Two honest costs, both of which will come up:

- **It needs `crypt_shared`**, a MongoDB Enterprise download that is not on
  PyPI. Every read path here works without it, but the strongest version of
  the story requires a component many Atlas users do not have configured.
- **Queryable Encryption and per-subject erasure are mutually exclusive**, and
  this is structural, not a gap. Measured in
  [`tests/test_queryable_encryption_costs_what_it_costs.py`](tests/test_queryable_encryption_costs_what_it_costs.py):
  CSFLE resolves `keyId` through a JSON pointer, so the driver picks a
  different key per document, which is what makes per-scope shredding
  possible. QE **rejects a pointer keyId** — one key covers one field across
  the whole collection, so shredding it erases that field for everybody.
  Wanting both means a collection per subject, which is a sharding decision
  wearing an encryption costume.

Also worth having on the label: crypto erasure is not instant either.
libmongocrypt caches data keys, measured here at **~60s** — the same shape and
very nearly the same number as the TTL window this whole project exists to
complain about. The two mechanisms cover each other exactly, which is the
argument for having both rather than picking one.

### 4. The deadline has one owner, which is a real Postgres win

[`drift/exhibit.py`](drift/exhibit.py) stands up the polyglot alternative —
Postgres for the row, Qdrant for the vector, MinIO for the bytes, cron to keep
them agreeing — and lets the expired document answer the query. Four owners,
four clocks, four ways to drift.

And the portability file concedes the honest counterpart: **Postgres has no
TTL.** The moment you need rows actually gone, `pg_cron` or an external job is
the answer, and the deadline has two owners again. That is a place where
MongoDB is straightforwardly stronger, and it is stronger for a boring
structural reason rather than a benchmark.

### 5. It is a credible, non-embarrassing story about AI governance

Erasure obligations are drifting from "delete the record" toward "ensure the
data is not used," and RAG is the case that makes the difference *visible* — a
deleted record that still answers a prompt is about as showable as harm gets.
This is the rare governance story that is a database feature rather than a
policy document, which is a category MongoDB can speak in and a compliance
vendor cannot.

Treat this as the fifth argument, not the first. It is the one most likely to
overclaim, and [`voyd/engine/ledger.py`](voyd/engine/ledger.py) already spends
forty lines on what a hash chain does *not* prove — including that the operator
of the database could rewrite it from entry zero. Any pitch should stay inside
those lines.

---

## Part 3 — The three counterarguments, stated at full strength

### "pgvector is *better* at this, because its index is inside MVCC"

This is the sharpest objection and it is partly right. In Postgres, a deleted
row is atomically invisible to an index scan in the same transaction. There is
no window. In Atlas, **mongot indexes asynchronously** — this repository's own
tests wait on an index-lag timeout before asserting anything, because a freshly
written document is not instantly searchable.

So on the narrow question *"can your index return a row your collection no
longer has?"*, Atlas has a **larger** raw gap than pgvector, not a smaller one.

The honest reframe, which is stronger than a denial:

1. Index lag is precisely why the guarantee cannot live in the index on Atlas.
   The read path is the only place that is synchronous with the caller.
2. MVCC saves Postgres only for *hard deletes in the same transaction*. It does
   nothing for a deadline that has passed, a revocation flag, a quarantine, a
   clearance rule, or a key that was destroyed — which is every reason in this
   system except one.
3. Postgres has no TTL, so the moment the requirement is "and the bytes must
   actually go," it is back to two owners.

Say this out loud rather than hoping it does not come up. "MongoDB needs this
more, and MongoDB is the only one that can ship the whole thing" is a coherent
position. "MongoDB has no gap" is false and checkable in an afternoon.

### "This is a pattern, not a product — anyone can copy it in a sprint"

Largely true, and this repository proves it by doing exactly that on Postgres
in one file. The idea is not defensible.

What is defensible is the assembly: the row, the index, the model, and the key
vault under one lifecycle, with the deadline owned by the storage engine. A
competitor can copy the read-path check in a sprint. Copying *server-owned
embeddings governed by the same erasure as the row* requires owning an
embedding model, which requires an acquisition.

Position on the assembly. Never position on the idea.

### "Customers will just add `deleted: false` to the filter"

The honest answer is that this is 90% correct and costs an afternoon, and any
pitch that pretends otherwise will lose the room. The argument for the
structural version is not that the filter is wrong. It is that the filter is a
**convention**, it holds until somebody writes a second read path, and the
measured history in this codebase is six read paths, one rule, six chances to
forget it.

The response is a demo, not a paragraph: the naive read and the handle, side by
side, one of them returning a revoked document. That is
[`examples/quickstart.py`](examples/quickstart.py), and it runs in ten seconds.

---

## Part 4 — What MongoDB would actually have to do

Ordered by cost. The cheapest is worth doing regardless of whether anything
else happens.

**Cheap — document the traps as guarantees.** The `compound.must` vs
`compound.filter` scoring finding, the fact that a `vectorSearch` definition
cannot be updated in place, and the index-lag-looks-like-empty behaviour are
all things a customer currently discovers in production. Turning them into
documented guidance costs a docs page and prevents a class of silent incident.

**Medium — make the pattern a first-class recipe.** A canonical "admission
control for retrieval" guide in the Atlas AI docs: the per-document check, why
the index filter is an optimisation, and the `autoEmbed` story about the vector
being database state. No product change; it makes the pattern legible and
attaches it to Atlas.

**Expensive, and the actual prize — a server-side visibility predicate.**
A rule attached to a collection that `$vectorSearch` and `$search` are
guaranteed to honour, evaluated per hit, that no read path can omit. That is
this entire library collapsed into the server, and it would be a genuine
category-defining feature rather than a pattern. It is also where the
`vectorSearch`-definitions-are-immutable constraint would have to be solved
rather than worked around.

**The part that is not MongoDB's to solve.** None of this addresses the
external copies — the ETL job, the BI tool, the second service in Go, the
snapshot on a laptop. Crypto-shredding covers the bytes; nothing covers the
read path of an application you do not control. The honest ceiling is *"we
moved the failure from every call site to one construction site."* That is
large, true, and defensible. It is **not** "we made it impossible," and a good
engineer catches the difference in ninety seconds and then discounts everything
else you said.

---

## The one-line version

> Every database can delete; none of them can refuse — and MongoDB is the only
> vendor that owns the row, the index, the embedding model **and** the key
> vault, which is what it takes to make refusal cover the copy of the fact that
> is not stored as text.

## What would falsify this

- A competitor ships a server-side per-hit visibility predicate first. The idea
  is portable and the implementation is not hard; the window is the moat.
- Customers turn out not to care, because the failure is counterfactual and
  invisible — the floor case in [`review.md`](review.md), and the most likely
  one.
- pgvector plus `pg_cron` proves close enough in practice that "one clock"
  stops being a differentiator worth a migration.

None of those are settled. This document is an argument, not a finding, and it
should be read at a lower confidence than anything in
[`AHA.md`](AHA.md) or [`ISSUES.md`](ISSUES.md) — those are measured, and this
is positioning.
