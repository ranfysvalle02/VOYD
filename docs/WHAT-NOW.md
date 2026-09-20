# What now

**Four things moved underneath this repository. Three are edits. The fourth
is a design question that the document model just asked us, and it is the
only one worth staying up for.**

Checked against vendor documentation on **2026-09-20**. Everything below is
either a line in this tree or a dated citation at the bottom — no claim here
rests on recollection, because this is the fastest-rotting surface in the
stack and the whole argument of this project is that a guarantee you have to
remember is not enforced.

---

## The four

| | what changed | status | costs us |
|---|---|---|---|
| 1 | Voyage 4 generation shipped | GA | a default, three lines |
| 2 | `$rankFusion` floor is 8.0, not 8.1 | GA since 8.0 | a silent tier downgrade |
| 3 | Atlas Local can auto-embed now | preview tag | a stale fallback comment |
| 4 | **Nested embeddings** | GA 2026-06-30 | the unit of refusal |

---

## 1. `voyage-3` is two generations back

`voyd/config.py:42` and `voyd/intelligence/__init__.py:13` both default to
`model: str = "voyage-3"`, `dimensions: int = 1024`.

The current lineup is `voyage-4-large`, `voyage-4`, `voyage-4-lite`, and
`voyage-4-nano` (open-weight), with `voyage-code-4` for code. `voyage-4` is
the documented recommendation. `voyage-3` still serves — it is listed as
previous-generation, not deprecated — but it is the one model in the
comparison with **fixed 1024 dimensions and no quantization support**. The
4-series and the 3.5/3-large models all take 256/512/1024/2048 via
Matryoshka truncation and support int8/binary output.

That matters here more than it would elsewhere. `VoyageConfig.dimensions`
feeds `SearchSpec.dimensions`, which feeds `numDimensions` in
`vector_definition()` — and changing the dimension of a live vector index is
the unmigratable index change that `voyd/engine/search.py` already spends
paragraphs explaining. Picking the default that *cannot* be reduced later
without a rebuild is the wrong default to have frozen.

**The fix is a default and a sentence.** The sentence is the important half:
whatever is chosen, `VoyageConfig` should say why that dimension, because the
next person to touch it will be doing so during an index rebuild.

---

## 2. `RANK_FUSION_MIN_VERSION = (8, 1)` is wrong, and wrong in the direction this repo hates

`voyd/engine/capabilities.py:23`:

```python
# $rankFusion (reciprocal rank fusion as a first-class aggregation stage) is 8.1+.
RANK_FUSION_MIN_VERSION = (8, 1)
```

The server manual states `$rankFusion` is available for deployments using
**MongoDB 8.0 and later**.

So every 8.0 cluster this engine connects to is probed, found search-capable,
told it cannot do rank fusion, and silently demoted from the `hybrid` tier to
the `vector` tier. It returns worse results, forever, with no error. The
health endpoint reports `"tier": "vector"` and is believed, because it is
supposed to be the honest answer.

Read `capabilities.py`'s own opening docstring against this:

> It exists because the opposite bit us. Atlas support used to be inferred
> from the connection string [...] Every local run silently used a fallback
> path and `$vectorSearch` never executed at all, for months, without a
> single log line. **Asking the server is the only honest question.**

The module that was written to stop capability being *guessed* guesses a
version floor from a hardcoded constant. Same failure, one layer in. The
constant is not probed and cannot be, which is the argument for lowering it
to `(8, 0)` and for treating the `OperationFailure` on an unsupported stage
as the real detector — the same shape as `_supports_search`.

**There are also two new rungs on the ladder that this engine has no concept
of.** `$scoreFusion` (normalised score combination rather than reciprocal
rank) is GA in 8.3, and `$rerank` is in public preview on 8.3. The
`search_tier` property currently reads `cosine → vector → hybrid`. The real
ladder is longer now, and `search_tier` is a string that gets put on
dashboards.

---

## 3. Atlas Local *can* auto-embed now, and the fallback detector says it cannot

`voyd/engine/search.py:333` string-matches the server's rejection to decide
whether auto-embedding exists:

```python
_NO_AUTO_EMBED = ("supported models are: []", "not registered yet", ...)
```

with the reasoning, in the method below it, that this is "expected on Atlas
Local, which registers no models."

That is now false. Atlas Local supports automated embedding on the
**`mongodb/mongodb-atlas-local:preview`** tag, given a `VOYAGE_API_KEY`
environment variable, with a documented caveat that it accepts only one key
and uses it for both indexing and querying. `docker-compose.yml:13` pins
`mongodb/mongodb-atlas-local:8.2`.

Self-managed and Community need `mongot` 1.70.1+ and **MongoDB 8.3+**, two
API keys (indexing and querying, separately rate-limited), and outbound
network access to `https://ai.mongodb.com/v1/embeddings` or directly to
Voyage. Models are called remotely; nothing is downloaded.

Two consequences:

- **`tests/test_the_server_can_own_the_embedding.py` is currently testing the
  fallback, not the feature.** Its header pins mongot 0.69.1 / edition
  `localDev`. The auto path it describes as untestable locally is now
  testable locally.
- **The declared-not-probed design was right and is now paying off.** The
  comment on `SearchSpec.auto_embed` says adoption is "safe before every
  deployment supports it," and that is exactly what happened: the fallback
  held for a year and the same code takes the auto path now that models
  exist. Nothing has to change for it to start working — only the detector
  that decides it cannot.

**One real gap while we are here.** `auto_embed_definition()` at
`voyd/engine/search.py:179` emits only `type`, `path`, `model`, `modality`,
plus filters. The documented `autoEmbed` field definition also accepts
`numDimensions`, `similarity`, `indexingMethod`, `hnswOptions`, and
`quantization`. Leaving them unset means taking defaults on the two knobs —
Matryoshka dimension and scalar/binary quantization — that decide what the
index costs to store and scan. `vector_definition()` already sets
`numDimensions` and `similarity` for the bring-your-own-vector path. The two
definitions have drifted.

---

## 4. Nested embeddings, and the unit of refusal

The first three are edits. This one is not.

Nested embeddings went GA on 2026-06-30. `$vectorSearch` can now index
embeddings held **inside arrays of subdocuments** and return the *parent*
document, ranked by its children — `max` to surface a parent with one strong
match, `avg` to rank by overall alignment — with child embeddings and parent
documents filterable **independently**.

It is a good feature and it is aimed squarely at the pattern this engine
serves: a document with chunks, retrieved whole, so a RAG answer gets the
parent as context instead of an orphaned fragment.

It also breaks an assumption that runs through every file in
`voyd/engine/admission/`.

### The assumption

> A fact is a document. A document has an `_id`. Refusal marks a document,
> lineage names a document, and `_admit` is handed a document.

`why_refused(doc, spec)` reads top-level fields — `doc[at_field]`,
`doc[mark_field]`. `revoke()` writes a top-level mark with `$set`. `lineage`
is an array of `_id`s, transitively closed, reachable with one `$in`.
`Page.examined` counts documents. Every one of those is a statement about a
root document.

### What nested retrieval does to it

Now the **unit of relevance is the child** and the **unit of retrieval is the
parent**. Four things follow, and the third is the serious one:

1. **A revoked chapter inside an admitted book is invisible.** If the mark
   lives on the subdocument, no rule sees it: rules read top-level fields. If
   the mark lives on the parent, revoking one chapter withholds the whole
   book. Neither is right, and there is currently no way to say which was
   meant.

2. **Lineage has nothing to point at.** A subdocument has no `_id`. A summary
   derived from chapter 3 can only name the book — so `impose()` propagating
   to descendants either over-reaches (everything made from any chapter) or
   the closure stops being able to express what happened.

3. **The two enforcement points can now disagree, and disagree *silently*.**
   This is the one that matters. The whole architecture rests on the rule in
   `voyd/engine/admission/core.py`: `_query` is the optimisation, `_admit` is
   the guarantee, and the guarantee is authoritative because it sees every
   document on the way out. Nested filters break the symmetry — mongot can
   now filter *child* embeddings server-side, and `_admit` is handed the
   *parent*. A clause that prunes children has no per-document counterpart at
   the boundary, because the boundary never sees a child. That is precisely
   the condition this repository names as fatal:

   > A rule you can express in a query but **not** per document is not a
   > slower rule, it is a silent hole.

   Nested filtering makes it possible to write exactly that rule, using a
   first-party MongoDB feature, without noticing.

4. **`Page` accounting becomes ambiguous.** `examined` and `refused` count
   candidates. Parents or children? A budget charging per parent while
   relevance was decided per child is a budget measuring the wrong thing.

### The options, with their costs

- **Refuse to support it.** Declare that an admitting collection is flat, and
  fail loudly at `ensure()` if a nested vector index is found on one. Cheap,
  honest, and gives up the document model's best pattern — which, for a
  MongoDB-native product, is a real price.
- **Root-only semantics, stated.** Nested indexes are allowed; the mark and
  the deadline are parent-level, full stop; a nested filter clause is
  rejected at declaration. Preserves the invariant. Means chapter-level
  erasure is not expressible.
- **Make the subdocument a first-class subject.** Marks and deadlines on
  array elements, `_admit` walking children, lineage naming
  `(parent_id, path, index)` or a stable child key. This is the correct
  answer and it is expensive: array-filter updates in `marks.py`, a
  composite identity through `lineage.py`, and re-derived `Page` accounting.
- **Split the difference: `$unset` the child.** Refusing a child by removing
  it from the returned parent at the boundary. Keeps `_admit` authoritative,
  but it mutates what the caller receives, and a book silently missing
  chapter 3 is its own category of lie unless `Page` says so.

I am not picking one here. The point of this section is that **the choice
exists now and is currently being made by default** — which is the condition
this repository was built to eliminate.

---

## The autoEmbed erasure gap, which nobody would notice

Separate from all four, found while reading the above.

`AdmissionSpec.derived_fields` defaults to `("embedding",)`
(`voyd/engine/admission/spec.py:33`), and `marks.py:352` nulls every one of
them inside the same update that writes an irreversible mark:

> And the derived encodings go now, not on the reaper's schedule. [...] the
> vector beside an erased document is a copy of it in a coat.

On an `auto_embed` collection **there is no embedding field in the
document.** `auto_embed_definition()` says so outright — "there is no vector
field, because nothing in this process ever computes one." The vector lives
inside mongot.

So on an auto-embedding collection, `mark_set["embedding"] = None` sets a
field that does not exist, and the lossy encoding of the erased text stays in
the vector index. It is not re-embedded away, either, because `revoke()`
deliberately **does not change the text** — the row stays on disk until the
reaper takes it, which is the entire design.

Be precise about the size of this, because overstating it would make it the
kind of claim this repo refuses elsewhere:

- The **refusal guarantee is intact.** `_admit` still catches the document on
  the way out; nothing reaches a prompt.
- What is lost is the **second** guarantee — destroy the derived encoding
  immediately rather than on the reaper's schedule — which this codebase
  advertises, implements, and argues for in a comment.
- It is lost **silently**. There is no warning at declaration and no field on
  `health()` saying "derived-field destruction is a no-op here."

The minimum fix is a loud one: refuse, or warn at `ensure()`, when a spec
declares both `auto_embed` and non-empty `derived_fields`. The honest fix is
to work out what erasure means when a third-party index holds the lossy copy
— and that question is not MongoDB-specific. It is true of every hosted
embedding index, which makes it a `drift/` exhibit, not a patch.

---

## What shipped from this list

Written as a worklist; most of it is done, and leaving the original order
here as a to-do would make this document the stale thing it complains about.

| | | |
|---|---|---|
| 1 | the version floor | **gone** — `RANK_FUSION_MIN_VERSION` deleted, the stage is probed by `_supports_rank_fusion` and an AST guard bans the shape |
| 2 | the unwritable derived copy | **named** — `INTERNAL` and `derived_index()` in `perimeter.py`, purged through the field it was derived from |
| 3 | the stale default | **moved** to `voyage-4`, with the dimension rationale written where the next person will need it |
| 4 | `auto_embed_definition()` parity | open — `numDimensions`, `similarity`, `quantization` still unset |
| 5 | the local stack on `:preview` | open — needs 8.3 for the self-managed path |
| 6 | `$scoreFusion` / `$rerank` rungs | open |
| 7 | the nested-embeddings question | **decided** — `subjects=` and `subject_key=`, and `ensure()` refuses a nested index on a collection that never named its subjects |

And one thing that was not on the list, because it is the reason the list
existed: every item above is an assumption about software this package does
not ship, and there was nothing anywhere that knew that. There is now —
`voyd/engine/assumptions.py`, and `SUBJECTS.md` for the design that came out
of item 7.

## What this does not claim

- **None of this is tested.** Every statement about vendor behaviour is read
  from documentation dated today, not observed against a cluster. The `8.0`
  rank-fusion floor in particular should be confirmed against a real 8.0
  deployment before the constant is changed — a version floor moved on the
  strength of a doc page is the same class of mistake as one guessed from a
  connection string.
- **The nested-embeddings analysis is a reading of the feature, not an
  exploit.** I have not built a nested index against this engine and watched
  `_admit` miss a child. That demo is the next step and it belongs in
  `drift/`, beside `drift/refusal_on_qdrant.py`, because "the filter and the
  boundary disagreed" is the house genre.
- **"Previous generation" is not "deprecated."** `voyage-3` is not broken and
  nothing here is urgent on that axis. The argument for moving is the
  dimension flexibility, not the model quality.
- **Pricing and rate limits are noted where the docs stated them and are not
  reproduced here**, because a number copied out of a pricing page into a
  repository is stale the week after and this file would then be the thing it
  is complaining about.

---

## Sources

- [Voyage AI — embedding models](https://docs.voyageai.com/docs/embeddings)
- [MongoDB — Models for Automated Embedding](https://www.mongodb.com/docs/vector-search/crud-embeddings/automated-embedding/models/)
- [MongoDB — Configure mongot for Automated Embedding (self-managed)](https://www.mongodb.com/docs/search/self-managed/current/configuration/automated-embedding/)
- [MongoDB — Nested embeddings in Atlas](https://www.mongodb.com/company/blog/product-release-announcements/search-way-you-model-nested-embeddings-in-atlas)
- [MongoDB — `$rankFusion` (aggregation)](https://www.mongodb.com/docs/manual/reference/operator/aggregation/rankFusion/)
- [MongoDB — Native reranking and hybrid search](https://www.mongodb.com/company/blog/product-release-announcements/improving-agent-retrieval-native-reranking-hybrid-search)
