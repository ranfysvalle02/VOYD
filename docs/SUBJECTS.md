# A subject is not always a document

**Three gaps found this week are one gap. `admission/` knows exactly two
places a fact can be — inside a document, and outside the database — and the
modern stack has invented a third, twice.**

This is the design note for that finding. It contains one proof, one fix that
shipped, one guard that shipped, and one problem left open on purpose.

---

## The assumption, written down at last

Nothing in this package ever stated it, because it was true for long enough
to become invisible:

> **A fact is a document. A document has an `_id`. The subject of a policy,
> the unit of retrieval, and the row in the collection are the same thing.**

Every mechanism here rests on it. `why_refused(doc, spec)` reads
`doc[at_field]` and `doc[mark_field]` — top-level. `revoke()` writes a
top-level mark with `$set`. `lineage` is an array of `_id`s, transitively
closed, reachable with one `$in`. `receipt_for` commits to a list of `_id`s
and calls it *what the model was allowed to see*. `Page.examined` counts
documents.

The assumption held because retrieval used to return the thing the policy was
about. It has now stopped doing that in three separate ways, and each one
lands in a place the taxonomy has no name for.

| | a fact can be… | `admission/` calls that | reality now |
|---|---|---|---|
| 1 | inside a document, but not *be* the document | *(no name)* | embedded subjects |
| 2 | inside the database, outside the document | *(no name)* | the mongot vector |
| 3 | inside your cluster, outside your process | *(no name)* | embedding egress |

`derived_fields` handles copies inside a document. `Perimeter` handles copies
outside the database. The middle of that Venn diagram was empty, and all
three findings live in it.

---

## Gap 1 — embedded subjects, and the receipt that lies

### The proof

Not a nested vector index. Not a preview feature. An ordinary `find()`
against the shipped engine, with the marks this package writes itself:

```python
books = engine.model("books", tenant="t").admitting(policy_revision="v1")
await db.books.insert_one({"t": "a", "chapters": [
    {"n": 1, "text": "ordinary"},
    {"n": 3, "text": "SUBJECT ERASURE REQUESTED",
     "forgotten": {"at": now(), "reason": "erasure"}},   # revoke()'s own mark
    {"n": 4, "text": "EXPIRED AN HOUR AGO",
     "expire_at": now() - timedelta(hours=1)},
]})

page = await books.find({"t": "a"})
```

Measured:

```
documents admitted : 1
chapters returned  : 3
   ch1   [live   ] 'ordinary'
   ch3   [REVOKED] 'SUBJECT ERASURE REQUESTED'
   ch4   [EXPIRED] 'EXPIRED AN HOUR AGO'
page.refused       : {}
receipt.refused    : {}
```

The erased chapter reaches the prompt. It is counted nowhere. And the last
line is the one that should end the argument: **`receipt_for` — the
hash-committed, independently recomputable artifact this repository offers as
evidence of what a model was allowed to see — attests that nothing was
refused.** A miscount is a bug. A confident, verifiable, wrong receipt is the
thing an incident review believes.

### Why nested embeddings made this urgent rather than causing it

The hole predates the feature by the entire life of the project. What changed
on 2026-06-30 is that nested embeddings made this shape the *recommended*
retrieval layout — parent documents matched by child embeddings — and handed
the query layer something worse: **child-level filters with no per-document
counterpart.**

That last part is the one that matters architecturally. The whole design
rests on the rule in `voyd/engine/admission/core.py`: `_query` is an
optimisation, `_admit` is the guarantee, and the guarantee is authoritative
*because it sees everything that comes out*. A filter that prunes children
cannot be matched at a boundary that is only ever handed parents. That is
precisely the condition this repository names as fatal:

> A rule you can express in a query but **not** per document is not a slower
> rule, it is a silent hole.

A first-party MongoDB feature now lets you write exactly that rule.

### The fix: name the subject

`AdmissionSpec.subjects` names the array whose elements are subjects in their
own right. `_admit` asks the rules of each element and drops the refused ones
from the document it returns.

```python
books = engine.model("books", tenant="t").admitting(subjects="chapters")
```

```
chapters returned : 1
page.redacted     : 2
receipts()        : {'revoked': 1, 'deadline': 1}
```

Four decisions inside that, each of which could have gone the other way:

**Redact, don't refuse the parent.** The guarantee is that nothing refused
reaches a prompt; removing the element satisfies it. Withholding the whole
document would mean one erased comment suppressing an entire case file —
correct, catastrophic, and not what anyone asked for. The opposite guess,
admitting the parent whole, is the bug being fixed.

**Redaction can never be silent.** A document that comes back shorter than it
is on disk is a lie unless the caller is told. Every removal lands in the
same tally document-level refusals use, and surfaces as `Page.redacted`. The
failure was a short chapter list with an empty `refused`; that must not also
be the fix.

**Cumulative rules are not asked of subjects.** A budget is a property of the
set assembled for one prompt, charged once per retrieval unit. Charging per
element would spend the allowance twice and make `Page.spent` depend on how
the corpus happens to be nested. `Budget` already abstains on a `tab` of
`None` — "not a set read: nothing to say" — so this needed no special case,
only the decision written down.

**Opt-in, and free when unused.** Inventing subjects inside somebody's
documents is a worse guess than the one being fixed. An undeclared collection
behaves exactly as before, and
`tests/test_a_subject_is_not_always_a_document.py` pins that as *current
behaviour* rather than an aspiration — so changing it later is a decision
somebody makes, not a side effect.

### What the fix does not do

- **It does not close the nested-filter hole.** A child-level `$vectorSearch`
  filter still has no per-document counterpart. `subjects` makes the boundary
  able to *see* children; it does not make a server-side child filter
  expressible as a rule. That is the open problem below.
- **It does not give a subject an identity.** A subdocument has no `_id`, so
  `lineage` still cannot name one, `revoke()` still cannot target one, and
  `receipt_for` still commits to parent ids only. Marks on subjects must be
  written by the application today. Composite identity —
  `(parent_id, path, key)` — is the next piece of work and it is not small.
- **It is one level deep, deliberately.** A dotted path is refused at
  declaration: a redaction whose depth nobody can state is worse than one
  that refuses to start.

---

## Gap 2 — the derived encoding that moved out of the document

`AdmissionSpec.derived_fields` defaults to `("embedding",)`, and `marks.py`
nulls every one of them inside the same update that writes an irreversible
mark, on a stated principle:

> the vector beside an erased document is a copy of it in a coat.

That is the right principle. Embeddings are lossy encodings of their source
and partially invertible; refusing the text while keeping the vector is
erasure theatre.

On an `auto_embed` collection **there is no embedding field in the
document.** `auto_embed_definition()` says so outright — "there is no vector
field, because nothing in this process ever computes one." The vector lives
in mongot. So the destruction step sets a field that does not exist, and
because `revoke()` deliberately does not change the text — the row stays on
disk until the reaper, which is the entire design — mongot never re-embeds it
away either.

Sized honestly:

- The **refusal guarantee is intact.** `_admit` still catches the document on
  the way out. Nothing reaches a prompt.
- What is lost is the **second** guarantee — destroy the lossy copy *now*
  rather than on the reaper's schedule — which this codebase advertises,
  implements, and argues for in a comment.
- It is lost **silently.** No warning at declaration, nothing on `health()`.

This is the taxonomy gap in its purest form. The copy is inside the database
you control, outside the document you can write. `derived_fields` was built
for in-document copies. `Perimeter` was built for out-of-process holders and
opens with the rule that governs it:

> **You cannot enforce refusal in a system you do not control. You can
> propagate, observe, and report.**

mongot is a system you *do* control and still cannot write to directly. It is
a fourth perimeter class — `internal`, holding a derived encoding, purgeable
only by changing or deleting the source row — and it has no entry in
`describe()`, which means the one question that module exists to answer
("who else holds this fact") currently has an answer it cannot print.

### The fix: a fourth perimeter class

`INTERNAL` — **a copy held inside the deployment you control, outside the
document you can write.** It is not `owned`: there is no endpoint to call and
no acknowledgement to collect. It is not `derived`: "cannot be recalled" is
false, and saying so gives up a purge that actually exists. It is not
`sealed`: the whole point of server-side embedding is that the server read the
plaintext.

What earns it a class of its own is that it has a *verb*. **It is purged by
overwriting the field it was derived from**, and `derived_index()` is that
purge as a sink:

```python
notes.bounded_by(
    Perimeter().register(derived_index(db, "notes", field="text")))
```

No new machinery in the admission core. `Perimeter.forget(ids, reason)` is
already called on irreversible revocation, already records acknowledgements
on the chain, and already surfaces in `describe()` — so the one question that
module exists to answer, *who else holds this fact*, now has an answer it can
print.

The cost is real and is why this is a registration rather than a default:

> the source text is destroyed at revocation rather than at its deadline, so
> `including_refused()` can no longer show an auditor what was erased.
> **Immediacy is bought with auditability.**

A library that made that trade silently would be deciding something only the
deployment can. Reversible holds never reach it — `Perimeter.forget` runs on
irreversible revocation only — so a quarantine that is later lifted destroys
nothing, and that is tested rather than assumed.

---

## Gap 3 — sealed, and embedded by the server *(guard shipped)*

`Sealed` carries this sentence, and until recently it was true:

> `fields` are encrypted with a Random algorithm and cannot be queried —
> which costs nothing here, because retrieval matches on the embedding and
> the embedding is not the sensitive field.

It is true when the *application* computes the embedding: the app holds
plaintext, produces a vector, stores ciphertext beside it, and the server
never sees the text. Server-side embedding inverts that architecture.
`auto_embed` requires mongot to read the field and send it to an embedding
endpoint over the network.

Declared together on the same path, those are not a trade-off. They are a
contradiction with two resolutions and no third:

1. mongot reads the CSFLE `Binary` and embeds **ciphertext** — every vector
   is noise, and retrieval silently returns nothing useful. The failure
   presents as bad relevance, which is the hardest kind to attribute.
2. or the field is not really sealed, and plaintext a deployment chose this
   library to protect is shipped to a third-party endpoint — a custody event
   `Perimeter.describe()` cannot print, because the embedding provider was
   never registered as a holder.

Before this change, both were declarable in four lines and nothing objected.
Now `Engine.ensure()` refuses, with the argument in the error. Sealing one
field and auto-embedding a *different* one is still allowed and tested —
lossy is not contradictory, and this has no business forbidding it.

---

## The subject that had no name

`subjects` made embedded subjects *visible* to refusal. It left the harder
half open: a subdocument has no `_id`, so nothing could **target** one. An
erasure request that says "forget chapter 3" had no verb, `lineage` could not
name a chapter, and `receipt_for` could not attest at that granularity.

### Position was the obvious answer and it is the wrong one

`chapters.3` is free to compute and stale the first time anybody `$pull`s an
element. Every later index shifts, silently, and the erasure lands on
somebody else's paragraph. On an audit path, *silently wrong* is the worst
available property — worse than refusing to answer.

### So the name is a field, and the field is enforced

`subject_key` names the element field that identifies it. That would
ordinarily make it a convention, and this package's whole complaint is about
guarantees that depend on somebody remembering one. It is not a convention,
because an element that does not carry the key is **refused as `unnamed`**
rather than admitted.

The tenant works exactly this way: application-supplied, non-optional, loud
when missing. `unnamed` fails closed in the same direction `unreadable` does,
and for a sharper reason — a subject nobody can address today is one nobody
can erase tomorrow. Whether it happens to be expired right now is a question
about a thing this deployment has no way to talk about.

It is counted apart from every other reason on purpose. `unnamed` is a
statement about the *schema*, not about the fact: it reads as "fix the
writer", where merging it into `revoked` would read as "the system is
forgetting things."

### And then the verb

```python
await books.revoke_subject({"t": "a", "doc_id": "b1"},
                           key="c3", reason="erasure")
```

It writes the same `revoked` mark the document-level verb writes, in the same
shape, so the read path needs no second rule — `_redact` already asks the
ordinary rules of each element. One vocabulary, two granularities. It is
authorised by the same `REVOKE` grant, counted in the same receipts, guarded
by the same unbounded-write check, and witnessed on the same chain with the
subject in `detail`.

**One asymmetry, stated rather than implied.** Revoking a document pulls its
`expire_at` earlier so the reaper takes the bytes. `revoke_subject` does not,
because there is nothing to pull: TTL collects documents, not array elements.
The element stays on disk, refused on every read, until its parent's own
deadline. That is unreachability, and the erasure is the parent's — and an
auditor can still see what was withheld, which is the reason the bytes stay.

Two implementation notes worth keeping, because both were discovered the hard
way. `arrayFilters` and pipeline-style updates are mutually exclusive in
MongoDB, so this is a plain `$set` — which also removes the need for the
`$literal` wrapper `impose` carries, since a `$`-prefixed value is only read
as a field path inside an aggregation expression. And the parent is looked up
through the audit query: revoking a chapter inside an expired book is a
legitimate instruction, and a query that hid the parent would report "nothing
matched" for a document that is plainly there.

### What is still open, and it is now one thing

Subjects have stable names. Nothing yet **carries** them:

- `lineage` is still an array of `_id`s. A summary derived from chapter 3 can
  name the book and not the chapter. The name now exists to put there —
  `(parent_id, path, key)` renders to a string — so this is plumbing rather
  than design.
- `receipt_for` commits to parent ids only. `ContextRef` already carries a
  typed `kind`; a third kind for an embedded subject is the obvious shape.
- **A nested `$vectorSearch` child filter still has no per-document
  counterpart.** `subjects` makes the boundary able to *see* children; it does
  not make a server-side child filter expressible as a rule. This is the one
  remaining instance of the condition this repository calls fatal, and the
  cheap interim is to refuse at `ensure()` when an admitting collection
  carries a nested vector index — turning a silent hole into a loud one.

## What shipped, and what is pinned

- `AdmissionSpec.subjects`, `AdmissionCore._redact`, `AdmissionCore._harvest`,
  `Page.redacted`.
- `AdmissionSpec.subject_key`, the `unnamed` reason, `AdmissionCore._unnamed`,
  and `Admission.revoke_subject()`.
- `INTERNAL` and `derived_index()` in `voyd/engine/perimeter.py`.
- `Engine._refuse_sealed_autoembed()`, run from `ensure()`.
- `tests/test_a_subject_is_not_always_a_document.py`, including the two cases
  that pin the *unfixed* behaviour — an undeclared collection still admits
  embedded subjects, and its receipt still says nothing was refused — so that
  neither can change by accident.

Two of those tests earned their place immediately. `_redact` stamps a private
key so it can return a document and a count in one value, and the test
asserting the key never reaches a caller failed on the first run: `find_one`
was handing it straight through. And the sealed-plus-auto-embed guard tripped
the engine's own vendor-vocabulary scan, because the word *coherent* contains
one. A sentinel that escapes is a worse bug than the one it was added for,
which is why both invariants are tests and not comments.
