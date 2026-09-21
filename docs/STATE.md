# State: what is wrong, what is next, what is worth doing

**Verified against the code on 20 September 2026.** Every entry was checked,
not recalled.

This replaces `ISSUES.md`, `ideas.md` and `opportunities.md`. Those three were
a defensible split — what is *wrong*, what is worth *building*, what is worth
*doing* — and each one opened by explaining how it differed from the other
two. When a document's first job is to distinguish itself from its siblings,
the split is costing more than it earns. Half of what they held was also
struck-through or marked shipped: a changelog, kept in the place a reader
looks for current state. That is what the git history is for, and it is where
those entries now live.

One page, three questions, no closed items.

---

## 1. What is wrong

### The embedding is not encrypted, and cannot be

**Medium — documented, mitigated, not eliminated.**

`Sealed(("text",))` encrypts the text; the vector beside it stays plaintext,
because encrypting it would end vector search. An erasure now destroys derived
encodings in the same write — measured before that fix, a surviving vector
separated its own topic from another at 0.9988 against 0.7992 cosine, which is
a membership oracle over somebody who asked to be forgotten. So a *revoked*
document keeps no vector.

What remains: a merely `quarantined` document keeps its embedding on purpose —
the row is evidence and the vector is how an investigator finds others like it
— so a held document is still attribute-inferrable by anyone who can read the
collection. That is the right trade, it is not free, and it belongs wherever
quarantine is described to an auditor.

### Queryable Encryption cannot do per-subject erasure

**Low — measured, documented, not fixable here.**

QE rejects a JSON-pointer `keyId`, so a QE key is bound per field per
collection at creation, and shredding it erases that field for every subject.
Not a bug and not a gap: it is what the mode is. Recorded because somebody
will eventually try to "fix" it, and because `Sealed` being the default
depends on this being understood. QE `range` queries are declared in the type
and only `equality` is exercised.

### Budget and sealing do not compose

**Low — refused at construction, not silently wrong.**

`Budget` charges a selected hit; sealing can only refuse that hit after
asynchronous decryption finds its key gone. Charging before decryption would
put ciphertext that never reached the caller into `Page.spent`. Both orderings
give a precise number with a false meaning, so `sealed_by()` rejects a handle
carrying a cumulative rule. The fix is not an exception in the counter — it is
ordering the read path as pure admission → decryption → cumulative admission,
with refill after either refusal. Until that exists, failing at construction
is the only honest composition.

### Destroying the derived encoding is a silent no-op under `auto_embed`

**A reader would be wrong about the second guarantee, not the first.**

`AdmissionSpec.derived_fields` defaults to `("embedding",)` and `marks.py`
nulls every one of them in the same update that writes an irreversible mark.
On an `auto_embed` collection there is no embedding field in the document —
the vector lives inside mongot — so that write sets a field that does not
exist and the lossy encoding of the erased text stays in the index.

- The **refusal guarantee is intact**: the per-document check still catches
  the document on the way out.
- What is lost is the **second** guarantee, destroying the derived encoding
  immediately rather than on the reaper's schedule — which this codebase
  advertises, implements, and argues for in a comment.
- It is lost **silently**: no warning at declaration, nothing on `health()`.

The minimum fix is loud — refuse or warn at `ensure()` when a spec declares
both `auto_embed` and non-empty `derived_fields`. The honest fix is to work
out what erasure means when a third-party index holds the lossy copy, which is
not MongoDB-specific and is therefore a [`drift/`](../drift) exhibit rather
than a patch.

### A nested `$vectorSearch` child filter has no per-document counterpart

**The one condition this repository calls fatal, present in one place.**

[`AHA.md`](AHA.md) rests on the asymmetry: a rule may be egress-only (slower,
safe), but a rule that exists *only* as a query clause is a silent hole.
`AdmissionSpec.subjects` and `subject_key` let the boundary see subdocuments,
and `ensure()` refuses a nested vector index on a collection that never named
its subjects — but neither makes a server-side child filter expressible as a
rule. A nested `$vectorSearch` filter therefore prunes at the index with no
per-document check behind it, which is the shape the rest of the package
exists to forbid.

Two smaller gaps sit behind it, both plumbing now that subjects have stable
names: `lineage` is an array of `_id`s, so a summary derived from chapter 3
names the book and not the chapter; and `receipt_for` commits to parent ids
only, where `ContextRef`'s typed `kind` wants a third value for an embedded
subject.

The cheap interim is to refuse at `ensure()` when an admitting collection
carries a nested vector index at all — turning a silent hole into a loud one,
which is the move this repository makes everywhere else. The real fix is marks
and deadlines on array elements: array-filter updates in `marks.py`, a
composite identity through `lineage.py`, and re-derived `Page` accounting.

---

## 2. What is worth building

### The freeze comes first

None of the items below is the next thing to build. The next thing is one
retained Python + MongoDB pilot on the handle ([`PILOT.md`](../PILOT.md)).
Until that exists, each of these adds surface to a project whose public
surface has already overgrown once — `voyd.engine.__all__` reached 100 names,
48 of which appeared in no README, blog or example, and it is pinned by
`tests/test_the_public_surface_is_deliberate.py` now precisely because nothing
had ever asked those names to earn themselves.

Frozen, with the reasoning kept so it is not relitigated: **the HTTP
namespace** and **the policy editor** (both owe the same unanswered
authorization story for verbs that change reachability), **MCP as an
identity** (a channel a model calls, not the category), **a TypeScript
client** (reach, not proof), **Qdrant as a second engine** and **the outward
leak detector** (both double the surface that has to hold), and **wiring
`redrive()`** (a worker with credentials for every sink is a deployment
decision, not a default).

The identity is the handle. These wait on evidence that a stranger keeps it.

**What has passed the freeze since, and why.** The same bar the policy
compiler cleared: one example, one test file, a paragraph of doc, and not one
line added to `voyd`.

*Set-relative rules are a category with more than two members.* `AHA.md` step
5 argued the category from `Budget` and `Distinct`, which is a category
asserted from the two examples that happen to ship.
[`examples/portfolio.py`](../examples/portfolio.py) writes three more against
the public protocol — a provenance quota, a per-source ceiling, a mixed-tier
cost budget — and they compose on one handle. It got through because it is
not surface: it is evidence that a stranger can write one, and a test asserts
the rules stay in `examples/` for exactly that reason. The reframing it
suggests is the part worth having: a prompt is a **regulated set**, not a
ranked list.

*Answer-level revocation already works.* An answer written back with
`derive()` naming the context it was built from is unreachable the moment any
source is revoked — every RAG cache in production is a pile of derived
documents with no erasure story, and this one has had the machinery the whole
time. Nothing was built; a test now says so.

**And one thing that turned out not to be buildable, which is worth more than
either.** An admission boundary on an agent's *session state* — a fact revoked
at turn 40 not surviving into turn 41 — cannot work, because refusal binds a
read and not a value. A copy taken before the mark was written is not the
document; it is what the document used to say, and `reachable()` correctly
admits it. That is the in-memory instance of the position `perimeter.py`
already takes, and the remedy that needs no code is re-reading the carried ids
through the handle at the top of each turn. Pinned in both directions in
`tests/test_refusal_binds_a_read_not_a_value.py`.

The version that *would* need code is a store-backed liveness check —
`still_reachable(ids)` asking the database rather than the copy. That is new
surface on the frozen side of the line, and it should wait for a pilot that
asks for it.

### The frontier — things that change what can be *claimed*

**The perimeter, past propagation.** `holds=SEALED` is a check rather than a
claim, unanswered acknowledgements retry within a horizon and close
*unconfirmed* past it, and registering a sink costs three lines. What is left:
nothing drives `redrive()` (frozen, above), and `audit()` has no scheduled
caller — it needs a genuinely shredded id to hand a sink, which makes it
natural to run right after a shred, so a deployment could be told "your mirror
claims to hold ciphertext and caches plaintext" at the moment the claim
matters rather than never.

**Context receipts, reverse-indexed — and the half of it that already works.**
Receipts recompute without a secret and compose with `as_of`, so *"was this
context legitimate when it was built?"* is two calls.

The question people actually have is *"which answers were built on this
fact?"*, and this entry used to say you could only check a receipt you already
hold. That is too broad. `derive()` closes lineage transitively at write time,
so `find({"lineage": source_id})` returns every summary, answer and embedding
built on a fact, at any depth, in one indexed query — today, for anything
written back into the collection, which is what a RAG cache *is*. Pinned in
`tests/test_refusal_binds_a_read_not_a_value.py`.

What is genuinely missing is narrower: the artefact that **left**. A Slack
message, a fine-tune, an answer served and not written back. For those, all
you have is a receipt you already hold, and storing receipts keyed by admitted
id is what turns that archaeology project into a query. The cost is a
retention decision worth making deliberately: a receipt names ids and not
text, but it is a record of who saw what, and that has its own sensitivity and
its own deadline.

### Sharp and cheap

**The quarantine reviewer.** `quarantine()` and `release()` ship; the queue
does not, and quarantine without a review loop is a graveyard —
indistinguishable from a leak nobody looked at. `engine.queue(when=…)` exists
and the document is already the job, so this is roughly one line plus a
surface: `queue(when={"quarantined": {"$ne": None}})`. `lifted_total` is
already counted apart from `revoked_total`, so the queue arrives with the
metric that matters: a climbing `lifted` means the detector is mistuned.

**Time-to-unreachable, as a packaged artifact.** [`PILOT.md`](../PILOT.md)
gate 1 asks a team to instrument both ends of one real erasure request, and
that is prose instructions with no tooling behind it. `bench/measure.py`
measures the TTL sweeper distribution, which is the "before" half; nothing
packages before-and-after as one artifact a team can drop in. It is the only
gate in the pilot that is not turnkey.

### Sealing on the HTTP path

The keyring is an engine primitive; nothing in the product encrypts anything.
Wiring it in needs an answer to *which fields a scope declares sensitive*, and
the vault API has no way to express a schema. That is a product decision, not
an encryption one, and doing it badly would put a schema in a URL — the same
shape as the reason holds are not on the HTTP surface: the missing piece is an
authorisation story, not a mechanism.

---

## 3. What is worth doing that is not code

Ranked by how much each moves the only number that is currently zero: people
who are not the author and have kept it.

**1. Publish the Qdrant finding as its own thing.** *A whole class of vector
databases can express this guarantee only politely.* Postgres can make the
unfiltered read raise `permission denied` — revoke the table, grant only a
view. Qdrant on the stock image cannot: no row, no view, no `GRANT`, no
collection-level default filter, so the payload filter is a convention that
holds until the next caller omits it.
[`drift/refusal_on_qdrant.py`](../drift/refusal_on_qdrant.py) demonstrates it.

**2. Spec the protocol, not the library.** The handle is a week of work for a
competent engineer who has read the post. The protocol underneath it — three
members, five optional attributes, and a theory of set-relative rules — is the
part that took the mistakes. Libraries get copied; protocols get adopted. It
ranks high because it is the only path to being *the standard* rather than one
implementation, and not first because a protocol with one implementation and
no users is a naming ceremony.

**3. The scanner can outgrow the parent.** *"Count your own leaks"* is a
broader product than *"adopt my handle."* [`scanner/`](../scanner/README.md)
is a separate distribution with zero dependencies and no import of `voyd`, and
it is the only artifact here that costs a stranger nothing and returns a
number about their own code. It is the top of every funnel — but a diagnostic
with no cure attached converts nobody.

**4. Agent memory, not RAG.** Agents write facts back, derive facts from
facts, and hold credentials with real lifetimes. That is exactly the shape the
lineage and inherited-refusal machinery was built for — forget a source and
the summary written out of it goes too — and no agent framework has it. The
most promising *reframing* available and the least evidenced.

**5. An employer is a distribution channel almost nobody has.** A credible,
non-embarrassing AI-governance story for a vector database is rare, and
solutions architects talk every week to teams doing retrieval under erasure
obligations. One of them running [`bench/pilot.py`](../bench/pilot.py) against
a customer's shape is worth more than any launch post. **Ranked fifth and
first on the calendar** — see below.

**6. Context receipts, reverse-indexed.** The most valuable *feature* on this
page and the one that least changes whether anyone adopts the thing. Also the
only item that helps with a consequence that has already left the building.

### The one thing this page cannot do

Five of the six above can be done alone at a desk, which is exactly why they
are a trap. The number that decides this project is **kept after two weeks**;
[`PILOT.md`](../PILOT.md) is built to answer it, and `bench/pilot.py`
deliberately leaves that line blank while filling in every other, because a
proof of the mechanism is not evidence of demand.

Item 5 is the only entry that can fill it in. Do that one first.

---

## 4. Deliberately not doing

Considered and rejected, with the reason, so it is not relitigated every six
months.

- **A delete tool or endpoint.** A delete hands the caller a cleanup
  obligation, and an agent that has to remember to clean up is the failure
  this exists to remove. CI asserts no MCP tool is named for reclaiming
  anything, and `tests/test_nothing_reclaims_out_of_band.py` now asserts the
  *endpoint* half too — a purge pass found `DELETE /v1/voyds/{slug}` on the
  HTTP surface the whole time, untested and cascading through a hardcoded list
  of two collections written before three more existed. Owner offboarding is
  `POST /v1/voyds/{slug}/forget`, the same verb the other tiers use. The
  guarantee had been strongest at the leaf and absent at the root, which is
  backwards.
- **An undo for `revoke()`.** Two reasons, either sufficient: the row is
  already scheduled for the reaper, so the undo would work until
  `ttlMonitorSleepSecs` decided otherwise — an API whose window is a storage
  event, in the codebase written to argue guarantees must not depend on
  sweepers. And it would make the chain *intact and false*. Re-admitting
  erased information is a new document with new provenance. See `Irreversible`
  in `voyd/engine/errors.py`.
- **Per-subject erasure under Queryable Encryption.** A measured constraint,
  not a missing feature — see §1. Wanting per-subject shredding *and* a
  searchable ciphertext means one collection per subject, which is a sharding
  decision wearing an encryption costume.
- **Pushing the deadline into the vector index.** Measured and rejected: a
  `vectorSearch` definition cannot be updated in place, so it is a
  drop-and-rebuild on every existing deployment, and a rebuilding index
  returns zero rows rather than erroring. Reasoning in
  `voyd/engine/search.py`.
- **Ledgering reads.** A write per refused hit, for a property the read path
  enforces anyway and the suite proves. The chain records *instructions* —
  revocations, holds, liftings — because those are facts about the world.
  Reverse-indexed receipts (§2) are the right version of what this was
  reaching for.
- **A browser surface.** Removed, and its residue kept surfacing for months:
  orphaned store methods, a dead download counter, a slug derived from a
  business name nobody types. One credential, three surfaces: the JSON API,
  the MCP tools, `import voyd`.

---

## 5. Known and accepted

- **Nothing has run against a hosted KMS.** KMIP is proven — a real server
  over TLS, rotation, shredding. The hosted providers (`Aws`, `Azure`, `Gcp`)
  share that code path; what is unproven is vendor-specific: credential
  discovery, throttling, and AWS `ScheduleKeyDeletion`'s 7-day minimum.
- **Atlas Local accepts `autoEmbed` index definitions it cannot serve.** An
  upstream defect this repository found and filed; kept in
  [`BUG.md`](BUG.md) because a test still depends on the fallback it forced.
- **`numCandidates` is `max(50, limit * 10)` and does not scale with filter
  selectivity.** MongoDB's guidance is that a highly selective pre-filter
  needs a proportionally larger candidate pool, or the query cannot find
  enough matches to fill `limit` — which would land hardest on exactly the
  case a tenant filter creates. Measured on Atlas Local before assuming it:
  600 documents, a filter selecting 5 of them (0.8%), `numCandidates` swept
  from 50 to 2000. All five hits came back at every level, because the filter
  is applied during HNSW traversal rather than to a pre-drawn sample.

  So it does not reproduce at laptop scale, and that is the whole of what is
  known. At millions of documents the guidance may well bite, and this
  repository has no way to find out without a corpus it does not have. Written
  down so the next person to read the MongoDB docs and worry can start from
  the measurement rather than repeat it. The formula is one line in
  `voyd/engine/search.py`.

  Worth noting what is *not* at risk here: a missing or not-yet-queryable
  index does not return a silent zero. `_queryable()` checks the named index
  and the Atlas path refuses until it is live, falling back to in-process
  cosine with a warning — the failure this project cares about most, already
  closed.

- **The scanner is a floor, not a census.** ORM layers and dynamically named
  collections are invisible to it, and rules with no query half are invisible
  to *every* static analyser — see [`AHA.md`](AHA.md) step 5.
