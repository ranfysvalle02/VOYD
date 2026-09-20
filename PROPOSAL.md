# Directions this could be

[`ideas.md`](ideas.md) is what to *build*. This is what to *be*. They are
different documents because a backlog that does not pick a buyer is how a
library stays a library.

The constraint is the one in [`appendix.md`](appendix.md): the guarantee is
enforced at a handle, in one process, in one language, against one database.
The engineer who must route reads through that handle bears the cost.
Compliance receives the benefit. The data subject is not in the room. That
split decides adoption more than any feature does.

Each direction below is a different answer to the split — a different first
customer, a different first sentence, and a different thing you would stop
pretending to be. They share the engine. They do not share a README.

The ranking is not which is most true. It is which is most likely to get
installed by someone who was not already convinced.

One category is deliberately not in the top three. **Agent memory is
saturated** — Mem0, Zep, Letta, and a new one every quarter, all judged
on how well they remember. This project's whole argument is a different
verb. Putting memory in the headline is how you enter that race and lose
it. `memory` is one of five traits, and the engine is "deliberately free
of application vocabulary" for a reason. Memory is a demo of the
primitive. It is not the company.

---

## 1. Admission control for what may reach a prompt

**Be the missing database verb: refuse. Not a memory product. Not a
guardrail. Not a filter you remember to apply.**

The empty slot is precise, and it is not "agent memory":

| layer | what it decides | who ships it |
|---|---|---|
| guardrails | what the model may *say* | Lakera, NeMo, LlamaGuard — crowded |
| vector search | what *ranks* | Pinecone, Qdrant, mongot — crowded |
| agent memory | what the agent *keeps* | Mem0, Zep, Letta — crowded |
| governance | what the catalogue *claims* | OneTrust, Collibra — crowded |
| **admission** | **what may *enter* a prompt** | **this project, structurally** |

Guardrails sit on the way *out* of the model. Metadata filters sit in
the query or index invocation, when someone remembers them, and
`$vectorSearch` does not pass through the collection query. VOYD sits
on the way *in*: a read handle with no unfiltered `find` and no
unfiltered `search`, two enforcement points, the unsafe path named
`including_refused()`. Kubernetes already taught the industry this
word — an admission controller intercepts what would otherwise just
happen. The module is already called `Admission`. The product is that
word, applied to retrieval.

What they wanted anyway is not a memory API. It is one of the wounds
the repo already has numbers for:

- the deleted document that still answers (TTL measured at 60.0s; four
  clocks in `drift/exhibit.py`, score 1.0000)
- the page that came back empty when six live documents were on disk
  (`Page.starved` — silence reads as absence, and a model will describe
  the two hits as what exists)
- the embedding-model swap that inverted ranking (identical text cosine
  −0.053, unrelated +0.301) and that width checks cannot see
  (`EmbeddedWith`)
- a leaked credential that must stop landing in prompts *now*, while
  the row stays for the investigation (`revoke()`, not `DELETE`)

Those are RAG / IR / eval problems. The engineer already owns them.
Refusal is how they become structural instead of conventional. The
auditor's sentence arrives as PCI did: a property of the charge, not
the pitch.

Inherited refusal belongs here without becoming a memory company. RAG
systems write derived chunks, summaries, and extracts whether or not
anyone bought a "memory layer." `derive()` is lineage for retrieval:
forgetting that survives being paraphrased. That is a property of the
verb, not a product category.

**Channel.** The handle, then the namespace. MCP is a way a *model*
calls the same admission path — `mcp.py` is right that runtimes are a
channel — but listing in an agent-memory marketplace is how the
category reasserts itself. A search tool that reports `refused` and
`starved` is honest retrieval, not a memory backend. The TypeScript
client still matters because the second language is the ceiling, not
because the ICP is "people who want Mem0."

**ICP.** Anyone whose retrieval already answers with a confident score
and no idea whether the hit was supposed to be there. Brownfield RAG
counts. So does a platform team. So does an agent, as a *caller*. The
first install is one collection going through `forgettable()`, or one
retriever pointed at `/v1`. Not a rip-and-replace of Pinecone with a
memory product.

**Why this is first.** It does not collapse neatly into a saturated
category: vector databases sell ranking and metadata filters, while
guardrails inspect model output. This is the admission boundary between
them. It matches what the code *is* — a read handle, a rule protocol,
two enforcement points — rather than one trait that happens to make a
good demo. It still pays the engineer (stale hits, starved pages,
inverted ranking, incident revoke) so the three-hop does not require a
CISO. And it refuses the saturated comparison on purpose.

**You would know it worked when** someone describes VOYD as "RLS for
vector search" or "an admission controller for the context window"
without having been told to, and a stranger's `docs.find({})` cannot
return a forgotten fact.

**Stop doing.** Leading with `remember` / `recall` / `pin`. Leading
with GDPR. Letting the README's first analogue be a memory library or
a governance platform. The first analogue is the database verb that
does not exist, and the two-line API contrast that makes the missing
`find` noticeable.

**Trap.** "Admission control" is true and can sound like a paper.
Philosophy loses to `I'll just be careful`; the appendix already said
this. The demo is still API first: show the missing method, show
`starved`, show the exhibit. The *category* is admission. The *wedge*
is a number and two lines of Python. If the landing page says
"Kubernetes for retrieval" you have lost. If it says `await docs.find({})
# cannot return a forgotten fact`, you have not.

---

## 2. The paved road for retrieval

**Be the URI product engineers are allowed to have — not the library they
must remember to wrap.**

The three-hop cost is a function of where enforcement sits. A library
makes the RAG engineer pay 100%. A connection-string change makes them
pay a line. A platform team taking the MongoDB URI away makes them pay
nothing they did not already pay when the company paved the road.

`/v1` and MCP already sit behind the handle. The ceiling in the appendix
says it outright: if you want the guarantee across languages, the
collection is not your API — the namespace is. That is not a code
argument. It is a deployment-topology argument, and it has a buyer who
is paid to make the wrong thing hard.

What they wanted anyway: a golden path. One URI, `health()` with
`degraded` as a first-class state, `including_refused()` as named
break-glass (the JIT-access pattern they already run for prod),
`starved` as a span attribute in the traces they already open. The
platform team does not care about refusal. They care that product
engineers stop each growing a second read path.

What arrives as a side effect: the guarantee, across languages, because
the Go service talks to the namespace rather than to MongoDB.

**Channel.** Platform engineering, SRE, the people who already run
Datadog and a service mesh. Sell in their vocabulary: paved road,
break-glass, error budget. `including_refused()` is not a hole to
apologise for. It is the break-glass they will require before they
take the raw URI away.

**ICP.** A company that has already decided product teams do not get
production database credentials. If they have not decided that, this
direction has no buyer.

**Why this is second.** It is the only direction that *changes the cost*
rather than compensating the engineer or overriding them. That is the
structurally correct answer to the appendix's opening constraint. It
is second, not first, because the buyer is slower and the install is
political — you are asking to become infrastructure — and because a
URI is just another proxy unless the thing behind it is a handle
people already want for a reason that is not compliance. The HTTP
surface is the choke point; admission is what makes pointing at it
feel like a win rather than a gate.

**You would know it worked when** a platform team's paved-road doc says
"retrieval goes through the namespace," and a new service in a second
language gets refusal without importing Python.

**Stop doing.** Selling `forgettable()` as a wrap-your-`find` library
to the person who owns the retriever. That person will add
`deleted: false` this afternoon. Sell to the person who can take
their URI away.

**Trap.** A mandated choke point that is worse than the raw driver gets
bypassed, and the ledger still looks intact. Resentful adopters are
how this product fails *while reporting success*. The namespace has to
be nicer — search, health, saturate, the missing `find` — or it is
OneTrust with a port. Ergonomics remain load-bearing even when the
buyer is platform.

---

## 3. Evidence that a fact stopped reaching a prompt

**Be Vanta for "did it reach a model?" — and the teeth OneTrust never
had.**

Counterfactual products (insurance, backups, seatbelts) are not adopted
out of taste. They are adopted because a deal is blocked, a regulator
asked, or something already caught fire. The honest go-to-market for
"a thing that would have been embarrassing didn't happen" is the
questionnaire, the incident, or the DSAR ticket that turned out not to
be true.

What they wanted anyway: an answer that unblocks a contract. *Show me
this document stopped being reachable at 14:02, and show me the record
has not been edited since.* A hash the subject walks away with, computed
before any dispute existed. `as_of(t)` that reconstructs the scope.
Eventually: *which answers were built on this fact?* — a recall campaign
for generations, which is what IR will actually open a PagerDuty for.

What arrives as a side effect: the handle, because the evidence is a
lie if reads do not go through it. That is the dangerous part, and why
this is third.

`compile_policy()` is the hop-collapser inside this direction. A `Rule`
as a Python object puts the people who get audited on the wrong side of
the release process. A deny clause stored on the scope, compiled into
both halves of the read path or refused at boot, lets compliance edit
data instead of filing a Jira for a deploy. That is also the partnership:
governance platforms describe and attest; they have no read path. Do
not compete with them. Be the runtime their policy compiles into.

**Channel.** The vendor filling an enterprise AI questionnaire. The DSAR
platform that needs tickets to become true. IR, the morning after a
leak — `revoke()` plus a receipt is an incident tool, and during an
incident buyer and beneficiary collapse. Partnership into OneTrust /
Collibra / BigID as enforcement, not as a slide that says they are
wrong.

**ICP.** Anyone who has already lost a deal, or expects to, on "how do
you forget." Not anyone who should have that problem in theory.

**Why this is third.** It is the fastest path to a purchase order and
the fastest path to resentful adopters. A mandated library that is
bypassable is the worst object in this category: legal thinks they
bought the sentence, engineering uses `including_refused()` at 2am or
the raw driver next month, and the chain still verifies. The README
already leads here. That is the mismatch the appendix named. Keep this
as ammunition and as the thing you hand the CISO *after* a handle is
in production — or after an incident — not as page one.

It still belongs in the top three because it is the only direction that
does not depend on anyone currently wanting it. Regulatory drift from
"delete the record" toward "ensure the data is not used" is a reason
for the project to exist on a timeline you do not control. Naming that
as a bet, with its timing acknowledged, is more honest than a
present-tense market claim.

**You would know it worked when** a customer's customer requires the
receipt, and a DSAR ticket closes with a hash instead of a status.

**Stop doing.** Arguing with governance vendors. The complementary
sentence is more persuasive: *your tickets become true faster, and you
get a hash chain instead of a ticket status.* Also stop implying the
chain is a public proof. HMAC is an attestation to whoever trusts the
key holder. The payload already says what it does not prove. That
honesty is the product.

**Trap.** Building a "compliance dashboard." Engineers will not look at
it; compliance will bookmark it and not reopen it. The same artifact
belongs in the traces they already debug (`starved`, `refused` as span
attributes) and in the receipt the subject holds. Dual-use or it does
not ship.

---

## Why this order, in one table

| # | direction | who pays willingly | what they wanted | hop |
|---|---|---|---|---|
| 1 | admission for the prompt | the engineer whose retrieval already lies | a handle that cannot return a forgotten fact; a page that admits it starved | paid — the wound is theirs |
| 2 | paved road | platform / SRE | one URI, break-glass, a health probe that admits degraded | moved — the retriever author never sees MongoDB |
| 3 | the auditor's sentence | whoever's deal or incident is on fire | a hash, a reconstructable scope, a questionnaire answer | overridden — then they hand engineering the library |

1 is the empty category. 3 is the fastest purchase order and produces
the ceiling as the default outcome if it goes first. 2 is the
structural fix and needs 1's object to be worth pointing at.

The current README is 3's first sentence, then 1's handle. That pairing
is the copy change this file asked for. Do not "fix" the rest by writing
1 as a memory product. That is a different crowded room. The remaining
work for 1 is evidence: a retained integration, which
[`PILOT.md`](PILOT.md) is for.

---

## Also real, not ranked with the three

These are on-ramps, wedges, or adjacent companies. Any of them can feed
the top three. None of them should *become* the top three by accident.

**Memory is a trait, not the headline.** `remember` / `recall` / `pin`
is a worked example of admission, and MCP is a way a model calls it.
Use that in a demo. Do not enter the Mem0 comparison set. If an agent
framework lists VOYD, it should be as the store whose search cannot
return a forgotten fact — not as "the memory layer." The moment the
landing page says *agent memory*, the thesis is a footnote and the
eval is recall@k.

**The first rule they adopt should be the one that burned them last
quarter.** `EmbeddedWith` — a model swap inverts ranking (identical text
cosine −0.053, unrelated +0.301) and width checks catch nothing.
`Clearance` / `for_caller` — authZ for embeddings, a category security
engineering is already buying, with the egress re-check that a metadata
filter is not. A context-token budget as a refusal reason — proof the
protocol is a primitive. Erasure is the rule they adopt second, without
noticing. That is how PCI arrived.

**IR and the detector companies need a sink.** Faster deletion destroys
the investigation. Refusal keeps the row as the proof and as the
forensics: unreachable now, on disk until the deadline,
`including_refused()` named, `Authority` so the pipeline may quarantine
at 3am and may not put it back. Lakera / Protect AI / every
prompt-injection classifier detects. Quarantine without a review loop
is a graveyard. Being the primitive they hold into is a partnership
that looks like direction 3 and installs like direction 2.

**Manufacture the flinch.** Step 2 of the sell — believing the window
is a problem — usually requires an incident. `drift/exhibit.py` is a
synthetic one: four clocks, score 1.0000, the deleted document answers,
ten minutes, no production credentials. The AST walker in
`test_no_module_reaches_past_the_handle.py`, turned outward, is Snyk:
"you have fourteen unfiltered reads against collections with
`expire_at`." Read the repo, not prod. The live Pinecone+Postgres
scanner in `ideas.md` is the same family with a worse permission
story. Code scan first.

**Postgres as the ten-line on-ramp.** `drift/refusal_on_postgres.py`
already has the structural version: revoke the table, grant only a
view, the naive read raises `permission denied`. A lot of RAG is
pgvector. A view named `docs_live` is a pattern a DBA already knows.
Honest about the rest: no TTL, so the moment rows must actually go the
deadline has two owners again. That part of the claim really is
stronger on MongoDB. Ship the pattern as a migration, not as advocacy.

---

## What picking does to the next ninety days

If **1**: the copy is done. The README opens on the two-line handle and
the missing `find`, then the exhibit. MCP stays a surface, not the
identity. Smallest adoption is one collection in under ten lines —
shipped as `examples/quickstart.py` and pinned by a test — though it
still constructs `Engine`. The admission overhead is measured and
published (`bench/admission.py`, ~0.5 µs p50 per candidate). What is
left is a retained pilot, not another sentence.

If **2**: finish the authorisation story on the HTTP surface (the
blocker is no longer a missing primitive; it is where claims come from).
`health()` and `starved` become the demo, not `revoke()`. Document
`including_refused()` as break-glass and count it. The TypeScript client
still matters, because the second language is the point.

If **3**: `compile_policy` loading and versioning, the subject-held
receipt as a first-class response, `as_of` reconstructability as a
published number, a one-pager that answers the questionnaire. Do not
rewrite the engine. Do rewrite who the README is speaking to, and
admit you are selling top-down.

The engine does not have to choose yet. The first sentence did: keep
the verb, show the handle. What is left is whether anyone keeps the
handle after two weeks — which is evidence, not copy. Until that
arrives, this remains a beautifully argued library whose actual
competitor is a developer adding `deleted: false` this afternoon.
