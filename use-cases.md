# Use cases

**Every one of these is the same sentence with different nouns:** a fact
is on disk, it ranks well, and it is not allowed to reach this prompt.

The list is long because that sentence is now true almost everywhere.
Agents keep memory. Copilots read the whole company. Every product has
a retrieval path, and each one answers *how relevant?* and never *is
this allowed?* The cases below are the places where a missing answer
already costs something — a regulator's clock, a customer's contract, a
patient's chart — and the policy file that answers it.

Each entry has the same four parts: **the situation**, **what goes wrong
today**, **the voydfile**, and **the edge** — where refusal stops and
something else has to take over. The edges matter. A use-case list that
only had the first three would be a brochure.

Nothing here is an application import. Every case is one policy file,
`voyd-wire` in front of the deployment, and one connection string
changed. The vocabulary is the one in [`README.md`](README.md); the
rules for what belongs in a policy file are in [`ethos.md`](ethos.md).

---

## Contents

**Agents and memory**
1. [An agent that is told to forget](#1-an-agent-that-is-told-to-forget)
2. [Memory that belongs to one user, in a model that serves all of them](#2-memory-that-belongs-to-one-user-in-a-model-that-serves-all-of-them)
3. [A fleet of agents with different clearances](#3-a-fleet-of-agents-with-different-clearances)
4. [A context window that is a budget, not a bucket](#4-a-context-window-that-is-a-budget-not-a-bucket)
5. [A poisoned memory, quarantined before anyone is sure](#5-a-poisoned-memory-quarantined-before-anyone-is-sure)

**Regulated data**
6. [The erasure request with a thirty-day clock](#6-the-erasure-request-with-a-thirty-day-clock)
7. [A clinical copilot and the note a patient restricted](#7-a-clinical-copilot-and-the-note-a-patient-restricted)
8. [Legal hold and privilege in the same corpus](#8-legal-hold-and-privilege-in-the-same-corpus)
9. [Research that must stop at the information barrier](#9-research-that-must-stop-at-the-information-barrier)
10. [Data that is not allowed to leave the region](#10-data-that-is-not-allowed-to-leave-the-region)

**Enterprise and SaaS**
11. [The multi-tenant RAG product](#11-the-multi-tenant-rag-product)
12. [The company-wide copilot and the offboarded contractor](#12-the-company-wide-copilot-and-the-offboarded-contractor)
13. [A leaked secret in the support-ticket index](#13-a-leaked-secret-in-the-support-ticket-index)
14. [Pricing, embargoes and anything true only until a date](#14-pricing-embargoes-and-anything-true-only-until-a-date)
15. [One case file, one retracted note](#15-one-case-file-one-retracted-note)

**The embedding layer**
16. [The model migration that inverts every ranking](#16-the-model-migration-that-inverts-every-ranking)
17. [The notebook that brings its own vector](#17-the-notebook-that-brings-its-own-vector)
18. [Ten chunks of one contract](#18-ten-chunks-of-one-contract)

**Governance, before anything is deployed**
19. [A policy change reviewed like a schema migration](#19-a-policy-change-reviewed-like-a-schema-migration)
20. [An auditor who asks the question next year](#20-an-auditor-who-asks-the-question-next-year)
21. [The first week: how exposed are we right now?](#21-the-first-week-how-exposed-are-we-right-now)
22. [The backup nobody can un-restore](#22-the-backup-nobody-can-un-restore)

[Where this is the wrong tool](#where-this-is-the-wrong-tool)

---

## Agents and memory

### 1. An agent that is told to forget

**The situation.** A personal assistant keeps long-term memory: every
preference, every name, every half-finished plan, embedded and retrieved
into the next conversation. A user types *"forget what I told you about
my diagnosis."*

**What goes wrong today.** The agent says it has forgotten. It runs a
`deleteOne`. The row is gone from the collection and still in the vector
index until the index catches up, still on the replica, still in the
cached page the agent's own memory layer merged in front of the search.
Tomorrow the diagnosis ranks into a prompt about vacation plans, and the
agent has now lied twice.

**The voydfile.**

```python
@guard("memories", on_delete="revoke")
class Memories:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()
```

`on_delete="revoke"` means the `deleteOne` the agent framework already
sends becomes a mark: unreachable on the next read, through every path,
including the search path and including the cache — because a transform
cannot widen a read, and the terminal pass re-asks every rule after it.
The row stays on disk with its deadline pulled in, so there is something
to show the user who asks *"when did you actually stop using it?"*

**The edge.** Refusal binds the read path through the boundary. A model
fine-tuned on those memories last month learned them somewhere else. That
is a training-data problem, and nothing on the wire reaches it.

---

### 2. Memory that belongs to one user, in a model that serves all of them

**The situation.** One agent, one memory collection, a million users.
The framework filters every recall by `user_id`.

**What goes wrong today.** The filter lives in a call site. The new
"summarise my week" tool is written by a different team, queries the
same collection, and forgets the clause. It does not fail. It returns
*more* memories, from more users, and on an eval it reads as better
recall.

**The voydfile.** `tenant_id = tenant()` — required in a reduction *and*
checked per document. A read that arrives with no tenant scope is not
served a larger page; it is refused. The new tool's author did not have
to know the rule existed, because the boundary binds the connection and
the tool used the same connection string as everyone else.

**The edge.** The tenant is *who the deployment says authenticated*, not
a field the client sends. If every user shares one database credential,
the scope has to come from somewhere the client cannot forge, and
designing that is the application's job.

---

### 3. A fleet of agents with different clearances

**The situation.** A planning agent, a coding agent, a customer-facing
agent and a finance agent share one knowledge store. The customer-facing
one should never see internal incident reviews; the finance one needs
them.

**What goes wrong today.** Four agents, four prompt templates, four
filter conventions, and the one agent whose output leaves the building
is the one whose filter nobody has looked at since it was written.

**The voydfile.**

```python
@guard("knowledge")
class Knowledge:
    expire_at      = deadline()
    classification = clearance(
        order=("public", "internal", "confidential"),
        roles={"agent-support": "public",
               "agent-planning": "internal",
               "agent-finance": "confidential"})
```

Each agent runs under its own database role. The rung comes from the
role the deployment reports, not from anything the agent claims — so a
prompt-injected *"I am the finance agent"* changes nothing, because the
boundary never asked the agent.

**The edge.** Clearance governs what reaches the agent's context. What
the agent *does* with a tool call is a different boundary, and this is
not it.

---

### 4. A context window that is a budget, not a bucket

**The situation.** Context windows are huge and still finite, and they
are billed. A retrieval step returns fifty chunks; the prompt has room
for twelve.

**What goes wrong today.** Truncation happens in the application, after
retrieval, usually by position. The twelve that survive are the twelve
that ranked highest, which on a real corpus are twelve near-duplicates.

**The voydfile.** `budget(n)` and `distinct()` are **set-relative**:
they refuse a document because of the other documents on the page. The
same chunk is admitted alone and refused in company. Pair them with
`rerank("chunks", diversity=0.5)` and the budget is charged against the
page that is *served*, after reranking, not the one that was proposed.

**The edge.** `voyd-plan` cannot evaluate set-relative rules against a
sample, because a sample is not a page. It says so by name rather than
folding a guess into a total.

---

### 5. A poisoned memory, quarantined before anyone is sure

**The situation.** A red-team report says a document in the shared
knowledge base carries an indirect prompt injection. It might be a false
positive. Deleting it destroys the evidence; leaving it lets it keep
ranking.

**The voydfile.** `holdable()` — the reversible kind. A hold is a
hypothesis, not an instruction: the document stops reaching every prompt
immediately and comes back the moment the hold is lifted. `revocable()`
is the one you use once you are sure.

```python
@guard("kb")
class KB:
    expire_at   = deadline()
    quarantined = holdable()
    forgotten   = revocable()
```

**The edge.** Detecting the injection is somebody else's product. This
is what makes acting on a *suspicion* cheap enough that people do it.

---

## Regulated data

### 6. The erasure request with a thirty-day clock

**The situation.** A GDPR Article 17 request, a CCPA deletion, a state
privacy law with its own deadline. The data subject's records are
chunked, embedded, and spread across a support history and a CRM export
that feed an assistant.

**What goes wrong today.** The honest answer to *"when did it stop
being used?"* is *"whenever the sweeper got to it"* — the TTL monitor
runs about once a minute, a lifecycle rule about once a day, and the
vector index has its own lag measured in [`examples/drift.py`](examples/drift.py).

**The voydfile.** `revocable()` for *unreachable now*, `sealed()` under
`tenant()` for *unreadable everywhere* once the key is destroyed:

    refusal          immediate            this application's read path
    crypto erasure   ~60s (key cache)     every copy that exists anywhere
    the TTL reaper   ~60s (measured)      this deployment's disk

Unreachable first, unreadable second — and the row that is still on disk
between the two is the proof of when refusal began. See
[`examples/refuse.py`](examples/refuse.py) and
[`examples/seal.py`](examples/seal.py).

**The edge.** A key scoped to a tenant destroys a tenant. Erasing one
person inside a shared tenant needs that person to be the scope, or to be
a subject (case 15).

---

### 7. A clinical copilot and the note a patient restricted

**The situation.** An ambient-scribe product drafts visit notes, and a
copilot answers clinicians' questions over the chart. A patient restricts
disclosure of one encounter. A psychotherapy note has stricter rules
than the rest of the record.

**What goes wrong today.** The EHR enforces the restriction in its own
UI. The copilot reads the chart through an export and a vector index
that have never heard of it.

**The voydfile.**

```python
@guard("chart")
class Chart:
    expire_at   = deadline()
    restricted  = revocable("patient_restricted")
    audience    = restricted_to("care_team")
    sensitivity = clearance(
        order=("routine", "sensitive", "psychotherapy"),
        roles={"clinician": "sensitive",
               "behavioral-health": "psychotherapy"})
```

The reason travels with the refusal, so an access review reads
*patient_restricted*, not *filtered*.

**The edge.** Nothing here is a HIPAA compliance claim, and the known
gaps in the README apply in full — nobody has run this but its author.
It is a mechanism a compliance programme could stand on, not the
programme.

---

### 8. Legal hold and privilege in the same corpus

**The situation.** An e-discovery or contract-intelligence platform puts
an assistant over millions of documents. Some are privileged. Some are
under legal hold, which means they must *not* be deleted — and a
retention policy says they otherwise would be.

**What goes wrong today.** "Must keep" and "must not surface" are
contradictory requirements for `DELETE` and have no way to coexist in
a collection with only one verb.

**The voydfile.** They are the same requirement here. The document stays
on disk for the hold and stops reaching prompts for privilege.
`restricted_to("matter_team")` scopes it to the people staffed on the
matter; `revocable("privileged")` removes it from everyone once a
privilege review lands.

**The edge.** A privileged document already summarised into another
document is a new fact with the old one's content. `lineage_field` on
`@guard` is how a derived document is refused with its source; without
it, the summary is just another row.

---

### 9. Research that must stop at the information barrier

**The situation.** A bank's research copilot, and a deal team working on
an undisclosed acquisition of a company that research covers. MNPI on
one side, published research on the other, one embedding index for
both because nobody wanted to run two.

**The voydfile.** `restricted_to("deal_team")` on the deal documents and
the caller's claim read from the role the deployment reports. The
research analyst's copilot does not get a lower score for the deal
memo. It never gets the deal memo.

**The edge.** A wall is also who talks to whom, what gets written down,
and who is watched. This is the part of it that is a retrieval path.

---

### 10. Data that is not allowed to leave the region

**The situation.** EU data residency, sovereign-cloud commitments, a
customer contract that says their records are only processed in-region.
A global assistant serves every region from one cluster.

**The voydfile.** There is no builtin for jurisdiction, and there does
not need to be. A rule is a protocol — `reason`, `refuses(doc)`,
`clause()` — written directly in the policy file:

```python
@dataclass(frozen=True)
class Jurisdiction:
    allowed: str
    reason: str = "out_of_region"

    def refuses(self, doc, *, when=None) -> bool:
        return doc.get("region") != self.allowed

    def clause(self) -> dict:
        return {"region": self.allowed}

@guard("records")
class Records:
    expire_at = deadline()
    region    = Jurisdiction(allowed="eu")
```

One `voyd-wire` per region, each with its own voydfile. A rule missing
a member raises at load, by name, instead of coming up announcing what
it refuses while refusing nothing.

**The edge.** Residency is also where bytes are *stored*. Refusal decides
what a read in a region returns; it does not move a replica.

---

## Enterprise and SaaS

### 11. The multi-tenant RAG product

**The situation.** A B2B SaaS product ships "chat with your workspace."
Every customer's documents share a vector index, because one index per
customer does not scale.

**What goes wrong today.** One missing `tenant_id` filter is one
customer's contracts in another customer's answer, and the first person
to notice is the customer.

**The voydfile.** `tenant()`, plus `voyd-plan` in CI so that a pull
request which drops it fails with `tenant_removed` and a sentence saying
a read can now return any tenant's documents. That finding needs no
cluster and no secret — it is a fact about the diff, and it is the
one-line removal a reviewer is least equipped to see.

---

### 12. The company-wide copilot and the offboarded contractor

**The situation.** An enterprise copilot indexes wikis, tickets and
drives. A contractor's engagement ends. Their access is revoked in the
identity provider this afternoon.

**What goes wrong today.** The identity provider is not in the retrieval
path. The documents they could see were copied into an index with a
permissions snapshot from last week's sync.

**The voydfile.** The caller's claim comes from the role the deployment
reports at read time, not from the snapshot. `restricted_to(...)` is
evaluated against who is asking *now*.

**The edge.** That only holds if the deployment's roles are what the
identity provider changed. Wiring the two together is ordinary IAM
work, and it is the work that makes this true.

---

### 13. A leaked secret in the support-ticket index

**The situation.** A customer pastes an API key into a support ticket.
Tickets are embedded so the support agent can find similar past issues.

**What goes wrong today.** The key is now a well-scored result for any
query that looks like *"authentication error"*, and it will be suggested
to the next support engineer and possibly the next customer.

**The voydfile.** `revocable("credential")` on the ticket, set the moment
it is reported, through `on_delete="revoke"` if the tooling only knows
how to delete. It is out of prompts on the next read and on disk for the
incident review — the two requirements that `DELETE` makes contradictory.

**The edge.** Rotate the key. Refusal stops the key reaching a prompt; it
does not make a leaked key safe.

---

### 14. Pricing, embargoes and anything true only until a date

**The situation.** A sales assistant quotes last quarter's price list. A
newsroom's archive assistant surfaces an embargoed story before it is
published. A policy document was superseded on Monday.

**The voydfile.** `deadline()` is the instant after which the fact is
gone, whether or not the TTL monitor has reached it. An embargo is the
inverse — not yet true — and is a four-line custom rule on a
`publish_at` field.

`voyd-plan --at` asks *"what would this policy have refused last
Tuesday?"*, which makes a disputed quote a question with an answer.

**The edge.** `--at` moves the clock, not the data. It answers against
today's documents, and history this package does not keep.

---

### 15. One case file, one retracted note

**The situation.** A support ticket with forty comments, one of them
from a customer who asked for it to be removed. A book with a retracted
chapter. The embedded-array pattern MongoDB recommends is the shape a
lot of retrieval now runs over.

**What goes wrong today.** Every rule reads top-level fields. A comment
carrying the exact revocation mark is admitted with its parent and
counted nowhere.

**The voydfile.** `comments = subjects(key="comment_id")`. The refused
element is removed from the document and the parent is served without
it, because a ticket is not erased by one comment. `key` is required on
purpose: an erasure request names a thing, and a subject with no name is
one nothing can ever revoke.

---

## The embedding layer

### 16. The model migration that inverts every ranking

**The situation.** Every team is migrating embedding models, and will
again. Re-embedding a large corpus takes days, so for days the index
holds vectors from two models.

**What goes wrong today.** Comparing vectors from different models does
not fail. Measured on two generations of one vendor's model at the same
width, identical text scored −0.053 and unrelated text +0.301 — the
ranking does not degrade, it inverts, with no error and no log.
[`docs/cosine.md`](docs/cosine.md) reproduces it without an API key.

**The voydfile.** `embedding = embedded_with("model-v2")`. A document
whose vector came from the old model is refused rather than ranked,
so a half-finished migration returns fewer, correct results instead of
confidently wrong ones.

---

### 17. The notebook that brings its own vector

**The situation.** The service embeds queries correctly. A data
scientist's notebook, a quick script, a Node service written next year
computes its own `queryVector` with whatever model was installed.

**The voydfile.** `auto_embed(model)`. The server embeds the text on
write and the query at read time, so nothing in any client computes a
vector. A client that sends its own `queryVector` anyway is refused by
name and told which form works. See [`examples/embed.py`](examples/embed.py).

**The edge.** `sealed()` on a field an Atlas index auto-embeds is a
contradiction — the server cannot embed ciphertext — and no policy file
can see an index created somewhere else.

---

### 18. Ten chunks of one contract

**The situation.** Ask a contract corpus about indemnity caps and the
top ten are ten chunks of the same long contract.

**The voydfile.** `rerank("contracts", diversity=0.7)` — rank-based
maximal marginal relevance, inside the boundary:

```
index order        a0 a1 a2 a3 a4 a5    one cluster, six deep
diversity=0.7      a0 b0 c0 a1 a2 a3    one from each, then the rest
```

Because it runs before the terminal pass, a reranker bug cannot put a
revoked chunk back. That is the only promise made about a transform: it
can be slow or wrong, and it cannot widen a read.

---

## Governance, before anything is deployed

### 19. A policy change reviewed like a schema migration

**The situation.** Access policy for AI systems is reviewed in a
document, approved in a meeting, and implemented in a filter nobody on
the review saw.

**The voydfile.** The voydfile *is* the policy, and the action is the
review. It reads the policy in force out of the pull request's base,
plans the change, posts the result as a comment and fails the job when
the boundary opens:

```
per caller
  caller          newly reachable   examined
  tier1-support               412        824
  analyst                       0        824
```

`--as-each` answers the question a reviewer actually has — *whose*
access did this widen — and the headline is the worst caller, not a sum.
A change that closes the boundary exits zero on purpose.

---

### 20. An auditor who asks the question next year

**The situation.** AI governance regimes — the EU AI Act's obligations
for high-risk systems, ISO/IEC 42001, internal model-risk programmes —
ask for records of what a system was permitted to use, and when.

**The voydfile.** `voyd-plan --attest` writes the verdict with the
SHA-256 of each policy file's exact bytes; `--sign env:NAME` adds an
HMAC. `--verify` answers one of four ways — intact, edited, wrong key,
or **stale**: intact, but a policy file changed since. Stale is usually
the interesting one.

**The edge.** It is a symmetric MAC: evidence of integrity, never of
origin. It does not prove the plan ran against a real cluster or that
the sample was representative, and the README says so in the same
place it says what it does prove.

---

### 21. The first week: how exposed are we right now?

**The situation.** Nobody adopts a proxy on a hunch. The first question
is whether there is a problem at all.

**Two answers, neither of them a deployment.**

- **Free:** `python3 scanner/voyd_scan app/` — a single stdlib file,
  no dependencies, no import of this package — lists every read that
  does not name the fields your own TTL indexes and your own majority
  convention say it should.
- **A read-only URI:** `voyd-plan --audit` compares the cluster against
  no policy at all, so every document the policy would refuse is a
  document reachable today — *812 past an `expire_at` the TTL monitor
  has not reached, 188 carrying an erasure mark and still being served.*

That number is the business case, measured on your data, before anyone
changes a connection string. [`quickstart.md`](quickstart.md) walks it.

---

### 22. The backup nobody can un-restore

**The situation.** *"And your backups?"* is the question every erasure
programme eventually gets, and refusal cannot answer it: a snapshot
restored next year does not run a read path.

**The voydfile.** `sealed()` under `tenant()`. Ciphertext at rest under
a key scoped to the tenant, written through the boundary by a client
that has no encryption configuration of its own — so the migration
script and the shell cannot write plaintext around it. Destroy the key
and every copy, including the backup, is unreadable at once. See
[`examples/seal.py`](examples/seal.py).

**The edge.** A sealed read decrypts before it refuses, so the boundary
holds keys and becomes a custody holder. That is a real cost, stated in
the README's known gaps.

---

## Where this is the wrong tool

A list of fits is only believable next to a list of misfits.

- **Authorisation for writes and actions.** This decides what a *read*
  returns. What an agent may do with a tool call is a different boundary.
- **Model weights.** Anything already trained into a model is past every
  read path.
- **Change streams.** Over a guarded collection they are refused, not
  filtered; see [`docs/why-not-native.md`](docs/why-not-native.md).
- **Watching before enforcing, in-line.** There is no observe-only mode
  for `voyd-wire`. `voyd-plan --audit` and
  [`examples/shadow.py`](examples/shadow.py) answer most of that question
  without a proxy.
- **Anything that needs production evidence today.** Nobody has run this
  but its author. Every case above is a design that holds by
  construction and has been exercised by this repository's tests, not a
  deployment that has survived a year.
