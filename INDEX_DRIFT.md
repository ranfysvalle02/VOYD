# Index drift: measuring the half of the premise we assume

**Proposal.** Ship a probe that measures, on a customer's own cluster,
**how long a deleted document keeps coming back from their vector index.**
It needs no policy file, no rules, no VOYD vocabulary, and — in its first
form — no access to a single customer document. The output is one number
nobody currently has, and the remedy for a bad number is this project.

This is the second of two proposals. [SHADOW_MODE.md](SHADOW_MODE.md)
measures *collection versus rules*: how many documents your read path
serves that your database already marked as gone. This measures
***index* versus collection**: how many documents your retriever still
ranks that the collection no longer has. It is the harder number to argue
with and the easier thing to install.

---

## The aha: our own opening paragraph is half measured

`README.md` opens with this:

> MongoDB's TTL monitor runs about once a minute (measured here: 60.0s)
> [...] and **in that window the index keeps returning the deleted
> document** as a normal, well-scored result.

The first clause is measured — twenty trials, `p50=60.0s`. The second
clause is **inferred**, and it is inferred from the wrong number.

The TTL interval tells you when the *row* goes. What a retriever serves
is decided by the *index*, and an Atlas Search index is maintained
asynchronously: `mongot` follows the change stream and applies at its own
pace. So the real exposure is not the TTL interval. It is

```
time-to-invisible  =  sweeper lag  +  index lag
```

and **nobody measures the second term.** Even where a platform exposes
search replication metrics, essentially nobody operating a RAG pipeline
correlates them with what the retriever actually returned. The
distribution is unmeasured, and the distribution is the whole question:
the median is probably fine and the tail is the incident.

This repository has been walking into that second term for weeks without
naming it. The Atlas test polls `_ranked()` for up to 180 seconds waiting
for `mongot` to catch up with two documents. `LIMITS.md` records that a
search index which is missing or still building *returns zero rows rather
than raising*, which is indistinguishable from "nothing matched". And the
sharpest instance: an Atlas test kept failing because the TTL monitor
**reaped a row mid-index-build** — the reaper winning a race against the
test written to complain about the reaper. Every one of those is index
drift, met by accident, three times, and never measured on purpose.

**So the opportunity is to measure the premise.** Not to market it — to
find out whether it is true at production scale, on somebody else's
cluster, with a number.

## The two numbers

**Time-to-visible.** Insert a document; poll the index until a search
finds it. This is ingest lag, and it is the number a team feels as *"why
isn't the new doc showing up"*. Useful, and not the point.

**Time-to-invisible.** Delete a document; poll the index until a search
stops finding it. **This is the number.** It is the literal answer to
*"if an erasure request landed right now, how long would my retriever keep
serving that fact?"* — asked of their cluster, under their write load,
continuously.

No team has this number. There is no dashboard for it, no eval metric that
covers it, and no error when it is bad.

## Two instruments, and the first one touches no customer data

### 1. The canary — measures the window, sees nothing

A dedicated collection with a small vector index, created by
`voyd-wire --ensure`. The agent writes its own synthetic document, polls
until the index finds it, deletes it, polls until the index stops. Two
timings per cycle, on a loop.

**We never see a customer document, because the only document involved is
ours.** That is a privacy story with nothing to negotiate, and it makes
the install a conversation about write access to one throwaway collection
rather than read access to production.

The honest limitation, stated before anybody finds it: a canary measures
*the canary's* lag. A cold collection with one tiny document may sync
faster than a hot collection taking a thousand writes a second. The
canary gives you a floor and a trend, not the exposure on the busiest
collection. Anybody who tells you otherwise is selling.

### 2. The audit — measures real exposure, needs read access

Sample the index: run a batch of searches, collect the returned `_id`s,
and look those ids up in the collection. Every hit falls into one of four
buckets:

| bucket | what it means | argument available to a skeptic |
|---|---|---|
| **phantom** | the index ranked a document the collection does not have | **none** |
| **forgotten** | present, but past its deadline or marked | "we do not consider that a problem" |
| **stale** | present, but its text changed after the index saw it | "our content rarely changes" |
| current | fine | — |

The **phantom** bucket is why this proposal exists. It is not a policy
disagreement, a definition, or an opinion about what *forgotten* means. It
is a referential integrity violation between two systems the customer
already pays for: the retriever returned a document that does not exist.
There is no version of "well, we would have filtered that" — there was
nothing to filter.

And it requires **no rules declared at all**. Shadow mode needs a team to
agree on what forgotten means before it can count anything. This needs
`_id`s and a `$in`.

## The market this opens, which is much larger

Shadow mode sells to teams that have erasure requests, deadlines, or
tenants — a real audience and a narrow one. Drift sells to **everybody
doing retrieval**, because two of the four buckets are not privacy
problems at all:

- **phantom** is a correctness problem. The retriever cited a source that
  is gone. Whatever the model said next was grounded in nothing.
- **stale** is worse and affects everyone. An embedding is a lossy copy of
  text at a moment. If the text changed and the index did not, the
  retriever is ranking by a vector that describes content which no longer
  exists — and it will do so confidently, forever, with a good score. No
  erasure request required. No compliance framing needed. Just a wrong
  answer nobody can trace.

That reframes the pitch from *"are you leaking?"* — which invites denial —
to **"how stale is your retrieval?"**, which every RAG team will answer
honestly because they genuinely do not know.

## The category observation

Three kinds of tool exist and none of them measures this.

- **RAG evaluation** (Ragas, TruLens, and the rest) measures answer
  quality against ground truth. It assumes the index faithfully mirrors
  the corpus, and measures what happens downstream of that assumption.
- **Data observability** (the warehouse-monitoring category) measures
  freshness and quality of *tables*. It does not look at vector indexes.
- **Database monitoring** measures replication, oplog, and index build
  state as *operational* metrics, disconnected from what any retrieval
  returned.

The gap between them is exactly this: **nobody measures whether the index
believes in a corpus that exists.** Every eval framework in the category
takes it as given. It is not given, it has never been measured in
production, and it is measurable in about fifty lines.

That is the aha, and it is testable rather than rhetorical: if the number
is always zero, the observation is worthless and this document should be
deleted.

## Why it sells this project rather than merely flattering it

The measurement is not a lead magnet bolted onto a product. It is the
argument.

A bad time-to-invisible has exactly two remedies. Make the sweeper and the
index faster — which is somebody else's roadmap, unbounded, and still
asynchronous when they are done. Or **stop asking the index to be
authoritative**, and take the verdict on the way out, where it is
immediate and does not depend on any sweeper. That second sentence is
`voyd-wire`, and a customer arrives at it themselves, from their own
number, which is worth more than any README.

It also composes with the boundary rather than duplicating it. `voyd-wire`
already refuses a ranked hit that is expired or marked — that closes
**forgotten**. A phantom is a document the boundary never sees, because
there is nothing on disk to judge, so the honest statement is that the
boundary shrinks the exposure from *"served"* to *"absent from the page"*
and drift is how you know by how much.

## What it does not mean

- **A canary measures a canary.** Floor and trend, not the hot path.
- **Phantom counts depend on write patterns.** A read-mostly corpus with
  monthly updates may genuinely be zero. That is a real answer and it
  should be reported as one, not spun.
- **Stale is the hardest bucket to measure honestly.** Comparing a
  document's `updatedAt` against "when the index saw it" needs a
  timestamp the index does not expose per document. The defensible
  version is the reverse probe: take documents updated recently, search
  for their *new* content, and count the ones the index cannot find. That
  measures lag positively rather than inferring it.
- **Sampling is sampling.** The audit finds the rate, not the incident.
  A single phantom that happened to be somebody's revoked credential is
  not discoverable by sampling, and claiming otherwise would be the
  confident-and-wrong failure this whole repository is about.
- **We would be collecting drift rates across customers.** That is
  competitive intelligence about other people's infrastructure. The same
  care `LIMITS.md` applies to keeping a refusal breakdown off the network
  applies here: aggregate by default, per-collection opt-in, and say so
  out loud.

## The kill criterion

**If time-to-invisible is consistently under one second across the first
five pilots, and phantom counts are zero, stop — and say so publicly.**

That result would mean Atlas Search keeps up well enough that the second
term in the exposure is noise, and the honest consequence is larger than
abandoning this proposal: it would narrow this project's opening claim
from *"the index keeps returning the deleted document"* to *"the row
survives the sweeper"*, which is a smaller and less interesting problem.
The README would have to change.

Writing that down is the point. A measurement that cannot embarrass the
person who commissioned it is marketing.

## What it costs

The probe is small: a write, a poll loop, a delete, a poll loop. The audit
is a batch of searches and one `$in`. `voyd-wire --ensure` already creates
the index a canary needs, and the suite already contains the polling
pattern — `_ranked()` in the Atlas test is most of it, written for a
different reason.

The work is not the code. It is the two sections above: refusing to
overstate what a canary proves, and having the discipline to publish a
zero.

## How the two proposals relate

Run drift first. It installs more easily, argues less, and reaches a
wider audience — and its **phantom** bucket is the one number a skeptic
cannot talk their way out of. Shadow mode is the natural follow-on:
once a team accepts that their index is not a faithful mirror, *"which of
these should not have been reachable at all"* is the next question they
ask, and they will already have declared half a policy file answering it.

Drift finds out whether the premise is true.
Shadow mode finds out whether they care.
The boundary is what they buy if both answers are yes.
