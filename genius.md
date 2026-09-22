# The unfair advantage

*One property. Two motions no competitor can run. Everything else here
is a consequence.*

---

## The sentence

> **VOYD is the only retrieval boundary that can tell you what it would
> have refused before you install it — and the only one where your
> reranker runs inside it instead of after it.**

Both halves come from the same fact, and it is not a feature. It is a
constraint that the placement forced and that turned out to be an asset:

**The enforcement check is a pure function.** A document, a policy, a
clock. No database beneath it, no connection, no state. Documents in,
the admissible ones out.

Every wire-proxy competitor — Cyral, Satori, any sidecar — has
enforcement that exists *only inside their running process*. That single
difference is what the rest of this document is about, and it is not
something any of them can retrofit in a quarter.

---

## Motion one: it audits before it installs

Every competitor's assessment requires their proxy to already be
running. Their check is a process, so getting a report means getting a
deployment first — which means platform review, security review, a
staging environment, and a change to somebody's connection string, all
before anyone has seen a single number.

VOYD's check is a function. So it runs as an offline analyser with
nothing in the data path at all:

```bash
voyd-plan --audit --proposed voydfile.py --target $READONLY_URI --all
```

```
reachable today, and refused by this policy

  records  1000 of 4100 read are reachable now and would be refused
         812  are past an expire_at the TTL monitor has not reached
         188  carry an erasure mark and are still being served

collections with no boundary in front of them today
  records

1000 documents, out of every document looked at, are reachable through
this cluster's retrieval path and would be refused by the policy in records
```

A read-only credential and one command. No sidecar, no manifest, no
staging environment, no connection string changed, nothing in anybody's
query path.

|  | passive-mode proxy | `voyd-plan --audit` |
|---|---|---|
| infrastructure change | a sidecar in the data path | none |
| who must approve | platform + security + probably SRE | whoever holds a read-only credential |
| time to first artifact | a deploy | one command |
| risk if it is buggy | it is in your query path | it is a batch job |

**The inversion: you do not sell a proxy and hope they find value. You
hand over the finding and sell the fix.** The install stops being the
thing you are asking for and becomes the remediation they ask you for.

And the number is not a projection. It is the same arithmetic the
boundary would run, on their documents, because it is literally the same
function.

---

## Motion two: the reranker is not a trojan horse

"Engineers adopt for the magic, security mandates for the promise" is a
familiar play, and it normally requires two features and a hope that one
install serves both. A competitor copies that in a quarter, because it
is a packaging decision.

Here it is not packaging. It is a structural necessity.

A team installs this because their top ten results are six chunks of the
same contract:

```python
rerank("notes", diversity=0.3)
```

To run that reranker in the egress path **at all** requires the terminal
admission pass, because that is the only thing that makes executing
arbitrary page-shaping code inside a data boundary defensible:

```
pure rules  →  your transform  →  every rule, terminally  →  the wire
```

> **A transform cannot widen what a read returns.** Not because it was
> reviewed. Because the boundary is downstream of it.

**You cannot take the magic without the boundary, because the boundary
is what makes the magic offerable.** An engineer installs a reranker; a
security team inherits a non-bypassable read boundary for every
notebook, agent and MCP server pointed at that cluster. Neither has to
lose for the other to win.

The proof is adversarial and it runs in CI: a policy file whose
transform exists for no reason other than to inject expired and revoked
documents, a real `voyd-wire` subprocess, and a `pymongo` client that
has never heard of this package. The transform is not disabled, not
sandboxed, not reviewed. It runs. It returns the documents. They do not
arrive.

This also inverts security's standing objection to a programmable proxy
— *"unvetted code modifying data in flight"* — into the reason to want
one. Your unvetted code is in the safest place it has ever run, because
for the first time it is inside the thing that would have caught it.

---

## Motion three: sell evidence before enforcement

```bash
voyd-plan --proposed voydfile.py --as-each roles.json \
          --attest plan.json --sign env:VOYD_ATTEST_KEY
```

Two artifacts a compliance buyer wants and cannot currently get from
anyone.

**Whose access changed, not whether it changed.**

```
per caller
  caller          newly reachable   examined
  tier1-support               412        824
  analyst                       0        824
  clinician                     0        824
```

The headline is the *worst* caller, not the sum: one document reachable
by four roles is one document that got out, not four.

**A verdict that survives the branch being deleted.** A signed envelope
holding the result, the SHA-256 of each policy file's contents, and when
it ran. `--verify` reports four outcomes, not a boolean:

| | |
|---|---|
| **intact** | unchanged since it was produced |
| **edited** | payload no longer matches its digest — caught with no key |
| **wrong key or altered** | the digest was recomputed; the signature was not |
| **stale** | intact, but a policy file changed since — a different finding, usually the more interesting one |

Ask any team today to prove an access-control change did not widen
access. The honest answer is a person's recollection. This is a batch
job with no runtime component, sold to a buyer who will never have an
opinion about wire protocols.

---

## Why a competitor cannot copy this

Not "would find it hard." Cannot, without rebuilding their enforcement
engine.

If your check lives inside a query — a `$match` clause, a rewritten
`WHERE`, a row-level-security predicate — there is nowhere to stand to
ask it about a policy that is not deployed. The only place the question
can be asked is a running production cluster with the policy already on
it, which is precisely the situation the audit motion exists to avoid.

And if your check needs a connection, it cannot run twice per page
cheaply, so it cannot run *after* somebody else's reranker, so page
shaping stays outside the boundary where it has always been and where it
can always undo you.

One property. Both motions. Neither retrofittable.

| the property | what it unlocks |
|---|---|
| the check is a pure function | audit with no install |
| …so it can be asked about an undeployed policy | `voyd-plan` as a PR gate |
| …so it is cheap enough to run twice | transforms inside the boundary |
| …so it needs no cluster to evaluate | an attestation that is a batch job |

---

## Three corrections before any of this goes in a deck

Stated here so they are not discovered in front of a technical buyer.

**This is the MongoDB wire protocol.** Not "MongoDB, Postgres, or vector
database traffic." Postgres is a different protocol and a substantially
different implementation, not a configuration flag. The first engineer
who asks will end the meeting. The MongoDB-shaped claim is strong enough
on its own — and the audit motion needs only a read-only URI, which is
the easiest thing in the world to ask for.

**There is no passive/observe mode, today.** No `--observe` on
`voyd-wire`. This was checked rather than assumed. It is the one small
feature that would complete the story — a boundary that logs *"would
have refused 4,100"* without refusing, making the install itself
reversible and boring — and it is the highest-value unbuilt thing on
this list. The audit gets you most of the way without it, because a
batch job is an even smaller ask than a reversible install.

**Multi-tenancy is a correctness pitch, not a cost pitch.** Pre-filtering
does degrade ANN recall — true — but the mechanism here is a
*post*-filter. Drop the tenant pushdown and a tenant asking for top-10
gets whatever survives egress, sometimes two. Keep the pushdown for
recall; the claim is that *your index filter becomes an optimisation
instead of your only line of defence.*

---

## The honest headline

**Nobody has run this but its author.** Five days old, one machine, one
cluster, zero production traffic. Every number in this document comes
from this repository's own test suite and benchmarks.

Which is exactly why motion one is the one to run first. It is the only
ask small enough that being five days old does not disqualify it: a
read-only credential, a batch job, and a finding they did not have
before. Nobody has to trust an unproven proxy with their traffic to find
out whether the thing it detects is real on *their* cluster.

Get the finding in front of one person who did not write this. That is
the whole plan.

---

*The design argument: [`docs/ranking-is-not-permission.md`](docs/ranking-is-not-permission.md).
The story, including the bug that hid inside an infrastructure flake:
[`blog.md`](blog.md). The best single fact, with its provenance and its
limits: [`docs/cosine.md`](docs/cosine.md).*
