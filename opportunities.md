# Opportunities

Where this goes, what it is worth, and what is wrong with each answer.

Every number below is an estimate with its basis stated. None comes from
a market study, and a figure without a stated basis is not in this file.

---

## The pitch

**Ranking is not permission.** A vector index scores relevance; nothing
in an ordinary retrieval path is ever asked whether a fact is *allowed*
to reach a prompt. So the answer gets reimplemented at every call site,
and the failure is silent in the worst direction — a missing
authorisation filter returns *more* documents, never raises, and on a
retrieval workload reads as better recall.

Deletion does not close it: a TTL monitor runs about once a minute, and
in that window the document is legitimately on disk and is returned as a
well-scored hit. **Deletion is a storage event. Refusal is a retrieval
promise.**

VOYD is the second one, on the wire. One policy file, one changed
connection string, no application code. Because the boundary binds the
*connection*, no driver, notebook, agent or language routes around it.

Three things that are hard to copy:

1. **Set-relative rules.** `budget(n)` and `distinct()` refuse a document
   because of the *other* documents on the page. No index filter can
   express that — `$vectorSearch` decides each candidate before the page
   exists — and `enforce(subject, object, action)` has nowhere to put the
   rest of the set.
2. **`voyd-plan`.** The per-document check is pure, so it can be asked
   about a policy that is not deployed. A change that widens the boundary
   fails a pull request and says which documents and why. Enforcement
   that lives inside the query has nowhere to stand to ask this.
3. **The guarantee is the egress check, not the pushdown.** A
   `$vectorSearch` hit never passes through the collection query, so every
   pushed-down clause is an optimisation. Implementations that have this
   backwards have a hole.

---

## 1. Data-leak CI — *build this first*

**Pitch.** Prove an access-control change did not widen access, in the
pull request, as a retained artifact. `voyd-plan` reports which documents
become reachable and fails the build if any do.

| | |
|---|---|
| **Audience** | Platform and SecOps teams carrying SOC 2 / HIPAA / GDPR evidence for a RAG system |
| **Size** | Small today, growing fast. Basis: every team with a compliance obligation *and* a vector index — the intersection is narrow now and is the fastest-growing half of both sets |
| **Readiness** | Shipped. Planner, role matrix, signed attestations, exit codes, GitHub Action, PR comments, 274 tests |

**Why.** It is the only opportunity here with **no adoption friction**.
Every other one requires a stranger to put an unproven proxy in the data
path of a production cluster. This one is a `uses:` line: no cluster, no
credentials, no secret, no proxy. The structural findings — a `@guard`
deleted, a `tenant()` dropped — need only the two policy files, and they
are exactly what a human reviewer cannot see in a diff.

It also sells something nobody currently supplies. Ask any team to prove
a policy change did not widen access and the honest answer is a person's
recollection.

**Why not.** A CI check is a feature, not a company. It is a wedge into
the boundary, and it has to be sold as one.

**Shipped since this was written.** `--as-each` plans the change once per
named caller and reports the role table, headlined by the worst caller
rather than the sum. `--attest` writes a verifiable envelope — the
result, the SHA-256 of each policy file's contents, the timestamp —
and `--sign env:NAME` adds an HMAC over it. `--verify` distinguishes
*intact*, *edited*, *wrong key*, and *stale*, that last one being an
intact attestation of a policy since changed.

**Still missing.** A reference deployment. See the last section.

---

## 2. Agent firewall for MCP and autonomous retrieval

**Pitch.** Shadow AI happens because anyone can point a local MCP server,
an open-source agent or a notebook straight at production. VOYD enforces
a non-bypassable read boundary without any agent team rewriting anything.

| | |
|---|---|
| **Audience** | CISOs and platform teams at organisations where agent deployment outpaces review |
| **Size** | The largest of the five, and the least defined. Basis: the population is "organisations running agents against production data", which is most of them and almost none of them under governance yet |
| **Readiness** | Works today for MongoDB-backed retrieval |

**Why.** "We do not need the agent team to cooperate" is the strongest
sentence available here. Wire placement means the notebook is covered,
the Friday MCP server is covered, and next year's framework is covered.

**Why not — read this before pitching it.** VOYD binds *the MongoDB
connection*. An MCP server against Postgres, an internal API or object
storage is untouched. Pitched as a general "agent firewall", the first
question about a non-MongoDB tool ends the meeting.

**Mitigation.** Scope the claim: the non-bypassable boundary for **agent
retrieval over MongoDB**, today, with no change to agent code. Then treat
a JSON-RPC gateway — same thesis, same pure rule engine, no wire protocol
to reimplement — as a *second product* rather than a bullet in this one.

**Second constraint.** The boundary forwards the handshake and asks the
deployment who authenticated, so per-agent policy needs per-agent
database users. That is the correct design and it is a rollout question;
have the answer ready.

---

## 3. Semantic anti-exfiltration

**Pitch.** Rate limits stop volume, not intent. Fifty semantically
adjacent queries reconstruct a confidential document without crossing any
threshold. Set-relative refusal is the only mechanism shaped to catch it.

| | |
|---|---|
| **Audience** | Security teams at organisations whose retrieval corpus *is* the asset |
| **Size** | Narrow and high-value. Basis: fewer buyers than (2), each with a larger budget and a named threat model |
| **Readiness** | New subsystem. Not an extension |

**Why.** This is the durable moat. Set-relative refusal has no equivalent
in an index filter or a policy engine, and exfiltration-by-adjacency is a
threat with no current answer.

**Why not.** Today's set-relative state is scoped to **one read** —
`Budgets.tab_for(guard, cursor_id)` dies with the cursor, and the proxy
forks workers into separate address spaces. Cross-session, time-windowed
detection needs shared state and retained query embeddings. That makes
the check **stateful**, which is precisely the property that makes
`voyd-plan` possible.

**Mitigation.** Build it as an explicitly separate tier — a ledger that
is loudly *not* the pure path, with the boundary drawn in the module
graph the way `voyd/engine/` and `voyd/wire/` already are. Sequence it
third, deliberately, so the dividend is not lost by accident.

---

## 4. Multi-tenant isolation on a shared index

**Pitch as usually written.** Host one dense global index, get hard
tenant isolation, drop the per-tenant partitioning cost.

**This is backwards and will not survive a technical reader.**
Pre-filtering degrades ANN recall — true. But VOYD's mechanism is a
*post*-filter. Drop the tenant pushdown and a tenant asking for top-10
receives whatever survives the egress check: sometimes two. The README
says as much; pushdown is an optimisation, egress is the guarantee.

**The correct pitch is correctness, not cost.** Keep the pushdown for
recall. VOYD guarantees that when it is missing, wrong, or bypassed by a
`$vectorSearch` path that never touched the collection query, the row
still does not leave.

> Your index filter becomes an optimisation instead of your only line of
> defence.

| | |
|---|---|
| **Audience** | SaaS vendors with one vector index across enterprise customers |
| **Size** | Moderate, well-defined, and reachable — these teams know they have this problem |
| **Readiness** | Works today. `tenant()` is enforced in the reduction *and* per document |

---

## 5. Federated clean rooms and k-anonymity

**Pitch.** Query a shared vector space across organisations without
leaking entities: refuse a page unless it meets a diversity threshold.

| | |
|---|---|
| **Audience** | Healthcare, banking and supply-chain consortia |
| **Size** | Few buyers, very large contracts |
| **Readiness** | Architecturally natural, commercially premature |

**Why.** k-anonymity *is* a set-relative predicate — the same shape
`distinct()` already has. The engine wants to do this.

**Why not.** Eighteen-month sales cycles, cross-organisational trust, and
a boundary nobody outside this repository has run. Shelve until (1) or
(2) has produced a reference deployment.

---

## The blocker, which is not on this list

Every opportunity above is gated by the same fact: **nobody has run this
but its author.** The design is finished; the outside evidence is not.

That is why the sequence is (1), then (2), then (3) — not in order of
size, but in order of how little a stranger has to risk to say yes.

| | Idea | Friction to first outside user |
|---|---|---|
| 1 | Data-leak CI | A `uses:` line. No cluster, no secret |
| 4 | Multi-tenant correctness | A proxy in a staging path |
| 2 | Agent firewall | A proxy in a production path |
| 3 | Anti-exfiltration | A proxy, plus a new stateful tier |
| 5 | Clean rooms | All of the above, plus a consortium |
