# The handle is the demo. The protocol is the product.

**This repository markets a MongoDB object. The thing worth owning is the
interface underneath it, and it is already built, already exercised by a
stranger's rule, and already the reason the guarantee turned out to be
portable.**

This document exists because the most original thing here is the thing least
argued for. [`AHA.md`](AHA.md) derives *where* the check belongs.
[`PORTABILITY.md`](PORTABILITY.md) measures that the decision layer never
learned a database. Neither says the thing both of them imply:

> The per-document check is not an implementation detail of VOYD. It is a
> **protocol for retrieval admission**, VOYD is one implementation of it, and
> a second implementation by somebody else would be a success rather than a
> competitor.

Libraries get copied. Protocols get adopted. The handle is a week of work for
a competent engineer who has read the blog post; the protocol is the part that
took the mistakes.

---

## What is actually being offered

Three required members, and that is the whole obligation:

```python
class Rule(Protocol):
    @property
    def reason(self) -> str: ...                    # its identity

    def refuses(self, doc: dict, *,                 # THE GUARANTEE
                when: datetime | None = None) -> bool: ...

    def clause(self) -> dict | None: ...            # an optimisation, or None
```

Then five optional class attributes, discovered with `getattr` and defaulting
to the behaviour of the original rules. They are deliberately **not** protocol
members: an optional method on a Python `Protocol` becomes *required* to a
static type checker, which would falsely reject an ordinary third-party rule.

| attribute | what declaring it buys |
|---|---|
| `needs_caller` | the rule is handed who is asking, so clearance and restriction are rules rather than a special case |
| `needs_tab` | the rule is **cumulative** — it compares the document against a running total for this read, and is asked only after every pure rule has admitted it |
| `charges` | the rule *spends* that state rather than only reading it, so it is asked last of all |
| `bypassable` | whether `including_refused()` may set this rule aside. False means *not this handle's to waive* |
| `reversible` | present at all means an operator *imposes* this reason with a verb; its value says whether that verb has an inverse |

That last one is worth a sentence, because it is where the protocol stops
being a filter interface and starts carrying policy. `Marked` is one class
doing two operationally opposite jobs: a **revocation** is an instruction
about the world and must not be undoable, a **quarantine** is a hypothesis and
must be, or the feature is a graveyard. That coupling used to live in the
caller of `revoke()`, which meant the next reason somebody added got whichever
half its author happened to remember. Now the reason declares its own
reversibility and the verb reads it — so *"can this be taken back?"* is
answered by looking at the rule instead of by reading the method that writes
it.

---

## The three laws, and each one is a bug somebody hit

### 1. The per-document check is the only authority

`refuses()` decides. `clause()` is an accelerator that must be deletable
without changing a single answer.

- **egress only** — slower, completely safe.
- **clause only** — a *silent hole*: one read path prunes correctly and
  another admits the same document, with no error anywhere.

This is not a portability argument. It is that a vector-search hit never
passes through the collection query at all, so a guarantee living in the query
is a guarantee that one read path does not have.

### 2. `None` is a valid answer, and it is the load-bearing one

A backend that cannot express a rule must be able to **say so** rather than
approximate it. `Budget.clause()` returns `None` unconditionally: a budget is
a running total across a page, not a property of any document, and no filter
in any query language expresses *"refuse once the prompt is full."*

An approximate clause is the silent hole with better manners.

This is the single most valuable line in the protocol and it was not designed
for what it turned out to do — see *The tell*, below.

### 3. Ordering is the engine's job, not the caller's

Rules are asked in three groups: pure, then cumulative-observing, then
cumulative-charging. Within each group the caller's declared order is kept
(the sort is stable), and among pure rules the *first* refusal is reported
rather than merged — an operator needs to know a document was **quarantined**
rather than merely expired, because those demand different responses.

The grouping is not taste. A `Budget` asked before a `Deadline` spends real
room on a document that was going to be refused anyway. A `Budget` asked
before a `Distinct` spends room on a duplicate that never reaches the page —
and then `Page.spent` stops being the sum of what was admitted, which is the
one thing `Tab.charge` promises. Four copies of one passage would report
`over_budget` for content nobody ever saw.

So `charges` is a **class contract**, not a constructor switch and not a
convention about declaration order. A protocol whose correctness depends on
callers declaring rules in the right sequence is a convention, and this
project's entire complaint is about conventions.

### The fourth thing, which is not a law but a promise

`why_refused` **never raises, whatever a rule does.** A rule that throws is
treated as a refusal and named. An exception inside a filter is how the filter
gets skipped, and a third-party rule must not be able to open the gate by
failing.

---

## The part nobody else has: a theory of set-relative rules

Every access-control system in the world answers *"may this subject do this
thing to this object?"* — one document at a time, statelessly. That is what a
policy engine is for, and [`policy-engines.md`](policy-engines.md) shows
against a live Casbin enforcer that a cumulative rule is something it
structurally cannot express.

A retrieval rule is not always about the document. Sometimes it is about the
**page**:

- *this is the fourth copy of a passage already on the page* (`Distinct`)
- *the prompt has no room left* (`Budget`)

Those are refusals in exactly the same sense as a deadline — the document does
not reach the model — and the protocol treats them as the same kind of thing.
Which forced three results that a per-document interface would never have
produced:

**A set-relative rule accumulates *during* admission, never before it.**
`Distinct` originally pre-scanned the candidate page to pick a winner per
cluster. On a page ordered by relevance that reads as obviously right. It ran
before any other rule had refused anything, so it awarded the slot to an
expired copy, `Deadline` then refused that copy, and the live one came back
`redundant` behind a document that never reached the page. Both lost. Empty
result, no error. **Only a document that actually got through may claim
anything.**

**Per-read state is keyed by identity, not value.** Rules are frozen
dataclasses, so `Budget(limit=50)` and `Budget(limit=50)` compare *equal* — a
value-keyed dict silently merges two declarations the caller wrote on purpose,
and one rule's limit governs the other.

**The house default is wrong for set-relative rules.** Almost everything here
fails **closed**: a fact whose status cannot be established has no business in
a prompt. `Distinct` fails **open**, and the asymmetry is the point — it
answers *"is this a duplicate,"* where a missing hash is not evidence that it
is. Failing closed there deletes content over an absent field.

That is a small theory of a kind of rule the access-control literature does
not have a word for, arrived at by hitting all three.

---

## The tell: it produced capabilities nobody designed

This is the evidence that the abstraction is *correct* rather than merely
tidy, and it is the strongest argument in this document because none of it was
planned.

**`clause() -> None` became an adapter boundary.** It exists because a token
budget could not be pushed into a query. It turns out to be the hard part of
any backend interface: a documented, exercised representation of *"this
backend cannot help,"* with every read path already degrading to the pure path
correctly when it is used. A port to another store inherits that for free, and
it was built for a reason having nothing to do with ports.

**A legibility test became a portability test.**
[`tests/test_the_admission_layers_do_not_invert.py`](../tests/test_the_admission_layers_do_not_invert.py)
was written to keep thirteen files readable after a large module was split. The
layer numbers it enforces draw the driver-free boundary exactly, as
[`PORTABILITY.md`](PORTABILITY.md) measures.

**The shipped rules used no private interface.**
[`tests/test_a_third_party_rule_is_a_first_class_reason.py`](../tests/test_a_third_party_rule_is_a_first_class_reason.py)
asserts that a stranger's rule is enforced on both halves, counted in
receipts, indexed by `ensure()`, pushed down correctly when it is
caller-aware, unable to open the gate by raising, able to declare itself
unwaivable — and that VOYD's *own* access rules reach for nothing a stranger
cannot. That last assertion is what makes this a protocol rather than a plugin
hook.

An abstraction that hands you a capability you were not designing for is the
signal. This one did it three times.

---

## The play

**Extract the conformance suite.** The third-party rule tests are already a
de-facto conformance suite for one half. Turned into a package an implementer
can run against *their* rules and *their* store, it becomes the thing that
makes a spec real: not "here is an interface we like," but "here is the
executable definition of conformance, and your implementation either passes or
does not."

That suite is the asset. It encodes the bugs above — the pre-scan, the
identity keying, the fail direction, the ordering groups — which is knowledge
an implementer cannot get from reading an interface, only from hitting all
four.

**Publish the protocol separately from the implementation.** The same split
[`scanner/`](../scanner/README.md) just got, and for the same reason: a
specification that ships inside one vendor's library reads as that vendor's
API. `voyd-rules` — three members, five attributes, the conformance suite, no
driver, no `voyd` — would be implementable against pgvector, Qdrant, Redis,
Elastic, or a list literal.

**Then the honest sequencing.** A protocol with one implementation and no
users is a naming ceremony. The order is: publish the finding, get a pilot,
*then* propose the protocol — with a second implementation in hand if at all
possible, because a spec's credibility comes entirely from having been
implemented twice by different people.

---

## What is deliberately not in it

- **Not an authorization system.** A rule is handed the caller's claims and
  cannot verify them. Who the caller *is* belongs to whatever already answers
  that, and pretending otherwise would be the overreach this codebase spends
  its docstrings avoiding.
- **Not a query language.** `clause()` returns whatever the backend's filter
  is. The protocol has no opinion about its shape, which is exactly why it
  ports.
- **Not a ranking system.** Admission is downstream of relevance and never
  argues with it. It only ever removes.
- **No `allow`, only `deny`.** An `allow` would have to mean "and refuse
  everything else," which no single rule can promise while other rules exist.

---

## What would falsify this document

- A stranger implements a rule and needs something not in the three members
  and five attributes. That is the protocol being under-specified, and the
  gap is the news.
- The protocol turns out to need a sixth attribute for every new kind of rule,
  which would make it a grab-bag rather than an abstraction.
- Nobody implements it on a second store, in which case this was an
  interface, not a protocol, and saying so is the correct outcome.

**Further:** [`AHA.md`](AHA.md) for why the check belongs on egress,
[`policy-engines.md`](policy-engines.md) for the rule a policy engine cannot
express, [`PORTABILITY.md`](PORTABILITY.md) for what survives a change of
database, and [`opportunities.md`](opportunities.md) for where this ranks
against everything else worth doing.
