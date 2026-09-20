# Opportunities, ranked

**Six things worth doing, in the order that spends the least to learn the
most. Ranked by how much each one moves the only number that is currently
zero: people who are not the author and have kept it.**

This is not the build backlog. [`ideas.md`](ideas.md) is what is worth
*building* next and is ranked by value per line of code.
[`ISSUES.md`](ISSUES.md) is what is *wrong*. This is what is worth *doing*,
which is mostly not code — and the distinction matters because the last time
those three were one pile, the pile grew to eighteen documents and the
zero stayed zero.

Every entry names the cheapest next action and what would falsify it, because
an opportunity with neither is a wish.

---

## 1. Publish the Qdrant finding as its own thing

**The claim.** *A whole class of vector databases can express this guarantee
only politely.* Postgres can make the unfiltered read raise `permission
denied` — revoke the table, grant only a view. Qdrant on the stock image
cannot: no row, no view, no `GRANT`, no collection-level default filter, so
the payload filter is a convention that holds until the next caller omits it.
[`drift/refusal_on_qdrant.py`](../drift/refusal_on_qdrant.py) does not assert
this; it issues the unfiltered query a second time and watches the expired
point come back with a confident score.

**Why first.** It is the only asset here that is *about the category rather
than about this library*, so it reaches people who would never click a repo
link. It is already written, already executable, and already verified against
the real service. It costs nothing to give away and it cannot be dismissed as
a pitch, because the script exits non-zero if a future Qdrant closes the gap —
an argument that fails when it stops being true.

**Cheapest next action.** One post: the enforcement ladder
(conventional → structural → engine-enforced → cryptographic), the two
measured results, the scripts. The library link goes at the bottom or not at
all.

**What would falsify it.** Qdrant ships a collection-level default filter, or
someone demonstrates the structural version on the stock image. Both would be
good outcomes and the exhibit would say so by failing.

**Tone risk, named because it is the way this goes wrong.** It is a claim
about somebody else's product. Keep it *measured, here is the script*, never
*Qdrant is broken*. Qdrant is a good vector database and the exhibit says so.

---

## 2. Spec the protocol, not the library

**The claim.** The handle is a week of work for a competent engineer who has
read the post. The protocol underneath it — three members, five optional
attributes, and a theory of set-relative rules — is the part that took the
mistakes. Libraries get copied; protocols get adopted.

**Why second and not first.** A protocol with one implementation and no users
is a naming ceremony. This ranks high because it is the only path to being the
standard rather than one implementation, and low-ish because it is worth
nothing until items 1 and 5 have produced somebody who wants it.

**Cheapest next action.** Extract the third-party rule tests into a
conformance suite an implementer can run against *their* rules and *their*
store. The suite is the asset, not the interface: it encodes the four bugs
that produced the design — the pre-scan that lost live documents, state keyed
by value instead of identity, the fail direction for set-relative rules, the
ordering groups — which an implementer cannot get from reading a `Protocol`.

**What would falsify it.** A stranger implements a rule and needs something
the protocol does not have; or nobody implements it on a second store, in
which case it was an interface and not a protocol.

**Full argument:** [`gold.md`](gold.md).

---

## 3. The scanner can outgrow the parent

**The claim.** *"Count your own leaks"* is a broader product than *"adopt my
handle."* [`scanner/`](../scanner/README.md) is already a separate
distribution with zero dependencies and no import of `voyd`, and it is the
only artifact here that costs a stranger nothing and returns a number about
their own code.

**Why third.** It is the top of every funnel and it feeds the parent forever,
but it is a diagnostic rather than a cure, and a diagnostic with no cure
attached converts nobody. It ranks here because it is cheap and compounding,
not because it is the point.

**Cheapest next action.** A GitHub Action, so the number appears in a pull
request rather than on somebody's laptop once. Then breadth: the ORMs and
query builders the header already admits it cannot see, which is where the
false negatives live.

**What would falsify it.** People run it, get a non-zero number, and do
nothing — which would mean the bug is real and nobody's problem, and that is
worth knowing early rather than after a year of building the cure.

**The standing risk.** Its credibility is the whole product. A single loud
false positive costs more than ten missed leaks, which is why the scanner
reports *indeterminate* rather than inventing a number, and why a path that
does not exist is an error rather than a clean bill of health.

---

## 4. Agent memory, not RAG

**The claim.** Agents write facts back, derive facts from facts, and hold
credentials with real lifetimes. That is precisely the shape the lineage and
inherited-refusal machinery was built for — forget a source and the summary
written out of it goes too — and no agent framework has it. The market is
plausibly larger than RAG retrieval and is certainly less crowded.

**Why fourth.** It is the most promising *reframing* available and the least
evidenced. Everything needed for it already exists here, which is either a
sign it is the right target or a sign of wishful pattern-matching, and there
is currently no way to tell.

**Cheapest next action.** One example that is unmistakably an agent problem
rather than a retrieval problem: an agent granted a credential with a deadline
that writes three derived notes, and the deadline reaching every one of them
without the agent's author having written any cleanup.
[`examples/agent.py`](../examples/agent.py) and
[`examples/worker.py`](../examples/worker.py) are most of that already.

**What would falsify it.** Agent authors read it and say *"our framework's
memory is a list of strings in a process that dies in an hour"* — which is
true today far more often than the pitch assumes, and would mean the pain is
real but not yet felt.

---

## 5. An employer is a distribution channel almost nobody has

**The claim.** A credible, non-embarrassing AI-governance story for a vector
database is a rare thing, and solutions architects talk every week to teams
doing retrieval with deletion and erasure obligations. One of them running
[`bench/pilot.py`](../bench/pilot.py) against a customer's shape is worth more
than any launch post.

**Why fifth on this list and first on the calendar.** It is ranked below the
publishable items because the *idea* does not need it, and it is the thing to
do first anyway, because it is the only entry here that can produce the one
number that is zero. Nothing else on this page moves *kept after two weeks*.

**Cheapest next action.** One internal conversation, carrying the scanner
rather than the library: *"run this against a customer repo and tell me the
number."*

**Why it can be done without it reading as advocacy.**
[`drift/`](../drift/README.md) exists. The thesis is ported to pgvector with no
MongoDB in the file, and the one-owner claim is stated as *genuinely stronger
on MongoDB and a property of the engine, not of the argument*. That is the
difference between an argument and a pitch, and it was written before anyone
needed it to be.

**What would falsify it.** The conversations happen and nobody's customer has
the pain — a real result, and the cheapest possible way to learn it.

---

## 6. Context receipts, reverse-indexed

**The claim.** *"Which answers were built on this fact?"* is the question with
compliance budget behind it. Receipts exist, recompute without a secret, and
compose with `as_of`, so *"was this context legitimate at the time it was
built?"* is answerable in two calls. What is missing is the reverse index:
today you can only check a receipt you already hold.

**Why last.** It is the most valuable *feature* on this page and the one that
least changes whether anyone adopts the thing. It is also the only item that
helps at all with a consequence refusal cannot reach — a Slack message
quoting the fact, a fine-tune, a vendor's prompt cache with its own TTL and no
purge API — by turning archaeology into a query.

**Cheapest next action.** Store receipts keyed by admitted id. The cost is a
retention decision worth making deliberately: a receipt names ids rather than
document text, but it is a record of *who saw what*, and that has its own
sensitivity and its own deadline. A governance feature that quietly becomes a
surveillance log is the failure mode.

**What would falsify it.** Buyers ask for the *report* rather than the query —
in which case this is a document-generation problem wearing an index's
clothes, and building the index first would be solving the wrong half.

---

## The one thing this page cannot do

Five of the six above are things that can be done alone at a desk, and that is
exactly why they are a trap. The number that decides this project is **kept
after two weeks**, [`PILOT.md`](../PILOT.md) is built to answer it, and
`bench/pilot.py` deliberately leaves that line blank when it fills in every
other line of the report, because a proof of the mechanism is not evidence of
demand.

Item 5 is the only entry that can fill it in. Do that one first.
