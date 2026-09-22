# Shadow mode, as a product

**Proposal.** Ship the measurement before the boundary. A team installs
something that changes nothing about what their retrieval returns and
counts how many documents it served that their own database had already
marked as gone. They get a number nobody currently has. We get the first
defect found by somebody who is not the author.

Nothing in this document requires a credential of ours, a document of
theirs to cross our network, or a proxy in anybody's data path.

---

## Why: two problems, and they are the same problem

**Theirs.** No team knows this number. Not because they are careless —
because nothing reports it. A retrieval that serves an expired row does
not error, does not log, and does not move a counter; on a relevance
workload it reads as *better recall*. The failure is invisible in the one
direction that looks like success, which is the whole premise of this
repository. So the honest position of any prospective user is not "we are
fine" or "we are exposed" — it is **"we have no idea"**, and there is no
cheap way to find out.

**Ours.** `LIMITS.md` §1 says it more bluntly than a README would: this
suite is good at holding claims somebody thought to state, and *it has
never once been the thing that caught a problem a user hit, because there
have been no users.* Every defect in this project's history was found by
its author poking his own work — a dozen of them in a single day recently.
That is a good day and a bad sign, and no amount of further testing fixes
it. The ceiling on this project is not code quality. It is that nobody has
run it.

Shadow mode is the only artefact here that addresses both at once, because
it is the one thing a stranger can run against production without asking
anybody's permission.

## The instrument already exists

`examples/shadow.py` is the whole integration, and the part that matters
is three lines:

```python
served    = await db.notes.find(q).to_list(None)   # unchanged. still yours.
reachable = notes.reachable(served)                # the read you might have
metrics.gauge("voyd.would_have_refused", len(served) - len(reachable))
```

No rollback story, because nothing rolled forward. No risk review, because
no user-visible behaviour moved. The rules are declared once, in the same
vocabulary a `voydfile.py` uses, so **the artefact that proves the problem
is the artefact that fixes it** — when the number convinces somebody, the
same spec becomes a policy file and the connection string does the rest.

Two properties make the measurement trustworthy rather than indicative:

- **It is exact, and exact for an unusual reason.** `receipts()` normally
  under-reports, because the same rule runs inside the collection query and
  MongoDB drops most forgotten documents server-side. Shadow mode inverts
  that: the documents are fetched by *your* unfiltered read and handed to
  `reachable()` one at a time, which is the same egress check a
  `$vectorSearch` hit arrives at. Nothing is dropped early, so nothing goes
  uncounted. The measurement is exact *because* the read is still the leaky
  one.
- **The interesting output is not a total, it is a variance.** Run it per
  read path. A team with six read paths and one remembered filter does not
  learn "we are 4% exposed" — they learn *which call site*. This project's
  own history is the case study: six read paths, five of them remembered.

## What the product is

Deliberately small, and small in a specific direction: **we receive
integers and reason names, never documents.**

1. **An agent.** A thin wrapper around the three lines, for Python first.
   It declares the rules, wraps an existing read, and emits counts. It
   never sends document text, and it does not need to send ids.
2. **An ingest endpoint and a dashboard.** The number over time, split by
   collection, by read path, and by *reason* — `deadline` climbing is one
   conversation and `revoked` climbing is a different one.
3. **One alert.** *"Last week your retrieval served N documents your
   database had already marked as gone."* That sentence is the product.
4. **A policy export.** The rules they declared to measure, emitted as a
   validated `voydfile.py`, with the sidecar manifest to run it. This is
   the only place the funnel lives, and it should be one button.

That is it. No hosted proxy, no credential custody, no data path.

**The control plane dogfoods the boundary.** Accounts, connection
metadata, anything we store goes behind `voyd-wire` with a policy file of
our own, and secrets use `sealed()` scoped to the account:

```python
@guard("accounts")
class Accounts:
    account_id = tenant()
    secret     = sealed()
```

`declare.py` refuses `sealed()` without `tenant()`, for exactly the reason
that matters here: one key per collection makes erasure all-or-nothing, so
honouring one account's deletion would make every other account's secrets
unreadable. Scoped to the account, "delete your account and your
credentials become unreadable everywhere, including in our backups" is a
sentence backed by `examples/shred.py` rather than by a policy page.

## Why this product and not the hosted proxy

| | credential custody | in the data path | attacks the zero-users problem |
|---|---|---|---|
| **Shadow mode** | none | none | **directly** |
| Control plane / policy editor | none | none | indirectly |
| Hosted proxy | every customer's database | every document | no |

The hosted proxy is a real category and a different company. It would take
on other people's production credentials and put every document they
retrieve through our infrastructure, which breaks the two structural claims
this project currently gets to make: *the boundary holds no credentials of
its own*, and *the sidecar is the supported shape, because nothing else on
the network can reach it and there is no route around it*. Those are worth
more than the revenue is, until there are users. Shadow mode is how there
are users.

## What the number does not mean

A measurement sold as evidence has to be honest about its edges, or the
first sharp customer discredits the rest.

- **It can only see what your data already records.** A team that
  hard-deletes rows has nothing for `revoked()` to find — the row is gone
  from the collection. Their exposure is real and it is somewhere else:
  in the *index*, for the 60 seconds before the TTL monitor runs, or in a
  vector index that has not caught up. Shadow mode as written does not
  measure that, and saying so up front is cheaper than being caught.
- **A low number on one read path is not a low number.** It may mean that
  path already has the filter. That is a correct result and a misleading
  headline.
- **Install only reasons that mean "forgotten".** A `Deadline` and a
  revocation both mean the fact is gone, so the delta has one meaning. Add
  a `Budget` and it starts meaning "forgotten, *or* further down the page
  than the token ceiling reached" — two facts under one number, which is
  how a trial produces a figure nobody can act on. `lineage_field` is not
  that kind of addition and is worth switching on from day one: it is not a
  new reason, it is what makes the existing one *travel* to what was made
  of the fact, and the derived-document case is usually where the
  interesting half of the number is.
- **Even counts are not nothing.** `LIMITS.md` argues that a refusal
  breakdown by reason describes what a corpus holds and who has been
  probing its doors. We would be collecting exactly that, across
  customers. It deserves the same care the metrics endpoint gets: default
  to aggregate, make per-reason opt-in, and say so.

## The kill criterion

Written down first, because a pilot that cannot fail is a demo.

**If the median exposure across the first five pilots is zero, stop.** Not
"iterate on positioning" — stop. It would mean the window this project was
built to close is not one that teams actually fall into, and the honest
response is the one `README.md` already gives in *When you do not need
this*: a TTL index plus a clause in the query is a smaller thing that
closes the same window, and plenty of systems have one read path nobody
else will touch.

A single non-zero result from somebody who is not the author is worth more
than everything in `CLAIMS.md`, because it is the first evidence that has
not been generated by the person being convinced.

## What it costs

The measurement is done. What is new is an agent, an ingest endpoint, a
chart, and an account. Small — and the risk is not in the building, it is
in the two places above: the honest edges, and the discipline to stop.

## What it does for the project

- **It converts the biggest weakness into the product.** The thing this
  repository cannot do for itself — be used — becomes the thing it sells.
- **It leaves every claim intact.** No new credentials, no data path, no
  new LIMITS section. The hosted proxy would need one titled *what hosting
  costs*, in the same voice as §5 on `--key-vault`. This needs none.
- **It makes the funnel the same artefact as the evidence.** The rules
  that produced the number become the policy file that enforces it. There
  is no second implementation to keep in step, which is the failure this
  whole project is named after.
- **And it answers the one question nobody here can answer.** Is the
  60-second window a problem people feel? Everything in this repository is
  rigorous except that, and this is the cheapest way to find out.
