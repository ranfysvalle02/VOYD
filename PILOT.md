# Pilot: find out whether you have this problem, then fix it

This is the smallest honest trial of VOYD, sized for a Python team already on
MongoDB. It is structured so that **you produce evidence before you install
anything**, and so that a result of "we do not have this problem" is a
first-class outcome rather than a failure.

The idea it rests on is one sentence, derived in [`AHA.md`](docs/AHA.md): the
per-document check on the way *out* is the guarantee, so refusal binds a
handle, not a collection. Everything below follows from that.

## The shape, and why it is this shape

An earlier version of this page opened with `git clone` and `uv sync`, then
asked for a ten-line integration, and only at the end asked whether anything
had been worth it. That order is backwards for this particular argument.

VOYD's whole claim is **you already have this problem and cannot see it**. A
pilot that starts by asking you to install something has requested trust
before it has offered evidence — and the evidence is unusually cheap here,
because it can be computed from code you already have and measured in
production without changing a single user-visible behaviour.

So the order is inverted. Four gates, each of which can end the pilot:

| gate | you do | you get | it costs |
|---|---|---|---|
| **0 — your number** | run a scanner on your repo | the line where your own convention already failed | one command, no install |
| **1 — shadow** | count, change nothing | how many facts your retrieval served that were already gone | 3 lines, no risk |
| **2 — one read path** | switch a single retrieval | the integration cost, measured, not estimated | <10 lines, ~30 min |
| **3 — decide** | against a criterion written *before* gate 0 | a yes or a no, either of them useful | two weeks |

Gate 1 is the pilot. Gates 0 and 2 are how you get to it honestly.

---

## Write this down before you start

Fill this in now, before any command below. A pilot that cannot fail is
marketing.

> **We will not adopt this if:** shadow mode finds fewer than ____
> would-have-refused documents over ____ weeks, *or* if the p99 admission
> overhead exceeds ____ on our data, *or* if the integration touches more
> than ____ application lines.

A reasonable first threshold for the first blank is **zero**. If two weeks of
your real traffic never once served a fact your own database had already
marked as gone, you do not have this problem, and nothing on this page should
talk you into it.

---

## Gate 0 — your number, before you install anything

No clone, no credentials, no database. One stdlib file you may also just copy
into your own tree:

```bash
python scanner/voyd_scan path/to/your/repo
```

It does not look for field names it already knows. For each collection it
counts what your reads actually filter on, and a field most of them name and
some do not is a convention with a deviation:

```
orders: `valid_until` (your convention: 9 of 11 reads name it)

  app/api/export.py:31  orders  (filter does not name `valid_until`, which 9 of 11 reads here do)
```

That is not "you might have a problem." It is *you already decided what the
rule is, and here is the line where it is not being followed* — this project's
founding incident, computed from your repository, on whatever you happen to
call the mark.

**Record the number and the date.** You will run this again at gate 3, and the
delta is part of the report.

**If it reports that it recognised no read at all, stop and fix that first.**
That is the likeliest outcome for a team with a repository class or an ORM,
and it means the gate is unmeasured rather than clean. `--read-verb` teaches
it your wrapper's method names, and the inference works identically through
one — it never cared what the method was called, only what the filters agree
on. Gate 1 does not have this blind spot, because it runs against real
objects rather than source.

**A zero here is informative, not disqualifying.** The scanner reads source
with `ast`, so ORM layers and dynamically named collections are invisible, and
it is honest about being a floor. It also cannot see the rules that have no
query half at all — a token budget refuses a document because of the *other*
documents on the page, so there is no filter in anybody's source to look for.
Gate 1 measures what gate 0 cannot see. See
[`scanner/README.md`](scanner/README.md).

---

## Gate 1 — shadow mode. This is the pilot.

**Change nothing.** Your existing read path keeps serving exactly what it
served yesterday. Alongside it, count how many of those documents should not
have been reachable:

```python
served = await db.notes.find(q).to_list(None)   # unchanged. still yours.
shadow = len(served) - len(notes.reachable(served))
metrics.gauge("voyd.would_have_refused", shadow)
```

`reachable()` is a pure classifier — no round trip, about 1µs per document —
so this is genuinely three lines. There is no rollback story because nothing
rolled forward, and no risk review because no user-visible behaviour moved.

Runnable, and asserted by
[`tests/test_shadow_mode_measures_without_changing_behaviour.py`](tests/test_shadow_mode_measures_without_changing_behaviour.py)
rather than described:

```bash
docker compose up -d mongo
uv run python examples/shadow.py
```

### The setup, in full

```python
from voyd import Engine
from voyd.engine import Deadline, revoked

engine = Engine(client, db)                    # your existing client + db
await engine.connect()
notes = engine.model("notes").admitting(
    Deadline(), revoked(), lineage_field="lineage")
await engine.ensure(search_wait_s=0)
```

**Install only reasons that mean "forgotten" while you measure.** A deadline
and a revocation mark both mean the fact is gone, so the delta has one meaning
and you can act on it. Add a `Budget` and the number starts meaning "forgotten,
*or* merely further down the page than the token ceiling reached" — two facts
under one number, which is how a trial produces a figure nobody can use.

`lineage_field` is not that kind of addition and is worth switching on from
day one. It is not a new reason; it is what makes the existing one *travel* to
what was made of the fact. Leaving it off does not make the measurement
cleaner, it makes it smaller — and derived documents are usually where the
interesting half of the number is.

### Why this count is exact, and the other one is not

`receipts()["refused_at_boundary"]` under-reports on purpose: the same rule
runs inside the collection query, so MongoDB drops most forgotten documents
server-side and the handle never sees them. Shadow mode inverts that. The
documents are fetched by *your* unfiltered read and handed to `reachable()`
one at a time — the same egress boundary a `$vectorSearch` hit arrives at — so
nothing is dropped early and nothing goes uncounted.

The measurement is exact precisely because the read feeding it is still the
leaky one. That is the only time in this system you get an exact number for
this, and it is available exactly once: during the shadow trial, before you
adopt anything.

### The metric that decides it

Not admission overhead. **Time-to-unreachable**: how long a fact stays
retrievable after someone asks for it to be gone.

Today that is bounded below by your TTL monitor — MongoDB's runs "about once a
minute", measured here at 60.0s by `bench/measure.py` — plus index lag. On the
`$vectorSearch` path it is not bounded at all, because the hit never passes
through the collection query that would have dropped it. With the handle it is
"next read", and `revoke()` is counted rather than merely true.

Instrument both ends of one real erasure request during the trial: timestamp
when it lands, and poll whether the fact is still retrievable. One chart, two
lines, no prose. Overhead belongs in the appendix — it is an answer to an
objection, not a reason to adopt.

### Pick the collection by blast radius

Not by convenience. Choose the one where **facts get copied**: summarised,
embedded into a second store, or written into agent memory. A hand-written
`deleted=true` filter handles the simple case perfectly well; what it
structurally cannot do is follow the fact into the summary something wrote
from it. That is the ground where this is differentiated, and
[`examples/lineage.py`](examples/lineage.py) is the five-second version of it.

If your candidate collection has no derived documents and one read path, be
honest that a filter may be enough for you. Say so in the report; it is a
finding.

---

## Gate 2 — one read path, measured

Only if gate 1 produced a number you care about.

The substantive change is the fenced block in
[`examples/quickstart.py`](examples/quickstart.py) — under ten lines, pinned by
a test so it cannot quietly grow:

```python
docs = engine.model("notes").forgettable()
```

Then two edits:

1. **Reads.** Replace the one retrieval that feeds the model —
   `db.notes.find(...)` — with `docs.find(...)`. Same filter, same documents;
   it simply cannot return a forgotten one. If you retrieve by vector, use
   `docs.search(vector, text=..., filters=...)` and let the handle own the
   fetch budget (it refills rather than returning a short page).
2. **Forgetting.** Wherever you delete-for-compliance today, add
   `await docs.revoke({"_id": x}, reason="...")`. It makes the fact
   unreachable on the next read and leaves the row on disk as proof; erasure
   stays on the deadline it already had.

Multi-tenant is one argument — `model("notes", tenant="tenant_id")` — after
which the tenant field is required in every read (`find({"tenant_id": t})`),
so a forgotten `{}` raises rather than crossing the boundary.

### The canary

Seed one document you can watch, and prove both halves in your own data:

```python
from datetime import timedelta
from voyd.engine.time import now

cid = (await engine.db.notes.insert_one(
    {"text": "CANARY", "expire_at": now() - timedelta(minutes=5)})).inserted_id

assert await docs.find_one({"_id": cid}) is None                 # handle refuses
assert await engine.db.notes.find_one({"_id": cid}) is not None  # raw still serves
```

The raw read serving what the handle refuses is not a bug — it is the gap the
handle exists to close, made visible.

### Keep it honest with the raw-read guard

The guarantee binds the handle, so the real risk is a teammate reading the raw
collection next month. Put
[`tools/raw_read_guard.py`](tools/raw_read_guard.py) in CI:

```bash
python tools/raw_read_guard.py --collection notes app/ services/
```

It fails on `db.notes.find(...)` and stays quiet on `docs.find(...)`, reading
the AST rather than the text. `--allow` exempts a designated audit module.
Gate 0's scanner is the broad version of the same instinct; this one is
targeted at the collection you actually piloted.

### Observability

- **`engine.health()["admission"]`** — `revoked_total` (exact),
  `refused_at_boundary` (a lower bound, for the reason given above), and
  `last_reason`/`last_at`. A climbing `revoked_total` with no erasure request
  behind it is a question.
- **`Page.starved`** on a search result — `True` only when the search gave up
  with candidates still unexamined, i.e. the one case where the caller was
  told less than the truth. This is the field worth an alert.
  `Page.examined` next to it is the over-fetch cost as a number.

---

## Gate 3 — decide

Re-run gate 0's scanner. Compare against the threshold you wrote down before
gate 0. Then answer one question in your own words: **would you take this out
now?**

### Rollback

There is nothing to migrate back. `revoke()` never deleted anything, so the
rows are all present; point the read back at `db.notes.find(...)` and remove
the handle. `engine.ensure()` only added a sparse index on the mark field and
a TTL index on `expire_at`; both are harmless to leave, and dropping them is a
one-liner.

---

## Appendix: what it costs

Measured and reproducible — re-run it in your environment with
`uv run python bench/admission.py` (writes
[`bench/results/admission.md`](bench/results/admission.md)): the per-candidate
egress check is about 1 microsecond p50 on a laptop, and over-fetch under a
realistic refusal rate stays near 2x up to 50% refused. If "you pay on every
read, forever" is the objection, this is the number — but it is an objection
being answered, not a reason to adopt, which is why it is down here.

## Appendix: run the whole thing against synthetic data first

Before piloting on your own corpus. Needs only a local MongoDB:

```bash
docker compose up -d mongo
uv run python bench/pilot.py        # writes bench/results/pilot.md
```

It stands up a support-notes scope, leaks a credential into it, has an agent
summarise that credential back into the collection, then honours an erasure
request — and shows, with assertions rather than prose, that the revoked fact
still reaches a prompt through the raw read a teammate writes *and* through
the unfiltered candidate batch handed directly to `reachable()`, while the
handle refuses it on both paths and the summary written out of it goes too.

Every line of the report template below is filled from that run except the one
that decides adoption — **kept after two weeks** — which a self-run
structurally cannot answer and leaves blank on purpose. A proof of the
mechanism is not evidence of demand.

---

## Exit criteria

- [ ] the threshold above was written down **before** gate 0;
- [ ] gate 0's number is recorded, with a date;
- [ ] shadow mode ran for the agreed period on real traffic, and the
      would-have-refused count is a number, not an impression;
- [ ] time-to-unreachable was measured on at least one real erasure request,
      before and after;
- [ ] the canary is returned by the raw path and refused by the handle, in
      your environment;
- [ ] p50/p99 admission overhead and over-fetch are captured on your data;
- [ ] no starvation is hidden — `Page.starved` is wired to an alert and quiet;
- [ ] the raw-read guard is in CI and green;
- [ ] the team chooses to keep the dependency after two weeks, and can say in
      its own words why.

The last one is the only one that matters. The rest are how you get there
honestly.

---

## Report: two audiences, one run

The engineer's number and the accountable person's number are not the same
number, and a report that only has the first one does not get read by the
second.

```
Pilot report — engineering
--------------------------
Team / service:
Collection and read path piloted:
Does this collection hold derived documents (summaries, embeddings)?  yes / no
find-only or vector (Atlas autoEmbed)?

Gate 0   voyd-scan candidate leaks, before / after:   ___ / ___
Gate 1   would-have-refused, over ___ weeks:          ___
         of those, derived documents:                 ___
Gate 2   integration time (first line to green CI):   ___ minutes
         application lines changed:                   ___
         admission overhead p50 / p99:                ___ / ___
         over-fetch (examined/admitted) at our rate:  ___
         starvation observed:                         yes / no

Threshold we wrote down before gate 0:
Did we meet it?                                       yes / no
Kept after two weeks?                                 yes / no
In our own words, why:

Friction worth fixing upstream (feeds docs/STATE.md):
```

```
Pilot report — accountable owner
--------------------------------
Over ___ weeks of production traffic, our retrieval served ___ facts that our
own database had already marked as expired or revoked. ___ of those were
documents derived from a fact somebody had asked us to erase.

Time from erasure request to the fact being unreachable:
  before:  ___          (bounded by the TTL sweeper and index lag)
  after:   next read

Evidence we can show: the refusal ledger (`receipts()`), which records what was
refused, why, and when — and names every break-glass read against it.

Facts deleted to achieve this: 0. The rows are still on disk, which is the
proof rather than an oversight.
```
