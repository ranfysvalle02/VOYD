# Pilot: refusal on one collection

This is the smallest honest trial of VOYD, sized for a Python team already on
MongoDB. One collection, one read path, one construction site. **No** HTTP
service, MCP server, crypto erasure, or perimeter — those are later, and only
if this earns them. The goal is to find out, in your environment, whether the
handle is nicer to keep than a filter is to remember.

The idea it rests on is one sentence, derived in [`AHA.md`](AHA.md): the
per-document check on the way *out* is the guarantee, so refusal binds a
handle, not a collection. Everything below follows from that.

---

## Before you start

- A MongoDB you can point a throwaway database at (Atlas or Atlas Local).
- One collection whose reads feed a model — a RAG corpus, a retrieval scope,
  a memory store. Pick the one where serving a deleted or revoked fact would
  be an incident, not a shrug.
- `pip install voyd` (the base package is `Engine` plus a MongoDB driver;
  nothing else is pulled in).
- Read [`examples/quickstart.py`](examples/quickstart.py) once. It is the
  whole integration, runnable.

## The 30-minute integration

The substantive change is the fenced block in
[`examples/quickstart.py`](examples/quickstart.py) — under ten lines, pinned by
a test so it cannot quietly grow. In your app it is:

```python
from voyd import Engine

engine = Engine(client, db)          # your existing AsyncMongoClient + db
await engine.connect()
docs = engine.model("notes").forgettable()    # "notes" = your collection
await engine.ensure(search_wait_s=0)          # 0 for a find-only pilot
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

## The canary

Seed one document you can watch, and prove the two halves of the claim in your
own data before trusting it anywhere:

```python
from datetime import timedelta
from voyd.engine.time import now

cid = (await engine.db.notes.insert_one(
    {"text": "CANARY", "expire_at": now() - timedelta(minutes=5)})).inserted_id

assert await docs.find_one({"_id": cid}) is None                 # handle refuses
assert await engine.db.notes.find_one({"_id": cid}) is not None  # raw still serves
```

The raw read serving what the handle refuses is not a bug — it is the gap the
handle exists to close, made visible. A revoked document behaves the same way:
`await docs.revoke({"_id": cid}, reason="canary")`, then the handle refuses it
while the row stays on disk.

## Observability

Wire two things into whatever you already watch (a health endpoint, Datadog):

- **`engine.health()["admission"]`** — one entry per handle:
  `revoked_total` (exact), `refused_at_boundary` (a lower bound; most forgotten
  facts are dropped server-side and never counted), and `last_reason`/`last_at`.
  A climbing `revoked_total` with no erasure request behind it is a question.
- **`Page.starved`** on a search result — `True` only when the search gave up
  with candidates still unexamined, i.e. the one case where the caller was told
  less than the truth. This is the field worth an alert. `Page.examined` next to
  it is the over-fetch cost as a number.

## Keep it honest with the raw-read guard

The guarantee binds the handle, so the pilot's real risk is a teammate reading
the raw collection next month. Put [`tools/raw_read_guard.py`](tools/raw_read_guard.py)
in CI, pointed at your source and the collection you piloted:

```bash
python tools/raw_read_guard.py --collection notes app/ services/
```

It fails on `db.notes.find(...)` and stays quiet on `docs.find(...)`, reading
the AST rather than the text. It is the outward version of the in-package gate
[`tests/test_no_module_reaches_past_the_handle.py`](tests/test_no_module_reaches_past_the_handle.py).
`--allow` exempts a designated audit module that legitimately reads everything.

## What it costs

Measured, reproducible, and yours to re-run in your environment with
`uv run python bench/admission.py` (writes
[`bench/results/admission.md`](bench/results/admission.md)): the per-candidate
egress check is about 0.5 microseconds p50 on a laptop, and over-fetch under a
realistic refusal rate stays near 2x up to 50% refused. If "you pay on every
read, forever" is the objection, this is the number.

## Rollback

There is nothing to migrate back. `revoke()` never deleted anything, so the
rows are all present; point the read back at `db.notes.find(...)` and remove the
handle. `engine.ensure()` only added a sparse index on the mark field and a TTL
index on `expire_at`; both are harmless to leave, and dropping them is a
one-liner if you want the collection pristine.

---

## Exit criteria

The pilot has succeeded when all of these hold:

- [ ] the integration changed fewer than ten application lines and took under
      30 minutes;
- [ ] the canary is returned by the raw path and refused by the handle, in your
      environment;
- [ ] p50/p99 admission overhead and the over-fetch factor are captured on your
      data, not just the laptop numbers above;
- [ ] no starvation is hidden — `Page.starved` is wired to an alert and quiet;
- [ ] the raw-read guard is in CI and green;
- [ ] the team chooses to keep the dependency after a two-week staging or
      production trial, and can say in its own words why.

The last one is the only one that matters. The rest are how you get there
honestly.

## Report template

Fill this in at the end of the trial. It is the evidence
[`DECISION.md`](DECISION.md) draws on for what to build next.

```
Pilot report
------------
Team / service:
Collection and read path piloted:
find-only or vector (Atlas autoEmbed)?

Integration time (first line to green CI):     ___ minutes
Application lines changed:                      ___
Where the time actually went:

Measured in our environment:
  admission overhead p50 / p99:                ___ / ___
  over-fetch (examined/admitted) at our rate:  ___
  starvation observed:                         yes / no

Incidents the handle would have caused / prevented during the trial:

Kept after two weeks?                          yes / no
In our own words, why:

Friction worth fixing upstream (feeds DECISION.md):
```
