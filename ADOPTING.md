# Adopting VOYD without restructuring your application

The most common reason to put this down is a fear that it is a framework — that
"admission control on the read path" means an `Engine` at the centre of your
application and a migration before anything works.

It does not. The wedge is one collection, one read path, and fewer than ten
substantive lines, with the rest of your code untouched. This page is the first
hour, in the order the cost rises, and it is explicit at every step about what
you still **do not** get by stopping there.

Nothing on this page deletes anything. `revoke()` makes a fact unreachable on
the next read; the row stays on disk. That is the proof, not a limitation.

| | you add | you get | you still don't have |
|---|---|---|---|
| **hour one** | a handle in front of one `find` | that path cannot serve an expired or revoked row | every *other* read on that collection |
| **hour two** | the same handle on `search` | the guarantee on `$vectorSearch`, where a query filter cannot reach | rules beyond expired-or-revoked |
| **hour three** | named rules instead of the preset | clearance, quarantine, model drift, token budget — on both halves | nothing you asked for; this is the full read path |
| **later** | an extra: `app`, `crypto`, `mcp` | a surface other callers can reach | — and none of it is the on-ramp |

Each step is additive, and each is reversible by deleting the lines you added.

---

## Hour one: one collection, `find` only

No Atlas, no vectors, no API key, no embedding model. Plain MongoDB is enough.

Take the read you are most afraid of — the one against a collection that
carries a deadline or a soft-delete mark — and put a handle in front of it:

```python
from voyd import Engine

engine = Engine(client, db)            # your existing client and database
await engine.connect()
docs = engine.model("notes").forgettable()
await engine.ensure(search_wait_s=0)   # 0: no search index to wait on yet

rows = await docs.find({})             # was: await db.notes.find({})
await docs.revoke({"_id": leaked}, reason="credential leaked")
```

That is the whole integration. It is not a prose estimate:
`examples/quickstart.py` fences exactly this between `integration:` markers,
and `tests/test_the_quickstart_refuses.py::test_the_on_ramp_stays_under_ten_lines`
counts the substantive lines and **fails the build if it passes ten**. The
on-ramp cannot quietly become a migration, because a test would object.

`forgettable()` also declares the TTL, on purpose: a deadline you refuse on
read but never collect is a storage leak, and a deadline you collect but never
refuse is the bug this exists to remove. They are one policy, so they are one
call.

**What you get.** That read path can no longer return an expired or revoked
document, and it cannot be made to by a future caller forgetting a filter —
there is no unfiltered `find` on the handle to forget. `revoke()` is
immediate: unreachable on the very next read, whatever the TTL monitor is
doing.

**What you do not get yet.** Every *other* read against `db.notes` is exactly
as leaky as it was this morning. The handle guarantees its own path, not the
collection. Which brings us to the honest way to measure the gap:

```bash
python tools/leak_scan.py path/to/your/repo
```

Run it before hour one and after. The number that matters is not how many
reads you wrapped, it is how many you did not.

**What it costs.** About 1 µs p50 and under 2 µs p99 per candidate, flat from
a 1-hit page to a 100-hit page. Because refused hits are fetched and then
dropped, a page can over-fetch — near 2× at up to 50% refused — and the handle
refills rather than returning you a short page. Measured, not asserted:
`bench/admission.py` writes `bench/results/admission.md`.

**How you back out.** Delete the handle lines and call `db.notes` directly
again. Nothing was migrated, no schema was rewritten, no row was destroyed;
`forgotten` is an additive mark on documents you revoked. The exit cost is the
diff you added, which is the point of keeping it under ten lines.

---

## Hour two: the search path

This is the step that is actually worth the trouble, because it is the one a
query filter cannot solve for you.

```python
engine.model("notes", tenant="tenant").searchable(
    text_paths=("text",), auto_embed="voyage-4")
docs = engine.model("notes", tenant="tenant").forgettable()
await engine.ensure(search_wait_s=300)

hits = await docs.search([], text="engine misfire", filters={"tenant": "t1"})
```

A `find` goes through a collection query, so the server can drop forgotten rows
for you. A `$vectorSearch` hit **does not pass through that query** — it
arrives from an index that ranked it. An index filter can express the same rule
only if every read path, every fallback and every future caller supplies it.
The per-document check on the way out is the form that does not depend on that.

Part 2 of `examples/quickstart.py` runs this against Atlas with server-side
embedding, so the refused hit is one whose vector your process never computed.

**What you do not get yet.** Rules beyond "expired or revoked."

---

## Hour three: the rules you actually have

`forgettable()` is a preset. When the real policy is bigger than a deadline,
name the reasons — they are asked in order, on every read, and reported by
name:

```python
docs = engine.model("notes").admitting(
    Deadline(), revoked(), quarantined(),
    EmbeddedWith("voyage-4"), Clearance(order=...), Budget(limit=8000))
```

`examples/rosetta.py` is the translation table: soft-delete, TTL, a feature
flag, row-level security and a token budget written as five rules on **one**
handle, enforced on both halves together. If you are currently maintaining
those as five unrelated mechanisms in five places, that example is the
argument.

Two things worth knowing before you write a rule:

- A rule must be expressible **per document**. `compile_policy(...)` refuses at
  boot anything it cannot compile to both the query clause and the egress
  check, because a rule that lives only in the clause is the silent hole.
- Per-document-*only* is fine — it is the safe asymmetry. `Budget(limit=...)`
  has no query half at all, since a running per-read total is not something a
  per-document query can express. Slower, never a leak.

---

## Later, and only if a pilot earns it

These are surfaces, not the product. The handle is the product; each of these
is a way to reach it, and none of them is the on-ramp.

| | | |
|---|---|---|
| `uv sync --extra app` | the HTTP service | when something that is not Python needs the same guarantee |
| `uv sync --extra crypto` | cryptographic erasure | when "unreachable here" is not enough and you need "unreadable in every backup" |
| `uv sync --extra mcp` | the same guarantee as tools a model can call | when an agent runtime is the caller |

`PILOT.md` is the smallest honest trial: refusal on one collection, exit
criteria, and a report template. `bench/pilot.py` runs the same flow against a
real MongoDB and fills every line of that report except the one only a real
team can answer — kept after two weeks. A proof of the mechanism is not
evidence of demand.

---

## What this does not do, stated here rather than discovered later

- **It binds this application, not your data.** A refusal is a guarantee about
  reads through the handle. Another service with its own connection to the same
  cluster is unaffected. That is why crypto-shredding exists as a separate,
  slower tier, and why `voyd/engine/perimeter.py` is candid that enforcing the
  perimeter is not on offer.
- **It is not a deletion product.** Refusal covers the window; the TTL reaper
  takes the row; key destruction reaches the copies. Three erasures, three
  different costs — the README's table says which reaches what.
- **It cannot fix a read that does not go through it.** See hour one. The
  leak scan is how you keep yourself honest about the remainder.
- **It has no production users yet.** The mechanism is checked by 878 tests
  against a real MongoDB and real `mongot` on every commit, which is evidence
  the mechanism works and is not evidence that anyone needs it.
  `docs/ISSUES.md` lists what is wrong, unproven or imprecise in what ships.
