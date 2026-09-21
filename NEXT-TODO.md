# NEXT-TODO — what the next level needs, measured

Written at `64b3e7f` and corrected at `dba7340`. Tree clean, **477 tests
and all of them pass** -- 476 in the default run plus the Atlas one,
which is now run isolated and passes in 78 seconds. Successor to
`TODO.md`, which described the cut and is now deleted because the cut
landed. Delete this one the same way.

Everything below is measured at the commit above, not remembered. Where
the previous note guessed, it was wrong twice in ways that mattered, and
both are recorded here so the next reader trusts the numbers or
re-measures them rather than splitting the difference.

---

## What landed, so nobody re-does it

- **Lineage on the wire.** `tools/voyd_cascade.py`. Children marked
  first, then the source; the ids resolved once and both halves pinned to
  them; an insert naming a parent has its ancestry closed transitively and
  is refused if that parent may not be reached. `LIMITS.md` §6b has the
  decision and its costs.
- **Four test files and seven examples** stopped driving `Engine`.
- **`Engine` and `model.py` are deleted**, and the wheel gate asserts they
  stay deleted.

---

## The two the old note guessed wrong

Recorded because the shape of the error matters more than the fact.

**`authority.py` does not go.** It was listed as "only used by the
handle's `authorised_by`". It is not: `core.py`, `marks.py`, `lineage.py`
and `sealing.py` all import operation constants (`AUDIT`, `REVOKE`,
`QUARANTINE`, `RELEASE`, `SHRED`, `DERIVE`) from it. Deleting it takes the
write verbs with it. It stays.

**The cut was ~600 lines, not ~1,500.** `voyd/` went 8,220 -> 7,626 while
`tools/` went 7,062 -> 7,555. A guarantee did not evaporate when the door
did; it moved, and moving it cost lines. Estimate the *next* one the same
way: by grepping, not by remembering.

---

## 1. The second cut, and it is now purely mechanical

Every name below is referenced only from docstrings and from other
members of this same set. Measured with
`grep -rn "\.NAME(" tests/ examples/ tools/ voyd/`:

```
reachability_at   0 callers
bounded_by        0
witnessed_by      0
contextualized_by 0
as_of             0
saturate          2, both inside reads.py
_next_ask         1, inside reads.py
search            1 live caller (reads.py -> search.py), 2 in docstrings
count / exists    exists() calls count(); nothing else calls either
authorised_by     1, a docstring in authority.py
```

So the removable set is the *pagination and query* half of the read path,
and it is self-contained:

| file | lines | what goes |
|---|---|---|
| `voyd/engine/admission/reads.py` | 429 | `search`, `saturate`, `_next_ask`, `count`, `exists`, `reachability_at`. **Keep `find`, `find_one`, `match`.** |
| `voyd/engine/search.py` | 602 | the query path: `search`, `_vector`, `_hybrid`, `_lexical`. **Keep `ensure_indexes`, `embeds_itself`, `_vector_stage`, `SearchSpec`.** |
| `voyd/engine/admission/core.py` | 825 | `bounded_by`, `witnessed_by`, `contextualized_by`, `as_of`, `ensure`, and `authorised_by` if `Grants` goes with it |

**Why `find`/`find_one` stay.** The sealing tests read through a handle
that decrypts. A test that cannot read what it sealed is not a test, and
there is no wire path that unseals into a Python process.

**Why `_vector_stage` stays.** `test_the_server_owns_the_encoding.py`
asserts the shape of the `$vectorSearch` stage an auto-embed index gets,
which is the same shape the proxy refuses a client vector against.

Roughly 700-900 lines. The blast radius is smaller than the cut that just
landed, because the tests that used to hold these up already moved.

**Do this before touching anything else in `voyd/`.** Every other item
here is easier against the smaller file.

## 2. `Clearance`, the one deliberately left open

Declares `claim="clearance"` and wants an *ordered level*. Nothing in a
MongoDB role says which level a role is, so on the wire it finds no claim,
"no claim is the lowest, not the highest", and it refuses everything. The
proxy **warns at boot** naming the collection and the claim
(`unsuppliable_claims`), and `examples/clearance.py` says so in its own
header rather than demonstrating around it.

The shape, when somebody needs it:

```python
@guard("notes")
class Notes:
    classification = clearance(order=("public", "internal", "secret"),
                               roles={"sec-cleared": "secret"})
```

A one-evening change. Do not invent the spelling before somebody needs
it; the example now tells a reader exactly what they would be asking for,
which is the cheap half of the work already done.

## 3. The bijection does not check *which door* a test drives

This is the hole that let the lineage claim go unqualified for as long as
it did. `tests/test_every_claim_names_its_evidence.py` asserts that every
claim names a test and every test file is named by a claim. It cannot see
that a test drives a library handle while the claim is printed beside a
connection string.

Now that there is only one door, the check is expressible and cheap: a
test file cited by CLAIMS.md should either start a `voyd-wire` subprocess
or be a pure unit test with no database in it. The exceptions are known
and few -- `shadow`, `portfolio`, `rosetta`, the sealing tests -- so the
rule can be "wire-driven, or on this list with a reason".

Do this before the next claim is added, not after.

## 4. `tools/voyd_wire.py` is 4,382 lines

Up ~270 from the cascade. It is the single biggest structural risk in the
repository and it holds every enforcement decision. Splitting framing /
codec / dispatch / policy would make "can this be bypassed?" answerable by
reading one file.

Two specific hazards, both already load-bearing:

- **16 of the repository's 28 broad `except Exception` handlers are in
  this file**, several in the request loop, where a swallowed exception
  reads as green.
- **The plain path and the fan-out `Conversation` hold duplicated
  blocks** -- the `judge(...)` call, and now the delete rewrites and the
  cascade. They are duplicated *on purpose* (both paths must agree, and
  the way to be sure is that both call the same function rather than one
  calling the other), but nothing enforces that they stay in step.
  `s.count(old) == 1` assertions in patch scripts catch a drift when you
  are editing; nothing catches one at rest.

## 5. The cascade is not on a dashboard

`Guard.cascaded` is counted per collection, summed in `tally`, merged
across workers and printed in `summarise`. It is **not** in
`voyd_metrics.Layout`, so it is invisible to Prometheus.

That matters for the same reason the erasure pair does: `revoked_total`
climbing while `cascaded_total` stays flat on a collection that declares
`lineage_field` means the cascade stopped running, and the only way to see
it from outside is that the two series diverge. Adding a counter means
touching `Layout`, which is shared-memory and pre-fork -- read the note in
`voyd_metrics.py` before widening it.

Also unmeasured: **what the cascade costs**. A delete on a lineage
collection is now a find plus an update before the forwarded command, and
an insert naming a parent is a find before it. `tools/voyd_bench.py`
measures the ordinary paths; nothing measures this one, and "one extra
round trip" is an assumption until it is a number.

## 6. The no-database subset is neither

Its whole premise is that it is pure and fast. Measured: **457 tests,
130 seconds**, with only 20 deselected -- so most of what runs under
`-m "not needs_mongo"` does in fact touch a database or start a proxy. The
marker is applied only to *mixed* files, which was a reasonable decision
that has outlived its accuracy.

`--durations=12` names the offenders, and they cluster:

```
6.9s  test_the_failover_signal_fires_on_a_real_election
5.9s  test_a_wedged_worker_is_visible_even_though_it_is_alive
5.3s  test_a_client_that_stops_reading_does_not_grow_the_boundary
5.0s  x5  TEARDOWN of test_the_vector_dies_with_the_fact
5.0s  test_a_killed_worker_is_replaced_exactly_once_and_counted
4.0s  test_the_sweep_runs_end_to_end_and_the_control_beats_the_proxy
```

**The five teardowns are the interesting one**, because they are not the
test. Twenty-five seconds is the proxy fixture's `proc.terminate()`
followed by `wait(timeout=5)` timing out: `voyd-wire` does not exit
promptly on `SIGTERM` while it drains. Either the drain should notice it
has no live connections and exit immediately -- which is a real
shutdown-latency improvement in production, not only in the suite -- or
the fixtures should `kill()` after a much shorter grace. Check the
production behaviour first; the test cost is the symptom.

---

## Gotchas that are still true

- **The bijection test will block a new test file** until `CLAIMS.md`
  names it. This is correct; budget for it.
- **Counts are asserted in prose.** `LIMITS.md` §4 and `README.md` both
  carry test and line counts, and both go stale on every commit:
  ```
  uv run --no-sync pytest -q -m "" --collect-only tests/ | tail -1
  grep -oE "tests/test_[a-z_]+\.py" CLAIMS.md | sort -u | wc -l
  find voyd -name '*.py' | xargs wc -l | tail -1
  ```
- **The Atlas test is still run isolated**, though it is no longer racing
  a sweeper: its refusable row is revoked rather than expired, because
  `--ensure` builds the TTL index and the monitor collected an
  already-expired row mid-build. Four index builds on one shared cluster
  can still outlast the poll budget, so the deselection stands. CI gates
  it behind a secret in its own step.
- **A client talking to the proxy must carry its own credentials.** The
  boundary forwards SCRAM and authenticates for nobody, so against a
  deployment that requires auth an unauthenticated client gets
  `Unauthorized` *through* the proxy. Correct, and it looks like a proxy
  bug the first time.
- **`voyd-mongo` stepped down mid-run once** (`not primary`, code 10107),
  producing 24 spurious errors. A cluster of fixture errors on
  `insert_many` is the container, not the code.
- **Killing a pytest run leaks test databases.** The session sweeper only
  runs at start-up:
  ```
  docker exec voyd-mongo mongosh --quiet --eval 'const d=db.adminCommand({listDatabases:1,nameOnly:true}).databases.map(x=>x.name).filter(n=>n.startsWith("voyd_test")); for(const n of d) db.getSiblingDB(n).dropDatabase(); print(d.length)'
  ```
- **A pinned `deleteOne` may not be `multi: true`.** The driver marks it
  retryable and the server rejects the combination with code 72. This cost
  a debugging round on the cascade; the comment in
  `revoke_instead_of_delete` says so.
- **Naming an async fixture `db` shadows the sync one** in a file that
  drives both doors, and the failure reads as "coroutine was never
  awaited" five tests away from the cause. See `adb` in
  `test_the_vector_dies_with_the_fact.py`.

---

## Verification (all of it)

```bash
uv run --no-sync ruff check voyd/ tools/ tests/ examples/ scanner/
uv run --no-sync mypy
VOYD_TEST_MONGO_URI="mongodb://localhost:27018/?directConnection=true" \
  uv run --no-sync pytest -q -m "" tests/ \
  --deselect tests/test_search_refuses_on_the_path_that_bypasses_the_query.py::test_the_server_embeds_and_refusal_still_holds
uv run --no-sync pytest -q -m "" tests/test_search_refuses_on_the_path_that_bypasses_the_query.py::test_the_server_embeds_and_refusal_still_holds
python3 scanner/voyd_scan --strict voyd/ tools/ scanner/
for f in examples/*.py; do VOYD_MONGO_URI="mongodb://localhost:27018/?directConnection=true" uv run --no-sync python "$f" >/dev/null || echo "FAIL $f"; done
uv build
```

Containers: `docker compose up -d --wait mongo rs`. The rs has auth
(`voyd:voyd`) and is the only deployment here that can test caller
identity -- `examples/clearance.py` needs it and skips with an explanation
without it.
