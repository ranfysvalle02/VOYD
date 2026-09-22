# NEXT-TODO — what the next level needs, measured

Written after the boundary was split into decide / encode / move, tree
clean. 510 tests, all passing: 509 in the default run plus the Atlas one,
which is run isolated.

Everything below is measured at that commit. Where a previous note
guessed, it was wrong; the habit that caused it is recorded at the bottom.

---

## 1. The bijection does not check *which door* a test drives

This is the hole that let the lineage claim go unqualified for as long as
it did. `tests/test_every_claim_names_its_evidence.py` asserts that every
claim names a test and every test file is named by a claim. It cannot see
whether the test exercises the boundary or calls a handle directly.

With one door left, the rule is finally expressible: a test file cited by
`CLAIMS.md` should either start a `voyd-wire` subprocess or be a pure unit
test with no database. The exceptions are known and few — `shadow`,
`portfolio`, `rosetta`, the sealing tests — so it can be "wire-driven, or
on this list with a reason".

Do it before the next claim is added, not after.

## 2. The two duplicated dispatch blocks

`proxy.py` is 2,795 lines now and the enforcement decisions are all in
`policy.py`, so "can this be bypassed?" is one file. What the split did
not fix is the one hazard underneath it.

**The plain path and the fan-out `Conversation` hold duplicated blocks**
— the `judge(...)` call, the delete rewrites, the cascade, the
`killCursors` cleanup. They are duplicated on purpose: both paths must
agree about what a command means, and the way to be sure is that both
call the same function rather than one calling the other. But nothing
enforces that they *stay* in step. `s.count(old) == 1` assertions in a
patch script catch a drift while you are editing; nothing catches one at
rest, and a boundary that means two different things depending on
whether `--fan-out` is set is the drift this project is about.

A test that drives the same command down both paths and asserts the
replies are byte-identical would close it. It is not free — the fan-out
path needs a replica set — but it is the assertion the duplication is
asking for.

## 3. What the cascade costs is unmeasured

`voyd_cascaded_total` is on the dashboard now, per collection, beside
`revoked_total`: the two diverging on a collection declaring
`lineage_field` is how a stopped cascade becomes visible from outside.

What is still an assumption is the **price**. A delete on a lineage
collection is a find plus an update before the forwarded command, and an
insert naming a parent is a find before it. `voyd-bench` measures the
ordinary paths and not this one, so "one extra round trip" is a sentence
in a docstring rather than a number, in a repository whose entire
argument is the difference between those.

## 4. The no-database subset is neither, and one cause is a shutdown bug

Its whole premise is that it is pure and fast. Measured: **457 tests, 130
seconds**, with only 20 deselected — most of what runs under
`-m "not needs_mongo"` touches a database or starts a proxy. The marker is
applied only to *mixed* files, a decision that has outlived its accuracy.

`--durations=12` names the offenders and they cluster:

```
6.9s  test_the_failover_signal_fires_on_a_real_election
5.9s  test_a_wedged_worker_is_visible_even_though_it_is_alive
5.3s  test_a_client_that_stops_reading_does_not_grow_the_boundary
5.0s  x5  TEARDOWN of test_the_vector_dies_with_the_fact
5.0s  test_a_killed_worker_is_replaced_exactly_once_and_counted
```

**The five teardowns are the interesting ones**, because they are not
tests. Twenty-five seconds is `proc.terminate()` followed by
`wait(timeout=5)` expiring: `voyd-wire` does not exit promptly on
`SIGTERM` while it drains. Either the drain should notice it has no live
connections and exit immediately — a real shutdown-latency improvement in
production, not only in the suite — or the fixtures should `kill()` after
a shorter grace. Check the production behaviour first; the test cost is
the symptom.

## 5. Two things deliberately kept

Recorded so nobody re-derives the decision and deletes them.

**`including_refused()`** has no caller outside the package and stays. It
is the named, audit-gated break-glass read, referenced from a dozen
docstrings and from `scanner/`, and the reason it is a separate object is
so a review can grep for it. A feature with no caller yet is not the same
as a dead one.

**`authority.py` and `authorised_by()`** stay for the same reason, and
because four modules import operation constants (`AUDIT`, `REVOKE`,
`QUARANTINE`, `RELEASE`, `SHRED`, `DERIVE`) from it. A previous note had
it listed for deletion as "only used by the handle's `authorised_by`",
which was wrong.

---

## Gotchas that are still true

- **The bijection test will block a new test file** until `CLAIMS.md`
  names it. This is correct; budget for it.
- **Counts are asserted in prose.** `LIMITS.md` §4 and `README.md` carry
  test and line counts, and both go stale on every commit:
  ```
  uv run --no-sync pytest -q -m "" --collect-only tests/ | tail -1
  grep -oE "tests/test_[a-z_]+\.py" CLAIMS.md | sort -u | wc -l
  find voyd -name '*.py' | xargs wc -l | tail -1
  ```
- **The Atlas test is run isolated.** Its refusable row is revoked rather
  than expired, because `--ensure` builds the TTL index and the monitor
  collected an already-expired row mid-build. Four index builds on one
  shared cluster can still outlast the poll budget, so the deselection
  stands.
- **A client talking to the proxy carries its own credentials.** The
  boundary forwards SCRAM and authenticates for nobody, so against a
  deployment requiring auth an unauthenticated client gets
  `Unauthorized` *through* the proxy. Correct, and it looks like a proxy
  bug the first time.
- **A pinned `deleteOne` may not be `multi: true`.** The driver marks it
  retryable and the server rejects the combination with code 72.
- **Naming an async fixture `db` shadows the sync one** in a file that
  drives both paths, and it presents as "coroutine was never awaited"
  five tests away from the cause. See `adb` in
  `test_the_vector_dies_with_the_fact.py`.
- **`voyd-mongo` stepped down mid-run once** (`not primary`, code 10107).
  A cluster of fixture errors on `insert_many` is the container.
- **Killing a pytest run leaks test databases.** The sweeper only runs at
  start-up:
  ```
  docker exec voyd-mongo mongosh --quiet --eval 'const d=db.adminCommand({listDatabases:1,nameOnly:true}).databases.map(x=>x.name).filter(n=>n.startsWith("voyd_test")); for(const n of d) db.getSiblingDB(n).dropDatabase(); print(d.length)'
  ```

## One habit, because it has cost twice

**Do not report a caller count. Report the callers.** An audit that said
"saturate: 2, both inside reads.py" was three, and the third was an
example that CI would have caught and a loop that echoed `FAIL` and
returned zero did not. A count with no list is an assertion about code
nobody read.

---

## Verification (all of it)

```bash
uv run --no-sync ruff check voyd/ tests/ examples/ scanner/
uv run --no-sync mypy
VOYD_TEST_MONGO_URI="mongodb://localhost:27018/?directConnection=true" \
  uv run --no-sync pytest -q -m "" tests/ \
  --deselect tests/test_search_refuses_on_the_path_that_bypasses_the_query.py::test_the_server_embeds_and_refusal_still_holds
uv run --no-sync pytest -q -m "" tests/test_search_refuses_on_the_path_that_bypasses_the_query.py::test_the_server_embeds_and_refusal_still_holds
python3 scanner/voyd_scan --strict voyd/ scanner/
fail=0; for f in examples/*.py; do VOYD_MONGO_URI="mongodb://localhost:27018/?directConnection=true" \
  uv run --no-sync python "$f" >/dev/null || { echo "FAIL $f"; fail=1; }; done; exit $fail
uv build
```

Containers: `docker compose up -d --wait mongo rs`. The rs has auth
(`voyd:voyd`) and is the only deployment here that can test caller
identity — `examples/clearance.py` needs it and skips with an explanation
without it.
