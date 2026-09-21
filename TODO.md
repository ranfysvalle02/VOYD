# TODO — cut the library front door

Working notes for the next session. Written at `1f10bb5`, tree clean,
474/475 green. Delete this file when the cut lands.

---

## The story we are cutting toward

**VOYD is a proxy.** One decorated policy file, one connection string. The
application has no import, no embedding library, no KMS client, no filter
in any query. Today there are two front doors onto one guarantee — the
library handle (`Engine`) and the wire — and the README recommends the
wire while several claims are held up only by the library. That gap is
the thing this project exists to make visible, and it is currently inside
the project.

The end state: `pip install voyd` stops being the artifact. The policy
vocabulary stays importable because the proxy loads it; nothing else in
`voyd/` is application-facing.

---

## Two blockers. Do not start deleting before these are decided.

### 1. Lineage / `derive()` — the hard one

`admission/lineage.py` (247 lines) cascades a revocation from a source to
everything derived from it. **The wire has no cascade.** Its only mention
of `lineage_field` is in `deciding_fields`, which reads the name so a
projection cannot hide it.

`CLAIMS.md` carries this as a headline — *"revoking a source reaches the
summary, the answer and the embedding built on it"* — now annotated with
which door it holds for.

**The decision to make first:** a cascade is a multi-document write
derived from a read, which the proxy does nowhere else. What happens when
the second write fails after the first has landed? Options, unranked:

- Do it in a transaction. Requires the proxy to open one on the client's
  connection; changes what a client's own session sees.
- Write children-first, then the parent, so a crash leaves the source
  still reachable and the derivations already gone — fails toward
  refusing more, which is the direction this codebase prefers.
- Refuse `delete` on a collection declaring `lineage_field` and say why.
  Honest, and removes a feature that has a claim.

Whatever is chosen, `tests/test_a_refusal_travels_and_is_gated.py` has to
be migrated to drive the proxy, or the claim has to change.

### 2. `Clearance` — the small one

Declares `claim="clearance"` and wants an *ordered level*. Nothing in a
MongoDB role says which level a role is, so on the wire it finds no
claim, and "no claim is the lowest, not the highest" means it refuses
everything. The proxy already **warns at boot** naming the collection and
claim (`unsuppliable_claims`).

**The decision:** a declared role-to-level mapping in the voydfile, e.g.
`clearance(order=(...), roles={"sec-cleared": "secret"})`. Do not invent
the spelling before someone needs it — but it is a one-evening change,
unlike lineage.

---

## Inventory — measured, not guessed

### Must stay (the proxy imports these)

```
voyd/declare.py                    policy vocabulary; `load`, `OPTIONS`
voyd/engine/admission/             the verdict: Admission, AdmissionSpec,
                                   rules, reasons, spec
voyd/engine/keyring.py             sealing (voyd_seal)
voyd/engine/custody.py             KMS custody (Ephemeral, LocalFile, from_env)
voyd/engine/search.py              SearchEngine, SearchSpec — --ensure needs
                                   ensure_indexes; the *query* path can go
voyd/engine/expiry.py              Expiry, ExpirySpec — --ensure
voyd/engine/capabilities.py        detect — --ensure
voyd/engine/time.py                now
voyd/engine/errors.py              raised across both
```

Exact import list, from `grep -hoE "from voyd[a-z_.]* import" tools/*.py`:

```
from voyd import guard, deadline, revocable
from voyd.declare import OPTIONS, load
from voyd.engine import Deadline, revoked
from voyd.engine.admission import Admission, AdmissionSpec
from voyd.engine.admission import reasons as R
from voyd.engine.admission.reasons import KEY_UNAVAILABLE, UNRECOVERABLE
from voyd.engine.admission.rules import _is_ciphertext
from voyd.engine.capabilities import detect
from voyd.engine.custody import Ephemeral, LocalFile, from_env
from voyd.engine.expiry import Expiry, ExpirySpec
from voyd.engine.keyring import ...
from voyd.engine.search import SearchEngine, SearchSpec
from voyd.engine.time import now
```

**`from voyd.engine.admission.rules import _is_ciphertext` is a private
name crossing a module boundary.** Promote it while you are in there.

### Candidates to cut

```
voyd/engine/__init__.py        526   Engine: connect/model/search/ensure/
                                     keyring/health. `ensure` orchestration
                                     is already reimplemented in
                                     tools/voyd_ensure.py — compare before
                                     deleting, do not lose a step.
voyd/engine/search.py          ~250  the query path only. KEEP ensure_indexes.
voyd/engine/admission/core.py  ~400  the chaining handle: authorised_by,
                                     bounded_by, witnessed_by,
                                     contextualized_by, for_caller,
                                     as_of, including_refused, receipts.
                                     KEEP: Admission, reachable, _query,
                                     for_caller (the wire calls it).
voyd/engine/admission/reads.py 429   handle read path
voyd/engine/model.py           209   check: policy-side or handle-side
voyd/engine/authority.py       241   only used by the handle's authorised_by
voyd/engine/admission/lineage.py 247 blocked on decision 1
```

`voyd/` is 8,226 lines. Realistic cut is ~1,500–2,000, not 8,000.

### Blast radius — smaller than it looks

**5 test files** drive `Engine`, holding these claims:

| test | claim | after the cut |
|---|---|---|
| `test_the_write_path_forgets_without_deleting.py` | delete → revocation | wire already does this; migrate |
| `test_encryption_is_the_answer_refusal_cannot_give.py` | key per scope, shred one tenant | wire does it via `--key-vault`; migrate |
| `test_search_refuses_on_the_path_that_bypasses_the_query.py` | `$vectorSearch` hit refused | wire does it; **Atlas test is contention-flaky, see gotchas** |
| `test_the_vector_dies_with_the_fact.py` | vector dies with the fact | already wire-driven; only the fixture imports Engine |
| `test_a_refusal_travels_and_is_gated.py` | refusal travels | **blocked on decision 1** |

**7 examples** use `Engine`. They are CI-gated (`for f in examples/*.py`),
so they must be converted in the same commit or CI goes red.

---

## Sequence

1. Decide lineage semantics (above). Write the decision into `LIMITS.md`
   before implementing it.
2. Implement the cascade on the wire, or refuse-and-say-why.
3. Migrate `test_a_refusal_travels_and_is_gated.py` to the proxy.
4. Migrate the other four Engine-driven tests to the proxy.
5. Convert the 7 examples.
6. *Then* delete, in one commit: `Engine`, the chaining API, `search.py`'s
   query path, `reads.py`, `authority.py`.
7. Update the wheel gate in `.github/workflows/test.yml` — it currently
   asserts `from voyd import Engine` **imports**. That assertion inverts:
   it should assert `Engine` is gone, alongside the existing
   `voyd.app/web/mcp/store/ledger/perimeter` cut check.
8. `README.md` opening, `pyproject.toml` description/keywords, `CLAIMS.md`
   rows, `LIMITS.md` §1 counts.

**Do not reorder 6 before 3–5.** The tests are the only thing that proves
the wire does what the handle did.

---

## Gotchas learned the hard way this session

- **The bijection test will block you.** A new test file fails the suite
  until `CLAIMS.md` names it. This is correct; budget for it. It caught
  three new files this session.
- **It does not check *which door* a test drives.** That is how the
  lineage claim went unqualified. Consider extending it.
- **Counts are asserted in prose.** `LIMITS.md` §4 has test/line counts and
  `README.md` has "N claims, N files". Both go stale on every commit:
  ```
  uv run --no-sync pytest -q -m "" --collect-only tests/ | tail -1
  grep -oE "tests/test_[a-z_]+\.py" CLAIMS.md | sort -u | wc -l
  ```
- **The Atlas test is contention-flaky, not broken.**
  `test_the_server_embeds_and_refusal_still_holds` passes alone in ~73s
  and fails beside the other three in its file — four index builds on one
  shared cluster outlast the poll budget. Run it isolated. CI already
  gates it behind a secret in its own step.
- **`voyd-mongo` stepped down mid-run once** (`not primary`, code 10107),
  producing 24 spurious errors. If you see a cluster of fixture errors on
  `insert_many`, check the container before debugging code.
- **The local suite hits a live shared Atlas cluster** via `VOYD_ATLAS_URI`
  in `.env` (`conftest.py:220`), creating and dropping databases. Runs
  cost real minutes and real cluster load.
- **Killing a pytest run leaks test databases.** The session sweeper only
  runs at start-up. Clean with:
  ```
  docker exec voyd-mongo mongosh --quiet --eval 'const d=db.adminCommand({listDatabases:1,nameOnly:true}).databases.map(x=>x.name).filter(n=>n.startsWith("voyd_test")); for(const n of d) db.getSiblingDB(n).dropDatabase(); print(d.length)'
  ```
- **`tools/voyd_wire.py` is 4,114 lines** and holds every enforcement
  decision. If you touch it, `mypy` earns its keep — it caught a
  variable-shadowing bug in `voyd_ensure.py` this session.
- **Two identical code blocks exist** in the plain path and the fan-out
  `Conversation` (the `judge(...)` call). `s.count(old) == 1` assertions
  in patch scripts catch this; keep using them.

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
identity.

---

## Trim-the-fat list (independent of the cut)

- `tools/voyd_wire.py` at 4,114 lines is the single biggest structural
  risk in the repo. Splitting framing / codec / dispatch / policy would
  make "can this be bypassed?" answerable by reading one file.
- The no-database test subset takes **6+ minutes**. Its whole premise is
  that it is pure and fast. `--durations=20` would find the offenders.
- **28 broad `except Exception`** handlers across `voyd/` and `tools/`.
  Several sit in the proxy's request loop, where a swallowed exception
  reads as green.
- A dead-code scan found **8 unreferenced definitions and all 8 are live**
  (framework overrides, deliberate type-level assertions, public API).
  Recorded so nobody repeats the afternoon.
