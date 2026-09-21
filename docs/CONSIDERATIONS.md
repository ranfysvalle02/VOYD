# Considerations

Things that are true of this codebase, cost something to find out, and are
easy to lose again. Not a style guide — every entry below is a trap somebody
already fell into, with what it cost and what now stops it recurring.

Two documents sit next to this one and answer different questions.
[`AHA.md`](AHA.md) is *why the design is this shape*. [`STATE.md`](STATE.md)
is *what is currently wrong*. This is *what will bite you while you work on
it* — and where a guard will stop you, so you meet the reasoning before you
meet the failure.

---

## Writing a rule

The rule protocol is the extension point, so it is where most of the
avoidable damage lives. A rule runs inside the filter that decides whether a
fact reaches a prompt; a rule that is subtly wrong does not raise, it returns
a confident, well-scored, wrong page.

### A rule must never see documents another rule will refuse

The one that cost the most, and it looked like the careful option.

`Distinct` originally pre-scanned the candidate set to pick one winner per
cluster of near-identical documents. On a page ordered by relevance that
reads as obviously right: how else would a rule know whether the row it is
about to admit has a better copy two positions down?

Because the pre-scan runs before any other rule has refused anything:

```
a passage indexed twice, the higher-ranked copy expired

admitted: []
refused : {'deadline': 1, 'redundant': 1}
```

The scan awarded the slot to the expired copy. `Deadline` then refused that
copy, and the live one came back `redundant` behind a document that never
reached the page. Both lost, no error, empty result.

**So a set-relative rule accumulates during admission, never before it.**
Only a document that actually got through may claim anything. This was not
even a trade: both designs keep the first copy in read order, so the pre-pass
bought nothing and cost that. The mechanism was deleted rather than fixed.

Regression:
[`test_a_live_copy_survives_an_expired_one_that_ranked_above_it`](../tests/test_a_reason_can_be_about_the_page_not_the_document.py).

### Decide the fail direction deliberately, and say which you chose

Almost every rule here fails **closed**: an unreadable deadline, an
unrecognised clearance label, a cost that cannot be computed. A fact whose
status cannot be established has no business in a prompt, and
[`why_refused`](../voyd/engine/admission/spec.py) turns any exception from
any rule into a named refusal for the same reason.

`Distinct` is the exception and fails **open**. The asymmetry is the point:
every other rule answers *may this reach a prompt*, where a missing field is
not evidence of permission. `Distinct` answers *is this a duplicate*, where a
missing hash is not evidence that it is. Failing closed there would delete
content over an absent field.

If you add a third set-relative rule, this is the decision to re-examine
hardest, because "fail closed" is the house default and it is the wrong
default for questions that are not about permission.

### `clause()` returning `None` is safe. A clause without an egress half is not

The invariant from [`AHA.md`](AHA.md), in the form you need while writing:

- **egress only** — slower, completely safe. The per-document check is the
  guarantee, and a `$vectorSearch` hit reaches it whether or not any query
  clause exists.
- **clause only** — a silent hole. One read path prunes correctly and another
  admits the same document.

`compile_policy` refuses at boot anything it cannot compile to both halves,
and every operator in [`policy.py`](../voyd/engine/policy.py) is a
hand-written pair checked against a live server. If you add an operator, you
are adding two implementations or none.

Some rules have no query half *by nature* — see
[`policy-engines.md`](policy-engines.md). Returning `None` is those rules
reporting that accurately. Returning an approximate clause would be the hole.

### Per-read state is keyed by identity, not value

Cumulative rules get one state object each, held in
[`Tabs`](../voyd/engine/admission/rules.py) and keyed by `id(rule)`.

It is tempting to key by the rule itself — they are frozen dataclasses and
therefore hashable. Do not. `Budget(limit=50)` and `Budget(limit=50)` compare
**equal**, so a value-keyed dict silently merges two declarations the caller
wrote on purpose, and one rule's limit governs the other. That is exactly the
bug the old "one cumulative rule per read" restriction existed to prevent,
reintroduced through a dict key.

### Declaration order must not decide correctness

Rules are asked in three groups: pure rules, then cumulative rules that only
*observe*, then cumulative rules that *charge*. Within each group the order is
the caller's.

The reason is that charging mutates. A `Budget` asked before `Distinct` spends
real room on a document `Distinct` is about to refuse, and then `Page.spent`
stops being the sum of what was admitted — which is the one thing
`Tab.charge` promises. Four copies of one passage would report `over_budget`
for content that never reached the page.

`charges` is therefore a class contract, not a constructor switch and not a
convention about declaration order. Getting this right is the engine's job,
and [`why_refused`](../voyd/engine/admission/spec.py) is where it is done.

### A Protocol member declared as an attribute is *settable*

`Rule.reason` was written `reason: str` for a long time. Every rule in the
package is a frozen dataclass, so **not one of them satisfied the protocol**
— a read-only attribute does not match a settable member. Nothing failed at
runtime, because structural typing is only ever checked by a type checker and
none was being run.

It is `@property` now. If you add a protocol member that implementations
expose immutably, declare it the same way.

---

## The admission package

### The layering guard cannot see sibling coupling

[`test_the_admission_layers_do_not_invert`](../tests/test_the_admission_layers_do_not_invert.py)
forbids the five capability mixins importing each other. It reads `import`
statements, and sibling coupling in a mixin needs no import: `ReadPath` reads
`self.seals`, `MarkWrites` awaits `self._descendants`. Both resolve through
`Admission`'s MRO at runtime and no import records it, so that rule passed
over two real edges for as long as the split existed.

They are legitimate — a read must know what is ciphertext, a cascading mark
must reach downstream — and they are now written down in
[`composition.py`](../voyd/engine/admission/composition.py), where each mixin
names the contracts it composes against. A *third* sibling edge means editing
that file, which is the "say it out loud" mechanism the import rule was
reaching for, applied to the coupling it structurally cannot see.

### The composition protocols are checked, and will reject you

`composition.py` is not documentation. [`handle.py`](../voyd/engine/admission/handle.py)
assigns the real classes to the protocols under `TYPE_CHECKING`, so mypy
fails at the composition point — naming both halves — if a mixin reaches for
something the core no longer provides, or a signature drifts under it.

That is why `_open_tab` returning `Tabs` instead of `Tab` produced three type
errors in two files rather than one runtime surprise later.

---

## Tests

### Scope a fix to the thing you own

A test needed MongoDB's TTL reaper to leave one expired row alone. The first
fix was `setParameter: {ttlMonitorEnabled: false}` with a restore in a
`finally`. It worked, and it was global state on a shared server protecting
rows that belong to one test: two concurrent runners and the first to finish
restores the monitor while the second is still going — which does not fail,
it silently reinstates the race.

`conftest.py` already listed two footguns of exactly this shape. The fix that
survived is one `drop_index` in the test's own throwaway database.

**Before reaching for a server-wide switch, check whether the scope you
actually need is already smaller.** Here it was: `app` gives every test its
own database and drops it afterwards.

### Measure before you fixture

The same reaper race was then "fixed" in a second test on the grounds that it
was the same defect class. Measured afterwards: that window is **4.3ms against
a 60s sweep — about one run in fourteen thousand**, versus up-to-60s for the
one that actually failed. Same class, four orders of magnitude apart.

The second fixture was removed and the number written into the test's
docstring instead. Indirection on every future reader is a real cost; pay it
for real failures.

### The suite runs in parallel; keep it that way

`uv run pytest -n 4` — about 70s against about 300s. Two things make that
safe, and both are easy to undo by accident:

**Throwaway databases carry their creation time.** The session sweep drops
databases left by interrupted runs, and the only way it can tell those from
the ones a *concurrent* run is using is the timestamp `throwaway_db_name`
puts in the name. Build a test database name by hand and the next run to
start will delete it out from under you, mid-test, and the symptom will be an
unrelated assertion about a row count.

**No test depends on how fast the reaper is.** One test turns
`ttlMonitorSleepSecs` down to 1 for about thirty seconds, which under `-n`
overlaps everything else by design. Three tests need an expired row to stay
on disk, and each drops the TTL index on its own database rather than
assuming a 60s sweep. If you add a fourth, do the same — the window you are
betting against is 60× smaller than the arithmetic in a serial run suggests.

A demo script run *alongside* the suite is still not safe: `setParameter` is
a server-global with no per-database equivalent.

### A skip that is always a skip is a test nobody has ever run

Optional dependencies that gate real assertions are declared as dev
dependencies and asserted present in CI — `pykmip` for the external-KMS rung,
`casbin` for the policy-engine comparison, `crypt_shared` for automatic
encryption. If you add a test that `importorskip`s something, add the CI step
too, or the test is decoration.

`voyd` itself must not import any of them.

### Assert the guard took effect, not just that it ran

A fixture that quietly fails to do its job leaves every test under it looking
green. Where a fixture establishes a precondition, assert the precondition —
`drop_index` raising on a missing index is that check for free, which is why
it replaced fifteen lines of hand-written assertion.

---

## Docs and numbers

### Do not invent precision

"`Budget` is eleven lines of arithmetic" was written into this repository's
own documentation by someone who did not count. It is 71.

This project's central objection to everyone else is fabricated precision —
a tokenizer that pretends to match a vendor's counting, a number that reads
like tokens and is not. A made-up number in the docs is that failure at home.
If you write a figure, derive it or delete it.

### Counts rot, and one direction is checked

[`test_the_docs_are_not_stale`](../tests/test_the_docs_are_not_stale.py)
checks links, anchors, source paths named in prose, and any "N tests" claim —
the last one-directionally, since `@parametrize` means the real number is
always at least the count of `def test_` functions.

Counted nouns in prose — *"fifteen runnable programs"*, *"six steps"* — are
checked **exactly**, against the directory and the headings they describe.
That guard exists because this paragraph used to say those two were "on you,
and both were stale within one commit of being written." They then went stale
again, in the same week, while the sentence naming them as a risk sat right
here. "On you" is not a mechanism, which is this repository's whole complaint
about conventions; the fix was to add a row to `COUNTED` rather than to try
harder. Adding a row is how the next counted noun gets watched.

---

## The guards that will reject your change

Each one exists because the thing it checks went wrong at least once.

| Guard | Rejects |
|---|---|
| [`the_public_surface_is_deliberate`](../tests/test_the_public_surface_is_deliberate.py) | a new name in `__all__` that is not typed out in its `SURFACE` set |
| [`the_admission_layers_do_not_invert`](../tests/test_the_admission_layers_do_not_invert.py) | a module importing its own layer or below, or two mixins importing each other |
| [`no_module_reaches_past_the_handle`](../tests/test_no_module_reaches_past_the_handle.py) | anything but the read path calling the engine's search primitive |
| [`nothing_in_the_package_is_orphaned`](../tests/test_nothing_in_the_package_is_orphaned.py) | a definition in `voyd/` with no caller and no allowlist entry giving a reason |
| [`the_docs_are_not_stale`](../tests/test_the_docs_are_not_stale.py) | a dead link, a renamed anchor, a source path that moved, a stale count of tests or of anything in `COUNTED` |
| [`every_example_still_runs`](../tests/test_every_example_still_runs.py) | an example that stopped running, or a new one nobody listed as exempt |
| [`every_documented_command_is_real`](../tests/test_every_documented_command_is_real.py) | a renamed extra, a dropped compose service, a moved script or a rejected flag in any fenced command |
| [`an_outward_tool_cannot_report_clean_about_nothing`](../tests/test_an_outward_tool_cannot_report_clean_about_nothing.py) | an outward CLI that blesses a path it never read, or whose exit code wraps to success |
| [`engine_standalone`](../tests/test_engine_standalone.py) | app vocabulary appearing in `voyd/engine/`, including in a comment |
| [`the_documented_first_run_works`](../tests/test_the_documented_first_run_works.py) | the quickstart's commands drifting from what exists |
| [`the_engine_pins_its_own_settings`](../tests/test_the_engine_pins_its_own_settings.py) | the engine inheriting the caller's environment or codecs |
| [`what_this_believes_about_the_world`](../tests/test_what_this_believes_about_the_world.py) | an assumption about external software with no recorded check |
| `ruff` + `mypy`, both in CI | lint, and the `py.typed` promise the wheel ships |

Four of them rejected the work that produced this document, which is the
argument for having them:

- the layering guard, because `composition.py` was a new module in the
  admission package and had not been given a layer;
- the orphan guard, because the three contract assertions in `handle.py` are
  called by mypy and by nothing else;
- `engine_standalone`, because a *comment* I added to `voyd/engine/__init__.py`
  contained the word the engine is not allowed to know;
- mypy, because `_open_tab` began returning `Tabs` and the composition
  protocol still promised `Tab`.

---

**Further:** [`AHA.md`](AHA.md) for why the design is this shape,
[`policy-engines.md`](policy-engines.md) for what a retrieval rule can and
cannot be, and [`STATE.md`](STATE.md) for what is wrong right now and what
is deliberately not being built.
