# The falsifier

**One sentence:** `voyd verify` is a command that tries to break this
software on *your* database and exits non-zero if it succeeds.

That's it. It is not a health check, not a test suite, and not a benchmark.
It is an attack, pointed at the claims in the README, running against your
deployment rather than the author's.

I have been sloppy about the word, so first — **two things, two names**:

| | what it is | where |
|---|---|---|
| **the falsifier** | `voyd verify` — the command *you* run | `voyd/verify.py` |
| **"the falsifier can fail"** | tests that deliberately break the software to prove the command notices | `tests/test_the_falsifier_can_fail.py` |

The second one exists because of an obvious problem with the first, and
that problem is most of this document.

---

## Why a test suite wasn't enough

There is already a normal test suite — 568 tests. It proves the properties
hold **on my machine, against my schema, on the MongoDB version I happen to
run.**

None of that is your deployment. Your Atlas tier may not have `$rankFusion`.
Your search index may still be building. Your driver may decode dates
differently. Your cluster may silently degrade to a fallback path that my
tests never exercise, and the degraded path may be wrong.

More importantly: **you have no reason to believe my test suite.** You'd have
to read 10,000 lines to know whether the tests test anything. Running a
command takes eleven seconds.

---

## Why *looking* doesn't work, which is the actual reason this exists

This is the part that makes a falsifier necessary rather than nice.

The failure this software prevents is:

> a deleted document coming back as a normal, well-scored search result

Read that again and notice what's missing. No exception. No log line. No
metric that moves. **The failure produces output that is indistinguishable
from the system working correctly.**

So you cannot evaluate this by using it. Install a completely broken build
and your searches still return plausible, well-ranked answers. You'd never
know. A property whose violation is invisible cannot be checked by
inspection — it has to be **attacked**.

That's what the command does. It doesn't ask "is the config right?" It
plants documents that must not be reachable and then tries every way it
knows to make them come back.

---

## What it actually does when you run it

```bash
voyd verify --uri "$MONGO_URI"; echo $?
```

1. **Creates a scratch database** named `voyd_verify_<random>` and drops it
   on the way out. It never touches your data.
2. **Parks your TTL monitor** (`ttlMonitorSleepSecs`) so the expired row is
   *provably* still on disk rather than maybe-swept. This is the honest
   version of the test — it removes the sweeper's help. The value is
   restored on the way out, including on failure. *(It's a server-global, so
   don't run this next to something that cares.)*
3. **Plants documents that must not be reachable** — expired, revoked,
   above your clearance, derived from an erased source.
4. **Asks for them every way the code can be asked** — `find`, `find_one`,
   `count`, the hybrid search path, the audit handle.
5. **Exits 0 if none of them answered. Exits 1 if any did.**

### The eight checks

| check | the claim it attacks |
|---|---|
| `deadline` | an expired document is unreachable *while its row is still on disk* |
| `revocation` | a revoked fact is refused on the next read — and its row survives, because unreachable-first is the claim |
| `starvation` | a page of refusals is refilled, not silently truncated |
| `clearance` | a document above your clearance is **absent**, not low-ranked — and both enforcement points agree |
| `reversal` | a hold can be lifted; an erasure cannot; a hold keeps no erase deadline on its own evidence |
| `inheritance` | erasing a fact erases the summary written from it, at any depth |
| `shredding` | destroying a scope's key makes its ciphertext unreadable to a cold client, and takes exactly one scope |
| `chain` | the refusal ledger recomputes from entry zero — no key required |

Each one maps to a way this has actually gone wrong, not to a feature.

---

## The obvious problem: who checks the checker?

A checker that always passes is worse than no checker. It converts an
unknown into a **false assurance**, and then somebody makes a promise on it.

You should be suspicious of `voyd verify` for exactly the reason you should
be suspicious of the README. It's my code, claiming my code is fine.

So `tests/test_the_falsifier_can_fail.py` breaks the software **thirteen
different ways on purpose** and asserts the command notices each one:

```
the deadline check fails when the read path stops refusing
the revocation check fails when the row is deleted
the revocation check fails when the embedding survives
the reversal check fails when an erasure can be undone
the reversal check fails when a hold erases its evidence
the inheritance check fails when the mark does not travel
the inheritance check fails when a new summary can be written
the shredding check fails when the key is not destroyed
the shredding check fails when plaintext can be written
the starvation check fails when the page is truncated
the clearance check fails when a missing claim is a pass
the clearance check fails when the audit handle leaks
the chain check fails when nothing was recorded
```

Read one of those as a sentence and you'll see the shape: *"if I sabotage
the software this way, does the command turn red?"* Every check has at
least one, and two checks have more than one because they can break in more
than one direction.

**That is the check on the check.** Without it, `voyd verify` is a green
light with no bulb.

---

## Three things it deliberately does *not* do

- **It is not a health check.** A health check confirms what's configured.
  This attacks what's claimed. `describe()` tells you the tier; this tells
  you whether the tier is lying.
- **It does not prove your data is deleted.** Nothing here claims that —
  the row is deliberately still on disk, and the `revocation` check *fails*
  if the row disappears, because a version that deleted would pass a weaker
  test while breaking the actual promise.
- **It does not pass vacuously.** The `chain` check refuses to accept
  "intact" alone, because an empty chain verifies trivially: a deployment
  recording nothing at all would otherwise get a green tick.

---

## It skips loudly, never quietly

If your machine has no encryption stack, the `shredding` check can't run.
It says so, in the output, next to the checks that did run:

```
[ok  ] shredding: ...
       SKIPPED -- neither crypt_shared nor mongocryptd found
       refusal was checked above and holds; this deployment cannot
       demonstrate the erasure that survives a backup
```

A silent skip and a pass must not look the same in a green run. That's the
same argument the whole tool is making, turned on itself — and CI asserts
the encryption stack is actually present, because *a test that is always
skipped is a test nobody has ever run.*

---

## The point, in one paragraph

Every retrieval system's README makes claims. None of them hands you the
experiment that would disprove those claims. That asymmetry is worst
precisely here, because this failure is silent by construction — so the
honest thing isn't to argue harder, it's to ship the attack and let your
deployment settle it.

```bash
voyd verify --uri "$MONGO_URI"
# 0 = every claim held here, on your machine, today
# 1 = one of them didn't, and you should believe it over anything I wrote
```

CI runs it on every commit, so the tool advertised as the falsifier is
itself known to work — and its exit code is load-bearing rather than
decorative.
