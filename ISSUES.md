# Known issues

**Verified against the code on 19 September 2026.** Every entry here was
checked, not recalled, and each one says what would close it.

This is not the roadmap — [`ideas.md`](ideas.md) is what is worth *building*
next. This is what is **wrong, unproven, or imprecise** in what already
ships. It exists because a project whose whole argument is "ship the
experiment that would falsify you" cannot keep its defects in a commit
message.

Severity is about *what a reader would be wrong about*, not about effort.

---

## 1. Nothing has ever run against a cloud KMS

**Severity: high — it is the difference between a claim and a demonstration.**

`custody.py` ships `Aws`, `Azure`, `Gcp` and `Kmip`. The provider names and
master-key documents are unit-tested, match the driver's documented
contract, and share a code path with the local rung that *is* exercised
against a live server on every commit.

That proves the shape. It does not prove it works. "Constructs the right
`master_key` document" and "works against AWS" are different claims, and
only the first is currently true.

**Most likely to break, in order:**

- **On-demand credentials may need a package that is not declared.**
  `Aws(access_key_id=None)` returns `{}` to select the credential chain,
  which is the correct production shape on EKS or an instance profile. It
  works in this repository's environment — but `boto3` is installed here
  only by accident, pulled in by the unrelated `drift` extra. If the
  driver's credential lookup needs it, `pip install voyd[crypto]` plus
  instance-profile auth fails on a clean machine and the extra is missing a
  dependency.
- **Latency and throttling.** Every cold decrypt becomes a KMS round trip.
  The key-cache window stops being trivia and becomes load-bearing, and
  KMS request-rate limits are reachable by a single page of cold
  documents.
- **`rewrap_many_data_key` against a real CMK.** Untested, and it is the
  operation that makes destruction credible over time.
- **The error taxonomy gets exercised for real.** Throttling, expired STS
  tokens, an IAM change — see issue 2, which is now fixed but has only
  ever been tested against a simulated failure.

**Closing it needs more than one run.** This project's standard is that
`voyd verify` exits non-zero on *your* deployment and the falsifier proves
each check bites. Holding that for KMS means credentials in CI, which means
org secrets, which means the falsifier cannot run on forks. The honest
resolution is probably an opt-in job gated on secrets that **skips loudly**
— the pattern already used for `crypt_shared`. A one-off manual run is
worth doing first, and is not the same thing.

---

## 2. ~~A failed KMS call looked like a shredded key~~ — fixed

`unseal()` now discriminates: `unrecoverable` when the data key is gone,
`key_unavailable` when it still exists and could not be fetched. Counted
apart, logged apart (ERROR for the outage, INFO for the erasure), and both
still fail closed.

Decided by asking **our own key vault** rather than by matching the
driver's error text — whether the key document exists is a fact we own,
and *"not all keys requested were satisfied"* is a string in somebody
else's library. An unreadable vault answers `key_unavailable`, because "the
key is gone" is a conclusion that evidence does not support.

Left open: it is tested against a simulated failure, not a real KMS
outage. See issue 1.

---

## 3. The embedding is not encrypted, and cannot be

**Severity: medium — documented, mitigated, not eliminated.**

`Sealed(("text",))` encrypts the text. The vector beside it stays
plaintext, because encrypting it would end vector search.

An erasure now destroys derived encodings in the same write (measured
before the fix: the surviving vector separated its own topic from another
by 0.9988 against 0.7992 cosine — a membership oracle over somebody who
asked to be forgotten). So a *revoked* document keeps no vector.

**What remains.** A document that is merely `quarantined` keeps its
embedding on purpose — the row is evidence and the vector is how an
investigator finds others like it — so a held document is still
attribute-inferrable by anyone who can read the collection. That is the
right trade and it is not free, and it should be stated wherever
quarantine is described to an auditor.

---

## 4. Queryable Encryption cannot do per-subject erasure

**Severity: low — measured, documented, and not fixable here.**

QE rejects a JSON-pointer `keyId` (*BSON field
'create.encryptedFields.fields.keyId' is the wrong type 'string'*), so a QE
key is bound per field per collection at creation. Shredding it erases that
field for every subject.

Not a bug and not a gap: it is what the mode is. Recorded because somebody
will eventually try to "fix" it, and because `Sealed` being the default
depends on this being understood.

**Untested:** QE `range` queries (8.0+) are declared in the type and only
`equality` is exercised.

---

## 5. ~~Three features blocked on one missing abstraction~~ — abstraction shipped

`authority.py`. There were three questions and only two had an answer:

    Guard       may this caller read the scope?          a passcode
    Admission   may this document reach a prompt?        rules, per document
    Authority   may this caller perform this operation?  -- nothing

Every verb that changes reachability was available to anyone holding a
handle, which in practice meant anyone holding the scope's passcode. The
asymmetry is the design: **withholding** (revoke, quarantine, shred) and
**granting** (release) are not equally dangerous and must not be equally
available. `Grants.withholding_only()` is the shape most services want —
your pipeline may quarantine anything at 3am and may not put a flagged
document back in front of a model.

Not attached means unchanged, because by default the caller of a library
*is* the application. Once attached, an unbound caller **raises** rather
than passing, for the same reason as `CallerRequired`.

**And the chain learned who.** It could say what stopped being reachable,
when, and on what instruction — and not by whom, so the strongest sentence
available to an auditor was *"somebody released the document the detector
flagged"*. `actor` is hashed with the rest of the entry, so it cannot be
attached afterwards, and it is `None` where nothing knows rather than
naming a service account nobody checked.

**Still open:** the HTTP surface. The blocker was conceptual and is now
mechanical — the endpoints need to map claims onto an `Authority` and
decide where those claims come from, which is a service design question
rather than a missing primitive. Policy *loading* is likewise one line
(`*compile_policy(stored)`); what remains is an editing endpoint, gated on
the `policy` operation that now exists.

---

## 6. ~~`redrive()` is a method nobody calls~~ — still unwired, deliberately

Unchanged and still correct: a worker that retries erasures holds
credentials for every registered sink, and where that runs is a deployment
decision this package should not make quietly.

What changed is that "nobody calls it" can no longer be because it was
awkward. The loop is four lines, documented in `redrive()` itself, and
`PerimeterLog.settled()` gives the two numbers to alert on — including the
one that matters, `unconfirmed`, which counts propagations that were given
up on. A dashboard showing only `open` reads as healthy precisely when the
queue has drained by expiry rather than by success.

---

## 7. ~~A `SEALED` sink is audited only when somebody audits it~~ — now with staleness

Still a pre-flight check. The fix is not to pretend otherwise but to make
the gap *visible*: `audit()` keeps its result, `describe()` reports each
sealed sink as `never verified` / `verified` / `verified, 400d ago
(stale)`, and passing a ledger puts the audit on the chain so a run
becomes a fact rather than a log line that rotated away.

"Verified 400 days ago" and "verified" must not read the same — which is
the same complaint this module makes about an unchecked claim, applied to
its own check.

**Still open:** nothing runs it continuously, and a sink that starts
caching plaintext the day after an audit is undetectable until the next
one. Staleness bounds the lie; it does not remove it.

---

## 8. The public surface grew for a year with nothing watching it

**Severity: closed, and recorded because the mechanism is the point.**

`voyd.engine.__all__` reached 100 names, 48 of which appeared in no README,
blog or example. Not wrong individually — nothing had ever asked them to
earn the name.

Cut to 75 and pinned by
`tests/test_the_public_surface_is_deliberate.py`. Nothing was deleted
except `POLICY` (a constant referenced nowhere); the rest went from
*promised* to *present*, still importable from the module that owns it.

**What this does not fix.** The engine is 17 modules and ~10,600 lines, and
a curated export list does not make it smaller — it makes the promise
honest. Whether the *concepts* have outgrown the project's own aesthetic is
a separate question, and the honest answer is that nobody has yet sat down
and asked which of the last five features would be missed.

## 9. A purge pass found a destructive endpoint nobody was watching

**Severity: closed, and the shape of it is the lesson.**

`DELETE /v1/voyds/{slug}` was untested, undocumented, referenced by
nothing, and cascaded through a hardcoded `("voids", "documents")` written
before `refusals`, `__keys` and `perimeter` existed. It also contradicted
this project's own *Deliberately not doing* entry, which says "a delete
tool **or endpoint**" — a sentence CI had only ever enforced for MCP
tools.

Removed, along with `store.delete_voyd` and `store.forget_documents` (dead:
its only other mention was a docstring in the method that replaced it), and
the endpoint half of the principle is now a test.

**What is left.** Owner offboarding has no story: a namespace is created and
never removed. That is a *product* gap rather than a defect, and the honest
options are a deadline on the voyd itself — which is what this package
would argue for — or an operator-level operation that is not an HTTP verb.
Neither is built.

## Operational caveats

Not defects — known trades, written down so they are not rediscovered as
surprises.

- **The key cache is not a contract.** Measured at ~60s in one shape and
  past 120s in another. Crypto erasure is eventually consistent and the
  window is unspecified; refusal is what covers it.
- **Master-key destruction is not immediate on a real KMS.** Per-scope
  shredding deletes a *data key* and is immediate. Destroying the *master*
  key is a 7-day minimum pending window on AWS (30 by default), with
  equivalents on Azure and GCP. The claim rests on the data key; the
  distinction still has to be stated, because this project's argument is
  about erasure timing.
- **Passcode rate limiting is per-replica.** In-process, the trade for not
  needing Redis, and the first thing to fix on more than one process.
- **CORS is wildcard-open on `/v1`**, which is the whole public surface.
- **The chain's signature is HMAC** — an attestation to whoever trusts the
  key holder, not a public proof. The chain itself needs no trust; only the
  signature does.
- **`auto_embed` is unavailable on Atlas Local** — see [`BUG.md`](BUG.md).
  The fallback is the normal path locally and in CI.
- **Two tests have flaked** on mongot index-build timing under load
  (`test_atlas_search`, `test_an_expired_void_is_gone`). Both pass in
  isolation and have never failed in CI. Recorded rather than dismissed:
  the last two flakes chased in this repository were both real bugs.
