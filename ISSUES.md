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

## 5. Three features are blocked on one missing abstraction

**Severity: medium — and the pattern is the finding.**

None of these are on the HTTP surface, each for the same reason:

- **holds** — who may `release()` a document a detector flagged?
- **sealing** — who may declare a field sensitive, and who may `shred()`?
- **policy loading** — a scope document can hold a `deny` clause and
  nothing reads it, because who may *edit* it is unanswered.

The passcode gates a scope. It says nothing about a review workflow, and
shipping any of the three without that answer would put "re-admit a
document an injection detector flagged" behind the same credential as
"read the scope".

Three separate features blocked on one absence is a message about what to
build, which is why this is an issue and not three.

---

## 6. `redrive()` is a method nobody calls

**Severity: low — deliberate, and worth stating so it is not read as an
oversight.**

Unacknowledged perimeter propagations are retried by `Perimeter.redrive()`,
and `engine.queue()` is the thing that would call it on a schedule. It is
not wired, because a worker that retries erasures is a worker holding
credentials for every registered sink, and where that runs is a deployment
decision this package should not make quietly.

---

## 7. A `SEALED` sink is audited only when somebody audits it

`Perimeter.audit()` turns `holds=SEALED` from a claim into a check, and
`voyd verify` runs it during the shredding check when a perimeter is
attached. Nothing runs it in production, and a sink that starts caching
plaintext after the audit is indistinguishable from one that never did.

The honest framing is that this is a *pre-flight* check, not a monitor.

---

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
