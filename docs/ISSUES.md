# Known issues

**Verified against the code on 20 September 2026.** Every entry here was
checked, not recalled, and each one says what would close it.

This is not the roadmap — [`ideas.md`](ideas.md) is what is worth *building*
next. This is what is **wrong, unproven, or imprecise** in what already
ships. It exists because a project whose whole argument is "ship the
experiment that would falsify you" cannot keep its defects in a commit
message.

Severity is about *what a reader would be wrong about*, not about effort.

---

## 1. ~~Nothing has ever run against a real KMS~~ — closed, and the framing was the bug

This was carried as the project's one honestly-unmet standard for a long
time, on an assumption that turned out to be wrong: that closing it needed
a cloud account and CI secrets.

**Enterprise key custody is not a synonym for one vendor's managed
service.** KMIP is the open standard the category actually runs on —
Thales, Fortanix, Entrust, HSM appliances — and a large share of
deployments choose it *because* they will not put keys in a public cloud.
It is also, unlike any hosted KMS, runnable: a conformant server starts in
a subprocess in eight seconds.

So `tests/test_an_external_kms_holds_the_key.py` runs against a real KMIP
server over TLS. The data key is wrapped by a key this process does not
hold, the stored document records `masterKey.provider = "kmip"`, and three
claims that had only ever been shapes are exercised against something that
can refuse:

- **rotation.** `rewrap_many_data_key` had never run against a real
  master. A key that cannot be re-wrapped is one that gets copied instead,
  and a copied key cannot be destroyed.
- **shredding**, with the wrapping key held elsewhere.
- **TLS options reaching the driver** — a KMIP appliance without mutual
  TLS is a key server on the open network, and nothing checked the options
  survived the trip from custody to the driver.

**What is genuinely left**, stated narrowly now that the category claim is
proven: the three *hosted* providers — `Aws`, `Azure`, `Gcp` — construct
provider-shaped master keys that are unit-tested and share every line of
the code path now exercised against KMIP. What is unproven is
vendor-specific: credential discovery (`Aws(access_key_id=None)` selects
the driver's chain and may need a package this project does not declare),
throttling behaviour under a cold page, and the fact that AWS
`ScheduleKeyDeletion` has a 7-day minimum pending window, so *master*-key
destruction there is not the immediate operation that shredding a data key
is.

That is a smaller and more honest claim than "nothing has run against a
KMS", and the difference is the one the framing was hiding.

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

Initially cut to 75 and pinned by
`tests/test_the_public_surface_is_deliberate.py`. Nothing was deleted
except `POLICY` (a constant referenced nowhere); the rest went from
*promised* to *present*, still importable from the module that owns it.
Since grown to 78 — the `Budget` rule and its two reasons (`OVER_BUDGET`,
`UNCOSTED`) — each addition a line somebody typed into that test's diff,
which is the mechanism working rather than the surface drifting again.

**What this does not fix.** A curated export list does not make the package
smaller — it makes the promise
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

**Owner offboarding is `POST /v1/voyds/{slug}/forget`** — the same verb the
other two tiers use, and the reason the gap existed is the interesting part:
there are four tiers and only the bottom two obeyed this package's own
thesis. A *customer's* erasure request was honoured in milliseconds on a
hash chain; the *account holder's* had a hardcoded cascade. The guarantee
was strongest at the leaf and absent at the root, which is backwards.

A namespace is not a folder, it is a key scope — `voyd_id` was already the
tenant on every document — so forgetting one destroys a key rather than
walking a list. The rows still go on the deadline, across the collections
the *engine declared expiring* rather than a literal somebody maintains.
It reports `unreadable: true/false` so a caller can tell "noise in every
backup" from "this database will forget on the reaper's schedule".

## 10. ~~`including_refused()` was ungated and uncounted~~ — closed

**Severity: closed.** A review named the one hole in the escape hatch: it turned the guarantee off, and it was neither gated nor
counted, so the 2am use to "just fix a bug" needed no permission and left no
trace.

Both halves are now code. Disclosing a forgotten fact is the *granting*
direction -- `AUDIT` in [`voyd/engine/authority.py`](../voyd/engine/authority.py),
alongside `RELEASE` -- so `including_refused()` asks an authority for it where
one is installed, and raises for a withholding-only caller, the same asymmetry
`release` sits behind. And it increments `including_refused_total` in
`receipts()` once per terminal read, recording the last actor/time; a cached
handle is re-authorised on every use and an unused one records nothing. The
engine's own write paths do not pay this: they use a private `_unfiltered()`
hatch, because `revoke`
seeing the row it marks is a `REVOKE`, not an `AUDIT`, and routing it through
the gate would break `Grants.withholding_only()`.
[`tests/test_break_glass_is_named.py`](../tests/test_break_glass_is_named.py) fails
the build if any module outside
[`voyd/engine/admission/core.py`](../voyd/engine/admission/core.py) reaches for the
public name.

**Still open:** the lint against *new* call sites is exactly that test, but it
only covers `voyd/`. A call site in application code is the deployment's to
police.

## 11. Budget and sealing do not yet compose

**Severity: low — refused at construction, not silently wrong.**

`Budget` charges a selected hit; sealing can then refuse that hit only after
asynchronous decryption discovers its key is gone. Charging before decryption
would make `Page.spent` include ciphertext that never reached the caller and
could make a budget-complete page look complete before an unreadable hit was
dropped. Both are precise numbers with false meanings.

So `sealed_by()` rejects a handle with a cumulative rule. The fix is not an
exception in the counter: it is ordering the read path as pure admission →
decryption → cumulative admission, with refill after either refusal. Until
that exists, failing at construction is the only honest composition.

## 12. Destroying the derived encoding is a silent no-op on an auto-embedding collection

**Severity: a reader would be wrong about the second guarantee, not the first.**

`AdmissionSpec.derived_fields` defaults to `("embedding",)`, and
`marks.py` nulls every one of them inside the same update that writes an
irreversible mark — with a comment arguing why: *"the vector beside an erased
document is a copy of it in a coat."*

On an `auto_embed` collection **there is no embedding field in the document.**
Nothing in this process ever computes one; the vector lives inside mongot. So
`mark_set["embedding"] = None` sets a field that does not exist, and the lossy
encoding of the erased text stays in the index. It is not re-embedded away
either, because `revoke()` deliberately does not change the text — the row
stays on disk until the reaper takes it, which is the whole design.

Be precise about the size of this:

- The **refusal guarantee is intact.** The per-document check still catches
  the document on the way out; nothing reaches a prompt.
- What is lost is the **second** guarantee — destroy the derived encoding
  immediately rather than on the reaper's schedule — which this codebase
  advertises, implements, and argues for in a comment.
- It is lost **silently.** No warning at declaration, and nothing on
  `health()` saying "derived-field destruction is a no-op here."

`Engine._refuse_sealed_autoembed()` already refuses the neighbouring
contradiction (a field both sealed and embedded by the server) at `ensure()`,
and does not cover this one.

**What would close it.** The minimum fix is loud: refuse, or warn, at
`ensure()` when a spec declares both `auto_embed` and non-empty
`derived_fields`. The honest fix is to work out what erasure means when a
third-party index holds the lossy copy — and that question is not
MongoDB-specific. It is true of every hosted embedding index, which makes it
a [`drift/`](../drift) exhibit rather than a patch.

---

## 13. A nested `$vectorSearch` child filter has no per-document counterpart

**Severity: this is the one condition this repository calls fatal, present in
one place.**

[`PORTABILITY.md`](PORTABILITY.md) and [`AHA.md`](AHA.md) both rest on the
asymmetry: a rule may be *egress only* (slower, safe), but a rule that exists
only as a query clause is a silent hole — one read path prunes correctly and
another admits the same document.

`AdmissionSpec.subjects` and `subject_key` made the boundary able to *see*
subdocuments, and `ensure()` refuses a nested vector index on a collection
that never named its subjects. What they did **not** do is make a server-side
child filter expressible as a rule. A nested `$vectorSearch` filter therefore
prunes at the index with no per-document check behind it, which is the shape
the rest of the package exists to forbid.

Two smaller gaps sit behind it, and both are plumbing rather than design now
that subjects have stable names:

- `lineage` is still an array of `_id`s, so a summary derived from chapter 3
  can name the book and not the chapter. `(parent_id, path, key)` already
  renders to a string; nothing carries it yet.
- `receipt_for` commits to parent ids only. `ContextRef` already carries a
  typed `kind`, and a third kind for an embedded subject is the obvious shape.

**What would close it.** The cheap interim is to refuse at `ensure()` when an
admitting collection carries a nested vector index at all — turning a silent
hole into a loud one, which is the move this repository makes everywhere else.
The real fix is marks and deadlines on array elements, which means array-filter
updates in `marks.py`, a composite identity through `lineage.py`, and
re-derived `Page` accounting.

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
- **CORS is wildcard-open on `/v1`**, which is the whole public surface -- and
  `/v1` is a frozen surface (see [`ideas.md`](ideas.md)): the HTTP namespace is
  not the on-ramp, so tightening this waits on the surface being promoted by a
  pilot rather than being fixed speculatively now.
- **The chain's signature is HMAC** — an attestation to whoever trusts the
  key holder, not a public proof. The chain itself needs no trust; only the
  signature does.
- **`auto_embed` is unavailable on Atlas Local** — see [`BUG.md`](BUG.md).
  The fallback is the normal path locally and in CI.
- **Two tests have flaked** on mongot index-build timing under load
  (`test_atlas_search`, `test_an_expired_void_is_gone`). Both pass in
  isolation and have never failed in CI. Recorded rather than dismissed:
  the last two flakes chased in this repository were both real bugs.
- **`auto_embed_definition()` does not set `numDimensions`, `similarity` or
  `quantization`.** The server's defaults apply, which is fine until they are
  not what a deployment wanted and nothing said so.
- **Assumptions about vendor behaviour are recorded, not all observed.**
  `voyd/engine/assumptions.py` and `voyd/assumptions.py` exist so that every
  belief about software this package does not ship has a recorded check, and
  some of those checks are documentation rather than a cluster.
