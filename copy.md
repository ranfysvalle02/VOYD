# Copy: the words that already fit

The engine is deliberately free of application vocabulary. This file is
not. It is the sell, and the sell is allowed to be memorable.

Nothing below proposes renaming an API. `Admission`, `custody`,
`including_refused()`, `Grants.withholding_only()` already exist. The
work is noticing that they are not engineering words that happen to
overlap with law. They *are* the law, applied to a prompt.

The register is family court, hospital doors, and school trips. Use the
structure. Do not analogise a data subject to a child. That turns clever
into grotesque in one sentence.

And keep [`AHA.md`](AHA.md) next to this one. The metaphor is only worth
using because it is *literally* the mechanism: the check happens on the
way out, before a fact reaches the third party, because no query or
index filter can be trusted as the rule's only home. Every play below
is that sentence in a different set of clothes. A metaphor that has to
be walked back under questioning is worse than plain prose, and this
one does not.

---

## The headline, if you get one

**Right of first refusal.**

In a parenting agreement, if one parent cannot take the time, the other
parent is offered it *before* a third party is. The child does not go to
a babysitter by default.

Retrieval today is the opposite. The vector index has first access. A
fact that ranks, reaches. The owner, the subject, the deadline, the
revocation — they get last refusal, on the sweeper's clock, if anyone
remembered the filter.

VOYD inverts the default:

> A fact does not enter a prompt until it has survived refusal.
> The model is the third party. It does not go first.

That is the whole thesis, in a phrase a lawyer already knows and an
engineer can watch in two lines:

```python
await docs.find({})                       # admitted only
await docs.including_refused().find({})   # the permission slip
```

"Right of first refusal" works on both sides of the three-hop. The
engineer hears: the unsafe path is named, the safe path is the default.
The payer hears: the subject was offered the refusal *before* the model
was served. The victim is not in the read path, so the handle exercises
the right in their stead. That is the hop, solved in language: Admission
is what stands in when the parent cannot be at the gate.

Do not acronym it on the landing page. ROFR is a term-sheet word. Say
the sentence. Let them recognise it.

---

## The system of the metaphor

Once you pick the register, the rest of the repo stops being a pile of
clever names and becomes one story.

| already in the code | the parallel | what it is for |
|---|---|---|
| **Admission** | you are not on the ward because you arrived; you are admitted | the door. Ranking is showing up. Serving is a different verb. |
| **including_refused()** | the permission slip | default is no. The unsafe trip has a form a reviewer can grep for. |
| **custody** | who holds the child; who holds the key | `custody.py` is already this. The claim is as strong as who can destroy the key without asking you. |
| **one `expire_at`** | sole custody of the deadline | four clocks is joint custody of a fact across Postgres, Pinecone, S3 and a cron. That is how you lose them at the airport. |
| **withholding / granting** | easier to take visitation than to give it back | `Grants.withholding_only()`. The pipeline may quarantine at 3am. It may not put the document back in front of a model. Family court already knows this asymmetry. So does `authority.py`. |
| **quarantine / release** | emergency order, reversible; then a hearing | hold without erasure. The row is the evidence. Release is the dangerous verb. |
| **revoke** | the order that is not taken back | `Irreversible`. No undo. A new document with new provenance if you must re-admit the information. |
| **shred** | termination, every copy | the key is gone; snapshots become noise. Not a delete. A custody event. |
| **sealed** | sealed records | ciphertext at rest. The DBA with `mongosh` gets nothing they can read. |
| **ledger / receipt** | the stamped order you walk out with | keep it. The other party can rewrite their docket. They cannot rewrite the paper in your hand. |
| **as_of(t)** | what were the arrangements last Tuesday | reconstruct the scope. `unknown` if the reaper took the row — absence is not proof. |
| **derive / lineage** | what was made of this | a summary is a descendant. Forgetting the parent and leaving the child is how the order fails. |
| **for_caller / Clearance** | this slip, this person, this trip | not "may they enter the building." May *this* document reach *this* prompt. |
| **witnessed_by** | the record is attested | the chain is a witness. HMAC is not a public notary. Say so. |
| **perimeter** | who else has a copy | you cannot enforce a court order in a house you do not control. You can list the houses. `describe()`. |
| **VOYD / void** | null and void | unreachable first. Erased second. The serving is void before the row is gone. |

The test of the system: if a word does not earn a row, it does not get
used in the pitch. `starved` is a brilliant engineering word and a
disastrous family-court word. Keep it in the traces. Do not put it in
the metaphor.

---

## Three plays that close a room

### 1. "Retrieval assumes consent. Admission asks."

The current stack treats a good score as permission. That is the blank
permission slip: anything that ranks, goes on the trip.

Admission is the signed one. No signature, no trip. The signature is a
rule, evaluated per document, per caller, per instant — not a filter
somebody remembered.

This is the demo order from the appendix, in one antithesis: show the
missing `find`, then say this sentence.

### 2. "The permission slip is named."

`including_refused()` is the product, inverted. A conventional filter
hides the bypass in a missing `AND`. You put it in a method a grep will
find and a code review will smell.

School-trip English: the default is you do not go. If you go anyway,
there is a slip. The slip is embarrassing to forge. That is the whole
failure-mode inversion, without saying "failure-mode inversion."

Use this when the objection is "we'll just add `deleted: false`." The
answer is not that their filter is wrong. It is that their permission
slip is invisible.

### 3. "Sole custody of the deadline."

Four owners is joint custody: Postgres has the row, Pinecone has the
vector, S3 has the bytes, a cron has the cleanup. Each is behaving.
The *system* is serving deleted data. There is nobody to escalate to.

One document, one `expire_at`, one TTL index. Sole custody. Nothing to
keep in step, because there is nothing to keep in step.

`custody.py` then does the other half: who holds the key that wraps the
keys. Physical custody of the row is not legal custody of the copies.
Shredding the key is how you reach the snapshot on someone's laptop.
Say "custody" and both modules light up without a slide that says
"architecture."

This is the `drift/exhibit.py` sentence.

---

## In loco parentis — the three-hop, in Latin, once

The data subject cannot sit in the read path. Compliance cannot change
the read path. The engineer can, and does not want to.

So the handle acts in the subject's stead, at the only moment that
matters: the moment a fact would otherwise enter a prompt. That is
literally *in loco parentis* — in the place of the parent, at the gate.

Use it once, in a room that likes Latin, and never in the README.
The README says: the subject is not there, so refusal has to be a
property of the handle, not a memory of the caller.

---

## What this does to the first sentence

Current README:

> Every database can delete. None of them can refuse.

Keep it. It is the verb. Pair it, do not replace it:

> Delete is last refusal, on a sweeper's clock.
> Admission is first refusal, on the next read.

Or, if the room is legal:

> The model does not have right of first access.
> The fact has right of first refusal.

Or, if the room is engineering:

> Ranking is not permission.
> `including_refused()` is.

Three rooms, one object. The mistake was using the auditor's sentence
as the only sentence. The mistake the other way is using "agent memory."
This register is neither. It is *access*, *consent*, and *who decides
before the third party does*.

---

## What is too clever (so it does not land in a commit)

- **Do not call a document a child.** Lineage, descendants, derive — those
  are already accurate for facts made of facts. Stop there.
- **Do not rename APIs** to `permission_slip()`, `visitation()`,
  `in_loco_parentis()`. The code is the sober half. The copy is allowed
  to be the other half. Mixing them makes both unserious.
- **Do not put `starved` in this register.** It means the page gave up
  while candidates remained. It does not mean what it sounds like next
  to custody.
- **Do not say "best interests of the model."** Cute, and it concedes
  the wrong principal. The principal is the subject. The model is the
  third party.
- **Do not fight "void" into every sentence.** The product is named.
  "Null and void" is a kicker, not a paragraph.
- **Chain of custody** is already a vendor category in forensics. The
  ledger is a hash chain of *instructions*, not of reads, and it says
  what it does not prove. If you use the phrase, use it for `custody.py`
  and the key, or do not use it.
- **Right of first refusal** is also a real-estate and term-sheet term.
  That is a feature (operators have heard it) and a risk (they hear
  "option to buy"). The parenting sense is the one that maps: offered
  *before a third party*, not "first dibs on a purchase." The sentence
  has to carry "before the model," or the phrase is decoration.

---

## Where to spend it

| surface | use | do not use |
|---|---|---|
| README first screen | delete vs refuse; two-line handle; permission slip as the named method | in loco parentis, ROFR as an acronym |
| ten-second demo | sole custody of the deadline; the row still here, already unreachable | family-court nouns over the timeline |
| CISO / questionnaire | right of first refusal; stamped receipt you walk out with; `as_of` | permission slip (too school) |
| platform / SRE | admission controller; break-glass is the slip; withholding vs granting | parenting |
| MCP tool description | a document is admitted or it is absent, not low-ranked | any of this metaphor. The model gets verbs and fields. |

The appendix said philosophy loses to `I'll just be careful`. This is
not philosophy. It is a picture of a door, a slip, and a third party
who does not go first. Show the missing method. Then name what they
just saw.
