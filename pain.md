# The pain

Eight stories. Most of them are not hypotheticals — they are incidents from
this repository, or numbers measured in it, with the file that closes each
one named at the end. A pain document made of things that might happen is
a brochure.

---

## I. The data you deleted

### The document that answered after it was deleted

You call `delete_one`. The API returns. The row is gone from your
application's point of view, and the ticket is closed.

Your vector index does not know that. A TTL monitor sweeps about once a
minute — **measured at 60.0s** — an S3 lifecycle rule runs about once a day,
and a cleanup cron runs whenever it last worked. In that window the fact is
still in the index, still ranking, and it comes back as a normal,
well-scored result. Nothing is logged. There is no error to page on, no
metric that moves, and no line in any dashboard that distinguishes it from a
correct answer.

The window is the bug, and it is invisible by construction: the failure
looks exactly like the system working.

→ Refusal is answered on every read, immediately. `voyd/engine/admission.py`

### The erasure that a summary defeated

A subject asks to be forgotten. You revoke the source document. Your
receipts are clean, your audit log is clean, and your lawyer is satisfied.

Six weeks earlier, an agent read that document, wrote a two-line summary,
and stored the summary in the same collection — because that is what agent
memory *is*. The summary quotes the fact. It has its own id, its own
embedding, and nothing connecting it to the thing you just erased.

It will keep answering queries for as long as the collection exists. The
erasure request was honoured against the source and defeated by the
paraphrase, and every artefact in your system says the erasure worked.

→ A refusal travels down the derivation edge, at any depth, in one indexed
query. `derive()` in `voyd/engine/admission.py`

### Four owners of one deadline

Postgres holds the row. Pinecone holds the vector. S3 holds the bytes. A
cron job is supposed to keep the three agreeing.

That is four clocks and three ways to drift, and the drift is not an edge
case — it is the steady state. The vector outlives the document. The bytes
outlive the row. Each service is behaving correctly and the *system* is
serving deleted data, so there is nobody to escalate to and nothing to fix,
only a runbook that gets longer.

The failure is architectural, which is why adding monitoring does not help:
you would be monitoring four systems that are each individually fine.

→ `drift/exhibit.py` stands all four up and runs it, rather than asserting it.

---

## II. The answers you gave

### The page that came back empty, and was not

A scope holds 46 documents. Forty are past their deadline and six are live.
A caller asks for five.

The naive read fetches `limit * 2`, filters out the expired ones, and
returns what survives — **zero hits**. Six live, indexed, on-disk documents,
reported as an empty scope. The caller's model then answers *"I don't have
information about that,"* confidently, and the user believes it.

This shipped. It was caught by a deployment check written alongside it,
which also flagged a *healthy* page on its first run and taught us that
"short" and "short **and** withholding" are different states.

→ `Page.starved` is set only when candidates remained, and the page is
refilled from the refusal rate just measured.

### The upgrade that inverted the ranking

You move to a newer embedding model. Same vendor, same 1024 dimensions, so
the index accepts every vector without complaint.

Measured against the real API, same text, both 1024-wide:

```
identical text, old model vs new       cosine  −0.053
unrelated text, both on the new model   cosine  +0.301
```

A model swap does not degrade ranking. It **inverts** it — unrelated text
outranks the document you were looking for, by five times. The width check
that catches a 512-in-1024 mistake catches none of this, because the widths
match. Nothing errors, nothing logs, and `describe()` looks healthy.

→ An embedding is a `(vector, model)` pair. A row embedded by anything else
is refused, not ranked. `EmbeddedWith`

---

## III. The questions you cannot answer

### "And your backups?"

You explain that the row is deliberately still on disk — unreachable first,
erased second, because the reverse order is the bug. The engineer in the
room nods.

The security reviewer writes it down as a finding, and they are right.
Refusal is a property of *your application's read path*. A restored snapshot
does not run your application's read path. Neither does a replica, a
nightly export, or the laptop somebody pulled a dump onto in March.

Every one of those holds the plaintext, and no amount of correctness in
your query layer reaches any of them.

→ A key per scope. Destroying it makes every copy unreadable at once,
without visiting one of them. `voyd/engine/keyring.py`

### The vector that remembers what the text forgot

You encrypt the sensitive field. You shred the key. The ciphertext is noise
everywhere, including in the backups.

The embedding is sitting in the same document, unencrypted — because
encrypting it would end vector search.

An embedding is a lossy encoding of the text it came from. Measured here,
before it was fixed: after a revocation, the surviving vector still
separated its own topic from another by **0.9988 against 0.7992** cosine.
That is a working membership oracle over somebody who asked to be
forgotten, and it needs no inversion model to use — you ask the index
whether a document about X is in there, and it says yes.

→ An irreversible reason destroys the derived encodings in the same write.
A reversible one does not, because a held document is evidence.

### "Who released it?"

An injection detector flags a document. It is held back from prompts.
Later, somebody puts it back.

Three months on, during an incident review, you go looking. Your chain can
tell you the document was quarantined at 14:02 and released at 14:05, with
the stated reason. It cannot tell you **by whom** — so the strongest
sentence available is *"somebody released the document the detector
flagged."*

Worse, until recently nothing stopped the indexing pipeline from being that
somebody. Releasing a flagged document sat behind the same credential as
searching the scope, because there was a question nobody had asked: not
*may this caller read this*, but *may this caller do this*.

→ `Authority` gates the verbs asymmetrically — withholding and granting are
not equally dangerous — and the actor is hashed into the chain entry, so
attribution cannot be attached afterwards.

---

## What all eight have in common

None of them raise. None of them page. Every one of them produces output
that is indistinguishable, at the moment it happens, from the system
working correctly.

That is the category: **failures whose signature is a plausible answer.**
You cannot monitor your way out of one, because there is nothing anomalous
to observe — and you cannot test your way out by looking, because looking is
what the failure defeats.

So the response is structural rather than vigilant. The unfiltered read does
not exist. The plaintext write is refused by the server. The mark travels
down the edge on its own.

And where a claim cannot be made structural, it is stated rather than
implied — [`ISSUES.md`](ISSUES.md) lists what is unproven in what already
ships, and `drift/` runs the counter-argument instead of asserting it.
