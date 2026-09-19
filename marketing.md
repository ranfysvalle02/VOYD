# VOYD

### Every database can delete. None of them can refuse.

**The right of first refusal — for your retrieval layer.**

---

## Your agent has perfect recall. That's the liability.

You built memory so it would remember. Congratulations: it remembers the
retracted figure, the leaked key, the customer who asked to be forgotten in
March, and a two-line summary of all three that it wrote itself.

Total recall is a feature for about a quarter. Then it's a subpoena.

The industry shipped **Retrieval-Augmented Generation** and skipped the
other half. This is the other half:

> ### Retrieval-Augmented **Forgetting**

---

## Delete is a wish. Refuse is a contract.

Here's the distinction nobody in retrieval draws, and it's the whole thing:

| | |
|---|---|
| **Deletion** | a *storage* event. Eventually consistent by nature. A TTL monitor sweeps about once a minute. A lifecycle rule runs about once a day. A cron runs whenever it last worked. |
| **Refusal** | a *retrieval* guarantee. Answered on every read, immediately, whatever the sweeper is doing. |

Between those two lives a window where your deleted data is still a
well-scored search result. Nothing logs it. Nothing pages. The failure
*looks exactly like the system working* — which is why you've never seen it,
and why it's been happening.

**Deletion is eventually consistent. Breaches are immediately embarrassing.**

---

## Your data isn't refuse. It's *refused*.

English handed us the pun and we took it. We don't take out the trash — we
decline to serve it.

```python
docs = engine.model("notes").forgettable()

await docs.find({})                       # cannot return a forgotten fact
await docs.search(vector, text="P0301")   # nor can the search path
await docs.including_refused().find({})   # the unsafe thing, named out loud

await docs.revoke({"_id": x}, reason="credential leaked")
# unreachable on the next read. The row is still on disk. That's the proof.
```

There is **no unfiltered read on that handle**. Not discouraged. Not
linted. Not in the style guide. *Absent.* The failure mode is inverted: you
used to have to remember to be safe, and now you have to declare that you
want the unsafe thing — in a word a reviewer can grep for.

---

## Forget-me-**now**

One word. Four scales. Identical semantics.

```
forget a fact          →  unreachable on the next read
forget a scope         →  and everything in it
forget a namespace     →  and every copy of it, everywhere
forget the summary     →  automatically, because it was made of the fact
```

That last one is the one that gets people. **An erasure defeated by a
paraphrase is not an erasure.** Revoke a source and the summary an agent
wrote from it goes too — and the summary of *that* summary, at any depth,
in one indexed query.

---

## Chain of custody. Custody of the chain.

Not a pun. A spec.

Every revocation is a link in an append-only **hash chain** — so *"this fact
stopped being reachable at 14:02, by alice@acme"* is a claim your auditor
can recompute, not one they have to take. No secret required. The actor is
hashed into the entry, so attribution can't be bolted on afterward.

And the key that wraps your keys is a **typed ladder**, not a dict somebody
assembled at a call site: `Ephemeral` → `LocalFile` → `AWS / Azure / GCP /
KMIP`. Your deployment can *print* its own custody story instead of a human
recalling it.

---

## "And your backups?"

The question a security reviewer asks four minutes in, and the one refusal
can't answer on its own. A restored snapshot doesn't run your read path.

So: **shred the key, keep the receipt.** A data key per scope, destroyed on
the deadline — and every copy of that ciphertext becomes noise at once. The
row. The replica. The snapshot. The backup nobody's restored since March.
Without visiting a single one of them.

Three layers, each honest about what it costs:

```
refusal          immediate     this read path only      unreachable now
crypto erasure   eventual      every copy, everywhere   unreadable soon
the TTL reaper   ~60s          this deployment only     gone eventually
```

Neither is the answer. **Both is.**

---

## Bon voyage, and bon oubli

**TTL: Time To Live. Also: Time To Leave.**

One `expire_at`. One owner. One TTL index. Not a Postgres row *and* a
Pinecone vector *and* an S3 object *and* a cron job pretending they agree —
that's four clocks and three ways to drift, and the drift *is* the bug.

Pinning is the absence of a deadline, not a second code path. Hybrid
retrieval plus expiry equals **recall with decay** — memory that forgets on
schedule, on purpose, on record.

---

## Null and voyd

- **The vector remembers what the text forgot.** Erase a document and its
  embedding is a lossy copy of it in a coat. We measured the leak. We
  destroy the vector in the same write.
- **An embedding is a `(vector, model)` pair.** Swap models at the same
  width and ranking doesn't degrade, it *inverts*: −0.053 for identical
  text, +0.301 for unrelated. Silently. We refuse the orphan instead of
  ranking it.
- **Latent space, latent liability.**
- **VOYD where prohibited.**

---

## Don't believe a word of this

Here's the part no other retrieval pitch will offer you: a list of what's
wrong with it.

[`ISSUES.md`](ISSUES.md) ships in the repo — defects, unproven claims and
imprecisions in what already works, each with what would close it. Including
the one that costs us something: **the enterprise KMS path has never been
run against a real KMS.** The shapes are unit-tested and share a code path
with the local rung. That is not the same claim, and we say so rather than
letting the feature list imply otherwise.

The rest is checkable without trusting us:

- **The tests run against a real MongoDB.** No mock tier. The properties
  here are only true if the *queries* are right, so CI stands up Atlas Local
  and runs against real `mongot`.
- **`drift/` runs the counter-argument.** `exhibit.py` stands up Postgres,
  Qdrant and MinIO and shows the deleted document answering a query.
  `refusal_on_postgres.py` ports the entire thesis to pgvector — no MongoDB
  in the file — and states plainly what is *harder* there.
- **The engine is one dependency.** `pymongo`. Read it in an afternoon.

Marketing that ships its own defect list is either confident or unwell.
**Read the issues first and decide.**

---

```bash
pip install voyd        # one dependency: a MongoDB driver
```

### Say no. Prove it.
