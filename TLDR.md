# TLDR

The short versions, at three lengths and for four rooms. Everything here
is argued at length somewhere else: [`AHA.md`](AHA.md) for the single
idea underneath all of it, [`pain.md`](pain.md) for the failures,
[`blog.md`](blog.md) for the reasoning, [`appendix.md`](appendix.md) for
the sell and its ceiling, [`PROPOSAL.md`](PROPOSAL.md) for what to be,
[`copy.md`](copy.md) for the words.

---

## One line

**Every database can delete. None of them can refuse.**

## One paragraph

Deletion is a storage event, so it is eventually consistent — MongoDB's
TTL monitor sweeps about once a minute (measured here: 60.0s), an S3
lifecycle rule runs about once a day, a cron runs whenever it last
worked. In that window your vector index keeps returning the deleted
document as a normal, well-scored hit, with nothing logged and nothing
to page on. Retrieval does not need a faster sweeper; it needs a
different guarantee — *this fact may not reach a prompt*, answered on
every read, immediately. That is **refusal**. Most stacks offer a
filter you must remember; this makes the filter structural.

## Thirty seconds

```python
docs = engine.model("notes").forgettable()

await docs.find({})                        # cannot return a forgotten fact
await docs.search(vector, text="P0301")    # nor can the search path
await docs.including_refused().find({})    # the unsafe thing, named out loud

await docs.revoke({"_id": x}, reason="credential leaked")
# unreachable on the next read. The row is still on disk. That is the proof.
```

There is no unfiltered `find` and no unfiltered `search` on that handle,
so the guarantee does not depend on the next author remembering it. The
failure mode is inverted: you used to have to remember to be safe, now
you have to declare that you want the unsafe thing, in a word a reviewer
can grep for.

---

## The load-bearing sentence

*Delete versus refuse* is the hook. This is the mechanism underneath it,
and it is the part a sceptical engineer actually needs:

> A retrieval rule has one authoritative form: a per-document check on
> the way **out**. Any query or index clause is an optional optimisation
> and must agree with it.

A `find` goes through a collection query; a `$vectorSearch` hit does
not. An index filter can express the same rule, but only if every read
path, fallback and future caller supplies it. [`AHA.md`](AHA.md)
derives why pushing the filter into the index is possible but
insufficient as the sole enforcement point.

## Why it reads as strange

Three of its central moves are the opposite of what the category does,
and each one is the reason it works.

**1. It deliberately does not delete.** The row stays on disk after
`revoke()`. The obvious response is faster deletion; this makes the fact
unreachable *now* and lets erasure stay on the deadline it already had.
Keeping the row is not a cleanup failure — it is the proof, and it is
also the forensics, which is why the same verb serves a subject erasure
request and a leaked credential that IR still needs to look at.

**2. The feature is a missing method.** Most products ship a filter you
apply. This ships a handle with nothing to forget to apply. The unsafe
read still exists, because audit needs it — it is just named
`including_refused()`, which is greppable, reviewable and embarrassing
to write. The repo's own history is the argument: six read paths in this
codebase forgot the deadline filter, written by someone who knew the
rule, in a codebase whose entire thesis is the rule.

**3. It publishes its own ceiling.** The guarantee binds one handle in
one process. `mongosh`, a BI tool, a replica, a snapshot on a laptop —
none of them run it. That is stated first rather than buried, answered
where it can be answered (destroy the scope key and every copy becomes
noise) and declared unanswerable where it cannot (a Slack quote, a
fine-tune). [`ISSUES.md`](ISSUES.md) lists what is wrong, unproven or
imprecise in what already ships.

The honest claim is *"we moved the failure from every call site to one
construction site"* — large, true, and defensible. Not "we made it
impossible."

---

## Pitches by room

**Engineer.** Ranking is not permission. Your retrieval answers with a
confident score and no idea whether that hit was supposed to be there —
an expired row the sweeper has not reached, a revoked fact, a vector
from the embedding model you swapped last quarter (measured: identical
text scores −0.053 across models, unrelated text +0.301, and a width
check catches neither). One handle, two enforcement points, every reason
reported by name.

**Platform / SRE.** One connection string instead of four systems with
four clocks. `health()` treats degraded as a first-class state.
Break-glass is a named method rather than a missing `AND`. If you want
the guarantee across languages, the collection is not your API — the
namespace is.

**Security / IR.** A credential leaks into a retrieval scope. You need
it out of prompts immediately and you need the row for the
investigation. Those are contradictory requirements for `DELETE` and the
same requirement for refusal: unreachable now, on disk until the
deadline, and every revocation is a link in an append-only hash chain.

**Compliance / the auditor.** *Show me this document stopped being
reachable at 14:02, and show me the record has not been edited since.*
A counter cannot answer that and neither can a log line held by the
party being audited. The requester walks away with a hash computed
before any dispute existed. And erasure survives paraphrase: revoking a
fact takes the summary an agent wrote from it, at any depth.

---

## What it is not

- **Not a memory product.** `memory` is one of five traits. The
  comparison set for memory is judged on recall; this is judged on what
  it refuses.
- **Not a guardrail.** Guardrails sit on the way *out* of the model.
  This sits on the way *in*.
- **Not a governance platform.** Those describe and attest. They are
  almost never in the read path. A catalogue can tell you a collection
  holds PII under a 30-day policy; it cannot stop the retrieval that
  happens on day 45.
- **Not a DSAR tool.** Those orchestrate the request and close a ticket
  when a system acknowledges the delete was *issued*. This answers the
  question they assume is already answered.
- **Not a faster sweeper.** A different verb.

---

## The one objection that matters

*"We'll just add `deleted: false` to the filter."* Three lines, no
dependency, ships this afternoon, and it is 90% correct. It fails only
in the paths somebody forgot — which is exactly the failure that is
invisible until it isn't, because a read path that forgets to filter
does not error, it returns more rows.

That is the real competitor. Not a vendor.

---

## Proof you can run

```bash
docker compose up -d mongo
uv run python examples/forget.py                      # ~10s, no API key
uv run python examples/quickstart.py                  # the lines a team actually adds

uv run --extra drift python drift/exhibit.py          # the counter-argument
```

The first watches a document become unreachable while its row is still
on disk, then watches the reaper take the row and its vector together.
The second is the on-ramp: refusal on one collection, find-only, under
ten lines. The third stands up Postgres, Qdrant and MinIO with their real
mechanisms — a cron `DELETE`, a real S3 lifecycle rule, Qdrant's real
delete API — and the deleted document answers the query at score 1.0000.

Everything is asserted against a real MongoDB on every commit. There is
no mock tier, because these properties are only true if the queries are
right.
