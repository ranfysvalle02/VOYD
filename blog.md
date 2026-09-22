# Ranking is not permission

There is a question your retrieval layer is never asked.

A vector index answers *what is most relevant to this?* — brilliantly,
approximately, in single-digit milliseconds. It does not answer *may this
fact reach a prompt?*, because nothing in the shape of an index has anywhere
to put that question. So the answer gets supplied elsewhere: a tenant filter
in the query, an `expire_at` clause beside it, a check in the service layer,
a second check in the notebook somebody wrote for the analytics team.

Each of those is correct the day it is written. The problem is that there is
no *one* of them.

## The failure returns more rows

Consider what happens when one is missing.

A missing authorization filter does not raise. It does not log. It returns
*more* documents rather than fewer, and on a retrieval workload more
documents look like better recall. There is no error to page on, no latency
spike, no failed assertion. The dashboard is green while a revoked
credential sits in somebody's context window.

Compare that to the equivalent bug anywhere else in the stack. Miss an
`WHERE org_id = ?` in SQL and somebody notices, usually quickly, because
relational results are *counted* and *joined* and the wrong cardinality
propagates into something a human reads. Miss an auth middleware on an HTTP
route and your integration tests 200 where they should 403.

Retrieval has neither property. The output is a ranked list of plausible
text, consumed by a language model that will happily summarize whatever it
is given. The wrong document does not look wrong. It looks like an answer.

## Deleting the row is not the fix

The obvious objection is that forgotten facts should not be in the index at
all. Delete them.

MongoDB's TTL monitor runs about once a minute. S3 lifecycle rules run about
once a day. Your cron runs whenever it last worked. In every one of those
windows the document is genuinely, correctly still on disk — nothing is
stale, nothing is broken, the sweeper simply has not arrived — and a search
returns it as a normal, well-scored hit.

This is not an implementation detail you can optimize away. It is the
category the operation belongs to:

    deletion   is a storage event      eventually consistent, by nature
    refusal    is a retrieval promise  immediate, by construction

A faster index does not close the gap, because the index is not wrong. A
faster sweeper only narrows it, and narrowing a disclosure window is a
strange thing to call a fix. The only operation that is immediate is the one
that happens on the read: *may this reach a prompt?*, answered before
anything is returned, whatever the sweeper is doing.

Delete is a wish. Refuse is a contract.

## A guarantee you can forget to apply is a suggestion

So you add the check. Re-reading a deadline on the way out is four lines,
and the author who just learned this lesson will write those four lines
correctly in the read path they were thinking about at the time.

Then the service grows a second read path. Then an analytics job in a
different language. Then a notebook, a migration script, an MCP server
somebody stood up on a Friday, an agent framework that does its own
retrieval. The rule is now only as good as the next author's memory of a
conversation they were not in.

This is the part I want to insist on, because it is the whole argument and
it is easy to nod past: **a rule you have to remember to apply is not
enforced, it is suggested.** Every enforcement mechanism that actually works
in a mature stack has the property that you cannot route around it by
forgetting. Kernel permission bits are not a convention. Row-level security
is not a code review checklist. They sit below the thing that would forget.

Retrieval has no such layer. That is the gap.

## Put it where the connection is

Which brings the question round to placement, and placement turns out to be
the entire design.

A library is the natural instinct — `from voyd import guarded_find` — and it
fails the test above immediately. A library is a thing a call site imports,
which makes it a thing a call site can decline to import. It also binds you
to one language, and the second retrieval path in an organization of any
size is rarely in the first language.

A sidecar or a framework middleware is better and still leaky: it governs
the traffic that goes through it, and the notebook connects directly.

The one place every read passes through, in every language, from every tool
— including Compass, including the shell, including code written next year
by somebody who has never read your policy file — is **the connection**. So
the boundary goes on the wire: a proxy speaking MongoDB's protocol, with the
policy declared in one file that is not your application.

```python
# voydfile.py
from voyd import guard, deadline, revocable, tenant

@guard("notes", on_delete="revoke")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()
```

```bash
voyd-wire --config voydfile.py --target localhost:27017
```

Change one connection string. Nothing is imported, no handle replaces a
collection, no read path is rewritten. The failure mode inverts: before, you
had to remember to be safe; now you have to deliberately connect somewhere
else.

## What the wire costs you, and what it buys

It is a process. It is a hop, a thing to deploy, a thing that can be down,
and one more participant in your failover story. Those are real and I will
not pretend the diagram got simpler.

What it buys is that the per-document check has to be **pure** — no
database, no connection, no I/O, just documents in and the admissible ones
out. That constraint is forced by the placement, and it turns out to be the
most valuable thing about the design, for a reason that has nothing to do
with performance.

A `$vectorSearch` hit does not pass through the collection query.

Read that again if you have ever pushed a filter down into an index and
considered the matter closed. The filter you added to your `find` does not
run on the search path. Which means every pushed-down clause is an
optimization — cheap work the database does on your behalf — and the
per-document check on the way out is the actual guarantee. Both halves
exist; only one of them is load-bearing. The asymmetry runs one way only: a
rule with no query half is merely slower, and a rule with *only* a query
half is a hole.

## A rule is a protocol, not a list

Once refusal is a per-document function, the interesting question stops
being "what reasons ship?" and becomes "what shape is a reason?"

Three members: a `reason` that names it, `refuses(doc)` that decides, and
`clause()` that offers the query half or `None`. Deadlines and revocations
are two implementations. So is a clearance ladder, an embedding-model check,
and a jurisdiction rule you write yourself in the policy file with no
privileged path for the builtins.

And then the category turns out to be bigger than access control, which is
the part I did not expect. A *token budget* is the same shape: `may this
reach the prompt?`, answered `no, there is no room`. So is a de-duplicator:
`no, that passage is already in the context`.

Those two are strange in a way worth naming. They are **set-relative** —
they refuse a document because of the *other* documents on the page, so the
same document is admitted alone and refused in company. Nothing else in the
stack can express that. `$vectorSearch` decides each candidate before the
page exists. A policy engine's `enforce(subject, object, action)` has no
argument for the rest of the set. The usual answer is a de-duplication pass
bolted on after retrieval, outside whatever governs the read — which is the
second enforcement point all over again, the one that gets forgotten.

## The embedding is not the vector

One more, because it is the failure I find most unsettling and the one
nothing warns you about.

An embedding is a `(vector, model)` pair. A vector without its model is an
orphan, and comparing orphans does not fail — it returns a number between -1
and 1. Measured on a real API, the same text, both 1024-wide, two
generations of one vendor's model:

```
identical text, old model vs new       cosine -0.053
unrelated text, both on the new one    cosine +0.301
```

A model swap does not degrade your ranking. It *inverts* it. Unrelated text
outscores the right answer by five times, with no error, no log, and a
perfectly healthy-looking health check. And when two models share a width —
as a whole generation of them does — the dimension check that catches a
512-in-1024 mistake catches none of this.

So the model is part of what a document *is*, and a row embedded by anything
else is refused rather than ranked. Better still, let the server own the
encoding: the index holds text, mongot embeds it on write and embeds the
query with the same model at read time, and nothing in your process ever
computes a vector that could drift.

At which point a client sending its own `queryVector` has put the embedder
back, through a driver that never read your policy file. That caller is
exactly who the boundary is for, so it is refused by name and told which
form works.

## What refusal cannot do

Refusal binds *this* read path. It has nothing whatsoever to say about a
replica, a snapshot, or the backup somebody restores in eighteen months —
none of those run it.

I would rather say that here than have you discover it. The answer is
cryptographic: a key per tenant, so destroying the key makes every copy
unreadable at once, everywhere, including the copies you do not know about.
That one is not immediate — a reader that decrypted a moment ago keeps
decrypting until its key cache turns over, about a minute — which is
precisely the window refusal covers.

    refusal          immediate    this application's read path
    crypto erasure   ~60s         every copy that exists anywhere

Each one's window is the other's guarantee. That is an argument for having
both, in that order: unreachable first, unreadable second.

## The generalization

The thesis underneath all of this is larger than vector search, and it is
the reason I keep finding the same bug in unrelated places:

| the intent | the window it actually has |
|---|---|
| `delete` removes the fact | ~60s of TTL monitor lag |
| a destroyed key makes it unreadable | ~60s of key cache |
| a replica's copy is current | unbounded replication lag |
| the index embeds with the declared model | nothing ever asks it |

Four subsystems, one defect: a statement of intent doing the work of a
guarantee. The gap between *what you declared* and *what is verified* is
where every one of these lives, and it does not announce itself, because
declaring something is exactly what makes you stop checking it.

A retrieval boundary does not fix that in general. It fixes it in the one
place where the consequence is a fact reaching a model that was not supposed
to have it — and it does it by making the check impossible to forget, which
is the only kind of check that survives contact with a growing codebase.

Ranking is not permission. Somebody has to ask the second question, once,
somewhere nobody can route around.

---

*VOYD is MIT-licensed and the code is at
[github.com/ranfysvalle02/VOYD](https://github.com/ranfysvalle02/VOYD).
Nobody has run it but its author; every number above comes from one machine
and one cluster.*
