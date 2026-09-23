# Why not just use what MongoDB already has?

*Change streams, `$where`, `$function`, views, `$$USER_ROLES`, TTL
indexes, RBAC, Queryable Encryption — what each one actually gives you,
and where the line is.*

This is the first question any competent MongoDB engineer asks, and most
of these mechanisms are good. Several are better than VOYD at the thing
they were built for. This document tries to be fair enough to be useful,
including in the places where the honest answer is *"use the native
thing."*

---

## The axis that explains all of it

Two questions sort every mechanism here, and almost nothing else matters:

1. **Who supplies the rule?** The caller, or the server?
2. **When does it run?** Before the read, during it, or after?

A rule the *caller* supplies is not a boundary, however good it is,
because the caller can supply a different one. A rule that runs *after*
the read is not a boundary either, because the read already happened.

|  | caller-supplied | server-supplied |
|---|---|---|
| **before/during the read** | `$match`, `$where`, `$function`, `$redact`, `$vectorSearch.filter` | **views**, RBAC, VOYD |
| **after the read** | application code | change streams, triggers, TTL |

Everything in the top-left is a convention. Everything in the bottom row
is a reaction. **The bottom-right cell is the only one where a guarantee
can live**, and MongoDB genuinely has something there — views — which is
why that section is the longest one below.

---

## Change streams

**What they are for.** Telling you a write happened, in near real time,
resumably. They are excellent at this and VOYD does not compete with it.

**Why they cannot be the boundary.** A change stream fires *after* the
write is durable. Everything between the write and your handler running
is a window in which an ordinary read returns the document — and closing
that window is the entire job. Using a change stream to enforce erasure
means: the document is written, it is readable, your handler wakes, and
*then* it is not. That is a faster sweeper, not a refusal.

    deletion / reaction   a storage event      eventually consistent, by nature
    refusal               a retrieval promise  immediate, by construction

**And a change stream is itself a read path.** This is worth dwelling
on, because VOYD got it wrong and shipped the bug.

A change event is not a document:

```js
{ _id: <resumeToken>, operationType: "update",
  ns: { db: "app", coll: "notes" },
  documentKey: { _id: 1 },
  fullDocument: { ...the entire document... } }
```

Every rule in VOYD reads **top-level** fields. An event has no top-level
`expire_at` and no top-level `forgotten`, so a deadline read as "no
deadline, pinned" and a mark read as absent. Both admitted. The whole
forgotten document rode out inside `fullDocument`. Measured before it
was closed:

```
as an ordinary document:    []
as a change stream event:   fullDocument leaked: 'SENSITIVE'
```

`voyd-wire` now **refuses** a change stream over a guarded collection
rather than filtering one, and the reason it refuses instead is the
interesting part: unwrapping `fullDocument` fixes one field and leaves
three. `fullDocumentBeforeChange` carries the prior copy.
`updateDescription.updatedFields` carries changed values verbatim. And a
`delete` event carries `documentKey` for a row whose deletion is the
very thing a revocation exists to hide — including with `fullDocument`
switched off, which is the default people assume is safe.

A partial fix would have been the thing this project is named after: a
guarantee that looks total with a hole nothing announces.

> **If you need change streams on a guarded collection, open them on a
> connection that goes straight to the deployment.** There they are a
> write-notification channel, which is what they are for. They are not a
> way around the boundary, and VOYD will not pretend to filter them.

---

## `$where` and `$function`

**What they are.** Server-side JavaScript in a query predicate or an
aggregation expression. You can absolutely write
`$where: "this.expire_at > new Date()"`.

**Why it is not a boundary, and this is the whole point:** *the client
wrote that string.* It is in the query. A caller who omits it gets
everything, and omitting it is not an error, an anomaly, or a thing
anybody will notice — see the rest of this repository on why a read that
returns *more* is the failure nobody catches.

That is the same objection that applies to `$match`, `$redact`, and
`$vectorSearch`'s `filter`. They are all excellent **optimisations** and
none of them is an authorization answer, because the authorization
answer cannot be a parameter the caller passes.

The practical objections are real too, and worth knowing:

- Server-side JS must be enabled (`security.javascriptEnabled`) and is
  **disabled on several Atlas tiers**. Building a security control on a
  feature your platform may not offer is a bad trade.
- `$where` cannot use an index, so it is a collection scan.
- It is a well-understood injection and denial-of-service surface.

But none of those is the reason. The reason is that it is caller-supplied.

**Where it genuinely wins:** expressing a predicate too gnarly for MQL,
in a trusted internal job. That is a real use and VOYD has nothing to say
about it.

---

## Views — the strongest native answer

This one deserves a fair hearing, because it is the closest thing
MongoDB has to what VOYD does, and for a large class of problems **it is
the right answer and you should use it.**

```js
db.createView("notes_live", "notes", [
  { $match: { expire_at: { $gt: "$$NOW" }, forgotten: { $exists: false } } }
])
```

Grant a role read on `notes_live` and *not* on `notes`, and you have a
server-enforced, non-bypassable, caller-independent filter. The caller
cannot omit it, because the caller cannot reach the base collection.
That is a genuine boundary in the bottom-right cell, and it costs you
nothing to run.

MongoDB 7.0+ also gives view pipelines `$$USER_ROLES`, so a view can
branch on the caller's roles — which is real row-level security,
natively, and a lot of teams should be using it and are not.

**Where views stop.**

- **They cannot express a set-relative rule.** `budget(8000)` and
  `distinct()` refuse a document because of the *other documents on the
  page* — the same document admitted alone and refused in company. A
  view pipeline is evaluated per document against the collection, and
  there is no "page" at that point to be relative to.
- **One view per shape.** Every combination of collection, filter and
  audience is another view to create, name, grant, and keep in sync with
  the others. A policy file is one declaration read by one boundary; N
  views are N declarations and no single place that says what the
  boundary *is*.
- **Nothing diffs them.** Nobody can tell you what editing a view
  definition would make newly reachable, because the enforcement only
  exists inside a running server with that definition installed. This is
  the purity dividend, and it is not a small one — see
  [`../genius.md`](../genius.md).
- **Page shaping still lives outside.** Your reranker runs after the
  view, in application code, where it can put back what the view removed.
- **Cross-language uniformity is on you.** A view is bypassed by anyone
  with permission on the base collection, so the guarantee is only as
  good as your grant hygiene across every service, notebook and admin
  user. VOYD binds the *connection*, so there is no base collection to
  accidentally grant.
- **`$vectorSearch` on a view is a moving target.** Support has changed
  across recent versions; check your deployment rather than this
  document. VOYD's per-document check runs on search hits by
  construction, because a hit never passes through a collection query at
  all.

> **Honest recommendation:** if your rule is a static per-document
> predicate, you control every grant, and you do not need to diff
> changes — **use a view.** It is free, native, and one less process.
> VOYD earns its place when the rule depends on the rest of the page,
> when you want the change reviewed before it ships, or when you cannot
> guarantee nobody has permission on the base collection.

---

## TTL indexes

**What they are for.** Reclaiming disk. They are good at it.

**The window.** The TTL monitor runs about once every 60 seconds, and
deletion is not instant even then. During that window the document is
genuinely, correctly on disk and a search returns it as a well-scored
hit. Nothing is broken; the sweeper has not arrived.

VOYD's `deadline()` is the same *field*, read on the read path. Use
both: the deadline refuses it now, the TTL index reclaims the bytes on
the schedule it already had. `on_delete="revoke"` even pulls the
deadline in so the reaper collects sooner.

Measured rather than assumed — see [`../examples/drift.py`](../examples/drift.py),
which runs against a local `mongod` in about thirty seconds.

---

## RBAC and field-level access

MongoDB's role system is excellent at *collection*-level and
*action*-level authorization. It has no native document-level concept:
there is no `GRANT SELECT ... WHERE tenant_id = ...`.

Views plus `$$USER_ROLES` is the native way to approximate one, covered
above. RBAC itself is a prerequisite for everything here — VOYD does not
replace it, forwards the handshake untouched, and asks the *deployment*
who authenticated rather than believing a claim the client asserts.

---

## Queryable Encryption and CSFLE

The strongest native primitive on this page, and it answers a question
refusal **cannot**.

Refusal binds one read path. It has nothing to say about a replica, a
snapshot, or a backup restored in eighteen months, because none of those
runs it. Destroy the key and every copy is unreadable at once, including
the copies you do not know about.

    refusal          immediate    this application's read path
    crypto erasure   ~60s         every copy that exists anywhere

Each one's window is the other's guarantee, which is an argument for
both, in that order: unreachable first, unreadable second. VOYD's
`sealed()` integrates with this rather than competing — and it is honest
that holding keys costs the boundary its purity.

---

## The summary table

|  | refuses a read? | server-enforced? | survives a client that ignores it? | set-relative? | diffable before deploy? |
|---|---|---|---|---|---|
| `$match` / `$vectorSearch.filter` | yes | no | **no** | no | no |
| `$where` / `$function` | yes | no | **no** | no | no |
| **view (+ grants)** | **yes** | **yes** | **yes** | no | no |
| change stream | **no** | n/a | n/a | no | no |
| TTL index | no (~60s) | yes | yes | no | no |
| RBAC | collection-level | yes | yes | no | no |
| Queryable Encryption | n/a (unreadable) | yes | yes | no | no |
| **VOYD** | **yes** | **yes** | **yes** | **yes** | **yes** |

Read the last two columns as the honest answer to "what is actually
new." Everything else in VOYD's column, a well-built view gets you.

---

## So what is genuinely only here?

Three things, and they all come from the same property — the check is a
pure function with no database under it.

**Set-relative rules.** `budget(n)` refuses because of the page, not the
document. No index filter can express that; `$vectorSearch` decides each
candidate before the page exists. No policy engine can either;
`enforce(subject, object, action)` has nowhere to put the rest of the
set.

**Answers before deployment.** `voyd-plan` diffs two policies, and
`voyd-plan --audit` reports what is reachable on your cluster *today*
that a policy would refuse — from a read-only URI, with nothing
installed. A view's enforcement exists only inside a running server, so
there is nowhere to stand to ask it.

**Page shaping inside the boundary.** Your reranker runs *before* the
terminal admission pass, so it cannot widen a read no matter what it
returns. With a view, the reranker is downstream and can undo it.

---

## The part worth taking away

None of these mechanisms is wrong. Each one is the right answer to the
question it was built for, and this document would be dishonest if it
pretended otherwise.

What none of them is built for is the specific question *may this fact
reach a prompt?*, asked on every read path including the one that never
goes through a query, with an answer declared once in a file that is not
your application.

And the shared failure mode is the one this whole repository is about: a
filter the caller supplies, a sweeper that has not run, a view somebody
has permission to route around, a change stream whose payload nothing
inspects. Each is **a statement of intent doing the work of a
guarantee** — true when written, unchecked since, and silent in the
direction of returning more.

---

*The argument for the wire: [`ranking-is-not-permission.md`](ranking-is-not-permission.md).
The story: [`../blog.md`](../blog.md). The strongest single fact and its
limits: [`cosine.md`](cosine.md).*
