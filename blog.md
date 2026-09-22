# Every bug in this story is disguised as its own opposite

*Building a retrieval boundary, and then watching the genre eat the tool.*

---

There is a particular kind of bug that does not announce itself, does not
raise, does not page anyone, and makes the graph go up.

Three of them are in the problem I set out to solve. One is in the thing
I built to solve it, which I did not plan and would not have believed in
advance. And somewhere in the middle, a constraint I had filed under
*cost* turned out to be the only reason the two best things in the
project are possible — including one that lets you run a stranger's
reranking code inside an authorisation boundary and still make a
guarantee about it.

## Exhibit A: the filter you forgot returns more rows

Somewhere in your codebase is a retrieval call with a tenant filter on
it. Somewhere else is the one without.

Consider what the second one does when it runs. It does not throw. It
does not log. It returns *more* documents than it should, which on a
retrieval workload is indistinguishable from the thing you have been
trying to achieve all quarter. Recall went up. The eval suite, which
measures whether the right documents came back and not whether the wrong
ones did, is delighted.

This is unusual. Most of the stack has the decency to fail in the
direction of *less*. Drop a `WHERE org_id = ?` in SQL and the cardinality
goes wrong somewhere a human eventually reads. Forget auth middleware on
an HTTP route and your tests 200 where they should 403 — a red test, a
diff, a Tuesday.

Retrieval gives you a ranked list of plausible prose, handed to a model
that will cheerfully summarise whatever it is given. The wrong document
does not look wrong. It looks like an answer. It looks, specifically,
like a *good* answer, because the index ranked it highly, and the index
is not broken. The index was asked which documents are most relevant and
it told you, accurately, at some speed you would put in a slide.

Nothing asked the other question.

## Exhibit B: `delete` is a wish with good branding

The obvious reply is that forgotten facts should not be there to be
found. Delete them.

Fine. MongoDB's TTL monitor runs about once a minute. An object-lifecycle
rule runs about once a day. Your cleanup cron runs whenever it last
worked, a fact you will learn more about later.

In every one of those windows the document is genuinely, correctly, still
on disk. Nothing is stale. Nothing is broken. The sweeper simply has not
arrived yet, because sweepers arrive when they arrive, and a search
returns the document as a perfectly ordinary, well-scored hit.

You cannot optimise your way out of this, because it is not an
inefficiency. It is a category:

    deletion   is a storage event      eventually consistent, by nature
    refusal    is a retrieval promise  immediate, by construction

A faster index does not help; the index is not wrong. A faster sweeper
narrows the window, and narrowing a disclosure window is a strange thing
to describe as a fix. There is exactly one operation that is immediate,
and it happens on the read.

## Exhibit C: the orphan vector, or, cosine has no opinions

This is my favourite, in the sense that it keeps me up.

An embedding is not a vector. An embedding is a `(vector, model)` pair,
and a vector without its model is an orphan. The trouble is that
comparing orphans *works*. It does not error. It returns a number
between -1 and 1, like a professional.

Measured against a real embedding API — same text, both 1024 dimensions,
two generations of one vendor's model:

```
identical text, old model vs new       cosine -0.053
unrelated text, both on the new one    cosine +0.301
```

Read those twice. A model swap does not gently degrade your ranking. It
**inverts** it. Unrelated text outscores the document you were actually
looking for by a factor of five, with no error, no log, and a health
check the colour of spring.

And the dimension guard you are thinking of — the one that catches a
512-wide vector in a 1024-wide index — catches precisely none of this,
because a whole generation of models shares a width. The safety net is
real and the fall goes around it.

## The pattern, stated once

Three failures, one genre. **Each is disguised as the good outcome
nearest to it.**

| what went wrong | what it looks like |
|---|---|
| authorisation filter missing | better recall |
| the row is still there | the sweeper is fine, and it is |
| embeddings from two models | a ranking, of the usual shape |

This is why the problem is hard, and it is not because any individual
piece is subtle. Each one is obvious once stated. They are hard because
**the feedback signal points the wrong way.** Nothing in your monitoring
is built to be suspicious of good news.

## So you put the check somewhere it cannot be skipped

If a rule can be forgotten, it is not enforced, it is *suggested*. That
disposes of the library — `from voyd import guarded_find` is a thing a
call site imports, which makes it a thing a call site can decline to
import, and it binds you to one language besides. The second retrieval
path in any organisation is rarely in the first language. It is usually
in a notebook.

The one place every read passes through — every driver, every language,
Compass, the shell, the migration script, the MCP server somebody stood
up on a Friday, the agent framework that does its own retrieval, code
written next year by somebody who has never heard of your policy file —
is **the connection**.

So the boundary goes on the wire. One file that is not your application,
and one changed connection string:

```python
# voydfile.py
from voyd import guard, deadline, revocable, tenant

@guard("notes", on_delete="revoke")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()
```

The failure mode inverts, which is the entire point. Before, you had to
remember to be safe. Now you have to deliberately connect somewhere else.

## The tax that turned out to be an inheritance

Putting the check on the wire imposes a constraint that felt, at the
time, like a tax: the per-document check has to be **pure**. No database
underneath it, no connection, no I/O. Documents in, the admissible ones
out. A proxy cannot phone home in the middle of a cursor batch.

I want to be honest that I accepted this as a cost.

Then, some weeks later, a question arrived that I could not have asked
otherwise: *what would this policy change actually let through?*

Because here is the thing about a policy file. It gets reviewed like
every access-control config gets reviewed — somebody reads the diff and
forms an opinion. The diff says a line was deleted. The diff does not say
that forty-one thousand documents just became reachable, and neither will
anything downstream, because — see Exhibit A — the boundary opening wider
does not look like a problem. It looks like recall.

But if the check is pure, it is just a function. And a function can be
asked about a policy that is not deployed. Or about an instant that is
not now.

```
$ voyd-plan --current voydfile.py --proposed voydfile.new.py \
            --target $URI --database app --all

the boundary moves, in the admitting direction
  notes  tenant_removed
    reads were scoped by 'tenant_id' and no longer are: a read can
    return documents belonging to any tenant

documents that become reachable
  notes  +9 of 200 read
           9  were refused as revoked

200 documents, read
newly reachable: 9
```

Exit code 1. Which makes it a pull request check.

A design decision I had filed under *compromise* turned out to be the
only reason this feature can exist. If enforcement lived inside the
query, there would be nowhere to stand to ask the question except the
production cluster, and no way at all to ask it about a policy the
cluster has never seen.

I did not earn this and did not see it coming. **Purity was not a virtue
I was practising. It was a constraint the placement forced, and it paid
a dividend I could not have designed for.**

Then it paid a second time, and the second one is bigger.

## The thing everybody builds outside the boundary

Every retrieval stack has a step after the search: rerank, de-duplicate,
serve from cache. It lives in application code, downstream of whatever
governs the read, and being downstream is the whole problem — anything
after a filter can undo it.

Almost never on purpose. It merges a cached list, and the cache did not
run a policy. It falls back to the unfiltered candidate pool because an
empty page looked like a bug to whoever wrote it. It reorders a list it
was handed by reference. The filter ran, correctly, and then something
ran after it.

The reflex is to review that code. The better answer is to make the
review unnecessary, and the pure check is what makes it possible:

```
pure rules  →  your transform  →  every rule, terminally  →  the wire
```

Put the reranker *inside*. The authoritative check is cheap — single
microseconds per document — so it can run again, last, on whatever the
transform returned. Reordered, merged, restored from a cache, invented
outright: all of it is checked before it leaves.

```python
# voydfile.py — the security rule and the magic rule, one file
@guard("notes")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()

rerank("notes", diversity=0.3)
```

> **A transform cannot widen what a read returns.** Not because it was
> reviewed. Because the boundary is downstream of it.

I wrote a test to try to break this, and I wrote it to win. A policy file
whose transform exists for no reason other than to inject forgotten
facts, a real `voyd-wire` subprocess, and a `pymongo` client that has
never heard of this package:

```python
@transform("notes")
class PutItBack:
    name = "hostile"

    def on_egress(self, docs, *, request):
        return list(docs) + [expired_document, revoked_document]
```

The transform is not disabled, not sandboxed, not reviewed. It runs. It
returns the documents. They do not arrive.

Eighteen more of those run without a cluster: a cache merge, an
empty-page fallback, a body swap that keeps the admitted document's
`_id` and replaces everything else, a launder that strips the revocation
mark before handing it back. The boundary does not care which one it is
looking at, because it is not looking — it is asking the same pure
question it asks every document, after everybody else has had their
turn.

The inversion in the pitch is the part I like. Security's objection to a
programmable proxy is *"unvetted code modifying data in flight."* Here
that is the feature: your unvetted code is the safest place it has ever
run, because for the first time it is inside the thing that would have
caught it.

## Three questions it refuses to answer

The temptation with a tool like this is to produce a number for
everything, because a number looks like coverage. It declines in three
places, by name, in the output.

`budget()` and `distinct()` are *set-relative* — they refuse a document
because of the **other** documents on the page, so the same document is
admitted alone and refused in company. A sample is not a page. Evaluating
them one document at a time would not be a weaker answer; it would be a
confident answer to a different question.

`clearance()` and `restricted_to()` decide by who is asking, so they are
planned only against callers you name — which is how you get *"this
change exposes 412 documents to tier1-support, and nothing to anyone
else"* instead of a single number nobody can act on.

And the tenant is enforced by the handle rather than by a rule, so the
plan reports that the boundary *moved* and does not claim to know which
rows crossed it.

A tool that quietly folded any of those into a total would be this
project's own complaint one level up: something that looks complete with
a hole in it that nothing announces.

## Exhibit D: in which the genre comes for the tool

A check nobody runs is a man page. So `voyd-plan` became a GitHub Action,
because the moment the answer matters is the moment somebody is reading a
diff and deciding whether one deleted line is fine — and at that moment
the tool was in a terminal, being excellent, unobserved.

I tested it properly. I built a throwaway repository, extracted the
steps out of `action.yml`, and ran the actual shell rather than my
description of it. I found and fixed three things doing that, one of
which was that the YAML did not parse at all.

Then I opened a real pull request, and it failed.

Not *failed* as in "correctly reported a fail-open." Failed as in: no
report, no comment, no output, exit 1 from the shell, nothing to read.

Here is what happened. GitHub runs a composite action step under:

```
bash --noprofile --norc -e -o pipefail
```

That `-e` is not mine. It arrives with the shell. And the entire job of
that step is to *read a non-zero exit status* — because exit 1 is how
`voyd-plan` says the boundary opened.

So the step died at the exact moment it succeeded. The plan was computed.
The boundary had opened. The tool returned 1 to say so, correctly, and
the shell killed it mid-sentence.

Sit with the shape of that for a second, because it is Exhibit A wearing
a different hat.

A check that fails with **no output** does not look like a finding. It
looks like an infrastructure flake. And what a team does about an
infrastructure flake in a required check is not investigate it. It is
mark the check non-blocking, ship the change, and put the fix in the
backlog behind everything that has a customer attached.

Which means the failure mode was not "the check is broken." It was **the
check is broken in a way whose natural remedy is to disable the check**
— which leaves you worse off than never having built it, because now you
also believe you have one.

The bug in the thing I built to catch invisible fail-open failures was
itself an invisible fail-open failure. I have written a lot of software
and I do not think I have previously been *out-argued by my own thesis*.

The fix is two characters and a word: `set +e`, first line. The second
instance was one line up — `[ -n "$x" ] && args+=(...)` takes the status
of the test when the test fails, so an unsupplied optional input killed
the step on the most ordinary path available.

And the reason my local rig missed both is the actual lesson: it ran the
steps with a bare `bash -c`. It was *nearly* a runner. Nearly a runner is
a thing that passes.

The suite now reads the steps out of `action.yml` and executes them under
that exact invocation, against a throwaway two-commit repository.
Reverting `set +e` fails two tests, which is the only evidence that a
regression test is one.

Then I opened the pull request again and watched a real runner print the
report, post the comment, patch that same comment in place across three
pushes, and fail the job with a sentence rather than a number — because
on a structural finding the count is legitimately zero, and *"0 documents
become reachable"* as the reason a build failed reads as a bug in the
tool. Which is, once again, an argument for turning the tool off.

Everything in this domain wants to become invisible. You have to keep
taking its hat off.

## The generalisation, which is bigger than vector search

| the intent | the window it actually has |
|---|---|
| `delete` removes the fact | ~60s of TTL monitor lag |
| a destroyed key makes it unreadable | ~60s of key cache |
| a replica's copy is current | unbounded replication lag |
| the index embeds with the declared model | nothing ever asks it |
| the policy file says what we enforce | nobody diffed what it admits |
| the reranker only reorders | nothing checks what it returns |

Six subsystems, one defect: **a statement of intent doing the work of a
guarantee.** The gap between what you declared and what is verified is
where all of these live, and it does not announce itself, for a reason
that is almost funny — declaring something is precisely what makes you
stop checking it.

A retrieval boundary does not fix that in general. It fixes it in the one
place where the consequence is a fact reaching a model that was not
supposed to have it, and it does so by making the check impossible to
forget, which is the only kind that survives contact with a codebase that
is still growing.

Ranking is not permission. Somebody has to ask the second question, once,
somewhere nobody can route around — and then, it turns out, somebody has
to check that the question is still being asked, in the place where
people decide to stop asking it.

---

*VOYD is MIT-licensed, at
[github.com/ranfysvalle02/VOYD](https://github.com/ranfysvalle02/VOYD).
The longer argument for the design is in
[docs/ranking-is-not-permission.md](docs/ranking-is-not-permission.md).*

*Nobody has run this but its author. Every number here comes from one
machine and one cluster, and the one honest gap in the story above is
that `voyd-plan --target` has never sampled a cluster from inside a CI
runner — the structural half is proven end to end, and the sampling half
is proven only on a laptop. Which is exactly the kind of distinction this
whole project exists to insist on, so it would be poor form to bury it.*
