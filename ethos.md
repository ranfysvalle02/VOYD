# Ethos

*What VOYD is for, and — more importantly — what a policy file must
never become.*

---

## Mission

Make **"may this fact reach a prompt?"** a question that is always
asked, declared once, in a file that is not your application, at a place
nobody can route around.

## Vision

Retrieval gets the enforcement layer every other data path already has.
HTTP has middleware. SQL has views and row-level security. The
filesystem has permission bits the kernel checks whether or not you
remembered to ask. Retrieval has a ranking function and a hope.

## Ethos

**Refusal is a promise, not a convention.** A rule you have to remember
to apply is not enforced, it is suggested. Everything here follows from
refusing to ship a suggestion.

---

## The magic, and where it comes from

The feeling this aims for is: *you declare one thing, and everything
obeys.* Change a connection string, and a forgotten fact stops being
reachable from every driver, every language, every notebook, every
agent, forever.

**That magic comes from being small and total. Not from being powerful.**

This distinction is the whole document. A policy layer that can express
anything is not magic — it is a second application, in a worse language,
with no debugger, running in your data path. The magic is that a
`voydfile.py` fits on a screen and there is nothing to reach past.

Every feature that makes the policy layer more capable makes it less
magic. That trade is almost never worth it, and this file exists so the
trade has to be argued rather than drifted into.

---

## A policy declares *what is refused*. Never *how anything works*.

A rule answers one question about one document: **is there a reason this
may not reach a prompt?**

That is the entire job. Not what to do about it. Not what happens next.
Not who to notify, what to log, how to transform it, or what the
business would prefer. A reason, or no reason.

If you are writing something that is not a reason a fact may not reach a
prompt, you are in the wrong file.

---

## The four tests

Before anything goes in a policy file, it has to pass all four. They are
deliberately mechanical — a taste-based rule gets argued away at 5pm on
a Friday.

**1. Can it be answered about one document, with no I/O?**
No database, no network, no filesystem, no clock beyond the `when` it is
handed. If your rule needs to look something up, it is application logic
wearing a rule's clothes.

**2. Can a reviewer say what it refuses in one sentence?**
"Refuses a document past its deadline." "Refuses a caller below the
document's clearance." If the sentence needs an "and then" or a
"depending on", it is two rules or it is a program.

**3. Would you be comfortable if it ran on every document of every read,
forever?**
Because it will.

**4. Can `voyd-plan` tell you what changing it would let through?**
If not, ask why not. There are exactly three legitimate answers — the
rule is set-relative, it depends on the caller, or it is the tenant —
and each is *named in the output* rather than quietly excluded. A fourth
reason is a design smell, not a new category.

---

## Smells: you are putting logic in the wrong layer

- `import requests`, `import boto3`, or anything that opens a socket
- A rule that reads a second collection
- `if`/`elif` chains branching on business state
- Anything with the word *workflow*, *pipeline*, *step*, or *retry* in it
- A rule whose behaviour depends on what happened in a previous request
- Configuration that configures the configuration
- A policy file you would not hand to a new engineer and expect them to
  understand in five minutes
- Wanting a policy file to `import` another policy file

Each of these is a real thing to want. **None of them belongs here.**
They belong in your application, where there is a debugger, a test
harness, a type checker, a rollback, and a human who owns the
consequences.

---

## Purity is how the discipline is enforced

This is not a style guide anybody has to remember. It is structural.

The per-document check is a **pure function** — a document, a policy, a
clock. That constraint arrived because the check has to run inside a
wire proxy, and it turned out to be the thing that keeps the policy
layer honest: **you cannot put a database call in a rule without
breaking the three capabilities that make this project worth using.**

| if a rule stays pure | you get |
|---|---|
| it can be asked about an undeployed policy | `voyd-plan` diffs a change before it ships |
| it can be asked with no cluster | `--audit` reports findings with nothing installed |
| it is cheap enough to run twice | your reranker runs *inside* the boundary |

Add I/O to the policy layer and all three go away at once. The
temptation to make rules more powerful is, precisely, the temptation to
delete the reasons this exists.

The suite parses the AST of every module that claims purity and fails if
it imports a driver, a socket or an HTTP client. Prose would have rotted.

---

## Extension is allowed, and it is narrow on purpose

A rule is a protocol, not a list: `reason`, `refuses(doc)`, `clause()`.
A stranger's rule is a first-class one with no privileged path for the
builtins. That openness is deliberate — nobody can enumerate every
reason a fact should be withheld.

But the protocol is the *whole* extension point, and its shape is the
constraint. Three members, one document, one answer. You can write any
reason you like. You cannot write a program.

**Transforms are the other extension point, and they are explicitly not
enforcement.** A `@transform` shapes the page — rerank, de-duplicate,
annotate. It gets no credit for filtering and no attestation, and if it
drops a document for a security reason it is duplicating a rule badly.
The terminal admission pass runs after it regardless.

That separation is a guard against logic creep as much as against leaks.
Transforms are where "make it nicer" goes, so it does not end up in the
rules.

---

## What VOYD will never be

Written down so the answer is *no* by default and adding one has to be
argued against this list:

- A programming language
- A workflow or orchestration engine
- An ETL or data-transformation pipeline
- A place for business logic
- A general-purpose plugin framework
- A second application server
- A thing that needs its own staging environment to reason about

If a request would require any of those, the correct answer is that it
belongs in the application, and the boundary stays small.

---

## The failure we are avoiding

Every configuration layer that became a programming language got there
the same way: one reasonable exception at a time, each individually
defensible, none of them the moment it went wrong.

The end state is a policy file nobody can review, enforcing rules nobody
can diff, in a language with no tooling, in the data path of every read.
At that point the boundary has not been strengthened — it has been
**moved**, into a place with worse tools than the one it came from, and
you now have two applications where one of them cannot be tested.

A boundary is only a boundary while it is small enough to hold in your
head.

---

## The one-line test

> **If a policy file starts to look like an application, something has
> gone wrong — and the thing that has gone wrong is not in the policy
> file.**

Keep it declarative. Keep it pure. Keep it short enough to read in one
sitting.

That is the magic. Everything else is a feature request.
