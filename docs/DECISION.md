# Decisions, pre-registered

The next API is decided by pilot evidence, not by taste. This file records the
criteria *before* the data arrives, so a convenience that felt nice in a demo
cannot smuggle itself onto the public surface. It is the counterweight to the
one thing this project is repeatedly tempted by: adding a name because it reads
well, which [`ISSUES.md`](ISSUES.md) records happening once already (the public
surface grew to 100 names, 48 of them unused).

Each entry has a trigger, and stays `pending` until [`PILOT.md`](../PILOT.md)'s
report supplies the evidence the trigger asks for. "Interest," "it would be
nicer," and "a demo went well" are not triggers.

---

## Pending

### `Engine.open(uri, db)` — a one-call constructor
- **Trigger:** the pilot report's "where the time actually went" names client
  and database construction, or `connect()`/`ensure()` ordering, as a real
  cost — in more than one pilot.
- **Why it is not already here:** `Engine(client, db)` takes a client the app
  already has, and a library that opens a connection you cannot close has
  traded one chore for a worse one. A constructor is justified by repeated
  friction, not by saving one line in a snippet.
- **Status:** pending evidence.

### A `refuse(...)` / top-level façade
- **Trigger:** integrators cannot reach a working read path from
  `model(...).forgettable()` without reading the engine module — i.e. the
  under-ten-line path in [`examples/quickstart.py`](../examples/quickstart.py) is
  not, in fact, discoverable.
- **Default answer: no.** Collapsing a working six-line path to three by adding
  a second promised surface is exactly the move this project regrets. The bar
  is a discoverability failure, not a line count.
- **Status:** pending; current evidence (the quickstart runs, its size is
  pinned by a test) argues against.

### The HTTP namespace as the first surface
- **Trigger:** a pilot needs the guarantee across a language boundary *before*
  it has adopted the Python handle at all — the collection genuinely is not the
  API, the namespace is, and there is a caller in another language on day one.
- **Why later:** the HTTP surface still owes an authorization story for the
  verbs that change reachability (see [`ISSUES.md`](ISSUES.md) and
  [`ideas.md`](ideas.md)); shipping it as the on-ramp would front-load that.
- **Status:** pending; promote only after the Python handle is wanted.

### A TypeScript client
- **Trigger:** a retained pilot's own stack is TypeScript-first and the Python
  handle is the thing blocking adoption, not the concept.
- **Why it is real anyway:** the API is five calls, and a second implementation
  is where an API finds out it has fourteen ([`ideas.md`](ideas.md) item 9).
  But it is reach, not proof; the first milestone is one retained integration,
  not a second language.
- **Status:** pending the first retained Python pilot.

---

## Decided

- **The first wedge is Python + MongoDB, `find`-first.** It is the smallest
  truthful integration and the fastest way to measure installation friction.
  Vector search (Atlas + Voyage autoEmbed) is the second example, not the
  gate. Recorded here so the sequencing is not relitigated.
- **The public identity is the handle.** `Engine.model(...).forgettable()` is
  the first sentence and the on-ramp. The HTTP namespace, the MCP tools, the
  `memory` trait and the MongoDB-specific pitch are frozen as later surfaces,
  not the product, until a filled [`PILOT.md`](../PILOT.md) report says otherwise.
  The reframe that set this is "ranking is not permission"
  ([`README.md`](../README.md)); the frozen list is in [`ideas.md`](ideas.md).

## How an entry moves

An entry leaves `pending` only with a filled [`PILOT.md`](../PILOT.md) report
attached to the trigger it names. When it does, move it to **Decided** with the
date and the evidence in one line — and, if the answer was yes, the diff that
added it to the public surface, which
[`tests/test_the_public_surface_is_deliberate.py`](../tests/test_the_public_surface_is_deliberate.py)
will then hold.
