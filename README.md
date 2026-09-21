# VOYD

**Ranking is not permission.**

A vector index ranks by relevance and is never asked the other question — *may
this fact reach a prompt?* So retrieval answers with a confident score and no
idea whether the hit was allowed to be there: an expired row the sweeper has
not reached, a fact somebody revoked, a vector from a model you swapped last
quarter.

Delete is a wish. MongoDB's TTL monitor runs about once a minute (measured
here: 60.0s); an S3 lifecycle rule runs about once a day. In that window your
index keeps returning the deleted document as a normal, well-scored result,
with nothing logged and nothing to page on.

**Refuse is a contract** — answered on every read, immediately, whatever the
sweeper is doing.

---

## No code

Declare the rules once, in a file that is not your application:

```python
# voydfile.py
from voyd import guard, deadline, revocable, tenant

@guard("notes", on_delete="revoke")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()
```

Point the boundary at your database:

```bash
python tools/voyd_wire.py --config voydfile.py --target localhost:27017
```

Then change one connection string. **That is the whole integration.** No
import is added to your application, no handle replaces a collection, no read
path is rewritten, and nobody has to remember anything.

### Reads refuse

```
direct, no boundary   5 documents
through the boundary  ['a note somebody will delete', 'the fault code is P0301']
                      the expired and the revoked are refused, and
                      globex was never in scope
```

That is a plain `pymongo` client with no VOYD import in it. It would be the
Node driver, or Compass, or a notebook — they all send the same bytes. The
boundary binds the *connection*, so there is nothing to reach past.

### Writes forget

And the verb already in everybody's code gets the better meaning:

```
  db.notes.delete_one({'text': 'a note somebody will delete'})
    -> deleted_count=1   (the driver is satisfied)

  reachable now         ['the fault code is P0301']
  rows on disk          5   <- nothing was destroyed
  the mark              'deleted via voyd-wire' at 2026-09-21T05:59:17
  the deadline          set, so the reaper collects the bytes
                        on the schedule they already had
```

Delete is a wish — eventually, best effort, unprovable. Refuse is a contract.
They asked for the wish and got the contract, and the bytes still go, on the
deadline they already had. A credential you need out of prompts *now* and on
disk *for the investigation* are contradictory requirements for `DELETE` and
the same requirement for this.

`on_delete="revoke"` is opt-in, because silently redefining `delete` for an
operator who did not ask is the kind of surprise this project exists to
remove — and because somebody, somewhere, means it. Left alone, a delete
really deletes. Declaring it without a `revocable()` field to write the mark
into is refused at load: there would be nowhere to record that the fact was
forgotten, and the delete would quietly do nothing.

The update it emits is the same pipeline `Admission.revoke()` writes — the
literal mark, the deadline moved *earlier only*, the derived encodings nulled
— so a fact forgotten through the wire and one forgotten through the library
are the same document afterwards. Two spellings producing different rows would
be the drift this whole package is about.

Run it: `uv run python examples/wire.py`.

The proxy holds no database connection of its own. The per-document check is
pure — handed documents, returns the ones a prompt may see — which is what
makes it movable to a wire at all.

## The vocabulary

| in a `voydfile` | means |
|---|---|
| `deadline()` | this field holds the instant after which the fact is gone |
| `revocable()` | a mark an operator sets to forget it *now*, irreversibly |
| `holdable()` | the reversible kind: a hypothesis, not an instruction |
| `tenant()` | the tenant id — required in every query *and* checked per document |
| `restricted_to(claim)` | admit only callers whose claim overlaps this audience |
| `embedded_with(model)` | refuse a vector from a different embedding model |
| `budget(n)` | refuse once the prompt has no room left |
| `distinct()` | refuse a repeat of content already on the page |

The last two are **set-relative**: they refuse a document because of the
*other* documents on the page, so the same document is admitted alone and
refused in company. No index filter and no policy engine can express that —
`$vectorSearch` decides each candidate before the page exists, and
`enforce(subject, object, action)` has nowhere to put the rest of the set.

A policy file that is wrong fails when it is *loaded*, not when a query comes
back with the wrong rows.

## In-process, if you want it

The declarative form compiles to the same objects the library exposes, so
there is no cliff between declaring a rule and writing one:

```python
from voyd import Engine

engine = Engine(client, db)
await engine.connect()
docs = engine.model("notes").forgettable()

await docs.find({})                      # cannot return a forgotten fact
await docs.revoke({"_id": x}, reason="credential leaked")
```

`revoke()` makes a fact unreachable on the next read while its row is still on
disk. Unreachable first, erased second — the reverse order is the bug.

Also kept, and both are reachable only from the library today:
**automatic encryption** (a key per scope, destroyed on the same deadline, so
every copy becomes unreadable at once — the one question refusal cannot
answer) and **server-side embedding** (`auto_embed`, so the index owns the
vector and a client-side embedder cannot drift from it).

## Status

**Mid-rewrite, and honest about it.** This repository was just cut hard: the
HTTP service, the MCP server, the store layer, the job queue, the perimeter,
the hash-chain ledger and the context index are gone, along with the tests and
documentation that described them. What is left is the boundary, the policy
file, and the wire.

So: **there are no tests right now.** The previous suite ran 817 checks
against a real MongoDB with no mock tier, and it is in `git log` — it was used
to verify this cut before it was deleted, which is the only reason the cut can
be called clean. A new suite belongs to the new shape and has not been
written.

Known gaps, stated rather than discovered:

- The proxy is a demonstration: no TLS termination, no pooling, one thread per
  direction, compression negotiated away in the handshake so replies arrive
  readable.
- `on_delete="revoke"` covers `delete`. An `update` that overwrites a fact is
  still an ordinary update, and a `findAndModify` delete is not intercepted.
- **Automatic encryption and server-side embedding are library-only.** Both
  survive the trim and neither is reachable through the wire: decryption needs
  the application's key context, which a proxy deliberately does not hold.

MIT.
