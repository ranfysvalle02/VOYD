# Limits

What this does not do, why, and what would change it. Written down because
the failure this project is named after is a system that is confidently
wrong and quiet about it, and being that system while complaining about it
would be a poor look.

Nothing here is a to-do list. Some of these are permanent, some are
decisions waiting for evidence, and a few are bugs that have not happened
yet. They are marked.

---

## 1. The one that actually matters

**Nobody has used this but its author.** 87 commits, one contributor, zero
external users, zero pilots. Every claim in this repository is verified by
somebody who also wrote the claim.

That is not a coverage problem and no amount of code fixes it. The suite is
good at holding claims somebody thought to state; it has never once been the
thing that caught a problem a *user* hit, because there have been no users.
Nine defects this month, and the way they were found is the point. Seven
came from running something new: three from exercising paths nobody had
exercised, four more from the hostile pass in §4. One came from the
benchmark contradicting a commit message that had already been pushed. One
came from *writing a test* — the scanner's two-mark finding, in §4 — which
is the first time this month the act of testing found something rather than
recording something already known.

Not one was found by the suite going red. That is the honest description of
where an outside perspective would land: the suite is a ratchet, not a
search, and everything above was a search.

**What would change it:** one team, two weeks, their own corpus. Everything
else on this page is second.

---

## 2. What refusal structurally cannot do

These are properties of the idea, not gaps in the implementation. None of
them will be fixed; they should be designed around.

### It binds a read, not a value

Once a caller holds the fields, they are outside the boundary. A copy taken
before a mark was written is not the document — it is what the document
*used to say* — and the per-document check admits it, correctly, because it
refuses what it is **shown**.

This matters most where it is least expected. In a long-running agent, a
fact revoked at turn 40 does not vanish from the context the agent carried
forward itself. The remedy is not a cleverer boundary: re-read the carried
ids through the handle at the top of each turn. That context is a cache and
this is the cache invalidating.

### It binds this application, not your data

Another service with its own connection to the same cluster is unaffected.
This is the entire reason the wire boundary exists (it binds a *connection*
rather than an import) and the entire reason cryptographic erasure exists
beside it (a destroyed key is not bypassable by connecting somewhere else).

Neither fully closes it. A DBA with a shell still reads everything that is
not encrypted.

### Admission is a veto, not a constructor

It can refuse a document for what is already on the page. It cannot
**require** that something be on it. So a diversity *floor* — "this context
must include a dissenting source" — is not expressible as a refusal.

A floor is a retrieval objective and belongs to the ranker. A ceiling is an
admission rule and belongs here. Do not let anyone talk you into faking the
first with the second.

### A rule with no query half is invisible to static analysis

You can scan a repository for reads that forget a deadline filter. You
cannot scan it for a token budget, because the reads it refuses look
identical to the reads it admits. This is true of every static analyser, not
just a homegrown one — Semgrep and CodeQL have the same nothing to work
with.

### Partial enforcement is worse than none

Covering `deleteOne` and not `findOneAndDelete` does not give you half a
guarantee, it gives you a false one — which is the only kind that gets
trusted. This already happened once here and was caught by a probe that
tried every destructive verb rather than the one under test.

**Consider:** any new write path is a new instance of this. The question to
ask of each is not "does it work?" but "what else could make a fact
unreachable that I have not looked at?"

---

## 3. The wire boundary

It is correct before it is operable. Some of that is closed; the rest is
listed honestly.

### Closed

Aggregation stages that write elsewhere (`$out`, `$merge`).
TLS termination for clients (`--tls-cert`; without one it binds loopback
only, because a plaintext boundary on a network would carry in the clear
everything it just refused). TLS and SRV upstream, so it can front Atlas.
Primary discovery. Failover by reading the server's own
`NotWritablePrimary` rather than polling. Message size capped at MongoDB's
own 48MB ceiling. Bounded connections, closed rather than queued. A draining
`SIGTERM`.

**Metrics, while it is still running** (`--metrics PORT`). Counters printed
on shutdown answer "what did that process do?" after it is too late to act,
and this page carried "no metrics endpoint" as the first thing an operator
would ask for. Prometheus text on `/metrics`: documents admitted and refused
per collection, refusals broken down by the reason vocabulary in
`reasons.py`, connections open and total and refused-at-the-limit, upstream
re-resolutions, and a per-worker flush counter that goes flat when a
worker's loop wedges.

Three details in it are decisions rather than defaults:

*It is a slab of shared memory, one slot per worker.* A port per worker
pushes the summing onto whoever is scraping, and their total is only as
right as their service discovery. Workers pushing to the parent over a pipe
puts an IPC round trip on a reporting path, and a worker blocked writing to
a full pipe is a worker not refusing documents. Each worker being the only
writer to its own slot needs no locks and no coordination at all.

*Counters flush on a timer, not per document.* Refusal costs about 2.3us per
document and a shared-memory write on that path would be a measurable tax on
the number being reported. Measured with `--with-metrics`: 2.50us/doc
without, 2.51us/doc with, which is noise. The cost is staleness of up to a
second, and it is published as `voyd_metrics_age_seconds` rather than left
for somebody to discover.

*It binds loopback, and there is no flag to change it.* A refusal count
broken down by reason is a description of what a corpus holds and who has
been probing it -- a climbing `deadline` is the system working, a climbing
`not_cleared` is somebody trying doors. A test asserts the string `0.0.0.0`
does not appear in that module.

**Clients cannot walk past it.** `--advertise-self` rewrites `hello` so clients stay on the boundary rather
than following the cluster's host list, which is what makes this
*enforcement* rather than a `directConnection=true` the caller has to
remember. Two fields are deliberately passed through untouched:
`isWritablePrimary` and `secondary`. Forcing them true would keep clients
pinned during a failover, which sounds like an improvement and is the
opposite — that flag is the signal a driver uses to notice its upstream is
no longer writable, and masking it means the client writes happily into an
outage. `setName` is kept for the same class of reason: strip it and drivers
treat the target as a standalone, which silently disables retryable writes.

### Open

**A worker that is alive but wedged is a metrics problem, not a
supervision one.** The parent replaces workers that *die* — `SIGKILL` on
one of three is detected, the slot is cleared, a replacement is forked and
`voyd_worker_restarts_total` records the discontinuity. It cannot detect
one that is alive and not working, because from the outside that is a
process sitting in a syscall. `voyd_worker_flush_age_seconds{worker="N"}`
is the signal: one slot climbing while the others stay flat.
**Consider:** nothing acts on that automatically. Alerting on it is the
operator's job, and there is no `--restart-wedged-after` because a
timeout that kills a worker mid-request would turn a slow upstream into
dropped connections.

**`--workers` orphans on `SIGKILL`.** Workers leave the parent's process
group so the parent is the only thing that signals them -- that is what
stops a terminal's `SIGINT` reaching a worker twice and killing it mid-drain
before it reports its counts. The cost is the other direction: `kill -9` on
the parent leaves the children accepting connections with nobody to drain
them. `SIGTERM` and `SIGINT` are both handled and both drain cleanly, so
this needs somebody to reach for `-9` specifically. **Consider:** a
supervisor that reaps by process group will not find them.

**One node, no topology.** Clients are pinned here, but *here* is a single
process group: it does not load-balance reads, honour read preference, or retry a
write the client already saw fail. Pinning and fanning out are different
problems and only the first one is solved.

**A failover costs the in-flight requests.** Re-resolution happens on the
*next* connection. The request that received `NotWritablePrimary` is
returned to the client, which retries — correct, and worth knowing before
somebody reports it as a bug.

This is now measured rather than reasoned about. `replSetStepDown` with
`force` on the single-node replica set Atlas Local already is holds a real
election, so the whole path has a test: the client sees two
`NotPrimaryError`s, the boundary reads the server's own error and
invalidates, the driver retries, and a `delete` issued across the election
still lands as a revocation with the mark on it and every row still on
disk. The claim that this "cannot be caused on demand" was an excuse, and
it is gone.

**No upstream pooling, deliberately.** A MongoDB connection carries
authentication, sessions, cursors and transactions; sharing one would hand a
cursor to whoever asked second. One upstream per client is the right shape;
what is bounded is how many exist. Connection count still scales 1:1 with
clients -- that part is permanent and correct.

What is no longer true is the cost of one. This used to be two OS threads
per connection, and this page used to say that past a few hundred it wanted
"an event loop or a different language." The second half was wrong: every
byte-rewriting function here is `bytes -> bytes` over a pure `reachable()`,
so nothing about the *boundary* was ever tied to the transport. Only the
shell was, and replacing it was a contained change rather than a rewrite.

Measured on this laptop, idle connections held open, old versus new:

| connections | threads | RSS | accept |
|---|---|---|---|
| 400 | 1,201 -> 19 | 87.6MB -> 50.7MB | 0.12s -> 0.03s |
| 1,500 | 4,501 -> 19 | 210.0MB -> 68.2MB | 0.85s -> 0.11s |
| 3,000 | 9,001 -> 19 | 364.5MB -> 92.0MB | 3.39s -> 0.25s |

The 19 is a fixed executor pool, not per connection; it does not grow.

**One event loop is still one core.** A single worker sits at exactly
**1.00 cores** under load -- the per-message cost is BSON decode in
`decode_sections` and `enforce`, and no event loop spreads that.
`--workers N` pre-forks N processes over one inherited listening socket,
which is the knob that uses the other cores.

It scales close to linearly. `tools/voyd_bench.py`, 14 cores, 100 documents
per batch with one in ten revoked:

| | docs/s admitted | cores | us/doc | vs 1 worker |
|---|---|---|---|---|
| no proxy (control) | 12,434,609 | | | |
| `--workers 1` | 444,215 | 1.00 | 2.25 | 1.00x |
| `--workers 2` | 861,098 | 2.00 | 2.32 | **1.94x** |
| `--workers 4` | 1,587,041 | 3.98 | 2.51 | **3.57x** |
| `--workers 8` | 2,655,548 | 6.91 | 2.60 | **5.98x** |

**Refusal costs about 2.3 microseconds per document**, and that is the
whole price of the boundary. The per-document cost drifts up ~15% from one
worker to eight, which is memory bandwidth, not contention in the code --
there is nothing shared between workers to contend on.

**This page previously claimed `--workers 4` bought 1.42x.** That number
was wrong, and it was wrong in an instructive way: it was measured against
a real `mongod` with a `pymongo` load generator on the same laptop, so the
proxy was never the bottleneck and the experiment could not see the thing
it claimed to measure. An earlier attempt said 1.18x, because that load
generator was Python threads holding the GIL against itself. The fix was
not a better proxy, it was a harness that removes both ends: a synthetic
upstream that answers with one pre-encoded reply, and raw-socket clients
that never decode one.

**The control is the part to check first.** `--workers 0` runs the clients
straight at the upstream. At 12.4M docs/s it is 4.7x the best proxied
result, which is what makes the rows below it measurements of the proxy
rather than of the harness. The benchmark prints that ratio and says so
when it drops under 1.5x.

**And it verifies it was still refusing.** A proxy that got fast by quietly
forwarding everything would post the best numbers on this page, so each row
also reports the refused share read back from the worker summary. It is
10.0% in every row above, which is the one document in ten the batch was
built with. A row that says `LEAKED` is a row whose throughput means
nothing.

### What the proxy stopped paying for, and what it started paying

`enforce` used to decode every reply body in full before asking whether it
was even a cursor batch on a guarded collection. Reading the body lazily
(`RawBSONDocument`) and asking the cheap questions first -- is there a
cursor, what is its collection, is that collection declared -- means a
reply nobody guards is forwarded after four field reads.

**The first framing of this change was wrong, and the bench is what said
so.** It was committed as "decode less", which is true of exactly one of
the three paths. Measured in process on a 100-document batch carrying
1536-dimension embeddings, 2.06MB on the wire:

| path | before | after | |
|---|---|---|---|
| unguarded collection | 2.73ms | 0.11ms | **24.0x** |
| guarded, 10% refused | 6.13ms | 3.93ms | **1.6x** |
| guarded, nothing refused | 3.03ms | 3.23ms | **0.9x** |

Three different mechanisms, only one of which is the one advertised:

1. **Unguarded is the real prize, and it is decoding less.** The batch is
   never materialised at all.
2. **Guarded-and-refusing got faster at the *re-encode*, not the decode.**
   A surviving document is spliced back as the bytes it arrived in instead
   of being re-serialised from decoded values.
3. **Guarded-and-refusing-nothing got 10% slower.** Both paths must inflate
   every document to judge it -- `RawBSONDocument` inflates a whole document
   on the first field read, so nothing is saved -- and the wrapper is not
   free. That is a regression on what may well be the most common steady
   state in a healthy deployment: a read where nothing has expired.

**That trade is deliberate.** It pays 10% on the cheap case to buy 1.6x on
the case that costs twice as much, and 24x on traffic that is most of a
real connection. A deployment where nothing is ever refused would be better
off without this change -- and would also not need this project.

End to end, through the harness, 4 workers, three runs each, embeddings on:

| | docs/s before | docs/s after | |
|---|---|---|---|
| 10% refused | 35,042 | 45,169 | **1.29x** |
| nothing refused | 48,667 | 47,650 | 0.98x |

The proxied result moves from **7.0x** slower than the control to **5.5x**.
Variance across runs was under 3%.

**The benchmark could not previously say any of this**, because its
documents were `{_id, i, text}` with a 200-byte pad and no vector. The
shape of a document is a claim about the workload, and short documents were
quietly asking the easy question of a boundary that exists to sit in front
of a retrieval corpus, where a 1536-float array costs more to materialise
than every other field put together. `--dims` now exists and defaults to 0,
so the older rows on this page remain comparable and remain answers to a
question nobody was asking.

**The remaining cost is mostly not avoidable by decoding less.** A
hand-written scan for named top-level fields measures 0.12ms against
2.77ms -- a real 24x still sitting there on the guarded path -- and it is
not being taken. Hand-rolled BSON parsing on the enforcement path fails in
the direction of admitting something, and the prototype already produced a
naive datetime for a different reason than the decoder produces one. That
is the class of bug this repository is named after, offered in exchange for
a millisecond nobody has asked for. It stays a number, not a branch, until
somebody's p99 makes the case.

**Decoding lazily is a speed change inside the enforcement path**, which is
the worst place to put one: a decoder that disagrees with the old decoder
about a deadline does not get slower, it gets wrong and quiet. So the two
are pinned against each other in `test_the_codec_round_trips.py` -- same
values, same verdicts, same absent timezone, an unguarded reply returned as
the identical object, and every field of a surviving document spliced back
from the bytes it arrived in.

---

**`update` is not intercepted.** An `update` that overwrites a fact is
mutation, not forgetting, and treating it otherwise would make every edit a
revocation. That is the right call, but it means "make this unreachable" has
exactly two supported spellings and a third that silently does something
else.

**Aggregation `$out` / `$merge` — found here, verified, and closed.** These
write inside the server, so the documents never come back to the client and
the read path is never handed one to refuse. Measured: a connection that had
just declined to show a revoked document copied it into another collection
anyway. A proxy cannot make these safe, so they are refused with a reason,
the same answer `drop` gets. Ordinary aggregation is untouched.

**Consider:** that hole was invisible because it does not *look*
destructive. Any future server-side write stage is the same shape, and the
question to ask is not "is this a delete?" but "does the client ever see the
documents?"

---

## 4. Coverage

201 tests, ~3,922 lines, against 8,078 lines of `voyd/` and 2,731 of
`tools/`. Well-targeted rather than thorough: the coverage is by *claim*,
which is the right axis, but it is not line coverage and should not be
mistaken for it.

557 lines are mentioned by no test file, and all of it is defensible now:
`composition.py` is type-checked rather than executed by design,
`trait.py` and `expiry.py` are small and exercised indirectly, `sealing.py`
runs under the encryption tests even though a name-scan cannot see it.

**The scanner had 1,043 lines and no test. It now has 27.** `voyd_scan` is
the first thing a stranger runs and the only thing in this repository that
passes judgement on code nobody here has seen, so a false all-clear there is
this project's own failure mode aimed at somebody else. The suite asserts
findings *and* the absence of them, and spends more of its length on the
second: a false negative is the thesis turned on itself, but a false
positive is spent on a stranger's codebase, and a tool that cries about
clean reads is one nobody runs twice.

What it pins, beyond the obvious true positives: a lookup by `_id` is still
a leak (the most specific-looking read is exactly the one that keeps serving
a revoked fact); a field *every* read names is a schema rather than a
convention and must not become a mark; two agreeing reads are not yet
evidence and three is the documented floor; a `# voyd:` claim inside a
string literal suppresses nothing, because an all-clear reachable from
inside a doctest is not one you would let gate a build; one unparseable file
does not turn a repository into an all-clear; and all three ways the tool
can print "clean" without having established anything -- no files, no
recognised reads, a missing path -- still say so.

**Writing them found one real defect.** On a collection carrying two
declared marks, a read that named one was reported as "filter does not name
the mark", which does not say which mark, on a read that visibly names the
other. The generic wording was conditioned on one mark being *missed*; it is
now conditioned on the collection carrying *one mark in total*, which is the
case it was always arguing for. A finding whose first question is "which
mark?" costs more to action than it saves to print.

**CI now also runs it on a bare interpreter** -- no `uv sync`, no install,
no `PYTHONPATH` -- against this repository's own source. The claim that it
costs a stranger nothing to try is worth exactly as much as the last time
somebody tried it that way.

**`mypy` now reads `scanner/voyd_scan` too, and still not `tools/`.**
Adding the scanner cost nothing: it was already clean. `tools/` is a
different matter -- `voyd_wire.py` has **31 errors**, most of them a
`Meter | None` that the runtime guards and the checker cannot see. That is
real work rather than a config line, and blanket-ignoring them would leave
the 1,716-line front door -- the hardest code here, with the concurrency and
the failover handling -- checked by nobody while appearing to be checked.
It stays open, with a number attached.

`capabilities.py` was listed here as "the one with no real excuse" and now
has seventeen. It was a bad gap specifically because that module decides
which search tier everything above it uses, and its own docstrings record
two occasions when it got that wrong silently for months — Atlas inferred
from the connection string, and a hardcoded `(8, 1)` floor that told every
8.0 deployment it could not fuse ranks. Both are now tests. A regression
that is only described in a comment is one that can come back.

**Consider:** the suite is fast by default (197 tests, ~52 seconds) with
real index builds and the live-Atlas tests deselected. `-m ""` includes
them and takes minutes, varying with cloud latency -- that variance is the
flag working, not a flake, and it is worth knowing before somebody reports
it as one. CI clears the deselection and a test pins those two
facts together — but that arrangement is exactly how a test quietly stops
being run, so check it is still true before trusting it.

---

### What a hostile pass found

The transport was rewritten in a day and had a day of exercise, which is
the wrong amount for concurrency. A pass that caused the failures on
purpose — clients that stop reading, vanish mid-reply, or half close;
workers killed and workers frozen; an election under load — found four
real defects, and all four are now tests in
`test_the_boundary_survives_hostile_conditions.py`.

**A half close cost the caller its last reply.** A client that calls
`shutdown(SHUT_WR)` is saying "no more requests" and is still reading. The
request direction hitting EOF tore the reply direction down with it. Not a
regression from the event loop — the threaded version did the same, which
is why nothing caught it.

**One `SIGKILL` produced four restarts.** The first supervisor closed the
listening socket in the parent, so every replacement inherited a closed fd
and died at once: a crash loop manufactured by the thing meant to recover
from one. A listening socket's accept queue belongs to the socket, not to
a process, so the parent holding the fd steals nothing.

**A dead worker was invisible.** Capacity dropped by its share,
`voyd_workers` went on reporting the number asked for, and nothing logged
anything.

**`voyd_metrics_age_seconds` reported the freshest worker.** So a wedged
worker among healthy ones was hidden completely — measured, a `SIGKILL`ed
worker left it reading 0.095. A staleness number that only reports the
healthiest worker is a liveness check that cannot fail.

What the same pass did *not* break, which is worth recording too:
backpressure held (20 stalled clients with 4,000 unread ~1MB replies grew
the process 55MB, not 4GB), fifty resets mid-reply cost fifty connections
and not the listener, garbage on the port cost one connection, and the
boundary survived a full `mongod` restart without one of its own.

---

## 5. Operational notes that will surprise somebody

**A search index is not free, and `mongot` is shared.** Nine abandoned
databases carrying 24 search indexes between them was enough to starve new
index builds and make a healthy test fail for a reason unrelated to
refusal. If index builds get slow, count your leftovers before debugging
anything else.

**Atlas Local registers no embedding models.** It *declines* an `auto_embed`
declaration and silently falls back to expecting a client-supplied vector.
Anything testing server-side embedding locally is testing the opposite of
what it claims.

**The embedding model list moves.** `voyage-3` was dropped; the server
reports the supported set in its own error, which is the most useful error
message in this stack.

**A collection must exist before you can index it.** Atlas answers "Error
retrieving collection UUID," which reads like a permissions problem.

**`.primary` is `None` on an undiscovered topology.** The driver connects
lazily. Ping first, or you silently select whichever node DNS returned —
which on a replica set reads perfectly and rejects every write.

---

## 6. Decisions waiting on evidence

Not frozen out of caution — frozen because building them before somebody
wants them adds surface that has to be kept honest forever.

| | what it would take | what would unfreeze it |
|---|---|---|
| **`$out` / `$merge` handling** | small, and it is a hole | do this one anyway |
| **Revocation that propagates** | a sync protocol | `perimeter.py` says who else holds a copy is auditable and never enforceable. That is true without a protocol between you and the replica — and stops being true with one |
| **Reverse-indexed receipts** | a storage decision | *"which answers were built on this fact?"* is already a query for anything written back; what is missing is the artefact that **left** — a Slack message, a fine-tune |
| **A second engine** | doubles the surface | a user who is not on MongoDB |
| **A second listener topology** | real work | `--workers` pins clients to one host; fanning out is still a different problem |

---

## 7. Deliberately not doing

Reasons recorded so they are not relitigated every six months.

- **A delete verb of our own.** A delete hands the caller a cleanup
  obligation, and an agent that has to remember to clean up is the failure
  this exists to remove. Asserted by a test that has now outlived three
  surfaces.
- **An undo for `revoke()`.** The row is already scheduled for the reaper,
  so the undo would work until `ttlMonitorSleepSecs` decided otherwise — an
  API whose window is a storage event, in a codebase written to argue that
  guarantees must not depend on sweepers. Re-admitting erased information is
  a new document with new provenance.
- **Pushing the deadline into the vector index.** A `vectorSearch`
  definition cannot be updated in place, so it is a drop-and-rebuild on
  every deployment, and a rebuilding index returns zero rows rather than
  erroring.
- **Ledgering reads.** A write per refused hit, for a property the read path
  enforces anyway.

---

## 8. If you read one thing

The recurring defect in this project is not a category of bug. It is a
**category of silence**: an instrument that is wrong and says nothing. The
decode that returned `None` and was read as "not a delete". The proxy that
answered `deleted_count=1` while really deleting. The scanner that blessed a
path it never read. The suite that passed because a closed socket counted as
alive.

Every one was found by running the thing at the size and in the manner the
documentation promised, and none by re-reading the documentation. That is
the method, and it transfers to whatever gets built next.
