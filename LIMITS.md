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

**Nobody has used this but its author.** 105 commits, one contributor, zero
external users, zero pilots. Every claim in this repository is verified by
somebody who also wrote the claim.

That is not a coverage problem and no amount of code fixes it. The suite is
good at holding claims somebody thought to state; it has never once been the
thing that caught a problem a *user* hit, because there have been no users.
Twenty defects this month, and the way they were found is the point.
Eleven came from running something new: three from exercising paths nobody
had exercised, four from the hostile pass in §4, two more from the
hostile pass against fan-out in §3 -- a cheap query pattern withdrawing
the expensive one it shared a collection with, and a secondary's error
becoming the client's -- and two from pointing an ordinary driver at
`--key-vault` and reading what came back: an erasure that destroyed the key
without first revoking the documents, leaving them readable for the length
of a key cache (§5), and a delete clause read from the command body when a
`delete` carries it in a document sequence, which made the boundary miss
every erasure request it was sent. One came from the benchmark contradicting a commit
message that had already been pushed. Five came from *writing a test*: the scanner's two-mark finding in §4; the
read-preference claim in §3, where the defect was in the prose and three
files had spent weeks talking a reader out of something the proxy could
already do; and fan-out's identity check, which looked for a standalone
`saslStart`, never fired against a real driver's speculative handshake, and
was fail-open while it did not — the most serious of the twenty, and the
only one a user could have been harmed by rather than merely misled; and two
from the sealing work -- an erasure that revoked rows its key had never
protected, making unencrypted documents of the same tenant unreachable as a
side effect of a key deletion, which is the boundary inventing policy out of
a verb; and a metrics `Meter` that hand-listed the counters `flush` reads, so
adding one raised inside the flusher task, killed that worker's reporting,
and presented as the proxy dropping connections -- a reporting bug wearing
the costume of a network one.

One was found by a type checker being pointed at code it had never read:
`voyd_bench`'s inner coroutine claimed to return two floats and had been
returning two lists since the spread was added, so a function reporting a
median and a range was documented as reporting one number. That is the
whole argument for §4's `voyd/wire/` change in one line -- the annotation was
wrong for as long as nothing checked it.

And one was a defect in the *suite* rather than in the code, which belongs
here more than any of the others. A test named
`test_one_erased_tenant_does_not_fail_the_page` carried a docstring about a
page of fifty containing one erased row, and asserted a single-tenant page
with nothing erased in it -- a duplicate of the test above it, with a comment
admitting it had punted. It passed. It passed under sabotage. It would have
gone on passing while the claim it was named after went unchecked, and the
count on this page would have included it as coverage. Getting a genuinely
mixed batch turned out to need care: inside one scope the key is shared, so a
shred is all-or-nothing, and a cross-scope read is refused wholesale before
decryption is reached -- so both obvious ways to write that test produce a
uniform batch and check nothing. A test that cannot fail is a screenshot,
and this page has said that about examples for a while without checking
whether it was true of the tests.

And the nineteenth was not in the code at all. It was a paragraph on this
page: §5 explained that the declaration and the index could disagree and
that reading Atlas back was not worth the risk, having silently substituted
the risk of *creating* an index for the risk of *reading* one. A reviewer
asked why, which is the only reason it was found -- the suite cannot go red
over a justification, no test covers prose, and the sentence had been read
several times by the person who wrote it without the substitution showing.
The fix was 400 lines and closed four classes of silent drift that had
nothing to do with embedding. The thing worth taking from it is the ratio:
one question from outside beat every pass over the same file from inside,
which is what the top of this section has been claiming all along.

That last one is worth the sentence it costs. It was written *and* reviewed
in the same hour as the feature, by the same person, with the failure mode
explicitly in mind, and it still shipped inverted. The test that caught it
was written in the same hour too. Everything on this page about a suite
being a ratchet rather than a search is true; this is the counter-example
where writing the assertion was the search.

Not one was found by the suite going red. That is the honest description of
where an outside perspective would land: the suite is a ratchet, not a
search, and everything above was a search.

The two newest are the cleanest example on the page, because they cost
nothing to find. The feature was finished, the code read correctly, and the
first client pointed at it produced a shredded tenant's plaintext and an
erasure the boundary never noticed. Fifteen minutes of *using* it beat every
hour of writing it. That is not an argument for more testing; it is the
argument for the paragraph above this one.

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
not encrypted -- and as of `--key-vault` (§5), what a policy declares
`sealed()` is encrypted for every writer in every language rather than only
for the ones that imported this package. What that DBA reads there is
ciphertext, and once the scope's key is destroyed so is everybody's.

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

**A cumulative rule spans the read, not the batch.** This one was a
silent hole and is worth the space, because it was found by measuring
rather than by reading and it defeated a declared rule *by accident*.

`budget()` and `distinct()` judge a document against the running total of
the page so far. The admission handle opens one tab per `reachable()`
call, and on the wire that is one call per cursor **batch** -- so the
total reset on every `nextBatch`, and `batchSize` is a field in the
client's own `find`. Measured, ten documents at 40 tokens each under a
declared budget of 100:

```
one batch     -> 2 documents    correct
batchSize=2   -> 10 documents   400 tokens under a 100-token budget
```

Nothing errored and nothing was logged. Every driver has a default batch
size and plenty of frameworks set their own, so this was not an attack, it
was a configuration.

`Budgets` holds one tab per cursor id, per connection, and hands it to
`Guard.filter`. Per connection rather than on the `Guard`, which every
connection shares -- a running total is one client's read. Dropped when
the server reports `id: 0` and when the client sends `killCursors`, which
are the only two ways a cursor ends; without the second, a long-lived
connection would accumulate a tab per query it ever ran. A policy with no
cumulative rule allocates nothing: `Guard.cumulative` is the gate and the
dict stays empty.

Held by `tests/test_a_page_budget_survives_the_batch_size.py`, which
asserts the **number of documents served** at five different batch sizes
rather than a counter the boundary keeps about itself.

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

**Fan-out exists, and it cost the boundary a property.** `--fan-out URI`
ranks reads on secondaries and re-reads each guarded batch's marks from the
primary before releasing it. The secondary ranks, the primary permits;
`test_the_boundary_ranks_on_a_replica_and_asks_the_primary.py` freezes
replication with `stopReplProducer`, revokes a document on the primary only,
and asserts the boundary still refuses it -- with a control assertion that
first proves the secondary really was behind, because otherwise that test
passes on a deployment where nothing was ever at risk.

What it gave up is stated here rather than in the README's margin:

- **It carries its own credential.** Every other upstream connection this
  proxy makes is the client's; this one cannot be. Authentication is per
  connection and SCRAM is a challenge-response bound to a nonce, so the
  client's handshake cannot be replayed onto a second socket without the
  password. "Holds no credentials" was true of every version of this file
  before fan-out and is now true only when fan-out is off.
- **Authenticated fan-out works, and it did not at first.** The boundary
  authenticates its own secondary connection by driving pymongo's SCRAM
  through a shim rather than implementing the exchange. The earlier version
  of this refused to, on the grounds that a security primitive should not
  be written by somebody who did not have to -- right reasoning, wrong
  conclusion: the choice was never "write SCRAM or skip authentication",
  it was "write SCRAM or drive the implementation already installed". The
  test rig runs with `--auth` and a keyfile for this reason, because an
  open rig would exercise the one path that needs no SCRAM at all.
- **Identity is checked, and the first version of that check never fired.**
  A client authenticating as a different user than the fan-out URI names
  has fan-out switched off for its connection. The check originally looked
  only for a standalone `saslStart`, and every modern driver folds the
  first round into the handshake as `speculativeAuthenticate` -- so against
  a real driver it matched nothing and fan-out stayed on. It was fail-open
  as well as wrong, which is the pair of mistakes that makes a privilege
  change invisible. It now starts *off* on any deployment whose
  secondaries need a credential and is enabled only by a client proving the
  matching identity, so a mechanism this boundary cannot read -- X.509,
  AWS, OIDC -- is "not us" rather than "probably fine".
  **Consider:** the check compares *usernames*. Two identities with the
  same name in different auth databases would pass it.
- **One extra round trip per guarded batch**, and a whole-document fetch
  rather than a projection whenever a rule cannot be introspected.
  `verdict_fields` returns `None` for any third-party rule, which is the
  case that matters, because this module cannot have been written with one
  in mind.

**The cost argument is now measured rather than assumed.** It assumes the
scan dominates the lookup -- obviously true for a `$vectorSearch` returning
10 of 100,000, obviously false for a `find` returning most of a small
collection, and nothing about the request distinguishes them. An operator
flag naming a threshold would have been asking somebody to guess a number
this process can measure, so `Payoff` compares how long the secondary took
to rank against how long the primary took to confirm, per collection, and
withdraws the collection when confirming stops being the cheaper half.

The measurement is keyed by the read's *shape* -- collection, whether it
carries a search stage, and the requested size rounded to a power of two --
and keying it by collection alone was one of the two defects a hostile pass
found. See below.

**Consider:** withdrawal is one-way inside a process. There is no path back
until a restart, deliberately -- re-admitting on a favourable sample is how
a boundary oscillates, and the cost of staying on the primary is a slower
read rather than a wrong one.

**Consider:** two `find`s of very different selectivity that ask for the
same number of documents still share a bucket. The shape is read off the
request, and the request does not say how much work the filter implies.

**Consider:** the ratio reads backwards at a glance. A *larger*
`--fan-out-give-up` is more tolerant, because it is how much the check is
allowed to cost relative to what it bought. The end-to-end test for this was
written against the wrong direction first and passed for the wrong reason
until the assertion was tightened to watch the secondary's own counters.

### What a hostile pass found in fan-out

Same method as §4 and the same justification: the feature was written in a
day and had a day of exercise, which is the wrong amount for anything
concurrent. Causing the failures on purpose -- a primary that will not
answer the mark lookup, secondaries that refuse reads, twenty clients
paging at once, invented cursor ids, garbage on the port -- found **two
real defects**, and both are now tests.

**One cheap query pattern withdrew the expensive one it shared a
collection with.** The payoff measurement was keyed by collection. Every
RAG deployment runs `$vectorSearch` and ordinary `find`s against the same
collection; the finds are cheap to rank and expensive to confirm, so they
withdrew the collection, and the vector search -- the only reason fan-out
was switched on -- never fanned out again. Measured on a 301-document
collection: a selective read went from ranking on a secondary 5 times out
of 5 to 0 out of 5 after twelve full-collection finds. It is keyed by
shape now.

**A secondary's error became the client's error.** The boundary chose to
route the read; when the secondary answered with a failure, that failure
went straight to the caller. So fan-out could turn a read the primary
would have served perfectly into an error the application could do nothing
about, because it sees one node and cannot retry elsewhere. An
optimisation is not allowed to reduce availability. The read is now re-sent
to the primary, fan-out goes off for that connection, and
`voyd_fanout_retried_on_primary_total` counts it. The retry goes through
ordinary enforcement, which is asserted rather than assumed.

What the same pass did *not* break, worth recording too: twenty concurrent
clients doing five paged reads each returned the right 301 documents every
time; a primary made to fail every mark lookup produced `refused 101 of
101` and zero documents served rather than one unverified one; an invented
cursor id, a half close, garbage on the port and thirty abrupt resets each
cost one connection and not the listener.

**Two of the probes initially reported a false pass**, and the reason is
worth more than the probes. The payoff measurement had already withdrawn
the collection, so the reads under test were quietly running on the
primary and the secondary failures being injected touched nothing. A
hostile pass against a boundary that adapts has to pin the adaptation
first; `--fan-out-give-up 0` exists partly for that.

The other two were wrong, and wrong in the direction that talks a reader out
of the tool. This page said the boundary does not "honour read preference, or
retry a write the client already saw fail." Both were reasoned rather than
measured. Measured:

- **Read preference is honoured against a topology of one.** The
  `*Preferred` modes and `nearest` are served by the primary, which is what
  the spec prescribes when no secondary exists, and the refusal still
  applies to every one of them. A `secondaryPreferred` read carrying a tag
  set that matches nothing falls back to the primary ignoring the tags,
  again per spec.
- **Strict `secondary` is an error, not a quiet primary read.** That is the
  one case that could have handed a caller a correct-looking answer to a
  question nobody asked, and it fails client-side before a byte is sent,
  because `secondary` is passed through the `hello` rewrite untouched.
- **Retryable writes are armed.** `txnNumber` is attached and the driver
  sees `ReplicaSetWithPrimary` -- a *richer* topology than the same driver
  gets connecting directly with `directConnection=true`, which sees
  `Single`. That is the `setName`-is-kept decision above paying off. The
  proxy does not retry because the driver does; §3's `replSetStepDown` test
  already walks that whole path.
- **Sessions and multi-statement transactions cross intact**, and a read
  inside a transaction still refuses.

Every line of that is now an assertion in
`tests/test_the_wire_is_the_front_door.py`. Restating a claim in prose and
leaving it untested would have replaced a pessimistic guess with an
optimistic one, which is not an improvement.

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

It scales close to linearly. `voyd/wire/bench.py`, 14 cores, 100 documents
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

**And the mirror of it, found by asking that question the other way round
-- closed, and it was open longer.** `$out` hides the documents by writing
them somewhere else. A `distinct`, a `count`, or a `$group` hides them by
turning them into something else first, and the reply comes back to the
client either way. Measured against one live row and one revoked one:

    find through the boundary:        ['live']
    distinct("owner"):                ['live', 'revoked-that-should-be-gone']
    aggregate [{$count: "n"}]:        [{'n': 2}]
    aggregate [{$group: "$owner"}]:   ['live', 'revoked-that-should-be-gone']
    aggregate [{$project: {owner:1}}]:['live', 'revoked-that-should-be-gone']
    aggregate [{$match: {}}]:         ['live']

An ordinary driver through the proxy against a real `mongod`, not a unit
test: the same connection, in the same second, refused the revoked document
to `find` and handed its owner's name to `distinct`. The last line is the
control, and it is why this went unnoticed: ordinary retrieval was correct
the whole time, so every path anybody actually looked at said the boundary
was working.

`filter_batch` only acts on a `cursor.firstBatch`/`nextBatch`, so `distinct`
and `count` were never offered a batch at all. The third is the quiet one:
the batch *arrives*, `Guard.filter` runs on it, and `len(kept) ==
len(batch)` holds because a `$group`ed document has no marks to be refused
on. The boundary said yes by having nothing to say no about -- a
per-document check whose precondition, *these are still the documents*, was
never checked.

Closed by **push-down, not refusal**, and the difference is the whole of
what makes this usable. `$out` cannot be made safe by a proxy -- the copy
happens where the boundary is not. A count can: the refusal is a *query*,
so the boundary puts it into the pipeline ahead of the reducing stage (or
into `count`'s and `distinct`'s `query`) and the server reduces over
admitted documents only. Same rewrite-rather-than-refuse instinct as
`delete` becoming a revocation. Re-measured, same rig:

    distinct("owner"):                ['live']
    aggregate [{$count: "n"}]:        [{'n': 1}]
    aggregate [{$group: "$owner"}]:   ['live']
    aggregate [{$project: {owner:1}}]:['live']

Ordinary retrieval is not touched at all -- `$match`, `$sort`, `$limit`,
`$vectorSearch` and friends still return byte-identical bytes, because
`filter_batch` already covers them and a rewrite would be cost with no
guarantee.

**Refusing is what happens when the push-down would be a lie**, and there
are exactly three such cases. They matter more than the fix:

1. *A rule that cannot express itself as a query.* `_query` in
   `admission/core.py` already says a rule with no clause "is simply
   enforced on the way out instead" -- fine for a batch, useless for a
   number. A filter built from only the rules that *can* speak is narrower
   than the guarantee, and a count too high by exactly the rows the silent
   rule would have caught is the original bug with an extra step.
2. *A rule that asks who is calling.* This process holds no caller.
3. *A declared tenant the command does not pin.* `Guard.filter` takes the
   scope from the batch it is judging. A reduction has no batch, so an
   unpinned tenant is not a narrower answer -- it is every tenant's rows
   summarised into one number.

`explain` is refused rather than rewritten for a fourth reason: an explain
of a rewritten query describes a command the client did not send.

**What it costs, said plainly.** On a **sealed** collection, `count`,
`distinct` and every reducing pipeline now error, because case 1 is
permanently true there -- whether a row decrypts is not a thing `$match`
can ask. That is a real capability removed from a real workload, and it is
the right trade only because the alternative is a number that silently
counts shredded rows. One test in the suite was relying on it:
`test_an_erased_document_does_not_fail_the_page_it_is_on` opened with a
`count_documents` control, which was measuring the leak.

Held up by `tests/test_a_derived_read_cannot_launder_a_forgotten_fact.py`.

**And the same hole on the plain `find` path, which is the worse one.**
Found by asking what *else* reaches the per-document check carrying
documents whose marks it cannot read. A reduction was one answer. A
projection is the other:

    find({})                    ->  [1]
    find({}, {"text": 1})       ->  [1, 2, 3]
    find({}, {"forgotten": 0})  ->  [1, 2, 3]

One live row, one expired, one revoked, through the proxy with an
ordinary driver. `enforce` reads the marks off the documents in the batch;
the projection removed them; and absent is not refused, because absent is
how a *living* document looks -- no deadline means pinned, no revocation
mark means live. The whole batch was admitted.

This needs no aggregation and no intent. `find({}, {"text": 1})` is what
an ORM selecting columns emits, what a driver's `projection=` produces,
what anybody trimming a payload writes. It turned the guarantee off for
that read, silently, in the direction of returning more.

Closed the same way as the reductions, because it is the same problem: if
the verdict cannot be read off the reply, put it in the query, where a
projection cannot reach it. The rewrite goes into `filter` (or
`findAndModify`'s `query`), never into the projection -- a boundary that
added fields to satisfy itself and left them in the answer would be
paying for the guarantee with the client's contract. `findAndModify`
spells its projection `fields`, and covering one spelling and not the
other is the mistake `findOneAndDelete` already was.

**Still open in the same family:** a `$lookup` *from* an unguarded
collection *into* a guarded one is not seen at all, because the command
names the unguarded collection and no guard is found. The allowlist covers
the guarded side only.

---

## 4. Coverage

477 tests, ~8,479 lines, against 7,626 lines of `voyd/` and 7,555 of
`voyd/wire/`. `voyd/` shrank by ~600 and `voyd/wire/` grew by ~500 in the same
pass: the library front door was deleted and the guarantee it was the last
holder of moved to the wire. A cut that only subtracted would have been a
smaller number and a smaller product. Well-targeted rather than thorough: the coverage is by *claim*,
which is the right axis, but it is not line coverage and should not be
mistaken for it.

**124 lines in one file are mentioned by no test file**, and it is
defensible: `composition.py` declares the protocols a type checker reads
and the runtime never imports. It used to be two files and 189 lines;
`trait.py` joined the tested set when the tools that provision indexes
became its callers.

That figure is a name-scan, not coverage, and it is re-measurable in four
lines rather than quoted -- which it needed to be. It previously read "557
lines" across four files, two of which (`expiry.py`, `sealing.py`) had since
gained tests that name them. Wrong in the number *and* the list, and neither
was going to fix itself:

```python
tests = "\n".join(p.read_text() for p in Path("tests").glob("*.py"))
[(p, len(p.read_text().splitlines())) for p in Path("voyd").rglob("*.py")
 if p.name not in tests and p.stem not in tests]
```

**Every claim is attached to a file, and that mapping is checked.**
`CLAIMS.md` names each guarantee and the test that would go red if it stopped
holding; `tests/test_every_claim_names_its_evidence.py` asserts the mapping
in both directions and refuses a citation it cannot parse. Currently 29
claims across 28 test files -- not quite a bijection, because lineage is
two claims held by one file: the cascade on read, and the ancestry closed
on write. They fail separately, so they are stated separately.

**What that is worth, stated narrowly.** It closes the gap between a README
sentence and a file that runs in CI. It does *not* know whether a test is any
good, and this page has the counter-example: a test on that very map had a
docstring about a page of fifty documents, asserted a page of one, and passed
under sabotage for two commits (§1). Attachment is a floor. A reader who
takes "23 of 23 attached" as "23 guarantees verified" has made exactly the
substitution this project is about.

**Consider:** the obvious next step is to check that each cited file's
assertions relate to the claim, and there is no honest way to do that
mechanically. What would help is the thing §1 asks for -- somebody outside
reading a claim, disagreeing, and finding the test that should have caught
them being wrong.

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

**`mypy` reads `voyd/wire/` now, and the exclusion is gone.** This entry used to
explain why it did not, and the explanation was a count: *`voyd_wire.py` has
31 errors*. By the time anybody re-measured it was 59, in a file that had
grown to 3,180 lines and holds the concurrency, the failover and the
byte-level protocol rewriting -- the hardest code here, and the least
statically checked, kept that way by a stale number acting as an argument.

It is zero. And the 59 were never 59 problems, which is the part worth
recording: **two root causes were a third of the total.** Seventeen
`attr-defined` errors were one decision -- `Meter` setting its counters from
`GLOBAL` instead of declaring them, which had removed a real drift and paid
for it in visibility. Sixteen `arg-type` errors were one unannotated dict
splatted into `**kwargs`, where `dict[str, object]` erased all eight of
`pump`'s parameters. Both are fixed in a way that keeps what the original
change bought: the counters are declared *and* initialised from `GLOBAL`,
with a test asserting the two sets are equal, so the duplication is checked
rather than merely present. Duplication that cannot drift is two views of
one fact.

The rest were individual, and most were narrowings a reader was doing in
their head: a payoff record indexed after checking a *different* variable's
nullity, a guard printed after a check that did not include it, a
`Meter | None` used inside a closure that only ever runs when it is not
None. Two were real if unlikely -- pymongo's address type permits a portless
entry, which this proxy cannot dial and now drops explicitly; and one name
held two different tuple shapes in one function, readable only because
`[1]` happened to mean the body in both.

One was a committed lie about a return type. `voyd_bench.seal_cost`'s inner
coroutine was annotated `tuple[float, float]` and had been returning
`tuple[list[float], list[float]]` since the spread was added -- so the
function that reports a median and a range was documented as returning one
number each way, and seven errors downstream were the checker noticing.

**The two remaining suppressions are both at the pymongo boundary**, and
neither is a blanket. Reaching into `_authenticate_scram` is deliberate and
argued where it happens: the client proof, the salting and the
server-signature check stay in the library. The `_AuthShim` handed to it is
not a `Connection` and is not pretending to be beyond the two methods SCRAM
calls on it -- satisfying that type means constructing a real connection
pool, which is the thing being avoided.

**And `ruff` caught a bug `mypy` did not.** The helper that narrows a
command's target was first called `named`, and `refuse_unrewritable` already
binds a local `named` further down -- so the name was function-scoped there,
and the call at the top of that same function would have raised `NameError`
before a byte reached the server. `F823`, in about a second, on a line a
type checker had nothing to say about. Worth remembering which tool is for
what.

`capabilities.py` was listed here as "the one with no real excuse" and now
has seventeen. It was a bad gap specifically because that module decides
which search tier everything above it uses, and its own docstrings record
two occasions when it got that wrong silently for months — Atlas inferred
from the connection string, and a hardcoded `(8, 1)` floor that told every
8.0 deployment it could not fuse ranks. Both are now tests. A regression
that is only described in a comment is one that can come back.

**Consider:** the suite is fast by default (473 tests, ~150 seconds) with
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

## 5. What `--key-vault` costs

This section exists because the trade is real and the README leads with the
property it spends. Everything else the wire boundary does is a refusal: it
is handed documents and returns the ones a prompt may see, which is why
`reachable()` is pure, why the proxy holds no database connection of its own,
and why refusal costs 2.3 microseconds per document. Those are the same fact
said three ways, and `--key-vault` gives all three up.

**Why it had to be given up.** Refusal binds *this application's read path*
(§2). A replica does not run it, a snapshot does not, a backup restored next
year does not, and a DBA with a shell does not. No amount of refusing closes
that -- the plaintext is on disk and every copy of the disk has it.
Destroying a key closes it for every copy at once without visiting any of
them. But a key is a thing you must hold, and a boundary that holds no keys
cannot destroy one.

**What is now true with the flag on**, stated rather than discovered:

- **The boundary has a database connection of its own.** One per worker, to
  the key vault. Every other upstream connection this proxy makes is the
  client's.
- **The boundary holds KMS credentials and is a custody holder.** It prints
  which rung is in force at startup, and prints `THIS BOUNDARY NOW HOLDS
  KEYS` beside it, because a reader who learned the purity claim from the
  README is owed the correction louder than a footnote.
- **A sealed read costs about 8.1 microseconds per document rather than
  2.3**, because it decrypts before it refuses. That ordering is not a
  preference: it is the order `Admission._unsealed` uses, and the two must
  agree or the same document would be admitted through the library and
  refused through the wire. Measured by `voyd_bench.py --seal` against a
  real key vault: decrypt 5.8us, stable to a hundredth across passes;
  encrypt ~8.7us warm and ~26us on the first pass, while libmongocrypt's
  key cache fills; refusal 2.3us. The benchmark prints the spread rather
  than one draw, because that first encrypting pass is three times the
  steady state and quoting a single sample of it to two decimal places
  would be a precision claim this page cannot support -- an earlier
  version of this line said "21.0us" and that was exactly that mistake.
  Unsealed collections are untouched and still take the pure path, so a
  deployment sealing one collection of twelve pays for one of twelve.
- **A document refused by a deadline has still been decrypted** by the time
  the deadline sees it. Wasted work, not a leak -- it never leaves the
  process -- but worth naming.

**What is bought** is the sentence the library version cannot say. In-process,
`schema_map` encrypts below the *application*, so no writer in that Python
process can forget. On the wire it encrypts below the *driver*, so no writer
in any language can: not the Node service, not the migration script, not the
shell, not the notebook, not the one written next year by somebody who has
not read any of this. That is the same upgrade the wire gave `delete`,
applied to the stronger guarantee.

### The defect that running it found

The first working version destroyed the key and nothing else, which is what
"crypto-shredding on the wire" sounds like it should mean. It was wrong, and
it was wrong in the way this repository is named after.

Destroying a key is not instant at the reader. libmongocrypt caches data
keys, so a process that decrypted a scope a moment ago keeps decrypting it
until that cache turns over -- about 60 seconds, which is the same shape and
very nearly the same number as the TTL monitor window the README opens by
complaining about. A shred on its own therefore opened *a second
delete-is-a-wish window, inside the feature that exists to close the first
one*: the boundary reported an erasure, the operator believed it, and the
plaintext kept being served for the next minute.

`keyring.py` already had the answer written down -- *unreachable first,
erased second; the reverse order is the bug* -- and the wire shipped the
reverse order anyway. So an erasure through the boundary is now two things
in one command: the scope's documents are revoked, which makes them
unreachable on the very next read with no window at all, and *then* the key
is destroyed, which makes every copy unreadable everywhere once the cache
turns over. The two halves cover each other exactly, which is the argument
for having both rather than choosing.

It was found by pointing a driver at it and reading the output, not by the
suite going red -- §1, again, and this is the fourteenth. The assertion that
now catches it (`test_destroying_a_key_is_immediate_not_eventual`) was
written after the defect, which is the honest order.

### What it reports, and the one thing it cannot

The read half needed no new series: the undecryptable tally is recorded on
the *guard* rather than beside it, so it arrives in
`refused_by_reason_total` with the deadline and the revocation, where an
operator is already looking. The write half had nothing at all, which is
worse than it sounds -- a boundary that silently stopped encrypting is
indistinguishable from one that is encrypting. `sealed_writes_total`,
`sealed_reads_total`, `seal_refused_writes_total`, `erasures_total` and
`erasure_revocations_total` are the five that close it.

**`erasures_total` and `erasure_revocations_total` are a pair.** The first
climbing while the second stays flat is the ordering defect above as a
graph: a key destroyed with nothing marked ahead of it.

**What the per-reason series cannot tell you** is an erasure from an
expiry. A revocation writes the mark *and* pulls `expire_at` in, and
`Deadline` is declared first, so an erased subject is refused under
`deadline` -- the same reason a naturally expired document reports. That is
not new with sealing; it is what every `delete` rewritten as a revocation
has always done. But it means `refused_by_reason_total` is the wrong place
to ask a compliance question, and the erasure pair is the right one.
**Consider:** reporting the *first* reason that fires is a choice, and a
rule set could instead report all of them. That would make the series
overlap and stop summing to the refusal total, which is a worse trade than
the ambiguity. Undecided, and not currently a problem anybody has.

### Open, and marked

**An erasure is recognised by its shape, not by a verb.** The key vault is an
ordinary collection, so `db["__keys"].delete_one({"keyAltNames": "alice"})`
is how any driver in any language asks -- which is the right interface and
is also why the boundary has to *notice*. Only an exact match or an `$in` on
`keyAltNames` is recognised. A filter this cannot read forwards the delete,
so the key still dies, and the revocation that should have preceded it is
skipped. **Consider:** that is fail-open on the *window*, not on the erasure.
A regex or `$nin` delete against the vault would erase correctly and leave
the minute-long window open, and nothing currently refuses it.

**The boundary declares who embeds; it does not create the index -- but it
now checks.** This entry previously read, in full, that the declaration and
the index could disagree and that nothing here read Atlas back, with a
paragraph about why creating an index is a schema change against a cluster
the proxy does not own.

That paragraph was a category error, and it is worth leaving the correction
visible rather than editing it away. *Creating* an index is a write and
deserves the caution. *Reading one back* is a `$listSearchIndexes` call. The
risk of the first was used to justify skipping the second, which is not a
judgement call -- it is two different operations wearing one sentence.

`--verify DB` now asks, read-only, before serving: a TTL index behind every
`deadline()`, an index leading with every `tenant()`, an `autoEmbed` field
naming the model every `auto_embed()` declares, a `binData` validator behind
every `sealed()`. `--verify-only` exits instead of serving, which is the form
a deploy gate wants. See `voyd/wire/preflight.py`; the argument for it is
`capabilities.py`'s own -- a claim about software this package does not ship,
with no expiry and nobody responsible for it, is asked rather than assumed.

**It needs a database name, and that is not laziness.** A policy file names
collections; the *client* names the database. This process therefore cannot
know which database to check, and inferring one would be the exact mistake
`capabilities.py` was written to stop. So it is an argument.

**Consider:** creating the index from the declaration is still not done, and
the caution above is the real reason now rather than a borrowed one. A wrong
index definition is a relevance failure, which this page already calls the
hardest kind to attribute, and a proxy that silently altered search indexes
on a cluster it does not own would be a worse surprise than the one it fixes.
The check closes the detection half; the creation half stays with the
library, where an operator called `ensure_indexes` on purpose.

**Still open, and now named rather than implied:** the preflight runs once,
at startup. An index dropped or redefined while the boundary is running is
not noticed, and the boundary will go on refusing client vectors for an
index that stopped being an autoEmbed one an hour ago. A watcher is
implementable -- `$listSearchIndexes` is cheap and change streams exist --
and is not implemented. What would make it worth building is somebody
hitting it.

**What `--verify` cannot check**, because nothing on the wire can: whether
the *documents already stored* were embedded with the model the index now
declares. A re-indexed collection whose old rows carry vectors from last
quarter's model is exactly what `embedded_with()` refuses per document, and
that is the right place for it -- a per-row question has a per-row answer.
The preflight reads definitions, not data.

**Queryable Encryption is library-only and stays that way for now.** The
wire seals with CSFLE, which is the mode whose `keyId` may be a JSON pointer
-- the only reason per-subject shredding is possible at all. QE rejects a
pointer, so a key is bound per field per collection at creation time, and
destroying it erases that field for every document rather than for one
subject. That is the opposite of what `--key-vault` exists to provide, so
the wire does not offer it. **Consider:** a deployment that genuinely needs
a queryable ciphertext needs collection-granularity erasure too, and should
be told so rather than handed a flag that quietly changes what an erasure
request means. The full trade, with the error message, is in
`voyd/engine/keyring.py`.

**A sealed collection is never ranked on a secondary.** Fan-out takes the
marks from the primary and the documents from a secondary, which is right
for a verdict that reads marks and wrong for one that must decrypt what it
was handed. Sealing and fan-out otherwise compose; this is the narrow case
where they must not, so it is a routing rule with a test rather than a
discovery.

**Ephemeral custody with `--workers N` is a data-loss shape, and is avoided
by construction rather than by care.** The master key is built in the parent
before the fork and inherited, so every worker has the same one. Built per
worker it would mint a different key each, and a tenant written through one
worker would be undecryptable through the next -- a bug that appears only at
`--workers 2` and looks like corruption. The default custody is still
`Ephemeral`, which does not survive a restart, and the boundary says so in
capitals at startup.

**An erasure revokes only the rows the key protected**, meaning rows that
carry one of the sealed fields. A row of the same tenant with none of them
was never encrypted, so it has no cache window to close, and revoking it
would be the boundary inventing policy out of a key deletion -- an operator
would be surprised to find unencrypted documents unreachable because they
destroyed a key. Somebody who means "forget this tenant entirely" has a
verb for that already: a `delete` on the collection under
`on_delete="revoke"`. **Consider:** the test matches on `$exists` rather
than on the BSON subtype, so a plaintext value sitting in a field the
policy declares sealed is revoked too. That is deliberate -- such a row was
written while sealing was off and an erasure should still reach it -- but it
is a judgement rather than a derivation.

**A pipeline update that may assign a sealed field is refused.** Its stages
compute values inside the server, where this boundary cannot encrypt what
they produce, so the field would land as plaintext written by the server
itself. Detected by looking for the field name in the pipeline's text, which
is deliberately over-broad: a pipeline that merely mentions the name is
refused too. **Consider:** that is the safe direction and it is still a
false positive somebody will hit.

**`$inc`, `$push` and `$rename` on a sealed field are refused**, because a
sealed value is opaque ciphertext and those operations have no meaning
against one. `$set` and `$setOnInsert` are the two that do.

**The server-side validator is not applied by the wire.** In-process,
`Keyring.enforce()` puts a `binData` validator on a sealed collection, so a
writer that bypasses the library entirely is refused by the *server*. The
wire boundary does not install it, so a second service connecting directly
to the cluster can still write plaintext into a sealed field. **Consider:**
the boundary could install the same validator at startup. It would close the
gap for every writer, and it would also mean a proxy silently altering
collection options on a cluster it does not own, which is a bigger surprise
than the one it fixes. Undecided, and unclosed today.

---

## 6. Operational notes that will surprise somebody

**A search index is not free, and `mongot` is shared.** Nine abandoned
databases carrying 24 search indexes between them was enough to starve new
index builds and make a healthy test fail for a reason unrelated to
refusal. If index builds get slow, count your leftovers before debugging
anything else.

**Atlas Local registers no embedding models.** It *declines* an `auto_embed`
declaration and silently falls back to expecting a client-supplied vector.
Anything testing server-side embedding locally is testing the opposite of
what it claims.

**The embedding model list moves.** `voyage-3` is the example: this
repository named it everywhere until Atlas stopped registering it, and a
policy file is a *claim about software this package does not ship*. The
server reports the supported set in its own error, which is the most
useful error message in this stack -- and the reason `--verify` asks the
cluster instead of trusting the declaration. Everything here now says
`voyage-4`, which will also be wrong one day; the check is what does not
go stale.

**A collection must exist before you can index it.** Atlas answers "Error
retrieving collection UUID," which reads like a permissions problem.

**`.primary` is `None` on an undiscovered topology.** The driver connects
lazily. Ping first, or you silently select whichever node DNS returned —
which on a replica set reads perfectly and rejects every write.

---

## 6b. Who is asking, and what it still costs

**Caller-scoped rules run on the wire now.** `restricted_to()` and the
clearance rule declare `needs_caller`, and this process used to hold no
caller, so `expressible_clauses` returned `None` for them and
`Guard.filter` passed no claims -- the last thing the library front door
could do and the wire could not.

The claims come from the *deployment*, and that is the design rather than
an implementation detail. `for_caller` in `admission/core.py` says it
outright: a handle that believed `{"clearance": "secret"}` because it was
passed one "would be an authorisation system whose only input is the
attacker's". A proxy is in a worse position still, because the client is
the only thing talking to it. So the boundary asks `connectionStatus` on
the client's own connection and reads `authenticatedUserRoles` -- the
server's account of who authenticated there, which a client cannot forge
without forging the authentication. A role *is* a group, which is what
`db.createRole({role: "legal"})` already means, so `restricted_to("groups")`
needs no further declaration.

Asked lazily, once per connection, and only for a collection whose rules
ask: a policy with no caller-aware rule pays nothing, and an authenticated
connection cannot become somebody else.

**What it cost to get right, because both bugs were the interesting kind.**

*The ordering.* Identity was resolved after the push-down that needs it,
so every caller-scoped reduction was refused for want of an identity the
boundary already had the means to ask for. Refusing is the safe direction,
which is exactly why it survived a test run -- it looked like the
documented behaviour.

*Judging a reply twice.* With the refusal pushed into the query, the rows
come back already filtered and what arrives is a *reduction over* them.
Running the per-document check on that asks the rules about documents that
no longer exist, and one rule answers badly: `Restricted` refuses a
document with no audience, because untagged is not public. A `$group`
result has no audience. So the boundary filtered correctly server-side and
then threw its own answer away -- `count_documents()` returning 0 on a
collection the same caller could `find()` two rows in. Deadline and
revocation hid it for weeks' worth of tests by being absent-tolerant.
Replies to a pushed-down read are now recognised and left alone, and the
cursor is matched on the `getMore` *request*, because the batch that
drains a cursor comes back with `id: 0` and has nothing left to match on.

**Both request loops answer the same way, and that took moving one.**
`Conversation` carried its own copy of "ask on the client's own
connection" and no identity at all, so a `--fan-out` connection to a
caller-scoped collection saw empty claims and refused everything -- safe,
and *different from the default path*, which is the part that matters. One
boundary meaning two things depending on a flag is the drift this package
is about. Both now share one `Backchannel` and one `CallerIdentity`, and
`test_the_fan_out_path_learns_the_same_identity` is what keeps them
sharing it.

**Closed, and it was the blocker: lineage on the wire.** `derive()` and
the cascade behind it -- revoking a source and having the refusal reach
the summary, the answer and the embedding built out of it -- used to exist
only in `admission/lineage.py`, reachable only through the handle. The
wire's one mention of `lineage_field` was in `deciding_fields`, which
reads the name so a projection cannot hide it, and nothing anywhere
followed a parent to its children.

That mattered more than a missing feature, because `CLAIMS.md` carries it
as a headline and **a reader of the README had no way to know the claim
did not hold through the connection string the README tells them to use.**
The claim was true; the artifact it was true of was not the one being
recommended. It is now true of both, and `voyd/wire/cascade.py` is where
the wire's half lives.

**The decision, and why.** A cascade is a multi-document write derived
from a read, which the proxy does nowhere else, so the question is what
happens when the second write fails after the first has landed. Three
answers were available:

- **A transaction.** Atomic, and rejected. The proxy would have to open
  one on the *client's own connection*, which changes what that client's
  subsequent reads see -- a far larger surprise than the one being fixed,
  and it makes the guarantee depend on the caller's session staying up
  for the length of a write they did not issue.
- **Refuse `delete` on a collection declaring `lineage_field`.** Honest,
  one evening, and it deletes a headline claim rather than holding it.
- **Children first, then the parent.** Chosen.

The order is the whole mechanism. `cascade_first` resolves the ids the
delete matched, marks everything downstream of them, and only then lets
the rewritten revocation of the source go. A crash in between leaves the
source still reachable and its derivations already gone: a visible
half-erasure the caller fixes by re-running an idempotent delete. The
reverse order leaves the source refused and the summary of it still
answering prompts, with nothing anywhere saying so. One of those two
failures is recoverable by retrying and the other is the bug this whole
package is about, so the boundary fails toward refusing more.

**Resolving the ids is not an optimisation.** `deleteOne` asks the server
to pick one of the documents a filter matches and does not say which, so
a boundary that cascaded from its own second look at the filter would
mark the children of a document the server then did not revoke -- a
cascade and a revocation landing on different rows, under the same
command. The ids are resolved once and *both* halves are pinned to them.
`findOneAndDelete` gets the same treatment, carrying the caller's `sort`
into the resolution, because a boundary that covered one delete verb and
silently not the other is the specific failure §2 calls worse than none.

**The write side had to move too, and this is the part that is easy to
miss.** The cascade is one `$in` at any depth *only because* the ancestry
stored on each document is transitively closed -- a child's lineage is its
parent's lineage plus the parent, so a grandchild already names the
grandparent. The library got that closure from `derive()`, which the
application had to import and call. On the wire, `derive_on_insert` gets
it from the field the application already writes: an insert naming a
parent has its ancestry closed, inherits the earliest deadline among its
parents, and is **refused** if any named parent is missing, out of scope,
or already refused. Without that, the cascade would be correct for
children and silently wrong for grandchildren, which is worse than not
having it.

**What it costs, stated plainly:**

- **A second connection, per worker.** Opened only when some collection
  declares `lineage_field`, for the same reason the vault's is: the
  cascade is the boundary's write, not the caller's. It is dialled from
  `--target`, by construction rather than by a flag somebody could point
  elsewhere.
- **A round trip on the write path.** A delete on a lineage collection is
  now a find plus an update before the forwarded command, and an insert
  naming a parent is a find before it. Collections that declare no
  lineage pay nothing -- the gate is a field being `None`.
- **The cascade can reach a descendant the caller could not have read.**
  The library rebuilds the unbypassable rules when it walks the edge. The
  wire cannot: those rules decide by *who is asking*, per document, and
  there is no query that expresses them. The tenant **is** carried
  across, so the cascade cannot leave the caller's namespace -- that one
  would be a cross-tenant write dressed up as an erasure. What remains is
  that a clearance-gated descendant is marked by a caller who could not
  see it, which is in the direction of refusing more.
- **A tenanted delete that does not pin its tenant does not cascade.** It
  is already refused upstream by the push-down rules; if that ever
  changes, this logs and declines rather than marking every namespace at
  once.

Held up by `tests/test_a_refusal_travels_and_is_gated.py`, which drives
the proxy.

**Closed: an ordered `Clearance`, declared.** It used to want a
`clearance` claim naming a level, and nothing in a MongoDB role says which
level a role corresponds to -- so on the wire it found no claim, "no claim
is the lowest, not the highest", and it refused every document to
everybody. Fail-closed, which is the right direction and the wrong
outcome.

The missing piece was never a claim source. It was that **a role says who
somebody is and not how far up a ladder they stand**, and only the
deployment can say which. So the policy file says it:

```python
classification = clearance(
    order=("public", "internal", "secret"),
    roles={"analyst": "internal", "sec-cleared": "secret"})
```

With a mapping the rule reads `roles` -- which `connectionStatus` does
answer -- and takes the **highest** rung any of the caller's roles maps
to. `unsuppliable_claims` then has nothing to report and the boot warning
does not fire.

Four defaults, and each is the one somebody would otherwise get wrong:
a caller with no mapped role is cleared for the lowest rung rather than
the highest; a role this policy never mapped contributes nothing rather
than raising, because an unmapped role is an unanswered question; a
document labelled with something outside `order` is refused, since an
unrecognised classification is not a low one; and an unlabelled document
is refused unless `default` is set, because untagged is not public and
untagged is exactly the population written before anybody thought about
this. A role mapped to a level the ladder does not define is a **load**
error -- it would otherwise clear its holders for nothing, silently, and
the collection would read as empty for the people it was written for.

The unmapped form is still declarable, for a process that already knows
the level, and is still **announced at boot**: a rule whose claim
`claims_from` cannot produce prints a warning naming the claim, what the
wire can supply instead, and the fact that every read of that collection
will be refused.

Held by `tests/test_a_clearance_ladder_is_declarable.py`, half of it pure
and half of it two real MongoDB users reading through the boundary.

---

## 7. Decisions waiting on evidence

Not frozen out of caution — frozen because building them before somebody
wants them adds surface that has to be kept honest forever.

| | what it would take | what would unfreeze it |
|---|---|---|
| **`$lookup` into a guarded collection** | reading the `from` of every pipeline on every collection | somebody joins to a guarded collection and is surprised. §3 closed the guarded-side case; this is the other direction |
| **Revocation that propagates** | a sync protocol | `perimeter.py` says who else holds a copy is auditable and never enforceable. That is true without a protocol between you and the replica — and stops being true with one |
| **Reverse-indexed receipts** | a storage decision | *"which answers were built on this fact?"* is already a query for anything written back; what is missing is the artefact that **left** — a Slack message, a fine-tune |
| **A second engine** | doubles the surface | a user who is not on MongoDB |
| **A second listener topology** | real work | `--workers` pins clients to one host; fanning out is still a different problem |

---

## 8. Deliberately not doing

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

## 9. If you read one thing

The recurring defect in this project is not a category of bug. It is a
**category of silence**: an instrument that is wrong and says nothing. The
decode that returned `None` and was read as "not a delete". The proxy that
answered `deleted_count=1` while really deleting. The scanner that blessed a
path it never read. The suite that passed because a closed socket counted as
alive.

Every one was found by running the thing at the size and in the manner the
documentation promised, and none by re-reading the documentation. That is
the method, and it transfers to whatever gets built next.
