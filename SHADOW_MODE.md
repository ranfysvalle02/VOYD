# Shadow mode: ship the measurement first

**Proposal.** A team installs something that changes nothing about what
their retrieval returns and counts how many documents it served that their
own database had already marked as gone. No credential of ours, no
document of theirs on our network, no proxy in anybody's data path.

## Why this axis

Because it is where the exposure measurably is. `examples/drift.py`
measures a real `mongot`: a deleted document stops being ranked in **5ms**
(the result is materialised from the collection, so there is nothing to
return), while a row past its deadline was **ranked for 40.8s with the row
on disk the whole time**. Search was not stale — it correctly returned a
document that existed. The window is the sweeper, and what closes it is a
verdict on the read.

And it is where the exposure is *unknown*. A retrieval that serves an
expired row does not error, does not log, and on a relevance workload
reads as better recall. So the honest position of any prospective user is
not "we are fine" or "we are exposed" — it is **"we have no idea"**.

`LIMITS.md` §1 says the mirror image about us: this suite has never caught
a problem a user hit, because there have been no users. Every defect here
was found by its author. That is the ceiling, and no further testing moves
it.

## The instrument already exists

`examples/shadow.py`, and the part that matters is three lines:

```python
served    = await db.notes.find(q).to_list(None)   # unchanged. still yours.
reachable = notes.reachable(served)                # the read you might have
metrics.gauge("voyd.would_have_refused", len(served) - len(reachable))
```

No rollback story, because nothing rolled forward. The rules are declared
in the same vocabulary a `voydfile.py` uses, so **the artefact that proves
the problem is the artefact that fixes it.**

The count is exact, for an unusual reason: `receipts()` normally
under-reports because the same rule runs inside the query and MongoDB
drops most forgotten documents server-side. Here the documents come from
*your* unfiltered read and are handed to `reachable()` one at a time —
nothing is dropped early, so nothing goes uncounted.

## The product

Small, and small in one direction: **we receive integers and reason names,
never documents.** An agent wrapping those three lines, an ingest endpoint,
one chart, one alert — *"last week your retrieval served N documents your
database had already marked as gone"* — and a button that exports the
rules they declared as a validated `voydfile.py`.

The control plane runs behind `voyd-wire` with a policy of its own, and
secrets use `sealed()` scoped to the account. `declare.py` refuses
`sealed()` without `tenant()` for exactly the reason that matters: one key
per collection makes erasure all-or-nothing. Scoped, "delete your account
and your credentials become unreadable everywhere, including in our
backups" is backed by `examples/shred.py`.

## What the number does not mean

- **It only sees what your data records.** A team that hard-deletes has
  nothing for `revoked()` to find.
- **A low number on one read path may mean that path already has the
  filter.** Correct result, misleading headline. Run it per read path; the
  interesting output is the variance between them.
- **Install only reasons that mean "forgotten".** A `Budget` makes the
  delta mean two things at once. `lineage_field` is not that kind of
  addition and is worth switching on from day one.
- **Even counts are not nothing.** A refusal breakdown by reason describes
  what a corpus holds and who has been trying its doors — the argument
  `LIMITS.md` makes for keeping `/metrics` on loopback applies to
  collecting it across customers.

## The kill criterion

**If median exposure across the first five pilots is zero, stop.** Not
reposition — stop. It would mean the window this project closes is not one
teams fall into, and `README.md`'s *When you do not need this* already
says what the honest answer is then.

One non-zero result from somebody who is not the author is worth more than
everything in `CLAIMS.md`, because it is the first evidence not generated
by the person being convinced.
