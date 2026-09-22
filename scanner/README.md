# voyd-scan

**How many reads in your repository can serve a document your own code already
treats as gone?**

One stdlib file. No database, no credentials, no install, and no dependency on
VOYD — you point it at *your* repository, not this one.

```bash
python scanner/voyd_scan path/to/your/repo
```

```
scanned 34 file(s).
2 collection(s) carry a mark your code expects its reads to name:
  orders: `valid_until` (your convention: 9 of 11 reads name it)
  notes:  `expire_at` (declared by a write or index)

3 of 14 read(s) against them do not:

  app/api/search.py:88   orders  (filter does not name `valid_until`, which 9 of 11 reads here do)
  app/api/export.py:31   orders  (filter does not name `valid_until`, which 9 of 11 reads here do)
  app/store.py:5         notes   (filter does not name the mark)
```

## The pattern match is not the interesting part

Semgrep and CodeQL can already express *"find reads on collection X that do not
name field Y"* — and express it better than this file does. What they cannot do
is work out what **Y** is without somebody already knowing the answer and
writing the rule.

That inference is the whole tool. The abstraction underneath it:

> a mark-bearing collection + a read that does not name the mark
> = a class of silent defect

Deletion is the sharpest instance of that class, not the definition of it.
`expire_at` is one spelling of Y. So is `valid_until`, `is_active`,
`tombstone`, `tenant_id`, and a field name nobody has invented yet.

## How it finds Y

**Declared.** A TTL index names its own field:

```python
db.sessions.create_index("purge_after", expireAfterSeconds=0)
```

`expireAfterSeconds` is MongoDB's word; `purge_after` is your team's. The
pairing hands over Y for a name this scanner has never heard. A write or
filter that names one of the usual soft-delete spellings counts too — that
list is a shortcut for small repositories, not the mechanism.

**Inferred, from your own convention.** For each collection, the fields its
reads actually filter on are counted. A field most reads name and some do not
is a convention with a deviation — and **the convention is the spec, so the
deviation is the finding**. No configuration, no allowlist, no rule to write.

This is why the output is not "you might have a problem" but *"you already
have a convention, and here is the exact line where it already failed"* — the
founding incident, computed from your own repository.

It also **gets stronger on larger codebases**, because the majority that
establishes a convention is bigger. That is the opposite of how pattern-based
static analysis usually scales, where more code means more noise.

Two guards keep the inference honest, and both are pinned by tests:

- A field needs **at least two reads that honour it and at least one that does
  not** — so three judgeable reads minimum. One read naming a field is a fact
  about that read, not a rule the others are breaking.
- A field that **every** read names is deliberately *not* reported. There is
  no deviation, so there is nothing to say — and manufacturing a mark out of a
  unanimous schema would let a real leak look filtered because it happened to
  name the unanimous field.

A read must name **every** mark its collection carries. A deadline and a
tenant key are the same defect in different clothes; a read that remembers one
and forgets the other is not half safe.

## Indeterminate is a proof obligation, not a shrug

The output is three-state — **leak**, **filtered**, **indeterminate** — and
the third one is what makes the first two worth reading. A filter assembled by
a helper cannot be read from source, and calling it a leak would be inventing
a number. Most tools collapse to found/not-found and quietly spend their
credibility on the first false positive.

But a shrug is not a result either. So an unjudged read is an obligation you
discharge **in the source**, the way `# type: ignore` discharges one for mypy:

```python
return db.notes.find(living(user))   # voyd: filtered(expire_at) -- living() applies it

return db.notes.find({})             # voyd: audit -- the retention report, by design
```

| claim | says | effect |
|---|---|---|
| `# voyd: filtered(field) -- why` | the filter you cannot see does name the mark | the read moves to **discharged** |
| `# voyd: audit -- why` | this read deliberately does not filter | the read moves to **audited**, reason printed |

Neither is a way to go quiet:

- Both are **counted and printed**, with the author's reason next to them.
  `audit` is the static half of VOYD's `including_refused()` — a door with an
  alarm, not a permanent pass — and an `audit` with **no reason given is
  itself a finding**.
- A claim that stops describing the code under it is reported as **stale**:
  `filtered` on a read whose filter is plainly visible, or on one that plainly
  does not name the mark. This is mypy's `warn_unused_ignores` and it is for
  the same reason — without it, an annotation added once keeps suppressing
  after the code beneath it changed, which is how a suppression file rots into
  a lie.
- Claims are read with `tokenize`, so a `# voyd:` inside a string literal is
  not a claim.

`--strict` counts unjudged reads and stale claims towards the exit code. That
is the ratchet: the unjudged column can be driven to zero and then *held*
there by CI, which is something a number nobody can act on cannot do.

VOYD's own repository passes `voyd-scan --strict voyd/` with no claims at
all, and that is the weaker reading rather than the stronger one: nothing in
this package reads a guarded collection, so there is little here for a
scanner to see. A zero means the visible surface is small, not that it is
safe.

## Exit codes

It drops into CI, so the status has to mean something precise:

| code | meaning |
|---|---|
| `0` | nothing found in what could be read |
| `1`–`254` | that many candidate leaks — **`254` means 254 or more** |
| `255` | the scan could not run (a path that does not exist) |

With `--strict`, the count is leaks **+** unjudged reads **+** stale claims.
Without it the count is leaks only, so adding `--strict` to this tool did not
change what an existing CI job means.

Two of those rows are corrections rather than decoration. An exit status is
one byte, so an unclamped count means a repository with exactly 256 leaks —
the worst one this tool could be pointed at — exits `0` and reads as clean.
And `rglob` on a missing directory returns nothing rather than raising, so
`voyd-scan ./scr` (for `./src`) would otherwise print a clean bill of health
about a directory that does not exist. Both are the failure this scanner
exists to find, committed by the scanner. The real count is always printed,
never inferred from the status.

## If your data access is wrapped — read this one

Most teams do not call the driver directly. They have a repository class, a
`Store`, a `fetch_all`. **To those teams this tool is blind**, and a blind
tool that prints "nothing to check" is committing the exact defect it exists
to find.

So it does not print that. When it recognises no read at all, it says so, and
says it is a fact about the scanner rather than about your code:

```
scanned 340 file(s) and recognised no database read at all.

That is a fact about this scanner, not about your code. [...]
Until it finds a read, treat this as unmeasured rather than clean.
```

The remedy is one flag, and the inference works identically through a wrapper
because it never cared what the method was called — only what the filters
agree on:

```bash
python scanner/voyd_scan --read-verb fetch_all --write-verb save src/
```

## Reviewing the claims

`--claims` lists every `# voyd:` assertion in the tree with its reason. This
is the static half of what `including_refused()` does at runtime: the point of
break-glass was never to forbid the unsafe thing, it was to make sure somebody
can *see* it happened. Without this list, anyone can write
`# voyd: audit -- needed for the report` and the finding leaves the count for
good — reviewed once by whoever approved that diff, and never again.

```bash
python scanner/voyd_scan --claims src/
```

Read it the way you would read the break-glass column of an audit log, because
that is what it is. `git blame` supplies the author and the date.

## Other flags

```bash
python scanner/voyd_scan --json app/ services/ > leak_scan.json
python scanner/voyd_scan --all src/                      # every finding, not the first few
python scanner/voyd_scan --allow app/admin/ src/         # exempt an audit module
python scanner/voyd_scan --convention-threshold 0.8 src/ # stricter inference
```

The JSON carries the evidence for every mark — which field, by what route, on
what support — so an inferred finding can be argued with on its evidence
rather than accepted on faith.

**On a large repository the report groups rather than enumerates.** The
inference gets stronger with scale and a flat printout gets proportionally
less usable — true of the analysis, false of the thing a person reads. So the
shared reason and the shared path prefix are stated once and findings are
grouped by directory worst-first, because a thousand leaks are usually the one
module they live in: a 2,000-file tree that would print 1,690 lines prints 32.
`--all` still lists everything.

## Why it is a separate package

The first thing a stranger runs has to cost them nothing. `voyd-scan`
therefore declares **zero dependencies** and never imports `voyd`: a scanner
that pulls a database driver in order to tell you that you have a problem has
asked for more trust than its finding is worth, and a number produced by the
library it makes a case for is not independent evidence.

That also means you do not need this repository. `voyd_scan/__init__.py` is
the entire program — copy it into your own tree and run it there if that is
easier than cloning.

> **Not on PyPI yet.** `pip install voyd-scan` and `uvx voyd-scan` will 404
> today; the commands above are the ones that work. This note goes away when
> `0.1.0` is published.

## What it cannot see

The number is built to be defensible rather than alarming:

- It parses source with `ast`. ORM layers, query builders, and dynamically
  named collections (`db[name]`) are invisible. **False negatives are
  expected.**
- A filter assembled elsewhere — `{**base_filter(), "tenant": t}`, a `$match`
  whose value is a call — is **indeterminate**, never a leak.
- It never connects to anything. It cannot tell you a leak *fired*; it tells
  you a read *could*.

So the output is a floor, not a census. A non-zero floor is still the fastest
way to turn "this is a real problem" from somebody's claim into your own
incident.

## Then what

A leak is a read that can hand a prompt a document the collection's own rule
calls gone. Route it through a filter on the mark — and if you would rather
that be enforced structurally than remembered by every person who opens the
file, that is what [VOYD](../README.md) is for. It is one abstraction at both
ends: what this infers statically from your conventions is what a `Rule`'s
`clause()` states declaratively and the boundary enforces on every read, for
every driver, with nothing to remember.

**Where that stops, and why it is the interesting part.** Some rules have no
query half at all — a token budget refuses a document because of the *other*
documents on the page, so it has no per-document filter and never can. There
is no filter in your source for this tool to look for, and none for a missing
one to be the deviation from. Semgrep and CodeQL have the same nothing to work
with. The partition is checked over the whole rule set in the test above, so
the honest summary is: a scanner reaches exactly the rules that have a query
half, which is why a per-document check on the way out is not an optimisation
of this tool but the only place the rest can live.

The classifier's judgements — and the two ways it could lie about its own
result — are pinned by `tests/test_the_scanner_is_not_confidently_wrong.py`
in the parent repository, because an instrument that hands a stranger "you
have N leaks" earns nothing if N is noise.

MIT.
