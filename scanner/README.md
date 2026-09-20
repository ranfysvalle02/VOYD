# voyd-scan

**How many reads in your repository can serve a document your own schema says
is gone?**

One stdlib file. No database, no credentials, no install, and no dependency on
VOYD — you point it at *your* repository, not this one.

```bash
python scanner/voyd_scan path/to/your/repo
```

```
scanned 1 file(s).
1 collection(s) carry a deadline or mark: notes
2 of 3 read(s) against them do not filter the mark:

  app/store.py:5  notes  (filter does not name the mark)
  app/store.py:8  notes  (filter does not name the mark)
```

Exit code is the number of candidate leaks, so it drops into CI.

```bash
python scanner/voyd_scan --json app/ services/ > leak_scan.json
python scanner/voyd_scan --allow app/admin/ src/     # exempt an audit module
```

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

## How it decides, and what it cannot see

A collection is **deadline-bearing** when your own code treats it as one — a
write or index that names a mark field (`expire_at`, `deleted`, `revoked`,
`tombstone`, and the usual soft-delete spellings), or a read that already
filters on it. For every read against such a collection it asks one question
of the *filter*: do its keys name the mark?

The number is built to be defensible rather than alarming:

- It parses source with `ast`. ORM layers, query builders, and dynamically
  named collections (`db[name]`) are invisible. **False negatives are
  expected.**
- A filter assembled elsewhere — `{**base_filter(), "tenant": t}`, a
  `$match` whose value is a call — is reported as **indeterminate**, never as
  a leak. It will not manufacture a number it cannot stand behind.
- It never connects to anything. It cannot tell you a leak *fired*; it tells
  you a read *could*.

So the output is a floor, not a census. A non-zero floor is still the fastest
way to turn "this is a real problem" from somebody's claim into your own
incident.

## Then what

A leak is a read that can hand a prompt a document the collection's own mark
calls gone. Route it through a filter on the mark — and if you would rather
that be enforced structurally than remembered by every person who opens the
file, that is what [VOYD](../README.md) is for.

The classifier's four judgements are pinned by `tests/test_leak_scan.py` in
the parent repository, because an instrument that hands a stranger "you have
N leaks" earns nothing if N is noise.

MIT.
