"""Your own number: reads that can serve a forgotten fact, from your source.

    python scanner/voyd_scan path/to/your/repo
    python scanner/voyd_scan --json app/ services/ > leak_scan.json
    python scanner/voyd_scan --allow app/admin/ src/

This is a separate, dependency-free package on purpose. It ships apart from
``voyd`` because the first thing a stranger runs must cost them nothing: no
install, no database, no credentials, no import of the library it is trying
to make a case for. One stdlib file -- this one -- which you may also simply
copy into your own repository and run there.

VOYD's founding incident was a count: six read paths against a collection with
a deadline, and one of them forgot the filter. This turns that count outward.
Point it at a repository -- yours, not this one -- and it reports how many
reads hit a collection that carries a deadline or a soft-delete mark *without*
filtering on it. That is the number the pitch is about, computed from code you
already have.

**How it decides.** A collection is "deadline-bearing" if the repo's own code
treats it as one -- a write or index that names a mark field, or a read that
already filters on it. For every read against such a collection, it asks one
question of the *filter*: do its keys mention the mark? A read with no filter,
or a filter whose keys do not, is a candidate leak.

**What it cannot see, stated plainly so the number is defensible:**

- It reads source with ``ast``. Dynamically named collections
  (``db[name]`` where ``name`` is a variable), ORM layers, query builders and
  raw-driver wrappers are invisible. False negatives are expected.
- It inspects *filter keys only*, and only in literal ``dict``/``list``
  arguments. A filter built by a helper (``living("expire_at")``, a shared
  ``base_filter()``) is reported as *indeterminate*, not as a leak -- it will
  not manufacture a number it cannot stand behind.
- It never connects to a database. It cannot tell you the leak *fired*; it
  tells you the read *could*. The live version needs someone's production
  credentials, which is a different kind of responsibility (see
  ``docs/ideas.md``).

So the output is a floor, not a census. A non-zero floor is still the fastest
way to turn "refusal is a real problem" from a claim into your own incident.
Exit code is the number of candidate leaks, so it drops into CI.
"""

from __future__ import annotations

import argparse
import ast
import json
from dataclasses import dataclass, field
from pathlib import Path

# Reads that can hand a document to a caller. Writes are elsewhere: a write
# does not return a forgotten fact to a prompt.
READ_VERBS = {"find", "find_one", "aggregate", "distinct", "count_documents"}
# Writes and index declarations, used only to learn which collections carry a
# mark field -- never reported as leaks themselves.
WRITE_VERBS = {"insert_one", "insert_many", "update_one", "update_many",
               "replace_one", "bulk_write", "create_index", "create_indexes"}

# Field names that mean "this row can stop being valid": VOYD's own deadline
# and revocation fields, plus the soft-delete conventions other teams use.
# Compared after lowercasing and dropping underscores, so ``expire_at`` and
# ``expireAt`` and ``EXPIRE_AT`` are one field.
MARKS = frozenset({
    "expireat", "expireafterseconds", "forgotten", "revoked", "tombstone",
    "deleted", "isdeleted", "deletedat", "softdeleted", "removedat",
})


def _norm(key: str) -> str:
    """First dotted segment, lowercased, underscores dropped."""
    return key.split(".")[0].lower().replace("_", "").replace("-", "")


def _is_mark(key: str) -> bool:
    return _norm(key) in MARKS


def _collection_of(node: ast.AST) -> str | None:
    """The collection a receiver names, or ``None`` if it is not a literal.

    ``db.notes`` -> ``"notes"``; ``db["notes"]`` -> ``"notes"``;
    ``db.get_collection("notes")`` -> ``"notes"``. A variable
    (``db[name]``) is deliberately ``None``: unknowable from source.
    """
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Subscript):
        key = node.slice
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            return key.value
        return None
    if isinstance(node, ast.Call):
        fn = node.func
        if (isinstance(fn, ast.Attribute) and fn.attr == "get_collection"
                and node.args and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)):
            return node.args[0].value
    return None


def _dict_keys(node: ast.AST) -> set[str]:
    """Every string key in the literal dicts reachable from ``node``.

    Descends dicts, lists and tuples so a ``$and``/``$or`` filter or an
    aggregation pipeline is covered. Values are ignored on purpose: a filter
    is defined by what it constrains, and ``{"text": "expire_at happened"}``
    filters text, not the deadline.
    """
    keys: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Dict):
            for k in child.keys:
                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                    keys.add(k.value)
    return keys


def _mentions_mark(call: ast.Call) -> bool:
    """Does a write/index call name a mark field anywhere in its arguments?

    Broader than the read check on purpose: an index is declared as
    ``create_index("expire_at", expireAfterSeconds=60)`` or
    ``create_index([("expire_at", 1)])``, so a bare string constant or the
    TTL keyword both count as evidence the collection carries a deadline.
    """
    for kw in call.keywords:
        if kw.arg and _norm(kw.arg) == "expireafterseconds":
            return True
    for child in ast.walk(call):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            if _is_mark(child.value):
                return True
        if isinstance(child, ast.Dict):
            for k in child.keys:
                if (isinstance(k, ast.Constant) and isinstance(k.value, str)
                        and _is_mark(k.value)):
                    return True
    return False


def _filter_args(call: ast.Call) -> list[ast.AST]:
    """The dict/list arguments of a read -- its filter, or a pipeline."""
    args = list(call.args) + [kw.value for kw in call.keywords
                              if kw.arg in ("filter", "pipeline")]
    return [a for a in args if isinstance(a, (ast.Dict, ast.List, ast.Tuple))]


# Keys whose *value* is itself a filter rather than a value to compare
# against. If one of those is computed, the literal we can see is a shell
# around a sub-filter we cannot.
SUBFILTER_KEYS = frozenset({"$match", "$and", "$or", "$nor", "$not", "$expr"})

_LITERAL = (ast.Dict, ast.List, ast.Tuple, ast.Constant)


def _delegates_filter(node: ast.AST) -> bool:
    """Is part of this literal filter built somewhere this scanner cannot see?

    A literal argument is not the same as a *visible* filter. Three shapes
    hand the real constraint to an expression:

    - ``{**base_filter(), "tenant": t}`` -- unpacking, which ``ast`` records
      as a dict key of ``None``;
    - ``{"$match": handle.match({...})}`` -- an operator whose value is a
      sub-filter returned by a call;
    - ``[stage(), {"$group": ...}]`` -- a pipeline assembled from helpers.

    In all three the keys we can read are a shell, so calling the read a leak
    would be inventing a number. ``{"_id": some_var}`` is deliberately *not*
    included: a variable *value* leaves the keys fully visible, and keys are
    what the mark check reads.
    """
    for child in ast.walk(node):
        if isinstance(child, ast.Dict):
            for key, value in zip(child.keys, child.values):
                if key is None:                       # ``**helper()``
                    return True
                if (isinstance(key, ast.Constant)
                        and isinstance(key.value, str)
                        and key.value in SUBFILTER_KEYS
                        and not isinstance(value, _LITERAL)):
                    return True
        elif isinstance(child, (ast.List, ast.Tuple)):
            if any(isinstance(el, ast.Call) for el in child.elts):
                return True
    return False


@dataclass
class Read:
    file: str
    line: int
    collection: str
    status: str          # "leak" | "filtered" | "indeterminate"
    why: str


@dataclass
class Report:
    files: int = 0
    bearing: set[str] = field(default_factory=set)
    reads: list[Read] = field(default_factory=list)

    @property
    def leaks(self) -> list[Read]:
        return [r for r in self.reads
                if r.collection in self.bearing and r.status == "leak"]

    @property
    def filtered(self) -> list[Read]:
        return [r for r in self.reads
                if r.collection in self.bearing and r.status == "filtered"]

    @property
    def indeterminate(self) -> list[Read]:
        return [r for r in self.reads
                if r.collection in self.bearing and r.status == "indeterminate"]

    def as_dict(self) -> dict:
        def rows(rs: list[Read]) -> list[dict]:
            return [{"file": r.file, "line": r.line,
                     "collection": r.collection, "why": r.why} for r in rs]
        considered = len(self.leaks) + len(self.filtered) + len(self.indeterminate)
        return {
            "files_scanned": self.files,
            "deadline_bearing_collections": sorted(self.bearing),
            "reads_against_them": considered,
            "candidate_leaks": rows(self.leaks),
            "filtered_reads": len(self.filtered),
            "indeterminate_reads": rows(self.indeterminate),
        }


def analyze(sources: dict[str, str]) -> Report:
    """Classify every read in ``sources`` (path -> code). Pure; no I/O.

    Two passes, because the write that proves a collection carries a deadline
    may live in a different file from the read that forgets it.
    """
    report = Report(files=len(sources))
    bearing: set[str] = set()

    for path, code in sources.items():
        try:
            tree = ast.parse(code)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            if not isinstance(fn, ast.Attribute):
                continue
            collection = _collection_of(fn.value)
            if collection is None:
                continue
            if fn.attr in WRITE_VERBS and _mentions_mark(node):
                bearing.add(collection)
            elif fn.attr in READ_VERBS:
                dict_args = _filter_args(node)
                if not dict_args:
                    status, why = "indeterminate", "filter is not a literal"
                    # A read with genuinely no filter argument is a leak, not
                    # indeterminate: ``find()`` returns everything.
                    if not node.args and not any(
                            kw.arg in ("filter", "pipeline")
                            for kw in node.keywords):
                        status, why = "leak", "no filter"
                elif any(_delegates_filter(a) for a in dict_args):
                    status, why = ("indeterminate",
                                   "filter is partly built elsewhere")
                else:
                    keys = set().union(*(_dict_keys(a) for a in dict_args))
                    if any(_is_mark(k) for k in keys):
                        status, why = "filtered", "filter names the mark"
                        bearing.add(collection)   # it filters it -> it has it
                    elif keys:
                        status, why = "leak", "filter does not name the mark"
                    else:
                        status, why = "leak", "empty filter"
                report.reads.append(
                    Read(path, node.lineno, collection, status, why))

    report.bearing = bearing
    return report


def collect_sources(paths: list[Path], allow: list[Path]) -> dict[str, str]:
    """Read ``*.py`` under ``paths``, skipping anything under ``allow``."""
    allow_resolved = [a.resolve() for a in allow]
    out: dict[str, str] = {}
    for p in paths:
        files = [p] if p.is_file() else sorted(p.rglob("*.py"))
        for f in files:
            if "__pycache__" in f.parts:
                continue
            rf = f.resolve()
            if any(rf == a or a in rf.parents for a in allow_resolved):
                continue
            try:
                out[str(f)] = f.read_text()
            except (OSError, UnicodeDecodeError):
                continue
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", type=Path,
                    help="source files or directories to scan")
    ap.add_argument("--allow", action="append", default=[], type=Path,
                    help="a path exempt from the scan (e.g. a designated audit "
                         "module); repeatable")
    ap.add_argument("--json", action="store_true",
                    help="emit the full report as JSON on stdout")
    args = ap.parse_args(argv)

    report = analyze(collect_sources(args.paths, args.allow))

    if args.json:
        print(json.dumps(report.as_dict(), indent=2))
        return len(report.leaks)

    if not report.bearing:
        print(f"scanned {report.files} file(s); found no collection that "
              "carries a deadline or soft-delete mark. Nothing to check.\n"
              "(This is a source heuristic -- dynamically named collections "
              "and ORM layers are invisible. See the header.)")
        return 0

    leaks = report.leaks
    considered = len(leaks) + len(report.filtered) + len(report.indeterminate)
    print(f"scanned {report.files} file(s).")
    print(f"{len(report.bearing)} collection(s) carry a deadline or mark: "
          f"{', '.join(sorted(report.bearing))}")
    if leaks:
        print(f"{len(leaks)} of {considered} read(s) against them do not "
              f"filter the mark:\n")
        for r in leaks:
            print(f"  {r.file}:{r.line}  {r.collection}  ({r.why})")
    else:
        print(f"0 of {considered} read(s) against them are unfiltered.")
    if report.indeterminate:
        print(f"\n{len(report.indeterminate)} read(s) had a non-literal filter "
              "and could not be judged; inspect them by hand.")
    # A clean result has to *read* as clean. The closing paragraph used to
    # explain "each leak" to a reader who had none, which makes a passing
    # scan look like a broken one -- the wrong impression for the first
    # thing a stranger runs.
    if leaks:
        print("\nEach leak is a read that can serve a document the "
              "collection's own mark says is gone. Route it through a filter "
              "on the mark -- or, if you want that enforced structurally "
              "rather than remembered, that is what VOYD is for.")
    else:
        print("\nNo unfiltered read found against a marked collection. That "
              "is a real result for the paths this can see, and the header "
              "says what it cannot -- ORM layers, dynamically named "
              "collections, and the filters listed above as unjudged.")
    return len(leaks)


if __name__ == "__main__":
    raise SystemExit(main())
