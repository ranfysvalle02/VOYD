"""Flag direct reads of a piloted collection that bypass the handle.

VOYD's guarantee is structural *within* the handle and conventional *about
using the handle at all*: a refusal binds `docs.find(...)`, not the raw
`db.notes.find(...)` a teammate writes next month. Inside this package a CI
gate (`tests/test_no_module_reaches_past_the_handle.py`) makes that
convention checkable. This is the same idea, turned outward, for a team
piloting VOYD on one collection: point it at your source, name the collection
you put behind a handle, and it fails if anything still reads the raw
collection directly.

    python tools/raw_read_guard.py --collection notes app/ services/
    python tools/raw_read_guard.py --collection memories --allow app/admin/ src/

It reads the AST, not the text, for the same reason the in-package gate does:
`.find(` appears in strings, comments and docstrings, and a guard that fires
on prose is a guard somebody deletes. A read through the handle
(`docs.find(...)`) is never flagged, because its receiver is a plain name, not
`db.<collection>` or `db["<collection>"]`. Reaching past the handle to the raw
collection is the whole failure this looks for.

Exit code is the number of offenders -- clamped to 254, because an exit
status is one byte and 256 offenders exiting 0 would be this guard committing
the defect it looks for. 255 means the scan could not run at all.

Both of those are corrections, and both arrived late. ``voyd-scan`` learned
them first -- a missing path must not print a clean bill of health, and a
count that wraps must not read as success -- and this file, which `PILOT.md`
tells a piloting team to put in CI, had neither for as long as it existed.
Two tools, one lesson, learned in one of them. See
`tests/test_an_outward_tool_cannot_report_clean_about_nothing.py`, which now
states the property once for both rather than per tool.
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

# Reads on a raw collection that skip refusal. Writes are not here: a write
# does not return a forgotten fact to a prompt, and `revoke()`/`forget` are
# writes the handle owns anyway.
READ_VERBS = {"find", "find_one", "aggregate", "distinct", "count_documents"}


def _names_a_collection(node: ast.AST, collection: str) -> bool:
    """True if ``node`` is ``X.<collection>``, ``X["<collection>"]`` or
    ``X.get_collection("<collection>")`` -- the raw-handle shapes."""
    if isinstance(node, ast.Attribute):
        return node.attr == collection
    if isinstance(node, ast.Subscript):
        key = node.slice
        return isinstance(key, ast.Constant) and key.value == collection
    if isinstance(node, ast.Call):
        fn = node.func
        if isinstance(fn, ast.Attribute) and fn.attr == "get_collection":
            return bool(node.args) and isinstance(node.args[0], ast.Constant) \
                and node.args[0].value == collection
    return False


def raw_reads(source: str, collection: str) -> list[int]:
    """Line numbers where the raw ``collection`` is read directly.

    A read is ``<receiver>.<verb>(...)`` with ``verb`` in :data:`READ_VERBS`
    and ``receiver`` naming ``collection`` as an attribute, subscript, or
    ``get_collection`` call. Reads through an ``Admission`` handle -- whose
    receiver is an ordinary variable -- do not match.
    """
    tree = ast.parse(source)
    hits: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if not isinstance(fn, ast.Attribute) or fn.attr not in READ_VERBS:
            continue
        if _names_a_collection(fn.value, collection):
            hits.append(node.lineno)
    return hits


# The exit status is one byte. See the module docstring.
EXIT_MAX = 254
EXIT_ERROR = 255


class ScanError(Exception):
    """The check could not be performed, as opposed to finding nothing."""


def _iter_py(paths: list[Path], allow: list[Path]):
    """Yield every ``*.py`` under ``paths``, skipping ``allow``.

    Raises ``ScanError`` for a path that does not exist. ``Path.rglob`` on a
    missing directory yields nothing rather than raising, so without this
    check ``--collection notes ./ap`` (for ``./app``) printed *clean: no raw
    reads* and exited 0 -- confidently, and about nothing. In a pilot that is
    a CI job that goes green forever while the collection it was installed to
    protect is read raw in a file nobody scanned.
    """
    missing = [str(p) for p in paths if not p.exists()]
    if missing:
        raise ScanError(f"no such path: {', '.join(missing)}")
    allow_resolved = [a.resolve() for a in allow]
    for p in paths:
        files = [p] if p.is_file() else sorted(p.rglob("*.py"))
        for f in files:
            if "__pycache__" in f.parts:
                continue
            rf = f.resolve()
            if any(rf == a or a in rf.parents for a in allow_resolved):
                continue
            yield f


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--collection", required=True,
                    help="the collection you put behind a forgettable() handle")
    ap.add_argument("--allow", action="append", default=[], type=Path,
                    help="a path exempt from the check (e.g. a designated audit "
                         "module); repeatable")
    ap.add_argument("paths", nargs="+", type=Path, help="source files or dirs")
    args = ap.parse_args(argv)

    offenders: list[tuple[Path, int]] = []
    try:
        files = list(_iter_py(args.paths, args.allow))
    except ScanError as exc:
        print(f"raw_read_guard: {exc}", file=sys.stderr)
        return EXIT_ERROR
    for f in files:
        try:
            lines = raw_reads(f.read_text(), args.collection)
        except SyntaxError as exc:
            print(f"skip {f}: {exc}", file=sys.stderr)
            continue
        offenders.extend((f, ln) for ln in lines)

    if not offenders:
        print(f"clean: no raw reads of {args.collection!r} outside the handle")
        return 0

    print(f"{len(offenders)} raw read(s) of {args.collection!r} that bypass "
          f"the handle:")
    for f, ln in offenders:
        print(f"  {f}:{ln}")
    print("\nRoute these through the forgettable() handle, or pass --allow for a "
          "designated audit module. A raw read cannot refuse a forgotten fact.")
    return min(len(offenders), EXIT_MAX)


if __name__ == "__main__":
    raise SystemExit(main())
