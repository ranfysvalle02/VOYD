"""Every function and class in ``voyd/`` must have a caller.

This found five, in one pass: ``get_owner``, ``get_owner_by_email``,
``set_owner_api_key``, ``find_free_slug`` and ``stats_for_voyds``. All five
were the residue of a browser-based owner plane that was removed — the README
had already been updated to say there is no sign-in page and no session, and
the code that served one was still sitting there, importable, tested by
nothing, called by nothing.

That is the pattern worth a guard: **removing a feature is three deletions —
the code, the tests, and the prose — and a green suite only enforces the
second.** A dead method is not a bug, but it is a claim: somebody later reads
it as a supported path, extends it, or reimplements around it. And in this
repository it is worse than untidy, because the whole argument is that a
smaller surface is what makes a guarantee holdable.

Deliberately a *textual* reference count rather than a call graph. It cannot
tell whether a caller is reachable, only whether one exists, and that has
turned out to be the question with all the yield. Frameworks that invoke by
decorator or override are allowlisted below, each with a reason — the
allowlist is the interesting part of this file, because an entry with no
reason is somebody silencing the check.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Invoked by a framework, never by name. Each entry names what calls it.
FRAMEWORK_INVOKED = {
    # FastAPI route handlers: called by the router via the decorator.
    "add_documents", "search_void", "search_voyd",
    # Starlette middleware: called by the ASGI stack, not by us.
    "dispatch",
    # Pydantic validators: called by the model during construction.
    "_text_must_say_something", "_strip_name", "_metadata_or_nothing",
    "_query_is_required", "_accept_the_single_document_shorthand",
}

# Called by mypy, not by Python. The three functions in handle.py exist so
# that the protocols in composition.py are checked against the classes they
# claim to describe -- assigning an `AdmissionCore` to a `CoreState` is the
# assertion, and a return statement is how you write it. Running them would
# prove nothing; type-checking them is the entire point, and CI does.
#
# This is a third bucket rather than an entry in FRAMEWORK_INVOKED because
# "a framework calls it" and "nothing calls it and that is correct" are
# different claims, and collapsing them would make the allowlist above less
# true -- which is the one thing this file's docstring asks of it.
TYPE_CHECKED = {
    "_core_keeps_its_end", "_sealing_keeps_its_end", "_lineage_keeps_its_end",
}

# Public API with no in-package caller, and a stated reason it stays.
PUBLIC_API = {
    # The reader's half of Ledger.sign(). It cannot be called here: verifying
    # a signature with the key that produced it is a tautology, which is
    # written up in the method's own docstring.
    "signature_valid",
}

# Three levels, because ``voyd/engine/admission/`` is a package. A glob
# that stopped one level short would have quietly dropped eleven modules
# out of this check the day they were created -- a guard silently
# narrowing its own scope during a refactor is the exact failure this
# file exists to catch in other people's code.
SOURCE_GLOBS = ("voyd/*.py", "voyd/*/*.py", "voyd/*/*/*.py")
CALLER_GLOBS = SOURCE_GLOBS + ("tests/*.py", "examples/*.py", "bench/*.py",
                               "drift/*.py")


def _definitions() -> dict[str, tuple[Path, int]]:
    out: dict[str, tuple[Path, int]] = {}
    for pattern in SOURCE_GLOBS:
        for path in sorted(ROOT.glob(pattern)):
            for node in ast.walk(ast.parse(path.read_text())):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                         ast.ClassDef)):
                    continue
                name = node.name
                if name.startswith("__") and name.endswith("__"):
                    continue          # dunders are the protocol, not an API
                out[name] = (path.relative_to(ROOT), node.lineno)
    return out


def _reference_counts(names: set[str]) -> dict[str, int]:
    counts = dict.fromkeys(names, 0)
    patterns = {n: re.compile(rf'\b{re.escape(n)}\b') for n in names}
    for pattern in CALLER_GLOBS:
        for path in sorted(ROOT.glob(pattern)):
            for line in path.read_text().splitlines():
                for name, rx in patterns.items():
                    if rx.search(line):
                        counts[name] += 1
    return counts


def test_there_are_definitions_to_check():
    """A parse that silently finds nothing would make this file decorative."""
    assert len(_definitions()) > 100


def test_every_symbol_has_at_least_one_caller():
    defs = _definitions()
    counts = _reference_counts(set(defs))

    orphans = {
        name: defs[name] for name, n in counts.items()
        # One reference is the definition line itself.
        if n <= 1 and name not in FRAMEWORK_INVOKED
        and name not in PUBLIC_API and name not in TYPE_CHECKED
    }
    assert not orphans, (
        "these are defined in voyd/ and referenced nowhere: "
        + ", ".join(f"{name} ({f}:{line})" for name, (f, line) in
                    sorted(orphans.items()))
        + ". Either something still needs them -- in which case call them -- "
          "or they outlived the feature they belonged to. If a framework "
          "invokes them, add them to FRAMEWORK_INVOKED with the reason.")


def test_the_allowlists_have_not_outlived_their_entries():
    """An allowlist that names something gone is the next stale thing.

    Cheap, and it is what stops this file from slowly becoming a list of
    names nobody can account for.
    """
    defs = set(_definitions())
    for label, allow in (("FRAMEWORK_INVOKED", FRAMEWORK_INVOKED),
                         ("PUBLIC_API", PUBLIC_API)):
        stale = allow - defs
        assert not stale, (
            f"{label} exempts {sorted(stale)}, which no longer exist in voyd/")
