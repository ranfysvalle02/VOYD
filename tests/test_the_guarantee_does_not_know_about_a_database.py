"""The 460 lines that decide what may reach a prompt must not know MongoDB.

``docs/PORTABILITY.md`` measures a property of this package's import graph
and then argues from it: the *decision* layer of ``voyd/engine/admission/``
-- ``reasons``, ``rules``, ``spec``, ``receipts`` -- contains no driver, no
query language and no database, so the guarantee would run unchanged against
a Postgres row or a list literal. ``drift/refusal_on_postgres.py`` and
``drift/refusal_on_qdrant.py`` are that argument executed on other engines.

A measurement in a document is true on the day it is written. This makes it
an invariant, by the same technique
``test_the_admission_layers_do_not_invert.py`` uses one layer down: walk the
transitive import closure and fail if a driver appears in it.

The failure this catches is small and entirely plausible -- an ``ObjectId``
comparison in a rule, a ``bson`` date helper in a receipt, a ``pymongo``
error type caught in ``spec``. None of those break a test, and each one
quietly converts a portable guarantee into a MongoDB feature. That is
exactly the class of defect this repository builds guards for: nothing is
wrong enough to notice.

Deliberately *not* checked: that the layer is importable without pymongo
installed. It is not, and ``PORTABILITY.md`` says so -- the package
``__init__`` pulls ``handle`` -> ``core`` -> ``errors`` -> ``bson``, so the
decision layer's own closure is clean while the package around it is not.
Asserting the stronger thing would fail today and asserting it loosely would
be worse than not asserting it.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parents[1] / "voyd"

# The decision layer: layers 0-2 of the admission layering, which is the
# same set ``PORTABILITY.md`` counts.
GUARANTEE = ("engine/admission/reasons.py", "engine/admission/rules.py",
             "engine/admission/spec.py", "engine/admission/receipts.py")

DRIVERS = ("pymongo", "bson", "motor")

# The one place the claim leaks, with its reason, so the exception is a line
# of code rather than a paragraph somebody has to remember.
#
# BSON subtype 6 is the marker for a client-side-encrypted field, and
# ``Unrecoverable`` has to recognise it to tell ciphertext from plaintext.
# That concept is genuinely MongoDB-specific -- a port needs its own answer
# and may not have one as crisp. The import is deferred into the function
# precisely so the module's *own* closure stays clean, which is why the
# allowlist is keyed by the function and not by the file.
ALLOWED = {("engine/admission/rules.py", "_is_ciphertext", "bson.binary")}


def _module_path(module: str, origin: Path, level: int) -> Path | None:
    """Resolve an ``import`` to a file inside ``voyd/``, or ``None``.

    ``None`` means "not ours": stdlib, a third party, or a namespace we do
    not own. Those are judged by ``DRIVERS`` at the call site, not followed.
    """
    if level:
        base = origin.parent
        for _ in range(level - 1):
            base = base.parent
    else:
        if not module.startswith("voyd"):
            return None
        base = PACKAGE.parent
    target = base.joinpath(*module.split(".")) if module else base
    for candidate in (target.with_suffix(".py"), target / "__init__.py"):
        if candidate.exists():
            return candidate
    return None


def _imports(path: Path) -> list[tuple[str, int, str | None]]:
    """``(module, level, enclosing function)`` for every import in a file."""
    tree = ast.parse(path.read_text())
    enclosing: dict[int, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for child in ast.walk(node):
                if isinstance(child, (ast.Import, ast.ImportFrom)):
                    enclosing[id(child)] = node.name
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            out.append((node.module or "", node.level, enclosing.get(id(node))))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                out.append((alias.name, 0, enclosing.get(id(node))))
    return out


def _closure(entry: Path) -> set[Path]:
    """Every file under ``voyd/`` reachable from ``entry`` by import."""
    seen, stack = {entry}, [entry]
    while stack:
        current = stack.pop()
        for module, level, _ in _imports(current):
            resolved = _module_path(module, current, level)
            if resolved and resolved not in seen:
                seen.add(resolved)
                stack.append(resolved)
    return seen


@pytest.mark.parametrize("relative", GUARANTEE)
def test_no_driver_in_the_decision_layers_import_closure(relative):
    """A guarantee that imports a driver is a feature of that driver."""
    entry = PACKAGE / relative
    offences = []
    for module_file in sorted(_closure(entry)):
        name = str(module_file.relative_to(PACKAGE))
        for module, level, function in _imports(module_file):
            if level or not module:
                continue
            root = module.split(".")[0]
            if root not in DRIVERS:
                continue
            if (name, function, module) in ALLOWED:
                continue
            where = f"{name}:{function}()" if function else name
            offences.append(f"{where} imports {module}")
    assert not offences, (
        f"{relative} reaches a database driver: {offences}. The decision "
        f"layer is what makes the guarantee portable -- see "
        f"docs/PORTABILITY.md. If the import is genuinely unavoidable, "
        f"defer it into the function that needs it and add it to ALLOWED "
        f"with the reason, the way _is_ciphertext is.")


def test_the_allowlist_is_not_stale():
    """An exemption for something that no longer happens is a licence
    nobody revoked. Each entry must still describe a real import."""
    for relative, function, module in sorted(ALLOWED):
        found = [(m, fn) for m, _, fn in _imports(PACKAGE / relative)
                 if m.startswith(module)]
        assert (module, function) in found, (
            f"ALLOWED exempts {relative}:{function}() importing {module}, "
            f"which is no longer there. Delete the entry -- the claim in "
            f"docs/PORTABILITY.md is stronger without it.")


def test_the_guarantee_is_the_set_portability_measures():
    """``PORTABILITY.md`` counts four modules. If a fifth joins layers 0-2
    of the admission layering, the document's table is wrong and this list
    is the thing that noticed."""
    from tests.test_the_admission_layers_do_not_invert import LAYERS

    pure = {f"engine/admission/{name}.py"
            for name, layer in LAYERS.items() if layer <= 2}
    assert pure == set(GUARANTEE), (
        f"the driver-free layers are now {sorted(pure)} but this file and "
        f"docs/PORTABILITY.md still describe {sorted(GUARANTEE)}")
