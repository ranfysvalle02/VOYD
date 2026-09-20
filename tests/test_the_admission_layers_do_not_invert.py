"""The admission package has a direction, and this is what keeps it.

``admission`` was one 2,393-line module. Splitting it into eleven files only
buys something if the pieces stay in an order somebody can hold in their head
-- and a package that merely *starts* layered does not stay that way. The
first time ``marks.py`` wants something from ``reads.py`` the import is one
line, it works, and the layering is gone with no test failing and no reviewer
necessarily noticing.

So the order is declared here and enforced, rather than described in a
docstring and hoped for:

    reasons     the vocabulary. Strings, no behaviour, no imports.
    rules       what the answer is for one document. Pure functions.
    spec        where a collection keeps its deadline and its mark.
    receipts    what a read cost, and what a handle has refused.
    core        the state, and the two enforcement points.
    <mixins>    reads, marks, lineage, sealing, attestation.
    handle      the one object a caller holds.

Two rules, and the second is the interesting one:

1. **No module may import from its own layer or below it** (below meaning
   later in the list). That makes the graph acyclic by construction, so
   ``rules.py`` can never come to depend on the handle that calls it.

2. **The five capability mixins may not import each other.** They are
   siblings that all attach to one class, so an import between two of them
   is not a dependency -- it is a second, invisible way for capabilities to
   reach each other that bypasses ``AdmissionCore``. The whole argument for
   the split is that the guarantee lives in the core and every capability
   goes through it; two mixins wired directly together is that argument
   quietly stopping being true.

The test reads the import statements rather than the runtime module graph
deliberately: a ``TYPE_CHECKING`` import is still a coupling a reader has to
follow, and it is exactly the kind that gets used to smuggle a real one in
later.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parents[1] / "voyd" / "engine" / "admission"

# Lower number = closer to the bottom. A module may import strictly lower
# numbers only.
LAYERS = {
    "reasons": 0,
    "rules": 1,
    "spec": 2,
    "receipts": 2,
    "core": 3,
    "reads": 4,
    "marks": 4,
    "lineage": 4,
    "sealing": 4,
    "attestation": 4,
    "handle": 5,
    "__init__": 6,
}

MIXINS = {"reads", "marks", "lineage", "sealing", "attestation"}


def _intra_package_imports(path: Path) -> set[str]:
    """Sibling modules this file imports, by bare name.

    Only ``from .x import ...`` (level 1) counts. ``from ..errors import ...``
    reaches out of this package to the rest of the engine, which is fine and
    is not what this file is about.
    """
    tree = ast.parse(path.read_text())
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module:
            out.add(node.module.split(".")[0])
    return out


def test_every_module_is_placed_in_the_layering():
    """A new file must be given a layer, not silently exempted."""
    on_disk = {p.stem for p in PACKAGE.glob("*.py")}
    assert on_disk == set(LAYERS), (
        f"the admission package and this test disagree about its modules. "
        f"On disk only: {sorted(on_disk - set(LAYERS))}. "
        f"Declared only: {sorted(set(LAYERS) - on_disk)}. A new module needs "
        f"a layer here, and choosing one is the design decision.")


@pytest.mark.parametrize("module", sorted(LAYERS), ids=str)
def test_no_module_imports_its_own_layer_or_below(module):
    inversions = []
    for imported in sorted(_intra_package_imports(PACKAGE / f"{module}.py")):
        if imported not in LAYERS:
            inversions.append(f"{imported} (not in the layering)")
        elif LAYERS[imported] >= LAYERS[module]:
            inversions.append(
                f"{imported} (layer {LAYERS[imported]} from layer "
                f"{LAYERS[module]})")
    assert not inversions, (
        f"admission/{module}.py imports {inversions}, which inverts or "
        f"flattens the layering. Either the import is wrong, or the layering "
        f"is -- but it cannot be left ambiguous.")


@pytest.mark.parametrize("module", sorted(MIXINS), ids=str)
def test_the_capability_mixins_do_not_reach_each_other(module):
    """Siblings go through the core, or they are not siblings."""
    siblings = _intra_package_imports(PACKAGE / f"{module}.py") & MIXINS
    assert not siblings, (
        f"admission/{module}.py imports {sorted(siblings)}, which is another "
        f"capability mixin on the same handle. Capabilities reach each other "
        f"through AdmissionCore at runtime -- an import between two of them "
        f"is a second path that does not pass the boundary.")


def test_the_core_owns_the_per_document_check():
    """``why_refused`` is the authoritative check, and it has few callers.

    Not zero outside the core -- ``lineage.derive`` asks it directly, to
    report *which* reason made a parent unusable, and ``reads`` uses it for
    ``reachability_at``'s verdict. Both are reads of the answer rather than
    substitutes for the boundary. What this pins down is that the list stays
    short and deliberate: a capability computing its own admission verdict is
    how the two enforcement points come to disagree.
    """
    callers = set()
    for path in sorted(PACKAGE.glob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "why_refused"):
                callers.add(path.stem)
    assert callers == {"core", "reads", "lineage"}, (
        f"who calls why_refused() changed: {sorted(callers)}. Every addition "
        f"is a place deciding admission outside _admit, and needs a reason "
        f"written down here.")
