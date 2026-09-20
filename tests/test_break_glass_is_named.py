"""Break-glass has one door, and the engine's own writes do not use it.

``including_refused()`` turns the guarantee off. It has to exist -- audit and
administration need an unfiltered read -- and it is named for exactly that
reason: a review can grep the phrase and find every place the guarantee was
set aside. But a named hole is still a hole, and a review called out the
two things missing from it: it was ungated and uncounted, so the 2am use to
"just fix a bug" left no trace and needed no permission.

Both are fixed in code now (an ``AUDIT`` grant, a ``including_refused_total``
counter). This test defends the third leg, which is structural rather than
runtime: the *public*, gated door is for callers *outside* this package. The
engine's own write paths -- revoke seeing the row it marks, release finding
what it lifts, derive seeing a refused parent -- use ``_unfiltered()``, the
private hatch, because they are already gated by their own verb and must not
be made to demand an ``AUDIT`` grant to perform a ``REVOKE``.

So this is a grep with an AST behind it, the same shape as
``test_no_module_reaches_past_the_handle.py``: no module in ``voyd/`` may call
the public ``including_refused()`` except the file that defines it. If a new
internal caller reaches for it, the build fails and points here -- and the fix
is one underscore.
"""

from __future__ import annotations

import ast
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1] / "voyd"

# ``core.py`` defines both hatches and is the one file allowed to name the
# public one. Everything else in the package gets ``_unfiltered()``.
ALLOWED = {"core.py"}


def _public_break_glass_calls(path: Path) -> list[int]:
    """Line numbers of ``<something>.including_refused(...)`` calls in a module.

    AST rather than a regex: ``including_refused()`` appears in docstrings and
    code examples across this package -- including in the docstrings that
    explain the split -- and a guard that fires on prose is a guard somebody
    deletes. Only a real call node counts.
    """
    tree = ast.parse(path.read_text())
    hits = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if isinstance(fn, ast.Attribute) and fn.attr == "including_refused":
            hits.append(node.lineno)
    return hits


def test_no_module_calls_the_public_break_glass_directly():
    offenders = {}
    for path in sorted(PACKAGE.rglob("*.py")):
        if path.name in ALLOWED or "__pycache__" in path.parts:
            continue
        lines = _public_break_glass_calls(path)
        if lines:
            offenders[str(path.relative_to(PACKAGE))] = lines
    assert not offenders, (
        "these modules call the public, audit-gated including_refused(): "
        f"{offenders}. The engine's own write paths must use _unfiltered() "
        "instead -- they are already gated by their own verb, and routing "
        "them through the AUDIT gate would make a REVOKE demand an AUDIT "
        "grant and break Grants.withholding_only(). If an internal caller "
        "genuinely needs the unfiltered read, that is _unfiltered(); the "
        "public name is for callers outside this package.")
