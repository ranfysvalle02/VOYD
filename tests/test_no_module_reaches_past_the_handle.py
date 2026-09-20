"""No module in this package may search a refusing collection directly.

This repository's history is one bug, three times, in three disguises:

1. six read paths each carrying a hand-written deadline filter, and one of
   them carrying none;
2. two read paths each remembering to wrap the search primitive in
   ``Admission``, and each writing out its own fetch-budget guess -- the same
   wrong constant twice;
3. ``engine.search`` itself, which is a public, unfiltered read on a
   collection that refuses things, sitting one import away from anybody who
   has not read its docstring.

Each fix removed the *convention* rather than correcting an instance of it,
and each time the remaining convention looked small enough to trust. It was
not, twice. So this is the third fix, and it is a grep: the handle owns the
query now, and no module in ``voyd/`` may call the search primitive on a
collection that has an admission policy.

A grep is a blunt instrument and that is the point -- it does not need
anybody to be paying attention. The same shape as the CI gate asserting no
MCP tool is named for reclaiming anything, and the one asserting the engine
source contains no application vocabulary.
"""

from __future__ import annotations

import ast
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1] / "voyd"

# ``admission/reads.py`` is where the wrapping lives, so it must call the
# primitive. ``verify.py`` calls it deliberately to assert that the unwrapped
# version really does leak -- if that stopped being true, the read-path
# read-path check would have become a tautology, so it is a call worth
# keeping and worth exempting by name.
#
# This exemption used to read ``admission.py`` and cover a 2,393-line module,
# which meant *any* of admission's concerns could have reached for the
# primitive without this guard noticing. Splitting that module into a package
# narrowed the hole to the one file whose job is the read path: marks,
# lineage, sealing and attestation are now inside the rule like everybody
# else. An exemption that shrinks when code is reorganised is the only kind
# worth having.
ALLOWED = {"reads.py", "verify.py"}


def _calls_to_search(path: Path) -> list[int]:
    """Line numbers of ``<something>.search(...)`` calls in one module.

    AST rather than a regex: ``.search(`` appears in strings, docstrings and
    comments all over this package -- including in the docstring explaining
    this rule -- and a guard that fires on prose is a guard somebody deletes.
    """
    tree = ast.parse(path.read_text())
    hits = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if isinstance(fn, ast.Attribute) and fn.attr == "search":
            # ``self.admission.search`` / ``docs.search`` are the handle, which
            # is the whole point of the rule. What is banned is reaching the
            # engine's primitive.
            owner = fn.value
            name = getattr(owner, "attr", None) or getattr(owner, "id", None)
            if name in ("engine", "search_engine"):
                hits.append(node.lineno)
    return hits


def test_no_module_calls_the_search_primitive_directly():
    offenders = {}
    for path in sorted(PACKAGE.rglob("*.py")):
        if path.name in ALLOWED or "__pycache__" in path.parts:
            continue
        lines = _calls_to_search(path)
        if lines:
            offenders[str(path.relative_to(PACKAGE))] = lines

    assert not offenders, (
        f"these modules call the search primitive instead of searching "
        f"through an Admission handle: {offenders}. The primitive returns "
        f"what the index ranked, and the deadline is deliberately not in the "
        f"vector index -- so those hits have not been filtered by anything. "
        f"Use `handle.search(...)`, or add the file to ALLOWED with a reason.")


def test_the_guard_can_actually_fail(tmp_path):
    """A guard that cannot fire is decoration.

    Written as the mistake it is meant to catch: a new read path that reaches
    for the primitive because it was the first thing autocomplete offered.
    """
    offending = tmp_path / "new_read_path.py"
    offending.write_text(
        "async def recall(engine, vector):\n"
        "    return await engine.search('notes', vector, limit=5)\n")
    assert _calls_to_search(offending) == [2]

    fixed = tmp_path / "fixed.py"
    fixed.write_text(
        "async def recall(docs, vector):\n"
        "    return await docs.search(vector, limit=5)\n")
    assert _calls_to_search(fixed) == [], \
        "searching through the handle must not trip the guard"


def test_the_guard_ignores_prose():
    """It reads code, not comments -- including this module's own docstring.

    A regex-based version of this fired on the paragraph explaining the rule,
    which is exactly the sort of false positive that gets a check deleted
    rather than fixed.
    """
    assert _calls_to_search(Path(__file__)) == [], (
        "the guard tripped on its own docstring; it is matching text rather "
        "than calls")


def test_the_handle_refuses_to_search_without_an_engine():
    """And says why, because the alternative is an AttributeError on None."""
    import asyncio

    import pytest

    from voyd.engine.admission import Admission, AdmissionSpec

    handle = Admission(None, AdmissionSpec("notes"))
    with pytest.raises(RuntimeError, match="without an engine"):
        asyncio.run(handle.search([0.1, 0.2]))
