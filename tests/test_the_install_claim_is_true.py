"""The install instructions must describe an install that works today.

``pip install voyd`` is the intended distribution, and the wheel already
builds and installs clean -- CI proves that against the built artifact on
every commit. But ``0.1.0`` is not on any index yet, so a doc that prints
``pip install voyd`` as a runnable command sends a stranger to a 404: the
exact "a Quickstart that cannot be followed is the entire first impression"
failure that ``test_the_docs_are_not_stale.py`` exists for, one layer up.

So the claim is pinned to reality with a single switch. Flip it the day
``0.1.0`` is published and the assertion inverts -- the command must then
appear, because a truthful install that undersells a shipped package is its
own kind of stale. Either way the docs cannot drift away from what a stranger
can actually run.

The ``LICENSE`` check rides along because it is the same class of defect: a
thing every adopter needs, claimed present, and free to make true.
"""

from __future__ import annotations

import re
from pathlib import Path

import voyd

ROOT = Path(__file__).resolve().parents[1]

# Flip to True the day `voyd` 0.1.0 is actually on an index. Until then, no
# doc may present `pip install voyd` as a runnable command.
PUBLISHED_TO_PYPI = False

# A fenced-code line that *runs* `pip install voyd` (base or an extra). The
# command form is what 404s; prose mentioning the string -- with the not-yet
# caveat -- is fine and is not scanned, because it is not inside a fence.
PIP_INSTALL_VOYD = re.compile(r"""^\s*pip install\s+['"]?voyd""", re.MULTILINE)

# Prose lives in ``docs/`` now, not the root, so the glob has to reach it
# or the guard quietly stops guarding the sixteen documents that moved.
DOCS = sorted(ROOT.glob("*.md")) + sorted(ROOT.glob("docs/*.md"))


def _fenced_code(text: str) -> str:
    """Only the contents of ``` fences, so prose and inline code are ignored."""
    out, inside = [], False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            inside = not inside
            continue
        if inside:
            out.append(line)
    return "\n".join(out)


def test_the_license_file_exists_and_is_mit():
    """MIT is claimed in `pyproject.toml` and the README. A claimed licence
    with no file is a hard blocker for any company's OSS review, and free to
    fix."""
    text = (ROOT / "LICENSE").read_text()
    assert "MIT License" in text
    assert "Permission is hereby granted" in text


def test_no_doc_prints_an_install_command_that_404s():
    """While unpublished, no markdown code block may run `pip install voyd`."""
    if PUBLISHED_TO_PYPI:
        return
    offenders = {
        doc.name: PIP_INSTALL_VOYD.findall(_fenced_code(doc.read_text()))
        for doc in DOCS
        if PIP_INSTALL_VOYD.search(_fenced_code(doc.read_text()))
    }
    assert not offenders, (
        "these docs print `pip install voyd` as a runnable command, but it is "
        f"not on an index yet -- a 404 for the reader: {offenders}. Use `uv "
        "sync` from a clone (or `pip install dist/*.whl`), or flip "
        "PUBLISHED_TO_PYPI here the day 0.1.0 ships.")


def test_the_package_docstring_does_not_promise_the_index_install():
    """The top-level docstring is the other place a bare command misleads."""
    if PUBLISHED_TO_PYPI:
        return
    assert "pip install voyd" not in (voyd.__doc__ or ""), (
        "voyd.__doc__ still presents `pip install voyd`; describe the "
        "clone/`uv sync` path until 0.1.0 is published")


def test_when_published_the_command_must_reappear():
    """The switch cuts both ways: a truthful install that hides a real package
    is stale too. This documents the inverse so the flip is not forgotten."""
    if not PUBLISHED_TO_PYPI:
        return
    readme = (ROOT / "README.md").read_text()
    assert PIP_INSTALL_VOYD.search(_fenced_code(readme)), (
        "0.1.0 is published but the README no longer shows `pip install voyd`")
