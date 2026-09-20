"""Documentation rots silently, so it gets a guard like everything else.

This repository already refuses to let a rule depend on somebody
remembering it: `__all__` is pinned, the claim table's identifiers are
checked, no endpoint may be named for reclaiming, and nothing in `voyd/`
may reach past the handle. Prose was the last place where "somebody will
notice" was the whole mechanism -- and it is the place where nobody does,
because the people who would notice have already read it.

Four kinds of rot, all mechanically detectable:

1. a link to a file that moved or was deleted;
2. an anchor to a heading that was renamed;
3. a source path named in prose that no longer exists;
4. a count that was true when it was written.

What is deliberately *not* checked: prose accuracy. A test cannot tell you
whether a paragraph is still a good explanation, and pretending otherwise
would be the overreach this codebase spends its docstrings avoiding.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCS = sorted(ROOT.glob("*.md")) + [ROOT / "drift" / "README.md"]

# Things that have been deleted. A mention of one is a doc that was not
# updated when the code was -- and each entry here is a grave marker: it
# stays so the name cannot quietly come back in prose alone.
#
# ``ISSUES.md`` is exempt, and the exemption is the point rather than a
# concession: its job is to record what was removed and why, so naming the
# thing is the *correct* behaviour there. A guard that forbade it would be
# forcing the one document that should be specific to be vague.
RECORDS_REMOVALS = "ISSUES.md"

BURIED = (
    "voyd verify", "voyd-verify", "voyd.verify",
    "falsifier.md", "marketing.md",
    "delete_voyd", "forget_documents",
    "GuardSpec(kind=\"require_passcode\", params",
)


def slug(heading: str) -> str:
    """GitHub's anchor rule, near enough for our own headings."""
    text = heading.strip().lstrip("#").strip().lower()
    text = re.sub(r"[`*_\[\]()]", "", text)
    return re.sub(r"[^\w\- ]", "", text).replace(" ", "-")


@pytest.mark.parametrize("doc", DOCS, ids=lambda d: d.name)
def test_every_link_resolves(doc):
    """A README that points at a file somebody deleted is worse than one
    that says nothing: it reads as maintained."""
    broken = []
    for target in re.findall(r"\]\(([^)]+)\)", doc.read_text()):
        if target.startswith(("http", "mailto")):
            continue
        path, _, anchor = target.partition("#")
        if path:
            resolved = (doc.parent / path).resolve()
            if not resolved.exists():
                broken.append(f"{target} -> no such file")
                continue
        else:
            resolved = doc
        if anchor:
            headings = {slug(line) for line in
                        resolved.read_text().splitlines()
                        if line.startswith("#")}
            if anchor not in headings:
                broken.append(f"{target} -> no such heading")
    assert not broken, f"{doc.name}: {broken}"


@pytest.mark.parametrize("doc", DOCS, ids=lambda d: d.name)
def test_every_source_path_named_in_prose_exists(doc):
    """`engine/admission.py` in a sentence is a promise about the tree."""
    named = set(re.findall(
        r"`((?:voyd|tests|examples|drift|bench)/[\w./]+\.(?:py|md|yml))`",
        doc.read_text()))
    missing = sorted(p for p in named if not (ROOT / p).exists())
    assert not missing, f"{doc.name} names paths that do not exist: {missing}"


@pytest.mark.parametrize("doc", DOCS, ids=lambda d: d.name)
def test_nothing_deleted_is_still_advertised(doc):
    """Each entry in ``BURIED`` was removed with a reason. Prose that still
    offers it sends a reader looking for a command that is not there."""
    if doc.name == RECORDS_REMOVALS:
        pytest.skip(f"{RECORDS_REMOVALS} is where removals are recorded")
    text = doc.read_text()
    found = sorted(name for name in BURIED if name in text)
    assert not found, (
        f"{doc.name} still advertises {found}, which no longer exists. If it "
        f"is being discussed historically, phrase it in the past tense "
        f"without naming the command")


def test_a_claimed_test_count_is_not_lower_than_the_real_one():
    """Counts are the fastest-rotting sentence in any README.

    Checked one-directionally on purpose: ``@parametrize`` means the real
    number is always *at least* the count of ``def test_`` functions, so a
    document claiming fewer than that is certainly stale, while one
    claiming more may simply be counting parametrised cases. Catching the
    direction that actually happens is worth more than a number that has
    to be edited on every commit.
    """
    functions = sum(
        len(re.findall(r"^(?:async )?def test_", f.read_text(), re.M))
        for f in ROOT.glob("tests/test_*.py"))

    for doc in DOCS:
        for claimed in re.findall(r"(\d[\d,]*) tests?\b", doc.read_text()):
            n = int(claimed.replace(",", ""))
            assert n >= functions, (
                f"{doc.name} claims {n} tests; there are at least "
                f"{functions} test functions. The suite grew and the "
                f"sentence did not")


def test_the_front_door_points_at_documents_that_exist():
    """The README's table of contents is the first thing anybody uses and
    the last thing anybody updates."""
    readme = (ROOT / "README.md").read_text()
    for name in ("pain.md", "blog.md", "ISSUES.md", "ideas.md"):
        assert f"({name})" in readme, f"README no longer links {name}"
        assert (ROOT / name).exists()
