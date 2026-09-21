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
# The root holds the front door and the pilot report; everything else is
# reference material under ``docs/``. Both are checked -- a link that
# broke in the move is exactly the rot this file exists to catch.
DOCS = (sorted(ROOT.glob("*.md"))
        + sorted(ROOT.glob("docs/*.md"))
        + [ROOT / "drift" / "README.md",
           # `scanner/` is a second distribution with its own front
           # door, and it is the first page a stranger reads. A dead
           # link there costs more than one anywhere else here.
           ROOT / "scanner" / "README.md"])

# Things that have been deleted. A mention of one is a doc that was not
# updated when the code was -- and each entry here is a grave marker: it
# stays so the name cannot quietly come back in prose alone.
#
# ``STATE.md`` is exempt, and the exemption is the point rather than a
# concession: its job is to record what was removed and why, so naming the
# thing is the *correct* behaviour there. A guard that forbade it would be
# forcing the one document that should be specific to be vague.
RECORDS_REMOVALS = "STATE.md"

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
        r"`((?:voyd|tests|examples|drift|bench|docs|tools)/[\w./]+\.(?:py|md|yml))`",
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


# Written out because a README says "fourteen runnable programs", not "14".
WORDS = {w: i for i, w in enumerate(
    "zero one two three four five six seven eight nine ten eleven twelve "
    "thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty "
    "twenty-one twenty-two twenty-three twenty-four twenty-five".split())}

# Every counted noun this repository writes into prose, and how to count the
# real thing. Adding a row is how the next one gets watched.
#
# The list exists because `CONSIDERATIONS.md` named this gap in writing --
# *"Nothing checks 'thirteen runnable programs' or 'five steps'. Those are on
# you, and both were stale within one commit of being written."* -- and then
# both went stale again anyway, in the same week, for the reason this codebase
# states everywhere else: "on you" is not a mechanism. A guard that watches
# one noun is a guard against one stale count.
COUNTED = (
    (r"\b([\w-]+|\d+) runnable programs?\b",
     lambda: len(list(ROOT.glob("examples/*.py")))),
    (r"\bin ([\w-]+|\d+) steps\b",
     lambda: len(re.findall(r"(?m)^## Step ",
                            (ROOT / "docs" / "AHA.md").read_text()))),
)


@pytest.mark.parametrize("pattern,count", COUNTED,
                         ids=lambda v: v if isinstance(v, str) else "")
def test_a_counted_noun_in_prose_matches_the_thing_it_counts(pattern, count):
    """The gap the test above left open, found the way these are always found.

    The count guard covered ``tests`` and nothing else, so when `shadow.py`
    was added the README went on saying *thirteen runnable programs* and
    every check in this file passed. The same week, `AHA.md` grew a sixth
    step and two sentences went on saying *five*.

    Exact rather than one-directional, unlike the test count: there is no
    parametrisation here to make the real number legitimately larger, so a
    reader who counts the directory and gets a different answer has found a
    mistake either way.
    """
    real = count()
    seen = 0
    for doc in DOCS:
        for claimed in re.findall(pattern, doc.read_text()):
            seen += 1
            n = int(claimed) if claimed.isdigit() else WORDS.get(claimed.lower())
            assert n is not None, (
                f"{doc.name} says {claimed!r}; spell a counted noun as a word "
                f"this test knows or as a numeral")
            assert n == real, (
                f"{doc.name} claims {n} where there are {real}. The thing "
                f"grew and the sentence did not")
    assert seen, f"nothing claims {pattern!r} any more; drop the row with it"


# The canon. `docs/` went eighteen files -> eight -> ten -> seven, because a
# reader who cannot tell which three to read reads none of them. The cuts that
# stuck removed two kinds of thing, and neither was documentation: a thinking
# journal, and a *changelog* -- `ISSUES.md`, `ideas.md` and `opportunities.md`
# were half struck-through entries by the end, kept in the place a reader goes
# for current state. Both belong in the git history and are there.
#
# The three-way split was the subtler mistake. Each of those files opened by
# explaining how it differed from the other two, which is the tell: when a
# document's first job is to distinguish itself from its siblings, the split
# costs more than it earns. They are one `STATE.md` now.
#
# Each survivor has one job, and the README must still point at the
# load-bearing ones.
FRONT_DOOR = ("blog.md", "STATE.md", "PORTABILITY.md", "policy-engines.md")


def test_the_front_door_points_at_documents_that_exist():
    """The README's table of contents is the first thing anybody uses and
    the last thing anybody updates."""
    readme = (ROOT / "README.md").read_text()
    for name in FRONT_DOOR:
        target = f"docs/{name}"
        assert f"({target})" in readme, f"README no longer links {target}"
        assert (ROOT / target).exists()
