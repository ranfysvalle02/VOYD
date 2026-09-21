"""The thesis, applied to the documentation, mechanically.

This project's argument is that a statement of intent is not a guarantee.
`CLAIMS.md` is a page of statements of intent. So the mapping between them
and the files that hold them up is checked here rather than maintained by
good intentions, in both directions:

- a claim naming a test file that does not exist is a guarantee nobody
  holds up. It is also what a claim looks like *after* somebody deletes the
  test, which is the direction that actually happens.
- a test file no claim points at is evidence nobody is using. Less
  dangerous and more common: a file that quietly became the only thing
  standing between this project and a regression nobody has named.

**What this deliberately does not do** is judge whether a test is any good.
It cannot, and pretending otherwise would be the exact failure it exists to
catch. `LIMITS.md` §1 has the case in full: a test on this map had a
docstring about a page of fifty documents and asserted a page of one, passed
under sabotage, and would have gone on passing. Attachment is a floor.

So the value here is narrow and real: the distance between "we believe this"
and "this is held up by a named file that runs in CI" is the whole distance
this project is about, and nothing else in the suite measures it.

No database. It reads two directories and a markdown file.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CLAIMS = ROOT / "CLAIMS.md"
TESTS = ROOT / "tests"

# `CLAIMS.md` is the manifest and this is the only thing that parses it, so
# the format is asserted rather than assumed.
#
# Row-based rather than a scan for matching paths, and that distinction is a
# defect this file already had. The first version collected every substring
# matching `tests/test_[a-z0-9_]+\.py`, so a citation the pattern did not
# match -- a capital letter, a hyphen, a truncated name -- was not reported
# as broken. It was not seen at all. The row stayed on the page looking
# attached while nothing verified it, which is precisely the failure mode
# this file exists to catch, committed by the parser.
#
# So every claim row must yield a citation, and a row that does not is a
# failure rather than a row this skipped.
CITED = re.compile(r"^`(tests/test_[a-z0-9_]+\.py)`$")


def claim_rows() -> list[tuple[str, str]]:
    """``(claim, raw citation)`` for every row of every table in CLAIMS.md."""
    rows = []
    for line in CLAIMS.read_text().splitlines():
        line = line.strip()
        if not line.startswith("|") or not line.endswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) != 2:
            continue
        claim, cited = cells
        if claim == "claim" or set(claim) <= set("-: "):
            continue                     # header and separator
        rows.append((claim, cited))
    return rows

# There is deliberately no exemption list.
#
# There was one, for this file -- on the reasoning that a claim pointing at
# the checker would be circular. It never fired: `CLAIMS.md` cites this file
# like any other, so it was never an orphan, so the escape hatch was dead
# permission sitting next to a test asserting that dead permission is bad.
# The same defect as the `sealed()`/`auto_embed()` guard that could not run,
# one level up, in the file whose subject is exactly that.
#
# The bijection is therefore exact. A test file that genuinely should not be
# a product claim will trip the orphan check, and whoever adds it can decide
# in the open rather than inheriting a hole somebody left open in advance.

def cited_paths() -> set[str]:
    assert CLAIMS.exists(), "CLAIMS.md is the manifest; it has to exist"
    out = set()
    for _claim, cited in claim_rows():
        found = CITED.match(cited)
        if found:
            out.add(found.group(1))
    return out


def evidence_files() -> set[str]:
    # Not named `test_*`: pytest collected the helper as a test, which passed
    # by returning a set. A function pretending to be evidence, in the file
    # whose whole job is to notice that.
    return {f"tests/{p.name}" for p in TESTS.glob("test_*.py")}


def test_the_manifest_has_claims_in_it():
    """A parser that silently found nothing would pass every check below."""
    rows = claim_rows()
    assert len(rows) > 15, (
        f"parsed {len(rows)} claim rows out of CLAIMS.md, which is fewer "
        f"than the page plainly contains -- the format changed and this "
        f"parser did not, so every check below is now vacuous")


def test_every_claim_row_cites_a_parsable_path():
    """A citation this cannot read must fail, not vanish.

    The bug this file shipped with. A scan for well-formed paths treats a
    malformed one as absent, so a row with a typo reads as attached to a
    reader and as nonexistent to the checker -- the worst of both, and
    invisible from either side.
    """
    unreadable = [(claim[:48], cited) for claim, cited in claim_rows()
                  if not CITED.match(cited)]
    assert not unreadable, (
        f"these rows do not cite a readable `tests/test_*.py` path: "
        f"{unreadable}")


def test_every_claim_names_a_test_file_that_exists():
    """A claim whose evidence was deleted is worse than an unstated one.

    Worse because the claim stays legible and confident while the thing
    holding it up is gone -- which is the shape of every defect in
    `LIMITS.md` §1.
    """
    missing = sorted(cited_paths() - evidence_files())
    assert not missing, (
        f"CLAIMS.md cites {missing}, which do not exist. Either the test was "
        f"deleted and the claim is now unheld, or the path is a typo -- and "
        f"a typo here is indistinguishable from the first case to anybody "
        f"reading the page")


def test_every_test_file_is_named_by_a_claim():
    """Evidence nobody points at is a regression nobody has named.

    The less dangerous direction and the more common one. A test file that
    appears with no claim behind it is usually somebody's real discovery
    that never made it into the argument -- which means the next person to
    find it slow or awkward has nothing telling them what it is for.
    """
    orphans = sorted(evidence_files() - cited_paths())
    assert not orphans, (
        f"{orphans} hold up no claim in CLAIMS.md. Add the claim they are "
        f"evidence for -- and if they are evidence for nothing, that is the "
        f"more interesting answer")


@pytest.mark.parametrize("path", sorted(evidence_files()))
def test_no_cited_file_is_empty(path):
    """A file with no tests in it cannot hold a claim up.

    The cheapest version of "a test that cannot fail is a screenshot": this
    catches the degenerate case where a file is cited, exists, imports
    cleanly, collects zero tests, and the suite stays green. It does not
    catch a file full of weak assertions, and does not pretend to.
    """
    tree = ast.parse((ROOT / path).read_text())
    tests = [node.name for node in ast.walk(tree)
             if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
             and node.name.startswith("test_")]
    assert tests, (
        f"{path} is cited as evidence and defines no test functions, so the "
        f"claim it holds up is held up by an import")


@pytest.mark.parametrize("path", sorted(evidence_files()))
def test_every_test_file_says_what_it_is_for(path):
    """The module docstring is the claim in its own words.

    `CLAIMS.md` states each guarantee for a reader who has not opened the
    file; the docstring states it for the one who has. A file with neither
    is a file whose purpose is reconstructed by reading assertions, which is
    how a test's original intent gets lost and then contradicted.
    """
    doc = ast.get_docstring(ast.parse((ROOT / path).read_text()))
    assert doc and len(doc.strip()) > 40, (
        f"{path} has no module docstring worth the name. Say what breaks if "
        f"this file is wrong")
