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

It also checks **which door** each cited test drives, which is the hole
that let a headline claim go unqualified for months: the mapping said
lineage was held up by a named file, and the file drove a library handle
while the README pointed readers at a connection string. A claim that is
true of an artifact nobody is using is the exact gap this project exists
to make visible. Attachment was checked; *relevance* was not.

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


# --------------------------------------------------------------------------
# Which door. A claim is about the artifact people are told to use.
# --------------------------------------------------------------------------

# Fixtures that hand a test a live database.
DATABASE_FIXTURES = {"db", "adb", "rs_db", "atlas", "replica_set"}

# Cited files that touch a database without going through the boundary,
# and are allowed to. Each entry is a reason, not a waiver: the point of
# writing it down is that adding a fourth should feel like a decision.
THROUGH_THE_HANDLE = {
    "tests/test_encryption_is_the_answer_refusal_cannot_give.py":
        "a sealed collection is read through a client that decrypts, and "
        "decryption happens in a process holding the keys. There is no "
        "wire path that unseals into Python, so a test that could not "
        "read what it sealed would not be a test",
    "tests/test_the_write_path_forgets_without_deleting.py":
        "it pins the shape `_forget_pipeline` mirrors. The proxy does not "
        "call this code -- it emits the same update itself -- and the "
        "whole value of the file is that both have to leave the same row",
    "tests/test_a_rules_two_halves_agree.py":
        "it compares a rule's query half against its per-document half, "
        "which is a property of the rule and of MongoDB's query semantics. "
        "The database is the *subject* -- the whole point is to run the "
        "clause on a real server rather than reimplement `$exists` and "
        "null-matching in Python -- and a boundary in the middle would "
        "add nothing but a socket",
    "tests/test_the_suite_does_not_leak_databases.py":
        "it is about this suite's own housekeeping, not about the "
        "boundary. The database it touches is the subject, not the route",
}


def _fixtures_defined_in(tree: ast.AST) -> dict[str, set[str]]:
    """Fixture name -> the fixtures it asks for, for this module only."""
    out: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for deco in node.decorator_list:
            attr = getattr(deco, "attr", None) or getattr(
                getattr(deco, "func", None), "attr", None)
            if attr == "fixture":
                out[node.name] = {a.arg for a in node.args.args}
                break
    return out


def which_door(path: str) -> str:
    """``wire``, ``pure``, or ``handle`` for one cited test file.

    Deliberately crude, and crude in the safe direction. Spawning the
    proxy is unmistakable; constructing a driver client is unmistakable;
    everything else is a test with no database in it, which cannot be
    driving the wrong door because it is not driving a door at all.

    It cannot tell a *good* wire test from a token one. It is not meant
    to. It tells you a file cited for a guarantee about a connection
    string never opens one, which is the thing nobody noticed for months.
    """
    source = (ROOT / path).read_text()
    if "voyd.wire.proxy" in source and "subprocess" in source:
        return "wire"
    if re.search(r"\b(Async)?MongoClient\(", source):
        return "handle"
    tree = ast.parse(source)
    local = _fixtures_defined_in(tree)

    def wants_a_database(names: set[str], seen: tuple = ()) -> bool:
        return any(
            name in DATABASE_FIXTURES
            or (name in local and name not in seen
                and wants_a_database(local[name], (*seen, name)))
            for name in names)

    for node in ast.walk(tree):
        if (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name.startswith("test_")
                and wants_a_database({a.arg for a in node.args.args})):
            return "handle"
    return "pure"


@pytest.mark.parametrize("path", sorted(evidence_files()))
def test_every_claim_is_held_up_through_the_door_readers_are_sent_to(path):
    """A cited test drives the boundary, or touches no database at all.

    Anything else is a claim about a route the README does not recommend,
    and the README is what a reader believes. `CLAIMS.md` carried
    "revoking a source reaches the summary built on it" as a headline for
    months while the only thing holding it up imported a handle no
    application was told to use -- true, and true of the wrong thing.

    The escape is deliberate and narrow: a file on `THROUGH_THE_HANDLE`
    with a reason beside it. Three entries is a short enough list that a
    fourth is a conversation.
    """
    door = which_door(path)
    if door in ("wire", "pure"):
        return
    assert path in THROUGH_THE_HANDLE, (
        f"{path} is cited as evidence, touches a database, and never "
        f"starts the boundary -- so it holds its claim up through a route "
        f"no reader is pointed at. Drive it through `voyd.wire.proxy`, or "
        f"add it to THROUGH_THE_HANDLE with the reason it cannot be")


def test_no_reason_outlives_the_file_it_excuses():
    """An allowlist is a second place for a stale name to hide.

    The same failure as a claim citing a deleted test, one level up: an
    entry here for a file that has since moved to the wire would go on
    excusing nothing, and the next reader would believe the list.
    """
    cited = set(evidence_files())
    for path in THROUGH_THE_HANDLE:
        assert path in cited, f"{path} is excused here and cited nowhere"
        assert which_door(path) == "handle", (
            f"{path} no longer needs excusing -- it drives the boundary "
            f"now, or touches no database. Take it off the list")
