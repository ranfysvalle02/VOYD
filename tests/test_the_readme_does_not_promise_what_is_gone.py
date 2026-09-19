"""The claims table is a promise. This checks it still has code behind it.

The README ends with fifty-odd rows of the form *claim -> how it is proven*.
That table is the most load-bearing prose in the repository: it is what a
reader checks instead of reading the suite, and it is the thing a sceptical
reviewer greps.

It also rots in a way nothing else notices. Deleting a feature deletes its
tests, and a green suite then says nothing about a row still claiming the
feature works. Two were found that way -- a race-proof read limit and a
change-stream oplog counter, both of which went with the byte path they
bounded, and one of which the README had already announced the removal of
*twenty lines above the row still promising it*.

So: every identifier the table names in backticks must appear somewhere in the
source. Deliberately shallow. It cannot tell whether a claim is *true* -- that
is what the suite is for -- but it catches the only failure this table has
actually had, which is naming something that no longer exists.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Prose, not code: words that appear in backticks for emphasis or as literal
# API/JSON shapes rather than as identifiers to find in the source.
NOT_IDENTIFIERS = {
    "expire_at", "indexed", "true", "false", "null", "Days", "mappings",
    "voyd", "documents", "voids", "text", "name", "score", "matches",
}


def _claim_rows() -> list[str]:
    readme = (ROOT / "README.md").read_text()
    start = readme.index("| Claim | How |")
    table = readme[start:]
    table = table[:table.index("\n\n")]
    rows = [row for row in table.splitlines()
            if row.startswith("| ") and "---" not in row]
    return rows[1:]                    # drop the header


def _sources() -> str:
    parts = []
    for pattern in ("voyd/*.py", "voyd/*/*.py", "tests/*.py", "examples/*.py",
                    "bench/*.py", "drift/*.py"):
        for f in ROOT.glob(pattern):
            parts.append(f.read_text())
    return "\n".join(parts)


def test_the_table_is_not_empty():
    """If the parse breaks, this file must fail rather than vacuously pass."""
    rows = _claim_rows()
    assert len(rows) > 40, f"only parsed {len(rows)} claims; the table moved"


def test_every_identifier_the_readme_claims_still_exists():
    src = _sources()
    missing: dict[str, str] = {}

    for row in _claim_rows():
        claim = row.split("|")[1].strip()
        for ident in re.findall(r'`([A-Za-z_][A-Za-z0-9_\.]{2,})`', row):
            probe = ident.split("(")[0].split(".")[-1]
            if probe in NOT_IDENTIFIERS or probe.strip("_") == "":
                continue
            if probe not in src:
                missing[probe] = claim

    assert not missing, (
        "the README claims these are proven, and nothing in the source "
        "mentions them any more: "
        + "; ".join(f"`{k}` (in '{v}')" for k, v in missing.items())
        + ". Either the claim outlived its feature, or the identifier was "
          "renamed and the table was not.")
