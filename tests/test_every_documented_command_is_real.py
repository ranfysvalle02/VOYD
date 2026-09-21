"""Every command in a fenced block is a promise, and nothing was checking them.

Thirty distinct commands across twelve documents: `uv sync --extra crypto`,
`docker compose -f drift/... up -d --wait drift-qdrant`,
`python scanner/voyd_scan --read-verb fetch_all src/`. Rename an extra, drop a
compose service, rename a flag, and every document naming it lies -- silently,
in the copy-pasteable part, which is the part a stranger trusts most and
verifies least.

The documents were already guarded for links, anchors, source paths named in
prose, and counted nouns. The *commands* were the remaining surface, and they
are the highest-consequence one: a dead link is an annoyance, a command that
fails on the first run is the end of the evaluation.

This does not execute anything expensive. It checks the claim each command
makes about *this repository*, which is the part that rots:

- ``uv sync --extra X``            -> X is declared in pyproject.toml
- ``docker compose -f F up ... S`` -> F exists and declares service S
- ``python path/to/script.py``     -> the script is there
- a CLI with flags                 -> argparse accepts them

Commands about the outside world (`curl`, `git clone`) are skipped, and the
skip is listed rather than inferred so the next unparseable shape is a
decision somebody makes.
"""

from __future__ import annotations

import re
import shlex
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
DOCS = ([ROOT / n for n in ("README.md", "ADOPTING.md", "PILOT.md")]
        + sorted((ROOT / "docs").glob("*.md"))
        + [ROOT / "scanner" / "README.md", ROOT / "drift" / "README.md"])

# Shapes that are about somewhere else. Anything not matched here and not
# understood below fails, so a new kind of command is noticed rather than
# quietly unchecked.
EXTERNAL = ("curl", "git", "export", "cd")


def _commands() -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for doc in DOCS:
        for block in re.findall(r"```(?:bash|sh|console)\n(.*?)```",
                                doc.read_text(), re.S):
            for line in block.splitlines():
                line = line.split("#")[0].strip()
                if line and not line.startswith(("#", "$")):
                    out.append((doc.name, line))
    return sorted(set(out))


COMMANDS = _commands()


def test_the_documents_still_contain_commands():
    """If the extraction breaks, this file must fail rather than vacuously
    pass on an empty list -- the failure mode of every parser-backed guard."""
    assert len(COMMANDS) > 20, f"only extracted {len(COMMANDS)}; the fences moved"


@pytest.mark.parametrize("doc,cmd", COMMANDS, ids=lambda v: v)
def test_a_documented_command_is_real(doc: str, cmd: str):
    parts = shlex.split(cmd)
    if parts[0] in EXTERNAL:
        pytest.skip("about the outside world, not this repository")

    # uv sync --extra X / --all-extras
    if parts[:2] == ["uv", "sync"]:
        declared = set(tomllib.loads((ROOT / "pyproject.toml").read_text())
                       ["project"]["optional-dependencies"])
        for i, tok in enumerate(parts):
            if tok == "--extra":
                assert parts[i + 1] in declared, (
                    f"{doc} says `{cmd}` but pyproject declares "
                    f"{sorted(declared)}")
        return

    # docker compose [-f FILE] up ... [SERVICE]
    if parts[0] == "docker" and "compose" in parts:
        f = ROOT / "docker-compose.yml"
        if "-f" in parts:
            f = ROOT / parts[parts.index("-f") + 1]
        assert f.exists(), f"{doc} says `{cmd}` but {f.name} is not there"
        services = set(yaml.safe_load(f.read_text()).get("services", {}))
        for tok in parts[parts.index("up") + 1:] if "up" in parts else []:
            if not tok.startswith("-") and tok in ("mongo", "voyd") or \
                    tok.startswith("drift-"):
                assert tok in services, (
                    f"{doc} says `{cmd}` but {f.name} declares "
                    f"{sorted(services)}")
        return

    # Anything that runs a script in this tree, with or without `uv run`.
    argv = parts[parts.index("python") + 1:] if "python" in parts else None
    assert argv, f"{doc}: unrecognised command shape `{cmd}`"
    script = ROOT / argv[0]
    assert script.exists(), f"{doc} says `{cmd}` but {argv[0]} is not there"

    flags = [a for a in argv[1:] if a.startswith("--")]
    if not flags:
        return
    # The flags have to parse. The paths in the documentation are a stranger's
    # (`src/`, `app/`), so these runs are *expected* to fail on a missing
    # path -- 255 -- and the thing under test is that argparse did not reject
    # a flag first, which is exit 2.
    try:
        proc = subprocess.run([sys.executable] + argv, cwd=ROOT,
                              capture_output=True, text=True, timeout=20,
                              env={"PYTHONPATH": "scanner",
                                   "PATH": "/usr/bin:/bin"})
    except subprocess.TimeoutExpired:
        # Some documented commands are *servers* -- `voyd_wire.py` listens
        # until interrupted. Reaching the point of blocking means argparse
        # accepted every flag, which is the only thing under test here. A
        # guard that hung the suite on a documented daemon would be a worse
        # bug than the stale flag it was looking for.
        return
    assert proc.returncode != 2 and "unrecognized arguments" not in proc.stderr, (
        f"{doc} says `{cmd}` and the CLI rejected it:\n"
        f"{proc.stderr.strip().splitlines()[-1] if proc.stderr else ''}")
