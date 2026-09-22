"""A `docker compose up` in the docs has to name a service that exists.

The smallest possible member of this repository's argument, applied to the
first thing a stranger types. Every other check here asks whether the code
does what it claims; this one asks whether the *instructions* do, because a
README whose first command fails is a statement of intent like any other.

It is cheap on purpose. It does not run Docker and it does not check that
the service works -- it checks that the name in the prose is a key in the
compose file, which is the failure that actually happens: a service gets
renamed and the four places that name it do not.

This file is also why `pyyaml` is a declared dependency. It was listed in
`pyproject.toml` as being *for this test* while this test did not exist,
and nothing in the repository imported `yaml` at all -- a dependency
justified by a file that was never written, sitting in the block whose own
comment is about tools that were present by luck. Found by reading the
dependency block against the test directory.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yml"

# Where a reader could meet one of these commands.
DOCS = ("README.md", "LIMITS.md", "CLAIMS.md", "SHADOW_MODE.md",
        "scanner/README.md", ".github/workflows/test.yml")

# `docker compose up ... <service>` with any flags in between. The service
# is the last bare word, which is how the command is actually written.
INVOCATION = re.compile(
    r"docker compose up((?:\s+(?:-[\w-]+|--[\w-]+(?:=\S+)?))*)\s+([a-zA-Z0-9_-]+)")


def services() -> set[str]:
    loaded = yaml.safe_load(COMPOSE.read_text())
    return set(loaded.get("services") or {})


def documented() -> list[tuple[str, str]]:
    """Every `(where, service)` a document tells somebody to start."""
    found = []
    for name in DOCS:
        path = ROOT / name
        if not path.exists():
            continue
        for _flags, service in INVOCATION.findall(path.read_text()):
            found.append((name, service))
    return found


def test_the_compose_file_is_readable_and_has_services():
    """The control. Without it every assertion below passes vacuously on a
    file that failed to parse -- which is the shape of defect LIMITS.md §1
    already records against this suite once."""
    assert services(), f"{COMPOSE.name} declares no services"


def test_something_documents_starting_a_service():
    """The other half of the control: a regex that matches nothing would
    make this file a decoration."""
    assert documented(), (
        "no document names a `docker compose up` service; either the "
        "instructions changed or this test stopped being able to read them")


def test_every_documented_service_exists():
    real = services()
    wrong = [(where, name) for where, name in documented() if name not in real]
    assert not wrong, (
        f"these documents start a compose service that is not in "
        f"{COMPOSE.name} (which has {sorted(real)}): {wrong}")


def test_every_compose_service_is_documented_somewhere():
    """The other direction, and the more interesting one. A service nobody
    is told to start is either dead weight in the compose file or a step
    missing from the instructions -- and the reader who needs it has
    nothing telling them it is there."""
    named = {name for _where, name in documented()}
    orphans = sorted(services() - named)
    assert not orphans, (
        f"{orphans} exist in {COMPOSE.name} and no document tells anybody "
        f"to start them")
