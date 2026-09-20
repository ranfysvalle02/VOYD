"""The first command a stranger runs must be a command that exists.

``cp .env.example .env`` is the first line of CI and the one instruction the
README gives for booting the service, and
for a while ``.env.example`` was neither tracked nor present. So the documented
first run failed on its second line, and CI failed on its first -- a break that
no test could see, because every test builds its own settings and none of them
reads the file a new user is told to copy.

That is the general shape worth a guard: the parts of a repository that only
*humans* execute. A stale docstring is a nuisance; a Quickstart that cannot be
followed is the entire first impression, and it rots silently because the
people who would notice have already got it working.

So this asserts the three things that can drift apart:

1. the file the README and CI copy exists;
2. every key in it is a real setting, and every setting is in it -- a new
   option that nobody documents is the next silent break;
3. an unedited copy parses, and the values are the safe defaults rather than
   whatever was in the author's shell.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytest.importorskip("pydantic_settings")

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / ".env.example"


def _declared() -> dict[str, str]:
    """The keys an unedited copy actually sets, commented-out ones excluded."""
    out = {}
    for line in EXAMPLE.read_text().splitlines():
        if line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        out[key.strip()] = value.strip()
    return out


def test_the_file_the_readme_and_ci_copy_exists():
    assert EXAMPLE.is_file(), (
        f"{EXAMPLE.name} is missing, so `cp .env.example .env` fails -- which "
        f"is the Quickstart's second line and CI's first")

    readme = (ROOT / "README.md").read_text()
    workflow = (ROOT / ".github/workflows/test.yml").read_text()
    assert "cp .env.example .env" in readme
    assert "cp .env.example .env" in workflow, (
        "CI stopped copying it; if that is deliberate, this test should say so")


def test_every_key_is_a_real_setting_and_every_setting_is_documented():
    from voyd.settings import VoydSettings

    documented = {k.removeprefix("VOYD_").lower() for k in _declared()}
    # Commented-out keys count as documented -- VOYD_LEDGER_KEY is deliberately
    # left unset, and explaining it is the point of the line.
    documented |= {m.group(1).lower() for m in
                   re.finditer(r'^#\s*VOYD_([A-Z_]+)=', EXAMPLE.read_text(),
                               re.M)}
    fields = set(VoydSettings.model_fields)

    assert documented - fields == set(), (
        f"{EXAMPLE.name} sets keys that are not settings: "
        f"{sorted(documented - fields)}")
    assert fields - documented == set(), (
        f"these settings exist and are undocumented: "
        f"{sorted(fields - documented)} -- an option nobody writes down is "
        f"the next thing to silently stop working")


def test_an_unedited_copy_parses_and_is_safe_by_default():
    """No ``.env``, no environment: only what the file itself provides.

    ``_env_file=None`` matters. Without it this reads the author's own
    ``.env``, and a broken example would pass here on the one machine where
    nobody needs it to work.
    """
    from voyd.settings import VoydSettings, build_app

    kw = {k.removeprefix("VOYD_").lower(): v for k, v in _declared().items()}
    settings = VoydSettings(_env_file=None, **kw)

    # Points at the container docker-compose publishes, from the host.
    assert settings.mongo_uri.endswith("directConnection=true")
    # The first owner is open, which is what makes the Quickstart's curl work.
    assert settings.allow_signup is True
    # And nothing surprising is switched on for somebody who just copied it.
    assert settings.require_passcode is False
    assert settings.ledger_key is None, (
        "the example ships a signing key, so every deployment that copied it "
        "shares one")

    assert build_app(settings) is not None


def test_the_image_cannot_bake_in_the_real_env_file():
    """``COPY . .`` copies whatever is in the directory, including secrets.

    There was no ``.dockerignore``, so the Dockerfile's final ``COPY . .``
    baked the developer's real ``.env`` into a layer that anyone who pulled
    the image could read — alongside a 248MB host-built ``.venv``, copied
    *over* the one ``uv sync`` had created one layer earlier, so the image was
    also carrying an environment linked against the wrong machine.

    Both are invisible locally: the build succeeds, the container starts, and
    the credential ships. So the exclusions are asserted rather than trusted,
    and ``.env.example`` is asserted *not* to be excluded — it is
    documentation, and a rule that swept it up would break the Quickstart
    this file also guards.
    """
    ignore = ROOT / ".dockerignore"
    assert ignore.is_file(), (
        "no .dockerignore, so `COPY . .` bakes .env, .venv and .git into the "
        "image")

    rules = [line.strip() for line in ignore.read_text().splitlines()
             if line.strip() and not line.startswith("#")]

    for secret in (".env", ".venv/", ".git/"):
        assert secret in rules, f"{secret} is not excluded from the image"
    assert "!.env.example" in rules, (
        ".env.example must stay in the image -- it is the documentation the "
        "Quickstart tells people to copy")

    dockerfile = (ROOT / "Dockerfile").read_text()
    assert "COPY . ." in dockerfile, (
        "the Dockerfile stopped copying the tree; if that is deliberate, this "
        "test is the wrong guard and should say so")


def test_the_example_carries_no_credential_that_looks_real():
    """A placeholder is fine. A working key committed to a public repo is not.

    Cheap, and it is the mistake that is only ever made once per repository.
    """
    text = EXAMPLE.read_text()
    assert "vy-dev-key" in text, "the Voyage placeholder should stay a placeholder"
    for pattern, what in ((r'voyd_[A-Za-z0-9_-]{20,}', "a VOYD API key"),
                          (r'pa-[A-Za-z0-9_-]{20,}', "a Voyage key"),
                          (r'mongodb\+srv://[^\s]*:[^\s@]+@', "Atlas credentials")):
        assert not re.search(pattern, text), f"{EXAMPLE.name} contains {what}"
