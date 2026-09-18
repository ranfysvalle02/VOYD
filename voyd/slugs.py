"""Slug rules, shared by the console UI and the JSON API.

A human types a business name ("Auto Repair Orlando"); VOYD derives the
namespace ("auto-repair-orlando") and shows them the resulting URL before they
commit. Both entry points must agree on what a legal slug is, so the rules
live here rather than being duplicated per route.
"""

from __future__ import annotations

import re
import unicodedata

# 3-40 chars, lowercase alphanumeric and inner hyphens.
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$")

RESERVED_SLUGS = {
    "www", "api", "admin", "app", "voyd", "static", "assets", "mail",
    "localhost", "login", "signup", "logout", "new", "dashboard", "keys",
    "help", "support", "status", "docs", "blog", "cdn", "ftp", "smtp",
}


def slugify(name: str) -> str:
    """Turn a human business name into a candidate slug."""
    text = unicodedata.normalize("NFKD", name or "")
    text = text.encode("ascii", "ignore").decode("ascii").lower()
    text = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    text = re.sub(r"-{2,}", "-", text)
    return text[:40].strip("-")


def slug_error(slug: str) -> str | None:
    """Return a human-readable problem with this slug, or None if it's fine."""
    if not slug:
        return "Enter a business name."
    if len(slug) < 3:
        return "That name is too short - use at least 3 characters."
    if slug in RESERVED_SLUGS:
        return f"'{slug}' is reserved. Try another name."
    if not SLUG_RE.match(slug):
        return "Use letters, numbers and hyphens only."
    return None


def is_valid(slug: str) -> bool:
    return slug_error(slug) is None
