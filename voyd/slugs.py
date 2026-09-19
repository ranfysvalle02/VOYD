"""Slug rules for namespaces, in one place.

A namespace is selected by the Host header — `{slug}.voyd.com` — so the slug is
routing, not decoration: it has to be a legal DNS label, and it must not
collide with a name something else already answers to.

One function owns those rules. It used to be three checks written out in the
route *and* a predicate here that nothing called, which is the same shape as
the bug the rest of this codebase is organised against: two copies of one rule,
diverging quietly, with the copy that is actually reached being the one nobody
reviews. ``slug_error`` is now the only arbiter, and the route reports whatever
it says.

There used to be a ``slugify`` here too, turning "Auto Repair Orlando" into
"auto-repair-orlando" for a signup form to preview. The form is gone — there is
no browser surface and no sign-in — and the API takes the slug it is given, so
deriving one was a guess on the caller's behalf. It went with the form.
"""

from __future__ import annotations

import re

# 3-40 chars, lowercase alphanumeric, inner hyphens. The intersection of what
# a DNS label allows and what a person can read back over the phone.
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$")

# Names that resolve to something else, or would if this were deployed behind
# a wildcard. A namespace called "api" is a routing bug waiting for traffic.
RESERVED_SLUGS = {
    "www", "api", "admin", "app", "voyd", "static", "assets", "mail",
    "localhost", "login", "signup", "logout", "new", "dashboard", "keys",
    "help", "support", "status", "docs", "blog", "cdn", "ftp", "smtp",
}


def slug_error(slug: str) -> str | None:
    """What is wrong with this slug, phrased for the caller, or ``None``.

    Returns a message rather than a boolean because the caller is an HTTP
    route that has to say *why* it refused, and a predicate would have sent it
    back here to work that out — which is how the rules came to be written
    twice in the first place.

    Ordered from most specific to least, so "reserved" is reported as reserved
    rather than as a pattern failure.
    """
    if not slug:
        return "slug is required."
    if len(slug) < 3:
        return "slug must be at least 3 characters."
    if len(slug) > 40:
        return "slug must be at most 40 characters."
    if slug in RESERVED_SLUGS:
        return f"'{slug}' is reserved."
    if not SLUG_RE.match(slug):
        return ("slug must be lowercase letters, digits and inner hyphens "
                "only.")
    return None
