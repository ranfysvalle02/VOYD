"""A slug is routing, so the rules that accept one live in exactly one place.

``{slug}.voyd.com`` selects the namespace, which makes a slug a DNS label
rather than a display name. The rules were once written out in the route *and*
kept as a predicate in ``voyd.slugs`` that nothing called — two copies, one of
them unreachable, which is the shape of the bug the rest of this repository is
organised against. The route now asks ``slug_error`` and reports what it says.

So these tests are about the rules, plus one that asserts the route cannot go
back to having its own opinion.
"""

from __future__ import annotations

import re
from pathlib import Path

from voyd.slugs import RESERVED_SLUGS, SLUG_RE, slug_error


def test_a_legal_slug_has_no_error():
    for ok in ("acme", "auto-repair-orlando", "a1b", "x" * 40):
        assert slug_error(ok) is None, f"{ok!r} should be legal"


def test_the_error_names_the_actual_problem():
    """A 422 that says "invalid" makes the caller guess. These do not."""
    assert "required" in slug_error("")
    assert "3 characters" in slug_error("ab")
    assert "40 characters" in slug_error("x" * 41)
    assert "reserved" in slug_error("admin")
    assert "lowercase" in slug_error("Acme Corp")


def test_reserved_names_are_reported_as_reserved_not_as_a_pattern_failure():
    """Order matters: ``admin`` matches the pattern and is still refused.

    If the pattern check ran first, every reserved name would come back as
    "lowercase letters, digits and inner hyphens only", which is both untrue
    of the input and useless to whoever sent it.
    """
    for reserved in sorted(RESERVED_SLUGS):
        problem = slug_error(reserved)
        assert problem is not None, f"{reserved!r} must be refused"
        if SLUG_RE.match(reserved):
            assert "reserved" in problem, (
                f"{reserved!r} is a legal pattern and was refused for the "
                f"wrong reason: {problem}")


def test_nothing_illegal_gets_through_the_pattern():
    for bad in ("ab", "-acme", "acme-", "AC ME", "acme_corp", "a" * 41,
                "acme.corp", "", "ácme"):
        assert slug_error(bad) is not None, f"{bad!r} was accepted"


def test_the_route_does_not_keep_its_own_copy_of_the_rules():
    """The regression guard, and the reason this file is short now.

    Two copies of a validation rule diverge, and the copy that diverges
    silently is the one in the route -- because it is the one that is actually
    reached, and the other one's tests keep passing. So the route may not
    mention the primitives at all: it asks, and reports.
    """
    route = (Path(__file__).resolve().parents[1] / "voyd/web/owner.py").read_text()

    assert "slug_error" in route, "the route must ask the one arbiter"
    for primitive in ("SLUG_RE", "RESERVED_SLUGS"):
        assert primitive not in route, (
            f"voyd/web/owner.py reaches for {primitive} directly, which is how "
            f"the route and voyd/slugs.py came to disagree before")
    assert not re.search(r'len\(slug\)', route), (
        "the route is checking slug length itself again")
