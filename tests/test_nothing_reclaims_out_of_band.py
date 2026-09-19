"""The principle said "tool or endpoint". Only the tool half was enforced.

`ideas.md` has said this since the beginning, under *Deliberately not
doing*:

    **A delete tool or endpoint.** A delete hands the caller a cleanup
    obligation, and an agent that has to remember to clean up is the
    failure this exists to remove. CI asserts no tool is named for
    reclaiming anything.

CI did assert that -- for MCP tools. Meanwhile `DELETE /v1/voyds/{slug}`
had been on the HTTP surface the whole time: untested, undocumented,
referenced by nothing, and cascading through a **hardcoded** list of two
collections written before `refusals`, `__keys` and `perimeter` existed.
So the destructive path nobody exercised was also the one guaranteed to
rot.

It is gone. This is the other half of the assertion, so the sentence in
`ideas.md` is now true rather than aspirational -- and so that the next
person to add one has to argue with a test instead of with a paragraph.
"""

from __future__ import annotations

import pytest

fastapi = pytest.importorskip("fastapi")

from voyd.web import owner, vault  # noqa: E402

RECLAIMING = {"DELETE"}
NAMED_FOR_RECLAIMING = {"delete", "remove", "destroy", "purge", "drop",
                        "cleanup", "expire", "gc", "collect", "reclaim"}


def routes():
    for router in (owner.router, vault.router):
        for route in router.routes:
            for method in getattr(route, "methods", set()):
                yield method, route.path, getattr(route, "name", "")


def test_no_endpoint_reclaims_anything():
    """A scope collects itself. An owner who has to remember to clean up is
    the failure this package exists to remove, and an HTTP verb is not a
    smaller version of that failure than an agent tool."""
    offenders = [(m, p) for m, p, _ in routes() if m in RECLAIMING]
    assert not offenders, (
        f"reclaiming endpoint(s) {offenders}. The deadline is the mechanism: "
        f"a scope expires and its rows go with it. If something genuinely "
        f"needs removing out of band, say why here -- and test the cascade, "
        f"because the last one hardcoded two collection names and three more "
        f"appeared after it was written")


def test_no_endpoint_is_named_for_reclaiming():
    """``POST /purge`` is a delete with better manners."""
    offenders = [(p, n) for _, p, n in routes()
                 if any(w in n.lower() or w in p.lower()
                        for w in NAMED_FOR_RECLAIMING)]
    assert not offenders, f"named for reclaiming: {offenders}"


def test_forgetting_is_still_reachable():
    """The point is not that nothing can be forgotten -- it is that
    forgetting hands back no obligation. ``forget`` moves a deadline into
    the past; nothing is scheduled and nothing needs a follow-up call."""
    paths = {p for _, p, _ in routes()}
    assert "/v1/voids/{token}/forget" in paths
