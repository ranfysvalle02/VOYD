"""What the application believes about the vendors it chose.

The mechanism, and the argument for replacing a self-attested date with a
runnable check, is in ``voyd/engine/assumptions.py``. This file is the half
that cannot live there: ``voyd/engine/`` is a database library with no vendor
in it, enforced by ``tests/test_engine_standalone.py``, so a belief about an
embedding provider is declared by the layer that picked one.

Same rules. Every entry says what it believes, why it is not probed, what
breaks when it is wrong, and how a stranger re-establishes it. The
verification record is written beside this file by ``verify_all()`` and by
nothing else.

----

**On writing a check that actually expires.**

The obvious check for *"model X is the current recommendation"* is to assert
that X appears on the vendor's model page. It is also useless: X goes on
appearing there for years after it stops being the recommendation, so the
check passes forever and the registry is decoration with extra steps. That is
the same failure as the date, wearing a better costume.

So the checks below watch for the **successor**. The event that made the old
default stale was not voyage-3 disappearing -- it is still listed -- it was
voyage-4 arriving while nobody was looking. ``absent=("voyage-5",)`` fails on
exactly that event, which is the one worth a build stopping for.

It is not a complete encoding of "still recommended", and pretending
otherwise would be the overclaim this repository spends whole files avoiding.
A vendor can demote a model without shipping a successor. What this catches
is the case that actually happened, and the residual is written into
``breaks`` where somebody reading the failure will find it.
"""

from __future__ import annotations

from .engine.assumptions import Assumption, Check

VENDORS: tuple[Assumption, ...] = (
    Assumption(
        name="embedding.default_model",
        claim="voyage-4 is the vendor's current general-purpose embedding "
              "recommendation, and the 4-series supports configurable output "
              "dimensions and quantized embeddings where voyage-3 does not.",
        why_not_probed="Choosing a default is a judgement about a lineup, "
                       "not a capability. An API key answers 'can I call "
                       "this model', which is a different and much weaker "
                       "question than 'is this still the one to default "
                       "to'.",
        breaks="New deployments default to a superseded model. Existing "
               "indexes are unaffected, because the geometry is pinned by "
               "numDimensions rather than by the model name -- so this is "
               "quality drift rather than an outage, and it is exactly the "
               "drift that went unnoticed for two generations. Note the "
               "residual: this check fires when a successor ships, not when "
               "a model is quietly demoted without one.",
        # The first run of this check failed on ``matryoshka``, which the
        # claim asserted and the page does not contain -- the word came from
        # a rendered summary, not the source. The check was right and the
        # claim was wide, so the claim narrowed to what the evidence
        # actually carries. That is the mechanism working in the direction
        # it was built for: a belief got smaller because somebody had to
        # show their evidence.
        check=Check(
            url="https://docs.voyageai.com/docs/embeddings",
            present=("voyage-4", "voyage-4-large", "quantiz", "dimension"),
            absent=("voyage-5",),
        ),
    ),
    Assumption(
        name="embedding.server_side_models",
        claim="Automated embedding accepts the voyage-4 family and "
              "voyage-code-4, and voyage-code-4 is Atlas-only while "
              "voyage-code-3 is the self-managed fallback for code search.",
        why_not_probed="The failure path is probed -- ensure() attempts the "
                       "autoEmbed index and falls back loudly when the "
                       "deployment rejects the model. What cannot be probed "
                       "is the *list*, which is what a caller needs before "
                       "they declare one.",
        breaks="A deployment declares auto_embed with a model the server "
               "does not accept and gets the fallback: correct, loud, and "
               "slower than being told at declaration time.",
        check=Check(
            url="https://www.mongodb.com/docs/vector-search/crud-embeddings/"
                "automated-embedding/models/",
            present=("voyage-4", "voyage-code-4"),
            absent=("voyage-5",),
        ),
    ),
)


def _fetch(url: str) -> str:
    """The only thing here that reaches the internet.

    ``urllib`` rather than a dependency: this runs by hand or on a schedule,
    never on the request path, and adding an HTTP client to a package that
    installs as a database driver to support a twice-yearly chore would be a
    poor trade.
    """
    import urllib.request

    request = urllib.request.Request(
        url, headers={"User-Agent": "assumption-verifier"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8", errors="replace")


def verify_all(*, fetch=None) -> dict:
    """Re-check every belief in both registries and rewrite both records.

    Run it by hand, or on a schedule, when the build says something is
    unsettled. It is deliberately not part of the test suite: a suite that
    fetched six vendor pages would fail on somebody's flaky wifi and be
    disabled within a month, and a disabled check is worse than an honest
    "unverified".
    """
    import json

    from .engine import assumptions as engine_assumptions

    fetch = fetch or _fetch
    results = {}
    for registry, path in (
            (engine_assumptions.WORLD, engine_assumptions.RECORD),
            (VENDORS, RECORD)):
        record = engine_assumptions.verify(registry, fetch=fetch)
        path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        # Keyed by the full path: both records are called
        # ``assumptions.lock.json`` and live in different packages, so
        # keying by name silently reported one run twice.
        results[str(path)] = record
    return results


from pathlib import Path  # noqa: E402 - kept beside the constant it defines

# Written by ``verify_all``, read by the tests and ``health()``, hand-edited
# by nobody. See the engine module's docstring for what that does and does
# not achieve.
RECORD = Path(__file__).with_name("assumptions.lock.json")


if __name__ == "__main__":  # pragma: no cover - the chore, run by hand
    import logging

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    for name, record in verify_all().items():
        bad = [k for k, v in record.items() if not v["ok"]]
        print(f"{name}: {len(record)} checked, "
              f"{len(bad)} failed{': ' + ', '.join(bad) if bad else ''}")
