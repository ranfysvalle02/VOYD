"""The export list is a promise, so growing it should cost a line in a diff.

This repository has an opinion about every other kind of drift -- a rule you
have to remember is not enforced, a stale index cannot pass for a current
one, a skipped check must not look like a passing one -- and had none at all
about its own API surface. It reached a hundred names the way these things
always do: one justified addition at a time, each obviously fine, nobody
ever reading the list from the top.

Forty-eight of those hundred appeared in neither the README, nor the blog,
nor any example. Not because they were wrong, but because nothing had ever
asked them to earn the name.

So the surface is pinned here. The test is deliberately annoying: adding a
public name means editing this file, which means somebody types out that it
should be public. That is the entire mechanism, and it is the same one
``including_refused()`` uses -- the safe thing is the default, and the other
thing has to be said out loud.

**Being out of ``__all__`` is not being deleted.** Everything cut remains
importable from the module that owns it. The distinction is between *this
will keep working* and *this exists*, which are different promises and were
previously the same one.
"""

from __future__ import annotations

from pathlib import Path

import voyd.engine as engine

# The promise. Grouped as in the source, so a diff shows what kind of thing
# somebody is adding -- a new reason and a new error are not the same event.
SURFACE = {
    "engine": {"Engine", "PermanentFailure", "now", "deadline", "live",
               "living", "aware", "UTC", "cosine"},
    "declaring": {"Admission", "AdmissionSpec", "Page", "why_refused",
                  "Memory", "MemorySpec", "JobQueue", "SearchSpec",
                  "ExpirySpec"},
    "rules": {"Deadline", "Marked", "revoked", "quarantined", "Clearance",
              "Restricted", "EmbeddedWith", "Unrecoverable", "Budget",
              # The second set-relative reason. Public because declaring it
              # is the whole interface: `admitting(..., Distinct("hash"))`.
              "Distinct",
              "compile_policy"},
    "reasons": {"DEADLINE", "REVOKED", "UNREADABLE", "QUARANTINED",
                "WRONG_MODEL", "NOT_CLEARED", "OFF_SCOPE", "UNRECOVERABLE",
                "KEY_UNAVAILABLE", "LIFTED", "REACHABLE", "REFUSED",
                "UNKNOWN", "OVER_BUDGET", "UNCOSTED", "UNNAMED", "REDUNDANT"},
    "proof": {"Ledger", "LedgerSpec", "GENESIS", "canonical", "digest"},
    "context": {"ContextIndex", "ContextIndexSpec", "ContextUse",
                "DIRECT", "SOURCE"},
    "encryption": {"Keyring", "KeyringSpec", "Sealed", "Queryable",
                   "Ephemeral", "LocalFile", "Aws", "Azure", "Gcp", "Kmip"},
    "authority": {"Grants", "Anyone"},
    "perimeter": {"Perimeter", "PerimeterLog", "sink", "derived_index",
                  "SEALED", "OWNED", "DERIVED", "INTERNAL"},
    "errors": {"ScopeError", "ScopeRequired", "ScopeInvalid", "FilterInvalid",
               "CallerRequired", "Irreversible", "UnknownReason",
               "BlastRadius", "UnboundedForgetting", "DerivationBroken", "ContextIncomplete",
               "PolicyInvalid", "NotAuthorised", "AuthorityRequired"},
}

EXPECTED = {name for group in SURFACE.values() for name in group}


def test_the_surface_is_exactly_what_was_agreed():
    actual = set(engine.__all__)
    added, removed = actual - EXPECTED, EXPECTED - actual
    assert not added, (
        f"new public name(s) {sorted(added)}. If they should be public, add "
        f"them to SURFACE above -- that edit is the point of this test. If "
        f"they are a return type, an internal, or vocabulary for an "
        f"extension point, leave them importable from their own module and "
        f"out of __all__: 'this exists' and 'this will keep working' are "
        f"different promises")
    assert not removed, (
        f"public name(s) {sorted(removed)} disappeared. Removing one is a "
        f"breaking change and should be a decision, not a rename's shrapnel")


def test_every_promised_name_resolves():
    """``__all__`` lying is worse than ``__all__`` being long: it breaks
    ``import *`` and every tool that reads it."""
    missing = [n for n in engine.__all__ if not hasattr(engine, n)]
    assert not missing, f"__all__ names that do not exist: {missing}"


def test_nothing_is_promised_twice():
    assert len(engine.__all__) == len(set(engine.__all__))
    counts = {}
    for group, names in SURFACE.items():
        for n in names:
            counts.setdefault(n, []).append(group)
    twice = {n: g for n, g in counts.items() if len(g) > 1}
    assert not twice, f"named in two groups, so its role is unclear: {twice}"


def test_what_was_cut_is_still_reachable():
    """A deletion pass that broke imports would be a rename wearing a
    principle. These were demoted from *promised* to *present*."""
    from voyd.engine.authority import (DERIVE, QUARANTINE, RELEASE, REVOKE,
                                       SHRED, Authority, Recorded)
    from voyd.engine.capabilities import Capabilities, detect
    from voyd.engine.jobs import backoff
    from voyd.engine.model import Model
    from voyd.engine.perimeter import Acknowledgement, Sink
    from voyd.engine.policy import Denies
    from voyd.engine.trait import Trait

    for thing in (REVOKE, QUARANTINE, RELEASE, SHRED, DERIVE, Authority,
                  Recorded, Capabilities, detect, backoff, Model,
                  Acknowledgement, Sink, Denies, Trait):
        assert thing is not None


def test_the_extension_point_protocols_are_documentation_not_imports():
    """``Rule``, ``Trait``, ``Sink``, ``Authority`` and ``Custody`` are
    ``runtime_checkable`` protocols that nothing in this package ever
    ``isinstance``-checks, and whose own docstrings say *inherit nothing*.

    A user writing one of these writes a class with the right attributes
    and never imports the protocol. Keeping them in ``__all__`` advertised
    a base class that does not exist.
    """
    import inspect
    import pathlib

    from voyd.engine import authority, custody, perimeter, trait
    from voyd.engine import admission

    for module, name in ((trait, "Trait"), (perimeter, "Sink"),
                         (authority, "Authority"), (admission, "Rule"),
                         (custody, "Custody")):
        assert hasattr(module, name), f"{name} must stay importable"

    source = "\n".join(p.read_text() for p in
                       pathlib.Path("voyd").rglob("*.py"))
    for name in ("Trait", "Sink", "Authority", "Rule"):
        assert "isinstance(" + name not in source.replace(" ", ""), \
            f"{name} is isinstance-checked somewhere; reconsider demoting it"
    assert inspect.getdoc(trait.Trait)


ROOT = Path(__file__).resolve().parents[1]


def test_the_top_level_package_is_the_policy_file_and_nothing_else():
    """``import voyd`` is the front door, and the front door is now a
    *policy file* rather than a library.

    Every name here appears in a `voydfile.py`, which is the test for whether
    it belongs: `guard` and the eight field declarations are the vocabulary a
    team writes, and `Engine` is the escape hatch for the in-process form. If
    a name is added that nobody would put in a policy file, it belongs in
    `voyd.engine` with the rest of the advanced surface.

    The list grew by nine when the declarative layer landed, and that is the
    mechanism working rather than the surface drifting: adding a public name
    costs a line in this diff, which is how the last overgrowth was caught
    (`voyd.engine.__all__` had reached 100 names, 48 of them in no README,
    blog or example).
    """
    import voyd

    assert set(voyd.__all__) == {
        "Engine", "PermanentFailure",
        "guard", "deadline", "revocable", "holdable", "tenant",
        "restricted_to", "embedded_with", "budget", "distinct",
        "__version__",
    }

    policy_vocabulary = set(voyd.__all__) - {"Engine", "PermanentFailure",
                                             "__version__"}
    declared = (ROOT / "voydfile.py").read_text()
    unused = {n for n in policy_vocabulary if n not in declared}
    assert unused <= {"holdable", "restricted_to", "embedded_with",
                      "budget", "distinct"}, (
        f"{sorted(unused)} is exported but the example policy file does not "
        f"show it; a vocabulary word nobody has written down is a guess")
