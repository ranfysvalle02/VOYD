"""Turning a plan into something a person or a CI job reads.

Split from the command for the reason everything in this package is
split: these are pure functions of a ``Plan``, and the command is
sockets, files and an exit code. Keeping them together meant the
renderers could only be exercised by running the CLI, which is how a
report format acquires assertions about argv.

``render`` and ``as_json`` are deliberately not derived from each other.
A formatter that parsed its own text back would make the text a wire
format, and the text is meant to be improved.
"""

from __future__ import annotations

from voyd.engine.plan import (GUARD_ADDED, NEEDS_CALLER, Matrix,
                              Plan, SET_RELATIVE)


def _looked(result: Plan) -> str:
    """What the counts are counts *of*.

    One word, and it is the difference between an estimate and a claim. A
    report that said "sampled" under ``--all`` would understate itself; one
    that said "every document" under a sample would be the other thing.
    """
    return "read" if result.exhaustive else "sampled"


def render(result: Plan, *, missing: list[str] | None = None) -> str:
    """The plan as a person reads it, worst direction first.

    Ordering is an argument, not a layout. ``newly_reachable`` is printed
    before anything else and is printed even when it is the only non-empty
    section, because it is the finding; a report that listed changes in
    collection order would bury the one line somebody needed to see under
    forty lines of a rename.
    """
    out: list[str] = []
    say = out.append

    opens = [s for s in result.structural if s.fails_open]
    closes = [s for s in result.structural if not s.fails_open]

    if opens:
        say("the boundary moves, in the admitting direction")
        for s in opens:
            say(f"  {s.collection}  {s.kind}")
            say(f"    {s.detail}")
        say("")

    reachable = [c for c in result.collections if c.newly_reachable]
    if reachable:
        say("documents that become reachable")
        for c in reachable:
            say(f"  {c.collection}  +{c.newly_reachable_total} "
                f"of {c.sampled} {_looked(result)}")
            for reason, n in sorted(c.newly_reachable.items(),
                                    key=lambda kv: -kv[1]):
                say(f"    {n:>8}  were refused as {reason}")
        say("")

    refused = [c for c in result.collections if c.newly_refused]
    if refused:
        say("documents that stop being reachable")
        for c in refused:
            say(f"  {c.collection}  -{c.newly_refused_total} "
                f"of {c.sampled} {_looked(result)}")
            for reason, n in sorted(c.newly_refused.items(),
                                    key=lambda kv: -kv[1]):
                say(f"    {n:>8}  now refused as {reason}")
        say("")

    changed = [c for c in result.collections if c.reason_changed]
    if changed:
        say("documents refused for a different reason")
        for c in changed:
            for (before, after), n in sorted(c.reason_changed.items(),
                                             key=lambda kv: -kv[1]):
                say(f"  {c.collection}  {n:>8}  {before} -> {after}")
        say("")

    if closes:
        say("the boundary moves, in the refusing direction")
        for s in closes:
            say(f"  {s.collection}  {s.kind}: {s.detail}")
        say("")

    aside = result.set_aside
    if aside:
        say("not planned, and not because nothing changed")
        for why, note in ((SET_RELATIVE,
                           "refuses a document because of the other "
                           "documents on the page. A sample is not a page."),
                          (NEEDS_CALLER,
                           "decides by who is asking. Re-run with --as to "
                           "plan against a caller.")):
            these = sorted({f"{s.collection}.{s.rule}"
                            for s in aside if s.why == why})
            if these:
                say(f"  {why}: {', '.join(these)}")
                say(f"    {note}")
        say("")

    silent = [c.collection for c in result.collections if c.not_compared]
    if silent:
        say("compared nothing, because every rule was set aside")
        say(f"  {', '.join(sorted(silent))}")
        say("")

    if missing:
        say("declared by a policy, absent from this cluster")
        say(f"  {', '.join(sorted(missing))}")
        say("")

    if not result.changed:
        if not result.sampled and not result.exhaustive:
            # No cluster was read, so the honest claim is about the two
            # files and nothing else. "The same documents" would be a
            # sentence about documents this run never saw.
            say("no difference: the two policies declare the same boundary")
        else:
            say("no difference: the two policies admit and refuse the same "
                + ("documents in this collection" if result.exhaustive
                   else "documents in this sample"))
        say("")

    scope = (f"{result.sampled} documents, {_looked(result)}"
             if result.sampled or result.exhaustive
             else "the policy files only; no documents were read")
    if result.when is not None:
        scope += f", as of {result.when.isoformat()}"
    if result.caller is not None:
        scope += f", as a caller with {sorted(result.caller)}"
    say(scope)
    # The one sentence that must be true. A sample supports a statement
    # about the sample; the claim "nothing becomes reachable" is about the
    # collection, and only --all earns it.
    if result.fails_open or result.exhaustive:
        qualifier = ""
    elif not result.sampled:
        qualifier = "  (no documents were read; --target to count them)"
    else:
        qualifier = "  (in the sample; --all to say it about the collection)"
    say(f"newly reachable: {result.newly_reachable_total}{qualifier}")
    return "\n".join(out)


def render_matrix(result: Matrix, *, missing: list[str] | None = None) -> str:
    """The same change, seen from every role, worst role first.

    The structural findings are printed once. They are identical for
    every caller by construction, and a report that repeated
    `tenant_removed` per role would scale the loudest line in the file by
    the size of the role table until it read as boilerplate.
    """
    out: list[str] = []
    say = out.append

    opens = [s for s in result.structural if s.fails_open]
    closes = [s for s in result.structural if not s.fails_open]
    if opens:
        say("the boundary moves, in the admitting direction  "
            "(the same for every caller)")
        for s in opens:
            say(f"  {s.collection}  {s.kind}")
            say(f"    {s.detail}")
        say("")

    ranked = sorted(result.plans.items(),
                    key=lambda kv: (-kv[1].newly_reachable_total, kv[0]))
    width = max((len(name) for name in result.plans), default=4)
    say("per caller")
    say(f"  {'caller'.ljust(width)}   newly reachable   examined")
    for name, one in ranked:
        say(f"  {name.ljust(width)}   {one.newly_reachable_total:>15}"
            f"   {one.sampled:>8}")
    say("")

    for name, one in ranked:
        if not one.newly_reachable_total:
            continue
        say(f"what {name} gains")
        for coll in one.collections:
            if not coll.newly_reachable:
                continue
            for reason, n in sorted(coll.newly_reachable.items(),
                                    key=lambda kv: -kv[1]):
                say(f"  {coll.collection}  {n:>8}  were refused as {reason}")
        say("")

    if closes:
        say("the boundary moves, in the refusing direction")
        for s in closes:
            say(f"  {s.collection}  {s.kind}: {s.detail}")
        say("")

    aside = tuple({(a.collection, a.rule, a.why)
                   for one in result.plans.values() for a in one.set_aside})
    if aside:
        say("not planned, and not because nothing changed")
        for where, rule, why in sorted(aside):
            say(f"  {why}: {where}.{rule}")
        say("")

    if missing:
        say("declared by a policy, absent from this cluster")
        say(f"  {', '.join(sorted(missing))}")
        say("")

    worst = result.worst
    say(f"{len(result.plans)} callers, "
        + (f"{next(iter(result.plans.values())).sampled} documents each"
           if result.plans else "no callers"))
    # The worst role, not the sum: one document reachable by four callers
    # is one document that got out, not four.
    say("newly reachable: "
        + (f"{result.newly_reachable_total} (worst caller: {worst})"
           if worst else "0"))
    return "\n".join(out)


def matrix_as_json(result: Matrix, *,
                   missing: list[str] | None = None) -> dict:
    return {
        "fails_open": result.fails_open,
        "newly_reachable_total": result.newly_reachable_total,
        "worst_caller": result.worst,
        "when": result.when.isoformat() if result.when else None,
        "exhaustive": result.exhaustive,
        "structural": [{"collection": s.collection, "kind": s.kind,
                        "detail": s.detail, "fails_open": s.fails_open}
                       for s in result.structural],
        "callers": {name: as_json(one) for name, one in result.plans.items()},
        "missing_collections": sorted(missing or []),
    }


def as_json(result: Plan, *, missing: list[str] | None = None) -> dict:
    """The same plan, for something that is not a person.

    Kept beside ``render`` rather than derived from it: a formatter that
    parsed its own output back would make the text format a wire format,
    and the text format is meant to be improved.
    """
    return {
        "fails_open": result.fails_open,
        "newly_reachable_total": result.newly_reachable_total,
        "sampled": result.sampled,
        "exhaustive": result.exhaustive,
        "when": result.when.isoformat() if result.when else None,
        "caller": result.caller,
        "structural": [{"collection": s.collection, "kind": s.kind,
                        "detail": s.detail, "fails_open": s.fails_open}
                       for s in result.structural],
        "collections": [{
            "collection": c.collection,
            "sampled": c.sampled,
            "newly_reachable": c.newly_reachable,
            "newly_refused": c.newly_refused,
            "reason_changed": [{"before": b, "after": a, "count": n}
                               for (b, a), n in c.reason_changed.items()],
            "unchanged_admitted": c.unchanged_admitted,
            "unchanged_refused": c.unchanged_refused,
            "not_compared": c.not_compared,
        } for c in result.collections],
        "set_aside": [{"collection": s.collection, "rule": s.rule,
                       "why": s.why} for s in result.set_aside],
        "missing_collections": sorted(missing or []),
    }


def render_audit(result: Plan, *, missing: list[str] | None = None) -> str:
    """The same arithmetic, asked as a question about today.

    ``--audit`` is ``--current none``: compare *no policy at all* against
    the one being proposed, and every document the policy would refuse is
    a document reachable right now. The numbers are identical to a plan's
    and the sentences must not be, because the reader is different and so
    is the question.

    A plan is read by somebody deciding whether to merge a change, and
    its finding is a *delta* -- "these documents stop being reachable".
    An audit is read by somebody who has not installed anything, and the
    same count means "these documents are reachable today and should not
    be". Printing the first sentence to the second reader buries the
    finding under a tense nobody asked about.
    """
    out: list[str] = []
    say = out.append
    total = 0

    for c in result.collections:
        if not c.newly_refused:
            continue
        total += c.newly_refused_total
        say(f"  {c.collection}  {c.newly_refused_total} of {c.sampled} "
            f"{_looked(result)} are reachable now and would be refused")
        for reason, n in sorted(c.newly_refused.items(),
                                key=lambda kv: -kv[1]):
            say(f"    {n:>8}  {_AUDIT_REASONS.get(reason, reason)}")
        say("")
    if total:
        out.insert(0, "")
        out.insert(0, "reachable today, and refused by this policy")

    unguarded = [s.collection for s in result.structural
                 if s.kind == GUARD_ADDED]
    if unguarded:
        say("collections with no boundary in front of them today")
        say(f"  {', '.join(sorted(unguarded))}")
        say("")

    if missing:
        say("declared by the policy, absent from this cluster")
        say(f"  {', '.join(sorted(missing))}")
        say("")

    # An audit is read by somebody deciding whether this is worth
    # installing, so the honest scope of the number goes next to it
    # rather than in a footnote they will not reach.
    scope = ("every document" if result.exhaustive
             else f"a sample of {result.sampled}")
    say(f"{total} documents, out of {scope} looked at, are reachable "
        f"through this cluster's retrieval path")
    say("and would be refused by the policy in "
        + (", ".join(sorted({c.collection for c in result.collections
                             if c.newly_refused})) or "no collection"))
    if not result.exhaustive:
        say("")
        say("  --all reads every document, which is what it takes to say "
            "this about the collection rather than about the sample.")
    return "\n".join(out)


# An audit reader has not read this project's vocabulary, so the reason
# names are spelled out. The strings themselves stay stable elsewhere --
# this is a rendering, not a rename.
_AUDIT_REASONS = {
    "deadline": "are past an expire_at the TTL monitor has not reached",
    "revoked": "carry an erasure mark and are still being served",
    "quarantined": "are held back for review and are still being served",
    "wrong_model": "were embedded by a different model than declared",
    "unreadable": "have a deadline field nothing can parse",
    "not_cleared": "are above this caller's clearance",
    "unrecoverable": "are sealed with a key that no longer exists",
}
