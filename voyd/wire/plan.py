"""`voyd-plan`: what a policy change would let through, before it ships.

Everything that decides anything lives in ``voyd.engine.plan`` and is pure.
This file is the three things that are not: reading documents off a
cluster, turning a ``Plan`` into something a person or a CI job reads, and
an exit code.

The split is the same one the rest of the package makes, and here it buys
something concrete: the comparison can be tested against a list of dicts,
with no cluster, no network and no fixtures -- which is what makes it
reasonable to assert the interesting cases (a rule removed, a tenant
dropped, a set-relative rule set aside) rather than the one case a test
cluster makes convenient.

**What a plan reads.** A plan is a read-only operation and it reads
*around* the boundary on purpose. Sampling through the proxy would show
only what the current policy already admits, and the question is about the
documents it does not -- a plan that could not see a refused document could
not report that one is about to become reachable.

**The exit code is the product.** ``0`` when nothing becomes reachable,
``1`` when something does. That is a pull-request check: a policy change
that opens the boundary fails the build and prints which documents and why,
and a change that closes it does not, because a change that refuses more is
already visible to whoever it refuses.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping

from voyd import __version__
from voyd.declare import load
from voyd.engine.plan import (NEEDS_CALLER, Plan, SET_RELATIVE, plan)


UTC = timezone.utc


# ---- reading the documents ---------------------------------------------

class Sampler:
    """Documents off a real cluster, read around the boundary.

    ``$sample`` rather than ``find().limit()``, and the difference matters
    more here than it usually does. A limit returns whatever the storage
    engine reaches first, which on most collections is insertion order,
    which on a collection with a deadline is *the oldest documents* -- so a
    plan built on a limit would systematically over-report expiry and
    under-report everything else. It would be biased towards looking fine.

    ``--all`` exists for the case where an estimate is not good enough,
    which is any plan somebody is about to sign off on. It streams, so the
    cost is time rather than memory.
    """

    def __init__(self, db, size: int, *, everything: bool = False):
        self.db = db
        self.size = size
        self.everything = everything
        self.missing: list[str] = []

    def __call__(self, collection: str) -> Iterable[Mapping]:
        names = self.db.list_collection_names()
        if collection not in names:
            # Not an error. A policy is allowed to declare a collection the
            # cluster has not seen yet, and the structural findings for it
            # are still worth printing -- so this is recorded and rendered
            # rather than raised, and the per-document counts for it are
            # honestly zero.
            self.missing.append(collection)
            return iter(())
        coll = self.db[collection]
        if self.everything:
            return coll.find({})
        return coll.aggregate([{"$sample": {"size": self.size}}])


def _database(uri: str, name: str | None):
    import pymongo

    client: Any = pymongo.MongoClient(uri, serverSelectionTimeoutMS=8000,
                                      directConnection=True)
    if name:
        return client[name]
    default = client.get_default_database()
    if default is None:
        raise ValueError(
            "--target names no database and --database was not given. A plan "
            "has to know which database to sample; put one in the URI or "
            "pass --database")
    return default


# ---- saying it ----------------------------------------------------------

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
        say("no difference: the two policies admit and refuse the same "
            + ("documents in this collection" if result.exhaustive
               else "documents in this sample"))
        say("")

    scope = f"{result.sampled} documents, {_looked(result)}"
    if result.when is not None:
        scope += f", as of {result.when.isoformat()}"
    if result.caller is not None:
        scope += f", as a caller with {sorted(result.caller)}"
    say(scope)
    # The one sentence that must be true. A sample supports a statement
    # about the sample; the claim "nothing becomes reachable" is about the
    # collection, and only --all earns it.
    say("newly reachable: "
        f"{result.newly_reachable_total}"
        + ("" if result.fails_open or result.exhaustive
           else "  (in the sample; --all to say it about the collection)"))
    return "\n".join(out)


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


# ---- the command --------------------------------------------------------

def _when(spec: str | None) -> datetime | None:
    """The clock the plan runs against, and what it honestly is.

    ``--at`` moves the *clock*, not the data. A deadline and a hold are
    functions of time, so asking what a policy would have refused last
    Tuesday is a real question with a real answer -- but it is asked of the
    documents as they are **now**, not as they were then. This package does
    not keep history and will not pretend to: a document written since is
    included, and one whose mark was set yesterday is refused for the whole
    replay.
    """
    if spec is None:
        return None
    text = spec.strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _caller(spec: str | None) -> dict | None:
    """The claims to plan against, from JSON or a file.

    ``None`` -- the default -- is not "an anonymous caller", it is "do not
    plan the caller-dependent rules at all", and the two differ. Planning
    them against empty claims would report every restricted document as
    refused under both policies and print a confident zero, which is a
    stronger statement than this tool is in a position to make.
    """
    if spec is None:
        return None
    text = spec
    if not spec.lstrip().startswith("{"):
        with open(spec) as handle:
            text = handle.read()
    claims = json.loads(text)
    if not isinstance(claims, dict):
        raise ValueError(f"--as must be a JSON object of claims, got "
                         f"{type(claims).__name__}")
    return claims


def build(argv: list[str] | None = None) -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="voyd-plan",
        description="What a policy change would let through, before it ships.")
    ap.add_argument("--current", required=True,
                    help="the voydfile in force")
    ap.add_argument("--proposed", required=True,
                    help="the voydfile being proposed")
    ap.add_argument("--target",
                    help="a MongoDB URI to sample documents from. Without "
                         "it the plan reports structural findings only, "
                         "which needs no cluster and no credentials")
    ap.add_argument("--database",
                    help="the database to sample, if the URI names none")
    ap.add_argument("--sample", type=int, default=500,
                    help="documents per collection (default: 500)")
    ap.add_argument("--all", action="store_true",
                    help="every document, not a sample. Slower, and the "
                         "only way to earn a claim about the collection "
                         "rather than about the sample")
    ap.add_argument("--collection", action="append", dest="collections",
                    help="limit to this collection; repeatable")
    ap.add_argument("--at", metavar="WHEN",
                    help="run the clock at this instant (ISO 8601). Moves "
                         "the clock, not the data")
    ap.add_argument("--as", metavar="CLAIMS", dest="claims",
                    help="plan the caller-dependent rules against these "
                         "claims: inline JSON, or a path to a JSON file")
    ap.add_argument("--json", action="store_true",
                    help="machine-readable output")
    ap.add_argument("--version", action="version", version=__version__)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build().parse_args(argv)
    try:
        current = load(args.current)
        proposed = load(args.proposed)
        when = _when(args.at)
        caller = _caller(args.claims)
    except Exception as exc:                                  # noqa: BLE001
        print(f"voyd-plan: {exc}", file=sys.stderr)
        return 2

    missing: list[str] = []
    sample: Callable[[str], Iterable[Mapping]]
    if args.target:
        try:
            db = _database(args.target, args.database)
            sampler = Sampler(db, args.sample, everything=args.all)
        except Exception as exc:                              # noqa: BLE001
            print(f"voyd-plan: {exc}", file=sys.stderr)
            return 2
        sample = sampler
    else:
        # No cluster: the structural half is still the half that does not
        # depend on data, and it is the half that carries `guard_removed`.
        sampler = None
        def sample(_collection: str) -> Iterable[Mapping]:
            return iter(())

    try:
        result = plan(current, proposed, sample, when=when, caller=caller,
                      collections=args.collections,
                      exhaustive=bool(args.target) and args.all)
    except Exception as exc:                                  # noqa: BLE001
        print(f"voyd-plan: {exc}", file=sys.stderr)
        return 2
    if sampler is not None:
        missing = sampler.missing

    if args.json:
        print(json.dumps(as_json(result, missing=missing), indent=2))
    else:
        print(render(result, missing=missing))
    return 1 if result.fails_open else 0


if __name__ == "__main__":
    raise SystemExit(main())
