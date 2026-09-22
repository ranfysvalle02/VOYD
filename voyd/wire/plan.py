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
import os
import sys
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping

from voyd import __version__
from voyd.declare import load
from voyd.engine import attest
from voyd.engine.plan import Matrix, Plan, matrix, plan


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
        self._names: set[str] | None = None

    def _exists(self, collection: str) -> bool:
        """Is this collection on the cluster? Asked once, not per policy.

        A plan over twenty collections was issuing twenty `listCollections`
        commands to answer the same question, and the answer cannot change
        underneath one run without making the report incoherent anyway --
        a collection that appeared halfway through would be counted for
        some findings and not others.
        """
        if self._names is None:
            self._names = set(self.db.list_collection_names())
        return collection in self._names

    def __call__(self, collection: str) -> Iterable[Mapping]:
        if not self._exists(collection):
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


# Rendering lives in `plan_report`: those are pure functions of a
# `Plan`, and everything below is sockets, files and an exit code.
# Re-exported here because `voyd-plan` is the name people know.
from .plan_report import (as_json, matrix_as_json,  # noqa: E402
                          render, render_audit, render_matrix)


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


NO_POLICY = "none"


def _policy(path: str) -> dict:
    """A voydfile, or the literal ``none`` for *there is not one*.

    The pull request that adds the first ``voydfile.py`` has no policy in
    force, and the one that deletes the last has none proposed. Both are
    real changes to the boundary and both are the moments a plan is most
    worth having -- so "no policy" has to be sayable, and it cannot be an
    empty file: ``load`` refuses one of those on purpose, because a
    voydfile with no ``@guard`` in it would start a proxy that refuses
    nothing, silently.

    Symmetric on both flags. ``--proposed none`` is a policy being removed
    entirely, which is the loudest fail-open this tool can report, and a
    check that could not express it would go quiet exactly when it should
    not.
    """
    return {} if path == NO_POLICY else load(path)


def _callers(spec: str | None) -> dict[str, dict] | None:
    """A table of named callers, from JSON or a file.

    ``{"tier1-support": {"roles": ["support"]}, "analyst": {...}}``. The
    names are the deployment's, not this tool's, and they are what a role
    table is read by -- so they are preserved verbatim and never sorted
    into an order that implies a ladder.

    Distinct from ``--as`` rather than a generalisation of it, because
    the two answer different questions. ``--as`` asks *what does this
    change do to me*. This asks *whose access does it widen*, which is
    the question an access-control review is actually for, and which one
    caller can never answer.
    """
    if spec is None:
        return None
    text = spec
    if not spec.lstrip().startswith("{"):
        with open(spec) as handle:
            text = handle.read()
    table = json.loads(text)
    if not isinstance(table, dict) or not table:
        raise ValueError(
            "--as-each must be a non-empty JSON object mapping a caller "
            "name to its claims, e.g. "
            '{"tier1-support": {"roles": ["support"]}}')
    for name, claims in table.items():
        if not isinstance(claims, dict):
            raise ValueError(
                f"--as-each: claims for {name!r} must be an object, got "
                f"{type(claims).__name__}")
    return table


def _key(spec: str | None) -> bytes | None:
    """The signing key: an environment variable's name, or a file path.

    Never the key itself on a command line. A secret in `argv` is in the
    process table, in a shell history, and in the log of any CI system
    that echoes its own commands -- and a signing key that leaks makes
    every attestation it ever produced forgeable, retroactively.
    """
    if spec is None:
        return None
    if spec.startswith("env:"):
        name = spec.split(":", 1)[1]
        value = os.environ.get(name, "")
        if not value:
            raise ValueError(
                f"--sign env:{name} but {name} is unset or empty. An empty "
                f"key signs with a value anybody can guess, which looks "
                f"like a signature and is not one")
        return value.encode("utf-8")
    if spec.startswith("file:"):
        with open(spec.split(":", 1)[1], "rb") as handle:
            data = handle.read().strip()
        if not data:
            raise ValueError(f"--sign {spec}: the key file is empty")
        return data
    raise ValueError(
        f"--sign {spec!r}: expected `env:NAME` or `file:/path`. The key "
        f"itself is not accepted on a command line, because argv is not "
        f"a secret")


def build() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="voyd-plan",
        description="What a policy change would let through, before it ships.")
    # Not `required=True`: `--verify` is a different job that needs
    # neither, and argparse refusing to run it without two policy files
    # would be the parser asserting something untrue about the command.
    ap.add_argument("--audit", action="store_true",
                    help="what is reachable on this cluster *today* that "
                         "the proposed policy would refuse. Implies "
                         "`--current none`, needs no proxy and changes "
                         "nothing: a read-only URI and one command")
    ap.add_argument("--current",
                    help="the voydfile in force, or `none` when there is "
                         "not one yet")
    ap.add_argument("--proposed",
                    help="the voydfile being proposed, or `none` when the "
                         "change removes it")
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
    ap.add_argument("--as-each", metavar="CALLERS", dest="each",
                    help="plan once per named caller and report a role "
                         "table: JSON object of name -> claims, or a path")
    ap.add_argument("--attest", metavar="PATH",
                    help="write the plan as a verifiable envelope: the "
                         "result, the digest of each policy file, and when "
                         "it ran")
    ap.add_argument("--sign", metavar="KEY",
                    help="sign the attestation. `env:NAME` or `file:/path` "
                         "-- never the key itself, because argv is not a "
                         "secret")
    ap.add_argument("--verify", metavar="PATH",
                    help="check an attestation instead of planning. Exits 0 "
                         "if it is intact, 1 if it is not")
    ap.add_argument("--json", action="store_true",
                    help="machine-readable output")
    ap.add_argument("--report", metavar="PATH",
                    help="also write the human rendering here. A caller "
                         "that wants both forms gets them from one run, "
                         "which with --target is one pass over the data "
                         "rather than two")
    ap.add_argument("--version", action="version", version=__version__)
    return ap


def _verify(path: str, key_spec: str | None,
            policies: dict[str, str]) -> int:
    """Check an attestation. Says which of the two properties it has.

    The distinction is the reason this is not a boolean. A digest that
    checks out on an unsigned envelope rules out an accident and rules
    out nothing deliberate, and printing "verified" for both would be
    exactly the kind of claim exceeding its check that this repository
    exists to complain about.
    """
    with open(path) as handle:
        doc = json.load(handle)
    key = _key(key_spec)
    ok, why = attest.verify(doc, key)
    print(f"{'intact' if ok else 'FAILED'}: {why}")
    if ok and policies:
        fresh, note = attest.policies_match(doc, policies)
        print(f"{'current' if fresh else 'STALE'}: {note}")
        if not fresh:
            # An intact attestation of a policy that has since changed is
            # not corrupt, it is out of date -- a different finding, and
            # usually the more interesting one. It still fails, because
            # the thing somebody is about to rely on is not the thing
            # that was checked.
            return 1
    payload = doc.get("payload", {})
    verdict = payload.get("plan", {})
    print(f"attested {payload.get('at')}: fails_open="
          f"{verdict.get('fails_open')}, newly reachable="
          f"{verdict.get('newly_reachable_total')}")
    return 0 if ok else 1


def _read(path: str) -> str:
    """A policy file's contents, or the sentinel for there not being one."""
    if path == NO_POLICY:
        return NO_POLICY
    with open(path) as handle:
        return handle.read()


def main(argv: list[str] | None = None) -> int:
    args = build().parse_args(argv)

    if args.verify:
        # A different job. It needs no cluster, no policy files and no
        # plan -- and requiring them would make the one command an
        # auditor runs depend on the branch still existing.
        try:
            on_disk = {label: _read(path)
                       for label, path in (("current", args.current),
                                           ("proposed", args.proposed))
                       if path}
            return _verify(args.verify, args.sign, on_disk)
        except Exception as exc:                              # noqa: BLE001
            print(f"voyd-plan: {exc}", file=sys.stderr)
            return 2

    if args.audit:
        # An audit is a plan against nothing in force, which is the same
        # arithmetic read as a question about the present rather than
        # about a change. Setting it here rather than asking the operator
        # to spell `--current none` is the whole difference between a
        # report somebody runs and a flag combination somebody is told.
        if args.current and args.current != NO_POLICY:
            print("voyd-plan: --audit compares the cluster against no "
                  "policy at all, so --current cannot also be given",
                  file=sys.stderr)
            return 2
        args.current = NO_POLICY

    try:
        if not args.current or not args.proposed:
            raise ValueError(
                "--current and --proposed are both required to plan. Pass "
                "`none` for the side that does not exist yet")
        current = _policy(args.current)
        proposed = _policy(args.proposed)
        if not current and not proposed:
            raise ValueError(
                "--current and --proposed are both `none`. There is no "
                "change to plan, and reporting one would be a verdict about "
                "nothing")
        when = _when(args.at)
        caller = _caller(args.claims)
        each = _callers(args.each)
        if each and caller:
            raise ValueError(
                "--as and --as-each together. One plans against a caller "
                "and the other against a table of them; which number is "
                "the answer would be a guess")
        # Asked before the key is resolved, and the order is the whole
        # point: `--sign env:NOPE` with no `--attest` has two problems,
        # and the one to report is the one the operator made. Resolving
        # first sends them to fix an unset variable for a signature that
        # was never going to be written.
        if args.sign and not args.attest:
            raise ValueError(
                "--sign without --attest. There is nothing to sign: a "
                "signature over output that was printed and discarded is "
                "not evidence of anything")
        key = _key(args.sign)
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

    exhaustive = bool(args.target) and args.all
    try:
        result: Plan | Matrix
        if each:
            result = matrix(current, proposed, sample, each, when=when,
                            collections=args.collections,
                            exhaustive=exhaustive)
        else:
            result = plan(current, proposed, sample, when=when,
                          caller=caller, collections=args.collections,
                          exhaustive=exhaustive)
    except Exception as exc:                                  # noqa: BLE001
        print(f"voyd-plan: {exc}", file=sys.stderr)
        return 2
    if sampler is not None:
        missing = sampler.missing

    if isinstance(result, Matrix):
        text = render_matrix(result, missing=missing)
        blob = matrix_as_json(result, missing=missing)
    elif args.audit:
        text = render_audit(result, missing=missing)
        blob = as_json(result, missing=missing)
    else:
        text = render(result, missing=missing)
        blob = as_json(result, missing=missing)

    if args.report:
        try:
            with open(args.report, "w") as handle:
                handle.write(text + "\n")
        except OSError as exc:
            # The verdict is already computed and is the thing that
            # matters, so a report that could not be written is said and
            # stepped over rather than turned into exit 2 -- which would
            # be reporting "could not plan" about a plan that exists.
            print(f"voyd-plan: could not write {args.report}: {exc}",
                  file=sys.stderr)

    if args.attest:
        try:
            doc = attest.envelope(
                plan=blob,
                policies={"current": _read(args.current),
                          "proposed": _read(args.proposed)},
                tool=f"voyd-plan/{__version__}",
                context={"target": bool(args.target),
                         "exhaustive": exhaustive,
                         "sample": args.sample,
                         "callers": sorted(each) if each else None})
            if key:
                doc = attest.sign(doc, key)
            with open(args.attest, "w") as handle:
                json.dump(doc, handle, indent=2, sort_keys=True)
                handle.write("\n")
        except Exception as exc:                              # noqa: BLE001
            # Unlike the report, this one *is* fatal. An attestation is
            # the whole reason a compliance pipeline runs this command,
            # and a run that quietly produced no evidence while exiting 0
            # is a gap nobody notices until an auditor asks.
            print(f"voyd-plan: could not attest: {exc}", file=sys.stderr)
            return 2

    print(json.dumps(blob, indent=2) if args.json else text)
    return 1 if result.fails_open else 0


if __name__ == "__main__":
    raise SystemExit(main())
