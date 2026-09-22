"""The command line: what an operator types, and what it does before serving.

Separated from the transport because the two have different readers. A
person debugging a refusal reads the `policy` package; a person deploying
this reads
here -- what the flags are, what `--ensure` builds, where the key vault
comes from, and what the boundary refuses to start without.

The order in `main` is the argument. `--ensure` builds what the policy
declares, then `--verify` has a separately written checker refuse to agree
it is there; one of those alone is a boot step, and the pair is evidence.
Both finish before the listener binds, so a boundary that would enforce a
policy the cluster cannot satisfy says so on one screen rather than one
query at a time.

`voyd-wire` points here. `voyd.wire.proxy` is the transport underneath and
imports nothing from this file, which is what keeps "what does it do with
a message" answerable without reading an argument parser.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from typing import Mapping

from voyd import __version__
from voyd.declare import OPTIONS, load

from . import ensure
from . import preflight
from . import seal
from .policy import Guard
from .proxy import serve
from .upstream import vault_uri
from .report import summarise


def _custody(spec: str):
    """`local`, `local:/path`, or `env:PREFIX`. Never a guess.

    Built here, in the parent, *before* any fork -- so every worker
    inherits the same master key. An `Ephemeral` custody constructed per
    worker would mint a different key each, and a tenant written through
    one worker would be undecryptable through the next: a data-loss bug
    that only appears with `--workers 2` and looks like corruption.
    """
    from voyd.engine.custody import Ephemeral, LocalFile, from_env

    if spec == "local":
        return Ephemeral()
    if spec.startswith("local:"):
        return LocalFile(path=spec.split(":", 1)[1])
    if spec.startswith("env:"):
        return from_env(spec.split(":", 1)[1])
    raise ValueError(
        f"--kms {spec!r}: expected `local`, `local:/path/to/master.key`, or "
        f"`env:PREFIX`. Custody is the whole of the erasure claim, so this "
        f"refuses to guess at it")


def _vault_from(args) -> dict | int:
    """The vault configuration, or an exit code and a reason on stderr.

    Three ways to be wrong, and all three are startup errors rather than
    surprises later:

    - a policy declares `sealed()` and nobody passed `--key-vault`. The
      boundary would read ciphertext it could not decrypt and refuse every
      sealed document under `unrecoverable` -- fail-closed, but a
      deployment reporting a total erasure it never asked for.
    - `--key-vault` with no `sealed()` anywhere. Holding keys buys nothing
      and costs a credential, so it is a mistake worth naming.
    - a `--kms` this cannot parse.
    """
    declared = seal.sealed_from(OPTIONS)
    if declared and not args.key_vault:
        print("voyd-wire: this policy declares sealed() on "
              + ", ".join(sorted(declared))
              + " but no --key-vault was given. Without one this boundary "
                "holds no keys, so it cannot decrypt those fields and would "
                "refuse every document in them as unrecoverable -- a total "
                "erasure nobody asked for, reported as if it were working. "
                "Pass --key-vault DB, or drop sealed() from the policy",
              file=sys.stderr)
        return 2
    if args.key_vault and not declared:
        print("voyd-wire: --key-vault was given but no collection declares "
              "sealed(). Holding a master key buys nothing here and costs "
              "this process a credential it does not need", file=sys.stderr)
        return 2
    if not declared:
        return {}
    database, _, collection = args.key_vault.partition(".")
    try:
        custody = _custody(args.kms)
    except ValueError as exc:
        print(f"voyd-wire: {exc}", file=sys.stderr)
        return 2
    return {"uri": vault_uri(args.target), "database": database,
            "sealed": declared, "custody": custody,
            "collection": collection or "__keys"}


def _ensure(args, guards: dict[str, Guard]) -> int:
    """Build what the policy declares, before serving. 0 to continue.

    Deliberately in front of `_preflight` in `main`, so the ordinary first
    run is `--ensure app --verify app`: create it, then have a separately
    written checker refuse to agree it is there. One of those alone is a
    boot step; the pair is evidence.
    """
    try:
        lines = asyncio.run(ensure.provision(
            vault_uri(args.target), args.ensure, guards, OPTIONS,
            wait_s=args.ensure_wait))
    except Exception as exc:                                  # noqa: BLE001
        print(f"voyd-wire: --ensure could not build the policy's schema "
              f"({type(exc).__name__}: {exc}). Nothing was served, because "
              f"a boundary enforcing a policy whose indexes do not exist "
              f"refuses correctly and ranks badly, one query at a time",
              file=sys.stderr)
        return 4
    for line in lines:
        print(line, flush=True)
    print(flush=True)
    return 0


def _preflight(args, guards: dict[str, Guard]) -> int:
    """Ask before serving. Returns an exit code, 0 to continue.

    Synchronous and finished before `serve` binds anything, which is the
    whole point: the answer belongs in the same screen of output as the
    guarantees the boundary is about to start making, not in a metric
    somebody reads afterwards.
    """
    found, why = asyncio.run(preflight.inspect(
        vault_uri(args.target), args.verify,
        preflight.declarations(guards, OPTIONS)))
    for line in preflight.report(found, why):
        print(line, flush=True)
    if preflight.fatal(found) and not args.verify_only:
        print("voyd-wire: refusing to start. The boundary would enforce a "
              "policy this cluster cannot satisfy, and it would do it one "
              "query at a time -- which is a worse way to find out than "
              "this. Fix the line above, or drop --verify to start anyway",
              file=sys.stderr)
        return 3
    if preflight.fatal(found):
        return 3
    print(flush=True)
    return 0


def _embeds_from(options: Mapping) -> dict:
    """Collection -> the model the server embeds it with.

    Flattened from the policy file's `OPTIONS`, because the boundary's
    question is per collection: *does this collection's index hold text
    the server encoded?* Which field it is declared on matters to the
    index and not to the refusal -- a client vector is wrong for the
    collection however many paths it embeds.
    """
    out = {}
    for name, opt in options.items():
        declared = opt.get("auto_embed") or {}
        if declared:
            out[name] = next(iter(declared.values()))
    return out


def main(argv: list[str] | None = None) -> int:
    # `prog` pinned, because argparse defaults it to `sys.argv[0]` and the
    # help then names whatever file happened to be executed -- `__main__.py`
    # under `-m`, an absolute path under a systemd unit. An operator copying
    # a usage line out of `--help` should get the command they typed.
    ap = argparse.ArgumentParser(
        prog="voyd-wire", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--listen", type=int, default=27099, help="local port")
    ap.add_argument("--target", default="localhost:27017",
                    help="the database this fronts: `host:port`, or a full "
                         "MongoDB URI. A `mongodb+srv://` URI is resolved "
                         "through DNS and connected over TLS, which is what "
                         "Atlas requires")
    ap.add_argument("--config", metavar="VOYDFILE",
                    help="a policy file declaring the rules per collection "
                         "(see voyd.declare). This is the whole of what you "
                         "write, and it is not in your application")
    ap.add_argument("--guard", action="append", default=[], metavar="COLLECTION",
                    help="a collection whose reads are admitted; repeatable. "
                         "Collections not named here are forwarded untouched, "
                         "which is stated rather than implied: this refuses "
                         "what it was told to refuse")
    ap.add_argument("--at-field", default="expire_at")
    ap.add_argument("--mark-field", default="forgotten")
    ap.add_argument("--tls-cert", metavar="PEM",
                    help="terminate TLS from clients with this certificate. "
                         "Without it the listener binds loopback only, "
                         "because a plaintext boundary reachable from the "
                         "network would carry in the clear every document it "
                         "just refused to serve")
    ap.add_argument("--tls-key", metavar="PEM",
                    help="the private key for --tls-cert, if it is not in "
                         "the same file")
    ap.add_argument("--advertise", metavar="HOST:PORT", default=None,
                    help="rewrite `hello` so clients see this address "
                         "instead of the cluster's own hosts. Without it a "
                         "driver that does not pass directConnection=true "
                         "reads the real host list and connects past this "
                         "boundary entirely. Defaults to localhost:<listen> "
                         "when --advertise-self is given")
    ap.add_argument("--metrics-bind", metavar="ADDR", default="127.0.0.1",
                    help="where the metrics and /health server listens "
                         "(default 127.0.0.1). Set it to 0.0.0.0 or a pod "
                         "IP when the scrape comes from somewhere else -- "
                         "and know what you are exposing: a refusal count "
                         "broken down by reason describes what the corpus "
                         "contains and who has been probing it. /health "
                         "carries one bit and no numbers")
    ap.add_argument("--advertise-self", action="store_true",
                    help="shorthand for --advertise localhost:<listen>")
    ap.add_argument("--max-connections", type=int, default=200, metavar="N",
                    help="concurrent client connections; further ones are "
                         "closed rather than queued, because a driver "
                         "retries and an unbounded backlog turns a busy "
                         "minute into an outage")
    ap.add_argument("--drain", type=float, default=20.0, metavar="SECONDS",
                    help="on SIGTERM, how long to let requests already in "
                         "flight finish. Connections sitting idle between "
                         "requests are closed at once and do not wait this "
                         "out. 0 hangs up on everything immediately")
    ap.add_argument("--workers", type=int, default=1, metavar="N",
                    help="worker processes sharing the listening socket. "
                         "The event loop makes a connection cheap but "
                         "cannot spread BSON decoding across cores, so "
                         "this is the knob that does. Counters are summed "
                         "across workers and reported once on shutdown")
    ap.add_argument("--metrics", type=int, metavar="PORT", default=None,
                    help="serve Prometheus metrics on this port. Always "
                         "loopback, with no flag to change it: a refusal "
                         "count broken down by reason describes what a "
                         "corpus holds and who has been probing it")
    ap.add_argument("--key-vault", metavar="DB[.COLLECTION]", default=None,
                    help="hold the keys for the fields a policy file "
                         "declared sealed(), encrypting them on the way in "
                         "and decrypting them on the way out. This is the "
                         "one flag that costs this boundary its purity: it "
                         "opens a database connection of its own, holds KMS "
                         "credentials, and makes a sealed read cost a "
                         "decrypt rather than 2.3us. What it buys is the "
                         "erasure refusal cannot perform -- destroying a "
                         "key makes every copy of that tenant's ciphertext "
                         "unreadable, in every replica, snapshot and "
                         "backup, without visiting any of them")
    ap.add_argument("--kms", metavar="SPEC", default="local",
                    help="who holds the master key: `local` (ephemeral, "
                         "demo-grade, gone on restart), "
                         "`local:/path/to/master.key` (durable; custody is "
                         "a file permission), or `env:PREFIX` to read a "
                         "provider out of the environment the way "
                         "voyd.engine.custody.from_env does -- which is the "
                         "rung that gets you aws/azure/gcp/kmip, where "
                         "destroying the master key is somebody else's "
                         "audited operation")
    ap.add_argument("--ensure", metavar="DB", default=None,
                    help="before serving, create what the policy file "
                         "declares in this database: the collection, a TTL "
                         "index behind every deadline(), an index leading "
                         "with every tenant(), and a vector index the "
                         "server embeds for every auto_embed(). The one "
                         "mode that writes -- it uses your credentials and "
                         "closes its connection before the listener binds. "
                         "Idempotent, so it is safe on every boot. Pair it "
                         "with --verify, which is the same declaration read "
                         "by different code that creates nothing")
    ap.add_argument("--ensure-wait", metavar="SECONDS", type=float,
                    default=90.0,
                    help="how long --ensure waits for a search index to "
                         "become queryable. mongot builds asynchronously "
                         "and a query against a half-built index returns "
                         "no rows rather than an error, so the wait is the "
                         "difference between a clean first run and a "
                         "confusing one (default: 90)")
    ap.add_argument("--ensure-only", action="store_true",
                    help="run --ensure and exit without serving, for a "
                         "deploy step that is not the process that serves")
    ap.add_argument("--verify", metavar="DB", default=None,
                    help="before serving, ask the cluster whether it "
                         "matches the policy file: a TTL index behind every "
                         "deadline(), an index leading with every tenant(), "
                         "an autoEmbed field naming the model auto_embed() "
                         "declares, a binData validator behind every "
                         "sealed(). Read-only -- it issues listIndexes, "
                         "$listSearchIndexes and listCollections, creates "
                         "nothing, and closes its connection before the "
                         "listener accepts anything. A contradiction (the "
                         "index embeds with a different model than the "
                         "policy names) refuses to start; a missing layer "
                         "underneath refusal (no TTL index) is a warning. "
                         "Needs a database because a policy file names "
                         "collections and the *client* names the database, "
                         "so this process genuinely cannot know it")
    ap.add_argument("--verify-only", action="store_true",
                    help="run --verify and exit without binding a port. "
                         "The form a deploy gate wants: exit 0 if the "
                         "cluster matches the policy, 3 if it contradicts "
                         "it, and print the warnings either way")
    ap.add_argument("--version", action="version",
                    version=f"voyd-wire {__version__}",
                    help="the version of the boundary that is running, "
                         "which is the first thing anybody asks when it is "
                         "behaving unlike the last one")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    if not args.config and not args.guard:
        print("voyd-wire: give it --config voydfile.py, or --guard naming at "
              "least one collection. With neither, this process is a plain "
              "TCP relay pretending to be a boundary", file=sys.stderr)
        return 2

    guards: dict[str, Guard] = {}
    if args.config:
        try:
            for collection, spec in load(args.config).items():
                guards[collection] = Guard(
                    spec,
                    on_delete=OPTIONS.get(collection, {}).get(
                        "on_delete", "forward"))
        except Exception as exc:
            # A policy file that is wrong must fail here, loudly, rather than
            # at the first query. Starting a boundary from a broken
            # declaration is how you get a door that is ajar.
            print(f"voyd-wire: {args.config}: {exc}", file=sys.stderr)
            return 2
    for c in args.guard:
        guards.setdefault(c, Guard.defaults(
            c, at_field=args.at_field, mark_field=args.mark_field))
    try:
        if args.tls_key and not args.tls_cert:
            print("voyd-wire: --tls-key needs --tls-cert", file=sys.stderr)
            return 2
        advertise = args.advertise
        if args.advertise_self and not advertise:
            advertise = f"localhost:{args.listen}"
        vault_spec = _vault_from(args)
        if isinstance(vault_spec, int):
            return vault_spec
        if args.ensure_only and not args.ensure:
            print("voyd-wire: --ensure-only needs --ensure DB naming the "
                  "database to build", file=sys.stderr)
            return 2
        if args.ensure:
            code = _ensure(args, guards)
            if code:
                return code
            if args.ensure_only and not args.verify:
                return 0
        if args.verify_only and not args.verify:
            print("voyd-wire: --verify-only needs --verify DB naming the "
                  "database to check", file=sys.stderr)
            return 2
        if args.verify:
            code = _preflight(args, guards)
            if code or args.verify_only or args.ensure_only:
                return code
        if args.workers < 1:
            print("voyd-wire: --workers must be at least 1", file=sys.stderr)
            return 2
        if args.workers > 1 and not hasattr(os, "fork"):
            print("voyd-wire: --workers needs fork(); this platform has "
                  "none, so run one process per port behind a balancer",
                  file=sys.stderr)
            return 2
        serve(args.listen, args.target, guards, not args.quiet,
              certfile=args.tls_cert, keyfile=args.tls_key,
              max_connections=args.max_connections, advertise=advertise,
              drain_seconds=args.drain,
              workers=args.workers, metrics_port=args.metrics,
              metrics_bind=args.metrics_bind,
              vault_spec=vault_spec, auto_embed=_embeds_from(OPTIONS))
    except KeyboardInterrupt:
        summarise(guards)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
