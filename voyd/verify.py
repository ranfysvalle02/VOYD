"""`voyd-verify`: check a set of served documents against public keys.

    voyd-verify --keys attest.pub [--policy SHA256] < context.jsonl

One document per line, as MongoDB Extended JSON (``bson.json_util.dumps``,
canonical or relaxed -- the digest does not care which). Prints one line per
document and a line per read, and exits 0 only if every document verified
and no chain between them was broken; 1 otherwise; 2 for a usage error.

No proxy, no cluster, no private key. The whole of what it trusts is the
key file it was handed, which is the point: an auditor's copy of the public
keys is the only thing that has to be kept honest.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import attest


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="voyd-verify", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--keys", required=True, metavar="PEM",
                    help="public keys, one or more PEM blocks. Keep the "
                         "retiring key and its successor together while a "
                         "rotation is in progress")
    ap.add_argument("--policy", action="append", default=None,
                    metavar="SHA256",
                    help="the policy hash(es) the documents must have been "
                         "served under; repeatable. Without it any policy "
                         "passes and the hash is only reported")
    ap.add_argument("input", nargs="?", default="-",
                    help="JSON lines file, or - for stdin (default)")
    ap.add_argument("--json", action="store_true",
                    help="one JSON verdict per line instead of text")
    args = ap.parse_args(argv)

    from bson import json_util

    try:
        with open(args.keys, "rb") as handle:
            keys = attest.load_public_keys(handle.read())
        stream = sys.stdin if args.input == "-" else open(args.input)
        with stream:
            docs = [json_util.loads(line) for line in stream if line.strip()]
    except Exception as exc:                                  # noqa: BLE001
        print(f"voyd-verify: {exc}", file=sys.stderr)
        return 2

    report = attest.verify_all(docs, keys, policy=args.policy)
    for n, verdict in enumerate(report.verdicts, 1):
        if args.json:
            print(json.dumps({"line": n, "ok": verdict.ok,
                              "reason": verdict.reason,
                              "citation": verdict.citation,
                              "kid": verdict.kid,
                              "policy": verdict.policy,
                              "read": verdict.read, "pos": verdict.pos}))
        else:
            mark = "ok  " if verdict.ok else "FAIL"
            print(f"{mark} line {n}: {verdict.citation or '-'}  "
                  f"{verdict.reason}")
    if not args.json:
        for read, (count, whole) in sorted(report.reads.items()):
            print(f"read {read}: {count} document(s), "
                  f"{'contiguous from 0' if whole else 'a subset'}")
        for broken in report.broken_links:
            print(f"FAIL chain {broken}")
        good = sum(v.ok for v in report.verdicts)
        print(f"{good} of {len(report.verdicts)} verified"
              + ("" if report.ok else " -- NOT verified"))
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
