"""``voyd-wire-health`` -- ask a running boundary whether it can serve.

Exists because a `python:slim` image has no `curl` and no `wget`, so a
`HEALTHCHECK` either ships a package manager's worth of extra surface or
inlines a `python -c` one-liner nobody can read. This is the third
option, and it is useful outside a container too: a systemd
`ExecStartPost`, a load balancer's script check, a shell.

It asks `/health`, which is deliberately *not* "is the port open". A
boundary whose deployment is unreachable accepts connections and fails
every read, so a TCP check marks it ready and a rollout sends it traffic.
See `metrics.py`.

    voyd-wire-health                    # http://127.0.0.1:27100/health
    voyd-wire-health --port 9100
    voyd-wire-health --url http://10.0.0.7:27100/health

Exit 0 when it can serve, 1 when it cannot. Nothing on stdout unless
something is wrong, because a health check that prints on success is a log
that is all heartbeat.
"""

from __future__ import annotations

import argparse
import sys
import urllib.error
import urllib.request


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="voyd-wire-health", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=27100,
                    help="the --metrics port of the boundary to ask")
    ap.add_argument("--url", default=None,
                    help="the full URL, when it is not host:port/health")
    ap.add_argument("--timeout", type=float, default=3.0)
    args = ap.parse_args(argv)

    url = args.url or f"http://{args.host}:{args.port}/health"
    try:
        with urllib.request.urlopen(url, timeout=args.timeout) as reply:
            if reply.status == 200:
                return 0
            print(f"voyd-wire-health: {reply.status} {reply.read().decode().strip()}",
                  file=sys.stderr)
            return 1
    except urllib.error.HTTPError as exc:
        # The expected failure: 503 with a reason the boundary wrote.
        print(f"voyd-wire-health: {exc.code} "
              f"{exc.read().decode(errors='replace').strip()}", file=sys.stderr)
        return 1
    except Exception as exc:                                   # noqa: BLE001
        # Nothing listening, DNS, a timeout. Broad because every one of
        # them means the same thing to a prober -- and a health check that
        # raised would be reported as the checker crashing rather than as
        # the thing it was checking being down.
        print(f"voyd-wire-health: cannot reach {url} "
              f"({type(exc).__name__})", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
