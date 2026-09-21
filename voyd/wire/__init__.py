"""The boundary itself: a MongoDB wire proxy that enforces a policy file.

This is the product. A client connects here instead of to the deployment,
speaks ordinary MongoDB, and cannot read a fact the policy says is
forgotten -- in any driver, in any language, with no import and no code.

    voyd-wire --config voydfile.py --target localhost:27017

    proxy       the boundary: framing, codec, dispatch, every enforcement
                decision. `main()` is the CLI.
    cascade     a revocation reaching what was derived from the fact
    seal        `--key-vault`: ciphertext at rest, a key per scope
    ensure      `--ensure`: build what the policy declares
    preflight   `--verify`: ask the cluster whether it matches the policy
    metrics     `--metrics`: Prometheus, over shared memory across workers
    fanout      `--fan-out`: rank on a secondary, confirm on the primary
    bench       what the boundary costs, measured rather than asserted

The per-document check these all rest on lives in `voyd.engine.admission`
and is pure -- no database, no connection, no I/O. That is what makes it
movable to a wire at all.
"""

from .proxy import main

__all__ = ["main"]
