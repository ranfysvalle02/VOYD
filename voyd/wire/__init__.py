"""The boundary itself: a MongoDB wire proxy that enforces a policy file.

This is the product. A client connects here instead of to the deployment,
speaks ordinary MongoDB, and cannot read a fact the policy says is
forgotten -- in any driver, in any language, with no import and no code.

    voyd-wire --config voydfile.py --target localhost:27017

    policy      every decision about a message: what a verb may mean,
                what a read may see, what is refused outright. One
                package, grouped by the kind of decision, so "can this be
                bypassed?" is one import list to read and one category at
                a time to check.
    codec       the wire as bytes: framing, OP_MSG, compression
    proxy       transport: accept, pump both directions, fork, drain
    upstream    where it forwards to, and how an election is followed
    identity    who the *server* says this connection authenticated as
    report      what was refused, counted across workers and said once
    cli         the flags, and what runs before the listener binds
    cascade     a revocation reaching what was derived from the fact
    seal        `--key-vault`: ciphertext at rest, a key per scope
    ensure      `--ensure`: build what the policy declares
    preflight   `--verify`: ask the cluster whether it matches the policy
    metrics     `--metrics`: Prometheus, over shared memory across workers
    bench       what the boundary costs, measured rather than asserted

The per-document check these all rest on lives in `voyd.engine.admission`
and is pure -- no database, no connection, no I/O. That is what makes it
movable to a wire at all.
"""

# Deliberately no imports. Importing `main` here would make the package
# load before `python -m voyd.wire.<submodule>` executed the module, which
# Python reports as a `RuntimeWarning` on stderr -- the first line of every
# container's log, read by somebody who is already worried. The console
# script points at `voyd.wire.cli:main`; `python -m voyd.wire` works
# through `__main__.py`.
