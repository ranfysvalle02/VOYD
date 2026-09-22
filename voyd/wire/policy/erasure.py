"""The three decisions that open a connection of their own.

Everything else in this package is `bytes -> bytes` and touches no socket.
These do work the caller did not issue, on the proxy's own connection, and
they are gathered here so that exception is one file rather than a
footnote in three.

Two orderings, and both are the whole point:

`erase_first` -- a client destroying a key has its documents revoked
*first*. A shred on its own leaves the key cache as a second window, so
the order is unreachable-then-unreadable, never the reverse.

`cascade_first` -- children are marked before the source is. A crash the
other way round leaves a summary of an erased fact still answering
prompts, which is the failure that makes lineage worth having at all.
"""

from __future__ import annotations

from typing import Mapping

from .. import metrics, seal
from ..codec import decode_op_msg, decode_sections
from .guarding import Guard
from .verbs import _forget_pipeline


async def erase_first(body: Mapping, statements: list,
                      guards: dict[str, Guard],
                      vault: "seal.Vault | None", verbose: bool,
                      meter: "metrics.Meter | None" = None) -> None:
    """If this client is destroying a key, revoke its documents first.

    Sequenced here, on the request, rather than left to the operator to
    remember as two commands in the right order. Getting it backwards is
    not a style question: a key destroyed before the documents are marked
    leaves them readable for as long as a decrypting process keeps the key
    cached, which is about a minute -- the same window, in the same shape,
    as the TTL monitor this repository opens by complaining about.
    """
    if vault is None:
        return
    scopes = vault.erasing(body, statements, body.get("$db", ""))
    if not scopes:
        return
    pipelines = {name: _forget_pipeline(g.spec, "key destroyed")
                 for name, g in guards.items()}
    marked = await vault.revoke_first(scopes, pipelines)
    for name, g in guards.items():
        if vault.seals(name):
            g.revoked += marked
    if meter is not None:
        # Counted as a pair on purpose. `erasures_total` climbing while
        # `erasure_revocations_total` stays flat is the ordering being lost,
        # which is the defect this feature already shipped once -- and the
        # only way to see it from outside is that the two series diverge.
        meter.erasures_total += len(scopes)
        meter.erasure_revocations_total += marked
    if verbose:
        print(f"  voyd: erasure of {', '.join(scopes)}: revoked {marked} "
              f"document(s) first, so they are unreachable now rather than "
              f"when the key cache turns over; destroying the key next",
              flush=True)


async def cascade_first(raw: bytes, guard: Guard, database: str,
                        verbose: bool) -> list[list] | None:
    """Mark what was made out of these facts, *before* revoking the facts.

    Children first. A crash after this and before the forwarded revocation
    leaves the source still reachable and its derivations already gone --
    a half-erasure the caller fixes by re-running an idempotent delete. The
    other order leaves the source refused and the summary of it still
    answering prompts, with nothing anywhere saying so.

    Returns the ids each delete clause matched, so the revocation that
    follows is pinned to exactly the documents this cascaded from, or
    ``None`` when there is no lineage here and the bytes should be left
    alone.
    """
    downstream = guard.cascade
    if downstream is None or not guard.spec.lineage_field:
        return None
    decoded = decode_sections(raw)
    if decoded is None:
        return None
    _flags, body, ident, docs = decoded
    if body.get("delete") != guard.collection or ident != "deletes":
        return None
    pipeline = _forget_pipeline(guard.spec, "derived from a fact deleted "
                                            "via voyd-wire")
    if not pipeline:
        return None

    pins = []
    for clause in docs:
        query = clause.get("q", {})
        ids = await downstream.resolve(database, guard, query,
                                    one=clause.get("limit", 0) == 1)
        guard.cascaded += await downstream.mark_descendants(
            database, guard, ids, pipeline, query)
        pins.append(ids)
    return pins


async def cascade_first_for_one(raw: bytes, guard: Guard, database: str,
                                verbose: bool) -> list | None:
    """The same, for ``findOneAndDelete``.

    A separate wire command, and intercepting one and not the other is how
    this boundary already shipped the guarantee for `deleteOne` and
    silently not for `findOneAndDelete`. The lineage half is not going to
    repeat that on its first commit.
    """
    downstream = guard.cascade
    if downstream is None or not guard.spec.lineage_field:
        return None
    decoded = decode_op_msg(raw)
    if decoded is None:
        return None
    _flags, body = decoded
    if body.get("findAndModify") != guard.collection or not body.get("remove"):
        return None
    pipeline = _forget_pipeline(guard.spec, "derived from a fact deleted "
                                            "via voyd-wire")
    if not pipeline:
        return None
    query = body.get("query", {})
    # `findAndModify` with a `sort` means the caller cares which one, so the
    # resolution has to honour it or the cascade and the revocation pick
    # different documents -- the same defect `pins` exists to prevent.
    ids = await downstream.resolve(database, guard, query, one=True,
                                sort=body.get("sort"))
    guard.cascaded += await downstream.mark_descendants(
        database, guard, ids, pipeline, query)
    return ids
