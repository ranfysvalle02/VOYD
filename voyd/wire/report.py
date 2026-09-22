"""What this boundary actually did, counted and then said once.

A guarantee nobody counted is a claim about one, so the boundary reports
its own refusals -- and the counting is separated from the printing for a
reason that only shows up with `--workers`: the counters live in N address
spaces, and a summary printed per worker is not a summary, it is N partial
ones that each look like the whole. Undercounting a refusal tally is the
specific way this tool would lie about the thing it exists to prove.

    tally      one process's counters, as data
    merge      N of those, added up
    summarise  the one sentence a human reads
"""

from __future__ import annotations

from . import seal
from .policy import Guard


def tally(guards: dict[str, Guard],
          vault: "seal.Vault | None" = None) -> dict:
    """What one process actually did, as data rather than as a print.

    Separated from the printing because with `--workers` the counters live
    in N address spaces and the number a human should read is the sum. A
    summary printed per worker is not a summary, it is N partial ones that
    each look like the whole -- and undercounting a refusal tally is the
    specific way this tool would lie about the thing it exists to prove.
    """
    reasons: dict[str, int] = {}
    for g in guards.values():
        for reason, n in g.reasons().items():
            reasons[reason] = reasons.get(reason, 0) + n
    counts = {"served": sum(g.admitted for g in guards.values()),
              "refused": sum(g.refused for g in guards.values()),
              "revoked": sum(g.revoked for g in guards.values()),
              "cascaded": sum(g.cascaded for g in guards.values()),
              "reasons": reasons}
    if vault is not None:
        counts["sealed"] = vault.sealed_writes
        counts["unsealed"] = vault.unsealed_reads
        counts["erased"] = vault.erasures
    return counts


def merge(tallies: list[dict]) -> dict:
    """N workers' counts, added up."""
    # Counts and reasons kept apart while summing, then joined on the way
    # out. One dict holding both an `int` and a `dict[str, int]` is what
    # made the reason accumulator untypeable -- and it is also why
    # `total[key] += ...` and `total["reasons"][reason] = ...` read as the
    # same kind of operation when they are not.
    counts = {"served": 0, "refused": 0, "revoked": 0, "cascaded": 0}
    reasons: dict[str, int] = {}
    for one in tallies:
        for key in counts:
            counts[key] += one.get(key, 0)
        for reason, n in (one.get("reasons") or {}).items():
            reasons[reason] = reasons.get(reason, 0) + n
    return {**counts, "reasons": reasons}


def summarise(counts: dict | dict[str, Guard]) -> None:
    """What this boundary actually did. A guarantee nobody counted is a
    claim about one."""
    if counts and all(isinstance(v, Guard) for v in counts.values()):
        counts = tally(counts)
    served = counts.get("served", 0)
    refused = counts.get("refused", 0)
    revoked = counts.get("revoked", 0)
    reasons = counts.get("reasons") or {}
    print(f"voyd-wire: served {served}, refused {refused} {reasons or '{}'}, "
          f"turned {revoked} delete(s) into revocations", flush=True)
    cascaded = counts.get("cascaded", 0)
    if cascaded:
        # Said separately from `revoked` on purpose. "3 facts revoked" and
        # "3 facts revoked and 41 things made out of them went too" are
        # different sentences, and the second one is the only one that
        # answers an erasure request honestly.
        print(f"voyd-wire: the refusal travelled to {cascaded} document(s) "
              f"derived from those facts, marked before the source was",
              flush=True)
    sealed = counts.get("sealed")
    if sealed is not None:
        print(f"voyd-wire: sealed {sealed} document(s) on the way in, "
              f"unsealed {counts.get('unsealed', 0)} on the way out, "
              f"sequenced {counts.get('erased', 0)} erasure(s)", flush=True)
        # The old line said this unconditionally, and with `--key-vault` it
        # would have been a half-truth: the boundary still deletes no
        # documents, but it does forward a key's destruction, and a key is
        # the one thing here whose deletion is the point. Saying both is
        # cheaper than letting a reader reconcile them.
        print(f"voyd-wire: documents deleted by this process: 0 "
              f"(key deletions forwarded: {counts.get('erased', 0)} -- the "
              f"one deletion this tool argues for)", flush=True)
    else:
        print("voyd-wire: documents deleted by this process: 0", flush=True)
