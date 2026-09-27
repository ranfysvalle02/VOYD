"""Ready-made pipeline vocabulary for a voydfile. Local, pure, no model.

    # voydfile.py
    from voyd import guard, deadline, tenant
    from voyd import contrib

    contrib.install()                          # every name below
    # or pick:
    from voyd.contrib import text, rank, context
    text.install("$redactPII", "$chunk")
    rank.install("$bm25", "$mmr")
    context.install()

    @guard("docs")
    class Docs:
        expire_at = deadline()
        tenant_id = tenant()

Three modules, each a set of ``@operator`` or ``@stage`` functions:

    voyd.contrib.text     operators  $redactPII $chunk $wordCount
                                     $tokenEstimate $truncate $highlight
                                     $normalizeWhitespace
    voyd.contrib.rank     stages     $bm25 $mmr $dedupe $freshness $rrf
    voyd.contrib.context  stages     $contextPack $cite $stats

``install`` registers through the public ``voyd.stage`` and
``voyd.operator``, so the load-time refusals apply unchanged: a name
declared twice (by two installs, or by an install and your own
``@stage``) fails the load. To use one under another name, register the
function yourself: ``stage("$myRank")(rank.NAMES["$bm25"][1])``.

Everything runs where every virtual step runs -- in the boundary, on
admitted documents only, with every rule asked again on what it returns.
Nothing here opens a socket, reads a file, calls a model or draws a random
number. The catalogue with a snippet for each is ``examples/operators/README.md``.
"""

from __future__ import annotations

from . import context, rank, text

MODULES = {"text": text, "rank": rank, "context": context}


def install(*names: str) -> list[str]:
    """Register every contrib name, or only those given, in this voydfile."""
    table = {n: m for m in MODULES.values() for n in m.NAMES}
    chosen = list(names) or list(table)
    unknown = [n for n in chosen if n not in table]
    if unknown:
        raise ValueError(f"voyd.contrib has no {unknown}; it has "
                         f"{sorted(table)}")
    done: list[str] = []
    for m in MODULES.values():
        mine = [n for n in chosen if n in m.NAMES]
        if mine:
            done += m.install(*mine)
    return done


__all__ = ["install", "text", "rank", "context", "MODULES"]
