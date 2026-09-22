"""Shaping the page, inside the boundary rather than beside it.

A rule answers *may this document reach a prompt?* about one document. A
transform answers a different question about the whole page -- *what
order, which of them, annotated how?* -- and the two have been separate
systems in every stack that has both: authorisation in a policy layer,
reranking and de-duplication in application code after retrieval.

Being separate is what makes the second one dangerous. A reranker that
runs after the boundary is outside it, and anything outside the boundary
can put back what the boundary removed -- not maliciously, usually; by
merging a cached list, by falling back to an unfiltered candidate pool
on an empty page, by reordering a list it was handed by reference.

So transforms run **inside**, and the placement is the whole design:

    pure rules  ->  transform  ->  every rule, terminally  ->  the wire

A transform never sees a forgotten fact, because the pure rules have
already taken them out. And a transform cannot emit one, because every
document it returns -- including ones it invents, merges in, or restores
-- goes through the authoritative check afterwards. Both halves are
needed and they guard different things: the first is defence in depth,
the second is the guarantee.

The consequence is worth saying plainly, because it is the reason this
is safe to offer at all:

    **A transform cannot widen what a read returns.** Not because it was
    reviewed. Because the boundary is downstream of it.

Which also means a transform is *not* an enforcement point, must never
be written as one, and gets no credit for filtering. A transform that
drops a document for a security reason is duplicating a rule badly; the
rule is the place, and `voyd-plan` can reason about a rule.

Cumulative rules are deliberately held back to the terminal pass. A
budget should charge for the page that is served, not the one that was
proposed and then reranked down -- the same argument ``why_refused``
already makes about asking ``charges`` rules last, one level up.
"""

from __future__ import annotations

import logging
from typing import Any, Protocol, runtime_checkable

log = logging.getLogger("engine.admission")


@runtime_checkable
class Transform(Protocol):
    """Shape the page. Two members, the same way a rule has three.

    ``name``      what it is called in a report and in a log line. A
                  transform that raises is named, so the name is not
                  decoration.
    ``on_egress`` the documents, in order, returning the documents it
                  wants served, in the order it wants them served.

    ``request`` carries what the transform needs to know about the read
    -- currently whether it was a vector search, and the caller's claims
    -- and is a plain mapping so that a stranger's transform is a
    first-class one, with no privileged path for anything shipped here.
    """

    name: str

    def on_egress(self, docs: list[dict], *,
                  request: dict) -> list[dict]:
        ...


def apply(transforms: tuple[Transform, ...], docs: list[dict], *,
          request: dict) -> list[dict]:
    """Run each transform in declared order. Never raises.

    A transform that throws is **skipped**, and its input is carried
    forward unchanged. That is the safe direction here and it is worth
    being explicit about why, because the equivalent decision for a
    *rule* goes the other way: a rule that raises is treated as a
    refusal, because a rule that fails open is a leak. A transform that
    fails does not open anything -- the terminal admission pass runs
    either way -- so the worst case of skipping it is an unranked page,
    and the worst case of refusing the whole read over a bad reranker is
    an outage caused by an optimisation.

    A transform that returns something that is not a list of dicts is
    treated the same way. The terminal pass would refuse the garbage
    anyway, document by document, and reporting "everything was
    forgotten" for what is really a broken transform is a diagnosis that
    sends somebody to the wrong file.
    """
    for one in transforms:
        before = docs
        try:
            got = one.on_egress(list(docs), request=dict(request))
        except Exception:                                      # noqa: BLE001
            log.exception("transform %r raised; skipping it",
                          getattr(one, "name", one))
            continue
        if not isinstance(got, list) or not all(
                isinstance(d, dict) for d in got):
            log.error("transform %r returned %s, not a list of documents; "
                      "skipping it", getattr(one, "name", one),
                      type(got).__name__)
            docs = before
            continue
        docs = got
    return docs


def request_for(*, caller: dict | None, collection: str,
                vector_search: bool = False,
                extra: dict | None = None) -> dict:
    """What a transform is told about the read it is shaping.

    Deliberately a plain dict rather than an object: it crosses into
    somebody else's code, and a transform holding a reference to an
    engine type would be a transform that can reach past the two members
    it declared.
    """
    about: dict[str, Any] = {"collection": collection,
                             "vector_search": vector_search,
                             "caller": dict(caller) if caller else None}
    if extra:
        about.update(extra)
    return about
