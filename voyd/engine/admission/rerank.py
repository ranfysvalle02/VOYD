"""Maximal marginal relevance, as a transform.

The first built-in reason to want page-shaping at all, and the one that
makes the invariant in ``transforms.py`` worth having: a reranker is
exactly the code that has always run *after* a retrieval boundary and
been able to undo it. Here it runs inside, and cannot.

**What MMR is for.** A vector index returns the most similar documents,
which on a real corpus means the most similar documents *to each other*.
Ten chunks of one contract outrank one chunk each from ten contracts,
and a prompt built from the first set knows one thing very well and
nothing else at all. MMR trades a little relevance for coverage: pick
greedily, and penalise each candidate by how much it duplicates what is
already picked.

    score(d) = lambda * relevance(d) - (1 - lambda) * max sim(d, picked)

**Where relevance comes from, and the honest limitation.** Textbook MMR
measures relevance as similarity to the *query vector*. A wire boundary
does not reliably have one: an aggregation carries its ``queryVector``,
an ordinary ``find`` has no query vector at all, and a client is free to
project the document vectors away. What every ranked page does have is
**arrival order**, which is the index's own relevance judgement already
made.

So relevance here is positional -- a linear ramp from 1.0 at the top of
the page to near 0 at the bottom -- and this is rank-based MMR rather
than the vector-query form. It is a real technique and it is not the
same technique, so it says so rather than claiming the stronger thing.
The consequence worth knowing: results are invariant to how the caller
phrased the query and sensitive to how deeply they over-fetched.

**Redundancy is measured against stored vectors**, which is the other
half and needs them present. A page with no usable vectors cannot be
diversified, and the honest response to that is to return the page
untouched rather than to invent an ordering -- see ``_vectors``.

Pure: no database, no clock, no I/O. NumPy accelerates it when present
and is not a dependency -- ``voyd[rerank]`` if you want it. Without it
the same arithmetic runs in Python, and above a measured ceiling the
transform declines rather than making a read slow; see
``_PURE_PYTHON_BUDGET``.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from typing import Any, Sequence

log = logging.getLogger("engine.admission")

# Roughly `page * page * dimensions` float multiplications, above which
# the pure-Python path stops being a reasonable thing to do on a read.
#
# Measured on one laptop, CPython 3.12, 1024-dimension vectors: a page of
# 10 takes ~3ms and a page of 50 takes ~72ms. The ceiling is set just
# above the second of those, so 50 documents is the largest page this
# will diversify without NumPy and the worst case stays under about a
# tenth of a second. With `voyd[rerank]` the same page is ~1ms and the
# ceiling never applies.
#
# A reranker is an optimisation, and an optimisation is not allowed to
# be the slow part. Over the line it declines and says so rather than
# quietly adding a second to every read.
_PURE_PYTHON_BUDGET = 2_600_000


def _as_vector(value: Any) -> list[float] | None:
    """A list of numbers, or ``None`` for anything that is not one.

    Deliberately tolerant about *container* -- a driver may hand back a
    list, a tuple, or a BSON binary vector that behaves like a sequence
    -- and deliberately strict about contents. A vector with a string in
    it is not a vector that should be silently treated as zeroes.
    """
    if value is None or isinstance(value, (str, bytes, dict)):
        return None
    try:
        out = [float(x) for x in value]
    except (TypeError, ValueError):
        return None
    return out or None


def cosine(a: Sequence[float], b: Sequence[float]) -> float:
    """Cosine similarity, or 0.0 when it is undefined.

    A zero vector has no direction, so its similarity to anything is not
    small -- it is undefined. Returning 0.0 makes it maximally
    non-redundant, which is the safe direction for a diversifier: an
    unmeasurable document competes on relevance alone rather than being
    suppressed by a number nobody computed.
    """
    if len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if not na or not nb:
        return 0.0
    return dot / (na * nb)


def _similarity_matrix(vectors: list[list[float]]):
    """All pairwise similarities, via NumPy when it is available.

    The quadratic part, and the only place the cost lives. NumPy is an
    optional accelerant rather than a dependency: this package's whole
    claim is that a policy file and a connection string are the
    integration, and adding a compiled dependency to the install for a
    page-shaping nicety would be a strange bargain.
    """
    try:
        import numpy as np
    except ImportError:
        return None
    matrix = np.asarray(vectors, dtype=float)
    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    # A zero row would divide by zero and poison the matrix with NaN,
    # which compares False against everything and silently disables the
    # penalty. Substituting 1.0 leaves that row's similarities at 0.0,
    # which is what `cosine` returns for the same case.
    norms[norms == 0] = 1.0
    unit = matrix / norms
    return unit @ unit.T


@dataclass(frozen=True)
class MMR:
    """Diversify a page. A transform, not a rule.

        # voydfile.py
        rerank("notes", diversity=0.3, vector="embedding")

    ``diversity`` is ``1 - lambda``: 0.0 keeps the index's order exactly,
    1.0 ignores relevance and picks the most mutually dissimilar set.
    Useful values are small -- 0.2 to 0.4 -- because the index's ordering
    is usually right and the problem is only its top-heavy redundancy.

    ``top`` truncates after reordering. Left ``None`` it reorders and
    keeps everything, which is the conservative default: a transform that
    silently shortened a page would be doing a rule's job badly, and a
    budget already exists for the case where the page has a size limit
    that must be *enforced* rather than preferred.
    """

    vector_field: str = "embedding"
    diversity: float = 0.3
    top: int | None = None
    name: str = "mmr"

    def __post_init__(self) -> None:
        if not 0.0 <= self.diversity <= 1.0:
            raise ValueError(
                f"rerank(diversity={self.diversity}) must be between 0 and 1: "
                f"0 keeps the index's order, 1 ignores relevance entirely")
        if self.top is not None and self.top < 1:
            raise ValueError(
                f"rerank(top={self.top}) must be at least 1. A page of zero "
                f"is a refusal, and refusing is a rule's job")

    def _vectors(self, docs: list[dict]) -> list[list[float]] | None:
        """The page's vectors, or ``None`` if the page has no usable ones.

        All or nothing, and that is the careful part. A page where half
        the documents carry vectors would rank the other half by
        relevance alone and interleave two incomparable scores -- an
        ordering that looks deliberate and means nothing. Returning
        ``None`` leaves the page exactly as the index ranked it, which is
        the honest answer to "this cannot be diversified".
        """
        got = [_as_vector(d.get(self.vector_field)) for d in docs]
        if any(v is None for v in got):
            return None
        widths = {len(v) for v in got if v is not None}
        if len(widths) != 1:
            # Two widths on one page is two embedding models, which is
            # `embedded_with`'s problem and a far bigger one than
            # ordering. Not this transform's to paper over.
            log.warning("mmr: %d vector widths on one page; not reranking",
                        len(widths))
            return None
        return [v for v in got if v is not None]

    def on_egress(self, docs: list[dict], *, request: dict) -> list[dict]:
        if len(docs) < 2:
            return docs
        vectors = self._vectors(docs)
        if vectors is None:
            return docs

        n = len(docs)
        width = len(vectors[0])
        sims = _similarity_matrix(vectors)
        if sims is None and n * n * width > _PURE_PYTHON_BUDGET:
            # No NumPy and a page big enough that the arithmetic would be
            # measured in seconds rather than milliseconds. A reranker
            # that silently adds two seconds to every read is worse than
            # one that does not run: this is an optimisation, and an
            # optimisation is not allowed to be the slow part.
            log.warning(
                "mmr: %d documents of %d dimensions needs numpy; leaving "
                "the page in the index's order. `pip install voyd[rerank]`",
                n, width)
            return docs

        # Positional relevance: the index already ranked this page, and
        # arrival order is that judgement. A linear ramp rather than a
        # reciprocal one, so the penalty stays comparable to a cosine
        # across the whole page instead of collapsing after the top few.
        relevance = [1.0 - (i / n) for i in range(n)]

        def similarity(i: int, j: int) -> float:
            if sims is None:
                return cosine(vectors[i], vectors[j])
            return float(sims[i][j])

        lam = 1.0 - self.diversity
        picked: list[int] = [0]                 # the index's own first choice
        remaining = list(range(1, n))
        # The running maximum similarity of each candidate to *anything*
        # already picked, updated as picks happen. Recomputing it inside
        # the inner loop is the obvious implementation and makes the
        # whole thing cubic -- measured at k=100 and 1024 dimensions, the
        # difference between milliseconds and minutes.
        redundancy = {i: similarity(i, 0) for i in remaining}
        while remaining:
            best, best_score = remaining[0], -float("inf")
            for i in remaining:
                score = lam * relevance[i] - self.diversity * redundancy[i]
                if score > best_score:
                    best, best_score = i, score
            picked.append(best)
            remaining.remove(best)
            for i in remaining:
                got = similarity(i, best)
                if got > redundancy[i]:
                    redundancy[i] = got

        out = [docs[i] for i in picked]
        return out[:self.top] if self.top else out
