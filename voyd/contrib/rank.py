"""Ranking stages: score, diversify, de-duplicate, decay, fuse.

    # voydfile.py
    from voyd.contrib import rank
    rank.install()                       # or rank.install("$bm25", "$mmr")

Then::

    {"$bm25":      {"query": "brake sensor fault", "field": "text",
                    "publish": "corpus"}},
    {"$dedupe":    {"field": "text", "threshold": 0.8}},
    {"$freshness": {"field": "published_at", "halfLife": "14d",
                    "multiply": "score"}},
    {"$mmr":       {"k": 5, "lambda": 0.7, "score": "score"}},

Each stage runs once over the documents the policy admitted, in the order
they arrive, and returns some of them with fields added -- never a document
it was not handed, which the boundary would drop anyway. Scores are
computed over the admitted set only: a BM25 idf here is the idf *of what
this caller may see*, not of the collection, and that is the point.

Field arguments are written ``"text"`` or ``"$text"``; dotted paths work.
The scoring functions are importable on their own: ``rank.bm25_scores``,
``rank.mmr_order``, ``rank.cosine``, ``rank.jaccard``, ``rank.minhash``.

Pure standard library, deterministic, no network, no model. Everything is
O(n) or O(n x kept) in the number of documents, bounded by the boundary's
``--virtual-max-docs``.
"""

from __future__ import annotations

import hashlib
import math
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Sequence

from ._common import (REQUIRED, get, installer, number, options, path,
                      target, words)

UTC = timezone.utc


# ---- similarity -------------------------------------------------------

def jaccard(a: Any, b: Any) -> float:
    """|a & b| / |a | b| of two sets; 0.0 when both are empty."""
    a, b = set(a), set(b)
    union = len(a | b)
    return len(a & b) / union if union else 0.0


def cosine(u: Sequence[float], v: Sequence[float]) -> float:
    """Cosine similarity of two equal-length vectors; 0.0 for a zero one."""
    if len(u) != len(v):
        raise ValueError(f"cosine of vectors of length {len(u)} and {len(v)}")
    dot = sum(x * y for x, y in zip(u, v))
    nu = math.sqrt(sum(x * x for x in u))
    nv = math.sqrt(sum(y * y for y in v))
    return dot / (nu * nv) if nu and nv else 0.0


def _vector(value: Any) -> list[float] | None:
    if isinstance(value, (list, tuple)) and value and all(
            isinstance(x, (int, float)) and not isinstance(x, bool)
            for x in value):
        return [float(x) for x in value]
    return None


# ---- $bm25 ------------------------------------------------------------

def bm25_scores(texts: Sequence[Any], query: Any, *, k1: float = 1.2,
                b: float = 0.75) -> tuple[list[float], dict]:
    """Okapi BM25 of ``query`` against each of ``texts``, and the stats.

    Returns ``(scores, {"n", "avgdl", "idf"})`` where ``idf`` covers the
    query's terms. ``idf = ln(1 + (n - df + 0.5) / (df + 0.5))``, the
    non-negative variant. Tokens are casefolded ``\\w+`` words: no stemming,
    no stop words, so ``fault`` and ``faults`` are different terms.
    """
    q = words(" ".join(query) if isinstance(query, list) else query)
    terms = list(dict.fromkeys(q))
    docs = [words(t) for t in texts]
    n = len(docs)
    avgdl = sum(map(len, docs)) / n if n else 0.0
    sets = [set(d) for d in docs]
    df = {t: sum(1 for d in sets if t in d) for t in terms}
    idf = {t: math.log(1 + (n - df[t] + 0.5) / (df[t] + 0.5)) for t in terms}
    scores = []
    for d in docs:
        tf: dict[str, int] = {}
        for w in d:
            if w in idf:
                tf[w] = tf.get(w, 0) + 1
        norm = (1 - b + b * len(d) / avgdl) if avgdl else 1.0
        s = sum(idf[t] * tf[t] * (k1 + 1) / (tf[t] + k1 * norm)
                for t in terms if t in tf)
        scores.append(round(s, 6))
    return scores, {"n": n, "avgdl": round(avgdl, 6),
                    "idf": {t: round(idf[t], 6) for t in terms}}


def _order(docs: list[dict], key: str, *, reverse: bool = True) -> list:
    """Stable sort by a numeric field, missing ones last, ties in order."""
    def k(pair):
        i, d = pair
        v = get(d, key)
        ok = isinstance(v, (int, float)) and not isinstance(v, bool)
        return (0 if ok else 1, (-v if reverse else v) if ok else 0, i)
    return [d for _, d in sorted(enumerate(docs), key=k)]


def _bm25(args, docs, ctx):
    """`$bm25` -- score ``query`` over ``field``, sort, optionally publish.

        {"$bm25": {"query": "brake fault", "field": "text", "as": "bm25",
                   "k1": 1.2, "b": 0.75, "sort": true, "publish": "corpus"}}

    Writes the score to ``as`` (default ``score``). With ``publish`` it
    makes ``$$<name>.n``, ``.avgdl`` and ``.idf.<term>`` available to later
    steps. The corpus is the admitted documents at this step, so a small
    admitted set gives noisy idf values.
    """
    a = options("$bm25", args, {"query": REQUIRED, "field": "text",
                                "as": "score", "k1": 1.2, "b": 0.75,
                                "sort": True, "publish": None})
    if not isinstance(a["query"], (str, list)):
        raise ValueError("$bm25: 'query' is a string or a list of strings")
    field = path("$bm25", "field", a["field"])
    out = target("$bm25", "as", a["as"])
    k1 = number("$bm25", "k1", a["k1"], low=0)
    b = number("$bm25", "b", a["b"], low=0, high=1)
    scores, stats = bm25_scores([get(d, field) for d in docs], a["query"],
                                k1=k1, b=b)
    for d, s in zip(docs, scores):
        d[out] = s
    if a["publish"] is not None:
        ctx.publish(a["publish"], stats)
    return _order(docs, out) if a["sort"] else docs


# ---- $mmr -------------------------------------------------------------

def mmr_order(relevance: Sequence[float], similarity, k: int,
              lam: float) -> list[int]:
    """Maximal marginal relevance: indices of ``k`` picks, in pick order.

    Each pick maximises ``lam * relevance[i] - (1 - lam) * max similarity
    to anything already picked``; ties go to the earlier index.
    ``similarity(i, j)`` is called lazily and cached.
    """
    n = len(relevance)
    chosen: list[int] = []
    best_sim = [0.0] * n
    left = list(range(n))
    while left and len(chosen) < k:
        pick = max(left, key=lambda i: (
            lam * relevance[i] - (1 - lam) * (best_sim[i] if chosen else 0),
            -i))
        chosen.append(pick)
        left.remove(pick)
        for i in left:
            best_sim[i] = max(best_sim[i], similarity(i, pick))
    return chosen


def _mmr(args, docs, ctx):
    """`$mmr` -- keep ``k`` documents that are relevant and unlike each other.

        {"$mmr": {"k": 5, "lambda": 0.7, "field": "text", "score": "bm25"}}
        {"$mmr": {"k": 5, "embedding": "vec", "queryVector": "$$qv"}}

    Relevance is, in order of preference: the numeric ``score`` field
    (min-max scaled to 0..1); cosine to ``queryVector`` over the
    ``embedding`` field; the share of ``query``'s words a document
    contains; or 1.0 for all, which makes it pure diversity. Similarity
    between two documents is cosine over ``embedding`` when both carry a
    numeric vector of the same length, otherwise Jaccard over the word
    sets of ``field``. ``lambda`` 1.0 is relevance only, 0.0 diversity only.
    Writes the 1-based pick order to ``as`` when given.

    Cosine is pure Python: fine for hundreds of documents with vectors of
    a few thousand dimensions, not a vector index.
    """
    a = options("$mmr", args, {"k": 5, "lambda": 0.7, "field": "text",
                               "embedding": None, "score": None,
                               "query": None, "queryVector": None,
                               "as": None})
    k = int(number("$mmr", "k", a["k"], low=1, integer=True))
    lam = number("$mmr", "lambda", a["lambda"], low=0, high=1)
    field = path("$mmr", "field", a["field"])
    emb = path("$mmr", "embedding", a["embedding"]) \
        if a["embedding"] is not None else None
    toks = [set(words(get(d, field))) for d in docs]
    vecs = [_vector(get(d, emb)) if emb else None for d in docs]

    if a["score"] is not None:
        key = path("$mmr", "score", a["score"])
        raw = [get(d, key) for d in docs]
        vals = [float(v) if isinstance(v, (int, float))
                and not isinstance(v, bool) else None for v in raw]
        have = [v for v in vals if v is not None]
        lo, hi = (min(have), max(have)) if have else (0.0, 0.0)
        rel = [0.0 if v is None else (1.0 if hi == lo else (v - lo) / (hi - lo))
               for v in vals]
    elif a["queryVector"] is not None:
        qv = _vector(a["queryVector"])
        if qv is None or emb is None:
            raise ValueError("$mmr: 'queryVector' needs a numeric list and "
                             "an 'embedding' field")
        rel = [cosine(qv, v) if v is not None and len(v) == len(qv) else 0.0
               for v in vecs]
    elif a["query"] is not None:
        q = set(words(" ".join(a["query"]) if isinstance(a["query"], list)
                      else a["query"]))
        rel = [len(q & t) / len(q) if q else 0.0 for t in toks]
    else:
        rel = [1.0] * len(docs)

    cache: dict[tuple[int, int], float] = {}

    def sim(i: int, j: int) -> float:
        pair = (min(i, j), max(i, j))
        if pair not in cache:
            u, v = vecs[i], vecs[j]
            cache[pair] = (cosine(u, v) if u is not None and v is not None
                           and len(u) == len(v) else jaccard(toks[i], toks[j]))
        return cache[pair]

    picks = mmr_order(rel, sim, k, lam)
    out = []
    for rank_, i in enumerate(picks, 1):
        if a["as"] is not None:
            docs[i][target("$mmr", "as", a["as"])] = rank_
        out.append(docs[i])
    return out


# ---- $dedupe ----------------------------------------------------------

_PRIME = (1 << 61) - 1


def shingles(text: Any, size: int = 3) -> set[tuple[str, ...]]:
    """The set of ``size``-word windows of ``text``; one window if shorter."""
    w = words(text)
    if len(w) <= size:
        return {tuple(w)} if w else set()
    return {tuple(w[i:i + size]) for i in range(len(w) - size + 1)}


def _h(shingle: tuple[str, ...]) -> int:
    return int.from_bytes(hashlib.sha256(
        "\x1f".join(shingle).encode()).digest()[:8], "big")


def minhash(sh: set, permutations: int = 64) -> tuple[int, ...]:
    """A MinHash signature: the same on every machine and every run.

    One SHA-256 per shingle, then ``permutations`` fixed affine maps
    modulo a Mersenne prime -- the coefficients come from a seeded
    sequence, not ``random``, so nothing varies with ``PYTHONHASHSEED``.
    """
    if not sh:
        return tuple([_PRIME] * permutations)
    hs = [_h(s) for s in sh]
    sig = []
    for p in range(permutations):
        seed = hashlib.sha256(f"voyd-minhash-{p}".encode()).digest()
        a = int.from_bytes(seed[:8], "big") % (_PRIME - 1) + 1
        b = int.from_bytes(seed[8:16], "big") % _PRIME
        sig.append(min((a * h + b) % _PRIME for h in hs))
    return tuple(sig)


def _dedupe(args, docs, ctx):
    """`$dedupe` -- drop exact and near duplicates, keeping the first seen.

        {"$dedupe": {"field": "text", "threshold": 0.85, "shingle": 3,
                     "method": "jaccard", "publish": "dedupe"}}

    Exact duplicates are the same casefolded word sequence (so spacing and
    case do not matter). Near duplicates have a shingle Jaccard of at least
    ``threshold`` with an earlier kept document: ``method: "jaccard"``
    computes it exactly, ``"minhash"`` estimates it from a
    ``permutations``-long signature (cheaper on long texts, and an
    estimate), ``"exact"`` skips near-duplicate detection. Put it *after*
    a ranking stage so the first seen is the best ranked. A document with
    no text in ``field`` is always kept. ``publish`` makes
    ``$$<name>.kept`` and ``.dropped`` available.
    """
    a = options("$dedupe", args, {"field": "text", "threshold": 0.9,
                                  "shingle": 3, "method": "jaccard",
                                  "permutations": 64, "publish": None})
    field = path("$dedupe", "field", a["field"])
    t = number("$dedupe", "threshold", a["threshold"], low=0, high=1)
    size = int(number("$dedupe", "shingle", a["shingle"], low=1,
                      integer=True))
    perms = int(number("$dedupe", "permutations", a["permutations"], low=1,
                       high=1024, integer=True))
    method = a["method"]
    if method not in ("jaccard", "minhash", "exact"):
        raise ValueError(f"$dedupe: 'method' is 'jaccard', 'minhash' or "
                         f"'exact', got {method!r}")
    seen: set[str] = set()
    kept_sh: list = []
    out = []
    for d in docs:
        w = words(get(d, field))
        if not w:
            out.append(d)
            continue
        digest = hashlib.sha256(" ".join(w).encode()).hexdigest()
        if digest in seen:
            continue
        if method != "exact":
            sh = shingles(" ".join(w), size)
            mine = minhash(sh, perms) if method == "minhash" else sh
            if any((sum(x == y for x, y in zip(mine, other)) / perms
                    if method == "minhash" else jaccard(mine, other)) >= t
                   for other in kept_sh):
                continue
            kept_sh.append(mine)
        seen.add(digest)
        out.append(d)
    if a["publish"] is not None:
        ctx.publish(a["publish"], {"kept": len(out),
                                   "dropped": len(docs) - len(out)})
    return out


# ---- $freshness -------------------------------------------------------

_UNITS = {"d": 86400.0, "h": 3600.0, "m": 60.0, "s": 1.0}


def half_life_seconds(value: Any) -> float:
    """``7`` (days), ``"14d"``, ``"12h"``, ``"30m"`` or ``"45s"``."""
    if isinstance(value, str) and value[-1:] in _UNITS:
        try:
            n = float(value[:-1])
        except ValueError:
            n = float("nan")
        seconds = n * _UNITS[value[-1]]
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        seconds = float(value) * 86400.0
    else:
        seconds = float("nan")
    if not (math.isfinite(seconds) and seconds > 0):
        raise ValueError(f"$freshness: 'halfLife' is a positive number of "
                         f"days or a string like '14d', '12h', '30m', got "
                         f"{value!r}")
    return seconds


def as_datetime(value: Any) -> datetime | None:
    """A datetime (naive is UTC), an ISO-8601 string, or epoch seconds."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str):
        try:
            got = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
        return got if got.tzinfo else got.replace(tzinfo=UTC)
    if isinstance(value, (int, float)) and not isinstance(value, bool) \
            and math.isfinite(value):
        return datetime(1970, 1, 1, tzinfo=UTC) + timedelta(seconds=value)
    return None


def decay(when: datetime, now: datetime, half_life_s: float) -> float:
    """``0.5 ** (age / half_life)``; a date in the future counts as now."""
    age = max((now - when).total_seconds(), 0.0)
    return 0.5 ** (age / half_life_s)


def _freshness(args, docs, ctx):
    """`$freshness` -- exponential decay by the age of a date field.

        {"$freshness": {"field": "published_at", "halfLife": "7d",
                        "as": "freshness", "multiply": "score"}}

    Writes ``0.5 ** (age / halfLife)`` to ``as``: 1.0 now, 0.5 one
    half-life ago. Age is measured from ``now`` if given, else from the
    read's one ``$$NOW``. With ``multiply``, that field is multiplied by
    the decay in place (missing counts as 0). A missing or unparseable
    date scores ``missing`` (default 0.0); a future date scores 1.0. It
    does not sort: follow it with ``{"$sort": {...}}`` or ``$mmr``.
    """
    a = options("$freshness", args, {"field": REQUIRED, "halfLife": REQUIRED,
                                     "as": "freshness", "multiply": None,
                                     "missing": 0.0, "now": None})
    field = path("$freshness", "field", a["field"])
    out = target("$freshness", "as", a["as"])
    hl = half_life_seconds(a["halfLife"])
    missing = number("$freshness", "missing", a["missing"], low=0, high=1)
    now = as_datetime(a["now"]) if a["now"] is not None else as_datetime(
        ctx.now)
    if now is None:
        raise ValueError(f"$freshness: 'now' is not a date: {a['now']!r}")
    mult = target("$freshness", "multiply", a["multiply"]) \
        if a["multiply"] is not None else None
    for d in docs:
        when = as_datetime(get(d, field))
        f = missing if when is None else round(decay(when, now, hl), 9)
        d[out] = f
        if mult is not None:
            v = get(d, mult)
            base = float(v) if isinstance(v, (int, float)) \
                and not isinstance(v, bool) else 0.0
            d[mult] = round(base * f, 9)
    return docs


# ---- $rrf -------------------------------------------------------------

def rrf_scores(columns: Mapping[str, Sequence[Any]], *, k: float = 60,
               weights: Mapping[str, float] | None = None,
               ascending: Sequence[str] = ()) -> list[float]:
    """Reciprocal rank fusion: ``sum(weight / (k + rank))`` per row.

    Each column is ranked on its own, highest first (lowest first for a
    name in ``ascending``), ties sharing the better rank. A non-numeric
    value contributes nothing for that column.
    """
    n = len(next(iter(columns.values()), []))
    total = [0.0] * n
    for name, col in columns.items():
        w = (weights or {}).get(name, 1.0)
        vals = [(i, float(v)) for i, v in enumerate(col)
                if isinstance(v, (int, float)) and not isinstance(v, bool)]
        vals.sort(key=lambda p: (p[1] if name in ascending else -p[1], p[0]))
        rank_, prev = 0, None
        for pos, (i, v) in enumerate(vals, 1):
            if v != prev:
                rank_, prev = pos, v
            total[i] += w / (k + rank_)
    return [round(t, 9) for t in total]


def _rrf(args, docs, ctx):
    """`$rrf` -- fuse several score or rank fields into one.

        {"$rrf": {"fields": ["bm25", "vectorScore"], "k": 60, "as": "rrf",
                  "weights": {"bm25": 1.0, "vectorScore": 2.0},
                  "ascending": [], "sort": true}}

    List a field in ``ascending`` when lower is better (a rank). Only the
    order within each field matters, so scores on different scales fuse
    without normalising. A document missing a field is simply unranked in
    it. Sorted by the fused score unless ``sort`` is false.
    """
    a = options("$rrf", args, {"fields": REQUIRED, "k": 60, "as": "rrf",
                               "weights": {}, "ascending": [], "sort": True})
    fields = a["fields"]
    if not isinstance(fields, list) or not fields:
        raise ValueError("$rrf: 'fields' is a non-empty list of field names")
    fields = [path("$rrf", "fields", f) for f in fields]
    if not isinstance(a["weights"], Mapping):
        raise ValueError("$rrf: 'weights' maps a field to a number")
    weights = {path("$rrf", "weights", f): number("$rrf", f"weights.{f}", w)
               for f, w in a["weights"].items()}
    if not isinstance(a["ascending"], list):
        raise ValueError("$rrf: 'ascending' is a list of field names")
    asc = [path("$rrf", "ascending", f) for f in a["ascending"]]
    k = number("$rrf", "k", a["k"], low=0)
    out = target("$rrf", "as", a["as"])
    scores = rrf_scores({f: [get(d, f) for d in docs] for f in fields},
                        k=k, weights=weights, ascending=asc)
    for d, s in zip(docs, scores):
        d[out] = s
    return _order(docs, out) if a["sort"] else docs


NAMES = {
    "$bm25": ("stage", _bm25),
    "$mmr": ("stage", _mmr),
    "$dedupe": ("stage", _dedupe),
    "$freshness": ("stage", _freshness),
    "$rrf": ("stage", _rrf),
}

install = installer("rank", NAMES)
