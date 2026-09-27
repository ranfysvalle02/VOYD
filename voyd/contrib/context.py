"""Context stages: fit a budget, number the sources, describe the set.

    # voydfile.py
    from voyd.contrib import context
    context.install()                    # or context.install("$contextPack")

Then, at the end of a retrieval pipeline::

    {"$contextPack": {"budget": 1500, "field": "text"}},
    {"$cite": {"source": ["title", "url"]}},

and the client builds its prompt from what came back: the documents, in
order, each with a ``citation`` marker, their text already trimmed to fit.
The published ``$$context`` and ``$$citations`` values are readable by any
later step in the same pipeline; a client that wants them in its reply
puts them on a document, e.g. ``{"$addFields": {"ctx": "$$context"}}``.

Token counts are the ``len / 4`` estimate from ``voyd.contrib.text`` unless
a ``tokens`` field supplies your own count. Pure standard library.
"""

from __future__ import annotations

import json
from typing import Any

from ._common import (REQUIRED, estimate_tokens, get, installer, number,
                      options, path, target, words)
from .text import truncate


def _context_pack(args, docs, ctx):
    """`$contextPack` -- keep documents in order until a token budget.

        {"$contextPack": {"budget": 2000, "field": "text", "tokens": null,
                          "trim": true, "minTokens": 16, "skip": false,
                          "flag": "truncated", "publish": "context"}}

    Walks the documents in the order they arrive (rank first), keeping
    each whose ``field`` fits in what is left of ``budget``. The first one
    that does not fit is trimmed to the remainder (ellipsis included) if
    ``trim`` is on and at least ``minTokens`` remain; after that it stops,
    unless ``skip`` is true, in which case it goes on looking for later
    documents small enough to fit. Every kept document gets ``flag`` true
    or false. Publishes ``$$context.used``, ``.budget``, ``.kept``,
    ``.dropped`` and ``.truncated``.

    A document with nothing in ``field`` costs 0 and is kept. Trimming cuts
    at a character offset, so it can end mid-sentence; ``tokens`` given
    per document is trusted, and a trimmed document's cost is re-estimated.
    """
    a = options("$contextPack", args, {
        "budget": REQUIRED, "field": "text", "tokens": None, "trim": True,
        "minTokens": 16, "skip": False, "flag": "truncated",
        "publish": "context"})
    budget = int(number("$contextPack", "budget", a["budget"], low=1,
                        integer=True))
    field = target("$contextPack", "field", a["field"])
    tokens = path("$contextPack", "tokens", a["tokens"]) \
        if a["tokens"] is not None else None
    least = int(number("$contextPack", "minTokens", a["minTokens"], low=1,
                       integer=True))
    flag = target("$contextPack", "flag", a["flag"])
    used, trimmed, out = 0, 0, []
    for d in docs:
        text = get(d, field)
        given = get(d, tokens) if tokens else None
        cost = int(given) if isinstance(given, (int, float)) \
            and not isinstance(given, bool) else estimate_tokens(text)
        left = budget - used
        if cost <= left:
            d[flag] = False
            used += cost
            out.append(d)
            continue
        if a["trim"] and left >= least and text is not None:
            d[field] = truncate(text, left * 4)
            d[flag] = True
            used += estimate_tokens(d[field])
            trimmed += 1
            out.append(d)
            if not a["skip"]:
                break
            continue
        if not a["skip"]:
            break
    if a["publish"] is not None:
        ctx.publish(a["publish"], {"used": used, "budget": budget,
                                   "kept": len(out),
                                   "dropped": len(docs) - len(out),
                                   "truncated": trimmed})
    return out


def _key(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return "j:" + json.dumps(value, sort_keys=True, default=str)
    return f"{type(value).__name__}:{value}"


def _cite(args, docs, ctx):
    """`$cite` -- number the sources ``[1]``, ``[2]``... in order of arrival.

        {"$cite": {"key": "_id", "source": ["title", "url"],
                   "as": "citation", "sourceField": "source",
                   "publish": "citations"}}

    Documents sharing a ``key`` (by default ``_id``, so the chunks of one
    document after an ``$unwind``) share a number. Each document gets
    ``as`` (``"[n]"``), ``<as>Id`` (``n``) and ``sourceField``: the first
    non-empty of the ``source`` paths, else the key. Publishes
    ``$$citations`` as ``[{"id", "marker", "source"}, ...]``. Numbers are
    stable for the same input order; a different ranking renumbers them.
    """
    a = options("$cite", args, {"key": "_id", "source": ["title", "url"],
                                "as": "citation", "sourceField": "source",
                                "publish": "citations"})
    key = path("$cite", "key", a["key"])
    srcs = a["source"] if isinstance(a["source"], list) else [a["source"]]
    srcs = [path("$cite", "source", s) for s in srcs]
    out = target("$cite", "as", a["as"])
    sf = target("$cite", "sourceField", a["sourceField"])
    ids: dict[str, int] = {}
    table = []
    for d in docs:
        kv = get(d, key)
        k = _key(kv)
        if k not in ids:
            ids[k] = len(ids) + 1
            label = next((str(get(d, s)) for s in srcs
                          if get(d, s) not in (None, "")), str(kv))
            table.append({"id": ids[k], "marker": f"[{ids[k]}]",
                          "source": label})
        n = ids[k]
        d[out] = f"[{n}]"
        d[f"{out}Id"] = n
        d[sf] = table[n - 1]["source"]
    if a["publish"] is not None:
        ctx.publish(a["publish"], table)
    return docs


def summarize(texts: list[Any]) -> dict:
    """Counts over a list of texts: n, chars, words, tokens and word range."""
    counts = [len(words(t)) for t in texts]
    present = [t for t in texts if t not in (None, "")]
    n = len(texts)
    return {"n": n, "missing": n - len(present),
            "chars": sum(len(str(t)) for t in present),
            "words": sum(counts),
            "tokens": sum(estimate_tokens(t) for t in present),
            "meanWords": round(sum(counts) / n, 6) if n else 0.0,
            "minWords": min(counts) if counts else 0,
            "maxWords": max(counts) if counts else 0}


def _stats(args, docs, ctx):
    """`$stats` -- publish counts over the admitted set, change nothing.

        {"$stats": {"field": "text", "publish": "stats"}}

    ``$$stats.n``, ``.missing``, ``.chars``, ``.words``, ``.tokens``,
    ``.meanWords``, ``.minWords``, ``.maxWords``. Computed over the
    documents at this step, which are only ever admitted ones.
    """
    a = options("$stats", args, {"field": "text", "publish": "stats"})
    field = path("$stats", "field", a["field"])
    ctx.publish(a["publish"], summarize([get(d, field) for d in docs]))
    return docs


NAMES = {
    "$contextPack": ("stage", _context_pack),
    "$cite": ("stage", _cite),
    "$stats": ("stage", _stats),
}

install = installer("context", NAMES)
