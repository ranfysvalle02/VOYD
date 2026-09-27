# Operators and stages you can install today

`voyd.contrib` is a library of pipeline vocabulary mongod does not have,
written as ordinary `@operator` and `@stage` functions. A voydfile installs
it in one line; any driver then uses the names in an ordinary `aggregate`.

```python
# voydfile.py
from voyd import guard, deadline, tenant
from voyd import contrib

contrib.install()                     # everything below
# or: from voyd.contrib import text, rank, context
#     text.install("$redactPII"); rank.install("$bm25", "$mmr")

@guard("docs")
class Docs:
    expire_at = deadline()
    tenant_id = tenant()
```

[`voydfile.py`](voydfile.py) in this folder is a template to copy.

Everything here runs where every virtual step runs: in the boundary, on
the documents the policy **admitted** — refused rows are never handed
over, masked values are already null — and every rule is asked again on
what comes back. A stage can add fields, drop documents and reorder them;
it cannot introduce one. All of it is pure standard-library Python:
deterministic, no network, no model, no credentials. VOYD guarantees the
context the client receives; the client owns inference.

`install` goes through the public `voyd.stage` / `voyd.operator`, so a
name installed twice, or installed beside your own `@stage` of the same
name, fails the load before the proxy listens.

## Scripts

| script | what it shows |
|---|---|
| [`rag_context.py`](rag_context.py) | `$chunk` → `$unwind` → `$bm25` → `$dedupe` → `$mmr` → `$contextPack` → `$cite`, then the client builds a numbered prompt, offline |
| [`pii_safe_export.py`](pii_safe_export.py) | `$normalizeWhitespace`, `$redactPII`, `$truncate`, `$wordCount` on an export; Luhn-invalid order numbers survive, originals stay on disk |
| [`fresh_news.py`](fresh_news.py) | `$bm25` then `$freshness` multiplying the score, then a native `$sort` |

```
docker compose up -d mongo
uv run python examples/operators/rag_context.py
```

`VOYD_MONGO_URI` points them at another deployment, as for every example.

## Text operators — `voyd.contrib.text`

Once per admitted document, as the whole value of one field in
`$addFields` / `$set`. Each takes a bare value or `{"input": ..., options}`.
A missing field gives `None` (strings), `0` (counts) or `[]` (`$chunk`).

| name | does | snippet |
|---|---|---|
| `$redactPII` | replaces emails, payment cards (13–19 digits **and** Luhn), SSNs, IPv4/IPv6, phone numbers | `{"$addFields": {"clean": {"$redactPII": {"input": "$body", "kinds": ["email", "card"], "replacement": "[{kind}]"}}}}` |
| `$chunk` | splits into pieces by `chars`, `words` or `sentences`, with `overlap` | `{"$addFields": {"chunks": {"$chunk": {"input": "$body", "by": "words", "size": 120, "overlap": 20}}}}` |
| `$wordCount` | counts `\w+` words, unicode-aware | `{"$addFields": {"words": {"$wordCount": "$body"}}}` |
| `$tokenEstimate` | `ceil(len / 4)` — an estimate, not a tokenizer | `{"$addFields": {"tokens": {"$tokenEstimate": "$chunk"}}}` |
| `$truncate` | cuts to `length` chars (ellipsis included) or words | `{"$addFields": {"preview": {"$truncate": {"input": "$body", "length": 280}}}}` |
| `$highlight` | wraps whole-word, case-insensitive matches | `{"$addFields": {"snippet": {"$highlight": {"input": "$chunk", "terms": ["brake fault"], "pre": "<b>", "post": "</b>"}}}}` |
| `$normalizeWhitespace` | collapses whitespace, removes zero-width characters | `{"$addFields": {"body": {"$normalizeWhitespace": "$body"}}}` |

## Ranking stages — `voyd.contrib.rank`

Once over the admitted set. Field arguments are `"text"` or `"$text"`.

| name | does | snippet |
|---|---|---|
| `$bm25` | Okapi BM25 of a query over a field; sorts; `publish` makes `$$corpus.n`, `.avgdl`, `.idf.<term>` available | `{"$bm25": {"query": "brake fault", "field": "text", "as": "score", "publish": "corpus"}}` |
| `$mmr` | keeps `k` relevant, mutually different documents; cosine over `embedding` when present, Jaccard over words otherwise | `{"$mmr": {"k": 5, "lambda": 0.7, "score": "score"}}` |
| `$dedupe` | drops exact copies (same casefolded words) and near copies (shingle Jaccard ≥ `threshold`, exact or MinHash), keeping the first | `{"$dedupe": {"field": "text", "threshold": 0.85, "method": "jaccard"}}` |
| `$freshness` | `0.5 ** (age / halfLife)` from a date field and `$$NOW`; optionally multiplies a score | `{"$freshness": {"field": "published_at", "halfLife": "7d", "multiply": "score"}}` |
| `$rrf` | reciprocal rank fusion of several score or rank fields | `{"$rrf": {"fields": ["bm25", "vectorScore"], "k": 60, "weights": {"vectorScore": 2}}}` |

## Context stages — `voyd.contrib.context`

| name | does | snippet |
|---|---|---|
| `$contextPack` | keeps documents in order until a token budget, trimming the one that does not fit; publishes `$$context.used`, `.budget`, `.kept`, `.dropped`, `.truncated` | `{"$contextPack": {"budget": 2000, "field": "text"}}` |
| `$cite` | numbers sources `[1]`, `[2]`… by `key` (default `_id`), adds `citation`, `citationId`, `source`; publishes `$$citations` | `{"$cite": {"source": ["title", "url"]}}` |
| `$stats` | publishes `n`, `missing`, `chars`, `words`, `tokens`, `meanWords`, `minWords`, `maxWords`; changes nothing | `{"$stats": {"field": "text", "publish": "stats"}}` |

A published value is read by later steps as `$$name.field`; to return it
to the client, put it on a document with a native step:
`{"$addFields": {"budget": "$$context"}}`.

## Limits

- **Patterns, not classifiers.** `$redactPII` misses names, addresses and
  anything it has no pattern for; a phone number needs a separator after
  the area code or a leading `+`; IPv6 needs at least one group before a
  `::`. Redact at ingest as well if it matters.
- **Tokens are estimated.** `len / 4` runs low for code and CJK text. Pass
  your own counts with `$contextPack`'s `tokens` option when they matter.
- **No stemming, no stop words.** `$bm25` and the Jaccard similarities
  treat `fault` and `faults` as different words.
- **Statistics are over the admitted set at that step**, which is the
  point — nothing refused moves an idf — and also means a small admitted
  set gives noisy ones.
- **Pure Python, in memory.** Bounded by `--virtual-max-docs` (1000 by
  default). `$mmr` with embeddings and `$dedupe` with `method: "jaccard"`
  compare pairs; `"minhash"` is cheaper on long texts and is an estimate.
- **`$contextPack` trims by characters**, so a trimmed document can end
  mid-sentence.

Each function's docstring in `voyd/contrib/` carries its full argument list.
The tests are `tests/test_the_contrib_operators_do_what_they_say.py`.
