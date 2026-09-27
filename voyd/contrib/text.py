"""Text operators: redact, chunk, count, trim, mark up. Once per document.

    # voydfile.py
    from voyd.contrib import text
    text.install()                       # or text.install("$redactPII")

Then, in any driver's pipeline::

    {"$addFields": {"clean":  {"$redactPII": "$body"}}},
    {"$addFields": {"chunks": {"$chunk": {"input": "$clean",
                                          "by": "sentences", "size": 3}}}},
    {"$unwind": "$chunks"},
    {"$addFields": {"tokens": {"$tokenEstimate": "$chunks"}}},

Every operator takes either a bare value -- ``{"$wordCount": "$text"}`` --
or a document with ``input`` and options beside it. ``None`` in (a missing
field) is ``None`` out for the string-valued operators, ``0`` for the
counts and ``[]`` for ``$chunk``. The plain functions are importable too,
for a stage of your own or a test: ``text.redact_pii("mail a@b.co")``.

Pure standard library. Nothing here calls a model or leaves the process.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

from ._common import (REQUIRED, estimate_tokens, installer, number, operand,
                      words)

# ---- PII --------------------------------------------------------------

EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
CARD = re.compile(r"(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])")
SSN = re.compile(r"(?<![\d-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)"
                 r"\d{4}(?![\d-])")
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
IP = re.compile(
    rf"(?<![\d.]){_OCTET}(?:\.{_OCTET}){{3}}(?!\.?\d)"
    r"|(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}(?![\w:])"
    r"|(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){1,7}:"
    r"(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?(?![\w:])")
PHONE = re.compile(
    r"(?<![\w+])(?<!\d[ .-])(?:\+\d{1,3}[ .-]?)?"
    r"(?:\(\d{2,4}\)[ .-]?|\d{2,4}[ .-])"
    r"\d{3,4}[ .-]?\d{3,4}(?![\w-]|[ .]\d)"
    r"|(?<![\w+])\+\d{8,15}(?!\w)")

# Applied in this order, so a card or an SSN is never half-eaten as a phone.
KINDS = ("email", "card", "ssn", "ip", "phone")
_PATTERNS = {"email": EMAIL, "card": CARD, "ssn": SSN, "ip": IP,
             "phone": PHONE}


def luhn(digits: str) -> bool:
    """The Luhn checksum every payment card number satisfies."""
    ds = [int(c) for c in digits if c.isdigit()]
    if len(ds) < 2:
        return False
    total = 0
    for i, d in enumerate(reversed(ds)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def redact_pii(text: Any, kinds: Iterable[str] = KINDS,
               replacement: str = "[{kind}]") -> Any:
    """``text`` with emails, cards, SSNs, IPs and phone numbers replaced.

        {"$addFields": {"clean": {"$redactPII": {
            "input": "$body", "kinds": ["email", "card"],
            "replacement": "<{kind}>"}}}}

    ``replacement`` may use ``{kind}``. A digit run is a card only if it is
    13-19 digits and passes Luhn, so an order number is left alone.

    Limits, honestly: these are patterns, not a classifier. Phone numbers
    need a separator after the area code or a leading ``+`` (a bare
    ``5551234567`` is not caught); IPv6 is full or ``::``-compressed with
    at least one group before the ``::``; names, addresses and dates of
    birth are not detected at all. Redact at ingest too if it matters.
    """
    if text is None:
        return None
    chosen = list(kinds)
    unknown = sorted(set(chosen) - set(KINDS))
    if unknown:
        raise ValueError(f"$redactPII: unknown kind(s) {unknown}; it knows "
                         f"{list(KINDS)}")
    if not isinstance(replacement, str):
        raise ValueError("$redactPII: 'replacement' must be a string")
    out = str(text)
    for kind in KINDS:
        if kind not in chosen:
            continue
        mark = replacement.replace("{kind}", kind)
        if kind == "card":
            def card(m: re.Match, mark: str = mark) -> str:
                return mark if luhn(m.group()) else m.group()
            out = CARD.sub(card, out)
        else:
            out = _PATTERNS[kind].sub(mark, out)
    return out


# ---- chunk ------------------------------------------------------------

SENTENCE = re.compile(r"(?<=[.!?。！？])\s+")


def chunk(text: Any, by: str = "words", size: int = 200,
          overlap: int = 0) -> list[str]:
    """``text`` cut into pieces of ``size`` units, ``overlap`` shared.

        {"$addFields": {"chunks": {"$chunk": {"input": "$body",
                                              "by": "words", "size": 120,
                                              "overlap": 20}}}},
        {"$unwind": "$chunks"}

    ``by`` is ``"chars"``, ``"words"`` (whitespace-separated) or
    ``"sentences"`` (split after ``.``, ``!``, ``?`` and their CJK forms
    when whitespace follows). Word and sentence chunks are rejoined with a
    single space, so original line breaks are not kept. The last chunk may
    be short; no chunk is empty.
    """
    if by not in ("chars", "words", "sentences"):
        raise ValueError(f"$chunk: 'by' is 'chars', 'words' or 'sentences', "
                         f"got {by!r}")
    size = int(number("$chunk", "size", size, low=1, integer=True))
    overlap = int(number("$chunk", "overlap", overlap, low=0, integer=True))
    if overlap >= size:
        raise ValueError(f"$chunk: 'overlap' ({overlap}) must be smaller "
                         f"than 'size' ({size})")
    if text is None:
        return []
    s = str(text)
    if by == "chars":
        units: list[str] = list(s)
        glue = ""
    elif by == "words":
        units, glue = s.split(), " "
    else:
        units = [p.strip() for p in SENTENCE.split(s.strip()) if p.strip()]
        glue = " "
    out = []
    step = size - overlap
    for i in range(0, len(units), step):
        piece = glue.join(units[i:i + size])
        if piece.strip():
            out.append(piece)
        if i + size >= len(units):
            break
    return out


# ---- counts -----------------------------------------------------------

def word_count(text: Any) -> int:
    """How many ``\\w+`` words ``text`` has. Unicode-aware; 0 for None.

        {"$addFields": {"words": {"$wordCount": "$text"}}}

    Scripts written without spaces (Chinese, Japanese, Thai) count a run
    of characters as one word, so use ``$tokenEstimate`` for budgets.
    """
    return len(words(text))


def token_estimate(text: Any) -> int:
    """About ``len(text) / 4``, rounded up -- an estimate, not a tokenizer.

        {"$addFields": {"tokens": {"$tokenEstimate": "$chunk"}}}

    Close for English prose, low for code and CJK text. VOYD ships no
    tokenizer: that would be one model's vocabulary inside the boundary.
    """
    return estimate_tokens(text)


# ---- shape ------------------------------------------------------------

def truncate(text: Any, length: int, unit: str = "chars",
             ellipsis: str = "…") -> Any:
    """``text`` cut to ``length`` chars (ellipsis included) or words.

        {"$addFields": {"preview": {"$truncate": {"input": "$body",
                                                  "length": 280}}}}

    Unchanged when it already fits. Cuts by code point, so a combining
    mark or an emoji sequence at the cut may be split.
    """
    length = int(number("$truncate", "length", length, low=0, integer=True))
    if unit not in ("chars", "words"):
        raise ValueError(f"$truncate: 'unit' is 'chars' or 'words', got "
                         f"{unit!r}")
    if not isinstance(ellipsis, str):
        raise ValueError("$truncate: 'ellipsis' must be a string")
    if text is None:
        return None
    s = str(text)
    if unit == "words":
        toks = s.split()
        if len(toks) <= length:
            return s
        return " ".join(toks[:length]) + ellipsis
    if len(s) <= length:
        return s
    keep = max(length - len(ellipsis), 0)
    return (s[:keep].rstrip() + ellipsis)[:length] if length else ""


def highlight(text: Any, terms: Any, pre: str = "**",
              post: str = "**") -> Any:
    """``text`` with each whole-word, case-insensitive match of ``terms``
    wrapped in ``pre``/``post``.

        {"$addFields": {"snippet": {"$highlight": {
            "input": "$chunk", "terms": "$$query", "pre": "<b>",
            "post": "</b>"}}}}

    ``terms`` is a string (split into words) or a list of phrases. Longer
    phrases win over the words inside them. Markup is inserted as given --
    escape ``text`` yourself before rendering it as HTML.
    """
    if not isinstance(pre, str) or not isinstance(post, str):
        raise ValueError("$highlight: 'pre' and 'post' must be strings")
    if text is None:
        return None
    if terms is None:
        phrases: list[str] = []
    elif isinstance(terms, str):
        phrases = terms.split()
    elif isinstance(terms, list):
        phrases = [str(t).strip() for t in terms]
    else:
        raise ValueError(f"$highlight: 'terms' is a string or a list, got "
                         f"{type(terms).__name__}")
    phrases = sorted({p for p in phrases if p}, key=lambda p: (-len(p), p))
    if not phrases:
        return str(text)
    rx = re.compile(r"(?<!\w)(?:" + "|".join(map(re.escape, phrases))
                    + r")(?!\w)", re.IGNORECASE)
    return rx.sub(lambda m: pre + m.group() + post, str(text))


ZERO_WIDTH = re.compile("[​‌‍⁠﻿]")


def normalize_whitespace(text: Any) -> Any:
    """Every run of whitespace one space, zero-width characters gone,
    ends stripped.

        {"$addFields": {"text": {"$normalizeWhitespace": "$text"}}}
    """
    if text is None:
        return None
    return re.sub(r"\s+", " ", ZERO_WIDTH.sub("", str(text))).strip()


# ---- the operator adapters --------------------------------------------

def _redact_pii_op(doc, args, ctx):
    a = operand("$redactPII", args, {"kinds": list(KINDS),
                                     "replacement": "[{kind}]"})
    if not isinstance(a["kinds"], list):
        raise ValueError("$redactPII: 'kinds' must be a list")
    return redact_pii(a["input"], a["kinds"], a["replacement"])


def _chunk_op(doc, args, ctx):
    a = operand("$chunk", args, {"by": "words", "size": 200, "overlap": 0})
    return chunk(a["input"], a["by"], a["size"], a["overlap"])


def _word_count_op(doc, args, ctx):
    return word_count(operand("$wordCount", args, {})["input"])


def _token_estimate_op(doc, args, ctx):
    return token_estimate(operand("$tokenEstimate", args, {})["input"])


def _truncate_op(doc, args, ctx):
    a = operand("$truncate", args, {"length": REQUIRED, "unit": "chars",
                                    "ellipsis": "…"})
    return truncate(a["input"], a["length"], a["unit"], a["ellipsis"])


def _highlight_op(doc, args, ctx):
    a = operand("$highlight", args, {"terms": REQUIRED, "pre": "**",
                                     "post": "**"})
    return highlight(a["input"], a["terms"], a["pre"], a["post"])


def _normalize_whitespace_op(doc, args, ctx):
    return normalize_whitespace(
        operand("$normalizeWhitespace", args, {})["input"])


NAMES = {
    "$redactPII": ("operator", _redact_pii_op),
    "$chunk": ("operator", _chunk_op),
    "$wordCount": ("operator", _word_count_op),
    "$tokenEstimate": ("operator", _token_estimate_op),
    "$truncate": ("operator", _truncate_op),
    "$highlight": ("operator", _highlight_op),
    "$normalizeWhitespace": ("operator", _normalize_whitespace_op),
}

install = installer("text", NAMES)
