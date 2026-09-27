"""Text on its way to a prompt, checked for instructions aimed at the model.

Pure: no database, no driver, no I/O. Two halves with different strengths,
and the difference is the whole of what this module has to say.

**Neutralisation of invisible characters is exact.** A zero-width space, a
bidi override or a Unicode tag character is a code point in a known range,
and whether a string contains one is a fact about its bytes rather than a
judgement about its meaning. They are removed from every declared field on
every document that leaves, and a model is then shown what a human reviewer
of the same text would see. ``INVISIBLE`` is the list; it is short and it is
the whole list.

**Signature detection is a tripwire, not a guarantee.** "Ignore previous
instructions" can be written in any language, paraphrased, spread across
two chunks, or encoded in a way no regular expression anticipates. What is
here catches the common, copy-pasted shapes -- the ones that arrive in bulk
from scraped pages and poisoned uploads -- and nothing else. A document that
*discusses* prompt injection and quotes one is matched exactly like a
document that carries one, because a pattern cannot tell quotation from
use. Both of those are properties of pattern matching, not defects in this
list, and they are stated here so nobody reads a green dashboard as
"injection-proof".

What a match does is declared, per field:

    ``refuse``      the document does not leave. Counted under
                    ``injection_signature``, like any other refusal.
    ``neutralise``  the matched span is replaced with a marker naming the
                    signature, so the chunk still reaches the prompt minus
                    the part that matched. If folding (NFKC, case) finds a
                    signature that cannot be located in the original text --
                    full-width letters, say -- there is no exact span to cut,
                    and the document is refused instead.

The invariant both modes hold, and the one the tests assert: **no text that
leaves matches a declared signature, after invisible characters are
removed and the text is folded.** That is exact about the list. It says
nothing about attacks the list does not describe.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping

from .reasons import INJECTION_SIGNATURE

# Code points that render as nothing, or that reorder what is rendered, and
# have no business steering a model a reader cannot see them steering.
#
#   U+00AD          soft hyphen
#   U+180E          Mongolian vowel separator
#   U+200B-U+200F   zero-width space / non-joiner / joiner, LRM, RLM
#   U+202A-U+202E   bidi embeddings and overrides
#   U+2060-U+2064   word joiner, invisible operators
#   U+2066-U+2069   bidi isolates
#   U+FEFF          zero-width no-break space (BOM)
#   U+E0000-E007F   the tag block: invisible ASCII, one-for-one
#
# The cost is real and named. ZWJ builds emoji sequences and ZWNJ shapes
# Persian and several Indic scripts; tag characters spell subdivision flags.
# Removing them changes how such text *renders* -- a family emoji becomes
# its members -- and never what the words say. That trade is the declared
# one: a field marked ``sanitized()`` is text for a model, not typography.
INVISIBLE = frozenset(
    [0x00AD, 0x180E, 0xFEFF]
    + list(range(0x200B, 0x2010))
    + list(range(0x202A, 0x202F))
    + list(range(0x2060, 0x2065))
    + list(range(0x2066, 0x206A))
    + list(range(0xE0000, 0xE0080)))

_STRIP = {cp: None for cp in INVISIBLE}


def strip_invisible(text: str) -> str:
    """``text`` without any code point in ``INVISIBLE``. Exact."""
    return text.translate(_STRIP)


def _fold(text: str) -> str:
    # What detection looks at: invisible characters gone, compatibility
    # forms collapsed (full-width letters, ligatures), case folded. Never
    # what is served -- NFKC changes text a reader would call different.
    return unicodedata.normalize("NFKC", strip_invisible(text)).casefold()


@dataclass(frozen=True)
class Signature:
    """One named shape of instruction-carrying text.

    ``name`` is what a match is counted under. ``replacement`` is what
    ``neutralise`` puts in its place; ``None`` means a marker naming the
    signature, so a reader of the served chunk can see something was cut.
    """

    name: str
    pattern: str
    replacement: str | None = None

    @property
    def regex(self) -> re.Pattern:
        return re.compile(self.pattern, re.IGNORECASE)

    def marker(self) -> str:
        return (self.replacement if self.replacement is not None
                else f"[voyd: removed {self.name}]")


# The built-in list. Short on purpose: every entry is a false-positive
# budget somebody else pays, and a list nobody can read is a list nobody
# can argue with. Each one is exercised by name in
# `tests/test_an_instruction_in_a_chunk_does_not_reach_the_prompt.py`.
SIGNATURES: tuple[Signature, ...] = (
    # "Ignore all previous instructions", "disregard the above rules".
    Signature("override_instructions",
              r"\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}?"
              r"\b(?:previous|prior|above|earlier|preceding|all|your)\b"
              r"[^.\n]{0,20}?\b(?:instructions?|prompts?|directions"
              r"|rules|guidelines)\b"),
    # "New system prompt:", "your real system prompt is".
    Signature("system_prompt_claim",
              r"\b(?:new|updated|real|actual|true)\s+system\s+prompt\b"),
    # Chat-template control tokens. Nothing legitimate in a stored chunk
    # needs to open a turn on the model's behalf.
    Signature("chat_template_token",
              r"<\|(?:im_start|im_end|system|user|assistant|endoftext)\|>"
              r"|\[/?INST\]|<</?SYS>>"),
    # Invisible once rendered as markdown, visible to a model reading the
    # raw text -- the same asymmetry as a zero-width character, one layer up.
    Signature("html_comment", r"(?s)<!--.*?-->"),
    # An image whose URL carries a query string. A model that renders it
    # sends the query to the host: the exfiltration shape, not every image.
    Signature("markdown_image_exfil",
              r"!\[(?P<alt>[^\]\n]{0,200})\]\(\s*<?(?:https?:)?//"
              r"[^)\s]*\?[^)\s]*\)",
              replacement=r"[image: \g<alt>]"),
)

ON_MATCH = ("refuse", "neutralise")


def _texts(value: Any) -> list[str] | None:
    """The strings a field holds, or ``None`` when it holds none.

    A string, or a list of strings. Anything else -- a number, a nested
    document, ciphertext -- is left alone and said to be left alone: this
    reads text, and a guess about where text hides inside a structure would
    be a claim the tests could not make.
    """
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)) and value and all(
            isinstance(v, str) for v in value):
        return list(value)
    return None


@dataclass(frozen=True)
class Sanitized:
    """A text field checked for instruction-shaped content on the way out.

    A rule, so the refusal half is counted, reported and planned like every
    other one. Also the one rule with a second member, ``neutralise``,
    which ``AdmissionCore._admit`` calls on documents the rules admitted --
    in the terminal pass only, so it sees whatever a transform returned.

    ``path`` rather than ``field`` on purpose. ``deciding_fields`` treats a
    rule's ``field`` as something the verdict is read from, and a query
    that projects this text away is not one this rule has anything to say
    about: the text does not leave.
    """

    path: str
    on_match: str = "refuse"
    signatures: tuple[Signature, ...] = SIGNATURES
    reason: str = INJECTION_SIGNATURE
    # Not a reason a fact is forgotten, so break-glass does not set it
    # aside: an audit read is still text somebody may paste into a prompt.
    bypassable: bool = False

    def _matches(self, text: str) -> bool:
        folded = _fold(text)
        return any(s.regex.search(folded) for s in self.signatures)

    def _cut(self, text: str) -> tuple[str, list[str]]:
        """Invisible characters out, then every locatable match replaced."""
        out = strip_invisible(text)
        hits = ["invisible"] if out != text else []
        if self.on_match != "neutralise":
            return out, hits
        for sig in self.signatures:
            out, n = sig.regex.subn(sig.marker(), out)
            if n:
                hits.append(sig.name)
        return out, hits

    def refuses(self, doc: Mapping, *, when: datetime | None = None) -> bool:
        texts = _texts(doc.get(self.path))
        if texts is None:
            return False
        if self.on_match == "refuse":
            return any(self._matches(t) for t in texts)
        # Neutralise mode refuses only what it cannot cut exactly: a
        # signature still present after every locatable span is replaced.
        return any(self._matches(self._cut(t)[0]) for t in texts)

    def clause(self) -> dict | None:
        # Not expressible, and that is the decision about derived reads.
        # A `distinct`, a `$group` or a `$project` returns this text without
        # the document it came from, so there is nothing to neutralise it
        # on and no query that asks "does this match a Python regex after
        # NFKC". `expressible_clauses` returning `None` refuses them.
        return None

    def neutralise(self, doc: Mapping) -> tuple[Any, list[str]]:
        """``(document, what_was_done)`` -- the same object when nothing was.

        Identity is the contract, as it is for ``_redact``: the proxy
        forwards a batch's original bytes only when every document comes
        back as the object it handed in.
        """
        value = doc.get(self.path)
        texts = _texts(value)
        if texts is None:
            return doc, []
        cut = [self._cut(t) for t in texts]
        hits = sorted({h for _, found in cut for h in found})
        if not hits:
            return doc, []
        cleaned = [c for c, _ in cut]
        return ({**doc, self.path: cleaned[0] if isinstance(value, str)
                 else cleaned}, hits)


def sanitizer(path: str, *, on_match: str = "refuse",
              patterns: tuple | list = (), without: tuple | list = (),
              where: str = "") -> Sanitized:
    """Build a ``Sanitized`` and refuse, at load, every way it can be wrong.

    ``patterns`` extends the built-in list with ``(name, regex)`` or
    ``(name, regex, replacement)``. ``without`` removes built-ins by name,
    for a corpus where one of them is ordinary -- ``html_comment`` in a
    collection of HTML, say.
    """
    if on_match not in ON_MATCH:
        raise ValueError(f"{where}sanitized(on_match={on_match!r}); "
                         f"expected one of {ON_MATCH}")
    known = {s.name for s in SIGNATURES}
    unknown = set(without) - known
    if unknown:
        raise ValueError(f"{where}sanitized(without=...) names "
                         f"{sorted(unknown)}, which are not built-in "
                         f"signatures: {sorted(known)}")
    sigs = [s for s in SIGNATURES if s.name not in set(without)]
    for entry in patterns:
        if (not isinstance(entry, (tuple, list)) or len(entry) not in (2, 3)
                or not all(isinstance(e, str) for e in entry)):
            raise ValueError(
                f"{where}sanitized(patterns=...) takes (name, regex) or "
                f"(name, regex, replacement); got {entry!r}. The name is "
                f"what a match is counted under, so it is not optional")
        sig = Signature(*entry)
        try:
            compiled = sig.regex
        except re.error as exc:
            raise ValueError(f"{where}signature {sig.name!r} is not a valid "
                             f"regular expression: {exc}") from exc
        if compiled.search("") is not None:
            raise ValueError(
                f"{where}signature {sig.name!r} matches the empty string, "
                f"so it matches every document -- refusing all of them, or "
                f"inserting a marker between every character")
        sigs.append(sig)
    names = [s.name for s in sigs]
    if len(set(names)) != len(names) or "invisible" in names:
        raise ValueError(f"{where}signature names must be unique and not "
                         f"'invisible'; got {names}")
    return Sanitized(path=path, on_match=on_match, signatures=tuple(sigs))
