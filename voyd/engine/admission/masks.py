"""A document admitted with one of its fields taken out.

Every rule in this package answers *may this document reach a prompt?* A
mask answers a narrower question about a document that already may: *which
of its values may not?* A contract is readable and its counterparty's tax
id is not; a patient note is readable and the patient's national id is
not. Refusing the document would withhold everything to protect one value,
and admitting it whole is the leak.

So a mask rewrites the admitted document instead of refusing it, and the
place it runs is the design:

    pure rules  ->  transforms  ->  every rule, terminally, then masks

It runs inside ``_admit``, after the verdict, on *every* pass -- the pure
pre-pass a transform is shown and the terminal pass after it. A transform
therefore never sees the value, and a transform that puts it back (from a
cache, from a second read, by merging an unmasked copy) has it taken out
again on the terminal pass. The invariant ``transforms.py`` states --
*a transform cannot widen what a read returns* -- holds for fields the same
way it holds for documents, and for the same reason: there is nowhere after
the terminal pass to stand.

Two shapes, and the difference is whether the *key* survives:

    mask()             {"ssn": None}     the field is there and says nothing
    mask(strip=True)   {}                the field is not there at all

The first keeps a document's shape stable for code that indexes into it.
The second does not even say the field exists, which matters when its
presence is itself the fact (``diagnosis`` present at all).

A mask can name an audience that sees the value: ``visible_to=("hr",)``,
read from the caller's ``roles`` (or whichever claim ``via`` names). The
claim comes from the server, never from the client, and an unknown caller
sees the mask -- the same fail-closed direction every caller-aware rule
takes.

Top-level fields only. A dotted path would mean deciding what to do about
arrays of subdocuments, and a redaction whose depth nobody can state is
worse than one that says where it stops: mask the parent field instead.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .sides import sides


@dataclass(frozen=True)
class Mask:
    """One field, rewritten on the way out."""

    field: str
    strip: bool = False
    # Callers holding any of these values in ``via`` see the field. Empty
    # means nobody does -- the ordinary case, and the one that needs no
    # caller at all.
    visible_to: tuple[str, ...] = ()
    via: str = "roles"

    @property
    def needs_caller(self) -> bool:
        return bool(self.visible_to)

    def applies(self, caller: Mapping | None) -> bool:
        """Is the value hidden from this caller?"""
        if not self.visible_to:
            return True
        if not caller:
            return True                     # unknown is not entitled
        # Visible only if every side asked is in the audience: on a
        # delegated read, the principal and the actor both. See `sides.py`.
        return any(not self._sees(held) for held in sides(caller, self.via))

    def _sees(self, held: Any) -> bool:
        if isinstance(held, str):
            held = [held]
        if not isinstance(held, (list, tuple, set, frozenset)):
            return False
        return any(v in self.visible_to for v in held if isinstance(v, str))

    def describe(self) -> str:
        how = "strip" if self.strip else "null"
        who = (f", visible to {self.via} {list(self.visible_to)}"
               if self.visible_to else "")
        return f"{self.field} ({how}{who})"


def active(masks: Iterable[Mask], caller: Mapping | None) -> tuple[Mask, ...]:
    """The masks that hide something from this caller."""
    return tuple(m for m in masks if m.applies(caller))


def apply(doc: Mapping, masks: Iterable[Mask],
          caller: Mapping | None) -> tuple[Any, int]:
    """``(document, how many values were taken out)``.

    Returns the document it was handed when nothing changed, so the wire's
    identity check still forwards untouched bytes for a batch no mask
    touched. A new ``dict`` otherwise -- never a mutation, because the
    caller may be holding the one it passed in.

    Counted only when something changes: a field already ``None`` or
    already absent is not masked twice, so a document that passes through
    the pre-pass and the terminal pass is counted once, and one a transform
    restored is counted again because it was masked again.
    """
    out: dict | None = None
    n = 0
    for mask in masks:
        if not mask.applies(caller):
            continue
        source = out if out is not None else doc
        if mask.field not in source:
            continue
        if mask.strip:
            out = {k: v for k, v in source.items() if k != mask.field}
            n += 1
        elif source[mask.field] is not None:
            out = dict(source)
            out[mask.field] = None
            n += 1
    return (doc, 0) if out is None else (out, n)
