"""What every contrib module shares: argument checks, paths, tokens.

Pure: the standard library and nothing else. No database, no network, no
model, no randomness -- the same input gives the same output on every
machine and every run, including under a different ``PYTHONHASHSEED``,
because nothing here depends on the iteration order of a set.
"""

from __future__ import annotations

import math
import re
from typing import Any, Callable, Mapping

WORD = re.compile(r"\w+", re.UNICODE)


def words(text: Any) -> list[str]:
    """The word tokens of ``text``, casefolded. Unicode-aware, no stemming."""
    if text is None:
        return []
    return WORD.findall(str(text).casefold())


def estimate_tokens(text: Any) -> int:
    """About one token per four characters, rounded up. An estimate.

    Real tokenizers differ by model and by language -- CJK text and code
    run well above this, plain English slightly below -- and VOYD holds no
    tokenizer on purpose: it would be a model's vocabulary inside the
    boundary. Use it for budgets with headroom, not for exact limits.
    """
    if text is None:
        return 0
    s = str(text)
    return math.ceil(len(s) / 4) if s else 0


def options(name: str, args: Any, allowed: Mapping[str, Any]) -> dict:
    """``args`` as a dict with defaults filled, refusing unknown keys.

    ``allowed`` maps each key to its default; a default of ``REQUIRED``
    makes the key mandatory.
    """
    if args is None:
        args = {}
    if not isinstance(args, Mapping):
        raise ValueError(f"{name} takes a document of options, got "
                         f"{type(args).__name__}")
    unknown = sorted(set(args) - set(allowed))
    if unknown:
        raise ValueError(f"{name}: unknown option(s) {unknown}; it takes "
                         f"{sorted(allowed)}")
    out = {}
    for key, default in allowed.items():
        if key in args:
            out[key] = args[key]
        elif default is REQUIRED:
            raise ValueError(f"{name}: {key!r} is required")
        else:
            out[key] = default
    return out


class _Required:
    def __repr__(self) -> str:
        return "REQUIRED"


REQUIRED = _Required()


def operand(name: str, args: Any, allowed: Mapping[str, Any]) -> dict:
    """An operator's arguments: a bare value is ``{"input": value}``.

    So ``{"$wordCount": "$text"}`` and ``{"$wordCount": {"input": "$text"}}``
    mean the same thing, and options ride beside ``input`` in the second.
    """
    if not isinstance(args, Mapping):
        args = {"input": args}
    return options(name, args, {"input": REQUIRED, **allowed})


def path(name: str, key: str, value: Any) -> str:
    """A field path argument, written ``"text"`` or ``"$text"``."""
    if not isinstance(value, str) or not value.lstrip("$"):
        raise ValueError(f"{name}: {key!r} must name a field, e.g. "
                         f"'text', got {value!r}")
    if value.startswith("$$"):
        raise ValueError(f"{name}: {key!r} is {value!r}, a variable; it "
                         f"names a field")
    return value.lstrip("$")


def target(name: str, key: str, value: Any) -> str:
    """A field a stage writes: top level, never ``_id``."""
    got = path(name, key, value)
    if "." in got or got == "_id":
        raise ValueError(f"{name}: {key!r} is {value!r}; a stage writes a "
                         f"top-level field and never `_id`, which is what "
                         f"every output is traced back to its input by")
    return got


def get(doc: Any, dotted: str) -> Any:
    """The value at a dotted path, or ``None`` when any step is missing."""
    here = doc
    for part in dotted.split("."):
        if isinstance(here, Mapping) and part in here:
            here = here[part]
        else:
            return None
    return here


def number(name: str, key: str, value: Any, *, low: float | None = None,
           high: float | None = None, integer: bool = False) -> float:
    """A numeric argument inside ``[low, high]``, or a clear refusal."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) \
            or (isinstance(value, float) and not math.isfinite(value)):
        raise ValueError(f"{name}: {key!r} must be a number, got {value!r}")
    if integer and int(value) != value:
        raise ValueError(f"{name}: {key!r} must be a whole number, got "
                         f"{value!r}")
    if low is not None and value < low:
        raise ValueError(f"{name}: {key!r} must be at least {low}, got "
                         f"{value!r}")
    if high is not None and value > high:
        raise ValueError(f"{name}: {key!r} must be at most {high}, got "
                         f"{value!r}")
    return int(value) if integer else float(value)


def installer(module: str, table: Mapping[str, tuple[str, Callable]]
              ) -> Callable[..., list[str]]:
    """The ``install(*names)`` a contrib module exports.

    Registers through the public ``voyd.stage`` / ``voyd.operator``, so
    every load-time refusal applies: a name declared twice, a name the
    server already has. Call it from a voydfile; it registers for the load
    in progress and returns the names it registered.
    """
    def install(*names: str) -> list[str]:
        from voyd.declare import operator, stage

        chosen = list(names) or list(table)
        unknown = [n for n in chosen if n not in table]
        if unknown:
            raise ValueError(f"voyd.contrib.{module} has no {unknown}; it "
                             f"has {list(table)}")
        for n in chosen:
            kind, fn = table[n]
            (stage if kind == "stage" else operator)(n)(fn)
        return chosen
    install.__doc__ = (f"Register voyd.contrib.{module}'s names in this "
                       f"voydfile: all of {list(table)}, or the ones named.")
    return install
