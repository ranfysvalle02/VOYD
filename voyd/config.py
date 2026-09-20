"""Configuration value objects for VOYD.

These are plain dataclasses returned by the public constructors
(``Store.Mongo``, ``Intelligence.Voyage``, ``Guard.*``).
They carry no behaviour beyond holding validated settings so the rest of the
engine can stay dependency-light and easy to test.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

GuardKind = Literal["require_passcode"]


@dataclass(frozen=True)
class MongoConfig:
    """Connection settings for the MongoDB operational layer."""

    uri: str
    db_name: str = "voyd"

    # Signs the refusal chain's head. Optional, and its absence is reported
    # rather than papered over: an unsigned chain is still tamper-evident,
    # because verifying it is arithmetic over public data and needs no key.
    # What a key adds is an attestation -- "this head was produced by
    # something holding the secret" -- so a missing one costs authentication,
    # not integrity. See ``engine/ledger.py``.
    ledger_key: str | None = None

    # There is deliberately no ``looks_like_atlas`` here. Guessing capability
    # from the URI is what made Atlas Local "not Atlas" for months, silently.
    # Capability is probed -- see ``voyd.engine.capabilities.detect``.


@dataclass(frozen=True)
class VoyageConfig:
    """Voyage AI embedding settings."""

    api_key: str
    model: str = "voyage-3"
    dimensions: int = 1024
    # Voyage context is generous; we still bound the text we embed so a huge
    # dropped file never balloons API memory. ~32k chars is a safe window.
    max_input_chars: int = 32_000


@dataclass(frozen=True)
class GuardSpec:
    """A composable guard, stamped onto new voyds/voids as policy data.

    There used to be a ``params: dict`` here for guards that take
    arguments. No guard ever did: it was constructed as ``{}`` at the only
    call site and read by nothing. A field written on every scope and read
    by nobody is a schema somebody later feels obliged to keep, which is
    this package's complaint about other people's data models -- so it is
    gone, and the guard that needs arguments can add it back with a reader.
    """

    kind: GuardKind
