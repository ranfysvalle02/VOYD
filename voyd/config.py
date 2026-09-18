"""Configuration value objects for VOYD.

These are plain dataclasses returned by the public constructors
(``Store.Mongo``, ``Intelligence.Voyage``, ``Guard.*``).
They carry no behaviour beyond holding validated settings so the rest of the
engine can stay dependency-light and easy to test.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

GuardKind = Literal["require_passcode"]


@dataclass(frozen=True)
class MongoConfig:
    """Connection settings for the MongoDB operational layer."""

    uri: str
    db_name: str = "voyd"

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
    """A composable guard, stamped onto new voyds/voids as policy data."""

    kind: GuardKind
    params: dict = field(default_factory=dict)
