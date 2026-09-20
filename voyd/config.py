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
    # The vendor's recommended general-purpose model. Moved off ``voyage-3``
    # once that became two generations old, and the reason is not "newer is
    # better": ``voyage-3`` is the one model in the current comparison with a
    # **fixed** 1024 dimensions and no quantization. Every 4-series model
    # emits 256/512/1024/2048 by Matryoshka truncation.
    model: str = "voyage-4"
    # 1024, and this number is the one worth arguing about rather than the
    # model name, because it is the one that cannot be changed later without
    # a full index rebuild -- ``numDimensions`` is baked into the vector
    # index, and ``search.py`` documents at length why that migration is the
    # expensive one.
    #
    # So the default is the middle rung, deliberately: 2048 costs storage and
    # scan time most corpora never recover in relevance, and 256/512 are
    # choices a deployment should make *knowing* it is trading accuracy for
    # cost. 1024 is also what the previous default was, so an existing index
    # keeps working across this change -- the model moved, the geometry did
    # not. Anything that reads a vector still has to check *which model*
    # wrote it (see ``EmbeddedWith``), because same-width vectors from two
    # models compare without error and rank like noise.
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
