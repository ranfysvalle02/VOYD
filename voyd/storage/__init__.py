"""Object-storage entry point: Cloudflare R2, or none at all.

``R2Storage`` is imported lazily, because ``aioboto3`` is the optional ``r2``
extra and importing it at module top made ``voyd.app`` -- the whole HTTP
service -- unimportable on a ``pip install 'voyd[app]'``. Same pattern as
``voyd/__init__.py``: a module-level ``__getattr__`` over ``_LAZY_EXPORTS``.
"""

from __future__ import annotations

from functools import lru_cache
from importlib import import_module
from typing import TYPE_CHECKING

from ..config import R2Config
from .base import NoObjectStorage, ObjectStorage
from .null import NullStorage

if TYPE_CHECKING:  # pragma: no cover - type-checkers only, never at runtime
    from .r2 import R2Storage

_LAZY_EXPORTS = {"R2Storage": (".r2", "R2Storage")}


def __getattr__(name: str):
    spec = _LAZY_EXPORTS.get(name)
    if spec is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(_load_r2_module(spec[0]), spec[1])
    globals()[name] = value
    return value


def __dir__():
    return sorted({*globals(), *_LAZY_EXPORTS})


def _load_r2_module(name: str = ".r2"):
    """Import the R2 backend, or say which extra is missing.

    Mirrors the message style in ``voyd/__main__.py``: a missing extra is an
    instruction, not a ``ModuleNotFoundError`` three imports deep.
    """
    try:
        return import_module(name, __name__)
    except ModuleNotFoundError as exc:
        raise ModuleNotFoundError(
            f"the voyd blob path needs the 'r2' extra (missing: {exc.name}).\n"
            "    pip install 'voyd[r2]'   # or uv sync --extra r2\n"
            "Inline text needs no object storage; leave VOYD_R2_* unset to "
            "run without the byte path.",
            name=exc.name,
        ) from exc


@lru_cache(maxsize=1)
def transient_storage_errors() -> tuple[type[BaseException], ...]:
    """The botocore exceptions that mean "the world", not "this document".

    Returned as a tuple so callers can ``except transient_storage_errors()``
    without importing botocore -- which, like aioboto3, ships with the ``r2``
    extra. An empty tuple never matches, which is the right answer when there
    is no object storage to be unreachable.
    """
    try:
        from botocore.exceptions import BotoCoreError, ClientError
    except ModuleNotFoundError:
        return ()
    return (ClientError, BotoCoreError)


class Storage:
    """Public factory. ``Storage.R2(...)`` -> :class:`R2Storage`."""

    @staticmethod
    def R2(endpoint: str, key_id: str, secret_key: str, bucket: str,
           region: str = "auto") -> "R2Storage":
        cls = getattr(_load_r2_module(), "R2Storage")
        return cls(R2Config(endpoint=endpoint, key_id=key_id,
                            secret_key=secret_key, bucket=bucket, region=region))

    @staticmethod
    def Null() -> NullStorage:
        """A deployment with no object storage: inline text only."""
        return NullStorage()


__all__ = ["Storage", "R2Storage", "NullStorage", "ObjectStorage",
           "NoObjectStorage", "transient_storage_errors"]
