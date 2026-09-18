"""The storage interface, stated without a dependency.

The app, the ops loops and the web layer talk to *this*, not to
:class:`~voyd.storage.r2.R2Storage`. Two reasons, and the second is the one
that bit us:

- there is a second implementation (:class:`~voyd.storage.null.NullStorage`),
  so a deployment with no object storage is a configuration and not a fork;
- ``aioboto3`` lives in the optional ``r2`` extra, so a type hint that names
  the concrete class drags the extra into every import of ``voyd.app``. This
  module imports nothing but ``typing``.
"""

from __future__ import annotations

from typing import ClassVar, Protocol, runtime_checkable


class NoObjectStorage(RuntimeError):
    """Raised when the byte path is used on a deployment that has none.

    Loud and specific on purpose: the alternative -- what this code used to do
    -- was hand out a presigned URL against placeholder credentials, so the
    failure surfaced as a broken download link at the client instead of an
    error at the server.
    """


@runtime_checkable
class ObjectStorage(Protocol):
    """What VOYD needs from object storage, and nothing more.

    ``offers_bytes`` is the capability flag the HTTP layer branches on: the
    blob endpoints refuse up front rather than letting a call travel three
    layers down to discover there is no bucket.
    """

    offers_bytes: ClassVar[bool]

    @staticmethod
    def key_for(slug: str, token: str, file_id: str) -> str: ...

    @staticmethod
    def voyd_prefix(slug: str) -> str: ...

    @staticmethod
    def void_prefix(slug: str, token: str) -> str: ...

    async def presign_put(self, key: str, *, content_type: str | None = None,
                          expires: int = 900) -> str: ...

    async def presign_get(self, key: str, *, filename: str | None = None,
                          expires: int = 900) -> str: ...

    async def head(self, key: str) -> dict | None: ...

    async def get_text_window(self, key: str, *, max_bytes: int) -> str: ...

    async def delete_prefix(self, prefix: str) -> int: ...

    async def delete_key(self, key: str) -> None: ...
