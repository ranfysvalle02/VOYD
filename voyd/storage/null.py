"""No object storage at all: the inline-text deployment.

``Storage.R2`` was once unconditional, which meant a deployment with no bucket
got placeholder credentials and handed out presigned URLs pointing at nowhere.
This is the honest version of that deployment. The split is deliberate:

- **byte path** (``presign_put``/``presign_get``/``head``/``get_text_window``)
  raises :class:`NoObjectStorage`. A missing capability must be an error the
  server states, never a URL the client discovers is dead.
- **cleanup** (``delete_key``/``delete_prefix``) no-ops quietly. There are no
  bytes to reclaim, and a void being torn down by its own deadline must not
  fail because of it -- the GC loop would log a warning per expired document
  forever.

Keys are still computed the same way, so a row written by one deployment reads
the same in another.
"""

from __future__ import annotations

from .base import NoObjectStorage

_WHY = ("this deployment has no object storage: the blob path is disabled. "
        "Inline text (POST /v1/voids/{token}/documents) needs none. "
        "To enable it, install the extra (pip install 'voyd[r2]') and set "
        "VOYD_R2_ENDPOINT / VOYD_R2_KEY_ID / VOYD_R2_SECRET / VOYD_R2_BUCKET.")


class NullStorage:
    """Satisfies :class:`~voyd.storage.base.ObjectStorage` by refusing bytes."""

    offers_bytes = False

    @staticmethod
    def key_for(slug: str, token: str, file_id: str) -> str:
        return f"voyds/{slug}/voids/{token}/{file_id}"

    @staticmethod
    def voyd_prefix(slug: str) -> str:
        return f"voyds/{slug}/"

    @staticmethod
    def void_prefix(slug: str, token: str) -> str:
        return f"voyds/{slug}/voids/{token}/"

    async def presign_put(self, key: str, *, content_type: str | None = None,
                          expires: int = 900) -> str:
        raise NoObjectStorage(_WHY)

    async def presign_get(self, key: str, *, filename: str | None = None,
                          expires: int = 900) -> str:
        raise NoObjectStorage(_WHY)

    async def head(self, key: str) -> dict | None:
        # Not ``None``: absent would read as "the client has not PUT yet", and
        # complete_file would happily confirm a file that can never exist.
        raise NoObjectStorage(_WHY)

    async def get_text_window(self, key: str, *, max_bytes: int) -> str:
        raise NoObjectStorage(_WHY)

    async def delete_prefix(self, prefix: str) -> int:
        return 0

    async def delete_key(self, key: str) -> None:
        return None
