"""Cloudflare R2 (S3-compatible) storage: the zero-byte byte path.

File bytes never flow through the API. Clients PUT/GET directly to presigned
R2 URLs. The server only ever:
- mints presigned URLs,
- HEADs an object to confirm upload + read its size,
- reads a *bounded* text window for embedding,
- deletes objects/prefixes when a void/voyd is torn down or TTL'd.

Object keys are namespaced per business: ``voyds/{slug}/voids/{token}/{file_id}``.
"""

from __future__ import annotations

import logging

import aioboto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import BotoCoreError, ClientError

from ..config import R2Config

log = logging.getLogger("voyd.storage")


class R2Storage:
    # There is a bucket, so the blob endpoints are open. See
    # ``voyd.storage.null.NullStorage`` for the deployment where there is not.
    offers_bytes = True

    def __init__(self, config: R2Config):
        self.config = config
        self._session = aioboto3.Session()
        # SigV4 + virtual addressing off (R2 uses path-style).
        self._boto_config = BotoConfig(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
            retries={"max_attempts": 3, "mode": "standard"},
        )

    def _client(self):
        return self._session.client(
            "s3",
            endpoint_url=self.config.endpoint,
            aws_access_key_id=self.config.key_id,
            aws_secret_access_key=self.config.secret_key,
            region_name=self.config.region,
            config=self._boto_config,
        )

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
        params = {"Bucket": self.config.bucket, "Key": key}
        if content_type:
            params["ContentType"] = content_type
        async with self._client() as s3:
            return await s3.generate_presigned_url(
                "put_object", Params=params, ExpiresIn=expires
            )

    async def presign_get(self, key: str, *, filename: str | None = None,
                          expires: int = 900) -> str:
        params = {"Bucket": self.config.bucket, "Key": key}
        if filename:
            params["ResponseContentDisposition"] = f'attachment; filename="{filename}"'
        async with self._client() as s3:
            return await s3.generate_presigned_url(
                "get_object", Params=params, ExpiresIn=expires
            )

    async def head(self, key: str) -> dict | None:
        async with self._client() as s3:
            try:
                resp = await s3.head_object(Bucket=self.config.bucket, Key=key)
                return {"size": resp.get("ContentLength"),
                        "content_type": resp.get("ContentType")}
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code not in ("404", "NoSuchKey", "NotFound"):
                    # Absent is the expected answer (the client has not PUT yet);
                    # denied or misconfigured is not, and must not masquerade as it.
                    log.warning("HEAD %s failed (%s); reporting as absent", key, code)
                return None

    async def get_text_window(self, key: str, *, max_bytes: int) -> str:
        """Read at most ``max_bytes`` and decode as UTF-8 (lossy).

        Bounded so a huge dropped file never balloons API memory.
        """
        async with self._client() as s3:
            resp = await s3.get_object(
                Bucket=self.config.bucket, Key=key, Range=f"bytes=0-{max_bytes - 1}"
            )
            body = await resp["Body"].read()
        return body.decode("utf-8", errors="ignore")

    async def delete_prefix(self, prefix: str) -> int:
        """Delete every object under a prefix. Returns count deleted."""
        deleted = 0
        async with self._client() as s3:
            paginator = s3.get_paginator("list_objects_v2")
            async for page in paginator.paginate(Bucket=self.config.bucket, Prefix=prefix):
                objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
                if not objs:
                    continue
                await s3.delete_objects(
                    Bucket=self.config.bucket, Delete={"Objects": objs}
                )
                deleted += len(objs)
        return deleted

    async def delete_key(self, key: str) -> None:
        async with self._client() as s3:
            try:
                await s3.delete_object(Bucket=self.config.bucket, Key=key)
            except (ClientError, BotoCoreError) as exc:
                # GC is best-effort -- a failed delete must not break the change
                # stream -- but a leaked object is a bill, so it gets named.
                log.warning("could not delete %s: %s", key, exc)
