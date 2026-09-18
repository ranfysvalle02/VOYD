"""Environment-driven settings, so the same code runs locally and in prod.

Used by ``python -m voyd``. Object storage is genuinely optional: leave the
``VOYD_R2_*`` variables unset and the service runs on
:class:`~voyd.storage.null.NullStorage`, where the inline-text path works in
full and the blob endpoints answer 501. Configuring R2 additionally requires
the ``r2`` extra.

There are deliberately no placeholder R2 credentials here. The previous
defaults (``https://example.r2.cloudflarestorage.com`` / ``dev-key``) made an
unconfigured deployment hand out presigned URLs against a bucket that does not
exist -- a broken download link at the client instead of an error at the
server.
"""

from __future__ import annotations

import logging

from pydantic_settings import BaseSettings, SettingsConfigDict

from . import Guard, Intelligence, Storage, Store
from .app import Voyd
from .storage.base import ObjectStorage

log = logging.getLogger("voyd.settings")


class VoydSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VOYD_", env_file=".env", extra="ignore")

    domain: str = "voyd.com"
    host: str = "0.0.0.0"
    port: int = 8000

    # Atlas Local from docker-compose. directConnection is needed from the host:
    # the deployment advertises its in-network hostname, which does not resolve here.
    mongo_uri: str = "mongodb://localhost:27018/?directConnection=true"
    db: str = "voyd"

    # All four or none. Partly-set is a misconfiguration, not a deployment
    # shape, and is refused by ``build_storage`` rather than silently degraded.
    r2_endpoint: str | None = None
    r2_key_id: str | None = None
    r2_secret: str | None = None
    r2_bucket: str | None = None

    voyage_api_key: str = "vy-dev-key"
    voyage_model: str = "voyage-3"

    require_passcode: bool = False
    max_downloads: int = 0  # 0 = no cap

    # Set false on a private instance to lock the console after the first owner.
    allow_signup: bool = True



_R2_FIELDS = ("r2_endpoint", "r2_key_id", "r2_secret", "r2_bucket")


def build_storage(s: VoydSettings) -> ObjectStorage:
    """R2 when it is configured, NullStorage when it is not."""
    missing = [f for f in _R2_FIELDS if not getattr(s, f)]
    if len(missing) == len(_R2_FIELDS):
        log.info("no object storage configured: the blob path is disabled "
                 "(POST /v1/voids/{token}/files answers 501). Inline text via "
                 "POST /v1/voids/{token}/documents works in full. Set "
                 "VOYD_R2_ENDPOINT/KEY_ID/SECRET/BUCKET to enable it.")
        return Storage.Null()
    if missing:
        # Half-configured storage would presign against the wrong bucket or
        # with no credentials, which fails at the client, not here.
        raise ValueError(
            "object storage is partly configured; set all of "
            + ", ".join(f"VOYD_{f.upper()}" for f in _R2_FIELDS)
            + " or none of them (missing: "
            + ", ".join(f"VOYD_{f.upper()}" for f in missing) + ")")
    return Storage.R2(endpoint=s.r2_endpoint, key_id=s.r2_key_id,
                      secret_key=s.r2_secret, bucket=s.r2_bucket)


def build_app(settings: VoydSettings | None = None) -> Voyd:
    s = settings or VoydSettings()
    guards = []
    if s.require_passcode:
        guards.append(Guard.require_passcode())
    if s.max_downloads > 0:
        guards.append(Guard.max_downloads(limit=s.max_downloads))

    app = Voyd(
        domain=s.domain,
        store=Store.Mongo(s.mongo_uri, db_name=s.db),
        storage=build_storage(s),
        intelligence=Intelligence.Voyage(api_key=s.voyage_api_key, model=s.voyage_model),
        guards=guards,
        allow_signup=s.allow_signup,
    )
    app.port = s.port
    return app
