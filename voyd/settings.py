"""Environment-driven settings, so the same code runs locally and in prod.

Used by ``python -m voyd``. One connection string and an embedding key is the
whole configuration surface -- there is no object storage to point at, because
documents are rows.
"""

from __future__ import annotations

import logging

from pydantic_settings import BaseSettings, SettingsConfigDict

from . import Guard, Intelligence, Store
from .app import Voyd

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

    voyage_api_key: str = "vy-dev-key"
    voyage_model: str = "voyage-4"

    require_passcode: bool = False

    # Signs the head of the refusal chain served by GET /v1/voids/{token}/proof.
    # Unset means the chain is served unsigned and says so (`signed: false`);
    # it is still verifiable, because verification needs no key.
    ledger_key: str | None = None

    # Set false on a private instance to refuse new owners after the first.
    allow_signup: bool = True



def build_app(settings: VoydSettings | None = None) -> Voyd:
    s = settings or VoydSettings()
    guards = []
    if s.require_passcode:
        guards.append(Guard.require_passcode())

    app = Voyd(
        domain=s.domain,
        store=Store.Mongo(s.mongo_uri, db_name=s.db,
                          ledger_key=s.ledger_key),
        intelligence=Intelligence.Voyage(api_key=s.voyage_api_key, model=s.voyage_model),
        guards=guards,
        allow_signup=s.allow_signup,
    )
    app.port = s.port
    return app
