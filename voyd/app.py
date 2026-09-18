"""The VOYD runtime: one FastAPI process, one MongoDB, and at most one bucket.

``Voyd(...)`` composes the store, storage, intelligence, and guard defaults,
then builds the API: create a namespace, open a void in it, drop files, search
inside the boundary, hand out a guarded link, let the deadline collect it all.
The Host header selects the namespace. A new voyd is an insert, not a deploy.
"""

from __future__ import annotations

import contextlib
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import GuardSpec
from .host import VoydHostMiddleware
from .intelligence.voyage import VoyageIntelligence
from .ops import Ops
from .storage.base import ObjectStorage
from .store.mongo import MongoStore
from .web import owner, vault

log = logging.getLogger("voyd.app")


class ApiCORSMiddleware(CORSMiddleware):
    """CORS for ``/v1`` only. Nothing else is a browser surface, and a
    wildcard on paths that are not the public JSON API is a habit worth not
    forming."""

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope.get("path", "").startswith("/v1"):
            return await self.app(scope, receive, send)
        return await super().__call__(scope, receive, send)


class Voyd:
    def __init__(self, *, store: MongoStore, storage: ObjectStorage,
                 intelligence: VoyageIntelligence,
                 domain: str = "voyd.com",
                 guards: list[GuardSpec] | None = None,
                 allow_signup: bool = True):
        self.store = store
        self.storage = storage
        self.intelligence = intelligence
        self.domain = domain
        self.guard_specs = guards or []
        self.allow_signup = allow_signup
        self.port = 8000
        self.ops: Ops | None = None
        self.api = self._build_app()

    def _build_app(self) -> FastAPI:
        @contextlib.asynccontextmanager
        async def lifespan(app: FastAPI):
            await self.store.connect()
            await self.store.ensure_schema(
                vector_dimensions=self.intelligence.config.dimensions)
            self.ops = Ops(self.store, self.storage, self.intelligence)
            self.ops.start()
            try:
                yield
            finally:
                if self.ops:
                    await self.ops.stop()
                await self.store.close()

        app = FastAPI(title="VOYD", version="0.1.0", lifespan=lifespan)
        app.state.engine = self

        # Wide-open CORS is right for the public JSON API and wrong everywhere
        # else, so it is scoped to /v1 rather than mounted app-wide.
        app.add_middleware(
            ApiCORSMiddleware, allow_origins=["*"], allow_methods=["*"],
            allow_headers=["*"], allow_credentials=False,
        )
        app.add_middleware(VoydHostMiddleware, domain=self.domain)

        app.include_router(owner.router)
        app.include_router(vault.router)

        @app.get("/healthz", include_in_schema=False)
        async def healthz():
            """Includes the search tier and whether change-stream pre-images are
            on, so a degraded deployment is visible to a probe instead of only
            showing up as quietly worse results -- or, for pre-images, as blobs
            that are never reclaimed."""
            engine = self.store.engine
            health = engine.health() if engine else {}
            return {"ok": True, "domain": self.domain,
                    # None = not attempted; False = blob GC via change stream
                    # is off, so expired voids leave their objects behind.
                    "pre_images": getattr(self.store, "pre_images", None),
                    **health}

        return app

    def run(self, host: str = "0.0.0.0", port: int = 8000) -> None:
        import uvicorn

        self.port = port
        uvicorn.run(self.api, host=host, port=port)
