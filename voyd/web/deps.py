"""Shared FastAPI dependencies and small serialization helpers.

The single ``Voyd`` engine is stashed on ``app.state.engine`` at startup;
dependencies pull the store/storage/intelligence from there. Host resolution
(apex vs voyd) was already done by :class:`~voyd.host.VoydHostMiddleware`, which
set ``request.state.voyd_slug``.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any

from bson import ObjectId
from fastapi import Depends, Header, HTTPException, Request

from ..engine.time import aware


def get_engine(request: Request):
    return request.app.state.engine


def hash_api_key(key: str) -> str:
    """API keys are high-entropy random tokens, so a fast deterministic hash
    is both safe and lookup-friendly (unlike a salted argon2 hash)."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def require_apex(request: Request) -> None:
    """Owner-plane endpoints only exist on the apex host."""
    if getattr(request.state, "voyd_slug", None) is not None:
        raise HTTPException(404, "Not found on a voyd host. Use the apex domain.")


async def require_owner(request: Request,
                        authorization: str | None = Header(default=None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Missing bearer token.")
    key = authorization.split(" ", 1)[1].strip()
    store = request.app.state.engine.store
    owner = await store.get_owner_by_key_hash(hash_api_key(key))
    if not owner:
        raise HTTPException(401, "Invalid owner key.")
    return owner


async def get_current_voyd(request: Request) -> dict:
    slug = getattr(request.state, "voyd_slug", None)
    if slug is None:
        raise HTTPException(404, "No voyd for this host.")
    voyd = await request.app.state.engine.store.get_voyd_by_slug(slug)
    if not voyd or voyd.get("status") != "active":
        raise HTTPException(404, f"voyd '{slug}' not found.")
    return voyd


async def require_voyd_owner(request: Request,
                             voyd: dict = Depends(get_current_voyd),
                             owner: dict = Depends(require_owner)) -> dict:
    if voyd.get("owner_id") != owner.get("_id"):
        raise HTTPException(403, "You do not own this voyd.")
    return voyd


def jsonify(value: Any) -> Any:
    """Recursively convert BSON types to JSON-serialisable values, and drop
    heavy/secret fields (embeddings, passcode hashes)."""
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if k in ("embedding",):
                continue
            if k == "guards" and isinstance(v, dict):
                v = {gk: gv for gk, gv in v.items() if gk != "passcode_hash"}
            out[k] = jsonify(v)
        return out
    if isinstance(value, list):
        return [jsonify(v) for v in value]
    if isinstance(value, ObjectId):
        return str(value)
    if isinstance(value, datetime):
        return aware(value).isoformat()
    return value
