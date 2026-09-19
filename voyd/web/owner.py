"""Owner control plane -- served on the apex host (voyd.com / localhost).

This is where an owner inserts a namespace. Creating a voyd is an insert, not
a deploy: one ``voyds`` doc, and the namespace is live at ``{slug}.{domain}``.
The process was already running, and there is nothing to provision.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from pymongo.errors import DuplicateKeyError

from ..auth import new_api_key
from ..guards import compile_guard_defaults
from ..slugs import slug_error
from .deps import get_engine, hash_api_key, jsonify, require_apex, require_owner

log = logging.getLogger("voyd.web.owner")

router = APIRouter(prefix="/v1", dependencies=[Depends(require_apex)])


@router.post("/owners")
async def create_owner(request: Request, payload: dict = Body(...)):
    """Bootstrap an owner. The first owner is open; after that a valid owner
    key is required to mint more. The raw API key is returned exactly once."""
    engine = get_engine(request)
    store = engine.store
    email = (payload.get("email") or "").strip().lower()
    if not email:
        raise HTTPException(400, "email is required.")

    if await store.count_owners() > 0:
        auth = request.headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            raise HTTPException(401, "An owner already exists; provide a bearer key.")
        existing = await store.get_owner_by_key_hash(hash_api_key(auth.split(" ", 1)[1].strip()))
        if not existing:
            raise HTTPException(401, "Invalid owner key.")

    api_key = new_api_key()
    try:
        owner_id = await store.create_owner(email, hash_api_key(api_key))
    except DuplicateKeyError:
        # The unique index on ``email`` is the only arbiter here.
        raise HTTPException(409, "An owner with that email already exists.")
    return {"owner_id": str(owner_id), "email": email, "api_key": api_key,
            "note": "Store this key now; it will not be shown again."}


@router.post("/voyds")
async def create_voyd(request: Request, owner: dict = Depends(require_owner),
                      payload: dict = Body(...)):
    engine = get_engine(request)
    store = engine.store

    slug = (payload.get("slug") or "").strip().lower()
    name = (payload.get("name") or "").strip()

    # One arbiter. These three checks used to be written out here, beside a
    # predicate in voyd/slugs.py that nothing called -- two copies of one rule,
    # which is the defect this codebase is organised against.
    if problem := slug_error(slug):
        raise HTTPException(422, problem)
    if await store.get_voyd_by_slug(slug) is not None:
        raise HTTPException(409, f"voyd '{slug}' already exists.")

    guard_defaults = compile_guard_defaults(engine.guard_specs)
    voyd = await store.create_voyd(slug, owner["_id"], guard_defaults, name=name)
    return {
        "voyd": jsonify(voyd),
        "url": f"http://{slug}.{engine.domain}",
        "local_url": f"http://{slug}.localhost:{engine.port}",
    }


@router.get("/voyds")
async def list_voyds(request: Request, owner: dict = Depends(require_owner)):
    voyds = await get_engine(request).store.list_voyds(owner["_id"])
    return {"voyds": jsonify(voyds)}
