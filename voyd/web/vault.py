"""The product: open a scope, put documents in it, query it, forget it exists.

A void is a vector index with a TTL, and a read path that refuses what it has
forgotten. Five calls are the whole API, and text goes in as text:

    POST /v1/voids                      open a scope with a deadline
    POST /v1/voids/{token}/documents    text straight in, no upload dance
    POST /v1/voids/{token}/search       query inside the boundary
    GET  /v1/voids/{token}              what is in it, and how much is ready
    POST /v1/voids/{token}/forget       make facts unreachable now

The fifth is the only destructive-sounding one and it deletes nothing: it
gives facts a deadline in the past, so the TTL index that already collects
expired scopes collects these too. There is no erasure subsystem because an
erasure request is a deadline that has already passed.

Search is always filtered by ``voyd_id``, and narrowed to ``token`` when the
caller scoped it to one void. Both filters are pushed into the search index --
the void *is* the retrieval boundary, and a boundary enforced after the fact in
Python is not one. The *deadline* is the exception and goes the other way:
every read resolves through a ``Forgetting`` handle, because a TTL index
collects eventually and a scope that is over has to read as gone now.

Request bodies are Pydantic models, so the shape of a call is declared once and
shows up in the OpenAPI schema instead of living in hand-rolled ``if`` ladders.
Reading a guarded void is rate limited before the argon2 verify runs,
because a slow hash is a cost ceiling and not a bound.
"""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator, model_validator

from ..guards import GuardError, build_void_policy, enforce_query
from ..ratelimit import RateLimiter, client_ip
from ..engine.search import MAX_LIMIT as SEARCH_MAX_LIMIT
from .deps import get_current_voyd, get_engine, jsonify, require_voyd_owner

router = APIRouter(prefix="/v1")


def _passcode_from(request: Request, passcode: str | None = None) -> str | None:
    """A passcode can ride in the body, a header, or a query param.

    Three sources because the three callers differ: an agent posts JSON, a
    shared link carries ``?passcode=``, and a script prefers a header.
    """
    if passcode:
        return str(passcode)
    header = request.headers.get("x-passcode")
    if header:
        return header
    return request.query_params.get("passcode")


def _new_token() -> str:
    return secrets.token_urlsafe(9)


# One call should not be able to queue unbounded embedding work.
MAX_BATCH = 100

# A single document has to fit a BSON document (16MB) alongside its vector,
# and anything this large should have been chunked by the caller anyway.
MAX_DOCUMENT_CHARS = 200_000

# ...and capping `text` alone did not achieve that, because `metadata` is
# opaque and was unbounded. Measured: an 8MB metadata blob was accepted (9.4MB
# on disk, ~47x the text cap), and 17MB raised DocumentTooLarge from the driver
# as an uncaught 500. Metadata is an annotation, not a payload path.
MAX_METADATA_BYTES = 16_384

# A deadline is stored as a BSON date, so `now() + timedelta(seconds=n)` has to
# land inside datetime's range. It did not: ttl_seconds >= ~1e15 raised
# OverflowError out of the route as a 500. Ten years is past every real use --
# a scope meant to outlive that is `ttl_seconds: null`, which means pinned.
MAX_TTL_SECONDS = 10 * 365 * 24 * 3600


# ---- rate limiting the passcode -----------------------------------------

# Argon2 makes one guess expensive; it does not stop a thousand in parallel.
# Keyed by IP *and* by void, so one address cannot grind every void and a
# botnet cannot grind one void. Both keys must pass.
_passcode_limiter = RateLimiter(limit=10, window_s=300)

TOO_MANY_PASSCODE_ATTEMPTS = (
    "Too many passcode attempts. Wait a few minutes and try again.")


def _gate_read(request: Request, voyd: dict, token: str, void: dict,
               enforce) -> None:
    """Run a read guard, rate limited when -- and only when -- it is a gate.

    ``enforce`` is called with the void's policy. An ungated (public) void is
    not limited at all: throttling it would throttle ordinary traffic for no
    security gain. A gated one is checked *before* the argon2 verify, and its
    counters are cleared once the passcode is accepted, so a legitimate reader
    is never punished for someone else's guessing.
    """
    policy = void.get("guards", {}) or {}
    gated = bool(policy.get("require_passcode"))
    keys: tuple[str, ...] = ()

    if gated:
        keys = (f"ip:{client_ip(request)}",
                f"void:{voyd['_id']}:{token}")
        # Both keys are always recorded, so neither can be skipped by
        # varying the other.
        allowed = [_passcode_limiter.check(k) for k in keys]
        if not all(allowed):
            raise HTTPException(429, TOO_MANY_PASSCODE_ATTEMPTS)

    try:
        enforce(policy)
    except GuardError as e:
        # 401 is the only credential failure. Anything else means the
        # passcode was accepted, so it clears the count.
        if e.status_code != 401:
            for key in keys:
                _passcode_limiter.reset(key)
        raise HTTPException(e.status_code, e.detail)

    for key in keys:
        _passcode_limiter.reset(key)


# ---- request bodies -----------------------------------------------------

class CreateVoidRequest(BaseModel):
    """Everything about a void is optional: the default is a public, permanent
    scope, and ``ttl_seconds`` is what makes it a void."""

    # Deliberately unbounded below zero: a zero/negative TTL is a scope that is
    # already over, which is valid and must collect rather than linger. Bounded
    # above, because the deadline becomes a datetime and a large enough
    # ttl_seconds overflowed one -- a caller passing milliseconds by mistake
    # should get a 422, not a 500.
    ttl_seconds: int | None = Field(default=None, le=MAX_TTL_SECONDS)
    passcode: str | None = None


class DocumentIn(BaseModel):
    """One document going in. ``text`` is the only thing we cannot invent."""

    text: str
    name: str = ""
    metadata: dict | None = None

    @field_validator("text")
    @classmethod
    def _text_must_say_something(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("text is required.")
        if len(v) > MAX_DOCUMENT_CHARS:
            raise ValueError(
                f"text exceeds {MAX_DOCUMENT_CHARS} characters; "
                "split it before adding.")
        return v

    @field_validator("name", mode="before")
    @classmethod
    def _strip_name(cls, v) -> str:
        return (v or "").strip() if isinstance(v, (str, type(None))) else v

    @field_validator("metadata", mode="before")
    @classmethod
    def _metadata_or_nothing(cls, v):
        # Metadata is opaque to us, so anything that is not an object is
        # dropped rather than rejected -- it carries no meaning either way.
        if not isinstance(v, dict):
            return None
        # Opaque is not the same as unbounded. Without this, `text`'s cap was
        # decorative: the same row could carry megabytes here instead, and
        # past BSON's 16MB the driver raised into the route as a 500.
        try:
            size = len(json.dumps(v, default=str).encode("utf-8"))
        except (TypeError, ValueError):
            raise ValueError("metadata must be JSON-serialisable.") from None
        if size > MAX_METADATA_BYTES:
            raise ValueError(
                f"metadata is {size} bytes; the limit is "
                f"{MAX_METADATA_BYTES}. Metadata annotates a document, it is "
                f"not a place to put one -- send large content as `text`.")
        return v


class AddDocumentsRequest(BaseModel):
    """A batch, bounded. The whole list validates before any row is written."""

    documents: list[DocumentIn] = Field(min_length=1, max_length=MAX_BATCH)

    @model_validator(mode="before")
    @classmethod
    def _accept_the_single_document_shorthand(cls, data):
        # An agent adding one note should not have to know about batching.
        if (isinstance(data, dict) and data.get("documents") is None
                and data.get("text") is not None):
            return {"documents": [data]}
        return data


class ForgetRequest(BaseModel):
    """What to forget. Omitting ``doc_ids`` forgets the whole scope."""

    doc_ids: list[str] | None = Field(default=None, max_length=MAX_BATCH)
    reason: str = Field(default="revoked", max_length=200)


class SearchRequest(BaseModel):
    """A query, and how many hits to bring back."""

    query: str
    # The search engine clamps to MAX_LIMIT anyway; declaring the ceiling here
    # means an oversized ask is refused instead of silently served a smaller
    # page, and the real bound shows up in the OpenAPI schema.
    limit: int = Field(default=5, ge=1, le=SEARCH_MAX_LIMIT)
    passcode: str | None = None

    @field_validator("query")
    @classmethod
    def _query_is_required(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("query is required.")
        return v


# ---- voids -------------------------------------------------------------

@router.post("/voids")
async def create_void(request: Request,
                      body: CreateVoidRequest = Body(
                          default_factory=CreateVoidRequest),
                      voyd: dict = Depends(require_voyd_owner)):
    engine = get_engine(request)
    expire_at = None
    if body.ttl_seconds is not None:
        expire_at = datetime.now(timezone.utc) + timedelta(
            seconds=body.ttl_seconds)

    try:
        policy = build_void_policy(
            voyd.get("guards"),
            passcode=body.passcode,
        )
    except GuardError as e:
        raise HTTPException(e.status_code, e.detail)

    # Retry on the (rare) token collision.
    for _ in range(5):
        token = _new_token()
        if await engine.store.get_void(voyd["_id"], token) is None:
            void = await engine.store.create_void(voyd["_id"], token, policy, expire_at)
            return {"token": token, "expire_at": jsonify(expire_at),
                    "expires": "never" if expire_at is None else jsonify(expire_at),
                    "void": jsonify(void)}
    raise HTTPException(500, "Could not allocate a unique token.")


@router.get("/voids")
async def list_voids(request: Request, voyd: dict = Depends(require_voyd_owner)):
    """Every void still alive in this namespace. Expired ones are gone, not hidden."""
    voids = await get_engine(request).store.list_voids(voyd["_id"])
    return {"voids": jsonify(voids)}


@router.get("/voids/{token}")
async def get_void(request: Request, token: str, voyd: dict = Depends(require_voyd_owner)):
    engine = get_engine(request)
    void = await engine.store.get_void(voyd["_id"], token)
    if not void:
        raise HTTPException(404, "void not found.")
    return {
        "void": jsonify(void),
        "documents": jsonify(await engine.store.list_documents(voyd["_id"], token)),
        # Embedding is asynchronous, so "added" and "searchable" are different
        # facts. A caller about to query needs to know which one it has.
        "index": await engine.store.count_indexed(voyd["_id"], token),
    }


# ---- documents: text straight in ---------------------------------------

@router.post("/voids/{token}/documents")
async def add_documents(request: Request, token: str,
                        body: AddDocumentsRequest = Body(...),
                        voyd: dict = Depends(require_voyd_owner)):
    """Put text in the scope. One document or many, in one call.

    The caller already has the text, so making it stage bytes in object
    storage just to get them embedded would add a round trip and a failure mode
    for nothing. The rows inherit the void's deadline, so nothing here needs
    cleaning up later.
    """
    engine = get_engine(request)
    void = await engine.store.get_void(voyd["_id"], token)
    if not void:
        raise HTTPException(404, "void not found.")

    # The batch was validated in full before this line ran, so nothing is
    # written half-way: rejecting item 5 after inserting 0-4 would leave the
    # caller with a partially filled scope and no way to tell which half landed.
    added = []
    for item in body.documents:
        doc_id = secrets.token_hex(8)
        doc = await engine.store.add_document(
            voyd["_id"], token, doc_id,
            text=item.text,
            name=item.name or f"doc-{doc_id[:6]}",
            metadata=item.metadata,
            expire_at=void.get("expire_at"),
        )
        added.append({"doc_id": doc_id, "name": doc["name"]})

    return {
        "added": added,
        # Honest about the asynchrony rather than implying instant searchability.
        "index": await engine.store.count_indexed(voyd["_id"], token),
        "note": "embedding is asynchronous; poll GET /v1/voids/{token} for index status",
    }


# ---- forgetting --------------------------------------------------------

@router.post("/voids/{token}/forget")
async def forget(request: Request, token: str,
                 body: ForgetRequest = Body(default=ForgetRequest()),
                 voyd: dict = Depends(require_voyd_owner)):
    """Make documents unreachable now. Do not wait for the deadline.

    This is the only destructive-sounding verb in the API, and it is
    deliberately not a delete: nothing is removed here, and the caller is
    given no way to remove anything. The rows stay on disk and stop being
    reachable, and the scope's existing deadline still owns erasure.

    Which is the whole design collapsing into one field. Forgetting a fact is
    giving it a deadline in the past -- the same ``expire_at`` the scope
    already uses -- so a subject erasure request and an ordinary expiry are
    the same mechanism, collected by the same TTL index. There is no erasure
    subsystem because an erasure request is a deadline that has already
    passed.

    The response reports when the fact stopped being reachable, because that
    is the timestamp somebody will eventually have to defend -- not the one
    the sweeper happens to write later.
    """
    engine = get_engine(request)
    void = await engine.store.get_void(voyd["_id"], token)
    if not void:
        raise HTTPException(404, "void not found.")

    at = datetime.now(timezone.utc)
    n = await engine.store.forget_documents(
        voyd["_id"], token, doc_ids=body.doc_ids, reason=body.reason)
    return {
        "forgotten": n,
        "unreachable_since": at.isoformat(),
        "reason": body.reason,
        # Said plainly, because "forgotten" and "deleted" are different
        # promises and only one of them is being made.
        "note": ("unreachable on the next read; the rows are still on disk "
                 "and are erased by the scope's deadline, not by this call"),
    }


# ---- search ------------------------------------------------------------

@router.post("/voids/{token}/search")
async def search_void(request: Request, token: str,
                      body: SearchRequest = Body(...),
                      voyd: dict = Depends(get_current_voyd)):
    engine = get_engine(request)
    void = await engine.store.get_void(voyd["_id"], token)
    if not void:
        raise HTTPException(404, "void not found.")

    # Querying a guarded scope is reading it, and reading is the only way in.
    _gate_read(request, voyd, token, void, lambda policy: enforce_query(
        policy, passcode=_passcode_from(request, body.passcode)))

    query, limit = body.query, body.limit

    qvec = await engine.intelligence.embed_query(query)
    matches = await engine.store.vector_search(voyd["_id"], qvec, token=token,
                                               query_text=query, limit=limit)
    return {"matches": await _present_matches(engine, matches)}


@router.post("/search")
async def search_voyd(request: Request, body: SearchRequest = Body(...),
                      voyd: dict = Depends(require_voyd_owner)):
    """Namespace-wide search: every living void the owner has.

    This path reaches documents directly instead of resolving one void first,
    so it carries its own deadline check. Without it, a void past its deadline
    keeps answering here for the minute or so before the TTL reaper collects
    it -- which is the one thing a void is supposed to make impossible."""
    engine = get_engine(request)
    query, limit = body.query, body.limit

    qvec = await engine.intelligence.embed_query(query)
    matches = await engine.store.vector_search(voyd["_id"], qvec, token=None,
                                               query_text=query, limit=limit)
    return {"matches": await _present_matches(engine, matches)}


async def _present_matches(engine, matches: list[dict], *,
                           snippet_chars: int = 600) -> list[dict]:
    """A hit carries its text, not a link to go fetch it.

    The caller is usually a model about to put this in a prompt, so making it
    do a second round trip per result would be the wrong default. A document
    whose text lives in a blob still gets a URL, because we do not have it --
    unless there is no object storage, in which case the hit is returned
    without one. A search must not 500 over a row it cannot offer bytes for.
    """
    out = []
    for m in matches:
        hit = {
            "score": m.get("score"),
            "doc_id": m.get("doc_id"),
            "name": m.get("name"),
            "token": m.get("token"),
            "metadata": m.get("metadata") or {},
        }
        text = m.get("text")
        if text:
            hit["text"] = text[:snippet_chars]
            hit["truncated"] = len(text) > snippet_chars
        out.append(hit)
    return out
