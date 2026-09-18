"""The owner console: the apex-host control center.

The human face of the control plane. An owner signs in, sees their namespaces,
types a name, and watches the URL appear. Going live is a write -- no bearer
tokens, no curl, no raw JSON, no deploy.

The voids inside a namespace are driven by the API (see :mod:`voyd.web.vault`),
because the caller opening one is usually an agent, not a person.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pymongo.errors import DuplicateKeyError

from ..auth import (
    SESSION_COOKIE,
    SESSION_TTL_DAYS,
    hash_password,
    hash_session_token,
    new_api_key,
    new_session_token,
    verify_password,
)
from ..guards import compile_guard_defaults
from ..ratelimit import RateLimiter, client_ip
from ..slugs import slug_error, slugify
from .deps import get_engine, hash_api_key

THEMES_DIR = Path(__file__).resolve().parent.parent / "themes"
templates = Jinja2Templates(directory=str(THEMES_DIR))

router = APIRouter(include_in_schema=False)

# Credential endpoints only. Keyed by IP *and* by email, so one IP cannot spray
# many accounts and a botnet cannot grind a single account from many IPs.
_credential_limiter = RateLimiter(limit=10, window_s=300)


def _rate_limited(request: Request, email: str) -> bool:
    ip = client_ip(request)
    # Both keys are always checked, so neither can be skipped by varying the other.
    ok_ip = _credential_limiter.check(f"ip:{ip}")
    ok_email = _credential_limiter.check(f"email:{email}")
    return not (ok_ip and ok_email)


def _clear_rate_limit(request: Request, email: str) -> None:
    _credential_limiter.reset(f"ip:{client_ip(request)}")
    _credential_limiter.reset(f"email:{email}")


TOO_MANY = "Too many attempts. Wait a few minutes and try again."


# ---- helpers -----------------------------------------------------------

def _require_apex(request: Request) -> None:
    """The console only exists on the apex host."""
    if getattr(request.state, "voyd_slug", None) is not None:
        raise HTTPException(404, "Not found.")


async def current_owner(request: Request) -> dict | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    return await get_engine(request).store.get_owner_by_session(
        hash_session_token(token)
    )


def host_suffix(request: Request) -> str:
    """The host voyds hang off, port included: ``localhost:8000``."""
    return request.headers.get("host", get_engine(request).domain)


def voyd_url(request: Request, slug: str) -> str:
    """Where the namespace lives. Selected by Host header, not by a route."""
    return f"{request.url.scheme}://{slug}.{host_suffix(request)}"


def _render(request: Request, name: str, ctx: dict) -> HTMLResponse:
    ctx.setdefault("host_suffix", host_suffix(request))
    return templates.TemplateResponse(request=request, name=name, context=ctx)


async def _start_session(request: Request, owner_id, url: str) -> RedirectResponse:
    token = new_session_token()
    await get_engine(request).store.create_session(
        owner_id, hash_session_token(token), SESSION_TTL_DAYS
    )
    response = RedirectResponse(url, status_code=303)
    response.set_cookie(
        SESSION_COOKIE, token, httponly=True, samesite="lax", path="/",
        # Secure in production; omitted over plain http so *.localhost dev works.
        secure=request.url.scheme == "https",
        max_age=SESSION_TTL_DAYS * 24 * 3600,
    )
    return response


# ---- root ---------------------------------------------------------------

@router.get("/", response_class=HTMLResponse)
async def root(request: Request):
    _require_apex(request)
    owner = await current_owner(request)
    if owner is None:
        return _render(request, "console/landing.html", {})
    return await _dashboard(request, owner)


async def _dashboard(request: Request, owner: dict) -> HTMLResponse:
    store = get_engine(request).store
    voyds = await store.list_voyds(owner["_id"])
    ids = [v["_id"] for v in voyds]
    stats = await store.stats_for_voyds(ids)
    cards = [{
        "name": v.get("name") or v["slug"],
        "slug": v["slug"],
        "created_at": v.get("created_at"),
        "url": voyd_url(request, v["slug"]),
        "stats": stats.get(v["_id"], {}),
    } for v in voyds]
    return _render(request, "console/dashboard.html",
                   {"owner": owner, "voyds": cards})


# ---- auth --------------------------------------------------------------

@router.get("/signup", response_class=HTMLResponse)
async def signup_page(request: Request):
    _require_apex(request)
    engine = get_engine(request)
    if not engine.allow_signup and await engine.store.count_owners() > 0:
        return _render(request, "console/login.html",
                       {"error": "Signups are closed on this instance.",
                        "closed": True})
    return _render(request, "console/signup.html", {})


@router.post("/signup", response_class=HTMLResponse)
async def signup(request: Request, email: str = Form(...), password: str = Form(...)):
    _require_apex(request)
    engine = get_engine(request)
    store = engine.store
    email = email.strip().lower()

    if _rate_limited(request, email):
        return _render(request, "console/signup.html",
                       {"error": TOO_MANY, "email": email})
    if not engine.allow_signup and await store.count_owners() > 0:
        return _render(request, "console/signup.html",
                       {"error": "Signups are closed on this instance."})
    if len(password) < 8:
        return _render(request, "console/signup.html",
                       {"error": "Use a password of at least 8 characters.",
                        "email": email})
    if await store.get_owner_by_email(email):
        return _render(request, "console/signup.html",
                       {"error": "That email already has an account. Sign in instead.",
                        "email": email})

    owner_id = await store.create_owner(
        email, hash_api_key(new_api_key()), password_hash=hash_password(password)
    )
    _clear_rate_limit(request, email)
    return await _start_session(request, owner_id, "/new")


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    _require_apex(request)
    return _render(request, "console/login.html", {})


@router.post("/login", response_class=HTMLResponse)
async def login(request: Request, email: str = Form(...), password: str = Form(...)):
    _require_apex(request)
    email = email.strip().lower()
    if _rate_limited(request, email):
        return _render(request, "console/login.html",
                       {"error": TOO_MANY, "email": email})
    store = get_engine(request).store
    owner = await store.get_owner_by_email(email)
    if not owner or not verify_password(owner.get("password_hash"), password):
        return _render(request, "console/login.html",
                       {"error": "Wrong email or password.", "email": email})
    _clear_rate_limit(request, email)
    return await _start_session(request, owner["_id"], "/")


@router.post("/logout")
async def logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        await get_engine(request).store.delete_session(hash_session_token(token))
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


# ---- insert a namespace ------------------------------------------------

@router.get("/new", response_class=HTMLResponse)
async def new_page(request: Request):
    _require_apex(request)
    owner = await current_owner(request)
    if owner is None:
        return RedirectResponse("/login", status_code=303)
    return _render(request, "console/new.html", {
        "owner": owner,
        "first": not await get_engine(request).store.list_voyds(owner["_id"]),
    })


@router.post("/new", response_class=HTMLResponse)
async def new_submit(request: Request, business_name: str = Form(...)):
    _require_apex(request)
    engine = get_engine(request)
    store = engine.store
    owner = await current_owner(request)
    if owner is None:
        return RedirectResponse("/login", status_code=303)

    async def fail(message: str) -> HTMLResponse:
        return _render(request, "console/new.html", {
            "owner": owner, "error": message, "business_name": business_name,
        })

    slug = slugify(business_name)
    problem = slug_error(slug)
    if problem:
        return await fail(problem)

    slug = await store.find_free_slug(slug)
    guard_defaults = compile_guard_defaults(engine.guard_specs)
    try:
        await store.create_voyd(slug, owner["_id"], guard_defaults,
                                name=business_name.strip())
    except DuplicateKeyError:
        # find_free_slug raced another owner to the same slug.
        return await fail("That name is already taken. Try a different one.")
    return RedirectResponse(f"/launched/{slug}", status_code=303)


@router.get("/launched/{slug}", response_class=HTMLResponse)
async def launched(request: Request, slug: str):
    _require_apex(request)
    owner = await current_owner(request)
    if owner is None:
        return RedirectResponse("/login", status_code=303)
    voyd = await get_engine(request).store.get_voyd_by_slug(slug)
    if not voyd or voyd.get("owner_id") != owner["_id"]:
        raise HTTPException(404, "Namespace not found.")
    return _render(request, "console/launched.html", {
        "owner": owner, "voyd": voyd, "url": voyd_url(request, slug),
    })


@router.get("/keys", response_class=HTMLResponse)
async def keys_page(request: Request):
    _require_apex(request)
    owner = await current_owner(request)
    if owner is None:
        return RedirectResponse("/login", status_code=303)
    return _render(request, "console/keys.html", {"owner": owner, "api_key": None})


@router.post("/keys", response_class=HTMLResponse)
async def rotate_key(request: Request):
    _require_apex(request)
    owner = await current_owner(request)
    if owner is None:
        return RedirectResponse("/login", status_code=303)
    key = new_api_key()
    await get_engine(request).store.set_owner_api_key(owner["_id"], hash_api_key(key))
    return _render(request, "console/keys.html", {"owner": owner, "api_key": key})
