"""Host-header routing: which voyd (namespace) is this request for?

``auto.voyd.com``            -> slug "auto"  (that voyd's shape + API)
``auto.localhost:8000``      -> slug "auto"  (local dev, no wildcard DNS)
``auto.voyd.localhost``      -> slug "auto"
``voyd.com`` / ``localhost`` -> None         (apex: owner control plane)
``X-Voyd: auto`` header      -> slug "auto"  (escape hatch when Host cannot help)

The apex host is where an owner inserts/lists/deletes voyds. Every voyd host
resolves to a slug that scopes every MongoDB query by ``voyd_id``. The routing
and handlers are identical for every namespace; only the Host header differs,
and it decides which ``voyd`` document the request is scoped to.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.types import ASGIApp

_APEX_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", ""}


def strip_port(host: str) -> str:
    host = (host or "").strip().lower()
    # IPv6 literals are not supported as namespaces; strip a trailing :port.
    if host.count(":") == 1:
        host = host.split(":", 1)[0]
    return host


def resolve_slug(host: str, domain: str, header_slug: str | None = None) -> str | None:
    """Return the voyd slug for a request, or ``None`` for the apex plane.

    Pure function so it can be unit-tested without a running server.
    """
    if header_slug:
        s = header_slug.strip().lower()
        return s or None

    host = strip_port(host)
    domain = (domain or "").strip().lower()

    if host in _APEX_HOSTS:
        return None

    # {slug}.{domain}  e.g. auto.voyd.com
    if domain and host == domain:
        return None
    if domain and host.endswith("." + domain):
        label = host[: -(len(domain) + 1)]
        return label.split(".")[0] or None

    # Local dev convenience: {slug}.localhost (and {slug}.voyd.localhost handled above).
    if host.endswith(".localhost"):
        label = host[: -len(".localhost")]
        return label.split(".")[0] or None

    # Unknown bare host (e.g. an IP or an unrelated domain) -> apex.
    return None


class VoydHostMiddleware(BaseHTTPMiddleware):
    """Populate ``request.state.voyd_slug`` from Host / ``X-Voyd``."""

    def __init__(self, app: ASGIApp, domain: str):
        super().__init__(app)
        self.domain = domain

    async def dispatch(self, request: Request, call_next):
        host = request.headers.get("host", "")
        header_slug = request.headers.get("x-voyd")
        request.state.voyd_slug = resolve_slug(host, self.domain, header_slug)
        return await call_next(request)
