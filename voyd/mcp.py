"""Recipes as MCP tools, called through ``voyd-wire``. Enforces nothing.

    pip install 'voyd[mcp]'
    voyd-mcp --policy voydfile.py \\
             --wire 'mongodb://svc:pw@voyd-wire:27017/?directConnection=true' \\
             --db support --transport http --port 8765

An agent framework speaks the Model Context Protocol; a ``voydfile.py``
declares recipes. This is the adapter between them, and it is thin on
purpose:

- **A tool is a recipe.** One per ``@recipe``, named for it, described by
  the first paragraph of its function's docstring and the collection it
  reads. Its input schema is the recipe's typed parameters, read from the
  same ``Param`` objects the boundary checks a value against -- so the
  schema an agent sees and the check a value meets cannot drift apart.
- **The caller is the bearer token.** Over HTTP the MCP request's
  ``Authorization: Bearer`` token is the delegated identity, verified by
  the same ``voyd.engine.delegation.verify`` against the same issuers the
  voydfile declares. No valid token, no tool list and no call.
- **A call is an aggregate through the wire.**
  ``aggregate([{"$recipe": {...}}], comment={"voyd": token})`` on a
  pymongo connection to ``voyd-wire`` -- never to MongoDB -- as a service
  user the issuer names in ``connection_users``. The wire verifies the
  token again, applies every rule, strips the token, and stamps what it
  serves.
- **The result is documents and their receipts.** Relaxed extended JSON,
  ``_voyd`` stamps included, plus ``voyd.attest.cite`` citations, as
  structured content and as text. A read larger than the bound is an
  error, never a truncation, because a silently shortened context is a
  context nobody chose.

**The wire is the boundary; listing is a convenience.** What this module
lists is its best reading of the policy for one identity -- the
collection's ``delegation=`` and ``scope=``, and the recipe's grants --
and a tool it lists may still be refused. The refusal comes from
``voyd-wire`` and reaches the agent as a tool error carrying the wire's
own message. If this module enforced anything, there would be two
boundaries to keep in agreement; it decides only what to show.

**stdio is local use.** There is no request to carry a token, so the token
is read once from ``--token-env VAR`` and every call is that identity.
Whoever can start the process chooses who it reads as; the wire still
verifies the token, so the trust granted is exactly the token's -- but it
is the token of whoever set the variable, not of whichever agent attached.

No model is called and no prompt is written. Nothing is kept between
requests.
"""

from __future__ import annotations

import argparse
import asyncio
import inspect
import json
import os
import sys
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping

import bson
from bson import json_util

from voyd.engine.delegation import Identity, Refusal, peek_issuer, verify

DEFAULT_MAX_DOCUMENTS = 100
DEFAULT_MAX_BYTES = 1024 * 1024

INSTALL_HINT = ("voyd-mcp needs the MCP Python SDK: "
                "pip install 'voyd[mcp]'")

_JSON_TYPES = {"str": "string", "int": "integer", "float": "number",
               "bool": "boolean"}


class Denied(Exception):
    """A request this adapter will not pass on. The message is the reason."""


# ---- a tool, from a recipe -------------------------------------------------

def input_schema(recipe: Any) -> dict:
    """The JSON Schema of a recipe's parameters, from its declared ``Param``s.

    ``str``/``int``/``float``/``bool``/``list[str]``, ``| None`` as a
    ``"null"`` alternative, a default as ``default``, no default as
    ``required``. ``additionalProperties`` is false because the boundary
    refuses an unknown parameter by name.
    """
    props: dict[str, dict] = {}
    required: list[str] = []
    for p in recipe.params:
        if p.kind == "list[str]":
            base: dict[str, Any] = {"type": "array", "items": {"type": "string"}}
        else:
            base = {"type": _JSON_TYPES[p.kind]}
        if p.nullable:
            base["type"] = [base["type"], "null"]
        if p.required:
            required.append(p.name)
        else:
            base["default"] = p.default
        props[p.name] = base
    schema: dict[str, Any] = {"type": "object", "properties": props,
                              "additionalProperties": False}
    if required:
        schema["required"] = required
    return schema


def description(recipe: Any) -> str:
    """The first paragraph of the recipe's docstring, and what it reads."""
    doc = inspect.getdoc(recipe.fn) or ""
    first = " ".join(doc.split("\n\n", 1)[0].split())
    reads = (f"Reads the {recipe.collection!r} collection through voyd-wire "
             f"as recipe {recipe.name}@{recipe.version}; results carry "
             f"_voyd receipts when the collection attests.")
    return f"{first}\n\n{reads}" if first else reads


# ---- who may see which tool ------------------------------------------------

def _granted(recipe: Any, identity: Identity) -> bool:
    """Whether a recipe's own grants admit this identity.

    ``actors=`` names the agents that may call it; ``scopes=`` the grants
    of which the token must hold one. A recipe that declares neither is
    granted to every identity. ``voyd.wire.policy.recipes.recipes_for``,
    when the policy code provides it, is the answer this defers to, so
    this adapter and the wire read grants with one function.
    """
    actors = tuple(getattr(recipe, "actors", ()) or ())
    scopes = tuple(getattr(recipe, "scopes", ()) or ())
    actor = identity.actor.get("user") if identity.actor else None
    if actors and actor not in actors:
        return False
    if scopes and not set(scopes) & set(identity.scopes):
        return False
    return True


def _collection_admits(spec: Any, identity: Identity) -> bool:
    """The collection-level terms a delegated read meets at the wire."""
    delegation = getattr(spec, "delegation", "allowed")
    if delegation == "forbidden":
        return False
    if delegation == "required" and identity.actor is None:
        return False
    scope = getattr(spec, "scope", None)
    return not (scope and scope not in identity.scopes)


def listable(recipes: Mapping[str, Any], specs: Mapping[str, Any],
             identity: Identity) -> list[Any]:
    """The recipes to list for this identity, by name."""
    granted: set[str] | None = None
    from voyd.wire.policy import recipes as book
    recipes_for = getattr(book, "recipes_for", None)
    if recipes_for is not None:
        from voyd.wire.policy.guarding import Guard
        got = recipes_for(identity, {c: Guard(s) for c, s in specs.items()})
        granted = {getattr(r, "name", r) for r in got}
    out = []
    for name in sorted(recipes):
        recipe = recipes[name]
        spec = specs.get(recipe.collection)
        if spec is None or not _collection_admits(spec, identity):
            continue
        if granted is not None and name not in granted:
            continue
        if granted is None and not _granted(recipe, identity):
            continue
        out.append(recipe)
    return out


# ---- the adapter -----------------------------------------------------------

@dataclass
class Result:
    documents: list[dict]
    citations: list[str]

    def structured(self, recipe: str) -> dict:
        return {"recipe": recipe, "documents": self.documents,
                "citations": self.citations}


class Tools:
    """A voydfile's recipes, one identity at a time. No MCP in here.

    ``db`` is a pymongo ``Database`` on a connection to ``voyd-wire``, or
    anything whose ``[collection].aggregate(pipeline, comment=...)``
    iterates documents -- which is what lets a test assert on the command
    without a socket.
    """

    def __init__(self, recipes: Mapping[str, Any], specs: Mapping[str, Any],
                 issuers: Mapping[str, Any], keys: Callable[[str, float], Any],
                 db: Any, *, max_documents: int = DEFAULT_MAX_DOCUMENTS,
                 max_bytes: int = DEFAULT_MAX_BYTES,
                 clock: Callable[[], float] = time.time):
        self.recipes, self.specs = dict(recipes), dict(specs)
        self.issuers, self.keys = dict(issuers), keys
        self.db, self.clock = db, clock
        self.max_documents, self.max_bytes = max_documents, max_bytes

    def identity(self, token: str | None) -> Identity:
        """The verified identity this token names, or ``Denied``."""
        if not token:
            raise Denied("no bearer token: voyd-mcp lists and calls recipes "
                         "only for a delegated identity")
        url = peek_issuer(token)
        issuer = self.issuers.get(url) if url else None
        if issuer is None:
            raise Denied(f"the token names issuer {url!r}, which the policy "
                         f"does not declare")
        now = self.clock()
        got = verify(token, self.keys(issuer.url, now), now, issuer)
        if isinstance(got, Refusal):
            raise Denied(f"the token is not believed ({got.reason}): "
                         f"{got.detail}")
        return got

    def listed(self, token: str | None) -> list[Any]:
        return listable(self.recipes, self.specs, self.identity(token))

    def call(self, token: str | None, name: str,
             arguments: Mapping[str, Any] | None) -> Result:
        """Run one recipe through the wire as this token. ``Denied`` on a
        bad token, an unknown tool, an oversized read or a wire refusal."""
        self.identity(token)
        recipe = self.recipes.get(name)
        if recipe is None:
            raise Denied(f"no tool is named {name!r}")
        from pymongo.errors import OperationFailure, PyMongoError

        pipeline = [{"$recipe": {"name": name,
                                 "params": dict(arguments or {})}}]
        docs: list[dict] = []
        size = 0
        try:
            cursor = self.db[recipe.collection].aggregate(
                pipeline, comment={"voyd": token})
            try:
                for doc in cursor:
                    docs.append(doc)
                    size += len(bson.encode(doc))
                    if len(docs) > self.max_documents:
                        raise Denied(
                            f"{name} returned more than {self.max_documents} "
                            f"documents. voyd-mcp does not truncate a read; "
                            f"ask for fewer, or raise --max-documents")
                    if size > self.max_bytes:
                        raise Denied(
                            f"{name} returned more than {self.max_bytes} "
                            f"bytes. voyd-mcp does not truncate a read; ask "
                            f"for fewer, or raise --max-bytes")
            finally:
                close = getattr(cursor, "close", None)
                if close is not None:
                    close()
        except OperationFailure as exc:
            details = exc.details or {}
            raise Denied(str(details.get("errmsg") or exc)) from None
        except PyMongoError as exc:
            raise Denied(f"voyd-wire could not be read: "
                         f"{type(exc).__name__}: {exc}") from None
        from voyd.attest import cite

        cites = [c for c in (cite(d) for d in docs) if c]
        as_json = json.loads(json_util.dumps(
            docs, json_options=json_util.RELAXED_JSON_OPTIONS))
        return Result(as_json, cites)


# ---- MCP -------------------------------------------------------------------

def _require_mcp() -> None:
    try:
        import mcp  # noqa: F401
    except ImportError:
        raise SystemExit(INSTALL_HINT) from None


def bearer(ctx: Any) -> str | None:
    """The bearer token of the HTTP request behind an MCP request."""
    headers = getattr(getattr(ctx, "request", None), "headers", None)
    raw = headers.get("authorization") if headers is not None else None
    if not isinstance(raw, str) or not raw.lower().startswith("bearer "):
        return None
    return raw[7:].strip() or None


def server(tools: Tools, token_of: Callable[[Any], str | None]) -> Any:
    """An MCP ``Server`` whose tools are ``tools``' recipes.

    ``token_of(ctx)`` is where the caller's token comes from: the HTTP
    request's bearer header, or a fixed token for stdio.
    """
    _require_mcp()
    import mcp_types as types
    from mcp.server.lowlevel import Server
    from mcp.shared.exceptions import MCPError

    async def list_tools(ctx: Any, params: Any) -> Any:
        try:
            shown = tools.listed(token_of(ctx))
        except Denied as exc:
            raise MCPError(-32001, str(exc)) from None
        return types.ListToolsResult(tools=[
            types.Tool(name=r.name, description=description(r),
                       input_schema=input_schema(r)) for r in shown])

    async def call_tool(ctx: Any, params: Any) -> Any:
        token = token_of(ctx)
        try:
            got = await asyncio.to_thread(tools.call, token, params.name,
                                          params.arguments)
        except Denied as exc:
            return types.CallToolResult(
                content=[types.TextContent(text=str(exc))], is_error=True)
        body = got.structured(params.name)
        return types.CallToolResult(
            content=[types.TextContent(text=json.dumps(body))],
            structured_content=body)

    return Server("voyd-mcp", version=_version(),
                  instructions="Governed retrieval: each tool is a recipe "
                               "read through voyd-wire as your token.",
                  on_list_tools=list_tools, on_call_tool=call_tool)


def _version() -> str:
    try:
        from importlib.metadata import version
        return version("voyd")
    except Exception:                                         # noqa: BLE001
        return ""


class Verifier:
    """The MCP SDK's ``TokenVerifier``, answered by ``Tools.identity``, so an
    HTTP request with no believable token is a 401 before any handler."""

    def __init__(self, tools: Tools):
        self.tools = tools

    async def verify_token(self, token: str) -> Any:
        from mcp.server.auth.provider import AccessToken
        try:
            who = self.tools.identity(token)
        except Denied:
            return None
        actor = who.actor.get("user") if who.actor else None
        return AccessToken(token=token, client_id=str(actor or "none"),
                           scopes=list(who.scopes), expires_at=int(who.expires),
                           subject=str(who.principal.get("user")))


def http_app(tools: Tools, *, host: str, port: int) -> Any:
    """The streamable-HTTP ASGI app: stateless, JSON responses, bearer auth."""
    _require_mcp()
    from mcp.server.auth.settings import AuthSettings
    from pydantic import AnyHttpUrl

    issuer = next(iter(tools.issuers))
    return server(tools, bearer).streamable_http_app(
        stateless_http=True, json_response=True, host=host,
        auth=AuthSettings(issuer_url=AnyHttpUrl(issuer),
                          resource_server_url=AnyHttpUrl(
                              f"http://{host}:{port}/mcp"),
                          validate_token_resource=False),
        token_verifier=Verifier(tools))


# ---- the command -----------------------------------------------------------

def load(policy: str) -> tuple[dict, dict, dict]:
    """(recipes, specs, issuers) declared by a voydfile."""
    from voyd import declare
    specs = declare.load(policy)
    return dict(declare.RECIPES), specs, dict(declare.ISSUERS)


def _refresh(trust: Any, stopping: threading.Event) -> None:
    due = {url: trust.clock() + i.refresh for url, i in trust.issuers.items()}
    while not stopping.wait(1.0):
        for url, when in due.items():
            if trust.clock() >= when:
                trust.load(url)
                due[url] = trust.clock() + trust.issuers[url].refresh


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="voyd-mcp",
        description="Serve a voydfile's recipes as MCP tools, called "
                    "through voyd-wire as the caller's delegated token.")
    ap.add_argument("--policy", required=True, help="the voydfile.py")
    ap.add_argument("--wire", required=True,
                    help="a mongodb:// URI for voyd-wire (not MongoDB), as a "
                         "user the issuer lists in connection_users")
    ap.add_argument("--db", required=True, help="the database recipes read")
    ap.add_argument("--transport", choices=("stdio", "http"), default="http")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--token-env", metavar="VAR",
                    help="stdio only: the environment variable holding the "
                         "one token every call is made as")
    ap.add_argument("--max-documents", type=int, default=DEFAULT_MAX_DOCUMENTS)
    ap.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    args = ap.parse_args(argv)
    _require_mcp()

    try:
        recipes, specs, issuers = load(args.policy)
    except Exception as exc:                                  # noqa: BLE001
        print(f"voyd-mcp: {args.policy}: {exc}", file=sys.stderr)
        return 2
    if not recipes:
        print("voyd-mcp: the policy declares no @recipe, so there is no "
              "tool to serve", file=sys.stderr)
        return 2
    if not issuers:
        print("voyd-mcp: the policy declares no issuer(), so no token could "
              "be verified and every call would be refused", file=sys.stderr)
        return 2
    token = None
    if args.transport == "stdio":
        if not args.token_env:
            print("voyd-mcp: --transport stdio needs --token-env VAR",
                  file=sys.stderr)
            return 2
        token = os.environ.get(args.token_env) or None
        if token is None:
            print(f"voyd-mcp: ${args.token_env} is empty or unset",
                  file=sys.stderr)
            return 2

    from pymongo import MongoClient

    from voyd.wire.jwks import Trust
    trust = Trust(issuers)
    for url in trust.preload():
        print(f"voyd-mcp: WARNING: issuer {url}: keys unreadable "
              f"({trust.why.get(url)}); tokens from it are refused until a "
              f"refresh succeeds", file=sys.stderr)
    stopping = threading.Event()
    threading.Thread(target=_refresh, args=(trust, stopping),
                     daemon=True).start()
    client: Any = MongoClient(args.wire, appname="voyd-mcp")
    tools = Tools(recipes, specs, issuers, trust.keys, client[args.db],
                  max_documents=args.max_documents, max_bytes=args.max_bytes)
    try:
        if args.transport == "stdio":
            from mcp.server.stdio import stdio_server
            app = server(tools, lambda _ctx: token)

            async def run() -> None:
                async with stdio_server() as (read, write):
                    await app.run(read, write,
                                  app.create_initialization_options())
            asyncio.run(run())
        else:
            import uvicorn
            uvicorn.run(http_app(tools, host=args.host, port=args.port),
                        host=args.host, port=args.port, log_level="warning")
    finally:
        stopping.set()
        client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
