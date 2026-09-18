"""VOYD as an MCP server: four tools, and forgetting is one of them.

Agent runtimes are not the competition, they are the channel. AgentCore,
Vertex and Claude managed agents all run agents and all hand the result back
with nowhere to put it. This is the somewhere -- reachable as tools, because
the caller is a model, not a person with a browser.

    open_scope(ttl_seconds)     a vector index that expires
    add(documents)              text straight in
    search(query)               query inside the boundary
    describe()                  what is in it, and how much is queryable

There is deliberately no ``delete`` tool. A scope has a deadline; an agent
that has to remember to clean up is the failure this exists to remove.

Run it over stdio::

    uv run --extra mcp python -m voyd.mcp

It talks to a VOYD deployment over HTTP -- the same ``/v1`` API a human would
curl -- so the agent needs a namespace URL and an API key, nothing else.
"""

from __future__ import annotations

import os
from typing import Any

MAX_BATCH = 100


class VoydClient:
    """A thin async client for one namespace's ``/v1`` API.

    Kept separate from the tool definitions so it can be exercised without an
    MCP runtime in the loop.
    """

    def __init__(self, base_url: str, api_key: str, *, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _headers(self, passcode: str | None = None) -> dict[str, str]:
        headers = {"Authorization": f"Bearer {self.api_key}"}
        if passcode:
            headers["X-Passcode"] = passcode
        return headers

    async def _post(self, path: str, payload: dict,
                    passcode: str | None = None) -> Any:
        import httpx

        async with httpx.AsyncClient(timeout=self.timeout) as c:
            r = await c.post(f"{self.base_url}{path}", json=payload,
                             headers=self._headers(passcode))
            r.raise_for_status()
            return r.json()

    async def _get(self, path: str, passcode: str | None = None) -> Any:
        import httpx

        async with httpx.AsyncClient(timeout=self.timeout) as c:
            r = await c.get(f"{self.base_url}{path}",
                            headers=self._headers(passcode))
            r.raise_for_status()
            return r.json()

    async def open_scope(self, ttl_seconds: int | None = None,
                         passcode: str | None = None) -> dict:
        payload: dict[str, Any] = {}
        if ttl_seconds is not None:
            payload["ttl_seconds"] = int(ttl_seconds)
        if passcode:
            payload["passcode"] = passcode
        return await self._post("/v1/voids", payload)

    async def add(self, token: str, documents: list[dict],
                  passcode: str | None = None) -> dict:
        return await self._post(f"/v1/voids/{token}/documents",
                                {"documents": documents}, passcode)

    async def search(self, token: str, query: str, limit: int = 5,
                     passcode: str | None = None) -> dict:
        return await self._post(f"/v1/voids/{token}/search",
                                {"query": query, "limit": limit}, passcode)

    async def describe(self, token: str, passcode: str | None = None) -> dict:
        return await self._get(f"/v1/voids/{token}", passcode)


def build_server(client: VoydClient):
    """Register the four tools on an MCP server and return it.

    ``MCPServer`` is the mcp 2.x name for what 1.x called ``FastMCP``; this
    targets 2.x, which is what ``voyd[mcp]`` resolves to.
    """
    from mcp.server.mcpserver import MCPServer

    mcp = MCPServer("voyd")

    @mcp.tool()
    async def open_scope(ttl_seconds: int = 86400,
                         passcode: str | None = None) -> dict:
        """Open a retrieval scope that deletes itself.

        Use this when you are about to gather documents you will need to search
        but will not need forever -- one task, one investigation, one batch.
        Everything you put in it (text, embeddings, any bytes) is deleted when
        the deadline passes. You do not need to clean it up, and there is no
        tool to do so.

        ttl_seconds: how long the scope lives. Default 24 hours.
        passcode: optional; required afterwards to search it or read from it.

        Returns the scope token -- pass it to add, search and describe.
        """
        return await client.open_scope(ttl_seconds=ttl_seconds, passcode=passcode)

    @mcp.tool()
    async def add(token: str, documents: list[dict],
                  passcode: str | None = None) -> dict:
        """Put documents into a scope so they can be searched.

        documents: a list of {"text": str, "name": str (optional),
        "metadata": object (optional)}. Up to 100 per call.

        Embedding happens in the background, so documents are not searchable
        the instant this returns. The reply reports how many are indexed; call
        describe to check again before relying on a search being complete.
        """
        if not documents:
            return {"error": "documents must not be empty"}
        if len(documents) > MAX_BATCH:
            return {"error": f"at most {MAX_BATCH} documents per call; "
                             f"got {len(documents)}"}
        return await client.add(token, documents, passcode)

    @mcp.tool()
    async def search(token: str, query: str, limit: int = 5,
                     passcode: str | None = None) -> dict:
        """Search inside one scope, and only that scope.

        Hybrid: semantic similarity fused with exact lexical matching, so
        identifiers, error codes and part numbers work as well as prose --
        which pure embedding search is bad at.

        Results carry their text, so you can use them directly without a
        second fetch. Documents in other scopes are not lower-ranked here;
        they are not reachable.
        """
        return await client.search(token, query, limit=limit, passcode=passcode)

    @mcp.tool()
    async def describe(token: str, passcode: str | None = None) -> dict:
        """What is in a scope, when it expires, and how much is queryable yet.

        Use this before trusting a search to be complete: ``index.pending``
        above zero means embeddings are still being built.
        """
        return await client.describe(token, passcode=passcode)

    return mcp


def main() -> None:
    """``python -m voyd.mcp`` -- serve the tools over stdio."""
    base_url = os.environ.get("VOYD_URL")
    api_key = os.environ.get("VOYD_API_KEY")
    if not base_url or not api_key:
        raise SystemExit(
            "set VOYD_URL and VOYD_API_KEY.\n"
            "    VOYD_URL=http://acme.localhost:8000 VOYD_API_KEY=voyd_... \\\n"
            "        uv run --extra mcp python -m voyd.mcp"
        )

    try:
        server = build_server(VoydClient(base_url, api_key))
    except ModuleNotFoundError as exc:  # the mcp extra is not installed
        raise SystemExit(
            f"the VOYD MCP server needs the 'mcp' extra (missing: {exc.name}).\n"
            "    pip install 'voyd[mcp]'   # or uv sync --extra mcp"
        ) from exc

    server.run()


if __name__ == "__main__":
    main()
