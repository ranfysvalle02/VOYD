"""The product in one file: open a scope, fill it, query it, walk away.

    docker compose up -d
    uv run python -m voyd          # in another shell; sign in, make a namespace
    VOYD_URL=http://acme.localhost:8000 VOYD_API_KEY=voyd_... \
        uv run --extra mcp python examples/scope.py

This is the same client the MCP server wraps, so what an agent does through
tools is exactly what happens here -- there is no second code path for models.
"""

from __future__ import annotations

import asyncio
import os

from voyd.mcp import VoydClient

NOTES = [
    {"name": "intake.md", "text": "Customer reports intermittent misfire under load."},
    {"name": "scan.md", "text": "Diagnostic scan returned fault code P0301, cylinder 1."},
    {"name": "parts.md", "text": "Ordered replacement coil pack, ETA Thursday."},
]


async def main() -> None:
    url, key = os.environ.get("VOYD_URL"), os.environ.get("VOYD_API_KEY")
    if not (url and key):
        raise SystemExit("set VOYD_URL and VOYD_API_KEY (see the module docstring)")

    voyd = VoydClient(url, key)

    # 1. A scope with a deadline. Nothing here needs cleaning up afterwards.
    scope = await voyd.open_scope(ttl_seconds=3600)
    token = scope["token"]
    print(f"scope {token} expires {scope['expires']}")

    # 2. Text straight in. It is a field on the row, not an upload.
    await voyd.add(token, NOTES)

    # 3. Embedding is asynchronous, so wait for the index rather than
    #    mistaking "still building" for "nothing matched".
    for _ in range(30):
        index = (await voyd.describe(token))["index"]
        if index["pending"] == 0:
            break
        await asyncio.sleep(1)
    print(f"indexed {index['indexed']}/{index['total']}")

    # 4. Hybrid: 'P0301' is an identifier, which pure embedding search is bad
    #    at. The lexical leg is what finds it.
    for hit in (await voyd.search(token, "P0301"))["matches"]:
        print(f"  {hit['score']:.3f}  {hit['name']}: {hit.get('text', '')[:60]}")

    # No cleanup below this line, and none needed: the scope carries its own
    # deadline, and the documents and vectors inherit it.
    print("\nnothing to delete. in an hour this scope and its vectors are gone.")
    print("to watch that happen on a 10-second timescale instead of an hour:")
    print("    uv run python examples/forget.py")


if __name__ == "__main__":
    asyncio.run(main())
