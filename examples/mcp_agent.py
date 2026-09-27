"""An agent's tools are the policy's recipes, and what they return is signed.

    docker compose up -d mongo
    uv run --extra mcp python examples/mcp_agent.py   # no model, no network

`voyd-wire` guards a `notes` collection that is read only through its
recipes and stamps what it serves. `voyd-mcp` sits in front of it and
turns each recipe into an MCP tool. An MCP client holding a delegated
token -- alice, through `support-bot`, granted `notes:read` -- then does
what any agent framework does, and each step is asserted:

1. **Lists its tools** and sees the recipe it was granted, with a JSON
   Schema made from the recipe's typed parameters. The recipe the agent
   was not granted is not listed.
2. **Calls one.** `voyd-mcp` sends one `$recipe` aggregate to the wire
   with the token in `comment`; the wire verifies it, applies the tenant
   and the audience rule, and stamps each document. The tool result is
   the documents, their `_voyd` receipts and short citations.
3. **Verifies the receipts** with `voyd.attest` and the wire's public key,
   the way an auditor would later -- and prints the context an agent
   would put in front of a model. No model is called.

The MCP client talks to the server in memory here; `voyd-mcp --transport
http` serves the same tools over streamable HTTP with the token as the
request's bearer.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
import textwrap
from pathlib import Path

from bson import json_util
from pymongo import MongoClient

from _boundary import boundary, deployment
from voyd import attest
from voyd import mcp as voyd_mcp
from voyd.testing import TestIssuer
from voyd.wire.jwks import Trust

IDP = TestIssuer("https://login.example.test", audience="voyd://example")

POLICY = textwrap.dedent('''
    from voyd import guard, issuer, recipe, restricted_to, tenant

    issuer("https://login.example.test", audience="voyd://example",
           jwks="{jwks}", connection_users=("*",), roles="roles",
           tenant="org", actor_roles="act.roles")

    @guard("notes", scope="notes:read", recipes_only=True, attest=True)
    class Notes:
        org      = tenant()
        audience = restricted_to("roles")

    @recipe("support_notes", collection="notes")
    def support_notes(topic: str = "refund", k: int = 5):
        """Support notes about a topic, oldest first."""
        return [{{"$match": {{"topic": topic}}}}, {{"$sort": {{"_id": 1}}}},
                {{"$limit": k}}]

    @recipe("billing_export", collection="notes",
            samples={{"month": "2026-01"}})
    def billing_export(month: str):
        """Every note of a month, for finance."""
        return [{{"$match": {{"month": month}}}}]
''')

CORPUS = [
    {"_id": 1, "org": "acme", "audience": ["support"], "topic": "refund",
     "text": "Refunds within 30 days need no approval."},
    {"_id": 2, "org": "acme", "audience": ["hr"], "topic": "refund",
     "text": "Refund fraud case: see HR file 12."},
    {"_id": 3, "org": "globex", "audience": ["support"], "topic": "refund",
     "text": "Globex refunds go through their portal."},
    {"_id": 4, "org": "acme", "audience": ["support"], "topic": "refund",
     "text": "Refunds over $500 need a lead's approval."},
]


async def agent(server, token: str) -> tuple[list, dict]:
    from mcp import Client

    async with Client(server) as client:
        tools = (await client.list_tools()).tools
        result = await client.call_tool("support_notes",
                                        {"topic": "refund", "k": 5})
    assert not result.is_error, result.content
    return tools, result.structured_content


def main() -> None:
    try:
        import mcp  # noqa: F401
    except ImportError:
        raise SystemExit(voyd_mcp.INSTALL_HINT) from None
    with tempfile.TemporaryDirectory() as tmp, \
            deployment("mcp") as (direct, db):
        jwks = IDP.write_jwks(str(Path(tmp) / "jwks.json"))
        private, public, _ = attest.generate()
        key = Path(tmp) / "attest.pem"
        key.write_bytes(private)
        policy = POLICY.format(jwks=jwks)
        policy_path = Path(tmp) / "voydfile.py"
        policy_path.write_text(policy)
        direct[db].notes.insert_many([dict(d) for d in CORPUS])

        # billing_export is granted to the finance agent alone. The
        # listing reads a recipe's `actors`; it is set on the loaded recipe
        # here, which is what `@recipe(..., actors=...)` declares.
        with boundary(policy, "--quiet", "--attest-key", str(key)) as uri:
            recipes, specs, issuers = voyd_mcp.load(str(policy_path))
            recipes["billing_export"].actors = ("finance-bot",)
            trust = Trust(issuers)
            assert trust.preload() == []
            wire = MongoClient(uri, serverSelectionTimeoutMS=8000)
            try:
                tools = voyd_mcp.Tools(recipes, specs, issuers, trust.keys,
                                       wire[db])
                token = IDP.mint("alice", actor="support-bot",
                                 scope="notes:read", org="acme",
                                 roles=["support"],
                                 actor_claims={"roles": ["support"]})
                server = voyd_mcp.server(tools, lambda _ctx: token)
                listed, got = asyncio.run(agent(server, token))
            finally:
                wire.close()

        print("\n  1. the tools support-bot sees for alice:")
        for tool in listed:
            print(f"     {tool.name}  {json.dumps(tool.input_schema)}")
        assert [t.name for t in listed] == ["support_notes"]

        docs = [json_util.loads(json.dumps(d)) for d in got["documents"]]
        print("\n  2. support_notes(topic='refund') returned "
              f"{len(docs)} documents, citations {got['citations']}")
        assert [d["_id"] for d in docs] == [1, 4]

        keys = attest.load_public_keys(public)
        report = attest.verify_all(docs, keys)
        print(f"\n  3. receipts verified: {report.ok}")
        assert report.ok, [v.reason for v in report.verdicts]

        print("\n  The context an agent would hand its model:\n")
        for doc, cite in zip(docs, got["citations"]):
            print(f"     [{cite}] {doc['text']}")
        print("\n  HR's note and Globex's never reached the tool result; "
              "both are still on disk.")
        assert direct[db].notes.count_documents({}) == 4
    print()


if __name__ == "__main__":
    main()
