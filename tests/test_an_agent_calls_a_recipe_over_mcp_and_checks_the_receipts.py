"""A recipe called as an MCP tool comes back through the real boundary, signed.

`voyd-wire` in a subprocess in front of a real deployment, `voyd-mcp`'s
server in process, and the MCP SDK's client talking to it in memory. The
token the client holds is the only identity: the wire verifies it,
narrows by tenant and audience, stamps what it serves, and the tool
result's receipts verify with `voyd.attest`.

The first test is pure and pins the one piece of the wire this needed:
a delegated `$recipe` is pinned to the token's tenant *after* it is
expanded, since before that there is no pipeline to pin into.
"""

from __future__ import annotations

import asyncio
import json
import textwrap

import pytest

pytest.importorskip("cryptography")

from voyd.engine.admission import AdmissionSpec
from voyd.wire.codec import decode_sections, encode_op_msg
from voyd.wire.policy import Guard, pin_expanded, pin_tenant

URL = "https://login.test"
AUD = "voyd://test"


def test_a_delegated_recipe_is_pinned_to_the_tenant_after_it_expands():
    recipe = {"aggregate": "notes", "pipeline": [
        {"$recipe": {"name": "r", "params": {}}}], "$db": "d"}
    assert pin_tenant(recipe, "org", "acme") == (recipe, None)

    guards = {"notes": Guard(AdmissionSpec(collection="notes", tenant="org"))}
    expanded = {"aggregate": "notes", "pipeline": [
        {"$match": {"topic": "refund"}}, {"$limit": 5}], "$db": "d"}
    raw = encode_op_msg(1, 0, 0, expanded)
    claims = {"user": "alice", "tenant": "acme",
              "principal": {"user": "alice", "tenant": "acme"},
              "actor": {"user": "bot", "tenant": None}, "delegated": True}
    _, head, refused = pin_expanded(raw, 1, 0, decode_sections(raw), guards,
                                    claims, False)
    assert refused is None
    assert head[1]["pipeline"][0] == {"$match": {"topic": "refund",
                                                 "org": "acme"}}
    # A plain read is left alone: the pin is the token's to impose.
    same, _, none = pin_expanded(raw, 1, 0, decode_sections(raw), guards,
                                 None, False)
    assert same == raw and none is None


POLICY = textwrap.dedent('''
    from voyd import guard, issuer, recipe, restricted_to, tenant

    issuer("{url}", audience="{aud}", jwks="{jwks}", connection_users=("*",),
           roles="roles", tenant="org", actor_roles="act.roles")

    @guard("notes", scope="notes:read", recipes_only=True, attest=True)
    class Notes:
        org      = tenant()
        audience = restricted_to("roles")

    @recipe("support_notes", collection="notes")
    def support_notes(topic: str = "refund", k: int = 5):
        """Support notes about a topic, oldest first."""
        return [{{"$match": {{"topic": topic}}}}, {{"$sort": {{"_id": 1}}}},
                {{"$limit": k}}]
''')


@pytest.mark.needs_mongo
def test_an_mcp_tool_call_returns_stamped_documents_that_verify(
        boundary, direct, database, tmp_path):
    pytest.importorskip("mcp")
    from bson import json_util
    from mcp import Client
    from pymongo import MongoClient

    from voyd import attest
    from voyd import mcp as voyd_mcp
    from voyd.testing import TestIssuer
    from voyd.wire.jwks import Trust

    idp = TestIssuer(URL, audience=AUD)
    jwks = idp.write_jwks(str(tmp_path / "jwks.json"))
    private, public, _ = attest.generate()
    key = tmp_path / "attest.pem"
    key.write_bytes(private)
    policy = POLICY.format(url=URL, aud=AUD, jwks=jwks)
    path = tmp_path / "voydfile.py"
    path.write_text(policy)
    direct[database].notes.insert_many([
        {"_id": 1, "org": "acme", "audience": ["support"], "topic": "refund",
         "text": "30 days"},
        {"_id": 2, "org": "acme", "audience": ["hr"], "topic": "refund",
         "text": "fraud case"},
        {"_id": 3, "org": "globex", "audience": ["support"],
         "topic": "refund", "text": "portal"},
    ])
    wire = boundary(policy, "--attest-key", str(key))
    recipes, specs, issuers = voyd_mcp.load(str(path))
    trust = Trust(issuers)
    assert trust.preload() == []
    client: MongoClient = MongoClient(wire.uri, serverSelectionTimeoutMS=8000)
    tools = voyd_mcp.Tools(recipes, specs, issuers, trust.keys,
                           client[database])

    def run(token):
        async def go():
            async with Client(voyd_mcp.server(tools, lambda _c: token)) as c:
                return (await c.list_tools(),
                        await c.call_tool("support_notes", {"k": 5}))
        return asyncio.run(go())

    try:
        token = idp.mint("alice", actor="bot", scope="notes:read", org="acme",
                         roles=["support"], actor_claims={"roles": ["support"]})
        listed, called = run(token)
        assert [t.name for t in listed.tools] == ["support_notes"]
        assert not called.is_error, called.content
        body = called.structured_content
        docs = [json_util.loads(json.dumps(d)) for d in body["documents"]]
        assert [d["_id"] for d in docs] == [1]
        assert body["citations"] == [attest.cite(docs[0])]
        assert json.loads(called.content[0].text) == body
        report = attest.verify_all(docs, attest.load_public_keys(public))
        assert report.ok, [v.reason for v in report.verdicts]

        # The wire refuses what the adapter would not have listed.
        wrong = idp.mint("alice", actor="bot", org="acme", roles=["support"])
        listed, called = run(wrong)
        assert listed.tools == []
        assert called.is_error
        assert "notes:read" in called.content[0].text
    finally:
        client.close()
    assert direct[database].notes.count_documents({}) == 3
