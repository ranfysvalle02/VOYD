"""`voyd-mcp` lists the recipes an identity may call and forwards the rest.

The adapter decides what to show and nothing else: a tool's schema is the
recipe's declared parameters, the list is filtered by the verified token,
and a call is one `$recipe` aggregate carrying the token in `comment`.
Everything here runs without a database -- the "wire" is a fake
collection that records the command and answers with documents or a
refusal -- and the last tests drive the same adapter through the MCP SDK,
in memory and over streamable HTTP with a real bearer header.
"""

from __future__ import annotations

import asyncio
import socket
import textwrap
import threading
import time

import pytest

pytest.importorskip("cryptography")

from pymongo.errors import OperationFailure

from voyd import mcp as voyd_mcp
from voyd.testing import TestIssuer
from voyd.wire.jwks import Trust

URL = "https://login.test"
AUD = "voyd://test"

POLICY = textwrap.dedent('''
    from voyd import deadline, guard, issuer, recipe

    issuer("{url}", audience="{aud}", jwks="{jwks}", connection_users=("*",))

    @guard("notes", scope="notes:read")
    class Notes:
        expire_at = deadline()

    @guard("tickets", delegation="required")
    class Tickets:
        expire_at = deadline()

    @guard("logs", delegation="forbidden")
    class Logs:
        expire_at = deadline()

    @recipe("note_search", collection="notes")
    def note_search(q: str = "refund", k: int = 5, boost: float = 1.0,
                    exact: bool = False, tags: list[str] | None = None,
                    since: str | None = None):
        """Notes matching a phrase, newest first.

        This paragraph is not part of the description.
        """
        return [{{"$match": {{"text": q, "exact": exact, "boost": boost,
                             "tags": tags, "since": since}}}},
                {{"$limit": k}}]

    @recipe("ticket_by_user", collection="tickets", samples={{"user": "u"}})
    def ticket_by_user(user: str):
        return [{{"$match": {{"user": user}}}}]

    @recipe("log_tail", collection="logs")
    def log_tail(n: int = 10):
        return [{{"$limit": n}}]
''')

STAMP = {"v": 1, "alg": "Ed25519", "kid": "k1", "digest": "abcdef0123456789"}


@pytest.fixture(scope="module")
def idp():
    return TestIssuer(URL, audience=AUD)


class Wire:
    """A stand-in for `db[collection]` on a connection to voyd-wire."""

    def __init__(self, answer=None, refuse: str | None = None):
        self.sent: list[tuple[str, list, dict]] = []
        self.answer = answer if answer is not None else []
        self.refuse = refuse

    def __getitem__(self, collection):
        wire = self

        class Collection:
            def aggregate(self, pipeline, **kw):
                wire.sent.append((collection, pipeline, kw))
                if wire.refuse:
                    raise OperationFailure(wire.refuse, 8000,
                                           {"ok": 0.0, "errmsg": wire.refuse})
                return iter([dict(d) for d in wire.answer])
        return Collection()


@pytest.fixture
def make(tmp_path, idp):
    def build(wire: Wire | None = None, **kw) -> voyd_mcp.Tools:
        jwks = idp.write_jwks(str(tmp_path / "jwks.json"))
        path = tmp_path / "voydfile.py"
        path.write_text(POLICY.format(url=URL, aud=AUD, jwks=jwks))
        recipes, specs, issuers = voyd_mcp.load(str(path))
        trust = Trust(issuers)
        assert trust.preload() == []
        return voyd_mcp.Tools(recipes, specs, issuers, trust.keys,
                              wire or Wire(), **kw)
    return build


# ---- the schema is the recipe's parameters --------------------------------

def test_each_parameter_type_becomes_its_json_schema(make):
    schema = voyd_mcp.input_schema(make().recipes["note_search"])
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    props = schema["properties"]
    assert props["q"] == {"type": "string", "default": "refund"}
    assert props["k"] == {"type": "integer", "default": 5}
    assert props["boost"] == {"type": "number", "default": 1.0}
    assert props["exact"] == {"type": "boolean", "default": False}
    assert props["tags"] == {"type": ["array", "null"],
                             "items": {"type": "string"}, "default": None}
    assert props["since"] == {"type": ["string", "null"], "default": None}
    assert "required" not in schema


def test_a_parameter_without_a_default_is_required(make):
    schema = voyd_mcp.input_schema(make().recipes["ticket_by_user"])
    assert schema["required"] == ["user"]
    assert "default" not in schema["properties"]["user"]


def test_the_description_is_the_first_paragraph_and_the_collection(make):
    text = voyd_mcp.description(make().recipes["note_search"])
    assert text.startswith("Notes matching a phrase, newest first.")
    assert "not part of the description" not in text
    assert "'notes'" in text and "voyd-wire" in text


# ---- the list is the identity's --------------------------------------------

def test_the_list_follows_the_token(make, idp):
    tools = make()
    names = lambda token: [r.name for r in tools.listed(token)]  # noqa: E731
    # Scope granted, actor present: notes and tickets, never logs.
    assert names(idp.mint("alice", actor="bot", scope="notes:read")) == [
        "note_search", "ticket_by_user"]
    # No scope: the notes recipe is not listed.
    assert names(idp.mint("alice", actor="bot")) == ["ticket_by_user"]
    # A user's own token, no actor: tickets require delegation.
    assert names(idp.mint("alice", scope="notes:read")) == ["note_search"]


def test_a_recipe_grant_narrows_the_list(make, idp):
    tools = make()
    tools.recipes["note_search"].actors = ("research-bot",)
    token = idp.mint("alice", actor="bot", scope="notes:read")
    assert [r.name for r in tools.listed(token)] == ["ticket_by_user"]
    ok = idp.mint("alice", actor="research-bot", scope="notes:read")
    assert "note_search" in [r.name for r in tools.listed(ok)]


def test_no_token_or_a_bad_one_lists_nothing(make, idp):
    tools = make()
    with pytest.raises(voyd_mcp.Denied, match="no bearer token"):
        tools.listed(None)
    stranger = TestIssuer(URL, audience=AUD)
    with pytest.raises(voyd_mcp.Denied, match="unknown_key"):
        tools.listed(stranger.mint("alice", actor="bot"))
    with pytest.raises(voyd_mcp.Denied, match="expired"):
        tools.listed(idp.mint("alice", actor="bot", ttl=-600))
    with pytest.raises(voyd_mcp.Denied, match="does not declare"):
        tools.listed(TestIssuer("https://evil.test").mint("alice"))


# ---- a call is one aggregate through the wire ------------------------------

def test_a_call_forwards_the_token_in_the_comment(make, idp):
    wire = Wire(answer=[{"_id": 1, "text": "hi"}])
    tools = make(wire)
    token = idp.mint("alice", actor="bot", scope="notes:read")
    got = tools.call(token, "note_search", {"q": "refund", "k": 2})
    assert wire.sent == [("notes", [{"$recipe": {
        "name": "note_search", "params": {"q": "refund", "k": 2}}}],
        {"comment": {"voyd": token}})]
    assert got.documents == [{"_id": 1, "text": "hi"}]


def test_a_call_without_a_valid_token_never_reaches_the_wire(make, idp):
    wire = Wire()
    tools = make(wire)
    for token in (None, "not.a.jwt", TestIssuer(URL, audience=AUD).mint("a")):
        with pytest.raises(voyd_mcp.Denied):
            tools.call(token, "note_search", {})
    assert wire.sent == []


def test_a_call_the_list_would_hide_is_still_the_wires_to_refuse(make, idp):
    """Listing is a convenience: the adapter forwards, the wire decides."""
    msg = "voyd-wire refuses this read on 'notes': scope notes:read"
    wire = Wire(refuse=msg)
    tools = make(wire)
    token = idp.mint("alice", actor="bot")
    assert "note_search" not in [r.name for r in tools.listed(token)]
    with pytest.raises(voyd_mcp.Denied) as refused:
        tools.call(token, "note_search", {})
    assert str(refused.value) == msg
    assert len(wire.sent) == 1


def test_stamps_pass_through_and_become_citations(make, idp):
    wire = Wire(answer=[{"_id": 1, "text": "a", "_voyd": dict(STAMP)},
                        {"_id": 2, "text": "b"}])
    got = make(wire).call(idp.mint("alice", actor="bot",
                                   scope="notes:read"), "note_search", {})
    assert got.documents[0]["_voyd"] == STAMP
    assert got.citations == ["voyd:k1:abcdef01"]


def test_a_read_over_the_bound_is_an_error_not_a_truncation(make, idp):
    token = idp.mint("alice", actor="bot", scope="notes:read")
    many = Wire(answer=[{"_id": i} for i in range(5)])
    with pytest.raises(voyd_mcp.Denied, match="more than 3 documents"):
        make(many, max_documents=3).call(token, "note_search", {})
    big = Wire(answer=[{"_id": 1, "text": "x" * 500}])
    with pytest.raises(voyd_mcp.Denied, match="more than 100 bytes"):
        make(big, max_bytes=100).call(token, "note_search", {})
    assert make(Wire(answer=[{"_id": i} for i in range(3)]),
                max_documents=3).call(token, "note_search", {}).documents


def test_an_unknown_tool_is_named(make, idp):
    with pytest.raises(voyd_mcp.Denied, match="no tool is named 'nope'"):
        make().call(idp.mint("a", actor="b"), "nope", {})


# ---- through the MCP SDK ---------------------------------------------------

def test_an_mcp_client_lists_and_calls_in_memory(make, idp):
    pytest.importorskip("mcp")
    from mcp import Client

    wire = Wire(answer=[{"_id": 1, "text": "a", "_voyd": dict(STAMP)}])
    tools = make(wire)
    token = idp.mint("alice", actor="bot", scope="notes:read")

    async def run(tok):
        async with Client(voyd_mcp.server(tools, lambda _ctx: tok)) as c:
            listed = await c.list_tools()
            called = await c.call_tool("note_search", {"q": "refund"})
            refused = await c.call_tool("nope", {})
            return listed, called, refused

    listed, called, refused = asyncio.run(run(token))
    assert [t.name for t in listed.tools] == ["note_search", "ticket_by_user"]
    note = listed.tools[0]
    assert note.input_schema["properties"]["k"]["type"] == "integer"
    assert not called.is_error
    assert called.structured_content["citations"] == ["voyd:k1:abcdef01"]
    assert called.structured_content["documents"][0]["_voyd"] == STAMP
    assert refused.is_error and "nope" in refused.content[0].text
    assert wire.sent[0][2] == {"comment": {"voyd": token}}

    async def bad():
        async with Client(voyd_mcp.server(tools, lambda _ctx: None)) as c:
            with pytest.raises(Exception, match="no bearer token"):
                await c.list_tools()
            got = await c.call_tool("note_search", {})
            assert got.is_error and "no bearer token" in got.content[0].text
    asyncio.run(bad())


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_over_http_the_bearer_token_is_the_identity(make, idp):
    pytest.importorskip("mcp")
    import httpx2
    import uvicorn
    from mcp import Client
    from mcp.client.streamable_http import streamable_http_client

    wire = Wire(answer=[{"_id": 7}])
    tools = make(wire)
    port = _free_port()
    srv = uvicorn.Server(uvicorn.Config(
        voyd_mcp.http_app(tools, host="127.0.0.1", port=port),
        host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    until = time.monotonic() + 10
    while not srv.started and time.monotonic() < until:
        time.sleep(0.05)
    url = f"http://127.0.0.1:{port}/mcp"
    token = idp.mint("alice", actor="bot")          # no notes:read
    try:
        async def run():
            headers = {"Authorization": f"Bearer {token}"}
            async with httpx2.AsyncClient(headers=headers) as http:
                async with Client(streamable_http_client(
                        url, http_client=http)) as c:
                    listed = await c.list_tools()
                    called = await c.call_tool("ticket_by_user",
                                               {"user": "alice"})
                    return listed, called

        listed, called = asyncio.run(run())
        assert [t.name for t in listed.tools] == ["ticket_by_user"]
        assert called.structured_content["documents"] == [{"_id": 7}]
        assert wire.sent[-1][2] == {"comment": {"voyd": token}}

        async def anonymous():
            async with httpx2.AsyncClient() as http:
                got = await http.post(url, json={
                    "jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                    headers={"Accept": "application/json, text/event-stream"})
                return got.status_code
        assert asyncio.run(anonymous()) == 401
    finally:
        srv.should_exit = True
        thread.join(timeout=10)
