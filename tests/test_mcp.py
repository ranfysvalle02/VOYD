"""The MCP surface: five tools, and no way to delete anything.

The tool *descriptions* are load-bearing -- they are the only documentation a
model reads before deciding whether to call something -- so the shape of the
surface is asserted here rather than left to drift.

No MongoDB and no network: the client is pointed at a stub transport.
"""

from __future__ import annotations

import pytest

pytest.importorskip("mcp")

from voyd.mcp import MAX_BATCH, VoydClient, build_server


class Recorder:
    """Stands in for a VOYD deployment: records calls, returns canned JSON."""

    def __init__(self):
        self.calls: list[tuple] = []

    async def open_scope(self, ttl_seconds=None, passcode=None):
        self.calls.append(("open_scope", ttl_seconds, passcode))
        return {"token": "tok", "expire_at": "2026-09-19T00:00:00+00:00"}

    async def add(self, token, documents, passcode=None):
        self.calls.append(("add", token, len(documents), passcode))
        return {"added": [{"doc_id": "d1"}], "index": {"total": len(documents)}}

    async def search(self, token, query, limit=5, passcode=None):
        self.calls.append(("search", token, query, limit, passcode))
        return {"matches": []}

    async def describe(self, token, passcode=None):
        self.calls.append(("describe", token))
        return {"index": {"total": 0}}

    async def forget(self, token, doc_ids=None, reason="revoked"):
        self.calls.append(("forget", token, doc_ids, reason))
        return {"forgotten": 1, "unreachable_since": "2026-09-18T00:00:00+00:00"}


@pytest.fixture
def server():
    rec = Recorder()
    return build_server(rec), rec


async def tools(server) -> dict:
    return {t.name: t for t in await server.list_tools()}


# ---- the surface -------------------------------------------------------

async def test_the_surface_is_the_five_tools_and_nothing_else(server):
    srv, _ = server
    assert set((await tools(srv)).keys()) == {
        "open_scope", "add", "search", "describe", "forget"}


async def test_no_tool_hands_the_agent_a_cleanup_obligation(server):
    """The invariant, stated as the property rather than as a headcount.

    This assertion used to be "the surface is exactly these four names",
    which froze the surface instead of protecting the rule -- adding
    ``forget`` read as a violation when it is the rule being kept. What must
    never appear is a verb that makes the agent responsible for reclaiming
    something, because an agent that has to remember to clean up is the
    failure this product exists to remove.
    """
    srv, _ = server
    names = (await tools(srv)).keys()
    banned = ("delete", "remove", "drop", "clear", "purge", "destroy",
              "cleanup", "collect")
    assert not any(w in n for n in names for w in banned)


async def test_forget_is_offered_as_reachability_not_deletion(server):
    """A model reads the description and nothing else, so the description is
    where the promise is either kept or broken. It must not imply that
    calling this reclaims anything, and it must not imply a follow-up."""
    srv, _ = server
    desc = (await tools(srv))["forget"].description.lower()
    assert "not a delete" in desc or "nothing is removed" in desc
    assert "unreachable" in desc or "stop coming back" in desc
    # The agent must be told it owes nothing afterwards.
    assert "follow-up" in desc or "cleanup" in desc or "deadline" in desc


async def test_forget_passes_the_reason_through(server):
    """``reason`` is the audit trail; dropping it silently would make the
    endpoint's record useless."""
    srv, rec = server
    await srv.call_tool("forget", {"token": "tok", "doc_ids": ["d1"],
                                   "reason": "user retracted it"})
    assert ("forget", "tok", ["d1"], "user retracted it") in rec.calls


async def test_every_tool_tells_the_model_what_it_is_for(server):
    """A tool with a thin description does not get called correctly, and the
    model cannot read the source."""
    srv, _ = server
    for name, tool in (await tools(srv)).items():
        assert tool.description and len(tool.description) > 80, name


async def test_open_scope_advertises_the_deadline(server):
    """The one thing a model must understand about this product is that the
    scope goes away by itself."""
    srv, _ = server
    desc = (await tools(srv))["open_scope"].description.lower()
    assert "ttl_seconds" in desc
    assert any(w in desc for w in ("deletes itself", "deadline", "expire"))


async def test_add_warns_that_indexing_is_asynchronous(server):
    """Otherwise a model adds 50 documents, searches immediately, gets two
    hits, and concludes the scope is empty."""
    srv, _ = server
    desc = (await tools(srv))["add"].description.lower()
    assert "background" in desc or "asynchronous" in desc


# ---- behaviour ---------------------------------------------------------

async def test_open_scope_defaults_to_a_day_not_to_forever(server):
    """The default has to be an expiry. A default of 'permanent' is precisely
    how vector namespaces leak in the first place."""
    srv, rec = server
    await srv.call_tool("open_scope", {})
    assert rec.calls == [("open_scope", 86400, None)]


async def test_add_rejects_an_oversized_batch_before_the_network(server):
    srv, rec = server
    out = await srv.call_tool(
        "add", {"token": "t", "documents": [{"text": "x"}] * (MAX_BATCH + 1)})
    assert "error" in str(out)
    assert rec.calls == [], "must not have been sent"


async def test_add_rejects_an_empty_batch(server):
    srv, rec = server
    out = await srv.call_tool("add", {"token": "t", "documents": []})
    assert "error" in str(out)
    assert rec.calls == []


async def test_search_passes_the_passcode_through(server):
    """A guarded scope is unusable from an agent if the passcode cannot ride
    along with the query."""
    srv, rec = server
    await srv.call_tool("search", {"token": "t", "query": "q", "passcode": "p"})
    assert rec.calls == [("search", "t", "q", 5, "p")]


async def test_add_passes_the_passcode_through(server):
    srv, rec = server
    await srv.call_tool(
        "add", {"token": "t", "documents": [{"text": "x"}], "passcode": "p"})
    assert rec.calls == [("add", "t", 1, "p")]


async def test_no_passcode_is_passed_as_none_not_an_empty_string(server):
    """An empty passcode must not look like a supplied one to the guard."""
    srv, rec = server
    await srv.call_tool("search", {"token": "t", "query": "q"})
    assert rec.calls[0][-1] is None


# ---- the client --------------------------------------------------------

def test_the_client_never_puts_the_key_in_a_url():
    """Keys in query strings end up in logs, proxies and referrers."""
    c = VoydClient("http://acme.localhost:8000/", "voyd_secret")
    assert c.base_url == "http://acme.localhost:8000", "trailing slash trimmed"
    assert c._headers()["Authorization"] == "Bearer voyd_secret"
    assert "voyd_secret" not in c.base_url


def test_the_passcode_travels_as_a_header_not_a_query_param():
    c = VoydClient("http://x", "k")
    assert c._headers("hunter2")["X-Passcode"] == "hunter2"
    assert "X-Passcode" not in c._headers()
