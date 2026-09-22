"""What the deployment can do is asked, never inferred.

`capabilities.py` is 130 lines that decide which tier of search every read
above them uses, and its whole reason for existing is that an inference --
Atlas-ness from a connection string, a stage from a version number -- is
wrong silently and stays wrong until somebody thinks to check.

Both inferences are described in its docstrings. Here they are as tests,
because a regression that is only described is a regression that can
happen.

No database. The probes are three commands and their failure modes, so
the honest test is a fake that answers the way each deployment answers --
which also means these run in milliseconds and cannot flake.
"""

from __future__ import annotations

import pytest
from pymongo.errors import OperationFailure

from voyd.engine.capabilities import Capabilities, detect


class FakeCursor:
    def __init__(self, rows):
        self.rows = rows

    async def to_list(self, _n):
        return self.rows


class FakeCollection:
    """Answers an aggregate the way a given deployment would.

    `stages` names the pipeline stages this deployment understands.
    Anything else raises `OperationFailure`, which is what a real server
    sends back for an unrecognised stage name.
    """

    def __init__(self, stages):
        self.stages = stages
        self.asked = []

    async def aggregate(self, pipeline):
        first = next(iter(pipeline[0]))
        self.asked.append(first)
        if first not in self.stages:
            raise OperationFailure(f"Unrecognized pipeline stage name: {first}")
        return FakeCursor([])


class FakeDb:
    def __init__(self, stages):
        self.collection = FakeCollection(stages)

    def __getitem__(self, _name):
        return self.collection


class FakeAdmin:
    def __init__(self, version, hello):
        self.version = version
        self.hello = hello

    async def command(self, name, *_a, **_k):
        if name == "buildInfo":
            return {"versionArray": list(self.version) + [0]}
        if name == "hello":
            return self.hello
        raise OperationFailure(name)


class FakeClient:
    def __init__(self, version, hello):
        self.admin = FakeAdmin(version, hello)


REPLICA_SET = {"setName": "rs0"}
SHARDED = {"msg": "isdbgrid"}
STANDALONE: dict = {}

SEARCHLESS = ("$sort", "$limit", "$match")
ATLAS_80 = (*SEARCHLESS, "$listSearchIndexes", "$rankFusion")
ATLAS_OLD = (*SEARCHLESS, "$listSearchIndexes")


# --------------------------------------------------------------------------
# The tier, which is what everything above this module branches on.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("search,fusion,tier", [
    (False, False, "cosine"),
    (True, False, "vector"),
    (True, True, "hybrid"),
    (False, True, "cosine"),   # no mongot: fusion is moot, not a promotion
])
def test_the_tier_is_the_worst_honest_answer(search, fusion, tier):
    caps = Capabilities(version=(8, 0, 0), search=search, rank_fusion=fusion)
    assert caps.search_tier == tier


def test_describe_says_the_tier_rather_than_the_flags():
    caps = Capabilities(version=(8, 2, 1), search=True, rank_fusion=True,
                        change_streams=True)
    assert caps.describe() == ("MongoDB 8.2.1 | search=hybrid "
                               "| change_streams=True")


def test_an_unprobed_deployment_describes_itself_as_unknown():
    assert "MongoDB unknown" in Capabilities().describe()


# --------------------------------------------------------------------------
# The two bugs this module's docstrings record. Both were silent for months.
# --------------------------------------------------------------------------

async def test_atlas_is_not_inferred_from_the_connection_string():
    """The original bug: Atlas support was `"mongodb.net" in uri`, so Atlas
    Local on `mongodb://localhost` was "not Atlas" and `$vectorSearch`
    never ran locally at all. Nothing here may consult a hostname -- the
    only evidence is what the server answers."""
    caps = await detect(FakeClient((8, 2), REPLICA_SET), FakeDb(ATLAS_80))
    assert caps.search and caps.search_tier == "hybrid"


async def test_an_eight_zero_deployment_is_not_denied_rank_fusion():
    """The second bug, and it was wrong by one minor release: a hardcoded
    `(8, 1)` floor meant every 8.0 deployment was probed, found
    search-capable, told it could not fuse ranks, and silently served the
    worse tier. `$rankFusion` exists from 8.0. Asking the stage is the
    only thing that cannot go stale."""
    caps = await detect(FakeClient((8, 0), REPLICA_SET), FakeDb(ATLAS_80))
    assert caps.rank_fusion, "8.0 has the stage; a version floor said it did not"
    assert caps.search_tier == "hybrid"


async def test_a_version_number_alone_never_grants_a_capability():
    """The inverse, which is the one a floor could never get right: a
    deployment new enough to have the stage but without mongot."""
    caps = await detect(FakeClient((8, 2), REPLICA_SET), FakeDb(SEARCHLESS))
    assert not caps.search and not caps.rank_fusion
    assert caps.search_tier == "cosine"


# --------------------------------------------------------------------------
# Each probe's failure mode.
# --------------------------------------------------------------------------

async def test_a_plain_mongod_degrades_to_cosine_rather_than_failing():
    """Correct but linear is the documented fallback. It has to be a
    fallback and not an exception, or a laptop cannot run this at all."""
    caps = await detect(FakeClient((7, 0), STANDALONE), FakeDb(SEARCHLESS))
    assert caps == Capabilities(version=(7, 0, 0), search=False,
                                rank_fusion=False, change_streams=False)


async def test_fusion_is_not_probed_when_there_is_no_search():
    """`search and await _supports_rank_fusion(db)` short-circuits. Worth
    pinning: the probe costs an aggregation per connect, and running it
    where it cannot matter is a round trip for an answer already known."""
    db = FakeDb(SEARCHLESS)
    await detect(FakeClient((8, 2), REPLICA_SET), db)
    assert "$rankFusion" not in db.collection.asked


async def test_search_without_fusion_is_the_middle_tier():
    caps = await detect(FakeClient((8, 0), REPLICA_SET), FakeDb(ATLAS_OLD))
    assert caps.search and not caps.rank_fusion
    assert caps.search_tier == "vector"


@pytest.mark.parametrize("hello,expected", [
    (REPLICA_SET, True),
    (SHARDED, True),
    (STANDALONE, False),
], ids=["replica-set", "sharded", "standalone"])
async def test_change_streams_follow_the_topology_not_a_trial_stream(
        hello, expected):
    """A standalone has no oplog, so `watch()` cannot work. Reading the
    topology is cheaper and clearer than opening a stream to watch it
    fail -- and it cannot leave a cursor behind when it does."""
    caps = await detect(FakeClient((8, 2), hello), FakeDb(ATLAS_80))
    assert caps.change_streams is expected


async def test_a_deployment_that_refuses_hello_is_not_assumed_streamable():
    """Fails closed. An unanswered question is not a yes."""
    client = FakeClient((8, 2), REPLICA_SET)

    async def refuse(name, *_a, **_k):
        if name == "hello":
            raise OperationFailure("no")
        return {"versionArray": [8, 2, 0]}

    client.admin.command = refuse
    caps = await detect(client, FakeDb(ATLAS_80))
    assert caps.change_streams is False


def test_capabilities_are_frozen_so_a_probe_cannot_be_edited_later():
    """Everything above this module branches on these flags. A probed
    answer that a caller could quietly upgrade would be the inference
    problem again, one layer up."""
    caps = Capabilities(version=(8, 2), search=False)
    with pytest.raises(Exception):
        caps.search = True          # type: ignore[misc]
