"""`auto_embed`: the index owns the vector, and the query cannot go around it.

`EmbeddedWith` refuses a **document** whose stored vector came from the wrong
model, and `rules.py` has the measurement that makes it worth having: two
generations of one vendor's model at the same width, identical text scoring
-0.053 and unrelated text scoring +0.301. A model swap does not degrade
ranking, it inverts it.

Nothing refused the **query**. That is the same failure and it is worse,
because it is one message rather than one row: a client-computed vector
compared against an index mongot built from text does not error, it returns a
confident score for every candidate. The page comes back full, ranked,
plausible and meaningless.

`auto_embed` removes the client-side embedder that makes that possible --
nothing in the application ever computes a vector, so nothing can drift. A
client still sending `queryVector` has put the embedder back, through a
driver that never read the policy file, which is exactly the caller the wire
boundary exists for. These tests are that refusal, plus the two ways the
declaration itself can be wrong.

**Deliberately almost all pure.** One `$vectorSearch` body and a dict is
enough to decide this, with no database, no Atlas and no index -- which is
the same property that let refusal move to a wire in the first place. Only
the last two tests need a `mongod`, and none needs an embedding model.
"""

from __future__ import annotations

import subprocess
import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import voyd_wire as w  # noqa: E402

from voyd.declare import OPTIONS, load  # noqa: E402

from .conftest import free_port, mongo_host  # noqa: E402

POLICY = """
from voyd import guard, deadline, revocable, tenant, auto_embed

@guard("notes", on_delete="revoke")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()
    body      = auto_embed("voyage-4")
"""


def write(tmp_path, body: str) -> str:
    path = tmp_path / "voydfile.py"
    path.write_text(body)
    return str(path)


# --------------------------------------------------------------------------
# The declaration
# --------------------------------------------------------------------------

def test_the_policy_file_declares_who_embeds(tmp_path):
    """One word in a class body, and the boundary knows the index owns it."""
    load(write(tmp_path, POLICY))
    assert OPTIONS["notes"]["auto_embed"] == {"body": "voyage-4"}
    assert w._embeds_from(OPTIONS) == {"notes": "voyage-4"}


def test_two_declarations_of_the_model_must_agree(tmp_path):
    """`embedded_with` and `auto_embed` naming different models is fatal.

    Not a warning. One says *refuse any vector not from voyage-4*, the other
    says *the server will produce them with voyage-3.5*, so every document
    the index embeds would be refused by the rule sitting beside it and the
    collection would read as empty. A policy file that produces an empty
    collection should say so when it is read.
    """
    with pytest.raises(ValueError, match="embedded_with"):
        load(write(tmp_path, """
from voyd import guard, deadline, embedded_with, auto_embed

@guard("notes")
class Notes:
    expire_at = deadline()
    model     = embedded_with("voyage-4")
    body      = auto_embed("voyage-3.5")
"""))


def test_sealed_and_embedded_cannot_be_written_on_one_field(tmp_path):
    """The contradiction the library needs a runtime check for is, here,
    not expressible -- and that is the argument for the class body.

    `Engine._refuse_sealed_autoembed` compares a keyring's sealed fields
    against a search spec's text paths. Those are two objects naming one
    path, so they can disagree, and it raises at connect time when they do.
    In a class body the path *is* the attribute name, so the conflict
    cannot be written: Python binds the name once and the second
    declaration wins.

    This test exists because the obvious thing to do here was add a check,
    and a check that can never fire is code pretending to be a guarantee.
    Asserting the shape instead is honest and it keeps somebody from
    "fixing" the missing check later.
    """
    load(write(tmp_path, """
from voyd import guard, deadline, tenant, sealed, auto_embed

@guard("notes")
class Notes:
    expire_at = deadline()
    tenant_id = tenant()
    text      = sealed()
    text      = auto_embed("voyage-4")
"""))
    assert OPTIONS["notes"]["sealed"] == ()
    assert OPTIONS["notes"]["auto_embed"] == {"text": "voyage-4"}


def test_sealing_one_field_and_embedding_another_is_allowed(tmp_path):
    """Sealing the notes and embedding the title is lossy, not wrong.

    The boundary has no business forbidding it, and `Engine` says so too.
    """
    load(write(tmp_path, """
from voyd import guard, deadline, tenant, sealed, auto_embed

@guard("notes")
class Notes:
    expire_at = deadline()
    tenant_id = tenant()
    text      = sealed()
    title     = auto_embed("voyage-4")
"""))
    assert OPTIONS["notes"]["sealed"] == ("text",)
    assert OPTIONS["notes"]["auto_embed"] == {"title": "voyage-4"}


# --------------------------------------------------------------------------
# The refusal, with no database anywhere near it
# --------------------------------------------------------------------------

EMBEDS = {"notes": "voyage-4"}


def vector_search(collection: str, **stage) -> dict:
    return {"aggregate": collection, "pipeline": [{"$vectorSearch": stage}]}


def test_a_client_vector_on_a_server_owned_index_is_refused():
    body = vector_search("notes", queryVector=[0.1] * 8, limit=10)
    assert w.client_vector_on_server_index(body, EMBEDS) == "notes"


def test_query_text_is_the_form_that_passes():
    """The whole point: send the text and let the index embed it."""
    body = vector_search("notes", query="what is the fault code", limit=10)
    assert w.client_vector_on_server_index(body, EMBEDS) is None


def test_a_collection_the_server_does_not_embed_is_untouched():
    """A client vector is correct on an ordinary vector index.

    The control that stops this refusing everything: without it the test
    above would pass for a boundary that had simply banned
    `$vectorSearch`.
    """
    body = vector_search("other", queryVector=[0.1] * 8, limit=10)
    assert w.client_vector_on_server_index(body, EMBEDS) is None


def test_nothing_is_refused_when_nothing_declared_auto_embed():
    body = vector_search("notes", queryVector=[0.1] * 8, limit=10)
    assert w.client_vector_on_server_index(body, {}) is None


def test_an_ordinary_read_is_not_a_vector_search():
    assert w.client_vector_on_server_index(
        {"find": "notes", "filter": {}}, EMBEDS) is None
    assert w.client_vector_on_server_index(
        {"aggregate": "notes", "pipeline": [{"$match": {"a": 1}}]},
        EMBEDS) is None


def test_the_stage_is_found_wherever_it_sits_in_the_pipeline():
    """`$vectorSearch` must be first in a real pipeline, but this must not
    depend on that -- a boundary that only inspected stage zero would be
    one `$match` away from being bypassed."""
    body = {"aggregate": "notes", "pipeline": [
        {"$match": {"tenant_id": "acme"}},
        {"$vectorSearch": {"queryVector": [0.1] * 8, "limit": 10}},
    ]}
    assert w.client_vector_on_server_index(body, EMBEDS) == "notes"


def test_a_malformed_pipeline_is_not_a_crash():
    """Bytes arrive from the wire. This is handed whatever was in them."""
    for pipeline in (None, "not a list", [None], [{"$vectorSearch": "no"}], []):
        body = {"aggregate": "notes", "pipeline": pipeline}
        assert w.client_vector_on_server_index(body, EMBEDS) is None


def test_the_refusal_names_the_model_and_the_remedy():
    """An error that does not say what to do instead is a dead end."""
    raw = w.encode_op_msg(1, 0, 0, vector_search(
        "notes", queryVector=[0.1] * 8, limit=10))
    answer = w.refuse_client_vector(raw, 1, 1, EMBEDS)
    assert answer is not None
    reply = w.decode_op_msg(answer)[1]
    assert reply["ok"] == 0.0
    assert "voyage-4" in reply["errmsg"]
    assert "$vectorSearch.query" in reply["errmsg"], (
        "the refusal has to name the form that works, or a caller reads it "
        "as 'vector search is unavailable' and gives up")


# --------------------------------------------------------------------------
# End to end, through a driver that never read the policy file
#
# Marked `needs_mongo`, which everything above deliberately is not. CI runs
# the pure half in a step with no database at all -- so if the refusal above
# ever grows a dependency on one, that step goes red and the architecture
# has changed, which is the point of keeping the two halves separable.
# --------------------------------------------------------------------------

pymongo = pytest.importorskip("pymongo")


@pytest.fixture
def wired(tmp_path):
    """A boundary from the auto_embed policy. Yields (client, db name)."""
    import socket
    import time

    port = free_port()
    name = f"voyd_test_autoembed_{uuid.uuid4().hex[:8]}"
    proc = subprocess.Popen(
        [sys.executable, "tools/voyd_wire.py", "--config",
         write(tmp_path, POLICY), "--listen", str(port),
         "--target", mongo_host()],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    direct = pymongo.MongoClient(f"mongodb://{mongo_host()}/"
                                 "?directConnection=true")
    try:
        until = time.monotonic() + 20
        while time.monotonic() < until:
            if proc.poll() is not None:
                pytest.fail(f"voyd-wire exited early:\n{proc.stdout.read()}")
            try:
                with socket.create_connection(("127.0.0.1", port), 0.2):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            pytest.fail("voyd-wire never started listening")
        client = pymongo.MongoClient(
            f"mongodb://localhost:{port}/?directConnection=true",
            serverSelectionTimeoutMS=8000)
        client[name].notes.insert_one(
            {"tenant_id": "acme", "body": "the fault code is P0301"})
        try:
            yield client, name
        finally:
            client.close()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        direct.drop_database(name)
        direct.close()


@pytest.mark.needs_mongo
def test_a_plain_driver_cannot_send_its_own_vector(wired):
    """No VOYD import, no policy file read, no way to know. Refused anyway.

    This is the claim the library version cannot make. In-process,
    `SearchEngine._vector_stage` raises for a caller who passed a vector to
    an `auto_embed` collection -- which protects the callers that went
    through the library. A notebook, a Node service and Compass all send
    these bytes and never see that code.
    """
    client, name = wired
    with pytest.raises(pymongo.errors.OperationFailure) as caught:
        list(client[name].notes.aggregate([{"$vectorSearch": {
            "index": "engine_vector_index", "path": "embedding",
            "queryVector": [0.1] * 1024, "numCandidates": 100, "limit": 10}}]))
    said = str(caught.value)
    assert "voyd-wire" in said and "voyage-4" in said


@pytest.mark.needs_mongo
def test_the_boundary_says_who_embeds_at_startup(tmp_path):
    """An operator debugging "why is my $vectorSearch an error" should find
    the answer in the first screen of output rather than in a source file."""
    import time

    port = free_port()
    proc = subprocess.Popen(
        [sys.executable, "tools/voyd_wire.py", "--config",
         write(tmp_path, POLICY), "--listen", str(port),
         "--target", mongo_host()],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        until, lines = time.monotonic() + 20, []
        while time.monotonic() < until:
            line = proc.stdout.readline()
            if not line:
                break
            lines.append(line)
            if "connect any driver" in line:
                break
        said = "".join(lines)
        assert "embedded by the server" in said
        assert "auto_embed='voyage-4'" in said
        assert "queryVector" in said
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.mark.needs_mongo
def test_ordinary_reads_are_still_refused_the_ordinary_way(wired):
    """The control. `auto_embed` must not have replaced admission with
    itself: a normal find still comes back, and still comes back filtered."""
    client, name = wired
    assert [d["body"] for d in client[name].notes.find({"tenant_id": "acme"})] \
        == ["the fault code is P0301"]
    assert list(client[name].notes.find({"tenant_id": "globex"})) == []
