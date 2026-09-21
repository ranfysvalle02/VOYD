"""A vector is a copy of the text, so forgetting has to reach it too.

The claim this file exists for, and it was implemented twice and tested
never. An embedding is not a pointer to a document -- it is a lossy
encoding *of* it, close enough that inversion research keeps recovering
recognisable source text from one. So a document that is refused while its
vector stays on disk has not been forgotten; it has been made inconvenient
to read. The next `$vectorSearch` still ranks against a copy of it, and the
nearest-neighbour structure of the index still describes it.

Two paths write that erasure and they are two different pieces of code --
`Admission.revoke` in `admission/marks.py` and `_forget_pipeline` in
`tools/voyd_wire.py`. The wire one carries a docstring promising "one
definition, used by every verb this boundary rewrites, because two
spellings that produced different rows would be the drift this package is
about". They *are* two spellings. Nothing checked they agreed, so the first
test here is that they do.

What this file does not cover is the `auto_embed` case, where the index
owns the vector and there is no field to null -- see
`test_the_index_owned_vector_dies_with_its_source` at the bottom, which
needs a real Atlas cluster because nothing else registers an embedding
model.
"""

from __future__ import annotations

import subprocess
import sys
import time
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path

import pytest

from voyd.engine.time import now

from .conftest import free_port, mongo_host

pymongo = pytest.importorskip("pymongo")
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

PAST = now() - timedelta(days=1)
VEC = [0.1, 0.2, 0.3, 0.4]

POLICY = """
from voyd import guard, deadline, revocable

@guard("notes", on_delete="revoke")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
"""


# --- the two spellings have to agree ---------------------------------------

def test_both_erasure_paths_null_every_declared_derived_field():
    """`marks.py` and `voyd_wire.py` each build this update separately.

    The wire one's docstring claims "one definition, used by every verb",
    and that is true *within* the wire. Across the two front doors there are
    two definitions, and a derived field destroyed by one and left by the
    other is a vector that survives its document depending on which door the
    erasure came through.
    """
    import voyd_wire as w

    from voyd.engine.admission.rules import Deadline, revoked
    from voyd.engine.admission.spec import AdmissionSpec

    spec = AdmissionSpec("notes", derived_fields=("embedding", "summary_vec"),
                         rules=(Deadline(at_field="expire_at"),
                                revoked("forgotten")))
    stage = w._forget_pipeline(spec, "erased")[0]["$set"]

    for name in spec.derived_fields:
        assert name in stage, (
            f"{name!r} is declared derived and the wire's erasure does not "
            f"destroy it -- the encoding outlives the fact it encodes")
        assert stage[name] is None


def test_a_collection_with_no_derived_fields_is_left_alone():
    """The default is `("embedding",)`, and a policy may declare none. An
    erasure that invented a null field would be writing schema."""
    import voyd_wire as w

    from voyd.engine.admission.rules import Deadline, revoked
    from voyd.engine.admission.spec import AdmissionSpec

    spec = AdmissionSpec("notes", derived_fields=(),
                         rules=(Deadline(at_field="expire_at"),
                                revoked("forgotten")))
    stage = w._forget_pipeline(spec, "erased")[0]["$set"]
    assert set(stage) == {"forgotten", "expire_at"}


# --- through the library, against a real mongod ----------------------------

@pytest.fixture
async def engine():
    import uuid

    from pymongo import AsyncMongoClient

    from voyd import Engine

    from .conftest import MONGO_URI

    client = AsyncMongoClient(MONGO_URI)
    name = f"voyd_test_derived_{uuid.uuid4().hex[:8]}"
    eng = Engine(client, client[name])
    await eng.connect()
    try:
        yield eng
    finally:
        await client.drop_database(name)
        await client.close()


async def test_revoke_through_the_library_destroys_the_vector(engine):
    """The other door, and the one whose comment points at a function that
    does not exist (`marks.py` says "see `_destroy_derived`"; there is no
    such name in the package). The behaviour is real even though the
    signpost is not, and this is what pins it."""
    notes = engine.model("notes").forgettable()
    await engine.ensure(search_wait_s=0)
    await engine.db.notes.insert_many([
        {"text": "keep", "embedding": VEC},
        {"text": "forget", "embedding": VEC},
    ])

    await notes.revoke({"text": "forget"}, reason="erasure request")

    rows = {d["text"]: d async for d in engine.db.notes.find({})}
    assert rows["forget"]["embedding"] is None, (
        "revoked through the library and the vector survived -- the same "
        "erasure through the wire destroys it, which is drift between two "
        "front doors onto one guarantee")
    assert rows["keep"]["embedding"] == VEC


async def test_both_doors_leave_the_same_row(engine):
    """The drift check with teeth. The wire builds its own update and the
    library builds another; this asserts the row they leave is the same
    shape, which is what the wire's docstring already promises."""
    import voyd_wire as w

    notes = engine.model("notes").forgettable()
    await engine.ensure(search_wait_s=0)
    await engine.db.notes.insert_one({"_id": 1, "text": "x", "embedding": VEC})
    await notes.revoke({"_id": 1}, reason="erasure request")
    by_library = await engine.db.notes.find_one({"_id": 1})

    await engine.db.notes.insert_one({"_id": 2, "text": "x", "embedding": VEC})
    spec = notes.spec
    await engine.db.notes.update_one(
        {"_id": 2}, w._forget_pipeline(spec, "erasure request"))
    by_wire = await engine.db.notes.find_one({"_id": 2})

    assert set(by_library) == set(by_wire), (
        f"the two erasure paths write different fields: "
        f"library {sorted(set(by_library) - set(by_wire))}, "
        f"wire {sorted(set(by_wire) - set(by_library))}")
    assert by_library["embedding"] == by_wire["embedding"] is None
    assert by_library["forgotten"]["reason"] == by_wire["forgotten"]["reason"]


# --- through the wire, against a real mongod -------------------------------

@contextmanager
def _wire(tmp_path):
    policy = tmp_path / "voydfile.py"
    policy.write_text(POLICY)
    port = free_port()
    proc = subprocess.Popen(
        [sys.executable, "tools/voyd_wire.py", "--config", str(policy),
         "--listen", str(port), "--target", mongo_host()],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        until = time.monotonic() + 15
        while time.monotonic() < until:
            if proc.poll() is not None:
                pytest.fail(f"voyd-wire exited early:\n{proc.stdout.read()}")
            import socket
            try:
                with socket.create_connection(("127.0.0.1", port), 0.2):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            pytest.fail("voyd-wire never started listening")
        yield f"mongodb://localhost:{port}/?directConnection=true"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.fixture
def through(tmp_path, db):
    with _wire(tmp_path) as uri:
        yield pymongo.MongoClient(uri)[db.name], db


def test_a_delete_through_the_wire_destroys_the_vector(through):
    """The whole claim, end to end, with an ordinary driver.

    `deleteOne` becomes a revocation -- the row stays for the
    investigation, which is the point -- and the embedding beside it does
    *not* stay, because it is a copy of the thing being erased rather than
    evidence about it.
    """
    wired, direct = through
    wired.notes.insert_one({"_id": 1, "text": "the leak", "embedding": VEC})

    wired.notes.delete_one({"_id": 1})

    row = direct.notes.find_one({"_id": 1})
    assert row is not None, "the row is kept on purpose; this is a revocation"
    assert row["forgotten"], "and it is marked"
    assert row["embedding"] is None, (
        "the row was refused and its vector was left on disk -- the next "
        "$vectorSearch still ranks against a copy of the erased text")
    assert row["text"] == "the leak", (
        "the source text is deliberately kept: this is a revocation, and "
        "the reaper collects the row on the deadline that was just pulled in")


def test_the_revoked_row_is_unreachable_and_vectorless_together(through):
    """Both halves in one assertion, because either alone is a false
    comfort: a vector destroyed on a row that still reads is pointless, and
    a row refused with its vector intact is the hole this file is about."""
    wired, direct = through
    wired.notes.insert_many([
        {"_id": 1, "text": "live", "embedding": VEC},
        {"_id": 2, "text": "doomed", "embedding": VEC},
    ])

    wired.notes.delete_one({"_id": 2})

    assert [d["_id"] for d in wired.notes.find({})] == [1]
    assert direct.notes.find_one({"_id": 2})["embedding"] is None
    assert direct.notes.find_one({"_id": 1})["embedding"] == VEC, (
        "the living row's vector is untouched")


def test_an_expired_row_keeps_its_vector_until_it_is_erased(through):
    """The distinction that stops this being a blunt instrument.

    A deadline passing is not an erasure request. The row is refused on the
    way out and the reaper will collect it, but nobody asked for the
    encoding to be destroyed early -- and a boundary that nulled vectors on
    expiry would be inventing policy out of the clock.
    """
    wired, direct = through
    direct.notes.insert_one(
        {"_id": 1, "text": "old", "embedding": VEC, "expire_at": PAST})

    assert list(wired.notes.find({})) == []
    assert direct.notes.find_one({"_id": 1})["embedding"] == VEC
