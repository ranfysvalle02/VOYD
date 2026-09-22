"""An *ordered* clearance, declared in a policy file and answered by roles.

`restricted_to()` asks whether a caller is in a set. This asks how far up
a ladder they stand, which is a different question and the one a policy
file could not previously express at all: `declare.py` exported no
`clearance()`, and even written by hand the rule wanted a `clearance`
claim that a boundary has no honest way to produce.

**The claim is the whole design and the reason this took a mapping.** A
rule that believed `{"clearance": "secret"}` because a client sent one
would be an authorisation system whose only input is the attacker's. So
the boundary asks the deployment, and the deployment answers
`connectionStatus` with **roles** -- which say who somebody is and not how
far up a ladder they stand. Nothing in a MongoDB role carries a level, so
the policy file says:

    classification = clearance(order=("public", "internal", "secret"),
                               roles={"analyst": "internal",
                                      "sec-cleared": "secret"})

Half of this file needs no database at all, because the failure modes are
about *defaults* -- an unmapped role, an unlabelled document, a caller
with nothing -- and every one of them has to fail closed. The other half
puts two real MongoDB users behind the boundary and reads with them,
because a mapping that is right in a unit test and never reaches the
proxy is the drift this project is about.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

import pytest

from voyd.declare import load
from voyd.engine.admission import Admission
from voyd.wire.proxy import Guard, unsuppliable_claims

from .conftest import RS_URI, free_port

pymongo = pytest.importorskip("pymongo")
ROOT = Path(__file__).resolve().parents[1]

LEVELS = ("public", "internal", "secret")


def _policy(tmp_path, body: str) -> dict:
    path = tmp_path / "voydfile.py"
    path.write_text(body)
    return load(str(path))


LADDER = """
from voyd import guard, deadline, revocable, clearance

@guard("notes")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    classification = clearance(
        order=("public", "internal", "secret"),
        roles={"analyst": "internal", "sec-cleared": "secret"})
"""


# ---- the declaration refuses to compile a policy that cannot work --------

def test_a_role_mapped_to_a_level_that_does_not_exist_is_a_load_error(tmp_path):
    """The failure this catches is silent otherwise: a role cleared for a
    level the ladder does not define is cleared for *nothing*, and the
    collection reads as empty for exactly the people it was written for."""
    with pytest.raises(ValueError, match="not in order"):
        _policy(tmp_path, """
from voyd import guard, deadline, revocable, clearance

@guard("notes")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    classification = clearance(order=("public", "secret"),
                               roles={"analyst": "internal"})
""")


def test_a_ladder_with_a_repeated_rung_is_a_load_error(tmp_path):
    with pytest.raises(ValueError, match="repeats a level"):
        _policy(tmp_path, """
from voyd import guard, deadline, revocable, clearance

@guard("notes")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    classification = clearance(order=("public", "secret", "public"))
""")


def test_a_ladder_with_no_rungs_is_a_load_error(tmp_path):
    with pytest.raises(ValueError, match="needs an order"):
        _policy(tmp_path, """
from voyd import guard, deadline, revocable, clearance

@guard("notes")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    classification = clearance(order=())
""")


# ---- and the boundary can now answer it ----------------------------------

def test_a_mapped_clearance_needs_no_claim_the_wire_cannot_supply(tmp_path):
    """The point of the mapping. Before it, this rule asked for a
    `clearance` claim, `unsuppliable_claims` named it at boot, and every
    read of the collection was refused -- fail-closed, and useless."""
    guard = Guard(_policy(tmp_path, LADDER)["notes"])
    assert unsuppliable_claims(guard) == []


def test_an_unmapped_clearance_still_says_so_at_boot(tmp_path):
    """The other form is still declarable and still honest about itself."""
    guard = Guard(_policy(tmp_path, """
from voyd import guard, deadline, revocable, clearance

@guard("notes")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    classification = clearance(order=("public", "secret"), via="clearance")
""")["notes"])
    assert unsuppliable_claims(guard) == ["clearance"]


# ---- the ladder itself, with no database in sight ------------------------

CORPUS = [
    {"classification": "public", "t": "the office is closed on Monday"},
    {"classification": "internal", "t": "Q3 headcount is 14 engineers"},
    {"classification": "secret", "t": "the acquisition fell through"},
    {"t": "a note nobody classified"},
    {"classification": "cosmic", "t": "a label from another deployment"},
]


def _reachable(tmp_path, roles) -> list[str]:
    spec = _policy(tmp_path, LADDER)["notes"]
    handle = Admission(None, spec).for_caller({"roles": roles})
    return [d["t"] for d in handle.reachable(CORPUS)]


def test_a_role_clears_its_level_and_everything_below(tmp_path):
    assert _reachable(tmp_path, ["analyst"]) == [
        "the office is closed on Monday", "Q3 headcount is 14 engineers"]


def test_the_highest_role_wins_when_a_caller_holds_several(tmp_path):
    """Not the first, and not the last. A caller who is both an analyst and
    cleared for secrets is cleared for secrets."""
    both = _reachable(tmp_path, ["analyst", "sec-cleared"])
    assert both == _reachable(tmp_path, ["sec-cleared"])
    assert "the acquisition fell through" in both


def test_a_caller_with_no_roles_is_cleared_for_nothing(tmp_path):
    """No claim is the lowest, not the highest. The tempting default is the
    other one, and it is tempting because it is what makes tests pass."""
    assert _reachable(tmp_path, []) == []


def test_a_role_this_policy_never_mapped_clears_nothing(tmp_path):
    """An unmapped role is an unanswered question, and the answer to an
    unanswered question here is no. It must not raise, either: a rule that
    throws inside a filter is a rule that gets skipped."""
    assert _reachable(tmp_path, ["some-other-team"]) == []


def test_an_unlabelled_document_reaches_nobody(tmp_path):
    """Untagged is not public. Getting this backwards makes every document
    written before the policy existed world-readable, which is exactly the
    population most likely to be sensitive."""
    assert "a note nobody classified" not in _reachable(
        tmp_path, ["sec-cleared"])


def test_a_label_this_deployment_does_not_know_reaches_nobody(tmp_path):
    """An unrecognised classification is not a low one."""
    assert "a label from another deployment" not in _reachable(
        tmp_path, ["sec-cleared"])


# ---- and through the boundary, with roles the server granted -------------

@contextmanager
def _wire(tmp_path, target: str):
    path = tmp_path / "voydfile.py"
    path.write_text(LADDER)
    port = free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "voyd.wire.proxy", "--config", str(path),
         "--listen", str(port), "--target", target],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
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
        yield port
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.fixture
def cleared(replica_set):
    """Two users whose MongoDB roles *are* the rungs of the ladder."""
    admin = pymongo.MongoClient(replica_set, serverSelectionTimeoutMS=8000)
    name = f"voyd_test_clear_{uuid.uuid4().hex[:8]}"
    made = []
    try:
        for role in ("analyst", "sec-cleared"):
            admin[name].command("createRole", role, privileges=[],
                                roles=[{"role": "read", "db": name}])
        for user, role in (("ana", "analyst"), ("sec", "sec-cleared")):
            admin[name].command("createUser", user, pwd="pw",
                                roles=[{"role": role, "db": name}])
            made.append(user)
        admin[name].notes.insert_many([dict(d) for d in CORPUS])
        yield name
    finally:
        for user in made:
            try:
                admin[name].command("dropUser", user)
            except pymongo.errors.PyMongoError:
                pass
        for role in ("analyst", "sec-cleared"):
            try:
                admin[name].command("dropRole", role)
            except pymongo.errors.PyMongoError:
                pass
        admin.drop_database(name)
        admin.close()


def _as(port: int, user: str, database: str):
    return pymongo.MongoClient(
        f"mongodb://{user}:pw@localhost:{port}/?directConnection=true"
        f"&authSource={database}", serverSelectionTimeoutMS=8000)


def test_the_ladder_holds_through_a_plain_driver(tmp_path, cleared):
    """Two clients, one query, one policy file, and the difference between
    what they are given is a role the deployment granted -- not a header
    either of them sent, and not a line in either of their codebases."""
    with _wire(tmp_path, "localhost:27021") as port:
        seen = {}
        for user in ("ana", "sec"):
            client = _as(port, user, cleared)
            try:
                seen[user] = sorted(
                    d["t"] for d in client[cleared].notes.find({}))
            finally:
                client.close()

    assert seen["ana"] == ["Q3 headcount is 14 engineers",
                           "the office is closed on Monday"]
    assert seen["sec"] == ["Q3 headcount is 14 engineers",
                           "the acquisition fell through",
                           "the office is closed on Monday"]
    assert "the acquisition fell through" not in seen["ana"], (
        "the analyst was served a secret; the ladder did not reach the wire")


def test_the_unlabelled_document_reaches_neither_of_them(tmp_path, cleared):
    """The control on the assertions above, and the one that would fail
    first if `default` ever quietly became `public`."""
    with _wire(tmp_path, "localhost:27021") as port:
        client = _as(port, "sec", cleared)
        try:
            seen = {d["t"] for d in client[cleared].notes.find({})}
        finally:
            client.close()
    assert "a note nobody classified" not in seen
    assert "a label from another deployment" not in seen


def test_the_control_is_that_the_rows_are_all_on_disk(cleared, replica_set):
    """Five documents are there. If they ever stop being there, every
    assertion above passes because the collection is empty."""
    direct = pymongo.MongoClient(replica_set, serverSelectionTimeoutMS=8000)
    try:
        assert direct[cleared].notes.count_documents({}) == 5
    finally:
        direct.close()


def test_an_unauthenticated_caller_is_cleared_for_nothing(tmp_path, cleared):
    """No identity is the lowest rung. A boundary that fell back to the
    top one when it could not tell who was asking would be an access
    control system with an anonymous bypass."""
    with _wire(tmp_path, RS_URI) as port:
        client = pymongo.MongoClient(
            f"mongodb://localhost:{port}/?directConnection=true",
            serverSelectionTimeoutMS=8000)
        try:
            with pytest.raises(pymongo.errors.PyMongoError):
                list(client[cleared].notes.find({}))
        finally:
            client.close()
