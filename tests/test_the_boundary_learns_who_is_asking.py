"""Caller-scoped rules, on the wire, with the claims taken from the server.

`restricted_to()` decides by *who is asking*, which for a long time the
proxy could not answer: it held no caller, so `expressible_clauses`
returned `None` and `Guard.filter` passed no claims at all.

**Where the claims come from is the whole design, not an implementation
detail.** `for_caller` in `admission/core.py` says it plainly -- a handle
that believed ``{"clearance": "secret"}`` because it was passed one "would
be an authorisation system whose only input is the attacker's". A proxy is
in a worse position still, because the client is the only thing talking to
it. So the boundary asks the *deployment*: `connectionStatus`, run on the
client's own connection, returns the server's own account of who
authenticated there. A client cannot forge that without forging the
authentication.

Against the three-node set, because it is the only deployment here with
authentication turned on -- and a test for an identity check against a
server that authenticates nobody would be asserting the shape of the code
rather than the behaviour of the boundary.
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

from .conftest import RS_URI, free_port

pymongo = pytest.importorskip("pymongo")
ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.needs_mongo

POLICY = """
from voyd import guard, deadline, restricted_to, revocable


@guard("memos")
class Memos:
    expire_at = deadline()
    forgotten = revocable()
    audience = restricted_to("groups")
"""


@contextmanager
def _wire(tmp_path, target: str, *extra: str):
    policy = tmp_path / "voydfile.py"
    policy.write_text(POLICY)
    port = free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "voyd.wire.proxy", "--config", str(policy),
         "--listen", str(port), "--target", target, *extra],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        until = time.monotonic() + 15
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
def cast(replica_set):
    """Two users with different roles, and a database of memos.

    The roles *are* the groups: `db.createRole({role: "legal"})` is how a
    deployment already spells this, so `restricted_to("groups")` against a
    document listing `["legal"]` needs no further declaration.
    """
    admin = pymongo.MongoClient(replica_set, serverSelectionTimeoutMS=8000)
    name = f"voyd_test_who_{uuid.uuid4().hex[:8]}"
    tag = uuid.uuid4().hex[:6]
    legal, desk = f"legal_{tag}", f"desk_{tag}"
    made = []
    try:
        db = admin[name]
        for role in (legal, desk):
            admin[name].command("createRole", role, privileges=[],
                                roles=[{"role": "read", "db": name}])
        for user, role in ((f"lawyer_{tag}", legal), (f"seller_{tag}", desk)):
            admin[name].command("createUser", user, pwd="pw",
                                roles=[{"role": role, "db": name}])
            made.append(user)
        db.memos.insert_many([
            {"_id": 1, "text": "the settlement", "audience": ["legal"]},
            {"_id": 2, "text": "the discount",
             "audience": [f"desk_{tag}"]},
            {"_id": 3, "text": "for both",
             "audience": [f"legal_{tag}", f"desk_{tag}"]},
            {"_id": 4, "text": "for nobody", "audience": []},
            {"_id": 5, "text": "untagged"},
        ])
        yield name, tag, made
    finally:
        for user in made:
            try:
                admin[name].command("dropUser", user)
            except Exception:                                  # noqa: BLE001
                pass
        for role in (legal, desk):
            try:
                admin[name].command("dropRole", role)
            except Exception:                                  # noqa: BLE001
                pass
        admin.drop_database(name)
        admin.close()


def _as(port: int, user: str, database: str):
    return pymongo.MongoClient(
        f"mongodb://{user}:pw@localhost:{port}/?directConnection=true"
        f"&authSource={database}", serverSelectionTimeoutMS=8000)


def test_a_caller_sees_only_what_names_a_group_they_hold(tmp_path, cast,
                                                         replica_set):
    """The claim. Two identities, one connection string apart, one policy
    file, and neither client knows VOYD exists."""
    database, tag, _users = cast
    target = "localhost:27021"
    with _wire(tmp_path, target) as port:
        lawyer = _as(port, f"lawyer_{tag}", database)
        try:
            seen = sorted(d["_id"] for d in lawyer[database].memos.find({}))
        finally:
            lawyer.close()

        seller = _as(port, f"seller_{tag}", database)
        try:
            theirs = sorted(d["_id"] for d in seller[database].memos.find({}))
        finally:
            seller.close()

    assert seen == [3], (
        f"the lawyer holds legal_{tag} and should see only the memos whose "
        f"audience names it; got {seen}")
    assert theirs == [2, 3], (
        f"the seller holds desk_{tag}; got {theirs}")


def test_an_untagged_or_empty_audience_reaches_nobody(tmp_path, cast,
                                                      replica_set):
    """`Restricted` refuses a document with no audience, and the wire has
    to agree. Untagged is not public -- getting that backwards makes every
    document written before the policy existed world-readable, which is
    the population most likely to be sensitive."""
    database, tag, _users = cast
    with _wire(tmp_path, "localhost:27021") as port:
        lawyer = _as(port, f"lawyer_{tag}", database)
        try:
            seen = {d["_id"] for d in lawyer[database].memos.find({})}
        finally:
            lawyer.close()
    assert 4 not in seen, "an empty audience list reached a caller"
    assert 5 not in seen, "a document with no audience field reached a caller"


def test_the_claims_are_the_servers_account_not_the_clients(tmp_path, cast,
                                                            replica_set):
    """The property the whole design rests on.

    A client cannot talk its way into a group. There is no field in a
    MongoDB command that says "my groups are"; the boundary asks
    `connectionStatus` on the connection the client authenticated, and the
    server answers with the roles it granted. This pins the consequence:
    the same query, sent by two identities, returns different rows, and
    the only thing that differs is the credential.
    """
    database, tag, _users = cast
    query = {"_id": {"$in": [1, 2, 3]}}
    with _wire(tmp_path, "localhost:27021") as port:
        lawyer = _as(port, f"lawyer_{tag}", database)
        seller = _as(port, f"seller_{tag}", database)
        try:
            mine = sorted(d["_id"] for d in lawyer[database].memos.find(query))
            yours = sorted(d["_id"] for d in seller[database].memos.find(query))
        finally:
            lawyer.close()
            seller.close()
    assert mine != yours, (
        "two credentials, one query, one answer -- the identity is not "
        "reaching the rules")
    assert mine == [3] and yours == [2, 3]


def test_a_reduction_is_scoped_to_the_caller_too(tmp_path, cast,
                                                 replica_set):
    """`count_documents` is a read, and it used to be refused outright on a
    caller-scoped collection because the push-down could not be built
    without claims. With an identity it can: the count is over the rows
    this caller may see, not over the collection."""
    database, tag, _users = cast
    with _wire(tmp_path, "localhost:27021") as port:
        seller = _as(port, f"seller_{tag}", database)
        try:
            n = seller[database].memos.count_documents({})
        finally:
            seller.close()
    assert n == 2, (
        f"the seller may see two memos and the count said {n} -- a count "
        f"that disagrees with the page it summarises is the leak this "
        f"boundary is named after")


def test_the_fan_out_path_learns_the_same_identity(tmp_path, cast,
                                                   replica_set):
    """`--fan-out` is a second request loop, and it had a second answer.

    `Conversation` carried its own copy of "ask on the client's own
    connection" and no identity at all, so a fanned-out connection to a
    caller-scoped collection saw empty claims and refused everything --
    safe, and wrong for the operator, and *different from the default
    path*, which is the part that matters. One boundary that means two
    things depending on a flag is the drift this package is about.

    Both loops now share one `Backchannel` and one `CallerIdentity`, and
    this is what stops that from being a claim in a docstring.
    """
    database, tag, _users = cast
    with _wire(tmp_path, "localhost:27021", "--fan-out", RS_URI) as port:
        seller = _as(port, f"seller_{tag}", database)
        try:
            seen = sorted(d["_id"] for d in seller[database].memos.find({}))
        finally:
            seller.close()
    assert seen == [2, 3], (
        f"the same credential sees {seen} through --fan-out and [2, 3] "
        f"without it; the boundary means two different things")


# --- the claim the wire cannot supply --------------------------------------

def test_a_claim_the_wire_cannot_supply_is_announced_at_boot():
    """`Clearance` wants an ordered level, and nothing in a MongoDB role
    says which level a role is.

    So it gets no claim, and "no claim is the lowest, not the highest" --
    the collection refuses every document to everybody. Fail-closed, which
    is the right direction and the wrong outcome: it presents as "VOYD
    broke my reads" with nothing connecting it to a line in the policy
    file. Announced at boot instead, which is the only place it is cheap
    to notice.
    """
    from voyd.wire import proxy as w

    from voyd.engine.admission.rules import Clearance, Deadline, revoked
    from voyd.engine.admission.spec import AdmissionSpec

    unfillable = w.Guard(AdmissionSpec(
        "papers", rules=(Clearance(order=("public", "secret")),)))
    assert w.unsuppliable_claims(unfillable) == ["clearance"]

    fine = w.Guard(AdmissionSpec("memos", rules=(
        Deadline(at_field="expire_at"), revoked("forgotten"))))
    assert w.unsuppliable_claims(fine) == []


def test_a_groups_rule_is_not_announced_because_it_can_be_answered():
    """The other half of the control. A warning that fired on the rule
    this boundary *can* enforce would train people to ignore it."""
    from voyd.wire import proxy as w

    from voyd.engine.admission.rules import Restricted
    from voyd.engine.admission.spec import AdmissionSpec

    ok = w.Guard(AdmissionSpec(
        "memos", rules=(Restricted(field="audience", claim="groups"),)))
    assert w.unsuppliable_claims(ok) == []


def test_the_claims_the_wire_supplies_are_what_connection_status_gives():
    """The two lists have to agree or the warning above is decoration."""
    from voyd.wire import proxy as w

    claims = w.claims_from({"authInfo": {
        "authenticatedUsers": [{"user": "alice", "db": "admin"}],
        "authenticatedUserRoles": [{"role": "legal", "db": "app"},
                                   {"role": "read", "db": "app"}]}})
    assert set(claims) == w.SUPPLIABLE_CLAIMS
    assert claims["user"] == "alice" and claims["db"] == "admin"
    assert claims["groups"] == ["legal", "read"] == claims["roles"]


def test_an_unauthenticated_connection_yields_no_groups():
    """A deployment without auth answers with empty lists, and that is a
    real answer rather than a failure. The rules then refuse, which is
    correct: nobody is not everybody."""
    from voyd.wire import proxy as w

    claims = w.claims_from({"authInfo": {"authenticatedUsers": [],
                                         "authenticatedUserRoles": []}})
    assert claims["user"] is None
    assert claims["groups"] == []


def test_a_projection_that_hides_the_audience_still_scopes_to_the_caller(
        tmp_path, cast, replica_set):
    """Where the two fixes meet, and the case that needed both.

    `find({}, {"text": 1})` strips `audience`, so the refusal moves into
    the query. That leaves a batch of documents with no audience on them
    -- and `Restricted` refuses a document with no audience, because
    untagged is not public. Judging that batch again would throw away the
    rows the query had just correctly selected, which is exactly the
    `count_documents() == 0` failure one layer down.

    So the reply to a pushed-down read is left alone, and this is what
    says so on the path where getting it wrong is visible: the caller sees
    their own rows, projected as they asked.
    """
    database, tag, _users = cast
    with _wire(tmp_path, "localhost:27021") as port:
        seller = _as(port, f"seller_{tag}", database)
        try:
            got = sorted((d["_id"], set(d)) for d in
                         seller[database].memos.find({}, {"text": 1}))
        finally:
            seller.close()

    assert [i for i, _ in got] == [2, 3], (
        f"the seller sees [2, 3] unprojected and {[i for i, _ in got]} "
        f"with a projection -- the same read answered two ways")
    assert all(fields == {"_id", "text"} for _, fields in got), (
        "the boundary left the fields it added to satisfy itself in the "
        "reply the client gets")
