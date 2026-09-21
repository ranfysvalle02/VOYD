"""Fan-out, and the window it would have opened if nobody had looked.

The feature is a cost lever: rank a read on a secondary so the primary does
not pay for a `$vectorSearch` scan. The danger is that refusal is a function
of the marks on the document it is *shown*, so a secondary that has not
replicated a revocation hands the boundary something that still looks live --
and the boundary admits it, confidently, with a receipt saying it was
allowed. That is delete-is-a-wish, reintroduced by the thing that exists to
close it.

So the split these tests are about: the **secondary ranks**, the **primary
permits**.

The control assertion is the whole file. `test_a_stale_secondary_really_is_
stale` is not a test of VOYD at all -- it proves the window is real and open
on the deployment the other tests run against. Without it, a passing
lag test would be indistinguishable from one where replication happened to
be instant and nothing was ever actually at risk.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path

import pytest

from voyd.engine.time import now

from .conftest import RS_URI, free_port

pymongo = pytest.importorskip("pymongo")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import voyd_fanout  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def _credential() -> str:
    """``user:pass@`` from the rig's URI, or empty on an open deployment."""
    head = RS_URI.split("//", 1)[1]
    return head.split("@")[0] + "@" if "@" in head.split("/")[0] else ""


CRED = _credential()


def direct(hostport: str) -> str:
    """A direct URI for one member, carrying the rig's credential."""
    return (f"mongodb://{CRED}{hostport}/?directConnection=true"
            + ("&authSource=admin" if CRED else ""))

PAST = now() - timedelta(days=1)

POLICY = """
from voyd import guard, deadline, revocable, tenant

@guard("notes", on_delete="revoke")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()
"""


# --------------------------------------------------------------------------
# The routing rules are pure, and are tested as pure functions. Everything
# below this line needs three mongods; nothing above it needs any.
# --------------------------------------------------------------------------

class _Rule:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class _Spec:
    def __init__(self, rules, tenant=None):
        self.rules = rules
        self.tenant = tenant


class _Guard:
    def __init__(self, rules, tenant=None):
        self.spec = _Spec(rules, tenant)


def test_a_projectable_rule_set_names_the_fields_the_verdict_reads():
    guard = _Guard([_Rule(at_field="expire_at"), _Rule(field="forgotten")],
                   tenant="tenant_id")
    assert voyd_fanout.verdict_fields(guard) == {
        "_id", "expire_at", "forgotten", "tenant_id"}


def test_a_rule_this_module_has_never_heard_of_costs_a_whole_document():
    """The case that matters, because it is the third-party one.

    A rule whose fields cannot be named must not be quietly skipped -- the
    verdict would then be taken on a document missing exactly the field the
    rule reads. `None` means "fetch everything", which is slower and right.
    """
    assert voyd_fanout.verdict_fields(_Guard([_Rule(threshold=3)])) is None


def test_a_content_addressed_rule_also_costs_a_whole_document():
    distinct = type("Distinct", (), {})()
    distinct.on = None
    assert voyd_fanout.verdict_fields(_Guard([distinct])) is None
    distinct.on = "url"
    assert voyd_fanout.verdict_fields(_Guard([distinct])) == {"_id", "url"}


def test_a_budget_with_a_custom_cost_callable_is_opaque():
    budget = type("Budget", (), {})()
    budget.cost_field, budget.cost = "tokens", None
    assert voyd_fanout.verdict_fields(_Guard([budget])) == {"_id", "tokens"}
    budget.cost = len
    assert voyd_fanout.verdict_fields(_Guard([budget])) is None


@pytest.mark.parametrize("body,expected", [
    ({"find": "notes"}, True),
    ({"find": "notes", "projection": {"_id": 0}}, False),
    ({"find": "notes", "projection": {"text": 1}}, True),
    ({"aggregate": "notes", "pipeline": [{"$match": {}}, {"$limit": 5}]}, True),
    ({"aggregate": "notes", "pipeline": [{"$vectorSearch": {}}]}, True),
    ({"aggregate": "notes", "pipeline": [{"$group": {"_id": "$k"}}]}, False),
    ({"aggregate": "notes", "pipeline": [{"$project": {"t": 1}}]}, False),
])
def test_a_read_is_only_routed_if_its_answer_can_still_be_matched(body, expected):
    """Correlation needs `_id`, and it is decided from the *request*.

    Finding out from the reply would be too late: the batch would already
    have been ranked on a replica whose marks nobody could check, leaving a
    choice between refusing a whole page and serving it unverified.
    """
    assert voyd_fanout.correlatable(body) is expected


@pytest.mark.parametrize("body", [
    {"find": "notes", "txnNumber": 4},
    {"find": "notes", "startTransaction": True},
    {"find": "notes", "$readPreference": {"mode": "primary"}},
    {"find": "notes", "$readPreference": {"mode": "primaryPreferred"}},
    {"insert": "notes"},
    {"aggregate": "notes", "pipeline": [{"$match": {}}, {"$out": "copied"}]},
])
def test_what_never_leaves_the_primary(body):
    assert voyd_fanout.routes_to_secondary(body, {"notes": object()}) is None


def test_a_guarded_read_that_cannot_be_correlated_stays_on_the_primary():
    body = {"find": "notes", "projection": {"_id": 0}}
    assert voyd_fanout.routes_to_secondary(body, {"notes": object()}) is None
    # ...but the same read on a collection nobody declared has no verdict to
    # verify, so there is nothing to correlate and it may go.
    assert voyd_fanout.routes_to_secondary(body, {}) == "find"


def test_a_mark_lifted_on_the_primary_travels_as_an_absence():
    """The direction that is easy to get wrong.

    Merging only the marks that are *present* leaves a document refused
    forever on a stale copy: the secondary still carries `forgotten`, the
    primary no longer does, and a merge that skips missing fields keeps the
    stale one. An absence on the primary is a fact.
    """
    stale = [{"_id": 1, "text": "t", "forgotten": {"at": PAST}}]
    fresh = {1: {"_id": 1}}
    judgeable, originals = voyd_fanout.merge_marks(
        stale, fresh, {"_id", "forgotten"})
    assert "forgotten" not in judgeable[0]
    assert originals[0]["text"] == "t", "the client still gets its document"


def test_a_document_the_primary_does_not_have_is_dropped():
    stale = [{"_id": 1, "text": "gone"}, {"_id": 2, "text": "here"}]
    judgeable, originals = voyd_fanout.merge_marks(
        stale, {2: {"_id": 2}}, {"_id"})
    assert [d["_id"] for d in originals] == [2]
    assert len(judgeable) == 1


# --------------------------------------------------------------------------
# Against three real mongods, through a real proxy, with a real driver.
# --------------------------------------------------------------------------

@contextmanager
def _wire(tmp_path, uri, *extra):
    policy = tmp_path / "voydfile.py"
    policy.write_text(POLICY)
    port = free_port()
    proc = subprocess.Popen(
        [sys.executable, "tools/voyd_wire.py", "--config", str(policy),
         "--listen", str(port), "--target", uri, *extra],
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
        yield (f"mongodb://{CRED}localhost:{port}/"
               + ("?authSource=admin" if CRED else ""))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.fixture
def fanned(tmp_path, replica_set):
    """A boundary that ranks on secondaries and permits from the primary."""
    with _wire(tmp_path, replica_set, "--fan-out", replica_set,
               "--advertise-self") as uri:
        yield uri


@pytest.fixture
def pinned(tmp_path, replica_set):
    """The same boundary with fan-out off. The equivalence control."""
    with _wire(tmp_path, replica_set, "--advertise-self") as uri:
        yield uri


@pytest.fixture
def seeded(rs_db):
    rs_db.notes.with_options(
        write_concern=pymongo.WriteConcern(w=3)).insert_many([
            {"tenant_id": "acme", "text": "live"},
            {"tenant_id": "acme", "text": "expired", "expire_at": PAST},
            {"tenant_id": "acme", "text": "revoked",
             "forgotten": {"at": PAST, "reason": "leak"}},
            {"tenant_id": "globex", "text": "someone else's"},
        ])
    return rs_db


@contextmanager
def replication_stopped(uri):
    """Freeze every secondary, and hand back the ones that are truly behind.

    `stopReplProducer` stops a secondary *fetching*; anything already
    fetched still applies, so a node can cross the line a moment after the
    failpoint is on. The yielded list is therefore computed by the caller
    against real documents rather than assumed here -- assuming it is how
    this test would pass on a deployment where nothing was ever at risk.
    """
    client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=8000)
    # `ping` first. `.secondaries` on an undiscovered topology is an empty
    # set, which would have made this helper freeze nothing, find nothing
    # stale, and report it as "replication won the race" -- the same trap
    # `Upstream._resolve` documents for `.primary`, walked into again here.
    client.admin.command("ping")
    nodes = [pymongo.MongoClient(direct(f"{h}:{p}"),
                                 serverSelectionTimeoutMS=8000)
             for h, p in sorted(client.secondaries)]
    for node in nodes:
        node.admin.command({"configureFailPoint": "stopReplProducer",
                            "mode": "alwaysOn"})
    time.sleep(1.0)      # let the failpoint actually take hold
    try:
        yield nodes
    finally:
        for node in nodes:
            try:
                node.admin.command({"configureFailPoint": "stopReplProducer",
                                    "mode": "off"})
            finally:
                node.close()
        client.close()


def texts(uri, name, flt):
    client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=8000)
    try:
        return sorted(d["text"] for d in client[name].notes.find(flt))
    finally:
        client.close()


def test_fanning_out_changes_nothing_about_what_is_refused(seeded, fanned,
                                                           pinned):
    """The equivalence claim. A cost lever that changed an answer would be
    a different feature wearing this one's name."""
    assert texts(fanned, seeded.name, {"tenant_id": "acme"}) == ["live"]
    assert texts(pinned, seeded.name, {"tenant_id": "acme"}) == ["live"]


def test_the_read_is_actually_ranked_on_a_secondary(seeded, fanned):
    """Otherwise every other test here passes by never fanning out at all.

    Asserted from the server's own counters rather than the proxy's: an
    `opcounters.query` that moved on a *secondary* is the deployment saying
    where the work happened, which is not something this process can talk
    itself into.
    """
    client = pymongo.MongoClient(direct("localhost:27022"),
                                 serverSelectionTimeoutMS=8000)
    try:
        before = client.admin.command("serverStatus")["opcounters"]["query"]
        for _ in range(6):     # round robin: make sure this node sees some
            texts(fanned, seeded.name, {"tenant_id": "acme"})
        after = client.admin.command("serverStatus")["opcounters"]["query"]
    finally:
        client.close()
    assert after > before, "no read reached the secondary; fan-out is not on"


def test_a_stale_secondary_really_is_stale(seeded, replica_set):
    """The control. Not a test of VOYD -- a test of the danger.

    If this ever fails, the lag test below proves nothing, because there was
    never a window in which a revoked document could have been served.
    """
    with replication_stopped(replica_set) as nodes:
        seeded.notes.with_options(
            write_concern=pymongo.WriteConcern(w=1)).update_one(
                {"text": "live"},
                {"$set": {"forgotten": {"at": now(), "reason": "leak"}}})
        stale = [n for n in nodes
                 if "forgotten" not in (n[seeded.name].notes.find_one(
                     {"text": "live"}) or {"forgotten": 1})]
        assert stale, ("no secondary lagged, so there is no window here and "
                       "the lag test below would pass for the wrong reason")


def test_a_revocation_the_secondary_has_not_seen_is_still_refused(
        seeded, replica_set, tmp_path):
    """The whole feature, in one assertion.

    Replication is frozen, the document is revoked on the primary only, and
    the read is ranked on a replica that still believes it is live. The
    verdict comes from the primary, so it is refused -- and the naive
    version of this feature would have served it.
    """
    with replication_stopped(replica_set) as nodes:
        seeded.notes.with_options(
            write_concern=pymongo.WriteConcern(w=1)).update_one(
                {"text": "live"},
                {"$set": {"forgotten": {"at": now(), "reason": "leak"}}})
        behind = [n for n in nodes
                  if "forgotten" not in (n[seeded.name].notes.find_one(
                      {"text": "live"}) or {"forgotten": 1})]
        if not behind:
            pytest.skip("replication won the race; nothing was at risk")

        # What the secondary would have served on its own. This is the leak
        # the feature exists not to cause, demonstrated against the very
        # node the boundary is about to read from.
        assert behind[0][seeded.name].notes.find_one({"text": "live"})

        with _wire(tmp_path, replica_set, "--fan-out", replica_set,
                   "--advertise-self") as uri:
            for _ in range(6):      # every secondary in the rotation
                assert texts(uri, seeded.name, {"tenant_id": "acme"}) == [], (
                    "a revoked fact was served from a replica that had not "
                    "seen the revocation")


def test_a_write_still_goes_to_the_primary_and_still_becomes_a_revocation(
        seeded, fanned):
    """Fan-out is a read path. The delete rewrite is untouched by it, and
    that has to be asserted rather than assumed: the routing pump is a
    second copy of the request path and could have dropped it."""
    client = pymongo.MongoClient(fanned, serverSelectionTimeoutMS=8000)
    try:
        client[seeded.name].notes.delete_one({"text": "live"})
    finally:
        client.close()
    row = seeded.notes.find_one({"text": "live"})
    assert row is not None, "the row was destroyed rather than revoked"
    assert "forgotten" in row
    assert texts(fanned, seeded.name, {"tenant_id": "acme"}) == []


def test_a_cursor_opened_on_a_secondary_is_paged_from_the_same_secondary(
        rs_db, fanned):
    """A `getMore` sent anywhere else is asking a server about a cursor it
    has never heard of. With two secondaries in rotation, round robin makes
    that the *likely* outcome rather than a rare one."""
    rs_db.notes.with_options(
        write_concern=pymongo.WriteConcern(w=3)).insert_many(
            [{"tenant_id": "acme", "text": f"n{i:03d}"} for i in range(250)])
    client = pymongo.MongoClient(fanned, serverSelectionTimeoutMS=8000)
    try:
        got = [d["text"] for d in
               client[rs_db.name].notes.find({"tenant_id": "acme"},
                                             batch_size=20).sort("text")]
    finally:
        client.close()
    assert got == [f"n{i:03d}" for i in range(250)], (
        "paging across a fanned-out cursor lost or duplicated documents")


# --------------------------------------------------------------------------
# Authentication, which is what decides whether fan-out is a real feature or
# a localhost one.
#
# A secondary connection cannot replay the client's handshake -- SCRAM is a
# challenge-response bound to a nonce, and this proxy does not hold the
# password. So the boundary authenticates that connection itself, as the
# `--fan-out` URI's identity. Two things follow, and both are tested here:
# it has to actually work against an authenticated deployment, and it must
# not quietly serve one user's reads over another user's connection.
# --------------------------------------------------------------------------

def _requires_auth():
    if not CRED:
        pytest.skip("the rig is unauthenticated; nothing to prove here")


def test_fan_out_authenticates_its_own_connection_to_a_secondary(seeded,
                                                                 fanned):
    """The whole of what made fan-out a localhost feature until now.

    The rig runs with `--auth` and a keyfile, so a secondary refuses an
    unauthenticated read outright. A batch coming back ranked means SCRAM
    completed on a connection this process opened and proved an identity
    on -- there is no path to this assertion that skipped it.
    """
    _requires_auth()
    client = pymongo.MongoClient(direct("localhost:27022"),
                                 serverSelectionTimeoutMS=8000)
    try:
        before = client.admin.command("serverStatus")["opcounters"]["query"]
        for _ in range(6):
            assert texts(fanned, seeded.name, {"tenant_id": "acme"}) == ["live"]
        after = client.admin.command("serverStatus")["opcounters"]["query"]
    finally:
        client.close()
    assert after > before, (
        "no read reached the authenticated secondary: SCRAM did not complete "
        "and fan-out silently degraded to the primary")


def test_a_client_arriving_as_somebody_else_is_not_served_over_this_identity(
        seeded, fanned):
    """The privilege check, and the reason it is not optional.

    The secondary connection is authenticated as the `--fan-out` user. A
    client that authenticated as a different user has its reads served over
    that connection only if nobody is looking -- which is a privilege change
    wearing the shape of an optimisation. So fan-out switches off for the
    connection, and the read still happens, on the primary, correctly.
    """
    _requires_auth()
    port = fanned.split("localhost:")[1].split("/")[0]
    other = (f"mongodb://someone-else:someone-else@localhost:{port}"
             f"/?authSource=admin")
    node = pymongo.MongoClient(direct("localhost:27022"),
                               serverSelectionTimeoutMS=8000)
    client = pymongo.MongoClient(other, serverSelectionTimeoutMS=8000)
    try:
        before = node.admin.command("serverStatus")["opcounters"]["query"]
        for _ in range(6):
            got = sorted(d["text"] for d in
                         client[seeded.name].notes.find({"tenant_id": "acme"}))
            assert got == ["live"], "the answer changed, not just the route"
        after = node.admin.command("serverStatus")["opcounters"]["query"]
    finally:
        client.close()
        node.close()
    assert after == before, (
        "a client authenticated as someone-else had its reads served over a "
        "connection authenticated as voyd")


def test_a_fan_out_credential_that_does_not_work_degrades_to_the_primary(
        seeded, tmp_path, replica_set):
    """Wrong password, right answers.

    An optimisation that cannot authenticate must not become an outage, and
    it must not become a silent unauthenticated read either. The only
    acceptable outcome is the behaviour of every version of this proxy
    before fan-out existed.
    """
    _requires_auth()
    broken = replica_set.replace("voyd:voyd@", "voyd:wrong@")
    with _wire(tmp_path, replica_set, "--fan-out", broken,
               "--advertise-self") as uri:
        assert texts(uri, seeded.name, {"tenant_id": "acme"}) == ["live"]
