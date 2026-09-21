"""Crypto-shredding through a driver that has never heard of this package.

`test_encryption_is_the_answer_refusal_cannot_give.py` asserts the same
guarantee for the *library*: a key per scope, ciphertext at rest, destroying
the key making every copy unreadable. That version binds an import. A team
adopting it edits their application, and the writer that forgets -- the
migration script, the Node service, the shell -- writes plaintext that no
later fix reaches, because it is already in the backup.

This file asserts it for the *wire*, where the same guarantee binds the
connection instead. Every assertion below is made through a plain
`pymongo.MongoClient` with no encryption configured and no VOYD import in it,
which is the whole claim: if these hold for pymongo they hold for the Node
driver, for Compass and for a notebook, because all of them put the same
bytes on the wire.

Five things have to be true or the feature is worse than absent:

1. what reaches the disk is not the plaintext -- checked by reading the raw
   bytes through a *second, direct* connection, not by trusting the proxy;
2. the ordinary driver still gets a string back, or the encryption is a bug;
3. destroying one scope's key makes its documents unreachable *immediately*
   and leaves every other scope readable;
4. it is immediate rather than eventual, which takes revoking the documents
   before the key goes -- see `Vault.revoke_first`, and see the paragraph
   below, because this is the assertion that was added after running the
   feature showed the ordering was backwards;
5. a write this boundary cannot seal is refused, never forwarded.

**Why (4) is its own test.** Destroying a key is not instant at the reader.
libmongocrypt caches data keys, so a process that decrypted a scope a moment
ago keeps decrypting it until that cache turns over -- about a minute, which
is very nearly the TTL window this repository opens by complaining about. A
shred on its own therefore opens a second delete-is-a-wish window inside the
feature that exists to close the first one. Measured, not theorised: the
first working version of this did exactly that, and served a shredded
tenant's plaintext for thirty seconds afterwards.

Skips cleanly without `pymongocrypt`, and says so.
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

from .conftest import free_port, mongo_host

pymongo = pytest.importorskip("pymongo")
pytest.importorskip("pymongocrypt",
                    reason="no pymongocrypt: install the crypto extra")

ROOT = Path(__file__).resolve().parents[1]

SECRET = "alice was treated for a stress fracture in March"
KEPT = "the fault code is P0301"

POLICY = """
from voyd import guard, deadline, revocable, tenant, sealed

@guard("notes", on_delete="revoke")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()
    text      = sealed()
"""

# A policy that seals with nothing to scope the key to. Refused at load,
# which is the point: the alternative is one key for the collection, and
# erasing one subject taking every other tenant with them.
UNSCOPED = """
from voyd import guard, deadline, sealed

@guard("notes")
class Notes:
    expire_at = deadline()
    text      = sealed()
"""


@contextmanager
def _wire(tmp_path, database: str, *extra, policy: str = POLICY):
    """A sealing `voyd-wire` on a free port. Yields the port."""
    path = tmp_path / "voydfile.py"
    path.write_text(policy)
    port = free_port()
    proc = subprocess.Popen(
        [sys.executable, "tools/voyd_wire.py", "--config", str(path),
         "--listen", str(port), "--target", mongo_host(),
         "--key-vault", database, *extra],
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
def sealed_wire(tmp_path):
    """A sealing boundary, two tenants' rows, and a direct connection.

    Yields ``(through, direct, name)``. ``through`` is an ordinary client
    pointed at the boundary; ``direct`` is one pointed at the database, and
    it is the control: it reads the way a DBA, a replica and a restored
    backup all read, which is without us.
    """
    name = f"voyd_test_wire_seal_{uuid.uuid4().hex[:8]}"
    direct = pymongo.MongoClient(f"mongodb://{mongo_host()}/"
                                 "?directConnection=true")
    try:
        with _wire(tmp_path, name) as port:
            through = pymongo.MongoClient(
                f"mongodb://localhost:{port}/?directConnection=true",
                serverSelectionTimeoutMS=8000)
            through[name].notes.insert_many([
                {"tenant_id": "alice", "text": SECRET},
                {"tenant_id": "bob", "text": KEPT},
            ])
            try:
                yield through, direct, name
            finally:
                through.close()
    finally:
        direct.drop_database(name)
        direct.close()


def reachable(client, name, who):
    return sorted(d["text"] for d in client[name].notes.find(
        {"tenant_id": who}))


# --------------------------------------------------------------------------
# 1 + 2: the two halves of "encrypted, and still usable"
# --------------------------------------------------------------------------

def test_the_plaintext_never_reaches_the_disk(sealed_wire):
    """The client sent a string. What landed is ciphertext.

    No encryption is configured on that client. It has no `schema_map`, no
    `AutoEncryptionOpts`, no `crypt_shared`, and no VOYD import. It changed
    a connection string. That is the entire difference between this document
    and a plaintext one, and it is the claim the library version cannot
    make -- there, forgetting is a code review away.
    """
    _through, direct, name = sealed_wire
    on_disk = direct[name].notes.find_one({"tenant_id": "alice"})["text"]
    assert on_disk != SECRET
    assert getattr(on_disk, "subtype", None) == 6, (
        "a BSON Binary with subtype 6 is an encrypted value; this is not one")


def test_the_ordinary_driver_still_gets_a_string(sealed_wire):
    """Or the encryption is a bug rather than a feature."""
    through, _direct, name = sealed_wire
    assert reachable(through, name, "alice") == [SECRET]
    assert reachable(through, name, "bob") == [KEPT]


def test_the_control_holds(sealed_wire):
    """The direct connection must keep serving ciphertext it cannot read.

    Without this the tests above could pass for the wrong reason -- a
    boundary credited for something the database was doing. What a reader
    outside this boundary gets is bytes, and that is the property backups
    and replicas inherit.
    """
    _through, direct, name = sealed_wire
    rows = list(direct[name].notes.find({}))
    assert len(rows) == 2
    assert all(getattr(r["text"], "subtype", None) == 6 for r in rows)


# --------------------------------------------------------------------------
# 3 + 4: erasure, and the window it must not open
# --------------------------------------------------------------------------

def test_destroying_a_key_is_immediate_not_eventual(sealed_wire):
    """The assertion this feature shipped without, and failed.

    An erasure needs no new verb: the key vault is an ordinary collection,
    so `delete_one({"keyAltNames": "alice"})` is how any driver in any
    language asks. The boundary notices, revokes alice's documents, *then*
    lets the key die.

    Reading immediately afterwards is the whole test. A boundary that only
    destroyed the key would still be serving this plaintext, out of
    libmongocrypt's cache, for roughly the next minute -- and would look
    exactly like this one until you timed it.
    """
    through, _direct, name = sealed_wire
    through[name]["__keys"].delete_one({"keyAltNames": "alice"})

    assert reachable(through, name, "alice") == [], (
        "alice's key was destroyed and her document was still served: the "
        "revocation did not precede the shred, so the key cache is a window")


def test_shredding_one_tenant_leaves_the_others_readable(sealed_wire):
    """The only reason per-subject erasure means anything.

    A literal `keyId` would give one key per collection, and honouring one
    person's erasure request would make every other tenant's rows
    unreadable at the same instant. The key is resolved per scope, so it
    does not.
    """
    through, _direct, name = sealed_wire
    through[name]["__keys"].delete_one({"keyAltNames": "alice"})
    assert reachable(through, name, "bob") == [KEPT]


def test_the_row_survives_the_erasure_and_says_why(sealed_wire):
    """Unreachable first, erased second -- and the evidence stays.

    Nothing was destroyed except the key. The row is on disk for the
    investigation, carrying the mark and the reason, and its bytes are
    noise to every reader that does not hold a key nobody holds.
    """
    through, direct, name = sealed_wire
    through[name]["__keys"].delete_one({"keyAltNames": "alice"})

    assert direct[name].notes.count_documents({}) == 2
    row = direct[name].notes.find_one({"tenant_id": "alice"})
    assert row["forgotten"]["reason"] == "key destroyed"
    assert getattr(row["text"], "subtype", None) == 6


def test_the_key_is_actually_gone(sealed_wire):
    """Bob's key is untouched, and alice's is not there to be found."""
    through, direct, name = sealed_wire
    through[name]["__keys"].delete_one({"keyAltNames": "alice"})

    vault = direct[name]["__keys"]
    assert vault.count_documents({"keyAltNames": "alice"}) == 0
    assert vault.count_documents({"keyAltNames": "bob"}) == 1


def test_an_erased_document_does_not_fail_the_page_it_is_on(sealed_wire):
    """Fewer rows, never an error -- asserted on a genuinely mixed batch.

    Automatic decryption raises for the whole *batch* when one key is
    gone, so a page of fifty containing one erased row would be a 500.
    That is the "fewer rows, or an error" shape this codebase refuses
    everywhere else, and it is the entire reason `unseal` is per document.

    Getting a mixed batch takes some care, and an earlier version of this
    test did not: within one scope the key is shared, so a shred is
    all-or-nothing, and a *cross*-scope read is refused wholesale by the
    off-scope rule before decryption is even reached. Either way the batch
    is uniform and the claim goes unchecked.

    What does mix, inside one scope and one batch: rows that carry the
    sealed field and rows that do not. A note with no body is an ordinary
    thing to have. After the shred the twenty sealed rows are refused as
    unrecoverable and the twenty unsealed ones come back -- one page, two
    verdicts, no exception, and an exact count.
    """
    through, _direct, name = sealed_wire
    notes = through[name].notes
    notes.insert_many(
        [{"tenant_id": "carol", "text": f"sealed body {i}", "n": i}
         for i in range(20)]
        + [{"tenant_id": "carol", "label": f"no body {i}", "n": 100 + i}
           for i in range(20)])

    assert notes.count_documents({"tenant_id": "carol"}) == 40
    before = list(notes.find({"tenant_id": "carol"}))
    assert len(before) == 40, "the control: all forty are reachable first"

    through[name]["__keys"].delete_one({"keyAltNames": "carol"})

    # No exception is the first half of the assertion; the count is the
    # second. A batch that raised would never reach either.
    after = list(notes.find({"tenant_id": "carol"}))
    assert len(after) == 20, (
        f"expected the twenty rows with no sealed field to survive and the "
        f"twenty sealed ones to be refused; got {len(after)}")
    assert all("text" not in row for row in after)
    assert sorted(row["n"] for row in after) == list(range(100, 120))


# --------------------------------------------------------------------------
# 5: a write it cannot seal is refused, never forwarded
# --------------------------------------------------------------------------

def test_a_write_with_no_scope_is_refused(sealed_wire):
    """There is no safe fallback, so there is no fallback.

    A document with no tenant has no key to be sealed under. Forwarding it
    would put the plaintext this deployment chose encryption to protect
    onto the disk, the replica and the backup, permanently and silently.
    Refusing it is loud, harmless and fixable.
    """
    through, direct, name = sealed_wire
    with pytest.raises(pymongo.errors.OperationFailure) as caught:
        through[name].notes.insert_one({"text": "no tenant on this one"})
    assert "tenant_id" in str(caught.value)

    assert direct[name].notes.count_documents(
        {"text": "no tenant on this one"}) == 0, (
        "the write was refused to the client and forwarded anyway, which is "
        "the worst of both: an error the caller will retry and a plaintext "
        "row already on disk")


def test_an_update_seals_what_it_sets(sealed_wire):
    """`$set` on a sealed field is encrypted too, or the second write leaks.

    Covering `insert` and not `update` would give a team the guarantee for
    the row they created and silently not for the row they corrected --
    which is the same defect shape as covering one delete verb and not the
    other.
    """
    through, direct, name = sealed_wire
    through[name].notes.update_one(
        {"tenant_id": "bob"}, {"$set": {"text": "corrected: P0302"}})

    assert reachable(through, name, "bob") == ["corrected: P0302"]
    on_disk = direct[name].notes.find_one({"tenant_id": "bob"})["text"]
    assert getattr(on_disk, "subtype", None) == 6


# --------------------------------------------------------------------------
# The policy file is still the configuration
# --------------------------------------------------------------------------

def test_sealing_without_a_tenant_fails_at_load(tmp_path):
    """A scope with no name is one key for everybody. Refused when read.

    Not at the first write, and not at the erasure request that takes out
    every other tenant. When the file is loaded.
    """
    path = tmp_path / "voydfile.py"
    path.write_text(UNSCOPED)
    done = subprocess.run(
        [sys.executable, "tools/voyd_wire.py", "--config", str(path),
         "--listen", str(free_port()), "--target", mongo_host(),
         "--key-vault", "irrelevant"],
        cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert done.returncode == 2
    assert "tenant()" in done.stderr


def test_sealing_with_no_key_vault_refuses_to_start(tmp_path):
    """Fail-closed is not good enough when it is silent.

    Without a vault the boundary holds no keys, so every sealed document
    would be refused as unrecoverable -- a total erasure nobody asked for,
    reported by a process that looks like it is working.
    """
    path = tmp_path / "voydfile.py"
    path.write_text(POLICY)
    done = subprocess.run(
        [sys.executable, "tools/voyd_wire.py", "--config", str(path),
         "--listen", str(free_port()), "--target", mongo_host()],
        cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert done.returncode == 2
    assert "--key-vault" in done.stderr


def test_a_key_vault_with_nothing_to_seal_refuses_to_start(tmp_path):
    """Holding a master key that buys nothing still costs a credential."""
    path = tmp_path / "voydfile.py"
    path.write_text("""
from voyd import guard, deadline, tenant

@guard("notes")
class Notes:
    expire_at = deadline()
    tenant_id = tenant()
""")
    done = subprocess.run(
        [sys.executable, "tools/voyd_wire.py", "--config", str(path),
         "--listen", str(free_port()), "--target", mongo_host(),
         "--key-vault", "unused"],
        cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert done.returncode == 2
    assert "sealed()" in done.stderr


def test_the_boundary_says_that_it_now_holds_keys(tmp_path):
    """The purity claim is in the README. The correction has to be louder.

    A reader who learned "this proxy holds no database connection of its
    own" and then switched on `--key-vault` is owed the retraction at
    startup, not in a footnote they will not read.
    """
    name = f"voyd_test_announce_{uuid.uuid4().hex[:8]}"
    direct = pymongo.MongoClient(f"mongodb://{mongo_host()}/"
                                 "?directConnection=true")
    try:
        path = tmp_path / "voydfile.py"
        path.write_text(POLICY)
        port = free_port()
        proc = subprocess.Popen(
            [sys.executable, "tools/voyd_wire.py", "--config", str(path),
             "--listen", str(port), "--target", mongo_host(),
             "--key-vault", name],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True)
        try:
            until = time.monotonic() + 20
            lines = []
            while time.monotonic() < until:
                line = proc.stdout.readline()
                if not line:
                    break
                lines.append(line)
                if "connect any driver" in line:
                    break
            said = "".join(lines)
            assert "HOLDS KEYS" in said
            assert "custody is" in said
            # Ephemeral is the default and is demo-grade. A deployment that
            # silently ran on it and lost every sealed document to a
            # restart is the exact surprise this project exists to remove.
            assert "ephemeral" in said.lower()
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
    finally:
        direct.drop_database(name)
        direct.close()


# --------------------------------------------------------------------------
# Sealing and fan-out: the narrow case where they must not compose
# --------------------------------------------------------------------------

def test_a_sealed_collection_is_never_ranked_on_a_secondary():
    """A correctness stop, not a performance one, so it is asserted.

    Fan-out takes the *marks* from the primary and the *documents* from a
    secondary, which is exactly right for a verdict that reads marks and
    wrong for one that has to decrypt the document it was handed. The
    secondary's copy would be decrypted and released while the primary was
    only ever asked about `expire_at`, so a scope shredded a moment ago, or
    a field re-sealed under a new key, would be resolved against whichever
    copy the replica happened to have.

    A pure unit test with no database anywhere near it, which is the point:
    this is a routing decision taken from the request, before it is sent.
    """
    sys.path.insert(0, str(ROOT / "tools"))
    import voyd_fanout

    from voyd.engine.admission import AdmissionSpec

    class _Guard:
        spec = AdmissionSpec("notes")

    guards = {"notes": _Guard()}
    body = {"aggregate": "notes", "pipeline": [{"$vectorSearch": {}}]}

    assert voyd_fanout.routes_to_secondary(body, guards) is not None, (
        "the control: an unsealed collection still fans out, or this test "
        "would pass for the wrong reason")
    assert voyd_fanout.routes_to_secondary(
        body, guards, sealed=frozenset({"notes"})) is None


# --------------------------------------------------------------------------
# Custody: the two claims LIMITS.md §5 makes about it
# --------------------------------------------------------------------------

def test_every_worker_shares_one_master_key(tmp_path):
    """`--workers N` must not mint a key per worker.

    Ephemeral custody generates a master key per *process*, so building it
    after the fork would give each worker a different one, and a tenant
    written through one worker would be undecryptable through the next. It
    is therefore built in the parent and inherited -- a data-loss bug that
    appears only at `--workers 2` and looks like corruption.

    Six clients so the kernel spreads them across both workers' accept
    queue; all six must read what one of them wrote.
    """
    name = f"voyd_test_workers_{uuid.uuid4().hex[:8]}"
    direct = pymongo.MongoClient(f"mongodb://{mongo_host()}/"
                                 "?directConnection=true")
    try:
        with _wire(tmp_path, name, "--workers", "2") as port:
            uri = f"mongodb://localhost:{port}/?directConnection=true"
            clients = [pymongo.MongoClient(uri, serverSelectionTimeoutMS=8000)
                       for _ in range(6)]
            try:
                clients[0][name].notes.insert_one(
                    {"tenant_id": "alice", "text": SECRET})
                for i, client in enumerate(clients):
                    assert reachable(client, name, "alice") == [SECRET], (
                        f"worker serving client {i} could not decrypt what "
                        f"another worker sealed: the master key was minted "
                        f"per worker instead of inherited across the fork")
            finally:
                for client in clients:
                    client.close()
    finally:
        direct.drop_database(name)
        direct.close()


def test_durable_custody_survives_a_restart(tmp_path):
    """`--kms local:/path` is the rung a proof of concept should be on.

    Ephemeral custody loses every sealed document when the process dies,
    which is correct for a demo and catastrophic anywhere else. The
    difference between the two rungs is one flag, and this is the
    assertion that the flag does what the help text says: a boundary
    stopped and started against the same master key still reads what the
    first one wrote.
    """
    name = f"voyd_test_durable_{uuid.uuid4().hex[:8]}"
    key = tmp_path / "master.key"
    direct = pymongo.MongoClient(f"mongodb://{mongo_host()}/"
                                 "?directConnection=true")
    try:
        with _wire(tmp_path, name, "--kms", f"local:{key}") as port:
            first = pymongo.MongoClient(
                f"mongodb://localhost:{port}/?directConnection=true",
                serverSelectionTimeoutMS=8000)
            first[name].notes.insert_one(
                {"tenant_id": "alice", "text": SECRET})
            first.close()

        # A different process, the same file. Nothing else is shared.
        with _wire(tmp_path, name, "--kms", f"local:{key}") as port:
            second = pymongo.MongoClient(
                f"mongodb://localhost:{port}/?directConnection=true",
                serverSelectionTimeoutMS=8000)
            try:
                assert reachable(second, name, "alice") == [SECRET]
            finally:
                second.close()
    finally:
        direct.drop_database(name)
        direct.close()


# --------------------------------------------------------------------------
# It says what it did, while it is still running
# --------------------------------------------------------------------------

def test_the_sealing_counters_are_reported(tmp_path):
    """A guarantee nobody counted is a claim about one.

    The read half reports itself for free, because the undecryptable tally
    is recorded on the *guard* rather than beside it -- so it arrives in
    `refused_by_reason_total{reason="unrecoverable"}` with the deadline and
    the revocation, which is where an operator is already looking.

    The write half had no series at all until these existed, and that is
    the gap worth a test: a boundary that silently stopped encrypting looks
    exactly like one that is encrypting. `sealed_writes_total` flat while a
    sealed collection is being written is plaintext reaching the disk, and
    nothing else in this process would say so.
    """
    import urllib.request

    name = f"voyd_test_metrics_seal_{uuid.uuid4().hex[:8]}"
    direct = pymongo.MongoClient(f"mongodb://{mongo_host()}/"
                                 "?directConnection=true")
    metrics_port = free_port()
    try:
        with _wire(tmp_path, name, "--metrics", str(metrics_port)) as port:
            client = pymongo.MongoClient(
                f"mongodb://localhost:{port}/?directConnection=true",
                serverSelectionTimeoutMS=8000)
            try:
                client[name].notes.insert_many(
                    [{"tenant_id": "alice", "text": f"body {i}"}
                     for i in range(5)])
                # One write it cannot seal, refused rather than forwarded.
                with pytest.raises(pymongo.errors.OperationFailure):
                    client[name].notes.insert_one({"text": "no tenant"})
                assert len(list(client[name].notes.find(
                    {"tenant_id": "alice"}))) == 5
                client[name]["__keys"].delete_one({"keyAltNames": "alice"})
                assert list(client[name].notes.find(
                    {"tenant_id": "alice"})) == []

                # Counters flush on a timer, not on the message path, so
                # the exposition is deliberately up to a second stale.
                deadline = time.monotonic() + 15
                said = ""
                while time.monotonic() < deadline:
                    with urllib.request.urlopen(
                            f"http://127.0.0.1:{metrics_port}/metrics",
                            timeout=5) as page:
                        said = page.read().decode()
                    if "voyd_sealed_writes_total 5" in said:
                        break
                    time.sleep(0.25)
            finally:
                client.close()

        assert "voyd_sealed_writes_total 5" in said, (
            "five documents were sealed and the series does not say so")
        assert "voyd_seal_refused_writes_total 1" in said
        assert "voyd_erasures_total 1" in said
        # The pair that must move together. An erasure counted with no
        # revocation behind it is the ordering being lost -- the key dies
        # and the documents stay readable until a cache turns over -- and
        # the only way to see that from outside is these two diverging.
        assert "voyd_erasure_revocations_total 5" in said, (
            "an erasure was sequenced but nothing was revoked ahead of it, "
            "which is the window this feature exists to close")
        # And now the interesting one, which is not the reason a reader
        # would guess.
        #
        # Those five documents were refused as **revoked**, not as
        # unrecoverable. The boundary had just encrypted them, so
        # libmongocrypt still holds the scope's key and the decrypt
        # *succeeds* -- for about another minute. What refuses them in that
        # window is the revocation the boundary wrote before destroying the
        # key, and that is precisely the arrangement the two halves exist
        # to produce:
        #
        #   the key cache is a window where the ciphertext still reads
        #       -> the revocation already refused the document
        #   refusal only binds this application's read path
        #       -> the key is gone, so every other copy is noise
        #
        # So `unrecoverable` staying at zero here is the design working,
        # not a gap. It starts climbing once the cache turns over, or
        # immediately in a process that never held the key -- which is any
        # other reader of the same data, including the next restart of
        # this one. Asserting the reason a reader would *expect* would have
        # made this test fail against a correct boundary.
        assert 'reason="deadline"} 5' in said, (
            "during the key-cache window the refusal belongs to the "
            "revocation the boundary wrote; if this is zero, nothing was "
            "revoked ahead of the shred and those documents were served")
        assert 'reason="unrecoverable"} 0' in said
        assert 'voyd_revoked_total{collection="notes"} 5' in said

        # `deadline` rather than `revoked`, and that is worth knowing
        # before an alert is written against it. The revocation pipeline
        # writes the mark *and* pulls `expire_at` in, so both rules now
        # refuse the document, and `Deadline` is declared first -- the
        # same reason an ordinary `delete` rewritten as a revocation
        # reports, so this is a property of the tool rather than of
        # sealing.
        #
        # Which is the argument for the two counters above existing at
        # all: the per-reason series cannot tell a subject who was erased
        # from a document that merely expired, because the boundary wrote
        # the same marks for both. `erasures_total` and
        # `erasure_revocations_total` are the pair that can, and they are
        # what a compliance question should be asked of. See LIMITS.md
        # §5.

        # And the help text has to survive, or a stranger reading the
        # endpoint cannot tell these apart.
        assert "# HELP voyd_erasures_total" in said
        assert "requests handled and not keys confirmed gone" in said
    finally:
        direct.drop_database(name)
        direct.close()
