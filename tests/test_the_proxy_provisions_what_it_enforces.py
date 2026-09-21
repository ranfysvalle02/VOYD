"""One artifact declares the policy, and the same artifact builds it.

Split those and you get a seam rather than an inconvenience: a boundary
that reads a policy file, enforces every word of it, and cannot create a
single index it depends on. Two artifacts, one declaration, and nothing
checking they agree.

What makes this testable rather than merely nice is the pair. `--ensure`
builds what the policy declares; `--verify` is separately written code that
reads the same declaration, creates nothing, and refuses to agree until the
cluster matches. **Ensure, then verify, then clean** is the claim, and it
already earned its keep: the first run of `voyd_ensure` reported a
server-embedded index that had silently fallen back to a client-vector one,
and `--verify` is what said so.

Against a real `mongod`, because the assertion is about indexes that exist.
"""

from __future__ import annotations

import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from .conftest import MONGO_URI, mongo_host

pymongo = pytest.importorskip("pymongo")
ROOT = Path(__file__).resolve().parents[1]

# No `auto_embed` here. Atlas Local registers no embedding models, so it
# *declines* the declaration and builds a client-vector index instead --
# which `--verify` correctly calls a contradiction, because the boundary
# refuses client-supplied vectors. That disagreement is the subject of its
# own test below rather than noise in every other one.
POLICY = """
from voyd import deadline, guard, revocable, tenant


@guard("notes", on_delete="revoke")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()
"""

EMBEDDING_POLICY = POLICY + """

@guard("papers")
class Papers:
    expire_at = deadline()
    forgotten = revocable()
    body = auto_embed("voyage-4")
"""


def _policy(tmp_path, body: str) -> Path:
    path = tmp_path / "voydfile.py"
    path.write_text(body)
    return path


def _run(policy: Path, *args: str, timeout: int = 180):
    return subprocess.run(
        [sys.executable, "-m", "voyd.wire.proxy", "--config", str(policy),
         "--target", mongo_host(), *args],
        cwd=ROOT, capture_output=True, text=True, timeout=timeout)


@pytest.fixture
def database():
    """A throwaway database name, dropped afterwards."""
    name = f"voyd_test_ensure_{uuid.uuid4().hex[:8]}"
    client = pymongo.MongoClient(MONGO_URI)
    try:
        yield name
    finally:
        client.drop_database(name)
        client.close()


def _seed(database: str) -> None:
    """One document, so the collection exists and `--verify` has something
    to inspect. It short-circuits on a collection that is absent -- "none
    of the checks below could run" -- and a run where the verifier checked
    nothing must not be mistaken for a run where it approved something."""
    client = pymongo.MongoClient(MONGO_URI)
    try:
        client[database].notes.insert_one({"tenant_id": "acme", "x": 1})
    finally:
        client.close()


def _findings(result) -> list[str]:
    return [ln for ln in result.stdout.splitlines()
            if "preflight warning" in ln or "preflight FATAL" in ln]


def test_verify_complains_before_anything_is_built(tmp_path, database):
    """The control, and it is load-bearing rather than ceremony.

    `--verify` exits 0 on a missing TTL index -- it is a warning, because
    refusal still holds and only the bytes linger. So the claim below
    cannot be "verify exited 0"; on an unprovisioned database it exits 0
    too. It has to be "verify found nothing to say", and this pins that
    the verifier is capable of saying something about this exact policy.
    """
    policy = _policy(tmp_path, POLICY)
    _seed(database)

    found = _findings(_run(policy, "--verify", database, "--verify-only"))

    assert any("deadline" in ln for ln in found), found
    assert any("tenant" in ln for ln in found), found


def test_ensure_then_verify_has_nothing_to_report(tmp_path, database):
    """The claim. Two separately written readers of one declaration, and
    the second one has nothing left to complain about.

    Asserted on the findings rather than the exit code, for the reason the
    control above records.
    """
    policy = _policy(tmp_path, POLICY)
    _seed(database)

    built = _run(policy, "--ensure", database, "--ensure-wait", "30",
                 "--ensure-only")
    assert built.returncode == 0, built.stdout + built.stderr

    checked = _run(policy, "--verify", database, "--verify-only")
    assert _findings(checked) == [], (
        f"--ensure built the schema and --verify still has complaints, so "
        f"one of the two is wrong about the same policy file:\n"
        f"{checked.stdout}\n{checked.stderr}")
    assert checked.returncode == 0, checked.stdout + checked.stderr


def test_ensure_is_idempotent(tmp_path, database):
    """Safe on every boot, because the alternative is a deploy step people
    are afraid to re-run."""
    policy = _policy(tmp_path, POLICY)
    _seed(database)
    first = _run(policy, "--ensure", database, "--ensure-wait", "30",
                 "--ensure-only")
    second = _run(policy, "--ensure", database, "--ensure-wait", "30",
                  "--ensure-only")
    assert first.returncode == 0, first.stdout + first.stderr
    assert second.returncode == 0, second.stdout + second.stderr

    checked = _run(policy, "--verify", database, "--verify-only")
    assert _findings(checked) == [], checked.stdout
    assert checked.returncode == 0, checked.stdout + checked.stderr


def test_ensure_builds_what_the_policy_names(tmp_path, database):
    """The indexes themselves, read back with an ordinary driver.

    `--verify` passing is the argument; this is the evidence underneath it,
    so a verifier that silently stopped checking would not take this test
    with it.
    """
    policy = _policy(tmp_path, POLICY)
    assert _run(policy, "--ensure", database, "--ensure-wait", "30",
                "--ensure-only").returncode == 0

    client = pymongo.MongoClient(MONGO_URI)
    try:
        indexes = list(client[database].notes.list_indexes())
    finally:
        client.close()

    ttl = [i for i in indexes if "expireAfterSeconds" in i]
    assert ttl, (
        "deadline() was declared and no TTL index backs it -- refusal is "
        "immediate either way, but the bytes would stay forever")
    assert ttl[0]["key"] == {"expire_at": 1}

    leading = [i for i in indexes if next(iter(i["key"])) == "tenant_id"]
    assert leading, (
        "tenant() was declared and no index leads with it: a scan that "
        "filters the tenant afterwards has already read the other "
        "tenant's rows in order to discard them")


def test_ensure_only_does_not_start_serving(tmp_path, database):
    """A deploy step is not a process that serves. If this ever blocked,
    it would hang a pipeline rather than fail it."""
    policy = _policy(tmp_path, POLICY)
    done = _run(policy, "--ensure", database, "--ensure-wait", "30",
                "--ensure-only", timeout=120)
    assert done.returncode == 0
    assert "listening" not in done.stdout.lower()


def test_ensure_only_without_ensure_is_refused(tmp_path, database):
    """The flag names a database because a policy file does not. Asking to
    build without saying where is a question, not a default."""
    policy = _policy(tmp_path, POLICY)
    asked = _run(policy, "--ensure-only")
    assert asked.returncode == 2
    assert "--ensure DB" in asked.stderr


def test_a_declined_auto_embed_is_reported_as_a_contradiction(tmp_path,
                                                              database):
    """Atlas Local registers no embedding models, so this is the one
    disagreement `--ensure` and `--verify` are *supposed* to have.

    The boundary refuses client-supplied vectors on a collection that
    declares `auto_embed`. If the deployment then declines to embed, the
    index that gets built needs exactly the vector the boundary refuses --
    so every vector read would be an error. That is a contradiction to
    report at boot, not a degradation to serve through, and this pins that
    `--ensure` says so rather than claiming it built what was asked.
    """
    policy = _policy(tmp_path, "from voyd import auto_embed\n" + EMBEDDING_POLICY)

    built = _run(policy, "--ensure", database, "--ensure-wait", "30",
                 "--ensure-only")
    assert built.returncode == 0, built.stdout + built.stderr
    assert "declined auto_embed" in built.stdout, (
        f"the deployment fell back to a client-vector index and --ensure "
        f"reported success at server-side embedding:\n{built.stdout}")

    checked = _run(policy, "--verify", database, "--verify-only")
    assert checked.returncode != 0, (
        "the index needs a client-supplied vector and the boundary refuses "
        "exactly those; --verify has to call that fatal")
