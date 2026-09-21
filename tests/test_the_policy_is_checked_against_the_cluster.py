"""A policy file is a set of claims about a cluster nobody verified.

`capabilities.py` exists because the engine used to *infer* what a deployment
could do, and both times it inferred it was wrong for months with no log line.
Its docstring is the argument this file is built on:

    A version floor is a claim about software this package does not ship,
    with no expiry and nobody responsible for it.

`auto_embed("voyage-4")` in a voydfile is a claim about software this package
does not ship, with no expiry and nobody responsible for it. So is *there is
a TTL index on `expire_at`*, and *the server refuses plaintext in this sealed
field*. Every one can be false while the boundary goes on enforcing a policy
the storage underneath it is not holding up.

**Almost none of this needs a database, and that is not a convenience.** The
part that decides is `audit()` -- index listings in, findings out -- so every
branch is tested against the exact documents a cluster would have returned,
*including the ones no cluster here can produce*. Atlas Local registers no
embedding models: it rejects `auto_embed("voyage-4")` at index creation with
`CanonicalModel: voyage-4 not registered yet, supported models are: []`. The
happy path for server-side embedding is therefore untestable against anything
in this repository's docker-compose, and a pure analysis function is what
makes it testable at all.

The two branches Atlas Local *can* produce -- no search index, and a plain
vector index where the policy expects an autoEmbed field -- are asserted end
to end at the bottom, against a real `mongod` and a real proxy.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

from voyd.wire import preflight as pf

from voyd.declare import OPTIONS, load  # noqa: E402

from .conftest import free_port, mongo_host  # noqa: E402

TTL = {"key": {"expire_at": 1}, "name": "expire_at_1", "expireAfterSeconds": 0}
PLAIN_ON_DEADLINE = {"key": {"expire_at": 1}, "name": "expire_at_1"}
TENANT = {"key": {"tenant_id": 1}, "name": "tenant_id_1"}
TRAILING_TENANT = {"key": {"kind": 1, "tenant_id": 1}, "name": "kind_1_t_1"}
ID_ONLY = {"key": {"_id": 1}, "name": "_id_"}


def search_index(*fields, name="engine_vector_index"):
    return {"name": name, "type": "vectorSearch", "status": "READY",
            "latestDefinition": {"fields": list(fields)}}


AUTO = {"type": "autoEmbed", "path": "body", "model": "voyage-4"}
VECTOR = {"type": "vector", "path": "embedding", "numDimensions": 4}


def audit(declared, indexes=(ID_ONLY,), search=(), validator=None, **kw):
    return pf.audit(declared, indexes=list(indexes),
                    search_indexes=list(search), validator=validator, **kw)


def checks(findings):
    return {f.check for f in findings}


def by_check(findings, check):
    return next(f for f in findings if f.check == check)


# --------------------------------------------------------------------------
# The deadline: refusal works, and nothing reaps
# --------------------------------------------------------------------------

def test_a_deadline_with_no_ttl_index_behind_it_is_reported():
    """The README's whole opening premise, absent, and nothing says so.

    Refusal still works -- an expired fact is unreachable on the next read.
    What is missing is the layer *underneath* it, so the collection grows
    forever. A warning rather than fatal: the guarantee holds, the disk bill
    does not.
    """
    found = audit(pf.Declared("notes", deadline="expire_at"))
    assert checks(found) == {"deadline"}
    one = by_check(found, "deadline")
    assert one.severity == pf.WARN
    assert "grows without bound" in one.detail
    assert "expireAfterSeconds" in one.remedy


def test_a_plain_index_on_the_deadline_field_is_not_a_ttl_index():
    """The trap this check exists for. An index on `expire_at` looks like
    coverage in `listIndexes` output and reaps nothing -- only
    `expireAfterSeconds` makes the monitor visit it."""
    found = audit(pf.Declared("notes", deadline="expire_at"),
                  indexes=(ID_ONLY, PLAIN_ON_DEADLINE))
    assert "deadline" in checks(found)


def test_a_ttl_index_satisfies_the_deadline():
    assert audit(pf.Declared("notes", deadline="expire_at"),
                 indexes=(ID_ONLY, TTL)) == []


# --------------------------------------------------------------------------
# The tenant: correct, and not fast
# --------------------------------------------------------------------------

def test_a_tenant_with_no_index_leading_with_it_is_reported():
    found = audit(pf.Declared("notes", tenant="tenant_id"))
    assert checks(found) == {"tenant"}
    assert by_check(found, "tenant").severity == pf.WARN


def test_an_index_that_merely_contains_the_tenant_does_not_count():
    """`(kind, tenant_id)` cannot serve a query that knows only the tenant.

    Counting it would report coverage that does not exist, which is worse
    than reporting none -- somebody would read the clean bill and stop
    looking for why their reads are slow.
    """
    found = audit(pf.Declared("notes", tenant="tenant_id"),
                  indexes=(ID_ONLY, TRAILING_TENANT))
    assert "tenant" in checks(found)


def test_an_index_leading_with_the_tenant_satisfies_it():
    assert audit(pf.Declared("notes", tenant="tenant_id"),
                 indexes=(ID_ONLY, TENANT)) == []


# --------------------------------------------------------------------------
# auto_embed: the branches no cluster here can produce
# --------------------------------------------------------------------------

def test_auto_embed_with_no_search_index_at_all_is_fatal():
    """Nothing can serve this collection by any route.

    The boundary refuses every client-supplied `queryVector` -- correctly,
    by the declaration -- and there is no server-side encoding to query
    instead. That is a total outage for the collection, so it is better to
    not start than to discover it one query at a time.
    """
    found = audit(pf.Declared("notes", auto_embed={"body": "voyage-4"}))
    assert by_check(found, "auto_embed").severity == pf.FATAL
    assert "no search index at all" in by_check(found, "auto_embed").detail


def test_an_index_that_wants_a_client_vector_is_fatal():
    """A plain vector index under an `auto_embed` declaration.

    The index needs exactly the thing the boundary refuses. This is the
    self-inflicted outage the whole preflight was written for.
    """
    found = audit(pf.Declared("notes", auto_embed={"body": "voyage-4"}),
                  search=(search_index(VECTOR),))
    one = by_check(found, "auto_embed")
    assert one.severity == pf.FATAL
    assert "needs a client-supplied vector" in one.detail


def test_an_autoembed_field_on_a_different_path_does_not_count():
    """Embedding the title does not make the policy's claim about the body
    true, and a check matching on type alone would say it did."""
    elsewhere = {"type": "autoEmbed", "path": "title", "model": "voyage-4"}
    found = audit(pf.Declared("notes", auto_embed={"body": "voyage-4"}),
                  search=(search_index(elsewhere),))
    assert by_check(found, "auto_embed").severity == pf.FATAL


def test_the_model_in_the_index_must_be_the_model_in_the_policy():
    """The finding the whole thing exists for, and it cannot be produced
    locally: Atlas Local registers no models at all.

    An embedding is a (vector, model) pair. A policy naming voyage-4 over
    an index built with voyage-3.5 does not fail at query time -- it
    returns a confident score for the wrong documents, which `rules.py`
    measured at cosine +0.301 for unrelated text against -0.053 for the
    right answer.
    """
    other = {"type": "autoEmbed", "path": "body", "model": "voyage-3.5"}
    found = audit(pf.Declared("notes", auto_embed={"body": "voyage-4"}),
                  search=(search_index(other),))
    one = by_check(found, "auto_embed")
    assert one.severity == pf.FATAL
    assert "voyage-3.5" in one.detail
    assert "voyage-3.5" in one.remedy, (
        "the remedy has to offer both directions -- change the policy or "
        "rebuild the index -- because only the operator knows which of the "
        "two is the mistake")


def test_a_matching_autoembed_declaration_is_clean():
    """The happy path, asserted against the document a real Atlas cluster
    returns, on a machine where no such cluster exists."""
    assert audit(pf.Declared("notes", auto_embed={"body": "voyage-4"}),
                 search=(search_index(AUTO),)) == []


def test_the_field_is_found_among_several_and_across_indexes():
    assert audit(pf.Declared("notes", auto_embed={"body": "voyage-4"}),
                 search=(search_index(VECTOR, name="other"),
                         search_index(VECTOR, AUTO))) == []


# --------------------------------------------------------------------------
# sealed: the gap LIMITS listed as open, now reported
# --------------------------------------------------------------------------

def validator(*fields):
    return {"$jsonSchema": {"bsonType": "object", "properties": {
        f: {"bsonType": "binData"} for f in fields}}}


def test_a_sealed_field_with_no_validator_is_reported():
    """`--key-vault` encrypts writes *through* the boundary. It does not
    install the `binData` validator `Keyring.enforce()` does,
    so a writer connecting straight to the cluster can still store
    plaintext -- silently, permanently, and into the next backup.

    LIMITS.md listed that as open. It is still open; it is no longer
    silent.
    """
    found = audit(pf.Declared("notes", sealed=("text",)))
    one = by_check(found, "sealed")
    assert one.severity == pf.WARN
    assert "connects straight to the cluster" in one.detail
    assert "collMod" in one.remedy


def test_a_validator_pinning_the_field_satisfies_it():
    assert audit(pf.Declared("notes", sealed=("text",)),
                 validator=validator("text")) == []


def test_a_validator_covering_only_some_sealed_fields_is_reported():
    found = audit(pf.Declared("notes", sealed=("text", "notes_body")),
                  validator=validator("text"))
    assert "notes_body" in by_check(found, "sealed").detail
    assert "'text'" not in by_check(found, "sealed").detail


def test_a_validator_that_pins_a_field_to_something_else_does_not_count():
    """A `string` validator on a sealed field is the opposite of the point."""
    wrong = {"$jsonSchema": {"bsonType": "object",
                             "properties": {"text": {"bsonType": "string"}}}}
    assert "sealed" in checks(
        audit(pf.Declared("notes", sealed=("text",)), validator=wrong))


# --------------------------------------------------------------------------
# Absence, severity, and the reporting contract
# --------------------------------------------------------------------------

def test_a_collection_that_does_not_exist_yet_is_a_warning():
    """An ordinary first deploy, not a misconfiguration. But it is also
    what a typo in the policy file looks like, so it is said out loud."""
    found = audit(pf.Declared("notes", deadline="expire_at"), exists=False)
    assert checks(found) == {"exists"}
    assert by_check(found, "exists").severity == pf.WARN
    assert "typo" in by_check(found, "exists").remedy


def test_only_a_contradiction_is_fatal():
    """Severity is the whole interface. A missing TTL index must never
    block a deploy -- a deployment that has run that way for a month should
    not have its next restart refused by this file noticing."""
    soft = audit(pf.Declared("notes", deadline="expire_at",
                             tenant="tenant_id", sealed=("text",)))
    assert soft and not pf.fatal(soft)

    hard = audit(pf.Declared("notes", auto_embed={"body": "voyage-4"}))
    assert pf.fatal(hard)


def test_every_finding_carries_a_remedy():
    """A check that reports a problem and not its fix is one somebody
    disables."""
    everything = (
        audit(pf.Declared("n", deadline="expire_at", tenant="tenant_id",
                          sealed=("text",), auto_embed={"body": "voyage-4"}))
        + audit(pf.Declared("n"), exists=False))
    assert len(everything) == 5
    for finding in everything:
        assert finding.remedy.strip()
        assert finding.detail.strip()
        assert finding.collection and finding.check
        assert finding.severity in (pf.FATAL, pf.WARN)
        assert finding.check in finding.line()


def test_a_probe_that_could_not_run_never_reports_a_clean_bill():
    """The sharpest distinction in the file.

    A cluster that is correctly configured and a probe that never happened
    both produce an empty finding list. Reporting them identically would
    make this module worse than absent: "preflight found nothing" on a run
    where preflight never ran is the exact confidently-wrong shape this
    project is named after.
    """
    clean = "\n".join(pf.report([], None))
    assert "matches the policy file" in clean

    blind = "\n".join(pf.report([], "ServerSelectionTimeoutError: no primary"))
    assert "matches the policy file" not in blind
    assert "could not run" in blind
    assert "unreachable is not misconfigured" in blind


def test_findings_are_reported_worst_first():
    order = pf.report(
        [pf.Finding("n", "deadline", pf.WARN, "d", "r"),
         pf.Finding("n", "auto_embed", pf.FATAL, "d", "r")], None)
    assert "FATAL" in order[0]


# --------------------------------------------------------------------------
# What is verified is what is enforced
# --------------------------------------------------------------------------

def test_the_declarations_come_off_the_compiled_policy(tmp_path):
    """Read from the rules the boundary will enforce, not by re-parsing the
    file -- otherwise the thing verified and the thing enforced are two
    objects that can disagree, which is the bug class this module is for.
    """
    path = tmp_path / "voydfile.py"
    path.write_text("""
from voyd import guard, deadline, revocable, tenant, sealed, auto_embed

@guard("notes", on_delete="revoke")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()
    secret    = sealed()
    body      = auto_embed("voyage-4")

@guard("plain")
class Plain:
    expire_at = deadline()
""")
    specs = load(str(path))

    class _Guard:
        def __init__(self, spec):
            self.spec = spec

    declared = pf.declarations(
        {k: _Guard(v) for k, v in specs.items()}, OPTIONS)
    assert [d.collection for d in declared] == ["notes", "plain"]

    notes = declared[0]
    assert notes.deadline == "expire_at"
    assert notes.tenant == "tenant_id"
    assert notes.sealed == ("secret",)
    assert notes.auto_embed == {"body": "voyage-4"}

    plain = declared[1]
    assert plain.deadline == "expire_at"
    assert plain.tenant is None and plain.sealed == ()
    assert not plain.auto_embed


def test_a_collection_with_nothing_to_verify_produces_nothing():
    """A guard with only a revocation makes no claim about storage. It must
    not generate advice."""
    assert audit(pf.Declared("notes")) == []


# --------------------------------------------------------------------------
# End to end: the two branches Atlas Local can actually produce
# --------------------------------------------------------------------------

pymongo = pytest.importorskip("pymongo")

POLICY = """
from voyd import guard, deadline, revocable, tenant, auto_embed

@guard("notes", on_delete="revoke")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()
    body      = auto_embed("voyage-4")
"""


def run_wire(tmp_path, database: str, policy: str = POLICY, *extra):
    """The CLI, in `--verify-only` form so it exits either way.

    Which is the shape a deploy gate wants and the reason the flag exists:
    without it a *passing* check starts serving and never returns, so the
    success case could not be asserted from a test at all. The failure case
    would have worked, which is the trap -- a suite that can only assert
    the unhappy path looks complete and tells you nothing about the happy
    one.
    """
    path = tmp_path / "voydfile.py"
    path.write_text(policy)
    return subprocess.run(
        [sys.executable, "-m", "voyd.wire.proxy", "--config", str(path),
         "--listen", str(free_port()), "--target", mongo_host(),
         "--verify", database, "--verify-only", *extra],
        cwd=ROOT, capture_output=True, text=True, timeout=120)


@pytest.mark.needs_mongo
def test_a_contradicted_declaration_refuses_to_start(tmp_path, db):
    """Against a real cluster, with a real policy file, through the CLI.

    `db` is a throwaway database with a `notes` collection and no search
    index, which is the shape of a first deploy that got the declaration
    wrong. The boundary must not bind a port.
    """
    db.notes.insert_one({"tenant_id": "acme", "body": "the fault code"})
    done = run_wire(tmp_path, db.name)
    assert done.returncode == 3, done.stdout + done.stderr
    assert "preflight FATAL" in done.stdout
    assert "no search index at all" in done.stdout
    # The warnings still print. A fatal finding must not swallow the rest:
    # somebody fixing the index should learn about the TTL index now rather
    # than on the next run.
    assert "preflight warning" in done.stdout
    assert "expire_at" in done.stdout


@pytest.mark.needs_mongo
def test_a_matching_cluster_starts_and_says_so(tmp_path, db):
    """The control, and the only way to know the checks can pass at all.

    No `auto_embed` in this policy, because Atlas Local cannot satisfy one:
    it registers no embedding models and rejects the index at creation. So
    this asserts the two checks a plain `mongod` *can* satisfy, and asserts
    the clean bill is printed rather than inferred from silence.
    """
    db.notes.insert_one({"tenant_id": "acme", "body": "the fault code"})
    db.notes.create_index("expire_at", expireAfterSeconds=0, sparse=True)
    db.notes.create_index("tenant_id")
    done = run_wire(tmp_path, db.name, policy="""
from voyd import guard, deadline, revocable, tenant

@guard("notes", on_delete="revoke")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()
""")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "matches the policy file" in done.stdout
    assert "preflight FATAL" not in done.stdout
    assert "preflight warning" not in done.stdout


@pytest.mark.needs_mongo
def test_an_unreachable_cluster_does_not_block_the_boundary(tmp_path):
    """Unreachable is not misconfigured, and a deploy must survive it.

    A probe that refused to boot because a replica was electing would cause
    more outages than it prevents, so this asserts the *opposite* of the
    test above it: the reason is printed and the exit code is not 3.
    """
    path = tmp_path / "voydfile.py"
    path.write_text(POLICY)
    done = subprocess.run(
        [sys.executable, "-m", "voyd.wire.proxy", "--config", str(path),
         "--listen", str(free_port()),
         # A port nothing is listening on.
         "--target", f"127.0.0.1:{free_port()}", "--verify", "whatever",
         "--verify-only"],
        cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "preflight could not run" in done.stdout
    assert "unreachable is not misconfigured" in done.stdout
    assert "matches the policy file" not in done.stdout


def test_unreadable_search_indexes_are_not_a_contradiction():
    """Ignorance and a contradiction are different findings.

    A deployment with no mongot cannot answer `$listSearchIndexes`. Reading
    it and finding no autoEmbed field means the policy is wrong; *failing to
    read it* means nothing yet. Conflating them would tell a plain `mongod`
    that its auto_embed declaration was fatally broken -- false, and the
    loudest available way to be false.
    """
    assert audit(pf.Declared("notes", auto_embed={"body": "voyage-4"}),
                 check_embedding=False) == []


def test_the_other_checks_still_run_when_embedding_cannot_be_read():
    """The bug this flag was added for.

    An earlier version returned from the whole probe on the first
    unanswerable collection, so a policy with five collections and no mongot
    got one of them checked and a message that mentioned only auto_embed.
    Partial coverage, described as a narrower failure than it was.
    """
    found = audit(pf.Declared("notes", deadline="expire_at",
                              tenant="tenant_id",
                              auto_embed={"body": "voyage-4"}),
                  check_embedding=False)
    assert checks(found) == {"deadline", "tenant"}
    assert not pf.fatal(found)
