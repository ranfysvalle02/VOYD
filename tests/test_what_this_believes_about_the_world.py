"""The guards here check intrinsic properties. The bugs were all extrinsic.

Every other architecture test in this suite is decidable from the tree alone:
the import graph does not invert, the export list was agreed to, no symbol is
orphaned, no document names a file that was deleted. Deterministic, never
flaky, and they have caught real regressions -- including several in this
session.

They also had nothing to say about any of the four bugs that actually
shipped: a version floor one minor release too high; ``derived_fields``
reaching for a field that server-side embedding had moved out of the
document; ``sealed()`` and ``auto_embed`` on one path with nothing to object;
an embedding default two generations stale. None is a logic error. Each is an
assertion about the outside world, encoded in the source, with no expiry and
no owner.

**And the first attempt to fix that did not work either.** It gave every
assumption a ``checked: date`` and failed the build six months on. The
docstring admitted the hole rather than closing it -- *moving the date
without re-reading the source is available* -- which makes the whole
mechanism decoration. A self-attested date is precisely the artifact
``ledger.py`` spends forty lines refusing to accept from anybody else.

So the date is gone. An assumption now carries a **runnable check**, and the
verification record is written by the verifier into a lock file beside each
registry. What this file guards, in four parts:

1. probeable facts must be probed, never encoded -- the shape that bit is
   banned outright;
2. every standing fact must carry a check a stranger can run;
3. the record must **bind to the claim it verified**, so editing a belief
   invalidates its attestation;
4. and it must be fresh.
"""

from __future__ import annotations

import ast
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import voyd.assumptions as app
import voyd.engine.assumptions as engine
from voyd.engine.assumptions import (SHELF_LIFE, Assumption, Check,
                                     load_record, status, unsettled, verify)

ENGINE_DIR = Path(__file__).resolve().parents[1] / "voyd" / "engine"

REGISTRIES = (
    ("engine", engine.WORLD, engine.RECORD),
    ("vendors", app.VENDORS, app.RECORD),
)
EVERYTHING = engine.WORLD + app.VENDORS


def _ok(text="anything"):
    return lambda url: text


# ---- 1. a probeable fact may not be a constant --------------------------

def _version_comparisons(path: Path) -> list[str]:
    """Comparisons of something version-shaped against a literal tuple.

    AST rather than a regex, for the reason the layering test gives: the
    thing being looked for is a *structure*, and a regex over the text would
    also match it inside a docstring explaining why not to do it -- which
    this package now has several of.
    """
    found = []
    for node in ast.walk(ast.parse(path.read_text())):
        if not isinstance(node, ast.Compare):
            continue
        parts = [node.left, *node.comparators]
        names = [p.id.lower() if isinstance(p, ast.Name) else p.attr.lower()
                 for p in parts if isinstance(p, (ast.Name, ast.Attribute))]
        if not any("version" in n for n in names):
            continue
        if any(isinstance(p, ast.Tuple)
               and all(isinstance(e, ast.Constant) for e in p.elts)
               for p in parts):
            found.append(ast.unparse(node))
    return found


@pytest.mark.parametrize("path", sorted(ENGINE_DIR.rglob("*.py")),
                         ids=lambda p: p.name)
def test_no_capability_is_inferred_from_a_hardcoded_version(path):
    """The exact bug, banned by shape.

    ``capabilities.py`` opens by explaining that Atlas support used to be
    guessed from a connection string, that every local run silently took a
    fallback path for months, and that **asking the server is the only
    honest question**. Three lines below that paragraph it compared a
    version tuple to a constant, and the constant was wrong.
    """
    offenders = _version_comparisons(path)
    assert not offenders, (
        f"{path.name} decides a capability by comparing a version to a "
        f"literal: {offenders}. Probe the feature instead -- run the stage "
        f"and catch OperationFailure, the way _supports_rank_fusion does. A "
        f"version floor is somebody else's release note pasted into this "
        f"repository, and it goes stale without anything failing.")


def test_the_version_floor_that_was_wrong_is_gone():
    source = (ENGINE_DIR / "capabilities.py").read_text()
    assert "RANK_FUSION_MIN_VERSION = (" not in source


async def test_rank_fusion_is_detected_by_asking_the_server(core):
    """The replacement, against a real deployment -- the only place this
    question has ever had an honest answer."""
    from voyd.engine.capabilities import _supports_rank_fusion

    engine_, db = core
    assert await _supports_rank_fusion(db) is True
    assert engine_.capabilities.search_tier == "hybrid"


# ---- 2. a standing fact must carry a runnable check ---------------------

@pytest.mark.parametrize("assumption", EVERYTHING, ids=lambda a: a.name)
def test_every_belief_can_be_re_established_by_a_stranger(assumption):
    """The field that replaced the date.

    A claim whose evidence cannot be retrieved is a memory. ``Check`` makes
    "model X is the recommendation" into a fetch and some substring tests,
    which anybody can repeat without trusting whoever wrote the entry.
    """
    assert assumption.check.url.startswith("https://")
    assert assumption.check.present or assumption.check.absent
    assert assumption.claim.strip().endswith(".")
    assert len(assumption.why_not_probed) > 40, (
        "why this is not probed is what keeps the registry from becoming a "
        "place to put things instead of checking them")
    assert len(assumption.breaks) > 40


def test_a_check_that_asserts_nothing_is_refused():
    """It would pass forever, which is the date's failure in a new costume."""
    with pytest.raises(ValueError, match="asserts nothing"):
        Check(url="https://example.invalid/doc")


def test_a_check_must_be_fetchable():
    with pytest.raises(ValueError, match="fetchable url"):
        Check(url="ask a colleague", present=("x",))


def test_an_assumption_cannot_be_declared_empty():
    with pytest.raises(ValueError, match="non-empty"):
        Assumption(name="x", claim="", why_not_probed="w", breaks="b",
                   check=Check(url="https://e.invalid", present=("x",)))


def test_the_engine_declares_no_vendor_beliefs():
    """The split follows the engine/application boundary rather than carving
    an exception into it."""
    banned = ("voyage", "openai", "cohere", "pinecone")
    for assumption in engine.WORLD:
        blob = f"{assumption.claim} {assumption.check.url}".lower()
        assert not any(v in blob for v in banned), \
            f"{assumption.name} names a vendor; declare it in VENDORS"


def test_no_two_assumptions_share_a_name():
    names = [a.name for a in EVERYTHING]
    assert len(names) == len(set(names))


# ---- 3. the record binds to the claim it verified -----------------------
#
# The property the date version could not have had at all.

def test_editing_a_claim_invalidates_its_attestation():
    """Re-verification is required by *changing your mind*, not only by the
    passage of time.

    Under the old design somebody could widen a claim -- soften it, change
    which model it names -- and the date would sit there attesting to a
    sentence that no longer existed. The fingerprint covers the claim text
    and the check together, so any edit to either moves it.
    """
    original = app.VENDORS[0]
    record = verify([original], fetch=_ok("voyage-4 voyage-4-large "
                                          "quantization dimensions"))
    assert status([original], record)[0]["state"] == "verified"

    widened = Assumption(
        name=original.name,
        claim=original.claim.replace("voyage-4 is", "some model is"),
        why_not_probed=original.why_not_probed, breaks=original.breaks,
        check=original.check)
    assert status([widened], record)[0]["state"] == "changed"


def test_editing_a_check_invalidates_its_attestation():
    """The other half: keeping the sentence and quietly weakening the test
    that backs it would otherwise inherit the old attestation."""
    original = app.VENDORS[0]
    record = verify([original], fetch=_ok("voyage-4 voyage-4-large "
                                          "quantization dimensions"))
    weakened = Assumption(
        name=original.name, claim=original.claim,
        why_not_probed=original.why_not_probed, breaks=original.breaks,
        check=Check(url=original.check.url, present=("voyage",)))
    assert status([weakened], record)[0]["state"] == "changed"


def test_there_is_no_date_in_the_source_to_bump():
    """The hole this rewrite exists to close, asserted rather than trusted.

    ``checked=date(...)`` was a human attesting to an action nobody
    witnessed. Staleness is now read from the machine's record, so there is
    nothing in either registry a person can edit to buy another six months.
    """
    for module in (engine, app):
        tree = ast.parse(Path(module.__file__).read_text())
        # AST, not a substring: both modules *discuss* the field they no
        # longer have, and a text search would match the explanation of why
        # it is gone. Same reason the layering test parses imports rather
        # than grepping for them.
        annotated = {n.target.id for n in ast.walk(tree)
                     if isinstance(n, ast.AnnAssign)
                     and isinstance(n.target, ast.Name)}
        keywords = {k.arg for n in ast.walk(tree)
                    if isinstance(n, ast.Call) for k in n.keywords}
        assert "checked" not in annotated | keywords, (
            f"{module.__name__} has a self-attested date again. Staleness "
            f"is read from the verifier's record; a field here is a number "
            f"somebody can edit to buy six months without reading anything.")


def test_the_record_is_machine_written_and_says_so():
    """Every entry carries a digest of the document the check ran against.

    Forging the record is still possible -- see the module docstring, which
    declines to pretend otherwise. What this buys is that forging it means
    fabricating a sha256 in a file nobody hand-edits, in a diff that shows
    exactly that, instead of changing one integer in a source file nobody
    reads closely.
    """
    for label, registry, path in REGISTRIES:
        record = load_record(path)
        assert record, f"{label}: no verification record; run verify_all()"
        for name, entry in record.items():
            assert set(entry) == {"fingerprint", "verified_at", "ok",
                                  "complaints", "evidence"}, name
            assert len(entry["fingerprint"]) == 64
            if entry["ok"]:
                assert len(entry["evidence"]) == 64


# ---- 4. and it must be fresh, and honest about not being ----------------

@pytest.mark.parametrize("label,registry,path", REGISTRIES,
                         ids=lambda v: v if isinstance(v, str) else "")
def test_every_belief_has_been_checked_and_agreed(label, registry, path):
    """**This test fails on a date, and that is the point.**

    The standing objection is real: it breaks a build for a reason unrelated
    to the commit that trips it. The alternative is the one already measured
    -- a constant wrong for an unknown number of months, found by accident,
    by somebody reading a vendor's documentation about something else.

    Fixing it is one command: ``python -m voyd.assumptions``. If the check
    still agrees, the record refreshes and the build moves on. If it does
    not, the failure names the substring that changed, which is the sentence
    somebody needs to go and read.
    """
    overdue = unsettled(registry, load_record(path))
    assert not overdue, (
        f"{label}: beliefs about other people's software are unsettled -- "
        + "; ".join(f"{r['name']} [{r['state']}"
                    + (f", {r['age_days']}d" if r.get("age_days") is not None
                       else "")
                    + "]" + (f" {r['complaints']}" if r.get("complaints")
                             else "")
                    for r in overdue)
        + ". Run `python -m voyd.assumptions` to re-check them against "
          "their sources.")


def test_an_unverified_belief_is_not_reported_as_a_passing_one():
    """Three states, deliberately not collapsed into a boolean. A fresh
    checkout has *no* record, which is neither passing nor failing, and
    reporting it as either would be a lie in one direction."""
    rows = status(app.VENDORS, {})
    assert {r["state"] for r in rows} == {"unverified"}
    assert unsettled(app.VENDORS, {}) == rows


def test_a_failing_check_names_what_changed():
    """The failure has to be actionable. "Something is wrong with the model
    page" sends somebody to read a page; "missing 'voyage-4'" sends them to
    the paragraph."""
    record = verify(app.VENDORS[:1], fetch=_ok("voyage-5 is here now"))
    row = status(app.VENDORS[:1], record)[0]
    assert row["state"] == "failed"
    assert any("voyage-4" in c for c in row["complaints"])
    assert any("voyage-5" in c for c in row["complaints"])


def test_a_successor_shipping_is_what_expires_the_claim():
    """Asserting that a model still appears on a page stays true for years
    after it stops being recommended. Watching for the *successor* fails on
    the event that actually made the last default stale."""
    good = "voyage-4 voyage-4-large quantization dimensions"
    assert verify(app.VENDORS[:1], fetch=_ok(good))[
        app.VENDORS[0].name]["ok"] is True
    assert verify(app.VENDORS[:1], fetch=_ok(good + " voyage-5"))[
        app.VENDORS[0].name]["ok"] is False


def test_a_fetch_failure_is_a_result_not_a_crash():
    """The verifier runs unattended. A network error that raised would stop
    the other checks, and the one that could not be reached is exactly the
    one worth recording."""
    def boom(url):
        raise TimeoutError("no route to host")

    record = verify(app.VENDORS[:1], fetch=boom)
    entry = record[app.VENDORS[0].name]
    assert entry["ok"] is False and entry["evidence"] is None
    assert "fetch failed" in entry["complaints"][0]


def test_staleness_is_measured_from_the_record(tmp_path):
    old = datetime.now(timezone.utc) - SHELF_LIFE - timedelta(days=1)
    record = verify(app.VENDORS[:1],
                    fetch=_ok("voyage-4 voyage-4-large quantization "
                              "dimensions"),
                    now=old)
    row = status(app.VENDORS[:1], record)[0]
    assert row["state"] == "verified" and row["stale"] is True
    assert unsettled(app.VENDORS[:1], record)


def test_an_unreadable_record_is_empty_not_fatal(tmp_path):
    """A corrupt lock file must degrade to "nothing is verified", which the
    build already treats as a failure -- not to an exception during
    ``health()``."""
    broken = tmp_path / "assumptions.lock.json"
    broken.write_text("{not json")
    assert load_record(broken) == {}
    assert load_record(tmp_path / "absent.json") == {}


# ---- 5. and it is visible to an operator --------------------------------

async def test_health_reports_what_the_engine_believes(core):
    """A registry nobody reads is a comment. It rides on the same endpoint
    as the search tier and the refusal counters, because "why is this
    deployment answering the way it is" is one question."""
    engine_, _ = core
    reported = engine_.health()["assumptions"]

    assert reported["declared"] == len(engine.WORLD)
    assert reported["shelf_life_days"] == SHELF_LIFE.days
    assert reported["unsettled"] == []
    assert all("url" in e and "state" in e for e in reported["entries"])


def test_the_report_names_what_is_unsettled_rather_than_hiding_it():
    reported = engine.report_assumptions(app.VENDORS, {})
    assert set(reported["unsettled"]) == {a.name for a in app.VENDORS}
    assert all(e["state"] == "unverified" for e in reported["entries"])
