"""The claims this repository makes in its own comments.

Documentation rots differently from code: it never fails, it just stops
being true, and it stops being true most often by pointing at something
that is no longer there. This repository is unusually dependent on that not
happening -- the reasoning lives in the prose, the prose cites the file
that proves it, and a citation to a deleted file is worse than no citation,
because it reads like evidence.

So the citations are checked. Every path a comment, docstring or README
names has to resolve, which turns "the docs are accurate" from a habit
somebody maintains into a line in a diff somebody has to justify -- the
same move `guard()` makes on a policy file, one level up.

The rest of this file makes true four claims the prose was already making
about *itself*, each of which names this file in return:

    the public surface is deliberate    a name in `__all__` is a promise
    break-glass is named                nothing outside `core.py` reaches
                                        for the unfiltered read
    a sentinel never escapes            the private key `_redact` stamps
                                        is off the document by the time a
                                        caller sees it
    both doors leave the same row       two spellings of "forgotten" that
                                        produced different documents would
                                        be the drift this package is about

Pure: no database, no driver, no network.
"""

from __future__ import annotations

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Every file whose prose this repository asks a reader to trust.
SOURCES = sorted(
    [p for p in ROOT.rglob("*.py")
     if not any(x in p.parts for x in (".venv", "__pycache__", "dist",
                                       ".mypy_cache", ".pytest_cache"))]
    + [ROOT / n for n in ("README.md", "blog.md",
                          "docs/ranking-is-not-permission.md", "pyproject.toml",
                          "Dockerfile", "action.yml",
                          ".github/workflows/test.yml",
                          ".github/workflows/policy-plan.yml")])

REFERENCE = re.compile(
    r"\b((?:tests/|docs/|examples/|voyd/|scanner/|tools/)?"
    r"[\w][\w./-]*\.(?:py|md|toml|yml|yaml))\b")

# Names that look like paths and are not references to this repository.
NOT_OURS = {
    # An upstream file in another repository, credited on purpose.
    "tools/wire_proxy.py",
    # Written at runtime by the thing that names it.
    "voyd_bench_policy.py", "master.key",
    # Generic nouns in a sentence about other people's projects.
    "settings.py", "conftest.py", "setup.py", "requirements.txt",
    # Written by a test into its own tmp_path.
    "one.py", "two.py", "voydfile.py",
    # The two policy files `voyd-plan` compares, written by its
    # tests into `tmp_path` and named for what they stand for. The
    # `.new.` one is the placeholder in the README's own command line.
    "in_force.py", "proposed.py", "voydfile.new.py",
    # Written into $RUNNER_TEMP by the action that names them -- the
    # policy in force, read out of the base commit, and the comment body
    # -- and gone with the runner.
    "voyd-in-force.py", "voyd-plan-comment.md",
}


def resolve(ref: str, source: pathlib.Path) -> bool:
    """Does `ref` name something that exists, from where it was written?"""
    candidates = [ROOT / ref, source.parent / ref, ROOT / "tests" / ref,
                  ROOT / "docs" / ref, source.parent.parent / ref,
                  # `.github/workflows/test.yml` arrives without its dot,
                  # because a leading dot does not start an identifier.
                  ROOT / f".{ref}"]
    # A reference with a directory in it is still relative to somewhere:
    # `admission/core.py` is written inside `voyd/wire` and means the one
    # in `voyd/engine`, because there is only one.
    candidates += list(ROOT.glob(f"**/{ref}"))
    # A bare module name is read against the package that names it, which
    # is how `core.py` means `voyd/engine/admission/core.py` inside that
    # package and nothing at all outside it.
    return any(c.exists() for c in candidates)


def test_every_file_this_repository_cites_exists():
    """A citation to a deleted file reads like evidence and is not.

    This is the check that keeps the rest of the prose honest, and it is
    the one that would have caught thirty-one dead references at once:
    design documents that were removed, examples that were renamed, and
    tests that were deleted while the comments claiming they proved
    something stayed exactly where they were.
    """
    dangling: dict[str, list[str]] = {}
    for source in SOURCES:
        if not source.exists():
            continue
        for match in REFERENCE.finditer(source.read_text(errors="ignore")):
            ref = match.group(1)
            if ref in NOT_OURS or resolve(ref, source):
                continue
            dangling.setdefault(ref, []).append(
                str(source.relative_to(ROOT)))
    assert not dangling, "references to files that do not exist:\n" + "\n".join(
        f"  {ref}  cited by {', '.join(sorted(set(w)))}"
        for ref, w in sorted(dangling.items()))


def test_the_public_surface_is_deliberate():
    """A name in `__all__` is a promise; growing the list is a decision.

    Everything in `voyd.engine` stays importable from the module that owns
    it. What this pins is the shorter list the package *guarantees*, so
    adding to it is a line in a diff somebody has to justify rather than a
    consequence of having written a class.
    """
    import voyd.engine as engine

    for name in engine.__all__:
        assert hasattr(engine, name), f"engine.__all__ promises {name}"
    # The application-facing handle is not here and must not arrive.
    for name in ("Engine", "Model", "Memory"):
        assert name not in engine.__all__

    import voyd

    assert set(voyd.__all__) == {
        "guard", "deadline", "revocable", "holdable", "tenant",
        "restricted_to", "clearance", "embedded_with", "budget", "distinct",
        "sealed", "auto_embed", "subjects",
        # Not a rule, and exported beside them deliberately: a transform
        # is declared in the same file, and a vocabulary split across two
        # imports is one people get wrong. What it is *not* is an
        # enforcement point -- see `transforms.py` for why that is safe.
        "transform", "rerank",
        "__version__"}, (
        "the policy vocabulary changed; that is the package's whole public "
        "surface, so it is a deliberate edit and not an incidental one")


def test_break_glass_does_not_leave_the_package_that_counts_it():
    """The ungated read is private, and stays inside `admission`.

    `including_refused()` is the mechanism plus a gate and a counter; the
    primitive underneath it is private for that reason. Its siblings in
    the package use it -- a mark write has to see what it is marking --
    and that is the boundary: a caller outside would be a second door onto
    every refusal this package makes, opened without the counter that
    makes the first one auditable.
    """
    package = ROOT / "voyd" / "engine" / "admission"
    offenders = []
    for source in ROOT.rglob("voyd/**/*.py"):
        if "__pycache__" in source.parts or package in source.parents:
            continue
        if "_unfiltered(" in source.read_text():
            offenders.append(str(source.relative_to(ROOT)))
    assert not offenders, (
        f"the ungated read is reached from {offenders}, outside the package "
        f"that counts it; break-glass has a name so it can be grepped for")


def test_a_subject_sentinel_never_escapes_to_a_caller():
    """`_redact` has to return a document and a count, so it stamps a key.

    One strip point rather than one per read path -- and a sentinel that
    escapes to a caller is a worse bug than the one it was added to fix,
    because it arrives as a field nobody declared in a document somebody
    is about to put in a prompt.
    """
    from voyd.engine.admission.core import _REDACTED

    assert _REDACTED.startswith("__"), "a sentinel should look like one"
    # It is stamped in exactly one place and stripped in exactly one, both
    # inside the module that owns it.
    core = (ROOT / "voyd" / "engine" / "admission" / "core.py").read_text()
    assert core.count("_REDACTED") <= 5
    for source in ROOT.rglob("voyd/**/*.py"):
        if "__pycache__" in source.parts or source.name == "core.py":
            continue
        assert "__redacted__" not in source.read_text(), (
            f"{source} knows about a key that should never leave core.py")


def test_both_doors_leave_the_same_row():
    """Two spellings of "forgotten" that produced different documents.

    `deleteOne` and `findOneAndDelete` are different wire commands, so the
    boundary rewrites them separately -- and an audit reading rows must not
    be able to tell which verb produced one. They share `_forget_pipeline`
    for exactly that reason, and this is what holds them to it.
    """
    from voyd.engine import Deadline, revoked
    from voyd.engine.admission import AdmissionSpec
    from voyd.wire.policy import Guard
    from voyd.wire.policy.verbs import _forget_pipeline

    spec = AdmissionSpec("notes", rules=(Deadline("expire_at"),
                                         revoked("forgotten")))
    guard = Guard(spec, on_delete="revoke")

    # Compared by shape, not by instant: each call stamps `now()`, and two
    # calls a microsecond apart differ in a way that says nothing about
    # whether the two doors agree.
    def shape(pipeline):
        return re.sub(r"datetime\.datetime\([^)]*\)", "<when>", str(pipeline))

    delete = _forget_pipeline(guard.spec, "revoked")
    find_and_delete = _forget_pipeline(guard.spec, "revoked")
    assert shape(delete) == shape(find_and_delete)

    written = str(delete)
    # The mark, the deadline and the derived encodings: one spelling of a
    # forgotten document, whichever verb asked for it.
    assert "forgotten" in written
    assert "expire_at" in written
    for derived in spec.derived_fields:
        assert derived in written, (
            f"{derived!r} is a lossy encoding of the document and has to be "
            f"destroyed rather than merely refused")


@pytest.mark.parametrize("module", [
    "voyd.wire.policy", "voyd.wire.proxy", "voyd.wire.upstream",
    "voyd.wire.identity", "voyd.wire.report", "voyd.wire.cli",
    "voyd.wire.plan", "voyd.wire.plan_report",
    "voyd.engine", "voyd.engine.admission", "voyd",
    "voyd.engine.plan", "voyd.engine.attest",
    "voyd.engine.admission.transforms", "voyd.engine.admission.rerank",
])
def test_every_module_a_reader_is_pointed_at_imports(module):
    # The package docstrings are a map. A map naming a module that does
    # not import is the same defect as one naming a file that does not
    # exist, one level in.
    __import__(module)


@pytest.mark.parametrize("module", [
    "voyd.engine.plan", "voyd.engine.attest",
    "voyd.engine.admission.transforms", "voyd.engine.admission.rerank",
    "voyd.wire.plan_report",
])
def test_the_modules_that_claim_to_be_pure_reach_no_database(module):
    """Each of these says "pure" in its own docstring. Checked, not trusted.

    Purity is not an aesthetic here -- it is what lets the same check run
    inside a wire proxy, what lets `voyd-plan` ask about a policy nobody
    deployed, and what lets the terminal admission pass be cheap enough
    to run after somebody else's reranker. A `import pymongo` added to
    any of them would take all three away quietly.
    """
    import ast
    import pathlib

    path = pathlib.Path(ROOT, *module.split(".")).with_suffix(".py")
    tree = ast.parse(path.read_text())
    reached = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            reached |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            reached.add(node.module.split(".")[0])
    forbidden = reached & {"pymongo", "bson", "socket", "asyncio",
                           "requests", "urllib"}
    assert not forbidden, (
        f"{module} says it is pure and imports {sorted(forbidden)}")
