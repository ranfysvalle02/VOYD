"""The action's steps, executed the way a runner executes them.

This file exists because a rig that was *nearly* a runner passed while
the real one failed on the first pull request that used it. The
difference was one flag. GitHub runs a composite step under

    bash --noprofile --norc -e -o pipefail {0}

and the `-e` is not the action's to choose -- it arrives with the shell.
The planning step's whole job is to read a non-zero exit status, so under
an inherited `-e` it died at the exact moment it succeeded: the plan was
computed, the boundary had opened, and the shell aborted before anything
could say so. The job failed with no report and no comment, which is the
shape of an infrastructure problem rather than a finding, and the thing
people do about infrastructure problems in a required check is turn the
check off.

So the steps are not described here, they are **read out of `action.yml`
and run**, under that exact shell, against a throwaway git repository
with two commits in it. The expression syntax is the one thing this file
has to fake, and it fakes it by substitution rather than by rewriting the
script -- a test that retyped the commands would be testing its own copy.

Needs git and bash, which CI and every development machine have. No
cluster, no network, no GitHub.
"""

from __future__ import annotations

import os
import pathlib
import subprocess

import pytest

yaml = pytest.importorskip("yaml")

ROOT = pathlib.Path(__file__).resolve().parents[1]
ACTION = ROOT / "action.yml"

# Exactly what a runner invokes. Copied here on purpose rather than
# simplified: every character of it is a behaviour this action inherits.
RUNNER_SHELL = ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail"]

SCOPED = """
from voyd import deadline, guard, revocable, tenant


@guard("notes")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()
"""

UNSCOPED = """
from voyd import deadline, guard, revocable


@guard("notes")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
"""


def git(repo: pathlib.Path, *args: str) -> str:
    done = subprocess.run(["git", "-C", str(repo), *args],
                          capture_output=True, text=True, check=True)
    return done.stdout.strip()


@pytest.fixture
def repo(tmp_path):
    """A repository with a policy at HEAD and another at its parent.

    The action reads the policy in force out of git rather than taking a
    second path, so a fixture that handed it two files would skip the
    part most likely to be wrong.
    """
    def build(before: str, after: str) -> tuple[pathlib.Path, str]:
        work = tmp_path / "repo"
        work.mkdir()
        git(work.parent, "init", "-q", str(work))
        git(work, "config", "user.email", "suite@example.invalid")
        git(work, "config", "user.name", "suite")
        (work / "voydfile.py").write_text(before)
        git(work, "add", "-A")
        git(work, "commit", "-qm", "the policy in force")
        base = git(work, "rev-parse", "HEAD")
        (work / "voydfile.py").write_text(after)
        git(work, "add", "-A")
        git(work, "commit", "-qm", "the policy being proposed")
        return work, base
    return build


class Runner:
    """Enough of a runner to be wrong in the same ways as the real one."""

    def __init__(self, tmp_path: pathlib.Path, base: str, inputs: dict):
        spec = yaml.safe_load(ACTION.read_text())
        self.steps = {s["name"]: s for s in spec["runs"]["steps"]
                      if s.get("name")}
        self.defaults = {k: str(v.get("default", ""))
                         for k, v in spec["inputs"].items()}
        self.defaults.update({k: str(v) for k, v in inputs.items()})
        self.base = base
        self.temp = tmp_path / "runner-temp"
        self.temp.mkdir()
        self.out = self.temp / "GITHUB_OUTPUT"
        self.out.touch()
        self.summary = self.temp / "GITHUB_STEP_SUMMARY"
        self.summary.touch()

    @property
    def outputs(self) -> dict[str, str]:
        return dict(line.split("=", 1)
                    for line in self.out.read_text().splitlines()
                    if "=" in line)

    def _expand(self, script: str) -> str:
        script = script.replace("${{ github.event.pull_request.base.sha }}",
                                self.base)
        script = script.replace("${{ github.action_path }}", str(ROOT))
        for key, value in self.defaults.items():
            script = script.replace("${{ inputs.%s }}" % key, value)
        for key, value in self.outputs.items():
            script = script.replace("${{ steps.before.outputs.%s }}" % key,
                                    value)
        return script

    def run(self, name: str, cwd: pathlib.Path):
        env = dict(os.environ,
                   RUNNER_TEMP=str(self.temp),
                   GITHUB_OUTPUT=str(self.out),
                   GITHUB_STEP_SUMMARY=str(self.summary),
                   VOYD_TARGET=self.defaults.get("target", ""))
        script = self._expand(self.steps[name]["run"])
        return subprocess.run([*RUNNER_SHELL, "-c", script],
                              cwd=cwd, env=env, capture_output=True,
                              text=True)


def plan_through_the_action(tmp_path, repo, before, after, **inputs):
    work, base = repo(before, after)
    runner = Runner(tmp_path, base, inputs)
    first = runner.run("Read the policy in force", work)
    assert first.returncode == 0, first.stderr
    second = runner.run("Plan", work)
    return runner, second


def test_a_change_that_opens_the_boundary_survives_long_enough_to_say_so(
        tmp_path, repo):
    """The regression. One flag, and it cost the first live run.

    Exit 1 from `voyd-plan` is the finding, not a failure, and under the
    `-e` a runner supplies the step used to abort on it -- before the
    report was printed, before the outputs were set, and before the
    comment could be posted. A required check that fails with nothing
    attached is one people make non-blocking.
    """
    runner, step = plan_through_the_action(tmp_path, repo, SCOPED, UNSCOPED)

    assert step.returncode == 0, (
        f"the planning step died reading its own exit status:\n"
        f"{step.stderr}")
    assert runner.outputs["fails-open"] == "true"
    assert "tenant_removed" in step.stdout
    # The two things the later steps consume. An output that never got
    # written is how the comment step goes quiet without failing.
    assert "report" in runner.outputs and "json" in runner.outputs
    assert pathlib.Path(runner.outputs["report"]).exists()
    assert "widens the boundary" in runner.summary.read_text()


def test_a_change_that_closes_the_boundary_reports_and_does_not_fail(
        tmp_path, repo):
    runner, step = plan_through_the_action(tmp_path, repo, UNSCOPED, SCOPED)
    assert step.returncode == 0, step.stderr
    assert runner.outputs["fails-open"] == "false"
    assert "tenant_added" in step.stdout


def test_a_policy_that_will_not_load_fails_the_step(tmp_path, repo):
    # Exit 2 has to stop the job, and it has to stop it *here* -- before
    # a comment claiming anything is posted. A plan that could not be
    # computed reported as a plan that found nothing is the one failure
    # that leaves a repository worse off than having no check.
    broken = "from voyd import guard, deadline\nthis is not python\n"
    _, step = plan_through_the_action(tmp_path, repo, SCOPED, broken)
    assert step.returncode == 2
    assert "could not compute a plan" in step.stdout


def test_the_first_voydfile_is_planned_against_no_policy(tmp_path, repo):
    """A policy added by the pull request has nothing at the base.

    The step has to reach `--current none` on its own, and it is the path
    where `set -e` bites twice: `git cat-file -e` failing is the normal
    case, not an error.
    """
    work, _ = repo(SCOPED, UNSCOPED)
    # Rewind to a commit with no policy file in it at all, and branch the
    # arrival of the first one off that.
    (work / "voydfile.py").unlink()
    git(work, "add", "-A")
    git(work, "commit", "-qm", "before there was a policy")
    empty = git(work, "rev-parse", "HEAD")
    (work / "voydfile.py").write_text(SCOPED)
    git(work, "add", "-A")
    git(work, "commit", "-qm", "add the first policy")

    runner = Runner(tmp_path, empty, {})
    first = runner.run("Read the policy in force", work)
    assert first.returncode == 0, first.stderr
    assert runner.outputs["path"] == "none"
    step = runner.run("Plan", work)
    assert step.returncode == 0, step.stderr
    assert runner.outputs["fails-open"] == "false"
    assert "guard_added" in step.stdout


def test_every_step_the_action_ships_is_one_this_file_can_run(tmp_path, repo):
    """A step added later and never executed here is untested by this file.

    Named rather than left implicit, because the failure it guards is
    silent: the suite keeps passing, and the new step is the one that
    breaks on somebody's runner.
    """
    spec = yaml.safe_load(ACTION.read_text())
    shell_steps = {s["name"] for s in spec["runs"]["steps"]
                   if s.get("name") and "run" in s}
    # `Install voyd` installs into the runner's interpreter and `Say it on
    # the pull request` talks to the GitHub API; neither can run here, and
    # both are listed so that a *third* exemption has to be argued for.
    unrunnable = {"Install voyd", "Say it on the pull request",
                  "Fail if the boundary opened"}
    exercised = {"Read the policy in force", "Plan"}
    assert shell_steps == exercised | unrunnable, (
        f"action.yml has steps this file neither runs nor excuses: "
        f"{shell_steps - exercised - unrunnable}")
