"""The documented on-ramp has to run, and stay small.

Two failures this catches, both of which shipped in prose before:

1. **The quickstart does not work.** The module docstring once declared a
   tenant and then read ``find({})`` -- which raises ``ScopeRequired``, so the
   very first line a new user copied threw. A doc snippet nobody executes
   rots exactly where a newcomer meets it. So this runs the find-only path
   against a real MongoDB and asserts the contrast the README promises: the
   raw collection still returns the revoked row, the handle does not.

2. **The on-ramp quietly becomes a migration.** ``examples/quickstart.py``
   fences the lines a team actually adds between ``integration:`` markers.
   This counts the substantive ones and fails if they pass ten -- the
   difference between "one handle" and "please refactor your read path".
"""

from __future__ import annotations

from pathlib import Path

QUICKSTART = Path(__file__).resolve().parents[1] / "examples" / "quickstart.py"


async def test_the_find_only_path_refuses_what_the_raw_collection_serves(core):
    """The exact claim the README hero makes, executed."""
    engine, db = core

    leaked = (await db.notes.insert_one(
        {"text": "aws key AKIA...leaked"})).inserted_id
    await db.notes.insert_one({"text": "the fault code is P0301"})

    docs = engine.model("notes").forgettable()
    await engine.ensure(search_wait_s=0)

    assert len(await docs.find({})) == 2, "both facts start reachable"

    await docs.revoke({"_id": leaked}, reason="credential leaked")

    reachable = await docs.find({})
    raw = [d async for d in db.notes.find({})]

    assert len(reachable) == 1, "the revoked fact was still reachable via the handle"
    assert leaked not in {d["_id"] for d in reachable}, "the leaked id came back"
    assert len(raw) == 2, "revoke deleted a row -- it must only refuse, not delete"
    assert any(d["_id"] == leaked for d in raw), "the row must stay on disk as proof"


async def test_the_unsafe_read_is_named_and_still_sees_it(core):
    """``including_refused()`` is the only way back to the row, by design."""
    engine, db = core
    leaked = (await db.notes.insert_one({"text": "secret"})).inserted_id
    docs = engine.model("notes").forgettable()
    await engine.ensure(search_wait_s=0)
    await docs.revoke({"_id": leaked}, reason="leaked")

    assert await docs.find_one({"_id": leaked}) is None
    seen = await docs.including_refused().find_one({"_id": leaked})
    assert seen is not None and seen["forgotten"]["reason"] == "leaked"


def _integration_body() -> list[str]:
    """The substantive lines a team adds, as fenced in the example."""
    text = QUICKSTART.read_text().splitlines()
    begin = next(i for i, ln in enumerate(text) if "integration: begin" in ln)
    end = next(i for i, ln in enumerate(text) if "integration: end" in ln)
    return [ln.strip() for ln in text[begin + 1:end]
            if ln.strip() and not ln.strip().startswith("#")]


def test_the_quickstart_example_exists_and_is_fenced():
    assert QUICKSTART.exists(), "the README points at examples/quickstart.py"
    body = _integration_body()
    assert body, "the integration fence is empty; the markers moved or vanished"


def test_the_on_ramp_stays_under_ten_lines():
    """The whole pitch is that adoption is a handful of lines, not a refactor.

    Counted on the fence in ``examples/quickstart.py`` so the number in the
    prose and the number in the runnable file cannot drift apart.
    """
    body = _integration_body()
    assert len(body) < 10, (
        f"the integration body is {len(body)} substantive lines; the on-ramp "
        f"is supposed to be under ten. If it genuinely needs more, the pitch "
        f"changed and the docs should say so:\n  " + "\n  ".join(body))
