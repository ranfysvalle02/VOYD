"""No verb anywhere here hands a caller a cleanup obligation.

`docs/STATE.md`, under *Deliberately not doing*:

    **A delete tool or endpoint.** A delete hands the caller a cleanup
    obligation, and an agent that has to remember to clean up is the failure
    this exists to remove.

That sentence has outlived two surfaces. It was first enforced against the
MCP tool list, then against the HTTP endpoints after a purge found
`DELETE /v1/voyds/{slug}` sitting there untested and cascading through a
hardcoded list of collections written before three more existed. Both
surfaces are gone now, cut in the pivot to the wire.

So it is asserted against what remains, which is the only thing a stranger
can reach: the engine's public surface, and the wire boundary. The principle
is not about a protocol -- it is about never handing anybody a mess to tidy.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import voyd.engine as engine_module
from voyd.engine.admission import Admission

ROOT = Path(__file__).resolve().parents[1]

NAMED_FOR_RECLAIMING = {"delete", "remove", "destroy", "purge", "drop",
                        "cleanup", "expire", "gc", "collect", "reclaim"}


def _looks_reclaiming(name: str) -> bool:
    parts = set(name.lower().replace("-", "_").split("_"))
    return bool(parts & NAMED_FOR_RECLAIMING)


def test_no_exported_name_is_named_for_reclaiming():
    """`__all__` is the promise. A verb in it named for taking things away
    would be the obligation this package exists to remove, offered."""
    offenders = sorted(n for n in engine_module.__all__ if _looks_reclaiming(n))
    assert not offenders, (
        f"{offenders} reached the public surface. Forgetting is a *reachability*"
        " change; reclaiming the bytes belongs to the deadline, which nobody"
        " has to remember.")


def test_no_public_method_on_the_handle_is_named_for_reclaiming():
    """The handle is what a caller holds, so it is where the temptation is."""
    offenders = sorted(
        name for name, _ in inspect.getmembers(Admission, callable)
        if not name.startswith("_") and _looks_reclaiming(name))
    assert not offenders, f"{offenders} on the admission handle"


def test_the_wire_boundary_has_no_write_path_at_all():
    """The strongest form of the principle, and it came free with the pivot.

    `tools/voyd_wire.py` rewrites replies and never requests anything. It
    cannot delete because it has no way to ask a database for anything --
    which is also why it needs no credentials of its own.
    """
    source = (ROOT / "tools" / "voyd_wire.py").read_text()
    for verb in ("delete_one", "delete_many", "drop", "insert_one",
                 "update_one", "find_one_and_delete"):
        assert verb not in source, (
            f"{verb} appeared in the wire boundary, which is supposed to be a "
            f"read path that rewrites replies and asks for nothing")
