"""Declare the rules once, in a file that is not your application.

The whole of a policy, and the whole of what anybody has to write::

    # voydfile.py
    from voyd import guard, deadline, revocable, tenant, budget, distinct

    @guard("notes")
    class Notes:
        expire_at  = deadline()
        forgotten  = revocable()
        tenant_id  = tenant()

    @guard("prompts")
    class Prompts:
        expire_at = deadline()
        tokens    = budget(8000)
        chunk     = distinct()

Then::

    python tools/voyd_wire.py --config voydfile.py --target localhost:27017

Your application is not edited. No import is added to it, no handle replaces
a collection, no read path is rewritten and nobody has to remember anything.
The connection string changes and a forgotten fact stops being reachable --
from Python, from Node, from Compass, from a notebook.

**Why a class body rather than a dict.** The field name is on the left and
the rule is on the right, which is the shape of the thing being described: a
schema with a rule per field. A dict would read the same way and lose the two
properties that matter -- the name is a real identifier so a typo is visible
where you wrote it, and the decorator can raise at *load* time rather than at
the first read. A policy file that is wrong should fail when it is loaded,
not when somebody's query returns the wrong rows.

**Why this is a declaration and not a framework.** Everything here compiles
to the ``Rule`` objects in ``voyd.engine`` -- the same ones a stranger writes
by hand in ``examples/portfolio.py``. Nothing is hidden behind the decorator:
``guard`` returns the class it was given and puts an ``AdmissionSpec`` in a
registry. If the declarative form cannot express what you need, drop to the
protocol and pass rules directly; there is no cliff between the two because
there is no second mechanism.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .engine import (Budget, Deadline, Distinct, EmbeddedWith, Marked,
                     Restricted, revoked)
from .engine.admission import AdmissionSpec


@dataclass(frozen=True)
class _Field:
    """One line of a policy: what this field means, not what it contains."""
    kind: str
    build: Callable[[str], Any] | None = None
    args: tuple = ()
    kwargs: dict | None = None


def deadline() -> _Field:
    """This field holds the instant after which the fact is gone.

    Enforced on the way out as well as by the TTL index, which is the whole
    point: the monitor runs about once a minute and serving a row during that
    window is the bug class this exists to remove.
    """
    return _Field("deadline", lambda f: Deadline(at_field=f))


def revocable(reason: str = "revoked") -> _Field:
    """This field holds a mark an operator sets to forget the fact *now*.

    Irreversible, because a revocation is an instruction about the world. Use
    ``holdable()`` for the reversible kind.
    """
    return _Field("mark", lambda f: revoked(f) if reason == "revoked"
                  else Marked(field=f, reason=reason, reversible=False))


def holdable(reason: str = "quarantined") -> _Field:
    """A reversible mark: a hypothesis, not an instruction.

    Quarantine without a review loop is a graveyard, so this one can be
    lifted and the row is deliberately not given a deadline -- it is the
    evidence.
    """
    return _Field("mark", lambda f: Marked(field=f, reason=reason,
                                           reversible=True))


def tenant() -> _Field:
    """This field is the tenant id, enforced on *both* halves.

    Required in every query, and checked per document on the way out, which
    are two different mistakes and both of them leak. See
    ``tests/test_the_tenant_is_enforced_on_both_halves.py``.
    """
    return _Field("tenant")


def restricted_to(claim: str) -> _Field:
    """This field names the audience; admit only callers whose ``claim``
    overlaps it."""
    return _Field("rule", lambda f: Restricted(field=f, claim=claim))


def embedded_with(model: str) -> _Field:
    """This field records which embedding model produced the vector.

    A vector from last quarter's model is not a worse hit, it is a hit in a
    different space.
    """
    return _Field("rule", lambda f: EmbeddedWith(model=model, field=f))


def budget(limit: int) -> _Field:
    """This field is the per-document cost; refuse once ``limit`` is spent.

    Set-relative: the same document is admitted alone and refused in company,
    which no index filter and no policy engine can express.
    """
    return _Field("rule", lambda f: Budget(limit=limit, cost_field=f))


def distinct() -> _Field:
    """This field is the content identity; refuse a repeat already on the page."""
    return _Field("rule", lambda f: Distinct(on=f))


# Every collection declared in a loaded policy file, by name.
REGISTRY: dict[str, AdmissionSpec] = {}


def guard(collection: str, *, lineage_field: str | None = None):
    """Declare the rules for one collection. Returns the class unchanged.

    Raises at *load* time for a body it cannot compile -- an unknown value, a
    second deadline, no rule at all. A policy file is the one place an error
    must not wait for a query to surface it.
    """
    def decorate(cls):
        rules, tenant_field, seen = [], None, set()
        for name, value in vars(cls).items():
            if name.startswith("__") or not isinstance(value, _Field):
                continue
            if value.kind == "tenant":
                if tenant_field is not None:
                    raise ValueError(
                        f"{collection}: two tenant fields ({tenant_field!r} "
                        f"and {name!r}); a scope with two keys is not a scope")
                tenant_field = name
                continue
            if value.kind == "deadline" and "deadline" in seen:
                raise ValueError(
                    f"{collection}: two deadline fields. Two clocks is the "
                    f"drift this exists to remove")
            seen.add(value.kind)
            assert value.build is not None
            rules.append(value.build(name))

        if not rules and tenant_field is None:
            raise ValueError(
                f"{collection}: declared with no rules. A guard that refuses "
                f"nothing is a slower read, and naming it a guard is worse "
                f"than not having one")

        REGISTRY[collection] = AdmissionSpec(
            collection, rules=tuple(rules), tenant=tenant_field,
            lineage_field=lineage_field)
        return cls
    return decorate


def load(path: str) -> dict[str, AdmissionSpec]:
    """Execute a policy file and return what it declared.

    Plain ``exec`` of a Python file, which is the same trust a ``conftest.py``
    or a ``settings.py`` already asks for: this is your file, on your disk,
    next to your deployment. It is not a sandbox and does not pretend to be.
    """
    import runpy
    REGISTRY.clear()
    runpy.run_path(path, run_name="voydfile")
    if not REGISTRY:
        raise ValueError(
            f"{path} declared no collections. A policy file with no @guard in "
            f"it would start a proxy that refuses nothing, silently")
    return dict(REGISTRY)
