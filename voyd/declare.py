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
from .engine.admission.rules import Unrecoverable
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


def auto_embed(model: str) -> _Field:
    """This field is text the *server* embeds, with the model named here.

    The other half of `embedded_with`. That one refuses a **document** whose
    vector came from the wrong model; this one removes the way a vector
    comes to be wrong in the first place, by taking the embedder out of the
    application entirely. The index holds the text, mongot embeds it on
    write, and mongot embeds the query with the same model at read time.
    Nothing in your process ever computes a vector, so nothing in your
    process can drift from the index.

    **Declaring it here also refuses the query that would defeat it.** A
    client sending its own ``queryVector`` against a collection the
    deployment declared server-embedded is the exact drift this prevents,
    arriving through a driver that never heard of the declaration -- and
    comparing a vector to an index built by a different model does not
    fail, it returns a number between -1 and 1, which is the whole problem.
    The boundary refuses it by name. See ``tools/voyd_wire.py``.

    Declared, not probed. A deployment that cannot do server-side
    embedding says so at index creation and ``--ensure`` falls back to an
    ordinary vector index, loudly -- so adopting this is safe before every
    deployment supports it. What is *not* safe is adopting it and then
    quietly sending client vectors anyway, which is what the boundary's
    refusal is for.
    """
    return _Field("auto_embed", args=(model,))


def sealed() -> _Field:
    """This field is ciphertext at rest, under a key scoped to the tenant.

    The one thing refusal structurally cannot do. Refusal binds *this*
    application's read path, so it has nothing to say about a replica, a
    snapshot, or the backup somebody restores next year -- none of those run
    this read path. Destroying the key binds all of them at once, and this
    is how a field opts into being destroyable that way.

    **The key is the tenant's, which is why this requires ``tenant()``.**
    A scope with no name is a scope with one key, and one key per collection
    makes erasure all-or-nothing: the subject who asked to be forgotten takes
    every other tenant with them. So ``sealed()`` without ``tenant()`` is
    refused at *load*, in the same breath as every other way a policy file
    can be wrong.

    Enforced with ``--key-vault``, which encrypts on the boundary: no
    writer in any *language* can forget -- not the shell, not the migration
    script, not the service written next year by somebody who has not read
    this file. A driver's own ``schema_map`` gets you the same ciphertext
    one process at a time; this gets it once.

    It is also what costs the boundary its purity: holding keys makes it a
    custody holder, and a sealed read decrypts before it refuses. See
    ``LIMITS.md`` §5.

    An ``Unrecoverable`` rule is attached alongside, so a sealed field that
    reaches a read path which never decrypted it is refused by name rather
    than serialised into a prompt as a ``Binary`` blob pretending to be text.
    """
    return _Field("sealed", lambda f: Unrecoverable(field=f))


# Every collection declared in a loaded policy file, by name, with the
# policy choices that are not rules: what a `delete` on the wire should
# mean, and which fields are ciphertext at rest under whose key.
REGISTRY: dict[str, AdmissionSpec] = {}
OPTIONS: dict[str, dict] = {}

ON_DELETE = ("forward", "revoke")


def guard(collection: str, *, lineage_field: str | None = None,
          on_delete: str = "forward"):
    """Declare the rules for one collection. Returns the class unchanged.

    ``on_delete="revoke"`` gives a client's ``delete`` the better meaning:
    the row is marked, unreachable on the next read, still on disk, its
    deadline pulled in so the reaper collects it. Opt-in, because silently
    redefining `delete` for an operator who did not ask for it is exactly the
    surprise this project exists to remove -- and because somebody, somewhere,
    means it.

    Raises at *load* time for a body it cannot compile -- an unknown value, a
    second deadline, no rule at all. A policy file is the one place an error
    must not wait for a query to surface it.
    """
    if on_delete not in ON_DELETE:
        raise ValueError(
            f"{collection}: on_delete={on_delete!r}; expected one of "
            f"{ON_DELETE}. 'forward' lets a delete really delete")
    def decorate(cls):
        rules, tenant_field, seen = [], None, set()
        sealed_fields: list[str] = []
        embedded: dict[str, str] = {}
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
            if value.kind == "sealed":
                sealed_fields.append(name)
            if value.kind == "auto_embed":
                embedded[name] = value.args[0]
                continue        # a declaration about the index, not a rule
            seen.add(value.kind)
            assert value.build is not None
            rules.append(value.build(name))

        # A field cannot be both hidden from the server and embedded by
        # it, and there is deliberately no check for that here, because in
        # this shape the contradiction cannot be *written*. The path is the
        # attribute name, so `text = sealed()` followed by
        # `text = auto_embed(...)` is not two conflicting declarations --
        # Python binds the name once and the second wins.
        #
        # A guard here would be code that can never run. It is instead one
        # more answer to "why a class body rather than a dict", up in the
        # module docstring: a shape in which a whole class of contradiction
        # has nowhere to live beats a shape that detects it.
        #
        # What is *not* closed: sealing `text` here while an Atlas index
        # declared somewhere else auto-embeds `text`. No policy file can
        # see that, and the wire boundary does not create indexes. See
        # LIMITS.md section 5.

        # Two declarations naming the same thing have to agree about it.
        for field, rule in ((r.field, r) for r in rules
                            if type(r).__name__ == "EmbeddedWith"):
            for path, model in embedded.items():
                if rule.model != model:
                    raise ValueError(
                        f"{collection}: embedded_with({rule.model!r}) on "
                        f"{field!r} and auto_embed({model!r}) on {path!r}. "
                        f"One says refuse any vector not from "
                        f"{rule.model!r}; the other says the server will "
                        f"produce them with {model!r}. Every document the "
                        f"index embeds would be refused by the rule beside "
                        f"it, and the collection would read as empty")

        if sealed_fields and tenant_field is None:
            raise ValueError(
                f"{collection}: sealed() on {', '.join(sealed_fields)} with "
                f"no tenant() field. The key is scoped to the tenant, so a "
                f"scope with no name is one key for the whole collection -- "
                f"and destroying it to forget one subject would make every "
                f"other tenant's rows unreadable at the same instant. "
                f"Declare tenant(), or encrypt with a literal keyId outside "
                f"this boundary and accept that erasure is all-or-nothing")

        if not rules and tenant_field is None:
            raise ValueError(
                f"{collection}: declared with no rules. A guard that refuses "
                f"nothing is a slower read, and naming it a guard is worse "
                f"than not having one")

        if on_delete == "revoke" and not any(
                getattr(r, "reversible", None) is False for r in rules):
            raise ValueError(
                f"{collection}: on_delete='revoke' needs a revocable() field "
                f"to write the mark into. Without one there is nowhere to "
                f"record that the fact was forgotten, and the delete would "
                f"silently do nothing at all")

        REGISTRY[collection] = AdmissionSpec(
            collection, rules=tuple(rules), tenant=tenant_field,
            lineage_field=lineage_field)
        OPTIONS[collection] = {"on_delete": on_delete,
                               "sealed": tuple(sealed_fields),
                               "scope_field": tenant_field,
                               "auto_embed": dict(embedded)}
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
    OPTIONS.clear()
    runpy.run_path(path, run_name="voydfile")
    if not REGISTRY:
        raise ValueError(
            f"{path} declared no collections. A policy file with no @guard in "
            f"it would start a proxy that refuses nothing, silently")
    return dict(REGISTRY)
