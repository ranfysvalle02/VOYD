"""Whose claims a caller-reading rule asks: the principal's, the actor's, or both.

Pure: a function of a claims mapping and a claim name. No database, no
connection, no clock.

A plain connection has one identity -- the one the server reports -- and
its claims are a flat mapping, ``{"user": ..., "roles": [...]}``. A
delegated read has two: the **principal** the agent acts for and the
**actor** doing the reading. Its claims carry both, under ``principal``
and ``actor``, with the principal's also spelled flat so a reader of
``user`` still finds somebody.

A rule names a claim three ways, and this module is the one place that
says what each means:

    "roles"             both sides when the read is delegated -- every side
                        present must satisfy the rule -- and the only side
                        when it is not
    "principal.roles"   the principal alone; on a plain connection that is
                        the server-reported caller, so nothing changes
    "actor.roles"       the actor alone; a plain connection has none, so
                        the value is absent and the rule admits nothing
                        that requires it

Both-by-default is the intersection, and it is the only default that
cannot leak: an actor's roles can only narrow the principal's view, and
a narrowly-scoped actor cannot read everything its principal can.
"""

from __future__ import annotations

from typing import Any, Mapping

PRINCIPAL = "principal"
ACTOR = "actor"
SIDES = (PRINCIPAL, ACTOR)

# Claims that belong to the delegation as a whole rather than to either
# side of it. Asked of the top level, never intersected.
WHOLE = frozenset({"scopes", "issuer", "token", "delegated"})


def split(claim: str) -> tuple[str | None, str]:
    """``("principal", "roles")`` for ``"principal.roles"``; ``(None, c)``
    for an unqualified claim."""
    head, dot, rest = claim.partition(".")
    if dot and head in SIDES and rest:
        return head, rest
    return None, claim


def asked(claim: str) -> frozenset[str]:
    """Which sides a rule naming ``claim`` consults on a delegated read.

    What ``voyd-plan`` compares: a rule that moves from both sides to one
    has stopped asking somebody, and that widens.
    """
    side, name = split(claim)
    if side is not None:
        return frozenset({side})
    if name in WHOLE:
        return frozenset()
    return frozenset(SIDES)


def is_delegated(caller: Mapping | None) -> bool:
    return caller is not None and caller.get("delegated") is True


def sides(caller: Mapping | None, claim: str) -> tuple[Any, ...]:
    """The value of ``claim`` on every side the rule must satisfy.

    One element for a plain connection or a qualified claim; two for an
    unqualified claim on a delegated read that has an actor. A rule
    admits only if it would admit on *every* element, which is what makes
    the default an intersection.
    """
    if not caller:
        return (None,)
    side, name = split(claim)
    if name in WHOLE and side is None:
        return (caller.get(name),)
    delegated = is_delegated(caller)
    principal = caller.get(PRINCIPAL) if delegated else caller
    actor = caller.get(ACTOR) if delegated else None
    principal = principal if isinstance(principal, Mapping) else {}
    if side == PRINCIPAL:
        return (principal.get(name),)
    if side == ACTOR:
        return ((actor.get(name) if isinstance(actor, Mapping) else None),)
    if isinstance(actor, Mapping):
        return (principal.get(name), actor.get(name))
    return (principal.get(name),)


def tenant_of(caller: Mapping | None, claim: str = "tenant") -> tuple[Any, str | None]:
    """``(tenant, None)`` for a delegated read, or ``(None, why)`` if it has none.

    Unqualified, the principal's tenant is the scope and an actor that
    carries a tenant must carry the same one -- an agent provisioned for
    one customer does not read another's rows because its user asked.
    Qualified, the named side's tenant is the scope. A missing tenant is
    not "any tenant": it is a reason to refuse.
    """
    side, name = split(claim)
    got = sides(caller, claim)
    if side is not None:
        value = got[0]
        if value is None:
            return None, f"the {side} carries no {name!r} claim"
        return value, None
    value = got[0]
    if value is None:
        return None, f"the principal carries no {name!r} claim"
    if len(got) > 1 and got[1] is not None and got[1] != value:
        return None, (f"the actor's {name!r} is not the principal's, and an "
                      f"agent does not cross tenants because its user asked")
    return value, None
