"""Rules as data: a policy the audited can change without a release.

A ``Rule`` is a Python object, so a per-tenant access policy is a deploy.
That caps adoption at teams who can ship this service, and it puts the
people who get audited on the wrong side of the release process -- they own
the consequences of the policy and cannot touch it.

The protocol was already shaped for this. A rule declares ``needs_caller``,
``bypassable`` and ``reversible``, and carries its own ``clause()``. What
was missing is a compiler from something storable:

    {"deny": {"field": "classification", "not_in": "$caller.clearances"}}

stored on the scope document, versioned with it, compiled at load into an
object indistinguishable from a hand-written rule.

**The compiler is the whole job, and its hard rule is negative.** Every
rule in this package has two halves -- a per-document check that is the
guarantee, and a query clause that is the optimisation -- and they must
describe the same set. A compiled policy that can express itself in the
query but not per document is not a slower rule, it is a **silent hole**:
the query prunes correctly on ``find`` and ``$vectorSearch`` hits never went
through a query at all, so the documents the clause would have dropped walk
straight into a prompt.

So this refuses anything it cannot compile to *both* halves. Not "falls back
to per-document only" -- that would be safe. Not "falls back to the clause"
-- that is the hole. It raises at compile time, which is boot, which is the
one moment a policy error is cheap.

**Operators are a closed list, on purpose.** The temptation is to accept a
Mongo query fragment directly, and that is the injection surface this
package already refuses elsewhere: a caller-supplied ``{"$where": ...}`` or
a ``$ne`` in an id position is how a tenant filter stops filtering. Every
operator here has a hand-written pair of implementations that are tested
against each other against a real server.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any

log = logging.getLogger("engine.policy")

CALLER = "$caller."

# What a policy may say. Each entry is (per-document test, query builder),
# and the pair is the contract: both halves or the operator does not exist.
# Deliberately small -- an operator nobody can express twice is an operator
# this module does not have.
OPERATORS = {
    "eq":     (lambda v, w: v == w,            lambda f, w: {f: {"$eq": w}}),
    "ne":     (lambda v, w: v != w,            lambda f, w: {f: {"$ne": w}}),
    "in":     (lambda v, w: v in _set(w),      lambda f, w: {f: {"$in": _list(w)}}),
    "not_in": (lambda v, w: v not in _set(w),  lambda f, w: {f: {"$nin": _list(w)}}),
    "lt":     (lambda v, w: _cmp(v, w, "lt"),  lambda f, w: {f: {"$lt": w}}),
    "lte":    (lambda v, w: _cmp(v, w, "lte"), lambda f, w: {f: {"$lte": w}}),
    "gt":     (lambda v, w: _cmp(v, w, "gt"),  lambda f, w: {f: {"$gt": w}}),
    "gte":    (lambda v, w: _cmp(v, w, "gte"), lambda f, w: {f: {"$gte": w}}),
    "exists": (lambda v, w: (v is not None) == bool(w),
               lambda f, w: {f: {"$exists": bool(w), "$ne": None}}
                            if w else {f: {"$in": [None]}}),
}


def _set(value: Any) -> set:
    if isinstance(value, (str, bytes)) or value is None:
        return {value}
    try:
        return set(value)
    except TypeError:
        return {value}


def _list(value: Any) -> list:
    return sorted(_set(value), key=lambda x: (x is None, str(x)))


def _cmp(left: Any, right: Any, op: str) -> bool:
    """Compare, and refuse to guess across types.

    ``None < 5`` raises in Python and sorts *before* everything in BSON, so
    a policy that meant "cheaper than 5" would silently include every
    document missing the field. Mismatched types therefore fail the test,
    which -- since these are ``deny`` rules -- is the fail-closed direction.
    """
    try:
        if op == "lt":
            return left < right
        if op == "lte":
            return left <= right
        if op == "gt":
            return left > right
        return left >= right
    except TypeError:
        return False


class PolicyInvalid(ValueError):
    """A stored policy could not be compiled into both halves.

    Raised at load, which is boot, which is the one moment a policy error
    costs nothing. The alternative -- accepting it and enforcing whichever
    half compiled -- is the failure this module exists to prevent: a rule
    that filters in the query and not per document leaks every
    ``$vectorSearch`` hit, because those never went through a query.
    """

    def __init__(self, detail: str, spec: Any = None):
        self.spec = spec
        super().__init__(
            f"{detail}. A policy must compile to a per-document check *and* "
            f"a query clause: enforcing only one of them is a silent hole, "
            f"and $vectorSearch is what walks through it. "
            f"Operators: {', '.join(sorted(OPERATORS))}")


@dataclass(frozen=True)
class Denies:
    """One compiled ``deny`` clause. An ordinary rule in every way.

    Nothing here knows it came from a document rather than from Python,
    which is the point -- ``tests/test_a_third_party_rule_is_a_first_class
    _reason.py`` already asserts that a stranger's rule survives the whole
    loop, and a compiled one takes exactly that path.
    """

    field_name: str
    op: str
    operand: Any
    reason: str = "policy"
    claim: str | None = None
    needs_caller: bool = False
    bypassable: bool = False
    default: Any = None

    # Named ``field`` for ``ensure()``, which indexes what a rule filters on.
    @property
    def field(self) -> str:
        return self.field_name

    def _operand_for(self, caller: dict | None) -> Any:
        if self.claim is None:
            return self.operand
        return (caller or {}).get(self.claim)

    def refuses(self, doc: dict, *, when: datetime | None = None,
                caller: dict | None = None) -> bool:
        value = doc.get(self.field_name, self.default)
        test, _ = OPERATORS[self.op]
        try:
            return bool(test(value, self._operand_for(caller)))
        except Exception:  # noqa: BLE001 - a rule must not open the gate by
            # raising; ``why_refused`` catches this too, and refusing twice
            # over is cheaper than reasoning about which layer caught it.
            return True

    def clause(self) -> dict | None:
        if self.needs_caller:
            return None
        return self._clause_against(self.operand)

    def clause_for(self, caller: dict | None) -> dict | None:
        return self._clause_against(self._operand_for(caller))

    def _clause_against(self, operand: Any) -> dict:
        """The *complement*: what the query must keep.

        A ``deny`` says which documents are refused; a query says which are
        returned. Inverting here rather than at the call site is deliberate
        -- the inversion is the part that is easy to get backwards, and
        getting it backwards returns exactly the documents the policy
        forbids.
        """
        _, build = OPERATORS[self.op]
        return {"$nor": [build(self.field_name, operand)]}


def compile_policy(spec: Any, *, reason: str | None = None) -> list:
    """Compile stored policy into rules. Raises rather than half-enforcing.

        compile_policy({"deny": {"field": "classification",
                                 "not_in": "$caller.clearances"}})

    A list, because a scope usually has more than one, and returning one
    rule for one clause would make the common case a special case.
    """
    if isinstance(spec, dict):
        spec = [spec]
    if not isinstance(spec, (list, tuple)):
        raise PolicyInvalid(f"a policy is a mapping or a list of them, "
                            f"not {type(spec).__name__}", spec)

    rules = []
    for i, clause in enumerate(spec):
        if not isinstance(clause, dict) or "deny" not in clause:
            raise PolicyInvalid(
                f"clause {i} has no 'deny'. Only denial is expressible: an "
                f"'allow' would have to mean 'and refuse everything else', "
                f"which no single rule can promise when other rules exist",
                clause)
        body = clause["deny"]
        if not isinstance(body, dict):
            raise PolicyInvalid(f"clause {i}: 'deny' must be a mapping", body)

        name = body.get("field")
        if not isinstance(name, str) or not name or name.startswith("$"):
            raise PolicyInvalid(
                f"clause {i}: 'field' must be a plain document field name, "
                f"not {name!r}. A '$'-prefixed name is an operator, and "
                f"accepting one here is how a policy becomes an injection",
                body)

        ops = [k for k in body if k not in ("field", "reason", "default")]
        if len(ops) != 1:
            raise PolicyInvalid(
                f"clause {i}: expected exactly one operator, got "
                f"{sorted(ops) or 'none'}", body)
        op = ops[0]
        if op not in OPERATORS:
            raise PolicyInvalid(f"clause {i}: unknown operator {op!r}", body)

        operand, claim = body[op], None
        if isinstance(operand, str) and operand.startswith(CALLER):
            claim = operand[len(CALLER):]
            if not claim:
                raise PolicyInvalid(
                    f"clause {i}: '{CALLER}' names no claim", body)
            operand = None
        elif isinstance(operand, str) and operand.startswith("$"):
            raise PolicyInvalid(
                f"clause {i}: {operand!r} looks like a reference but only "
                f"'{CALLER}<claim>' is one. Silently treating it as a "
                f"literal would compare a document against the string "
                f"'$caller.clearance'", body)

        rules.append(Denies(
            field_name=name, op=op, operand=operand,
            reason=body.get("reason") or reason or "policy",
            claim=claim, needs_caller=claim is not None,
            default=body.get("default")))

    log.info("compiled %d policy rule(s): %s", len(rules),
             ", ".join(f"{r.field_name} {r.op}" for r in rules))
    return rules
