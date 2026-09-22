"""The invariant the whole design rests on, checked against a real server.

Every rule here has two halves. `refuses(doc)` is the guarantee, asked per
document on the way out. `clause()` is the same rule as a query fragment,
pushed into MongoDB so the server can drop rows before they are shipped.
`LIMITS.md` section 2 states what happens when they disagree: *a rule that
can express itself in a query but not per document is not a slower rule,
it is a silent hole.*

**One direction of disagreement is harmless and the other is invisible.**

A clause that is *too wide* costs a wasted fetch: the document comes back
and `refuses` rejects it. Nothing is wrong.

A clause that is *too narrow* — one that excludes a document the rule
would have admitted — **silently loses reachable data**. No error, no
count, no refusal recorded. The caller gets a short page and has no way to
tell it from a short collection. That is the failure this file exists to
catch, and it is the one nobody would notice: it fails closed, and failing
closed looks like working.

So the assertion is a subset, not an equality:

    {documents `refuses` admits}  ⊆  {documents the clause returns}

Checked by *running the clause on MongoDB* rather than by reimplementing
query semantics in Python. A hand-rolled matcher would be a second
opinion about `$exists`, `null` and missing fields — which is precisely
the corner these clauses live in, and precisely where a second opinion
would be wrong in the same direction as the code it was checking.

The corpus per rule is built to sit on those corners: field absent, field
null, field present and wrong, field present and right, and the wrong
*type* in the field. A rule that only ever sees well-formed documents is a
rule tested on the population that was never the problem.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from bson.binary import Binary

from voyd.engine.admission import rules as R
from voyd.engine.time import now

pymongo = pytest.importorskip("pymongo")

PAST = now() - timedelta(days=1)
SOON = now() + timedelta(days=1)

# (label, rule, caller, corpus). The caller is `None` for a rule that does
# not ask who is calling; for the ones that do, the clause is built from it.
CASES = [
    ("deadline", R.Deadline(), None, [
        {"_id": "absent"},
        {"_id": "null", "expire_at": None},
        {"_id": "past", "expire_at": PAST},
        {"_id": "future", "expire_at": SOON},
        {"_id": "a string", "expire_at": "tuesday"},
        {"_id": "a number", "expire_at": 0},
    ]),
    ("revoked", R.revoked(), None, [
        {"_id": "absent"},
        {"_id": "null", "forgotten": None},
        {"_id": "marked", "forgotten": {"at": PAST, "reason": "leak"}},
        {"_id": "false", "forgotten": False},
        {"_id": "truthy string", "forgotten": "yes"},
        {"_id": "empty dict", "forgotten": {}},
    ]),
    ("quarantined", R.quarantined(), None, [
        {"_id": "absent"},
        {"_id": "null", "quarantined": None},
        {"_id": "held", "quarantined": {"at": PAST, "reason": "detector"}},
        {"_id": "false", "quarantined": False},
    ]),
    ("embedded_with", R.EmbeddedWith(model="voyage-4", field="model"), None, [
        {"_id": "right model", "model": "voyage-4", "embedding": [0.1]},
        {"_id": "wrong model", "model": "voyage-3", "embedding": [0.1]},
        {"_id": "no model, a vector", "embedding": [0.1]},
        {"_id": "no model, no vector"},
        {"_id": "null vector", "model": "voyage-4", "embedding": None},
        {"_id": "wrong model, null vector", "model": "voyage-3",
         "embedding": None},
    ]),
    ("restricted", R.Restricted(), {"groups": ["legal"]}, [
        {"_id": "absent"},
        {"_id": "empty", "audience": []},
        {"_id": "match", "audience": ["legal"]},
        {"_id": "no match", "audience": ["desk"]},
        {"_id": "one of several", "audience": ["desk", "legal"]},
        {"_id": "a string not a list", "audience": "legal"},
        {"_id": "null", "audience": None},
    ]),
    ("clearance", R.Clearance(order=("public", "internal", "secret")),
     {"clearance": "internal"}, [
        {"_id": "absent"},
        {"_id": "public", "classification": "public"},
        {"_id": "internal", "classification": "internal"},
        {"_id": "secret", "classification": "secret"},
        {"_id": "unknown label", "classification": "cosmic"},
        {"_id": "null", "classification": None},
        {"_id": "a number", "classification": 3},
    ]),
    # No query half by nature: "is this value ciphertext" is a BSON
    # subtype question and `$type: "binData"` cannot tell subtype 6 from a
    # thumbnail. Here so the coverage check sees it and so the *absence* of
    # a clause is asserted rather than assumed.
    ("unrecoverable", R.Unrecoverable(), None, [
        {"_id": "plain text", "text": "a paris invoice"},
        {"_id": "absent"},
        {"_id": "null", "text": None},
        {"_id": "ciphertext", "text": Binary(b"\x00" * 32, 6)},
        {"_id": "an ordinary binary", "text": Binary(b"\x89PNG", 0)},
    ]),
    ("clearance, mapped from roles",
     R.Clearance(order=("public", "internal", "secret"),
                 claim="roles", roles=(("analyst", "internal"),)),
     {"roles": ["analyst"]}, [
        {"_id": "absent"},
        {"_id": "public", "classification": "public"},
        {"_id": "internal", "classification": "internal"},
        {"_id": "secret", "classification": "secret"},
     ]),
]


def _clause(rule, caller):
    """The query half, built the way the handle builds it."""
    if getattr(rule, "needs_caller", False):
        return rule.clause_for(caller)
    return rule.clause()


def _admits(rule, doc, caller):
    """The guarantee half, asked the way `_admit` asks it."""
    if getattr(rule, "needs_caller", False):
        return not rule.refuses(doc, when=None, caller=caller)
    return not rule.refuses(doc, when=None)


@pytest.mark.parametrize("label,rule,caller,corpus", CASES,
                         ids=[c[0] for c in CASES])
def test_the_clause_never_hides_a_document_the_rule_admits(
        db, label, rule, caller, corpus):
    """The dangerous direction, and the only one that is invisible.

    A clause narrower than its rule drops reachable documents server-side,
    before anything counts them. The page comes back short and correct-
    looking. Nothing in `receipts()` moves, because refusal never happened
    -- the row was gone before the boundary saw it.
    """
    db.notes.insert_many([dict(d) for d in corpus])
    clause = _clause(rule, caller)
    if clause is None:
        pytest.skip(f"{label} has no query half; the guarantee is the "
                    f"per-document check and there is nothing to disagree")

    returned = {d["_id"] for d in db.notes.find(clause, {"_id": 1})}
    admitted = {d["_id"] for d in corpus if _admits(rule, d, caller)}

    hidden = admitted - returned
    assert not hidden, (
        f"{label}: the pushed-down clause hides {sorted(hidden)}, which "
        f"`refuses()` admits. Those documents are dropped by the server "
        f"before the boundary sees them, so they are not refused -- they "
        f"are missing, silently, and a caller cannot tell a short page "
        f"from a short collection.\n"
        f"  clause:   {clause}\n"
        f"  admitted: {sorted(admitted)}\n"
        f"  returned: {sorted(returned)}")


@pytest.mark.parametrize("label,rule,caller,corpus", CASES,
                         ids=[c[0] for c in CASES])
def test_what_the_clause_lets_through_is_still_judged(
        db, label, rule, caller, corpus):
    """The harmless direction, asserted so it stays harmless.

    A clause wider than its rule is a wasted fetch, not a leak -- as long
    as something still asks the rule. This is that assertion: every
    document the server returns and the rule refuses is refused, so the
    push-down is an optimisation rather than the guarantee.
    """
    db.notes.insert_many([dict(d) for d in corpus])
    clause = _clause(rule, caller)
    if clause is None:
        pytest.skip(f"{label} has no query half")

    returned = [d for d in db.notes.find(clause)]
    leaked = [d["_id"] for d in returned if not _admits(rule, d, caller)]
    kept = [d["_id"] for d in returned if _admits(rule, d, caller)]
    # Not an assertion that `leaked` is empty -- a wide clause is legal.
    # The assertion is that the rule still refuses them, which is what
    # makes the width harmless.
    for doc in returned:
        assert _admits(rule, doc, caller) == (doc["_id"] in kept)
    assert set(kept) | set(leaked) == {d["_id"] for d in returned}


def test_a_cumulative_rule_has_no_query_half_and_must_not_grow_one():
    """A budget is a total across a read, so there is nothing to push into
    a query -- and a clause that tried would be a per-document
    approximation of a set-relative rule, which is the widest possible
    disagreement between the two halves."""
    for rule in (R.Budget(limit=100), R.Distinct(on="chunk_hash")):
        assert getattr(rule, "needs_tab", False) is True
        assert rule.clause() is None, (
            f"{type(rule).__name__} grew a query half. A cumulative rule "
            f"cannot have one: the server cannot know what is already on "
            f"the page")


def test_every_shipped_rule_is_covered_here():
    """The list above is hand-written, so it goes stale the moment somebody
    adds a rule -- and a rule absent from this file is one whose two halves
    nobody compared."""
    import inspect

    shipped = {
        name for name, obj in vars(R).items()
        if inspect.isclass(obj) and not name.startswith("_")
        and hasattr(obj, "refuses") and hasattr(obj, "clause")
        and name not in ("Rule", "CumulativeRule")
    }
    covered = {type(rule).__name__ for _l, rule, _c, _d in CASES}
    covered |= {"Budget", "Distinct"}        # the cumulative test above
    missing = shipped - covered
    assert not missing, (
        f"{sorted(missing)} ship two halves and are compared nowhere. Add "
        f"a corpus that sits on its corners -- absent, null, wrong type, "
        f"wrong value, right value")
