"""A reason to refuse is an extension point, and this is the whole contract.

``test_engine_traits.py`` proves a third party can add a *primitive*. This
proves they can add a *reason* — which matters more now, because the two
access rules this package ships (``Clearance``, ``Restricted``) were written
against the same interface a stranger has, and if that interface is not enough
then either they are privileged or the extension point is decoration.

Deliberately the whole loop rather than the predicate alone. A rule that
answers correctly in isolation and is not applied on one of the two
enforcement points is worse than no rule: the guarantee is gone and the tests
still pass. So this asserts a stranger's rule is:

1. installed by declaration, and survives ``ensure()``;
2. enforced in the *query* when it can express itself, so the database does
   the work;
3. enforced *per document* on the way out, which is the half that holds for
   ``$vectorSearch`` hits that never went through a query;
4. counted in ``receipts()`` under its own name, so an operator can see it;
5. able to opt into the caller's claims, and to declare itself unwaivable —
   the two things the shipped access rules needed;
6. unable to open the gate by failing.

Nothing here imports the app extra or patches anything. The contract is
``reason``, ``refuses()``, ``clause()`` and two optional flags.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from voyd.engine import Deadline, now, revoked
from voyd.engine.admission import Admission, AdmissionSpec, why_refused

DIMS = 4


# ---------------------------------------------------------------------------
# A reason this package does not ship: a document nobody has reviewed yet.
# ---------------------------------------------------------------------------

class Unreviewed:
    """Refused until a human has signed it off.

    The shape a real policy takes: a field on the document, expressible as a
    query clause, and meaningful to an operator as a count.
    """

    reason = "unreviewed"

    def __init__(self, field: str = "reviewed_by"):
        self.field = field

    def refuses(self, doc: dict, *, when=None) -> bool:
        return not doc.get(self.field)

    def clause(self) -> dict:
        return {self.field: {"$nin": [None, "", False]}}


class Jurisdiction:
    """A caller-aware rule written by a stranger, using the same two flags.

    If the shipped ``Clearance`` needed anything the protocol does not
    advertise, this class could not exist — which is the point of writing it
    in the test suite rather than in the package.
    """

    reason = "out_of_jurisdiction"
    needs_caller = True
    bypassable = False

    def refuses(self, doc: dict, *, when=None, caller: dict | None = None) -> bool:
        allowed = (caller or {}).get("regions")
        if not allowed:
            return True                     # no claim is no access
        return doc.get("region") not in set(allowed)

    def clause(self) -> dict | None:
        return None

    def clause_for(self, caller: dict | None) -> dict:
        return {"region": {"$in": sorted((caller or {}).get("regions") or [])}}


# ---------------------------------------------------------------------------
# the predicate, with no database
# ---------------------------------------------------------------------------

def test_a_stranger_can_name_a_new_reason():
    spec = AdmissionSpec("facts", rules=(Deadline(), revoked(), Unreviewed()))

    assert why_refused({"expire_at": None, "reviewed_by": "dana"}, spec) is None
    assert why_refused({"expire_at": None}, spec) == "unreviewed"
    # Declared order is reported order: an expired *and* unreviewed document
    # is reported as expired, because that is what was asked first.
    assert why_refused({"expire_at": now() - timedelta(days=1)}, spec) == "deadline"


def test_the_shipped_access_rules_used_no_private_interface():
    """A stranger's caller-aware rule behaves exactly like ``Clearance``."""
    handle = Admission(None, AdmissionSpec("facts", rules=(Deadline(),
                                                           Jurisdiction())))
    eu = handle.for_caller({"regions": ["eu"]})

    assert eu.reachable([{"expire_at": None, "region": "eu"}])
    assert eu.reachable([{"expire_at": None, "region": "us"}]) == []
    assert handle.for_caller({}).reachable([{"expire_at": None,
                                             "region": "eu"}]) == []


def test_a_stranger_can_declare_a_rule_unwaivable():
    """``including_refused()`` must respect a flag it has never heard of."""
    handle = Admission(None, AdmissionSpec(
        "facts", rules=(Deadline(), revoked(), Jurisdiction())))
    auditor = handle.for_caller({"regions": ["eu"]}).including_refused()

    forgotten_in_eu = {"expire_at": None, "region": "eu",
                       "forgotten": {"reason": "retracted"}}
    live_in_us = {"expire_at": None, "region": "us"}

    assert auditor.reachable([forgotten_in_eu]) == [forgotten_in_eu], \
        "the audit handle must still see what was forgotten"
    assert auditor.reachable([live_in_us]) == [], (
        "a third-party rule marked unbypassable was waived by the audit "
        "handle, so declaring it is decoration")


def test_a_stranger_rule_cannot_open_the_gate_by_raising():
    class Broken:
        reason = "broken"

        def refuses(self, doc, *, when=None):
            raise KeyError("the document was not the shape I assumed")

        def clause(self):
            return None

    spec = AdmissionSpec("facts", rules=(Broken(),))
    assert why_refused({"anything": 1}, spec) == "broken"


# ---------------------------------------------------------------------------
# and the whole loop, against a real database
# ---------------------------------------------------------------------------

async def test_a_third_party_rule_is_enforced_on_both_halves_and_counted(core):
    """The test that makes the extension point real rather than advertised."""
    engine, db = core
    notes = engine.model("notes", tenant="tenant").admitting(
        Deadline(), revoked(), Unreviewed())
    await engine.ensure(search_wait_s=5)

    await db.notes.insert_many([
        {"tenant": "t1", "name": "signed", "reviewed_by": "dana",
         "expire_at": None},
        {"tenant": "t1", "name": "draft", "expire_at": None},
        {"tenant": "t1", "name": "empty-reviewer", "reviewed_by": "",
         "expire_at": None},
    ])

    # (2) the query half: the database did the filtering.
    assert {d["name"] for d in await notes.find({"tenant": "t1"})} == {"signed"}
    assert await notes.count({"tenant": "t1"}) == 1

    # (3) the per-document half: hits that never went through a query. This is
    # the one that holds for $vectorSearch, so it is the one worth asserting
    # separately rather than trusting the count above.
    raw = [d async for d in db.notes.find({"tenant": "t1"})]
    assert len(raw) == 3, "all three rows are on disk"
    assert {d["name"] for d in notes.reachable(raw)} == {"signed"}

    # (4) and the operator can see it, under the stranger's own name.
    receipts = notes.receipts()
    assert receipts["refused_by_reason"].get("unreviewed") == 2
    assert "unreviewed" in receipts["policy"], (
        "a declared reason must show up in the policy description, or "
        "/healthz cannot tell you what this collection refuses")


async def test_the_engine_indexes_a_third_party_rules_field(core):
    """``ensure()`` indexes what a rule filters on, including a new one.

    A rule whose field is unindexed still *works* -- it is checked on the way
    out either way -- but its clause becomes a collection scan, and a
    guarantee that gets expensive is one somebody eventually turns off.
    """
    engine, db = core
    engine.model("notes", tenant="tenant").admitting(Deadline(), Unreviewed())
    await engine.ensure(search_wait_s=5)

    indexed = {tuple(k for k, _ in info["key"])
               for info in (await db.notes.index_information()).values()}
    assert ("reviewed_by",) in indexed, (
        f"ensure() did not index the third-party rule's field; got {indexed}")


async def test_a_caller_aware_third_party_rule_pushes_down_correctly(core):
    """Both halves must agree, or one of the three search tiers is wrong."""
    engine, db = core
    notes = engine.model("notes", tenant="tenant").admitting(
        Deadline(), Jurisdiction())
    await engine.ensure(search_wait_s=5)

    await db.notes.insert_many([
        {"tenant": "t1", "name": "berlin", "region": "eu", "expire_at": None},
        {"tenant": "t1", "name": "austin", "region": "us", "expire_at": None},
        {"tenant": "t1", "name": "nowhere", "expire_at": None},
    ])

    for regions, want in ((["eu"], {"berlin"}),
                          (["us"], {"austin"}),
                          (["eu", "us"], {"berlin", "austin"}),
                          ([], set())):
        handle = notes.for_caller({"regions": regions})
        queried = {d["name"] for d in await handle.find({"tenant": "t1"})}
        raw = [d async for d in db.notes.find({"tenant": "t1"})]
        per_doc = {d["name"] for d in handle.reachable(raw)}

        assert queried == want, f"regions={regions} queried {sorted(queried)}"
        assert per_doc == want, (
            f"regions={regions}: the query and the per-document check "
            f"disagree ({sorted(queried)} vs {sorted(per_doc)})")


async def test_an_unbound_read_raises_for_a_third_party_rule_too(core):
    """The fail-loud behaviour is a property of the protocol, not of Clearance."""
    from voyd.engine import CallerRequired

    engine, _ = core
    notes = engine.model("notes", tenant="tenant").admitting(
        Deadline(), Jurisdiction())
    await engine.ensure(search_wait_s=5)

    with pytest.raises(CallerRequired, match="out_of_jurisdiction"):
        await notes.find({"tenant": "t1"})
