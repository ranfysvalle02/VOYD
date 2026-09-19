"""``Guard`` asks about the caller. ``Admission`` asks about the document.
Neither asks the question that leaks.

The pair is what matters: *may this document reach **this** caller's prompt*.
A scope-level lock is all-or-nothing, so the moment one document in a scope is
more sensitive than the rest, the only available answers are "everyone gets
everything" and "split the scope" -- and one retrieval boundary per
sensitivity level is four owners of one deadline all over again.

``for_caller(claims)`` closes it in the layer that already refuses things. The
tests below are almost entirely about the ways an access check is wrong while
passing its happy path: a missing claim read as permission, an unrecognised
label read as harmless, an untagged document read as public, a shared handle
carrying the previous request's identity, and an audit escape hatch that
waives clearance along with the deadline.
"""

from __future__ import annotations

import asyncio

import pytest

from voyd.engine import (NOT_CLEARED, CallerRequired, Clearance, Deadline,
                         Restricted, revoked)
from voyd.engine.admission import Admission, AdmissionSpec, why_refused

ORDER = ("public", "internal", "secret")


def _handle(rules):
    return Admission(None, AdmissionSpec("docs", rules=tuple(rules)))


def _doc(level="public", **kw):
    return {"expire_at": None, "classification": level, **kw}


# --------------------------------------------------------------------------
# the rule, in isolation. every one of these is a fail-closed direction.
# --------------------------------------------------------------------------

def test_a_caller_cleared_high_enough_gets_the_document():
    """The happy path, first, so the rest are not vacuous."""
    rule = Clearance(order=ORDER)
    assert not rule.refuses(_doc("internal"), caller={"clearance": "internal"})
    assert not rule.refuses(_doc("public"), caller={"clearance": "secret"})


def test_a_caller_cleared_too_low_is_refused_not_ranked_lower():
    rule = Clearance(order=ORDER)
    assert rule.refuses(_doc("secret"), caller={"clearance": "internal"})


def test_a_caller_with_no_claim_gets_nothing():
    """The tempting default is 'unrestricted', because it makes tests pass.

    It is also the shape of every accidental world-readable dataset: the
    claim is missing on the one code path nobody threaded it through, and
    absence reads as permission.
    """
    rule = Clearance(order=ORDER)
    for caller in ({}, None, {"clearance": None}, {"cleerance": "secret"}):
        assert rule.refuses(_doc("public"), caller=caller), (
            f"a caller with no usable clearance ({caller}) was served a "
            f"document")


def test_an_unrecognised_label_is_refused_not_treated_as_low():
    """A classification this deployment does not know is not a harmless one.

    It is a document somebody deliberately labelled, with a vocabulary that
    has since changed. Sorting it to the bottom of the ordering would make a
    renamed level silently world-readable.
    """
    rule = Clearance(order=ORDER)
    assert rule.refuses(_doc("top-secret"), caller={"clearance": "secret"})
    assert rule.refuses(_doc(42), caller={"clearance": "secret"})


def test_an_untagged_document_is_refused_unless_a_default_is_declared():
    """Untagged is not public.

    Getting this backwards makes every document written before the policy
    existed readable by everyone -- which is the population most likely to
    predate anybody thinking about sensitivity.
    """
    strict = Clearance(order=ORDER)
    assert strict.refuses({"expire_at": None}, caller={"clearance": "secret"})

    lenient = Clearance(order=ORDER, default="public")
    assert not lenient.refuses({"expire_at": None},
                               caller={"clearance": "public"}), (
        "a declared default is the one way untagged rows become readable, "
        "and it has to be typed out")


def test_a_caller_with_a_nonsense_claim_is_refused():
    rule = Clearance(order=ORDER)
    for claim in ("SECRET", "", [], {"a": 1}, 3):
        assert rule.refuses(_doc("public"), caller={"clearance": claim}), \
            f"{claim!r} passed as a clearance"


def test_restricted_needs_an_overlap_and_an_empty_list_is_not_open():
    rule = Restricted()
    doc = {"expire_at": None, "audience": ["legal", "deal-desk"]}
    assert not rule.refuses(doc, caller={"groups": ["legal"]})
    assert rule.refuses(doc, caller={"groups": ["support"]})
    assert rule.refuses(doc, caller={})
    for empty in ([], None, ""):
        assert rule.refuses({"expire_at": None, "audience": empty},
                            caller={"groups": ["legal"]}), (
            "a restriction nobody filled in is not an absent restriction")


def test_the_reason_is_reported_separately_from_forgetting():
    """``not_cleared`` is not a forgetting reason, and the counters say so.

    A climbing ``deadline`` is the system working. A climbing ``not_cleared``
    is somebody probing. Merging them into one number loses the only one that
    is a security signal.
    """
    spec = AdmissionSpec("docs", rules=(Deadline(), revoked(),
                                        Clearance(order=ORDER)))
    reason = why_refused(_doc("secret"), spec, caller={"clearance": "public"})
    assert reason == NOT_CLEARED
    assert reason not in ("deadline", "revoked")


def test_a_caller_aware_rule_that_raises_still_refuses():
    """The existing guarantee, extended to the rules that decide access.

    A rule that throws must not open the gate -- and a caller-aware rule is
    the worst place for that, since the exception would be thrown by data the
    caller supplied.
    """
    class Exploding:
        reason = "not_cleared"
        needs_caller = True
        bypassable = False

        def refuses(self, doc, *, when=None, caller=None):
            raise RuntimeError("claims were not what I expected")

        def clause(self):
            return None

    spec = AdmissionSpec("docs", rules=(Exploding(),))
    assert why_refused(_doc(), spec, caller={"clearance": "secret"}) == \
        "not_cleared"


# --------------------------------------------------------------------------
# the handle. this is where a shared object becomes a security bug.
# --------------------------------------------------------------------------

def test_for_caller_returns_a_new_handle_and_does_not_mutate():
    """``engine.admission()`` hands every request the *same* object.

    So a ``for_caller`` that assigned to the shared handle would make the
    last request's identity the current one, under concurrency, in an
    access-control check. That bug does not error, does not reproduce
    reliably, and shows one caller's documents to whoever asked second.
    """
    shared = _handle([Deadline(), Clearance(order=ORDER)])

    low = shared.for_caller({"clearance": "public"})
    high = shared.for_caller({"clearance": "secret"})

    assert low is not shared and high is not shared and low is not high
    assert shared._caller is None, "the shared handle was mutated"
    assert low._caller == {"clearance": "public"}
    assert high._caller == {"clearance": "secret"}

    secret = _doc("secret")
    assert low.reachable([secret]) == []
    assert high.reachable([secret]) == [secret], (
        "the two derived handles are sharing state")


def test_the_claims_are_copied_not_aliased():
    """A caller's dict must not be editable through the handle afterwards."""
    claims = {"clearance": "public"}
    bound = _handle([Clearance(order=ORDER)]).for_caller(claims)
    claims["clearance"] = "secret"
    assert bound.reachable([_doc("secret")]) == [], (
        "mutating the dict after binding escalated the handle")


def test_including_refused_cannot_waive_clearance():
    """The naive version of that method skips every rule. It did.

    A deadline and a revocation say the fact is forgotten, and auditing what
    was forgotten is the job that method exists for. A clearance says this
    caller may not have it, which is not a forgetting reason and not this
    handle's to waive -- or "let me see the deleted rows" is a privilege
    escalation.
    """
    handle = _handle([Deadline(), revoked(), Clearance(order=ORDER)])
    auditor = handle.for_caller({"clearance": "internal"}).including_refused()

    forgotten_but_permitted = _doc("internal", forgotten={"reason": "leaked"})
    above_clearance = _doc("secret")

    assert auditor.reachable([forgotten_but_permitted]) == \
        [forgotten_but_permitted], "an auditor must see what was forgotten"
    assert auditor.reachable([above_clearance]) == [], (
        "including_refused() served a document above the caller's clearance")


def test_the_query_narrows_to_what_the_caller_may_see():
    """Pushed down where it can be, for cost -- never as the guarantee.

    The per-document check above is what holds. This is so a caller cleared
    for nothing does not cause every row in the scope to be fetched and
    thrown away.
    """
    handle = _handle([Deadline(), Clearance(order=ORDER)])

    internal = handle.for_caller({"clearance": "internal"})._query({})
    levels = [c for c in internal["$and"] if "classification" in c]
    assert levels == [{"classification": {"$in": ["public", "internal"]}}]

    nobody = handle.for_caller({})._query({})
    assert {"classification": {"$in": []}} in nobody["$and"], (
        "a caller cleared for nothing should match nothing in the database, "
        "not be served everything and refused in Python")


def test_binding_a_caller_changes_nothing_without_a_caller_aware_rule():
    """So a request handler can call it unconditionally.

    If binding a caller altered behaviour on a collection with no
    caller-aware rule, every call site would need to know which collections
    have a policy -- and would get it wrong as policies were added.
    """
    plain = _handle([Deadline(), revoked()])
    doc = _doc()
    assert plain.for_caller({"clearance": "public"}).reachable([doc]) == [doc]
    assert plain.for_caller(None).reachable([doc]) == [doc]


# --------------------------------------------------------------------------
# an unbound read. found by an example, not by a test, which is typical.
# --------------------------------------------------------------------------

def test_reading_without_a_caller_raises_instead_of_picking_an_answer():
    """Neither available answer is acceptable, so it refuses to choose.

    Returning everything is the breach the rule exists to prevent. Returning
    nothing is worse in a subtler way -- and that is what the query clause
    does on its own, since an unknown clearance permits no level. An empty
    read looks like an empty scope, and the rest of this repository is
    organised around never letting that ambiguity exist.
    """
    handle = _handle([Deadline(), Clearance(order=ORDER)])
    with pytest.raises(CallerRequired, match="who is asking"):
        handle._query({})
    with pytest.raises(CallerRequired):
        handle.reachable([_doc("public")])


def test_an_unbound_revoke_does_not_silently_forget_nothing():
    """The bug this whole section exists for, and it was a write.

    ``revoke()`` builds its update from the same refusing query as a read, so
    with a clearance rule installed and no caller bound it matched zero rows
    -- and returned 0 having reported success. A revocation that quietly does
    nothing is the worst failure available to this codebase: the caller is
    told the fact is unreachable, and it is not.
    """
    class Trap:
        def __getitem__(self, name):
            raise AssertionError(
                "the write reached the collection before the caller was "
                "checked; which line raises first must not be luck")

    handle = Admission(Trap(), AdmissionSpec(
        "docs", rules=(Deadline(), revoked(), Clearance(order=ORDER))))
    with pytest.raises(CallerRequired):
        asyncio.run(handle.revoke({"doc_id": "d1"}, reason="leaked"))

    # Bound, it proceeds -- and trips the trap, which is how we know the
    # check above was the caller check and not the stub db.
    with pytest.raises(AssertionError, match="before the caller was checked"):
        asyncio.run(handle.for_caller({"clearance": "secret"}).revoke(
            {"doc_id": "d1"}, reason="leaked"))


def test_a_bound_caller_holding_no_claims_is_a_real_answer():
    """``for_caller({})`` is not the same as never binding.

    One is a caller who authenticated and holds no clearance -- entitled to
    nothing, which is an answer. The other is a code path that forgot to say
    who is asking, which is a bug. Collapsing them would mean either raising
    on a legitimate request or silently serving nothing on a broken one.
    """
    handle = _handle([Deadline(), Clearance(order=ORDER)])
    bound = handle.for_caller({})

    assert bound._bound is True
    assert bound.reachable([_doc("public")]) == []
    assert {"classification": {"$in": []}} in bound._query({})["$and"]


def test_a_collection_with_no_caller_aware_rule_never_demands_one():
    """Otherwise adding the feature would break every existing collection."""
    plain = _handle([Deadline(), revoked()])
    doc = _doc()
    assert plain._query({}) is not None
    assert plain.reachable([doc]) == [doc]


# --------------------------------------------------------------------------
# and through a real database, because the query half has to agree
# --------------------------------------------------------------------------

async def test_the_two_halves_agree_against_mongodb(core):
    """``find`` (query-side) and ``reachable`` (document-side) must match.

    They are two enforcement points for one rule, and the failure worth
    catching is them disagreeing: a row the query lets through and the
    per-document check refuses is merely slow, but a row the query lets
    through *and* the check admits, which the other half would have refused,
    is a leak that only shows up on one of the three search tiers.
    """
    engine, db = core
    docs = engine.model("classified", tenant="tenant").admitting(
        Deadline(), revoked(), Clearance(order=ORDER))
    await engine.ensure(search_wait_s=5)

    rows = [{"tenant": "t1", "name": n, "classification": c, "expire_at": None}
            for n, c in (("p", "public"), ("i", "internal"), ("s", "secret"),
                         ("unlabelled", None), ("weird", "cosmic"))]
    await db.classified.insert_many(rows)

    for clearance, expected in (("public", {"p"}),
                                ("internal", {"p", "i"}),
                                ("secret", {"p", "i", "s"})):
        handle = docs.for_caller({"clearance": clearance})
        found = {d["name"] for d in await handle.find({"tenant": "t1"})}
        assert found == expected, f"{clearance} saw {found}"

        # The same set, arrived at the other way: straight at the collection
        # and admitted per document. If these disagree, one of the two
        # enforcement points is wrong and $vectorSearch uses that one.
        raw = [d async for d in db.classified.find({"tenant": "t1"})]
        assert {d["name"] for d in handle.reachable(raw)} == expected, (
            "the query and the per-document check disagree about what this "
            "caller may see")

    uncleared = docs.for_caller({})
    assert await uncleared.find({"tenant": "t1"}) == []
    assert await uncleared.count({"tenant": "t1"}) == 0


async def test_restricted_pushes_down_correctly_against_an_array_field(core):
    """``$in`` on an array field is array-*contains*, and that is load-bearing.

    ``Restricted`` stores the audience as a list on the document and the
    clause is ``{"audience": {"$in": [caller's groups]}}``. That reads like a
    scalar comparison and is not: against an array field MongoDB matches if
    *any* element matches, which is exactly the overlap test wanted -- and is
    the kind of thing that is either right or silently inverted. So it is
    checked against the database rather than reasoned about, and checked
    against the per-document half at the same time.
    """
    engine, db = core
    docs = engine.model("shared", tenant="tenant").admitting(
        Deadline(), Restricted())
    await engine.ensure(search_wait_s=5)

    await db.shared.insert_many([
        {"tenant": "t1", "name": "contract", "audience": ["legal", "deal-desk"],
         "expire_at": None},
        {"tenant": "t1", "name": "ticket", "audience": ["support"],
         "expire_at": None},
        {"tenant": "t1", "name": "everyones", "audience": ["legal", "support"],
         "expire_at": None},
        {"tenant": "t1", "name": "nobodys", "audience": [], "expire_at": None},
        {"tenant": "t1", "name": "unset", "expire_at": None},
    ])

    for groups, want in (
            (["legal"], {"contract", "everyones"}),
            (["support"], {"ticket", "everyones"}),
            (["legal", "support"], {"contract", "ticket", "everyones"}),
            (["finance"], set()),
            ([], set())):
        handle = docs.for_caller({"groups": groups})
        found = {d["name"] for d in await handle.find({"tenant": "t1"})}
        assert found == want, f"groups={groups} saw {sorted(found)}"

        raw = [d async for d in db.shared.find({"tenant": "t1"})]
        assert {d["name"] for d in handle.reachable(raw)} == want, (
            f"the pushed-down clause and the per-document check disagree for "
            f"groups={groups}")

    # An empty audience and a missing one are refused by both halves, which is
    # the case a `$in` clause gets right only by accident.
    everyone = docs.for_caller({"groups": ["legal", "support", "finance"]})
    assert {"nobodys", "unset"} & {
        d["name"] for d in await everyone.find({"tenant": "t1"})} == set()


async def test_concurrent_callers_do_not_see_each_others_documents(core):
    """The bug ``for_caller`` returning a clone exists to prevent.

    Twelve interleaved requests against one shared handle, each asserting its
    own boundary. A mutating implementation passes this test sequentially and
    fails it here, which is the only place it would ever have been caught.
    """
    engine, db = core
    docs = engine.model("classified", tenant="tenant").admitting(
        Deadline(), Clearance(order=ORDER))
    await engine.ensure(search_wait_s=5)
    await db.classified.insert_many(
        [{"tenant": "t1", "name": n, "classification": c, "expire_at": None}
         for n, c in (("p", "public"), ("i", "internal"), ("s", "secret"))])

    async def ask(clearance, expected):
        for _ in range(4):
            got = {d["name"] for d in
                   await docs.for_caller({"clearance": clearance}).find(
                       {"tenant": "t1"})}
            assert got == expected, f"{clearance} saw {got}"

    await asyncio.gather(
        ask("public", {"p"}),
        ask("internal", {"p", "i"}),
        ask("secret", {"p", "i", "s"}),
    )


async def test_search_through_a_bound_handle_refuses_per_hit(core):
    """The path that matters, since a vector hit never went through a query.

    Note the tenant still has to be passed: the handle knows the *field* its
    boundary lives on, never the value, so ``search()`` inherits
    ``require_scope`` and an unscoped search raises rather than ranking every
    tenant's documents together.
    """
    engine, db = core
    model = engine.model("classified", tenant="tenant")
    model.searchable(text_paths=("name",), dimensions=4,
                     filter_fields=("classification",))
    docs = model.admitting(Deadline(), Clearance(order=ORDER))
    await engine.ensure(search_wait_s=60)

    await db.classified.insert_many(
        [{"tenant": "t1", "name": f"note {n}", "classification": c,
          "expire_at": None, "embedding": [0.1, 0.2, 0.3, 0.4]}
         for n, c in (("public", "public"), ("secret", "secret"))])

    loop = asyncio.get_running_loop()
    deadline = loop.time() + 60
    cleared = docs.for_caller({"clearance": "secret"})
    while loop.time() < deadline:
        if len(await cleared.search([0.1, 0.2, 0.3, 0.4], limit=10,
                                    filters={"tenant": "t1"})) == 2:
            break
        await asyncio.sleep(0.5)
    else:
        pytest.fail("mongot did not index both rows within 60s")

    page = await docs.for_caller({"clearance": "public"}).search(
        [0.1, 0.2, 0.3, 0.4], limit=10, filters={"tenant": "t1"})
    assert {d["name"] for d in page} == {"note public"}
    assert page.refused == {NOT_CLEARED: 1}, (
        "the refusal must be reported, and reported as an access refusal "
        "rather than as a forgotten fact")
