"""The invariant that makes running somebody's code inside the boundary safe.

Every other file here tests that the boundary refuses what it declared it
would refuse. This one tests that it keeps refusing while **arbitrary code
runs in the middle of the egress path** -- which is the thing a reranker,
a de-duplicator or a cache is, and the thing that has always lived outside
the boundary and therefore been able to undo it.

The claim under test is one sentence:

    A transform cannot widen what a read returns.

Not "a reviewed transform". Not "a transform that behaves". Any of them,
including one written specifically to get a forgotten fact out, because
the authoritative per-document check runs **after** the transform and
there is nowhere after it to stand.

So the transforms below are adversarial on purpose. Each one is a real
way application code puts back what a filter removed, and most of them
are accidents in the wild rather than attacks: merging a cached list,
falling back to an unfiltered candidate pool when a page comes back
empty, mutating a document in place, returning the input it was handed
by reference. The test does not care which it is. It cares that none of
them works.

The second claim is the quieter half:

    A transform is never shown a forgotten fact in the first place.

That one is defence in depth rather than the guarantee -- code that never
receives a fact cannot mishandle it -- and it is asserted separately,
because the two would be easy to conflate and only one of them is load
bearing.

Pure: no cluster, no driver, no network.
"""

from __future__ import annotations

import textwrap
from datetime import datetime, timedelta, timezone

import pytest

from voyd.declare import OPTIONS, REGISTRY, TRANSFORMS, load
from voyd.engine.admission import AdmissionSpec
from voyd.engine.admission.core import AdmissionCore

UTC = timezone.utc
NOW = datetime(2026, 9, 22, tzinfo=UTC)
PAST = NOW - timedelta(days=7)
FUTURE = NOW + timedelta(days=7)

LIVE = {"_id": 1, "text": "ordinary", "expire_at": FUTURE}
EXPIRED = {"_id": 2, "text": "past its deadline", "expire_at": PAST}
REVOKED = {"_id": 3, "text": "somebody asked", "expire_at": FUTURE,
           "forgotten": "gdpr-4411"}
EVERYTHING = [LIVE, EXPIRED, REVOKED]


@pytest.fixture(autouse=True)
def _clean_registry():
    REGISTRY.clear()
    OPTIONS.clear()
    TRANSFORMS.clear()
    yield
    REGISTRY.clear()
    OPTIONS.clear()
    TRANSFORMS.clear()


def handle(*transforms) -> AdmissionCore:
    """A boundary over `notes`, with these transforms in the egress path."""
    from voyd.engine.admission.rules import Deadline, revoked

    spec = AdmissionSpec("notes",
                         rules=(Deadline("expire_at"), revoked("forgotten")),
                         transforms=tuple(transforms))
    return AdmissionCore(db=None, spec=spec)


def served(core: AdmissionCore, docs=None) -> list:
    return [d["_id"] for d in core.reachable(list(docs or EVERYTHING),
                                             when=NOW)]


class Named:
    """A transform that does whatever it is handed. Two members, like any."""

    def __init__(self, name, fn):
        self.name = name
        self._fn = fn

    def on_egress(self, docs, *, request):
        return self._fn(docs, request)


# ---- the guarantee -----------------------------------------------------

def test_the_baseline_is_what_it_always_was():
    # With nothing in the egress path, this is the loop it replaced.
    assert served(handle()) == [1]


@pytest.mark.parametrize("name,fn", [
    # The cache merge. The commonest real one: a list from somewhere else
    # is unioned in, and "somewhere else" did not run a policy.
    ("cache-merge", lambda docs, req: docs + [EXPIRED, REVOKED]),
    # The empty-page fallback. A reranker that returns the unfiltered
    # candidate pool rather than nothing, because an empty page looked
    # like a bug to whoever wrote it.
    ("fallback", lambda docs, req: docs if len(docs) > 2 else list(EVERYTHING)),
    # Straightforwardly malicious.
    ("exfiltrate", lambda docs, req: list(EVERYTHING)),
    # Subtler: keep the admitted document's identity and swap its body
    # for a forgotten one's. Nothing is "added", so a check that counted
    # documents would see no change.
    ("body-swap", lambda docs, req: [dict(REVOKED, _id=1)]),
    # Un-forget it. Strip the mark that got it refused and send it on.
    ("launder", lambda docs, req: docs + [
        {k: v for k, v in REVOKED.items() if k != "forgotten"}]),
])
def test_no_transform_can_put_a_forgotten_fact_on_the_wire(name, fn):
    """Five ways application code undoes a filter. None of them works.

    `launder` is the interesting one and it is *allowed* to succeed in
    part: a document with the mark removed is, by the policy as written,
    no longer revoked. That is not a hole in the sandwich -- it is the
    policy answering the question it was asked, and the terminal pass
    asking it again is exactly why the answer is the policy's rather
    than the transform's. What must never happen is a document reaching
    the wire *carrying* a reason to be refused.
    """
    core = handle(Named(name, fn))
    out = core.reachable(list(EVERYTHING), when=NOW)
    for doc in out:
        assert doc.get("forgotten") is None, (
            f"{name} served a document still carrying its revocation")
        assert doc.get("expire_at") != PAST, (
            f"{name} served a document past its deadline")
    # And the expired one, which has no way to be laundered by these,
    # never appears at all.
    assert 2 not in [d["_id"] for d in out]


def test_a_transform_that_returns_its_input_by_reference_is_still_checked():
    # The laziest possible transform, and the one most likely to be
    # written: hand back exactly what arrived. The terminal pass must not
    # be skipped just because nothing appears to have changed.
    core = handle(Named("identity", lambda docs, req: docs))
    assert served(core) == [1]


def test_transforms_run_in_declared_order_and_the_check_is_after_all_of_them():
    trail = []

    def note(tag):
        def run(docs, req):
            trail.append(tag)
            return docs + [REVOKED] if tag == "second" else docs
        return run

    core = handle(Named("first", note("first")),
                  Named("second", note("second")))
    assert served(core) == [1]
    assert trail == ["first", "second"], "declared order is application order"


# ---- defence in depth --------------------------------------------------

def test_a_transform_is_never_shown_a_forgotten_fact():
    """The quieter half. Code that never receives a fact cannot leak it.

    Asserted apart from the guarantee because the two are easy to
    conflate: this one is a property of the *first* pass and could be
    removed without the boundary failing, and the terminal pass is the
    one that cannot.
    """
    seen: list[list[int]] = []
    core = handle(Named("observer",
                        lambda docs, req: (seen.append([d["_id"] for d in docs])
                                           or docs)))
    core.reachable(list(EVERYTHING), when=NOW)
    assert seen == [[1]], "the expired and revoked ones never reached it"


def test_the_transform_is_told_about_the_read_and_holds_no_engine():
    # A plain dict crosses into somebody else's code on purpose: a
    # transform holding an engine type could reach past the two members
    # it declared.
    got: list[dict] = []
    core = handle(Named("spy", lambda docs, req: (got.append(req) or docs)))
    core.reachable([LIVE], when=NOW)
    assert got[0]["collection"] == "notes"
    assert got[0]["vector_search"] is False
    assert set(got[0]) == {"collection", "vector_search", "caller"}


# ---- failing transforms fail safe --------------------------------------

def test_a_transform_that_raises_is_skipped_and_the_read_survives():
    """The opposite decision from a rule, and deliberately so.

    A rule that raises is treated as a refusal, because a rule that
    fails open is a leak. A transform that raises cannot open anything
    -- the terminal pass runs either way -- so refusing the whole read
    over a broken reranker would be an outage caused by an optimisation.
    """
    def explode(docs, req):
        raise RuntimeError("the reranker is down")

    core = handle(Named("broken", explode))
    assert served(core) == [1]


def test_a_transform_that_returns_nonsense_is_skipped_not_believed():
    # The terminal pass would refuse the garbage document by document
    # and report "everything was forgotten", which sends somebody to the
    # wrong file entirely.
    for junk in (None, "a string", [1, 2, 3], {"not": "a list"}):
        core = handle(Named("confused", lambda docs, req, j=junk: j))
        assert served(core) == [1], f"believed {junk!r}"


def test_one_broken_transform_does_not_take_the_others_with_it():
    def explode(docs, req):
        raise RuntimeError("down")

    core = handle(Named("broken", explode),
                  Named("reverse", lambda docs, req: list(reversed(docs))))
    assert served(core, [LIVE, dict(LIVE, _id=9)]) == [9, 1]


# ---- what a budget charges ---------------------------------------------

def test_a_budget_charges_the_page_that_is_served_not_the_one_proposed():
    """Cumulative rules are held back to the terminal pass, on purpose.

    A transform that drops documents runs before the budget is charged,
    so `Page.spent` stays the sum of what was admitted -- the promise
    `Tab.charge` makes. Charging the pre-rerank page would bill a prompt
    for text it never contained.
    """
    from voyd.engine.admission.rules import Budget, Deadline

    spec = AdmissionSpec(
        "notes",
        rules=(Deadline("expire_at"), Budget(limit=10, cost_field="tokens")),
        transforms=(Named("keep-one", lambda docs, req: docs[:1]),))
    core = AdmissionCore(db=None, spec=spec)
    docs = [{"_id": i, "expire_at": FUTURE, "tokens": 6}
            for i in range(3)]
    out = core.reachable(docs, when=NOW)
    # One document survives the transform and costs 6 of 10. Without the
    # hold-back, two would have been charged before the transform ran and
    # the budget would have latched.
    assert [d["_id"] for d in out] == [0]


# ---- declaring one -----------------------------------------------------

def policy(tmp_path, body: str) -> str:
    path = tmp_path / "voydfile.py"
    path.write_text(textwrap.dedent(body))
    return str(path)


def test_a_policy_file_can_declare_a_transform_either_side_of_the_guard(
        tmp_path):
    # Both orders work, and neither is "the" documented one: a policy
    # file whose behaviour depended on decorator order would be exactly
    # the class of surprise this loader exists to refuse.
    below = load(policy(tmp_path, '''
        from voyd import guard, deadline, transform

        @guard("notes")
        class Notes:
            expire_at = deadline()

        @transform("notes")
        class Reverse:
            name = "reverse"
            def on_egress(self, docs, *, request):
                return list(reversed(docs))
    '''))
    assert [t.name for t in below["notes"].transforms] == ["reverse"]

    REGISTRY.clear()
    OPTIONS.clear()
    TRANSFORMS.clear()
    above = load(policy(tmp_path, '''
        from voyd import guard, deadline, transform

        @transform("notes")
        class Reverse:
            name = "reverse"
            def on_egress(self, docs, *, request):
                return list(reversed(docs))

        @guard("notes")
        class Notes:
            expire_at = deadline()
    '''))
    assert [t.name for t in above["notes"].transforms] == ["reverse"]


@pytest.mark.parametrize("body,complaint", [
    ("""
        @transform("notes")
        class NoName:
            def on_egress(self, docs, *, request):
                return docs
     """, "missing name"),
    ("""
        @transform("notes")
        class NoEgress:
            name = "half"
     """, "missing on_egress"),
    ("""
        @transform("notes")
        class Misspelled:
            name = "typo"
            def on_egres(self, docs, *, request):
                return docs
     """, "missing on_egress"),
])
def test_a_half_written_transform_is_refused_at_load(tmp_path, body, complaint):
    # The same argument the rules make one level down. The two ways to
    # get a protocol wrong are to omit a member and to misspell one, and
    # from a loader they are indistinguishable -- so both are loud, or a
    # boundary comes up announcing a page shape it is not applying.
    with pytest.raises(TypeError, match=complaint):
        load(policy(tmp_path,
                    "from voyd import transform\n" + textwrap.dedent(body)))


def test_a_transform_is_part_of_what_makes_two_specs_differ():
    # Handles are deduplicated per collection by spec equality, so two
    # declarations that disagree about what shapes the page have to
    # collide rather than resolve to whichever was imported first.
    plain = AdmissionSpec("notes")
    shaped = AdmissionSpec("notes",
                           transforms=(Named("x", lambda d, r: d),))
    assert plain != shaped


# ---- through a real proxy, with a real driver --------------------------

HOSTILE = '''
from voyd import deadline, guard, revocable, transform


@guard("notes")
class Notes:
    expire_at = deadline()
    forgotten = revocable()


@transform("notes")
class PutItBack:
    """A reranker that merges an unfiltered candidate list. It cannot win."""

    name = "hostile"

    def on_egress(self, docs, *, request):
        import datetime as dt
        past = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=7)
        return list(docs) + [
            {"_id": "smuggled-expired", "text": "past its deadline",
             "expire_at": past},
            {"_id": "smuggled-revoked", "text": "somebody asked",
             "expire_at": dt.datetime.now(dt.timezone.utc)
                          + dt.timedelta(days=7),
             "forgotten": "gdpr-4411"},
        ]
'''


@pytest.mark.needs_mongo
def test_a_hostile_reranker_cannot_smuggle_a_fact_past_a_real_boundary(
        boundary, direct, database):
    """The claim, end to end: a socket, a driver, and somebody's code.

    Everything above this line is a unit test of the sandwich. This one
    starts `voyd-wire` as a subprocess with a policy whose transform
    exists solely to put forgotten facts back, and reads through it with
    a `pymongo` that has never heard of this package.

    The transform runs -- it is not disabled, sandboxed or reviewed. It
    returns documents. They do not arrive.
    """
    import datetime as dt

    now = dt.datetime.now(dt.timezone.utc)
    direct[database].notes.insert_many([
        {"_id": "live", "expire_at": now + dt.timedelta(days=7)},
        {"_id": "expired", "expire_at": now - dt.timedelta(days=7)},
        {"_id": "revoked", "expire_at": now + dt.timedelta(days=7),
         "forgotten": "gdpr-1"},
    ])
    # Around the boundary: all three are genuinely on disk. Both halves
    # of the claim need saying, and only the unguarded client can say
    # the first.
    assert direct[database].notes.count_documents({}) == 3

    from pymongo import MongoClient

    wire = boundary(HOSTILE)
    client: object = MongoClient(wire.uri, serverSelectionTimeoutMS=10_000)
    try:
        got = list(client[database].notes.find({}))
    finally:
        client.close()

    served = {d["_id"] for d in got}
    assert served == {"live"}, (
        f"the transform got something through the boundary: "
        f"{sorted(served - {'live'})}")
    # Named individually, because each is a different way of losing.
    assert "smuggled-expired" not in served, "an invented expired document"
    assert "smuggled-revoked" not in served, "an invented revoked document"
    assert "expired" not in served and "revoked" not in served
