"""MMR, and the two arithmetic paths it has.

The first built-in transform, and the reason the invariant next door is
worth having: a reranker is precisely the code that has always run
*after* a retrieval boundary, and precisely the code that has therefore
been able to undo it.

Three things are asserted here and the third is the one that decays
quietly if nobody watches it.

**It diversifies.** Given a page the index has stacked with one
cluster's worth of near-duplicates, it interleaves. Asserted against
constructed clusters rather than a fixture, so the expected answer is
arithmetic rather than a golden file somebody regenerates when it fails.

**It declines rather than guessing.** No vectors, mixed widths, a page
of one: the page comes back in the index's order. A reranker that
invented an ordering from the half of the page it could measure would
produce something that looks deliberate and means nothing.

**Both paths agree.** NumPy is an accelerant, not a dependency, so the
fallback is real code on a real path -- and a fallback exercised only on
machines that happen to lack a library is a fallback nobody has run. The
suite installs NumPy and then runs the Python path anyway, by taking the
import away.

Pure: no cluster, no driver, no network.
"""

from __future__ import annotations

import builtins
import random

import pytest

from voyd.engine.admission.rerank import MMR, _similarity_matrix, cosine

DIMS = 8


def cluster(axis: int, n: int, jitter: float = 0.02) -> list[list[float]]:
    """`n` vectors bunched around one axis. Near-duplicates, by design."""
    out = []
    for _ in range(n):
        v = [random.gauss(0, jitter) for _ in range(DIMS)]
        v[axis] = 1.0 + random.gauss(0, jitter)
        out.append(v)
    return out


@pytest.fixture(autouse=True)
def _deterministic():
    random.seed(11)


@pytest.fixture
def stacked() -> list[dict]:
    """What a vector index actually returns: six of one thing, then some.

    The failure MMR exists to fix. A prompt built from the first six
    documents knows one contract very well and nothing else at all.
    """
    docs = []
    for tag, axis, n in (("a", 0, 6), ("b", 1, 3), ("c", 2, 3)):
        for i, v in enumerate(cluster(axis, n)):
            docs.append({"_id": f"{tag}{i}", "embedding": v})
    return docs


@pytest.fixture(params=["numpy", "python"])
def arithmetic(request, monkeypatch):
    """Run the test on both paths, and say which one it is on.

    Taking NumPy away with an import hook rather than testing whichever
    one the machine happens to have: the two are meant to agree, and
    agreement is not something to find out about in production.
    """
    if request.param == "numpy":
        pytest.importorskip("numpy")
        return request.param
    real = builtins.__import__

    def refuse(name, *args, **kwargs):
        if name == "numpy":
            raise ImportError("numpy is not available in this test")
        return real(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", refuse)
    assert _similarity_matrix([[1.0, 0.0], [0.0, 1.0]]) is None
    return request.param


def order(docs: list[dict]) -> list[str]:
    return [d["_id"] for d in docs]


# ---- it diversifies ----------------------------------------------------

def test_the_top_of_the_page_stops_being_one_cluster(stacked, arithmetic):
    # The index's order opens with six near-identical documents.
    assert order(stacked)[:6] == ["a0", "a1", "a2", "a3", "a4", "a5"]
    got = MMR(diversity=0.7).on_egress(list(stacked), request={})
    assert order(got)[:3] == ["a0", "b0", "c0"], (
        "one from each cluster before a second from any")
    # Nothing is dropped. Reordering is the job; shortening is a rule's.
    assert sorted(order(got)) == sorted(order(stacked))


def test_zero_diversity_is_exactly_the_index_order(stacked, arithmetic):
    # The identity case has to be exact, not approximately respectful:
    # it is what somebody sets when they want the transform disabled for
    # a collection without deleting the declaration.
    got = MMR(diversity=0.0).on_egress(list(stacked), request={})
    assert order(got) == order(stacked)


def test_more_diversity_moves_the_second_cluster_further_up(stacked,
                                                            arithmetic):
    def first_b(diversity: float) -> int:
        got = order(MMR(diversity=diversity).on_egress(list(stacked),
                                                       request={}))
        return next(i for i, name in enumerate(got) if name.startswith("b"))

    assert first_b(0.7) < first_b(0.3) < first_b(0.0)


def test_the_index_keeps_its_first_choice_whatever_the_diversity(stacked,
                                                                 arithmetic):
    # Position one is the index's most relevant hit and there is nothing
    # picked yet to be redundant against, so no amount of diversity
    # should displace it. A reranker that reordered the top result would
    # be overruling the ranker rather than diversifying it.
    for diversity in (0.0, 0.3, 0.7, 1.0):
        got = MMR(diversity=diversity).on_egress(list(stacked), request={})
        assert order(got)[0] == "a0"


def test_top_truncates_after_reordering_not_before(stacked, arithmetic):
    got = MMR(diversity=0.7, top=3).on_egress(list(stacked), request={})
    assert order(got) == ["a0", "b0", "c0"], (
        "truncating first would return three of the same cluster")


# ---- it declines rather than guessing ----------------------------------

@pytest.mark.parametrize("docs,why", [
    ([], "an empty page"),
    ([{"_id": "only", "embedding": [1.0, 0.0]}], "a page of one"),
    ([{"_id": "a"}, {"_id": "b"}], "no vectors at all"),
    ([{"_id": "a", "embedding": [1.0, 0.0]}, {"_id": "b"}], "a missing one"),
    ([{"_id": "a", "embedding": [1.0, 0.0]},
      {"_id": "b", "embedding": "not a vector"}], "a string"),
    ([{"_id": "a", "embedding": [1.0, 0.0]},
      {"_id": "b", "embedding": [1.0, 0.0, 0.0]}], "two widths"),
])
def test_an_unmeasurable_page_comes_back_in_the_index_order(docs, why,
                                                            arithmetic):
    got = MMR(diversity=0.7).on_egress(list(docs), request={})
    assert order(got) == order(docs), why


def test_a_zero_vector_competes_on_relevance_rather_than_being_suppressed(
        arithmetic):
    # A zero vector has no direction, so its similarity to anything is
    # undefined rather than small. Treating that as maximally redundant
    # would bury a document for an arithmetic accident.
    docs = [{"_id": "a", "embedding": [1.0, 0.0, 0.0]},
            {"_id": "zero", "embedding": [0.0, 0.0, 0.0]},
            {"_id": "a2", "embedding": [1.0, 0.0, 0.0]}]
    got = MMR(diversity=0.7).on_egress(docs, request={})
    assert order(got) == ["a", "zero", "a2"]


@pytest.mark.parametrize("bad,complaint", [
    ({"diversity": 1.5}, "between 0 and 1"),
    ({"diversity": -0.1}, "between 0 and 1"),
    ({"top": 0}, "at least 1"),
])
def test_a_nonsense_setting_is_refused_where_it_is_written(bad, complaint):
    # At construction, which in a policy file is load time -- the same
    # promise `@guard` makes. A diversity of 1.5 discovered on the first
    # query is a boundary that came up announcing a page shape it cannot
    # produce.
    with pytest.raises(ValueError, match=complaint):
        MMR(**bad)


# ---- the two paths agree -----------------------------------------------

def test_both_arithmetic_paths_produce_the_same_order(stacked, monkeypatch):
    pytest.importorskip("numpy")
    accelerated = order(MMR(diversity=0.5).on_egress(list(stacked),
                                                     request={}))
    real = builtins.__import__

    def refuse(name, *args, **kwargs):
        if name == "numpy":
            raise ImportError("no numpy")
        return real(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", refuse)
    plain = order(MMR(diversity=0.5).on_egress(list(stacked), request={}))
    assert accelerated == plain


def test_cosine_agrees_with_the_matrix_it_replaces():
    pytest.importorskip("numpy")
    vectors = [[1.0, 0.0, 0.0], [0.7, 0.7, 0.0], [0.0, 0.0, 2.0],
               [0.0, 0.0, 0.0]]
    matrix = _similarity_matrix(vectors)
    for i, a in enumerate(vectors):
        for j, b in enumerate(vectors):
            assert abs(float(matrix[i][j]) - cosine(a, b)) < 1e-9, (i, j)


def test_a_page_too_big_for_python_declines_instead_of_being_slow(monkeypatch,
                                                                  caplog):
    """An optimisation is not allowed to be the slow part.

    Without NumPy the arithmetic is quadratic in the page and linear in
    the dimension: measured at ~72ms for 50 documents of 1024 dimensions
    on one laptop, and seconds beyond that. A reranker that silently
    added a second to every read would be worse than one that did not
    run, so past a measured ceiling it does not run and says which
    extra to install.
    """
    real = builtins.__import__

    def refuse(name, *args, **kwargs):
        if name == "numpy":
            raise ImportError("no numpy")
        return real(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", refuse)
    docs = [{"_id": i, "embedding": [float(i % 7)] * 1024} for i in range(120)]
    with caplog.at_level("WARNING"):
        got = MMR(diversity=0.7).on_egress(list(docs), request={})
    assert order(got) == order(docs), "left in the index's order"
    assert "needs numpy" in caplog.text
    assert "voyd[rerank]" in caplog.text


# ---- it is a transform, with everything that implies -------------------

def test_the_reranker_still_cannot_widen_a_read():
    """The invariant does not get an exception for code that ships here.

    A built-in transform is a transform. It runs in the same egress
    sandwich, before the same terminal pass, and gets no privileged
    path -- which is the property that makes adding more of them safe.
    """
    import datetime as dt

    from voyd.engine.admission import AdmissionSpec
    from voyd.engine.admission.core import AdmissionCore
    from voyd.engine.admission.rules import Deadline

    now = dt.datetime.now(dt.timezone.utc)
    spec = AdmissionSpec("notes", rules=(Deadline("expire_at"),),
                         transforms=(MMR(diversity=0.7),))
    core = AdmissionCore(db=None, spec=spec)
    docs = [{"_id": "live", "expire_at": now + dt.timedelta(days=1),
             "embedding": [1.0, 0.0]},
            {"_id": "expired", "expire_at": now - dt.timedelta(days=1),
             "embedding": [0.0, 1.0]}]
    assert order(core.reachable(docs, when=now)) == ["live"]


def test_declaring_it_in_a_policy_file_registers_a_transform(tmp_path):
    from voyd.declare import OPTIONS, REGISTRY, TRANSFORMS, load

    REGISTRY.clear()
    OPTIONS.clear()
    TRANSFORMS.clear()
    try:
        path = tmp_path / "voydfile.py"
        path.write_text(
            "from voyd import guard, deadline, rerank\n"
            "\n"
            '@guard("notes")\n'
            "class Notes:\n"
            "    expire_at = deadline()\n"
            "\n"
            'rerank("notes", diversity=0.4, vector="vec", top=5)\n')
        specs = load(str(path))
        shaping = specs["notes"].transforms
        assert [t.name for t in shaping] == ["mmr"]
        assert shaping[0].diversity == 0.4
        assert shaping[0].vector_field == "vec"
        assert shaping[0].top == 5
    finally:
        REGISTRY.clear()
        OPTIONS.clear()
        TRANSFORMS.clear()
