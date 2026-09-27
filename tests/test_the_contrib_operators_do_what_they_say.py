"""`voyd.contrib` does what each docstring says, and nothing it does not.

Every operator and stage in `voyd/contrib/` is local, deterministic code a
voydfile installs with one call. The claims under test:

    Each one computes what its docstring says, on the edge cases too.

Empty input, a missing field, unicode, a digit run that fails Luhn, a
budget that fits nothing. And it refuses a bad argument with a sentence
naming the option, not a `KeyError` from three frames down.

    The same input gives the same output, under any hash seed.

Nothing in it iterates a set into its output or draws a random number,
checked by running the same pipeline in fresh interpreters with different
`PYTHONHASHSEED`s.

    Installing goes through the public `stage` / `operator`.

So a name installed twice, or installed beside a hand-written one, fails
the load exactly as a duplicate `@stage` does.

    A contrib stage is still only handed what was admitted.

Through the real split path, with the fixtures of
`test_a_virtual_stage_sees_only_what_was_admitted.py`. Pure: no cluster.
The live half, where a pymongo client runs a contrib pipeline through a
real `voyd-wire`, is at the bottom and needs a deployment.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from datetime import datetime, timedelta, timezone

import pytest

from tests import test_a_virtual_stage_sees_only_what_was_admitted as admitted
from tests.test_a_virtual_stage_sees_only_what_was_admitted import (
    EXPIRED, GLOBEX, INJECTED, LIVE, LIVE2, PREFIX, REVOKED, ids, serve)
from voyd import contrib
from voyd.contrib import context, rank, text
from voyd.declare import OPERATORS, STAGES, load
from voyd.wire.policy import Virtuals

# The same fixtures, so "admitted" means exactly what it means there.
guards = admitted.guards
_clean_registry = admitted._clean_registry

UTC = timezone.utc
NOW = datetime(2026, 9, 1, tzinfo=UTC)


class Ctx:
    """What the boundary hands a step, reduced to what contrib reads."""

    def __init__(self, now=NOW):
        self.now = now
        self.vars: dict = {}

    def publish(self, name, value):
        self.vars[name] = value


def op(name, args, doc=None):
    kind, fn = contrib.MODULES[_module(name)].NAMES[name]
    assert kind == "operator"
    return fn(doc or {}, args, Ctx())


def run(name, args, docs, ctx=None):
    kind, fn = contrib.MODULES[_module(name)].NAMES[name]
    assert kind == "stage"
    ctx = ctx or Ctx()
    return fn(args, [dict(d) for d in docs], ctx), ctx


def _module(name):
    return next(m for m, mod in contrib.MODULES.items() if name in mod.NAMES)


# ---- $redactPII -------------------------------------------------------

def test_redact_pii_replaces_every_kind_it_names():
    got = text.redact_pii(
        "mail ana.b+x@acme.example; card 4111 1111 1111 1111; ssn "
        "123-45-6789; ip 10.0.0.1 and 2001:db8::1; call (555) 123-4567 or "
        "+44 20 7946 0958.")
    assert got == ("mail [email]; card [card]; ssn [ssn]; ip [ip] and [ip]; "
                   "call [phone] or [phone].")


def test_a_digit_run_that_fails_luhn_is_not_a_card():
    assert text.luhn("4111111111111111")
    assert not text.luhn("4111111111111112")
    assert not text.luhn("7")
    got = text.redact_pii("ref 4111 1111 1111 1112 and 1234567890123",
                          kinds=["card"])
    assert got == "ref 4111 1111 1111 1112 and 1234567890123"
    # Nor half of one as a phone number.
    assert "[phone]" not in text.redact_pii("ref 4111 1111 1111 1112")


def test_impossible_ssns_and_ips_are_left_alone():
    assert text.redact_pii("000-12-3456 666-12-3456 999.1.1.1 256.1.1.1",
                           kinds=["ssn", "ip"]) == (
        "000-12-3456 666-12-3456 999.1.1.1 256.1.1.1")


def test_redact_pii_kinds_and_replacement_are_configurable():
    s = "a@b.co 123-45-6789"
    assert text.redact_pii(s, ["email"], "<{kind}>") == "<email> 123-45-6789"
    assert op("$redactPII", {"input": s, "kinds": ["ssn"],
                             "replacement": "#"}) == "a@b.co #"
    with pytest.raises(ValueError, match="unknown kind"):
        text.redact_pii(s, ["passport"])
    with pytest.raises(ValueError, match="'kinds' must be a list"):
        op("$redactPII", {"input": s, "kinds": "email"})


def test_redact_pii_passes_unicode_through_and_none_as_none():
    assert text.redact_pii("café — josé@exemplo.pt") == "café — [email]"
    assert text.redact_pii(None) is None
    assert op("$redactPII", None) is None


# ---- $chunk -----------------------------------------------------------

def test_chunk_by_words_with_overlap():
    assert text.chunk("a b c d e f g", size=3, overlap=1) == [
        "a b c", "c d e", "e f g"]
    assert text.chunk("a b c d", size=3) == ["a b c", "d"]


def test_chunk_by_chars_and_sentences():
    assert text.chunk("abcdefg", by="chars", size=3) == ["abc", "def", "g"]
    assert text.chunk("One. Two! Three? Four.", by="sentences", size=2) == [
        "One. Two!", "Three? Four."]
    assert text.chunk("一。二。 三。", by="sentences", size=1) == ["一。二。", "三。"]


def test_chunk_of_nothing_is_no_chunks():
    assert text.chunk("") == [] and text.chunk("   ") == []
    assert text.chunk(None) == []
    assert op("$chunk", {"input": None}) == []


def test_chunk_refuses_a_shape_it_cannot_cut():
    with pytest.raises(ValueError, match="'overlap' .* smaller"):
        text.chunk("a b", size=2, overlap=2)
    with pytest.raises(ValueError, match="'by'"):
        text.chunk("a", by="paragraphs")
    with pytest.raises(ValueError, match="'size' must be at least 1"):
        text.chunk("a", size=0)
    with pytest.raises(ValueError, match="unknown option"):
        op("$chunk", {"input": "a", "length": 3})
    with pytest.raises(ValueError, match="'input' is required"):
        op("$chunk", {"size": 3})


# ---- counts and shape -------------------------------------------------

def test_word_count_and_token_estimate():
    assert op("$wordCount", "The brake-fault is B1342.") == 5
    assert op("$wordCount", {"input": "naïve café"}) == 2
    assert op("$wordCount", None) == 0
    assert op("$tokenEstimate", "abcd") == 1
    assert op("$tokenEstimate", "abcde") == 2
    assert op("$tokenEstimate", "") == 0 and op("$tokenEstimate", None) == 0


def test_truncate_keeps_what_fits_and_marks_what_it_cut():
    assert text.truncate("hello world again", 8) == "hello w…"
    assert len(text.truncate("x" * 50, 10)) == 10
    assert text.truncate("short", 10) == "short"
    assert text.truncate("a b c d", 2, unit="words") == "a b…"
    assert text.truncate("abc", 0) == ""
    assert op("$truncate", {"input": "abcdef", "length": 4,
                            "ellipsis": "."}) == "abc."
    with pytest.raises(ValueError, match="'length' is required"):
        op("$truncate", "abc")
    with pytest.raises(ValueError, match="'unit'"):
        text.truncate("abc", 2, unit="lines")


def test_highlight_wraps_whole_words_case_insensitively():
    assert text.highlight("Brake fault in brakes", "brake fault") == (
        "**Brake** **fault** in brakes")
    assert op("$highlight", {"input": "reset the ECU", "terms": ["the ecu"],
                             "pre": "<b>", "post": "</b>"}) == (
        "reset <b>the ECU</b>")
    assert text.highlight("a.b (c)", ["(c)"]) == "a.b **(c)**"
    assert text.highlight("abc", []) == "abc"
    assert text.highlight(None, "x") is None
    with pytest.raises(ValueError, match="'terms'"):
        text.highlight("a", 3)


def test_normalize_whitespace():
    assert op("$normalizeWhitespace", "  a​\t\n b  c  ") == "a b c"
    assert op("$normalizeWhitespace", None) is None


# ---- $bm25 ------------------------------------------------------------

CORPUS = [
    {"_id": 1, "text": "brake fault sensor out of range"},
    {"_id": 2, "text": "reset the ECU twice"},
    {"_id": 3, "text": "brake pads wear"},
    {"_id": 4},
]


def test_bm25_ranks_the_matching_documents_first_and_publishes():
    out, ctx = run("$bm25", {"query": "brake sensor", "publish": "corpus"},
                   CORPUS)
    assert [d["_id"] for d in out] == [1, 3, 2, 4]
    assert out[0]["score"] > out[1]["score"] > 0 == out[2]["score"]
    assert ctx.vars["corpus"]["n"] == 4
    assert set(ctx.vars["corpus"]["idf"]) == {"brake", "sensor"}
    assert ctx.vars["corpus"]["idf"]["sensor"] > ctx.vars["corpus"]["idf"][
        "brake"]


def test_bm25_on_nothing_and_without_sorting():
    out, _ = run("$bm25", {"query": "x"}, [])
    assert out == []
    out, _ = run("$bm25", {"query": ["reset"], "sort": False, "as": "s"},
                 CORPUS)
    assert [d["_id"] for d in out] == [1, 2, 3, 4] and out[1]["s"] > 0
    with pytest.raises(ValueError, match="'query' is required"):
        run("$bm25", {}, CORPUS)
    with pytest.raises(ValueError, match="never `_id`"):
        run("$bm25", {"query": "x", "as": "_id"}, CORPUS)
    with pytest.raises(ValueError, match="'b' must be at most 1"):
        run("$bm25", {"query": "x", "b": 2}, CORPUS)


# ---- $mmr -------------------------------------------------------------

def test_mmr_prefers_a_different_document_over_a_near_copy():
    docs = [{"_id": 1, "text": "brake fault sensor", "score": 3.0},
            {"_id": 2, "text": "brake fault sensor again", "score": 2.9},
            {"_id": 3, "text": "reset the ECU", "score": 2.8},
            {"_id": 4, "text": "unrelated", "score": 0.0}]
    out, _ = run("$mmr", {"k": 2, "lambda": 0.5, "score": "score",
                          "as": "pick"}, docs)
    assert [d["_id"] for d in out] == [1, 3]
    assert [d["pick"] for d in out] == [1, 2]
    only, _ = run("$mmr", {"k": 2, "lambda": 1.0, "score": "score"}, docs)
    assert [d["_id"] for d in only] == [1, 2]


def test_mmr_over_an_embedding_uses_cosine():
    docs = [{"_id": 1, "v": [1.0, 0.0]}, {"_id": 2, "v": [0.99, 0.1]},
            {"_id": 3, "v": [0.0, 1.0]}]
    out, _ = run("$mmr", {"k": 2, "lambda": 0.3, "embedding": "v",
                          "queryVector": [1.0, 0.0]}, docs)
    assert [d["_id"] for d in out] == [1, 3]
    assert rank.cosine([1, 0], [0, 0]) == 0.0
    with pytest.raises(ValueError, match="length"):
        rank.cosine([1], [1, 2])
    with pytest.raises(ValueError, match="queryVector"):
        run("$mmr", {"queryVector": [1.0]}, docs)


def test_mmr_on_fewer_documents_than_k_and_on_none():
    out, _ = run("$mmr", {"k": 10, "query": "brake"}, CORPUS)
    assert sorted(d["_id"] for d in out) == [1, 2, 3, 4]
    assert run("$mmr", {}, [])[0] == []
    with pytest.raises(ValueError, match="'lambda' must be at most 1"):
        run("$mmr", {"lambda": 1.5}, CORPUS)


# ---- $dedupe ----------------------------------------------------------

DUPES = [
    {"_id": 1, "text": "The brake fault means the sensor is out of range"},
    {"_id": 2, "text": "the  BRAKE fault means the sensor is out of range"},
    {"_id": 3, "text": "The brake fault means the sensor is out of range!"
                       " Check it"},
    {"_id": 4, "text": "Reset the ECU twice"},
    {"_id": 5},
    {"_id": 6, "text": ""},
]


def test_dedupe_drops_exact_and_near_copies_keeping_the_first():
    out, ctx = run("$dedupe", {"threshold": 0.7, "publish": "d"}, DUPES)
    assert [d["_id"] for d in out] == [1, 4, 5, 6]
    assert ctx.vars["d"] == {"kept": 4, "dropped": 2}
    exact, _ = run("$dedupe", {"method": "exact"}, DUPES)
    assert [d["_id"] for d in exact] == [1, 3, 4, 5, 6]


def test_minhash_estimates_the_same_decision_deterministically():
    out, _ = run("$dedupe", {"threshold": 0.7, "method": "minhash",
                             "permutations": 128}, DUPES)
    assert [d["_id"] for d in out] == [1, 4, 5, 6]
    a = rank.minhash(rank.shingles("a b c d e"), 16)
    assert a == rank.minhash(rank.shingles("a b c d e"), 16)
    assert rank.minhash(set(), 4) == rank.minhash(set(), 4)
    with pytest.raises(ValueError, match="'method'"):
        run("$dedupe", {"method": "simhash"}, DUPES)


# ---- $freshness -------------------------------------------------------

def test_freshness_halves_every_half_life():
    docs = [{"_id": 1, "at": NOW, "score": 2.0},
            {"_id": 2, "at": NOW - timedelta(days=7), "score": 2.0},
            {"_id": 3, "at": (NOW - timedelta(days=14)).isoformat()},
            {"_id": 4, "at": "not a date", "score": 1.0},
            {"_id": 5, "at": NOW + timedelta(days=3)},
            {"_id": 6, "at": datetime(2026, 8, 25)}]       # naive is UTC
    out, _ = run("$freshness", {"field": "at", "halfLife": "7d",
                                "multiply": "score"}, docs)
    f = {d["_id"]: d["freshness"] for d in out}
    assert f[1] == 1.0 and f[2] == 0.5 and f[3] == 0.25
    assert f[4] == 0.0 and f[5] == 1.0 and f[6] == 0.5
    s = {d["_id"]: d["score"] for d in out}
    assert s[2] == 1.0 and s[3] == 0.0 and s[4] == 0.0


def test_freshness_units_now_and_refusals():
    docs = [{"_id": 1, "at": NOW - timedelta(hours=12)}]
    out, _ = run("$freshness", {"field": "at", "halfLife": "12h"}, docs)
    assert out[0]["freshness"] == 0.5
    out, _ = run("$freshness", {"field": "at", "halfLife": 1,
                                "now": (NOW + timedelta(hours=12)).isoformat()},
                 docs)
    assert out[0]["freshness"] == 0.5
    for bad in (0, "-1d", "7w", "d", True):
        with pytest.raises(ValueError, match="halfLife"):
            run("$freshness", {"field": "at", "halfLife": bad}, docs)
    with pytest.raises(ValueError, match="'field' is required"):
        run("$freshness", {"halfLife": 1}, docs)


# ---- $rrf -------------------------------------------------------------

def test_rrf_fuses_ranks_not_scales():
    docs = [{"_id": 1, "bm25": 9.0, "vec": 0.1},
            {"_id": 2, "bm25": 1.0, "vec": 0.9},
            {"_id": 3, "bm25": 5.0, "vec": 0.5},
            {"_id": 4, "vec": 0.95}]
    # 4 has the best vector score and no bm25 at all; 1 is first in one
    # list and last in the other; 2 and 3 are second and third in both.
    out, _ = run("$rrf", {"fields": ["bm25", "$vec"]}, docs)
    assert [d["_id"] for d in out] == [1, 2, 3, 4]
    assert out[0]["rrf"] == round(1 / 61 + 1 / 64, 9)
    assert out[1]["rrf"] == out[2]["rrf"] > out[3]["rrf"] == round(1 / 61, 9)
    ranked, _ = run("$rrf", {"fields": ["r"], "ascending": ["r"]},
                    [{"_id": 1, "r": 2}, {"_id": 2, "r": 1}])
    assert [d["_id"] for d in ranked] == [2, 1]
    tie = rank.rrf_scores({"a": [1, 1, 0]}, k=0)
    assert tie == [1.0, 1.0, round(1 / 3, 9)]
    with pytest.raises(ValueError, match="'fields' is a non-empty list"):
        run("$rrf", {"fields": []}, docs)


# ---- $contextPack -----------------------------------------------------

def test_context_pack_keeps_until_the_budget_and_trims_the_last():
    docs = [{"_id": 1, "text": "a" * 40},        # 10 tokens
            {"_id": 2, "text": "b" * 40},        # 10
            {"_id": 3, "text": "c" * 400},       # 100
            {"_id": 4, "text": "d" * 4}]
    out, ctx = run("$contextPack", {"budget": 40}, docs)
    assert [d["_id"] for d in out] == [1, 2, 3]
    assert [d["truncated"] for d in out] == [False, False, True]
    assert text.token_estimate(out[2]["text"]) <= 20
    assert ctx.vars["context"] == {"used": 40, "budget": 40, "kept": 3,
                                   "dropped": 1, "truncated": 1}


def test_context_pack_without_trim_skip_and_given_tokens():
    docs = [{"_id": 1, "text": "x" * 400}, {"_id": 2, "text": "y" * 8}]
    out, ctx = run("$contextPack", {"budget": 10, "trim": False}, docs)
    assert out == [] and ctx.vars["context"]["dropped"] == 2
    out, _ = run("$contextPack", {"budget": 10, "trim": False, "skip": True},
                 docs)
    assert [d["_id"] for d in out] == [2]
    out, _ = run("$contextPack", {"budget": 5, "tokens": "n",
                                  "publish": "c"},
                 [{"_id": 1, "text": "x" * 400, "n": 3}, {"_id": 2}])
    assert [d["_id"] for d in out] == [1, 2]
    assert run("$contextPack", {"budget": 1}, [])[0] == []
    with pytest.raises(ValueError, match="'budget' is required"):
        run("$contextPack", {}, docs)


# ---- $cite and $stats -------------------------------------------------

def test_cite_numbers_sources_in_order_and_shares_a_number_per_key():
    docs = [{"_id": "a", "title": "Manual", "text": "1"},
            {"_id": "b", "url": "https://x.example/b", "text": "2"},
            {"_id": "a", "title": "Manual", "text": "3"},
            {"_id": {"k": 1}, "text": "4"}]
    out, ctx = run("$cite", {}, docs)
    assert [d["citation"] for d in out] == ["[1]", "[2]", "[1]", "[3]"]
    assert [d["citationId"] for d in out] == [1, 2, 1, 3]
    assert [d["source"] for d in out] == [
        "Manual", "https://x.example/b", "Manual", "{'k': 1}"]
    assert ctx.vars["citations"] == [
        {"id": 1, "marker": "[1]", "source": "Manual"},
        {"id": 2, "marker": "[2]", "source": "https://x.example/b"},
        {"id": 3, "marker": "[3]", "source": "{'k': 1}"}]


def test_stats_publishes_counts_and_changes_nothing():
    out, ctx = run("$stats", {"publish": "s"}, CORPUS)
    assert out == [dict(d) for d in CORPUS]
    s = ctx.vars["s"]
    assert s["n"] == 4 and s["missing"] == 1 and s["minWords"] == 0
    assert s["maxWords"] == 6 and s["words"] == 13
    assert run("$stats", {}, [])[1].vars["stats"]["n"] == 0


# ---- determinism ------------------------------------------------------

DETERMINISM = textwrap.dedent('''
    import json
    from voyd import contrib
    class Ctx:
        now = None
        vars = {}
        def publish(self, n, v): self.vars[n] = v
    docs = [{"_id": i, "text": t} for i, t in enumerate([
        "brake fault sensor", "brake fault sensor range", "reset ECU",
        "the pads wear", "brake pads wear out", "sensor range fault"])]
    c = Ctx()
    for name, args in [("$bm25", {"query": "brake sensor fault",
                                  "publish": "corpus"}),
                       ("$dedupe", {"method": "minhash", "threshold": 0.5}),
                       ("$mmr", {"k": 4, "score": "score"}),
                       ("$contextPack", {"budget": 12}),
                       ("$cite", {"key": "_id"})]:
        mod = next(m for m in contrib.MODULES.values() if name in m.NAMES)
        docs = list(mod.NAMES[name][1](args, docs, c))
    print(json.dumps([docs, c.vars], sort_keys=True, default=str))
''')


def test_the_same_pipeline_gives_the_same_bytes_under_any_hash_seed():
    outs = {subprocess.run([sys.executable, "-c", DETERMINISM], check=True,
                           capture_output=True, text=True,
                           env={"PYTHONHASHSEED": seed,
                                "PATH": "/usr/bin:/bin"}).stdout
            for seed in ("0", "1", "12345")}
    assert len(outs) == 1, outs


# ---- installing -------------------------------------------------------

def _voydfile(tmp_path, body):
    path = tmp_path / "voydfile.py"
    path.write_text(textwrap.dedent('''
        from voyd import guard, deadline
        @guard("notes")
        class Notes:
            expire_at = deadline()
    ''') + textwrap.dedent(body))
    return str(path)


def test_install_registers_through_the_public_decorators(tmp_path):
    load(_voydfile(tmp_path, "from voyd import contrib\ncontrib.install()\n"))
    assert set(OPERATORS) == set(text.NAMES)
    assert set(STAGES) == set(rank.NAMES) | set(context.NAMES)
    load(_voydfile(tmp_path, "from voyd.contrib import rank\n"
                             "rank.install('$bm25', '$mmr')\n"))
    assert set(STAGES) == {"$bm25", "$mmr"} and not OPERATORS


def test_installing_a_name_twice_fails_the_load(tmp_path):
    with pytest.raises(ValueError, match="declared twice"):
        load(_voydfile(tmp_path, "from voyd.contrib import text\n"
                                 "text.install()\ntext.install('$chunk')\n"))
    with pytest.raises(ValueError, match="declared twice"):
        load(_voydfile(tmp_path, textwrap.dedent('''
            from voyd import operator
            from voyd.contrib import text
            @operator("$wordCount")
            def mine(doc, args, ctx):
                return 0
            text.install()
        ''')))
    with pytest.raises(ValueError, match="has no"):
        load(_voydfile(tmp_path, "from voyd import contrib\n"
                                 "contrib.install('$summarize')\n"))


# ---- through the real split path --------------------------------------

def _virtuals():
    ops = {n: fn for n, (_, fn) in text.NAMES.items()}
    stages = {n: fn for m in (rank, context) for n, (_, fn) in m.NAMES.items()}
    return Virtuals(stages, ops)


def test_a_contrib_pipeline_is_handed_only_the_admitted_documents(guards):
    reply = serve(guards, [
        *PREFIX,
        {"$addFields": {"clean": {"$redactPII": "$text"}}},
        {"$bm25": {"query": "fault code ECU", "field": "clean",
                   "publish": "corpus"}},
        {"$dedupe": {"field": "clean"}},
        {"$contextPack": {"budget": 200, "field": "clean"}},
        {"$cite": {}},
        {"$stats": {"field": "clean"}},
    ], [LIVE, EXPIRED, REVOKED, INJECTED, LIVE2], virtuals=_virtuals())
    assert reply.get("ok") == 1.0, reply
    assert sorted(ids(reply)) == [1, 5]
    served = reply["cursor"]["firstBatch"]
    text_ = repr(served)
    for refused in ("last year's pricing", "AKIA", "Ignore all previous",
                    "globex", "123-45-6789"):
        assert refused not in text_, refused
    assert served[0]["_id"] == 1 and served[0]["citation"] == "[1]"
    assert all(d["ssn"] is None for d in served if "ssn" in d)


def test_a_batch_mixing_tenants_reaches_no_contrib_stage(guards):
    # The ordinary egress refuses the whole batch, so $stats publishes
    # nothing and nothing is ranked.
    reply = serve(guards, [*PREFIX, {"$bm25": {"query": "globex"}},
                           {"$stats": {}}],
                  [LIVE, GLOBEX], virtuals=_virtuals())
    assert ids(reply) == []


def test_a_contrib_stage_cannot_widen_the_read_it_ranks(guards):
    # $mmr with k larger than the admitted set returns what it was given:
    # two documents, never the five in the batch.
    reply = serve(guards, [*PREFIX, {"$mmr": {"k": 50, "query": "fault"}}],
                  [LIVE, EXPIRED, REVOKED, LIVE2], virtuals=_virtuals())
    assert sorted(ids(reply)) == [1, 5]


def test_a_bad_contrib_argument_is_an_error_the_driver_raises(guards):
    reply = serve(guards, [*PREFIX, {"$bm25": {"field": "text"}}],
                  [LIVE], virtuals=_virtuals())
    assert reply["ok"] == 0.0
    assert "'query' is required" in reply["errmsg"]


# ---- live -------------------------------------------------------------

LIVE_POLICY = """
from voyd import guard, deadline, revocable, tenant
from voyd import contrib

contrib.install()

@guard("notes")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()
"""


@pytest.mark.needs_mongo
def test_a_real_driver_runs_a_contrib_pipeline_through_a_real_boundary(
        boundary, direct, database):
    from pymongo import MongoClient

    from voyd.engine.time import now

    past = now() - timedelta(days=1)
    direct[database].notes.insert_many([
        {"_id": 1, "tenant_id": "acme", "title": "Brakes",
         "text": "Brake fault B1342: check the sensor. Mail ops@acme.example"},
        {"_id": 2, "tenant_id": "acme", "title": "Brakes copy",
         "text": "brake fault B1342: check the sensor. mail ops@acme.example"},
        {"_id": 3, "tenant_id": "acme", "text": "old brake fault notes",
         "expire_at": past},
        {"_id": 4, "tenant_id": "globex", "text": "globex brake fault"},
    ])
    tmp = f"{database}_tmp"
    try:
        wire = boundary(LIVE_POLICY, "--virtual-db", tmp)
        with MongoClient(wire.uri, serverSelectionTimeoutMS=10_000) as c:
            out = list(c[database].notes.aggregate([
                {"$match": {"tenant_id": "acme"}},
                {"$addFields": {"text": {"$redactPII": "$text"}}},
                {"$bm25": {"query": "brake sensor", "publish": "corpus"}},
                {"$dedupe": {}},
                {"$cite": {}},
                {"$addFields": {"n": "$$corpus.n"}},
                {"$project": {"text": 1, "citation": 1, "source": 1, "n": 1}},
            ]))
        assert [d["_id"] for d in out] == [1]
        assert out[0]["citation"] == "[1]" and out[0]["source"] == "Brakes"
        assert "[email]" in out[0]["text"] and out[0]["n"] == 2
        assert direct[tmp].list_collection_names() == []
    finally:
        direct.drop_database(tmp)
