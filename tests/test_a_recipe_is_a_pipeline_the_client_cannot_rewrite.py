"""A recipe is a pipeline the client names and cannot rewrite.

    @recipe("support_context", collection="tickets")
    def support_context(q: str = "refund", k: int = 8): ...

    db.tickets.aggregate([{$recipe: {name: "support_context",
                                     params: {q: "refund", k: 5}}}])

The claims under test:

    Expansion happens first, and what follows cannot tell it from a
    pipeline written by hand.

Asserted as bytes: the expanded message *is* the hand-written aggregate.
Then each downstream decision -- the masked-reference refusal, the
derived-read push-down, the virtual split, the backfill -- is run on the
expansion and shown to do what it does to a hand-written pipeline, and
`proxy.py` is read to show the expansion comes before all of them.

    A parameter is a value, never code.

Wrong types, documents, `$`-strings, unknown and missing names are refused
at the gate; a parameter that changes a name, an operator or a field path
is refused after the call.

    `recipes_only=True` leaves the recipe as the one way to read.

And load-time validation, the plan diff, and the version hash.

Pure: no cluster. The live half is at the bottom and needs one.
"""

from __future__ import annotations

import textwrap
from datetime import datetime, timedelta, timezone

import bson
import pytest

from voyd.declare import (OPERATORS, OPTIONS, RECIPES, REGISTRY, STAGES,
                          TRANSFORMS, load)
from voyd.engine.plan import (RECIPE_ADDED, RECIPE_CHANGED, RECIPE_REMOVED,
                              RECIPES_ONLY_ADDED, RECIPES_ONLY_REMOVED,
                              structural)
from voyd.wire.codec import decode_sections, encode_op_msg, encode_sections
from voyd.wire.policy import (Backfill, Guard, Virtuals, expand_recipe,
                              refuse_masked_reference, rewrite_derived_read,
                              split_virtual)

UTC = timezone.utc

POLICY = """
from voyd import guard, deadline, revocable, tenant, mask, recipe, operator

@guard("tickets")
class Tickets:
    expire_at = deadline()
    forgotten = revocable()
    ssn       = mask()

@guard("vault", recipes_only=True)
class Vault:
    expire_at = deadline()

@guard("notes")
class Notes:
    expire_at = deadline()

@operator("$redactPII")
def redact(doc, args, ctx):
    return str(args).replace("@", "[at]")

@recipe("support_context", collection="tickets")
def support_context(q: str = "refund", k: int = 8):
    return [
        {"$vectorSearch": {"index": "v", "path": "embedding", "query": q,
                           "numCandidates": k * 10, "limit": k}},
    ]

@recipe("cleaned", collection="tickets")
def cleaned(q: str = "refund"):
    return [{"$match": {"text": q}},
            {"$addFields": {"clean": {"$redactPII": "$text"}}}]

@recipe("by_ssn", collection="tickets")
def by_ssn():
    return [{"$group": {"_id": "$ssn"}}]

@recipe("how_many", collection="tickets")
def how_many(q: str = "refund"):
    return [{"$match": {"text": q}}, {"$count": "n"}]

@recipe("typed", collection="tickets",
        samples=[{"q": "x"}, {"q": "x", "owner": "o"}])
def typed(q: str, k: int = 3, score: float = 0.5, strict: bool = False,
          tags: list[str] = ["a"], owner: str | None = None):
    m = {"text": q, "k": k, "score": score, "strict": strict,
         "tags": {"$in": tags}}
    if owner is not None:
        m["owner"] = owner
    return [{"$match": m}]

@recipe("by_field", collection="tickets", samples=[{"field": "text"}])
def by_field(field: str, q: str = "x"):
    return [{"$match": {field: q}}]

@recipe("by_path", collection="tickets", samples=[{"field": "text"}])
def by_path(field: str):
    return [{"$project": {"out": "$" + field}}]

@recipe("vault_read", collection="vault")
def vault_read(id: str = "000000000000000000000000"):
    return [{"$match": {"$expr": {"$eq": ["$_id",
                                          {"$toObjectId": id}]}}}]

@recipe("joins_vault", collection="notes")
def joins_vault():
    return [{"$unionWith": "vault"}]
"""


@pytest.fixture(autouse=True)
def _clean_registry():
    tables = (REGISTRY, OPTIONS, TRANSFORMS, STAGES, OPERATORS, RECIPES)
    for table in tables:
        table.clear()
    yield
    for table in tables:
        table.clear()


def _load(tmp_path, text=POLICY, name="voydfile"):
    # A stem, not a filename, so the call sites do not read as citations.
    path = tmp_path / f"{name}.py"
    path.write_text(textwrap.dedent(text))
    return load(str(path))


@pytest.fixture
def guards(tmp_path):
    return {n: Guard(s) for n, s in _load(tmp_path).items()}


def call(collection, name, params=None, *rest, **extra):
    spec = {"name": name}
    if params is not None:
        spec["params"] = params
    return {"aggregate": collection,
            "pipeline": [{"$recipe": spec}, *rest],
            "cursor": {}, **extra, "$db": "app"}


def wire(body, req_id=7):
    return encode_op_msg(req_id, 0, 0, body)


def expand(guards, body):
    return expand_recipe(wire(body), 7, 0, guards, False)


def body_of(raw):
    return decode_sections(raw)[1]


def errmsg(refusal):
    got = bson.decode(refusal[21:])
    assert got["ok"] == 0.0
    return got["errmsg"]


def refused(guards, body, match):
    out, refusal = expand(guards, body)
    assert out is None and refusal is not None, body
    assert match in errmsg(refusal), errmsg(refusal)


# ---- expansion is first, and indistinguishable ---------------------------

def test_the_expansion_is_byte_for_byte_the_pipeline_written_by_hand(guards):
    out, refusal = expand(guards, call("tickets", "support_context",
                                       {"q": "late refund", "k": 5}))
    assert refusal is None
    by_hand = {"aggregate": "tickets", "pipeline": [
        {"$vectorSearch": {"index": "v", "path": "embedding",
                           "query": "late refund", "numCandidates": 50,
                           "limit": 5}}], "cursor": {}, "$db": "app"}
    assert out == encode_sections(7, 0, 0, by_hand)
    assert guards["tickets"].recipe_reads == {"support_context": 1}


def test_defaults_fill_what_the_client_did_not_send(guards):
    out, _ = expand(guards, call("tickets", "support_context"))
    stage = body_of(out)["pipeline"][0]["$vectorSearch"]
    assert stage["query"] == "refund" and stage["limit"] == 8


def test_the_expansion_runs_before_every_other_decision_in_the_pump():
    import pathlib

    proxy = pathlib.Path("voyd/wire/proxy.py").read_text()
    first = proxy.index("expand_recipe(raw")
    for later in ("_wants_a_caller(guards, body)", "refuse_scratch(body",
                  "refuse_unrewritable(raw", "refuse_change_stream(raw",
                  "refuse_masked_reference(", "refuse_client_vector(raw",
                  "split_virtual(body", "rewrite_derived_read(",
                  "rewrite_vector_search(", "backfill.widen("):
        assert first < proxy.index(later), later


def test_a_masked_field_in_a_recipe_is_refused_like_a_hand_written_one(
        guards):
    out, _ = expand(guards, call("tickets", "by_ssn"))
    refusal = refuse_masked_reference(out, 7, guards, False)
    assert refusal is not None and "masked" in errmsg(refusal)


def test_a_reducing_recipe_gets_the_refusal_pushed_into_its_query(guards):
    out, _ = expand(guards, call("tickets", "how_many", {"q": "late"}))
    pushed, refusal = rewrite_derived_read(out, 7, 0, guards, False)
    assert refusal is None and pushed is not None
    stages = body_of(pushed)["pipeline"]
    # The rules went in ahead of the reduction, as they would by hand.
    assert "$match" in stages[0] and stages[-1] == {"$count": "n"}
    assert len(stages) > 2


def test_a_virtual_operator_in_a_recipe_is_split_like_a_hand_written_one(
        guards):
    out, _ = expand(guards, call("tickets", "cleaned"))
    virtuals = Virtuals({}, dict(OPERATORS), database="tmp")
    read, refusal = split_virtual(body_of(out), 7, guards, virtuals)
    assert refusal is None and read is not None


def test_a_lone_vector_search_recipe_is_backfilled_like_a_hand_written_one(
        guards):
    out, _ = expand(guards, call("tickets", "support_context", {"k": 5}))
    widened = Backfill().widen(body_of(out), guards, 7)
    assert widened is not None
    assert widened["pipeline"][0]["$vectorSearch"]["limit"] > 5


# ---- parameters are data -------------------------------------------------

@pytest.mark.parametrize("params, match", [
    ({"q": "$$ROOT"}, "begins with '$'"),
    ({"q": "$ssn"}, "begins with '$'"),
    ({"q": {"$where": "sleep(1000)"}}, "expects str, got dict"),
    ({"q": {"$gt": ""}}, "expects str, got dict"),
    ({"q": ["refund"]}, "expects str, got list"),
    ({"k": "5"}, "expects int, got str"),
    ({"k": True}, "expects int, got bool"),
    ({"k": 5.5}, "expects int, got float"),
    ({"k": None}, "is null"),
    ({"limit": 3}, "unknown parameter 'limit'"),
])
def test_a_parameter_that_is_not_a_declared_value_is_refused(
        guards, params, match):
    refused(guards, call("tickets", "support_context", params), match)


def test_every_declared_type_is_accepted_and_checked(guards):
    out, refusal = expand(guards, call("tickets", "typed", {
        "q": "x", "k": bson.Int64(4), "score": 1, "strict": True,
        "tags": ["b", "c"], "owner": "ann"}))
    assert refusal is None
    match = body_of(out)["pipeline"][0]["$match"]
    assert match["score"] == 1.0 and isinstance(match["score"], float)
    assert match["tags"] == {"$in": ["b", "c"]} and match["owner"] == "ann"
    refused(guards, call("tickets", "typed", {}), "missing parameter 'q'")
    refused(guards, call("tickets", "typed", {"q": "x", "tags": ["$x"]}),
            "begins with '$'")
    refused(guards, call("tickets", "typed", {"q": "x", "tags": [1]}),
            "expects list[str]")
    refused(guards, call("tickets", "typed", {"q": "x", "strict": 1}),
            "expects bool")
    refused(guards, call("tickets", "support_context", ["q"]),
            "params must be a document")


def test_a_parameter_may_change_a_value_but_never_a_name(guards):
    # The declared sample produced `text`, so `text` is a name this recipe
    # is known to use. `ssn` is not, whichever way it would arrive.
    assert expand(guards, call("tickets", "by_field",
                               {"field": "text", "q": "y"}))[1] is None
    refused(guards, call("tickets", "by_field", {"field": "ssn"}),
            "never a name")
    assert expand(guards, call("tickets", "by_path",
                               {"field": "text"}))[1] is None
    refused(guards, call("tickets", "by_path", {"field": "ssn"}),
            "'$ssn'")
    refused(guards, call("tickets", "by_path", {"field": "$ROOT"}),
            "begins with '$'")


# ---- the call's shape ----------------------------------------------------

def test_only_limit_and_skip_may_follow_a_recipe(guards):
    out, refusal = expand(guards, call("tickets", "cleaned", None,
                                       {"$skip": 1}, {"$limit": 2}))
    assert refusal is None
    assert body_of(out)["pipeline"][-2:] == [{"$skip": 1}, {"$limit": 2}]
    for tail in ({"$project": {"ssn": 1}}, {"$limit": 0}, {"$limit": True},
                 {"$group": {"_id": "$ssn"}}, {"$recipe": {"name": "x"}}):
        refused(guards, call("tickets", "cleaned", None, tail),
                "may follow a $recipe")


def test_a_recipe_anywhere_but_first_is_refused(guards):
    refused(guards, {"aggregate": "tickets", "cursor": {}, "pipeline": [
        {"$match": {}}, {"$recipe": {"name": "cleaned"}}]}, "first stage")


def test_the_collection_must_be_the_one_the_recipe_declares(guards):
    refused(guards, call("notes", "cleaned"), "reads 'tickets', not 'notes'")
    refused(guards, call(1, "cleaned"), "not 'this database'")


def test_a_call_carrying_variables_or_asking_for_a_plan_is_refused(guards):
    refused(guards, call("tickets", "cleaned", let={"x": 1}), "'let'")
    refused(guards, {"explain": call("tickets", "cleaned"), "$db": "app"},
            "not explained")
    refused(guards, call("tickets", "nope"), "no recipe is named 'nope'")
    refused(guards, {"aggregate": "tickets", "cursor": {}, "pipeline": [
        {"$recipe": {"name": "cleaned", "extra": 1}}]}, "nothing else")


def test_a_message_with_no_recipe_in_it_is_left_alone(guards):
    for body in ({"find": "tickets", "filter": {}},
                 {"aggregate": "tickets", "pipeline": [{"$match": {}}]},
                 {"insert": "vault", "documents": [{"a": 1}]},
                 {"getMore": bson.Int64(5), "collection": "vault"},
                 {"hello": 1}):
        assert expand(guards, body) == (None, None), body


# ---- recipes_only --------------------------------------------------------

@pytest.mark.parametrize("body", [
    {"find": "vault", "filter": {}},
    {"find": "vault", "filter": {"_id": 1}, "limit": 1},
    {"aggregate": "vault", "pipeline": [{"$match": {}}], "cursor": {}},
    {"count": "vault"},
    {"distinct": "vault", "key": "a"},
    {"explain": {"find": "vault", "filter": {}}},
    {"aggregate": "notes", "cursor": {}, "pipeline": [
        {"$lookup": {"from": "vault", "as": "v", "pipeline": []}}]},
    {"aggregate": "notes", "cursor": {}, "pipeline": [
        {"$facet": {"a": [{"$unionWith": {"coll": "vault"}}]}}]},
    {"aggregate": 1, "cursor": {}, "pipeline": [
        {"$documents": [{}]}, {"$unionWith": "vault"}]},
])
def test_recipes_only_refuses_every_read_that_is_not_a_recipe(guards, body):
    refused(guards, {**body, "$db": "app"}, "recipes_only")


def test_recipes_only_still_serves_its_recipes_and_its_writes(guards):
    assert expand(guards, call("vault", "vault_read"))[1] is None
    # A recipe on another collection may read it: that read is reviewed.
    assert expand(guards, call("notes", "joins_vault"))[1] is None
    assert expand(guards, {"insert": "vault", "documents": []}) == (None,
                                                                     None)


# ---- load time -----------------------------------------------------------

GUARD = """
from voyd import guard, deadline, recipe
@guard("t")
class T:
    expire_at = deadline()
"""


@pytest.mark.parametrize("body, match", [
    ('@recipe("a", collection="t")\ndef a(): return []\n'
     '@recipe("a", collection="t")\ndef b(): return []', "declared twice"),
    ('recipe("a", collection="t")(42)', "cannot be called"),
    ('@recipe("a", collection="t")\ndef a(q): return []', "must be annotated"),
    ('@recipe("a", collection="t")\ndef a(q: dict = {}): return []',
     "must be annotated"),
    ('@recipe("a", collection="t")\ndef a(*q: str): return []', "Name each"),
    ('@recipe("a", collection="t")\ndef a(k: int = "x"): return []',
     "default is invalid"),
    ('@recipe("a", collection="t")\ndef a(q: str): return []',
     "no default and no value"),
    ('@recipe("a", collection="t", samples={"q": "$x"})\n'
     'def a(q: str): return []', "begins with '$'"),
    ('@recipe("a", collection="t")\ndef a(): return {"$match": {}}',
     "not a list of stages"),
    ('@recipe("a", collection="t")\ndef a(): return [{"$out": "x"}]',
     "$out"),
    ('@recipe("a", collection="t")\ndef a(): return [{"$merge": "x"}]',
     "$merge"),
    ('@recipe("a", collection="t")\n'
     'def a(): return [{"$match": {"$where": "1"}}]', "JavaScript"),
    ('@recipe("a", collection="t")\ndef a(): return [{"$bogus": {}}]',
     "neither a MongoDB stage"),
    ('@recipe("a", collection="t")\ndef a(): return [{"$match": {}, '
     '"$limit": 1}]', "one-key"),
    ('@recipe("a", collection="t")\ndef a(): raise RuntimeError("no")',
     "RuntimeError"),
    ('@recipe("a", collection="elsewhere")\ndef a(): return []',
     "has no @guard"),
    ('@recipe("$a", collection="t")\ndef a(): return []', "plain"),
])
def test_a_policy_file_with_a_bad_recipe_fails_at_load(tmp_path, body,
                                                       match):
    with pytest.raises((ValueError, TypeError), match=match.replace(
            "$", r"\$").replace("(", r"\(")):
        _load(tmp_path, GUARD + body)


def test_recipes_only_with_no_recipe_is_a_collection_nothing_can_read(
        tmp_path):
    with pytest.raises(ValueError, match="nothing can read"):
        _load(tmp_path, GUARD.replace('@guard("t")',
                                      '@guard("t", recipes_only=True)'))


def test_a_recipe_declared_above_its_guard_still_belongs_to_it(tmp_path):
    specs = _load(tmp_path, """
from voyd import guard, deadline, recipe
@recipe("early", collection="t")
def early(): return []
@guard("t")
class T:
    expire_at = deadline()
@recipe("late", collection="t")
def late(): return []
""")
    assert [r.name for r in specs["t"].recipes] == ["early", "late"]
    assert "recipes [early@" in specs["t"].describe()


# ---- the plan, and the version -------------------------------------------

def _two(tmp_path, before, after):
    was = _load(tmp_path, before, "current")
    now = _load(tmp_path, after, "proposed")
    return {(s.kind, s.fails_open) for s in structural(was, now)}, was, now


BASE = GUARD + '\n@recipe("a", collection="t")\ndef a(k: int = 3):\n' \
    '    return [{"$limit": k}]\n'


def test_a_recipe_change_is_a_structural_finding_in_the_plan(tmp_path):
    kinds, was, now = _two(tmp_path, BASE, BASE.replace("k: int = 3",
                                                        "k: int = 4"))
    assert kinds == {(RECIPE_CHANGED, False)}
    assert was["t"].recipes[0].version != now["t"].recipes[0].version
    kinds, *_ = _two(tmp_path, GUARD, BASE)
    assert kinds == {(RECIPE_ADDED, False)}
    kinds, *_ = _two(tmp_path, BASE, GUARD)
    assert kinds == {(RECIPE_REMOVED, False)}
    kinds, *_ = _two(tmp_path, BASE, BASE)
    assert kinds == set()


def test_lifting_recipes_only_fails_open(tmp_path):
    only = BASE.replace('@guard("t")', '@guard("t", recipes_only=True)')
    kinds, *_ = _two(tmp_path, only, BASE)
    assert kinds == {(RECIPES_ONLY_REMOVED, True)}
    kinds, *_ = _two(tmp_path, BASE, only)
    assert kinds == {(RECIPES_ONLY_ADDED, False)}


def test_the_version_is_stable_and_is_what_the_metrics_report(tmp_path):
    from voyd.wire.metrics import Layout, Meter, Slab, render

    one = _load(tmp_path, BASE, "a")["t"].recipes[0].version
    two = _load(tmp_path, BASE, "b")["t"].recipes[0].version
    assert one == two and len(one) == 12
    guard = Guard(_load(tmp_path, BASE, "c")["t"])
    out, _ = expand_recipe(wire(call("t", "a")), 7, 0, {"t": guard}, False)
    assert out is not None
    layout = Layout(("t",), recipes=(("t", "a", one),))
    slab = Slab(1, layout)
    Meter(layout, slab, 0).flush({"t": guard})
    text = render(slab).decode()
    assert (f'voyd_recipe_reads_total{{collection="t",recipe="a",'
            f'version="{one}"}} 1') in text


# ---- a real driver, a real boundary --------------------------------------

LIVE_POLICY = """
from voyd import guard, deadline, revocable, tenant, mask, recipe, operator

@guard("tickets", recipes_only=True)
class Tickets:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()
    ssn       = mask()

@operator("$shout")
def shout(doc, args, ctx):
    return str(args).upper()

@recipe("support_context", collection="tickets")
def support_context(tenant: str = "acme", q: str = "refund", k: int = 5):
    return [{"$match": {"tenant_id": tenant, "text": {"$regex": q}}},
            {"$sort": {"_id": 1}}, {"$limit": k}]

@recipe("loud", collection="tickets")
def loud(tenant: str = "acme"):
    return [{"$match": {"tenant_id": tenant}},
            {"$addFields": {"loud": {"$shout": "$text"}}}]

@recipe("how_many", collection="tickets")
def how_many(tenant: str = "acme"):
    return [{"$match": {"tenant_id": tenant}}, {"$count": "n"}]

@recipe("ssn_groups", collection="tickets")
def ssn_groups():
    return [{"$group": {"_id": "$ssn"}}]
"""


@pytest.fixture
def live(boundary, database, direct, tmp_path):
    from pymongo import MongoClient

    past = datetime.now(UTC) - timedelta(days=1)
    direct[database].tickets.insert_many([
        {"_id": 1, "tenant_id": "acme", "text": "refund late",
         "ssn": "123-45-6789"},
        {"_id": 2, "tenant_id": "acme", "text": "refund expired",
         "expire_at": past},
        {"_id": 3, "tenant_id": "acme", "text": "refund revoked",
         "forgotten": {"at": past, "reason": "leaked"}},
        {"_id": 4, "tenant_id": "globex", "text": "refund globex"},
        {"_id": 5, "tenant_id": "acme", "text": "refund second"},
    ])
    wire_ = boundary(LIVE_POLICY, "--virtual-db", f"{database}_tmp")
    client = MongoClient(wire_.uri, serverSelectionTimeoutMS=15_000)
    try:
        yield client[database].tickets
    finally:
        client.close()
        direct.drop_database(f"{database}_tmp")


def recipe_call(name, **params):
    return [{"$recipe": {"name": name, "params": params}}]


@pytest.mark.needs_mongo
def test_pymongo_reads_through_a_recipe_and_gets_every_guarantee(live):
    got = list(live.aggregate(recipe_call("support_context", q="refund")))
    assert [d["_id"] for d in got] == [1, 5]
    assert got[0]["ssn"] is None and "123" not in str(got)
    got = list(live.aggregate(recipe_call("support_context", k=1)))
    assert [d["_id"] for d in got] == [1]
    # Through a virtual operator, on admitted rows only.
    got = list(live.aggregate(recipe_call("loud")))
    assert sorted(d["loud"] for d in got) == ["REFUND LATE", "REFUND SECOND"]
    # A reduction gets the rules pushed into it: 2, not 4.
    assert list(live.aggregate(recipe_call("how_many"))) == [{"n": 2}]


@pytest.mark.needs_mongo
def test_pymongo_is_refused_an_injection_and_an_ad_hoc_read(live):
    from pymongo.errors import OperationFailure

    for params, match in (({"q": "$$ROOT"}, "begins with"),
                          ({"q": {"$where": "1"}}, "expects str"),
                          ({"nope": 1}, "unknown parameter")):
        with pytest.raises(OperationFailure, match=match):
            list(live.aggregate(recipe_call("support_context", **params)))
    with pytest.raises(OperationFailure, match="masked field"):
        list(live.aggregate(recipe_call("ssn_groups")))
    for attempt in (lambda: list(live.find({})),
                    lambda: live.find_one({"_id": 1}),
                    lambda: list(live.aggregate([{"$match": {}}])),
                    lambda: live.count_documents({}),
                    lambda: live.distinct("text")):
        with pytest.raises(OperationFailure, match="recipes_only"):
            attempt()
    # Writes are not retrieval, and still go through.
    live.insert_one({"_id": 9, "tenant_id": "acme", "text": "new"})
