"""What a message is allowed to mean, asked one decision at a time.

The rest of the suite reaches these through a socket, which proves they
work together and is a poor way to find out *which* of them is wrong. These
are the decisions themselves: a body in, a verdict out, no server, no
driver, no bytes on a wire except where the decision is about bytes.

Four kinds, which is the file's own account of itself:

    refuse a document   `Guard` judging a batch, whatever produced it
    rewrite a command   a delete that becomes the revocation it should
                        have been, a projection pushed into a query, a
                        `hello` that stops advertising a way around
    refuse a command    the verbs no rewrite is narrow enough to cover
    carry state         a cumulative rule spans a read; the boundary is
                        handed a batch, and the client picks how many

The projection cases get the most room here, and deliberately. Every other
decision refuses something visible; that one decides whether the verdict
can be *read at all*, and `find({}, {"text": 1})` is the most ordinary
query anybody writes.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone


from voyd.engine import Budget, Clearance, Deadline, Distinct, revoked
from voyd.engine.admission import AdmissionSpec
from voyd.wire.codec import (decode_op_msg, decode_sections,
                             encode_op_msg, encode_sections)
from voyd.wire.policy import (DERIVED_COMMANDS, EXFILTRATING_STAGES,
                              SUPPLIABLE_CLAIMS, UNREWRITABLE, Budgets, Guard,
                              blinded_find, blinds_a_subject,
                              client_vector_on_server_index, deciding_fields,
                              delete_reply, expressible_clauses, guard_for,
                              pins_the_tenant, projection_blinds,
                              reducing_stage, revoke_instead_of_delete,
                              rewrite_topology, strip_compression,
                              unsuppliable_claims, writes_elsewhere)

UTC = timezone.utc
PAST = datetime.now(UTC) - timedelta(hours=1)
FUTURE = datetime.now(UTC) + timedelta(days=1)


def notes(*rules, tenant=None, subjects=None, subject_key=None,
          on_delete="forward", collection="notes", **kw) -> Guard:
    spec = AdmissionSpec(collection, rules=tuple(rules) or
                         (Deadline("expire_at"), revoked("forgotten")),
                         tenant=tenant, subjects=subjects,
                         subject_key=subject_key, **kw)
    return Guard(spec, on_delete=on_delete)


# ---- refuse a document -------------------------------------------------

def test_a_guard_judges_a_batch_whatever_produced_it():
    # No database, no query, no index -- which is the property that lets
    # this run on a wire. A `$vectorSearch` hit passed through no filter.
    guard = notes()
    kept = guard.filter([
        {"_id": "live", "expire_at": FUTURE},
        {"_id": "gone", "expire_at": PAST},
        {"_id": "revoked", "forgotten": {"at": PAST}},
    ])
    assert [d["_id"] for d in kept] == ["live"]
    assert guard.admitted == 1 and guard.refused == 2
    assert guard.reasons() == {"deadline": 1, "revoked": 1}


def test_a_guard_takes_the_scope_from_the_batch_it_was_handed():
    # The proxy has no filter to read a tenant from, so it reads the batch:
    # every document in a cursor batch came from one query.
    guard = notes(Deadline("expire_at"), tenant="tenant_id")
    kept = guard.filter([{"_id": "a", "tenant_id": "acme"},
                         {"_id": "b", "tenant_id": "acme"}])
    assert [d["_id"] for d in kept] == ["a", "b"]

    # A batch carrying two tenants is already the leak, so none of it is
    # in scope and `off_scope` is what says so.
    mixed = notes(Deadline("expire_at"), tenant="tenant_id")
    assert mixed.filter([{"_id": "a", "tenant_id": "acme"},
                         {"_id": "b", "tenant_id": "globex"}]) == []
    assert mixed.reasons().get("off_scope") == 2


def test_one_guard_is_shared_by_every_connection_so_a_caller_is_not_bound():
    # `for_caller` clones rather than assigns. Binding onto the shared
    # handle would show one client's rows to whoever asked second, which
    # is the concurrency bug this package exists to be careful about,
    # committed by its own plumbing.
    rule = Clearance(order=("public", "secret"),
                     roles=(("analyst", "public"),), claim="roles")
    guard = notes(rule)
    docs = [{"_id": "p", "classification": "public"},
            {"_id": "s", "classification": "secret"}]
    low = guard.filter(list(docs), caller={"roles": ["analyst"]})
    assert [d["_id"] for d in low] == ["p"]
    # The next caller is judged on their own claims, not the last one's.
    high = guard.filter(list(docs), caller={"roles": ["chief"]})
    assert high == []
    assert guard.handle is not None


def test_an_unknown_caller_is_refused_by_the_rules_not_waved_past():
    rule = Clearance(order=("public", "secret"),
                     roles=(("analyst", "public"),), claim="roles")
    assert notes(rule).filter([{"classification": "public"}],
                              caller=None) == []


def test_a_guard_says_whether_it_needs_a_caller_or_a_running_total():
    assert notes().needs_caller is False
    assert notes().cumulative is False
    assert notes(Clearance(order=("a",))).needs_caller is True
    assert notes(Budget(limit=10)).cumulative is True
    assert notes(Distinct(on="chunk")).cumulative is True


def test_the_default_guard_is_still_a_complete_thing_to_type():
    # `--guard notes` with no policy file: the obvious two rules.
    guard = Guard.defaults("notes", at_field="ttl", mark_field="gone")
    assert [d["_id"] for d in guard.filter([
        {"_id": "a"}, {"_id": "b", "ttl": PAST},
        {"_id": "c", "gone": {"at": PAST}}])] == ["a"]


# ---- carry state a rule needs across messages --------------------------

def test_a_budget_spans_the_cursor_rather_than_restarting_per_batch():
    # The client picks how many batches a read arrives in, so a fresh tab
    # per batch is a hole, not an inefficiency: `batchSize=1` would admit
    # the whole collection one document at a time.
    guard = notes(Budget(limit=10, cost_field="tokens"))
    budgets = Budgets()
    tab = budgets.tab_for(guard, cursor_id=42)
    first = guard.filter([{"_id": "a", "tokens": 6}], tab=tab)
    second = guard.filter([{"_id": "b", "tokens": 6}], tab=tab)
    assert [d["_id"] for d in first] == ["a"]
    assert second == [], "the budget restarted on the second batch"


def test_a_page_is_only_cumulative_where_a_rule_asked_for_it():
    # A guard with no cumulative rule must not pay for per-read state.
    assert notes().cumulative is False


# ---- rewrite a command -------------------------------------------------

def test_a_delete_becomes_the_revocation_it_should_have_been():
    guard = notes(Deadline("expire_at"), revoked("forgotten"),
                  on_delete="revoke")
    raw = encode_sections(7, 0, 0, {"delete": "notes", "$db": "app"},
                          "deletes", [{"q": {"_id": 1}, "limit": 1}])
    rewritten = revoke_instead_of_delete(raw, 7, 0, guard, False)
    assert rewritten is not None
    _, body, ident, updates = decode_sections(rewritten)
    # An update, not a delete, and it writes the mark the policy declared
    # into the document sequence beside the body.
    assert body["update"] == "notes" and "delete" not in body
    assert ident == "updates"
    assert "forgotten" in str(updates)


def test_a_delete_is_left_alone_where_the_policy_did_not_ask():
    guard = notes(Deadline("expire_at"), revoked("forgotten"),
                  on_delete="revoke")
    # A command naming a different collection is not this guard's
    # business, however the policy declared this one.
    raw = encode_sections(7, 0, 0, {"delete": "other", "$db": "app"},
                          "deletes", [{"q": {}, "limit": 1}])
    assert revoke_instead_of_delete(raw, 7, 0, guard, False) is None
    # And a guard with no mark to write has nothing to rewrite into, so
    # the real delete is forwarded.
    plain = notes(Deadline("expire_at"), on_delete="revoke")
    raw2 = encode_sections(7, 0, 0, {"delete": "notes", "$db": "app"},
                           "deletes", [{"q": {}, "limit": 1}])
    assert revoke_instead_of_delete(raw2, 7, 0, plain, False) is None


def test_an_update_reply_is_handed_back_in_the_shape_the_client_asked_for():
    # The driver issued a delete and is entitled to a delete's reply. An
    # `nModified` it never asked for is true about the proxy and confusing
    # about its own call.
    raw = encode_op_msg(1, 7, 0, {"ok": 1.0, "n": 1, "nModified": 1})
    _, reply = decode_op_msg(delete_reply(raw, 1, 7))
    assert reply == {"ok": 1.0, "n": 1}
    # Anything without it is passed through byte for byte.
    plain = encode_op_msg(1, 7, 0, {"ok": 1.0, "n": 1})
    assert delete_reply(plain, 1, 7) == plain


def test_a_hello_stops_advertising_the_way_around_this_process():
    reply = {"maxWireVersion": 21, "isWritablePrimary": True,
             "hosts": ["node1:27017", "node2:27017"],
             "passives": ["p:27017"], "arbiters": ["a:27017"],
             "me": "node1:27017", "primary": "node1:27017",
             "setName": "rs0"}
    out = rewrite_topology(encode_op_msg(1, 2, 0, reply), 1, 2, "127.0.0.1:27099")
    assert out is not None
    _, got = decode_op_msg(out)
    assert got["hosts"] == ["127.0.0.1:27099"]
    assert got["me"] == got["primary"] == "127.0.0.1:27099"
    assert got["passives"] == [] and got["arbiters"] == []
    # Kept: stripping it makes a driver treat this as a standalone, which
    # silently disables retryable writes.
    assert got["setName"] == "rs0"
    # Passed through: this flag is how a driver notices a failover, and a
    # boundary that lies about writability has made itself the outage.
    assert got["isWritablePrimary"] is True


def test_a_hello_from_a_node_that_lost_the_primary_is_not_told_it_has_one():
    reply = {"maxWireVersion": 21, "isWritablePrimary": False,
             "secondary": True, "hosts": ["node1:27017"], "me": "node1:27017",
             "setName": "rs0"}
    _, got = decode_op_msg(
        rewrite_topology(encode_op_msg(1, 2, 0, reply), 1, 2, "here:1"))
    assert got["isWritablePrimary"] is False and got["secondary"] is True
    assert "primary" not in got


def test_a_message_that_is_not_a_hello_is_not_re_encoded_at_all():
    # The guarantee is the `out == reply` comparison, not the fast path:
    # nothing is re-encoded unless a field actually changed.
    for body in ({"ok": 1.0, "cursor": {"id": 0, "ns": "a.b"}},
                 {"maxWireVersion": 21, "setName": "rs0"},
                 {"hosts": ["x:1"]}):
        raw = encode_op_msg(1, 2, 0, body)
        assert rewrite_topology(raw, 1, 2, "here:1") is None, body


def test_compression_is_negotiated_away_so_the_traffic_stays_readable():
    raw = encode_op_msg(1, 0, 0, {"hello": 1, "compression": ["zstd", "zlib"]})
    _, got = decode_op_msg(strip_compression(raw, 1, 0))
    assert got["compression"] == []
    # A handshake that asked for none, and any other command, is untouched.
    plain = encode_op_msg(1, 0, 0, {"hello": 1})
    assert strip_compression(plain, 1, 0) == plain
    other = encode_op_msg(1, 0, 0, {"find": "notes", "compression": ["zstd"]})
    assert strip_compression(other, 1, 0) == other


# ---- refuse a command --------------------------------------------------

def test_the_verbs_no_rewrite_is_narrow_enough_to_cover_are_named():
    # A drop takes the marks with it and leaves no evidence anything was
    # ever forgotten, so it is refused rather than forwarded.
    assert set(UNREWRITABLE) == {"drop", "dropDatabase", "renameCollection"}
    assert all(isinstance(why, str) and why for why in UNREWRITABLE.values())


def test_a_pipeline_that_writes_somewhere_else_is_caught_by_name():
    # The sharpest hole a boundary can have: the documents never come back
    # to the client, so nothing on the read path ever sees them.
    assert EXFILTRATING_STAGES == ("$out", "$merge")
    for stage in ("$out", "$merge"):
        assert writes_elsewhere(
            {"aggregate": "notes", "pipeline": [{"$match": {}},
                                                {stage: "elsewhere"}]}) == stage
    assert writes_elsewhere({"aggregate": "notes",
                             "pipeline": [{"$match": {}}]}) is None
    assert writes_elsewhere({"aggregate": "notes", "pipeline": "nonsense"}) is None


def test_a_client_vector_is_refused_only_where_the_server_owns_the_index():
    embeds = {"notes": "voyage-4"}
    vector = {"aggregate": "notes", "pipeline": [
        {"$vectorSearch": {"queryVector": [0.1], "path": "embedding"}}]}
    assert client_vector_on_server_index(vector, embeds) == "notes"
    # The accepted form: the server embeds the query text too.
    text = {"aggregate": "notes", "pipeline": [
        {"$vectorSearch": {"query": "a question", "path": "body"}}]}
    assert client_vector_on_server_index(text, embeds) is None
    # A collection that declared nothing about who embeds is not refused:
    # a client vector is correct there and must keep working.
    other = dict(vector, aggregate="archive")
    assert client_vector_on_server_index(other, embeds) is None
    assert client_vector_on_server_index(vector, {}) is None


def test_a_claim_the_wire_cannot_honestly_answer_is_reported_at_boot():
    # Not wrong -- enforceable where an application already knows the
    # answer. Reported at boot because the alternative is correct and
    # useless: every read of that collection refused, with nothing
    # connecting it to a line in a policy file.
    assert SUPPLIABLE_CLAIMS == {"user", "db", "groups", "roles"}
    mapped = Clearance(order=("public", "secret"),
                       roles=(("analyst", "public"),), claim="roles")
    assert unsuppliable_claims(notes(mapped)) == []
    bare = Clearance(order=("public", "secret"), claim="clearance")
    assert unsuppliable_claims(notes(bare)) == ["clearance"]


def test_a_command_naming_no_collection_this_policy_knows_is_not_guarded():
    guards = {"notes": notes()}
    assert guard_for(guards, {"find": "notes"}, "find") is not None
    assert guard_for(guards, {"find": "other"}, "find") is None
    assert guard_for(guards, {"find": 7}, "find") is None      # from the wire
    assert guard_for(guards, {}, "find") is None


# ---- what a read may see: the query half -------------------------------

def test_a_rule_that_cannot_be_a_query_makes_the_whole_pushdown_none():
    # `None` is the load-bearing return. Partial is not a thing this may
    # be: a count too high by exactly the rows a rule would have caught is
    # the original bug with an extra step.
    assert expressible_clauses(notes()) is not None
    assert expressible_clauses(notes(Deadline("expire_at"),
                                     Budget(limit=10))) is None
    assert expressible_clauses(notes(Distinct(on="chunk"))) is None


def test_a_caller_aware_rule_is_expressible_only_once_the_caller_is_known():
    rule = Clearance(order=("public", "secret"),
                     roles=(("analyst", "public"),), claim="roles")
    guard = notes(rule)
    assert expressible_clauses(guard, caller=None) is None
    clauses = expressible_clauses(guard, caller={"roles": ["analyst"]})
    assert clauses == [{"classification": {"$in": ["public"]}}]


def test_a_reduction_must_pin_its_tenant_to_exactly_one_scalar():
    assert pins_the_tenant({"tenant_id": "acme"}, "tenant_id") is True
    # Legitimate ids that are falsey, which reading `.get() is not None`
    # would have refused.
    assert pins_the_tenant({"tenant_id": None}, "tenant_id") is True
    assert pins_the_tenant({"tenant_id": 0}, "tenant_id") is True
    assert pins_the_tenant({"tenant_id": ""}, "tenant_id") is True
    # Several tenants is one number over several tenants.
    assert pins_the_tenant({"tenant_id": {"$in": ["a", "b"]}},
                           "tenant_id") is False
    assert pins_the_tenant({"tenant_id": ["a"]}, "tenant_id") is False
    assert pins_the_tenant({}, "tenant_id") is False
    assert pins_the_tenant("not a query", "tenant_id") is False


def test_the_commands_whose_reply_is_not_the_documents_are_named():
    assert set(DERIVED_COMMANDS) == {"distinct", "count"}


def test_the_first_stage_that_does_not_hand_back_the_stored_document():
    assert reducing_stage([{"$match": {}}, {"$sort": {"_id": 1}}]) is None
    assert reducing_stage([{"$vectorSearch": {}}, {"$limit": 5}]) is None
    assert reducing_stage([{"$match": {}}, {"$group": {"_id": None}}]) == "$group"
    assert reducing_stage([{"$project": {"text": 1}}]) == "$project"
    # `writes_elsewhere` owns these, so this one steps over them.
    assert reducing_stage([{"$out": "elsewhere"}]) is None
    # A stage this cannot read is not assumed harmless.
    assert reducing_stage([{"$match": {}, "$group": {}}]) is not None
    assert reducing_stage(["nonsense"]) is not None


# ---- the projection that turns the boundary off ------------------------

def test_the_fields_a_verdict_is_read_from_come_from_the_policy():
    # Hardcoding them protects `expire_at` while the policy says `ttl`.
    guard = notes(Deadline("ttl"), revoked("gone"), tenant="tenant_id")
    assert {"ttl", "gone", "tenant_id"} <= deciding_fields(guard)


def test_an_ordinary_inclusion_that_hides_the_marks_is_caught():
    # `find({}, {"text": 1})` is the most ordinary query anybody writes,
    # and it was enough: the marks come back absent, and absent is not
    # refused -- no deadline is pinned, no mark is live.
    needed = deciding_fields(notes())
    assert projection_blinds({"text": 1}, needed) is True
    assert projection_blinds({"forgotten": 0}, needed) is True
    assert projection_blinds({"text": 1, "expire_at": 1, "forgotten": 1},
                             needed) is False
    assert projection_blinds({}, needed) is False
    assert projection_blinds(None, needed) is False


def test_the_two_spellings_of_an_id_projection_are_opposites():
    needed = deciding_fields(notes())
    # Removes nothing.
    assert projection_blinds({"_id": 0}, needed) is False
    # An *inclusion* of `_id` alone, which drops every mark there is.
    assert projection_blinds({"_id": 1}, needed) is True


def test_a_projection_is_judged_by_path_and_not_by_its_first_segment():
    # Truncating to the first segment is right while every field a verdict
    # reads is top-level and wrong the moment one is not: `chapters.text`
    # would satisfy a need for `chapters.forgotten`, and a refused chapter
    # is served with the evidence projected away.
    guard = notes(Deadline("expire_at"), revoked("forgotten"),
                  subjects="chapters", subject_key="title")
    needed = deciding_fields(guard)
    assert "chapters.forgotten" in needed and "chapters.title" in needed
    assert projection_blinds({"chapters.text": 1}, needed) is True
    # An ancestor keeps everything under it.
    assert projection_blinds({"chapters": 1, "expire_at": 1,
                              "forgotten": 1}, needed) is False
    # Excluding the whole array leaves nothing to redact and nothing to
    # leak, so it is not a blinding.
    assert projection_blinds({"chapters": 0}, needed) is False


def test_a_descendant_inclusion_still_leaves_the_field_present():
    # `{"forgotten.at": 1}` leaves a `forgotten` subdocument, which is
    # present, which is all a presence check asks.
    needed = {"forgotten"}
    assert projection_blinds({"forgotten.at": 1}, needed) is False
    # And excluding a descendant leaves the parent there.
    assert projection_blinds({"forgotten.at": 0}, needed) is False


def test_a_blinded_subject_mark_has_no_remedy_and_a_top_level_one_does():
    # The difference decides whether the refusal can move into the query.
    # No query expresses "return this book without its third chapter".
    plain = notes()
    assert blinds_a_subject({"text": 1}, plain) is False
    book = notes(Deadline("expire_at"), revoked("forgotten"),
                 subjects="chapters", subject_key="title")
    assert blinds_a_subject({"chapters.text": 1}, book) is True
    assert blinds_a_subject({"chapters": 1}, book) is False


def test_the_guard_whose_marks_a_command_would_strip_is_found_by_verb():
    guards = {"notes": notes()}
    assert blinded_find({"find": "notes", "projection": {"text": 1}},
                        guards) is not None
    # `findAndModify` spells it `fields`, which is the kind of detail a
    # boundary gets wrong once and never notices.
    assert blinded_find({"findAndModify": "notes", "fields": {"text": 1}},
                        guards) is not None
    assert blinded_find({"find": "notes", "projection": {"expire_at": 1,
                                                         "forgotten": 1}},
                        guards) is None
    assert blinded_find({"find": "notes"}, guards) is None


# ---- the property the split has to preserve ----------------------------

def test_every_decision_is_still_reachable_from_one_import():
    # "Can this be bypassed?" is only as good as the number of places a
    # reviewer has to look. The module may be organised however it needs
    # to be; what may not change is that the answer lives behind one name.
    import voyd.wire.policy as policy

    for decision in ("Guard", "Budgets", "judge", "enforce",
                     "revoke_instead_of_delete",
                     "revoke_instead_of_find_and_delete",
                     "rewrite_derived_read", "refuse_unrewritable",
                     "refuse_client_vector", "rewrite_topology",
                     "strip_compression", "delete_reply", "seal_refusal",
                     "derive_on_insert", "erase_first", "cascade_first",
                     "cascade_first_for_one", "unsuppliable_claims",
                     "guard_for", "expressible_clauses", "pins_the_tenant",
                     "projection_blinds", "deciding_fields",
                     "writes_elsewhere", "client_vector_on_server_index",
                     "UNREWRITABLE", "EXFILTRATING_STAGES"):
        assert hasattr(policy, decision), f"policy.{decision} moved out"


def test_the_transport_decides_nothing_a_policy_should():
    # The boundary's decisions are imported by the transport, never
    # reimplemented in it. A second copy of "should this be refused" is
    # exactly the drift this layout exists to prevent, and it would not
    # fail any other test in this suite.
    import pathlib

    proxy = pathlib.Path("voyd/wire/proxy.py").read_text()
    for verb in ("$out", "$merge", "dropDatabase", "renameCollection"):
        assert verb not in proxy, (
            f"{verb!r} is decided in proxy.py; that decision belongs in "
            f"the policy package")
