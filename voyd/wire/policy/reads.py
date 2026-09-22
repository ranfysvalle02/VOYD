"""What a read may see, and when the refusal has to move into the query.

Two enforcement points, and only one of them is the guarantee. A rule is
pushed into the query where a query can express it -- cheap, the database
does the work -- and re-checked per document on the way out, which is the
promise. This module owns the first half and the decision of when the
second half is unavailable.

`expressible_clauses` returning `None` is the load-bearing case: every
rule has to express itself or the pushed-down filter is *narrower than the
guarantee*, and a count too high by exactly the rows a rule would have
caught is the original bug with an extra step. Partial is not a thing this
may be.

The projection questions are here for the same reason. `find({}, {"text":
1})` is the most ordinary query anybody writes and it was enough to turn
the boundary off: the documents come back real with their marks projected
away, and absent is not refused -- no deadline is pinned, no mark is live.
`projection_blinds` is path-aware rather than first-segment-aware, which
matters the moment a verdict reads a field inside a subject array.
"""

from __future__ import annotations

from typing import Any, Mapping

from ..codec import LAZY, decode_op_msg, encode_op_msg
from .guarding import Guard, guard_for
from .refusals import EXFILTRATING_STAGES, _refuse


# ---------------------------------------------------------------------------
# Reads whose reply is not the documents.
#
# `filter_batch` is a per-document check, and it had a precondition nothing
# was checking: the reply has to be made of the *stored documents*, still
# carrying the fields the verdict is read from. Three shapes break that and
# were all forwarded --
#
#     distinct   -> {"values": [...]}   no cursor, so no batch, so no filter
#     count      -> {"n": 2}            the same
#     $group     -> a cursor of new documents with no marks on them
#
# -- and the third is the quiet one. The batch arrives, `Guard.filter` runs,
# and `len(kept) == len(batch)` holds because a reshaped document has
# nothing to refuse it *on*. The boundary said yes by having nothing to say
# no about, which is the exact silence this package is named after.
#
# Measured through the proxy against a real `mongod`, one live row and one
# revoked one, same connection, same second:
#
#     find:                              ['live']
#     distinct("owner"):                 ['live', 'revoked-...']
#     aggregate [{$count: "n"}]:         [{'n': 2}]
#     aggregate [{$project: {owner:1}}]: ['live', 'revoked-...']
#
# It is the mirror of `$out`/`$merge`. There the client never sees the
# documents because the server writes them elsewhere; here it never sees
# them because the server turned them into something else first.
#
# But the answer is not the same answer. `$out` cannot be made safe by a
# proxy -- the copy happens where the boundary is not. A count can: the
# refusal is a *query*, and pushing it into the pipeline makes the server
# reduce over admitted documents only. So these are rewritten rather than
# refused, the same way a `delete` is rewritten into a revocation, and
# refusing is what happens only when the rewrite would be a lie.
#
# It would be a lie in three cases, and they are the whole of why this is
# not just an injection:
#
#   1. A rule that cannot express itself as a query clause. `_query` in
#      `admission/core.py` already says this out loud -- a rule with no
#      clause "is simply enforced on the way out instead", which is fine for
#      a batch of documents and useless for a number. Unrecoverable-when-
#      sealed is the live example: whether a row decrypts is not a thing
#      `$match` can ask.
#   2. A rule that compares the document against *who is asking*. This
#      process holds no caller.
#   3. A declared tenant the command does not pin. `Guard.filter` infers the
#      scope from the batch it is judging; a reduction has no batch, so the
#      scope has to be in the query or it is not known at all.
#
# In those three, the honest answer is the one `drop` and `$out` get.

# Commands whose entire reply is computed from documents the client never
# sees. There is no batch, so there is nothing for `filter_batch` to judge
# and the refusal has to be in the query or nowhere.
DERIVED_COMMANDS: dict[str, str] = {
    "distinct": "returns field values, not documents",
    "count": "returns a number computed from documents you are not shown",
}

# Stages that hand the stored document back, marks and all. A pipeline made
# only of these produces a batch `filter_batch` can judge on its own, which
# is the case that already worked and must not start paying for this.
PRESERVING_STAGES = frozenset({
    "$match", "$sort", "$limit", "$skip", "$sample",
    "$vectorSearch", "$search", "$geoNear",
})

# Stages that must come first, so an injected `$match` goes after them
# rather than before. `$vectorSearch` is the one that matters here: it is
# the workload this package exists for.
LEADING_STAGES = frozenset({"$vectorSearch", "$search", "$geoNear"})

# Stages that read a *different* collection. Push-down cannot help: the
# documents they bring back were never covered by this guard, and the
# policy for where they came from was not declared. Refused, like `$out`.
FOREIGN_STAGES = frozenset({"$lookup", "$unionWith", "$graphLookup"})


def expressible_clauses(guard: Guard,
                        caller: dict | None = None) -> list[dict] | None:
    """This guard's refusal as query clauses, or `None` if it cannot be.

    `None` is the load-bearing return. Every rule has to express itself or
    the pushed-down filter is *narrower than the guarantee* -- and a count
    that is too high by exactly the rows a rule would have caught is the
    original bug with an extra step. Partial is not a thing this may be.
    """
    clauses: list[dict] = []
    for rule in guard.spec.rules:
        if getattr(rule, "needs_caller", False):
            # The boundary asks the server who the client authenticated
            # as -- see `CallerIdentity` -- so the rule gets its claims and
            # answers as a query like any other.
            # Still `None` when the identity is unknown: a reduction over
            # rows whose permission nobody established is the leak, not a
            # degraded version of preventing it.
            if caller is None:
                return None
            for_caller = getattr(rule, "clause_for", None)
            clause = for_caller(caller) if for_caller else None
        else:
            clause = rule.clause()
        if clause is None:
            return None                 # enforced on the way out, and there
        clauses.append(clause)          # is no way out here
    return clauses


def pins_the_tenant(query: Any, tenant: str) -> bool:
    """Does this query fix the tenant to one scalar?

    `Guard.filter` takes the scope from the batch, because every document in
    a cursor batch came from one query. A reduction has no batch to take it
    from, so an unpinned tenant is not a narrower answer -- it is every
    tenant's rows summarised into one number.
    """
    if not isinstance(query, Mapping) or tenant not in query:
        return False
    # Membership rather than `.get() is not None`, because
    # `admission/core.py` is explicit that `None`, `0` and `""` are tenant
    # ids a caller may legitimately hold -- and reading a pinned null as
    # "unpinned" would refuse a read that was perfectly well scoped.
    value = query[tenant]
    # A `$in`, a `$ne`, a regex: several tenants, and one number over
    # several tenants is the leak with an extra step.
    return not isinstance(value, (Mapping, list))


def _and_in(query: Any, clauses: list[dict]) -> dict:
    """The caller's query, narrowed by the boundary's, without losing either."""
    out = dict(query) if isinstance(query, Mapping) else {}
    existing = out.pop("$and", [])
    # A caller's `$and` that is not a list is their bug, and it is kept so
    # the server says so. Dropping it would be this boundary quietly making
    # a malformed query valid, which is a worse habit than the error.
    out["$and"] = ([*existing, *clauses] if isinstance(existing, list)
                   else [existing, *clauses])
    return out


def deciding_fields(guard: Guard) -> set[str]:
    """The document fields this guard's verdict is read from.

    Asked of the spec rather than hardcoded, because a policy file renames
    any of them -- a boundary protecting `expire_at` while the policy says
    `ttl` is protecting a field nobody uses.
    """
    spec = guard.spec
    names = {n for n in (spec.at_field, spec.mark_field, spec.lineage_field)
             if isinstance(n, str)}
    for rule in spec.rules:
        for attr in ("field", "at_field"):
            value = getattr(rule, attr, None)
            if isinstance(value, str):
                names.add(value)
    if spec.tenant:
        names.add(spec.tenant)
    if spec.subjects:
        # The same fields again, one level down, because a declared
        # `subjects` array is judged element by element and those rules
        # read the element's own copy of the mark. Dotted, and the caller
        # has to compare paths rather than truncate them -- see
        # `projection_blinds`, where `{"chapters.text": 1}` looked
        # indistinguishable from `{"chapters": 1}` and is the difference
        # between redacting a refused chapter and serving its text with
        # the evidence projected away.
        under = {n for n in names if "." not in n}
        if spec.subject_key:
            under.add(spec.subject_key)
        names |= {f"{spec.subjects}.{n}" for n in under}
    return names


def projection_blinds(projection: Any, needed: set[str]) -> bool:
    """Would this projection leave the verdict unable to be taken?

    The hole this closes is not exotic. `find({}, {"text": 1})` is the most
    ordinary query anybody writes, and it was enough: the documents come
    back real, with their marks projected away, and every rule that reads a
    mark finds nothing. Absent is not refused -- a document with no
    deadline is a pinned one, and a document with no revocation mark is a
    live one -- so the whole batch was admitted. Measured against one live,
    one expired and one revoked row:

        find({})                        ->  [1]
        find({}, {"text": 1})           ->  [1, 2, 3]
        find({}, {"forgotten": 0})      ->  [1, 2, 3]

    Nobody has to be attacking anything. An ORM that selects columns, a
    driver's `projection=`, a developer trimming a payload -- each one
    silently turns the boundary off for that query.
    """
    if not isinstance(projection, Mapping) or not projection:
        return False
    # `_id` is exempt from the inclusion/exclusion question by the server
    # and is never a field a rule reads, so it does not decide the kind.
    kinds = {bool(v) for k, v in projection.items() if k != "_id"}
    keys = {k for k in projection if isinstance(k, str)}
    if not kinds:
        # Only `_id` was named, and the two spellings are opposites.
        # `{"_id": 0}` removes nothing and is safe; `{"_id": 1}` is an
        # *inclusion* of `_id` alone, which drops every mark there is.
        # The first version of this exempted `_id` wholesale and let the
        # second through unjudged -- found by sweeping the shapes rather
        # than by thinking of it, which is the honest account.
        return bool(projection.get("_id")) and bool(needed)
    including = kinds != {False}
    for path in needed:
        parent = path.split(".")[0] if "." in path else None
        if parent is not None and not _survives(parent, keys, including):
            # A mark *inside* a subject array is only needed when any of
            # that array reaches the client. `{"chapters": 0}` removes
            # every element, so there is nothing left to redact and
            # nothing left to leak -- refusing the read would be strict
            # about a shape rather than about a guarantee.
            continue
        if not _survives(path, keys, including):
            return True
    return False


def _survives(path: str, keys: set[str], including: bool) -> bool:
    """Is ``path`` still on a document after this projection?

    Path-aware on purpose. The previous version truncated every projected
    key to its first segment, which is exactly right while every field a
    verdict reads is top-level and exactly wrong the moment one is not:
    `{"chapters.text": 1}` became `{"chapters"}` and satisfied a need for
    `chapters.forgotten`, so a refused chapter's text was served with the
    evidence of its refusal projected away.

    An inclusion keeps ``path`` when it names the path, an *ancestor* of
    it (`{"chapters": 1}` keeps `chapters.forgotten`), or a *descendant*
    of it (`{"forgotten.at": 1}` leaves a `forgotten` subdocument, which
    is present, which is all `Marked` asks). An exclusion removes it when
    it names the path or an ancestor; naming a descendant leaves the field
    there, so the presence check still answers.
    """
    if including:
        return any(path == k or path.startswith(f"{k}.")
                   or k.startswith(f"{path}.") for k in keys)
    return not any(path == k or path.startswith(f"{k}.") for k in keys)


def blinds_a_subject(projection: Any, guard: Guard) -> bool:
    """Does this projection hide the marks *inside* a subject array?

    The difference decides whether the refusal can be pushed into the
    query instead, and it is the whole reason this is a separate
    question. A blinded *top-level* mark has a remedy: put
    `{forgotten: null}` in the filter and the server drops the refused
    documents before the projection can hide anything that mattered.

    A blinded *subject* mark has no remedy. No query expresses "return
    this book without its third chapter", so the refusal cannot move into
    the filter and there is nothing left to take it on the way out. The
    read is refused instead -- the one case where the push-down that
    rescues every other blinded projection is not equivalent, and
    forwarding it would serve a refused chapter with the evidence of its
    refusal projected away.
    """
    if not guard.spec.subjects:
        return False
    needed = {p for p in deciding_fields(guard) if "." in p}
    return projection_blinds(projection, needed)


def blinded_find(body: Mapping, guards: dict[str, Guard]) -> Guard | None:
    """The guard whose marks this command's projection would strip.

    `find` only. An `aggregate` that projects is already caught by
    `reducing_stage` -- `$project` is not a stage that hands the stored
    document back -- and `findAndModify` spells its projection `fields`.
    """
    for verb, where in (("find", "projection"), ("findAndModify", "fields")):
        guard = guard_for(guards, body, verb)
        if guard is None:
            continue
        if projection_blinds(body.get(where), deciding_fields(guard)):
            return guard
    return None


def reducing_stage(pipeline: list) -> str | None:
    """The first stage whose output is not the stored document."""
    for stage in pipeline:
        if not isinstance(stage, Mapping) or len(stage) != 1:
            return "a stage this boundary cannot read"
        name = next(iter(stage))
        if name in PRESERVING_STAGES or name in EXFILTRATING_STAGES:
            continue                    # `writes_elsewhere` owns the second
        return name
    return None


def rewrite_derived_read(raw: bytes, req_id: int, resp_to: int,
                         guards: dict[str, Guard], verbose: bool,
                         caller: dict | None = None
                         ) -> tuple[bytes | None, bytes | None]:
    """`(rewritten_request, refusal)` -- at most one of them is not `None`.

    Two returns rather than two functions because the decision is one
    decision: this command needs the refusal in its query, and either that
    is possible or the command is refused. Splitting them invites a caller
    that asks the first question and forwards on a `None`, which is the
    fail-open shape this file has been bitten by before.
    """
    decoded = decode_op_msg(raw)
    if decoded is None:
        # `decode_op_msg` returns `None` on a kind-1 document sequence, and
        # reading that as a decision rather than an absence is the exact bug
        # `test_the_codec_round_trips` was written for. It is safe *here*
        # and only here: a document sequence carries `documents`, `updates`
        # or `deletes`, and none of the commands this function judges is a
        # write. If that ever stops being true this line is fail-open.
        return None, None
    flags, body = decoded

    # `explain` carries the real command as a subdocument and its plan
    # quotes the query. A boundary that handles `distinct` and forwards
    # `explain: {distinct: ...}` has made the guarantee a spelling question,
    # so the inner command is judged -- and only ever refused, never
    # rewritten, because an explain of a rewritten query would describe a
    # command the client did not send.
    inner = body.get("explain")
    if isinstance(inner, Mapping):
        _unused, refusal = rewrite_derived_read(
            encode_op_msg(req_id, resp_to, 0, dict(inner)),
            req_id, resp_to, guards, False, caller)
        if refusal is not None:
            return None, refusal
        if _needs_pushdown(inner, guards):
            return None, _refuse(req_id, _named(inner, guards),
                                 "`explain` describes a plan, not documents, "
                                 "so the refusal cannot be taken on the way "
                                 "out and must not be hidden in the plan",
                                 verbose)
        return None, None

    # A `find` whose projection strips the marks. The documents are real
    # and the verdict cannot be taken on them, which is the same shape as
    # a reduction and gets the same answer: put the refusal in the query,
    # where the projection cannot reach it.
    blinded = blinded_find(body, guards)
    if blinded is not None:
        where_proj = "projection" if "find" in body else "fields"
        if blinds_a_subject(body.get(where_proj), blinded):
            return None, _refuse(
                req_id, blinded.collection,
                f"this projection removes the fields each "
                f"{blinded.spec.subjects!r} element is judged by, and no "
                f"query can remove an element -- so the refusal has "
                f"nowhere to go. Ask for "
                f"{blinded.spec.subjects}.{blinded.spec.mark_field} and "
                f"{blinded.spec.subjects}.{blinded.spec.at_field} too, or "
                f"exclude {blinded.spec.subjects!r} entirely", verbose)
        clauses = expressible_clauses(blinded, caller)
        if clauses is None:
            return None, _refuse(
                req_id, blinded.collection,
                "this projection removes the fields the verdict is read "
                "from, and this policy has a rule that cannot be asked as "
                "a query, so the refusal has nowhere else to go", verbose)
        if blinded.spec.tenant and not pins_the_tenant(
                body.get("filter") or body.get("query"), blinded.spec.tenant):
            return None, _refuse(
                req_id, blinded.collection,
                f"this projection removes the fields the verdict is read "
                f"from, and the query does not say which "
                f"{blinded.spec.tenant!r} it is about", verbose)
        patched = dict(body)
        where = "filter" if "find" in body else "query"
        patched[where] = _and_in(body.get(where), clauses)
        if verbose:
            print(f"  voyd: {blinded.collection}: the projection hides the "
                  f"marks, so the refusal went into the query", flush=True)
        return encode_op_msg(req_id, resp_to, flags, patched), None

    for command in DERIVED_COMMANDS:
        guard = guard_for(guards, body, command)
        if guard is None:
            continue
        clauses = expressible_clauses(guard, caller)
        query = body.get("query")
        if clauses is None:
            return None, _refuse(req_id, guard.collection,
                                 f"`{command}` {DERIVED_COMMANDS[command]}, "
                                 f"and this policy has a rule that cannot be "
                                 f"asked as a query", verbose)
        if guard.spec.tenant and not pins_the_tenant(query, guard.spec.tenant):
            return None, _refuse(req_id, guard.collection,
                                 f"`{command}` {DERIVED_COMMANDS[command]}, "
                                 f"and this command does not say which "
                                 f"{guard.spec.tenant!r} it is about", verbose)
        patched = dict(body)
        patched["query"] = _and_in(query, clauses)
        if verbose:
            print(f"  voyd: {guard.collection}: pushed the refusal into "
                  f"`{command}`", flush=True)
        return encode_op_msg(req_id, resp_to, flags, patched), None

    guard = guard_for(guards, body, "aggregate")
    pipeline = body.get("pipeline")
    if guard is None or not isinstance(pipeline, list):
        return None, None

    foreign = next((next(iter(st)) for st in pipeline
                    if isinstance(st, Mapping) and len(st) == 1
                    and next(iter(st)) in FOREIGN_STAGES), None)
    if foreign is not None:
        return None, _refuse(req_id, guard.collection,
                             f"`{foreign}` brings back documents from another "
                             f"collection, which this guard was not declared "
                             f"for and cannot speak for", verbose)

    stage = reducing_stage(pipeline)
    if stage is None:
        return None, None               # ordinary retrieval: untouched bytes

    clauses = expressible_clauses(guard, caller)
    if clauses is None:
        return None, _refuse(req_id, guard.collection,
                             f"`{stage}` does not hand back the stored "
                             f"document, and this policy has a rule that "
                             f"cannot be asked as a query", verbose)
    lead = pipeline[0] if pipeline and isinstance(pipeline[0], Mapping) else {}
    lead_name = next(iter(lead), None) if len(lead) == 1 else None
    at = 1 if lead_name in LEADING_STAGES else 0
    if guard.spec.tenant:
        pinned = (lead_name == "$match" and pins_the_tenant(
            lead.get("$match"), guard.spec.tenant))
        if not pinned:
            return None, _refuse(
                req_id, guard.collection,
                f"`{stage}` summarises documents you are not shown, and this "
                f"pipeline does not open by saying which "
                f"{guard.spec.tenant!r} it is about", verbose)
    patched = dict(body)
    patched["pipeline"] = [*pipeline[:at], {"$match": {"$and": clauses}},
                           *pipeline[at:]]
    if verbose:
        print(f"  voyd: {guard.collection}: pushed the refusal in front of "
              f"`{stage}`", flush=True)
    return encode_op_msg(req_id, resp_to, flags, patched), None


def _named(body: Mapping, guards: dict[str, Guard]) -> str:
    for verb in (*DERIVED_COMMANDS, "aggregate"):
        guard = guard_for(guards, body, verb)
        if guard is not None:
            return guard.collection
    return "this collection"


def _needs_pushdown(body: Mapping, guards: dict[str, Guard]) -> bool:
    """Would this command have had the refusal pushed into it?"""
    if any(guard_for(guards, body, c) is not None for c in DERIVED_COMMANDS):
        return True
    guard = guard_for(guards, body, "aggregate")
    pipeline = body.get("pipeline")
    return (guard is not None and isinstance(pipeline, list)
            and reducing_stage(pipeline) is not None)


def _was_reduced(raw: bytes, resp_to: int, reduced: set[int] | None,
                 cursors: set[int] | None) -> bool:
    """Was this reply already filtered by a pushed-down query?

    Recognised by request id, which the request side records. What this
    adds is the *cursor*: a reduction can span several batches, and page
    two must be treated the same way page one was -- one read answered two
    different ways is worse than either answer.

    The cursor is tracked here and matched on the `getMore` **request**
    rather than on its reply, because the last batch of a drained cursor
    comes back with ``id: 0`` and there would be nothing left to match on.
    """
    if reduced is None or resp_to not in reduced:
        return False
    reduced.discard(resp_to)
    if cursors is not None:
        peek = decode_op_msg(raw, LAZY)
        cursor = peek[1].get("cursor") if peek else None
        if isinstance(cursor, Mapping):
            cursor_id = cursor.get("id")
            if isinstance(cursor_id, int) and cursor_id:
                cursors.add(cursor_id)      # more batches are coming
    return True


# What `claims_from` puts in front of a rule. A rule asking for anything
# else cannot be answered: there is nowhere else for a claim to come from,
# because the boundary will not believe one the caller asserts. See
