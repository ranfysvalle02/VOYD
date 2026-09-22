"""Every decision this boundary makes about a message. One file.

The question a reviewer actually has is *can this be bypassed?*, and the
honest answer is only as good as the number of places they have to look.
So each of these lives here and nowhere else: what a verb is allowed to
mean, what a read is allowed to see, and what is refused outright because
no rewrite of it would be narrow enough.

Four kinds of decision, and the fourth is the one that is easy to forget:

**Refuse a document.** `Guard` holds one collection's `Admission` and
judges a batch on the way out, per document, whatever produced it -- which
is the whole point, because a `$vectorSearch` hit passed through no query.

**Rewrite a command.** A `delete` becomes the revocation it should have
been; a `find` whose projection would blind the check gets the check
pushed into its query instead; a `hello` stops advertising hosts that
would route a client around this process.

**Refuse a command.** `drop`, `renameCollection`, `$out`, `$merge` -- the
verbs that make a guarded fact unreachable in a way no rewrite can cover.
A guarantee that holds for three verbs out of four is the silent hole this
package is named after, so these say no, out loud, with a reason.

**Carry state a rule needs across messages.** `Budgets` is the only one,
and it exists because a cumulative rule spans a *read* while this boundary
is handed a *batch*, and the client picks how many batches a read arrives
in.

Nothing here owns a socket, and almost nothing here is async. The three
that are open the proxy's own connection for work the caller did not issue
-- sequencing a revocation ahead of a key deletion, and making a refusal
reach what was derived from a fact -- and they say so.
"""

from __future__ import annotations

from typing import Any, Mapping


from voyd.engine import Deadline, revoked
from voyd.engine.admission import Admission, AdmissionSpec
from voyd.engine.time import now

from . import cascade, metrics, seal
from .codec import (LAZY, decode_op_msg, decode_sections,
                    encode_op_msg, encode_sections)


_FRESH_TAB: Any = object()


class Guard:
    """One collection's admission handle, and the tally it has refused.

    Built with ``db=None`` on purpose: this object never queries anything. It
    is the same construction the unit tests use, which is the evidence that
    the per-document check does not depend on a database at all -- the thing
    that makes it movable to a wire in the first place.
    """

    def __init__(self, spec: AdmissionSpec, *, on_delete: str = "forward"):
        self.collection = spec.collection
        self.spec = spec
        self.on_delete = on_delete
        self.handle = Admission(None, spec)
        self.refused = 0
        self.admitted = 0
        self.revoked = 0
        # What was marked because it was *made out of* something the caller
        # revoked, as opposed to what the caller named. Two numbers rather
        # than one because "you asked to erase 2 facts and 7 things built on
        # them went too" is the sentence an auditor needs, and a single
        # total cannot say it.
        self.cascaded = 0
        # The proxy's own connection, attached per worker by `_run` and only
        # when this collection declares `lineage_field`. `None` everywhere
        # else, which is the overwhelmingly common case and costs nothing.
        # A `Guard` is still constructible with no database at all -- the
        # per-document check has never needed one, and that is what made it
        # movable to a wire.
        self.cascade: "cascade.Cascade | None" = None
        # Refusals that happened during decryption rather than during
        # `reachable()`. Counted on the guard so one collection has one
        # tally: an operator asking "what did this refuse" should not have
        # to know that `unrecoverable` is answered by a different object
        # than `expired` is.
        self.sealed_refused: dict[str, int] = {}

    @classmethod
    def defaults(cls, collection: str, *, at_field: str, mark_field: str):
        """A guard for a collection nobody wrote a policy for.

        The two rules every collection with a deadline wants, so
        ``--guard notes`` is still a complete thing to type. A policy file
        says more; this says the obvious part.
        """
        return cls(AdmissionSpec(collection,
                                 rules=(Deadline(at_field=at_field),
                                        revoked(mark_field))))

    @property
    def needs_caller(self) -> bool:
        """Does any rule here decide by *who is asking*?

        Cached nowhere on purpose: it is a tuple scan over two or three
        rules, and a boundary that memoised it would have one more piece of
        state to get stale when a policy is reloaded.
        """
        return any(getattr(r, "needs_caller", False) for r in self.spec.rules)

    @property
    def cumulative(self) -> bool:
        """Does any rule here compare a document against the page so far?

        The gate on `Budgets` doing anything at all. A `budget()` or a
        `distinct()` needs a running total that outlives one batch;
        everything else is per document and needs no state between them.
        """
        return any(getattr(r, "needs_tab", False) for r in self.spec.rules)

    def filter(self, docs: list[dict], caller: dict | None = None,
               tab: Any = _FRESH_TAB) -> list[dict]:
        handle = self.handle
        if self.needs_caller:
            # `for_caller` clones rather than assigns, and here that is
            # load-bearing: one `Guard` is shared by every connection this
            # proxy serves, so binding an identity onto `self.handle` would
            # show one client's rows to whoever asked second.
            #
            # `caller=None` -- the question could not be answered -- binds
            # empty claims rather than skipping the rules, so an unknown
            # caller is refused by them instead of waved past.
            handle = handle.for_caller(caller or {})
        if self.spec.tenant:
            # A declared tenant is enforced per document, and the proxy has
            # no filters to read it from -- so it takes the scope from the
            # batch itself. Every document in a cursor batch came from one
            # query, so they share a tenant; a batch that does not is already
            # the leak, and `off_scope` is what names it.
            scopes = {d.get(self.spec.tenant) for d in docs}
            handle = handle.for_tenant(scopes.pop() if len(scopes) == 1
                                       else object())
        # `_FRESH_TAB` means "this call is the whole read", which is true
        # of everything except a cursor batch. `Budgets` hands in a tab
        # that spans the cursor; see its docstring for why a fresh one per
        # batch is a hole rather than an inefficiency.
        kept = (handle.reachable(docs) if tab is _FRESH_TAB
                else handle.reachable(docs, tab=tab))
        self.refused += len(docs) - len(kept)
        self.admitted += len(kept)
        return kept

    def note_sealed(self, tally: dict[str, int]) -> None:
        for reason, count in tally.items():
            self.sealed_refused[reason] = self.sealed_refused.get(reason, 0) + count
        self.refused += sum(tally.values())

    def reasons(self) -> dict:
        counts = dict(self.handle.receipts().get("refused_by_reason", {}))
        for reason, count in self.sealed_refused.items():
            counts[reason] = counts.get(reason, 0) + count
        return counts




# --------------------------------------------------------------------------
# The two legs. Only one of them rewrites anything.
# --------------------------------------------------------------------------

def _collection_of(reply: Mapping) -> str | None:
    """Which collection this cursor batch came from.

    ``cursor.ns`` is ``"db.collection"``, and it is the only place a reply
    names what it is. A reply without one is not a cursor batch.
    """
    ns = (reply.get("cursor") or {}).get("ns")
    if not isinstance(ns, str) or "." not in ns:
        return None
    return ns.split(".", 1)[1]


def revoke_instead_of_delete(raw: bytes, req_id: int, resp_to: int,
                             guard: Guard, verbose: bool,
                             pins: list[list] | None = None) -> bytes | None:
    """Turn a client's ``delete`` into the revocation it should have been.

    This is the half of the story the read path could not tell. A boundary
    that refuses forgotten facts is worth little if the only way to forget
    one is to import a library -- so the verb a caller already has is given
    the better meaning:

        db.notes.deleteOne({"_id": x})   # what they wrote
        -> the row is marked, unreachable on the next read, still on disk,
           and its deadline is pulled in so the reaper collects it

    Which is the whole thesis applied to somebody else's code without
    editing it. Delete is a wish -- eventually, best effort, unprovable.
    Refuse is a contract. They asked for the wish and got the contract, and
    the bytes still go, on the deadline they already had.

    **Only when the policy file says so.** `@guard(..., on_delete="revoke")`
    is opt-in because silently redefining `delete` for an operator who did
    not ask is precisely the kind of surprise this project exists to remove.
    Left alone, a delete is forwarded and really deletes.

    The update emitted here is the same pipeline ``Admission.revoke()``
    writes -- the literal mark, the deadline moved *earlier only*, and the
    derived encodings nulled. The two have to leave the same row, and
    `test_both_doors_leave_the_same_row` is what holds them to it: two
    spellings of "forgotten" that produced different documents would be the
    drift this whole package is about.

    ``pins`` arrives from ``cascade_first`` on a collection that declares
    lineage: the ids that clause actually matched, already resolved, with
    their descendants already marked. Pinning the clause to them rather
    than re-sending the caller's filter is what makes the two halves agree
    -- ``deleteOne`` asks the server to pick one of the matches and does
    not say which, so a cascade computed from the filter and a revocation
    computed from the filter can land on different documents.
    """
    decoded = decode_sections(raw)
    if decoded is None:
        return None
    flags, body, ident, docs = decoded
    if body.get("delete") != guard.collection or ident != "deletes":
        return None

    pipeline = _forget_pipeline(guard.spec, "deleted via voyd-wire")
    if not pipeline:
        return None          # nothing to mark with; forward the real delete

    updates = []
    for i, d in enumerate(docs):
        pin = pins[i] if pins is not None and i < len(pins) else None
        if pin is None:
            updates.append({
                "q": d.get("q", {}),
                # `limit: 1` means deleteOne; anything else is deleteMany.
                "multi": d.get("limit", 0) == 0,
                "u": pipeline,
            })
        else:
            # Pinned by id: the filter has already been resolved, and an
            # empty pin is a filter that matched nothing -- `$in: []`
            # matches nothing too, which keeps the reply's `n` honest
            # instead of turning a no-op into an unfiltered update.
            #
            # `multi` still comes from the clause and not from the pin's
            # length, because the driver marked a `deleteOne` retryable and
            # **the server rejects a retryable write with `multi: true`**
            # (code 72). Setting it from the resolved set looked more
            # accurate and turned every `deleteOne` on a lineage collection
            # into a write error. A pinned `deleteOne` resolves to at most
            # one id, so `multi: false` is not a narrowing anyway.
            updates.append({"q": {"_id": {"$in": pin}},
                            "multi": d.get("limit", 0) == 0,
                            "u": pipeline})

    new_body = {("update" if k == "delete" else k): v for k, v in body.items()}
    if verbose:
        print(f"  voyd: {guard.collection}: delete -> revoke "
              f"({len(updates)} clause(s)); the rows stay on disk",
              flush=True)
    guard.revoked += len(updates)
    return encode_sections(req_id, resp_to, flags, new_body, "updates", updates)


def _forget_pipeline(spec, reason: str) -> list:
    """The update `Admission.revoke()` writes, as a pipeline.

    One definition, used by every verb this boundary rewrites, because two
    spellings that produced different rows would be the drift this package
    is about arriving through its own front door.
    """
    mark_field = next((r.field for r in spec.rules
                       if getattr(r, "reversible", None) is False), None)
    if mark_field is None:
        return []
    stamp = now()
    at = spec.at_field
    return [{"$set": {
        mark_field: {"$literal": {"at": stamp, "reason": reason}},
        # A missing deadline is a *pinned* row, not an early one, so the two
        # cases are separated -- `$min` against null would pin an erased
        # fact forever.
        at: {"$cond": [{"$eq": [{"$type": f"${at}"}, "date"]},
                       {"$min": [f"${at}", stamp]}, stamp]},
        **{name: None for name in spec.derived_fields},
    }}]


def revoke_instead_of_find_and_delete(raw: bytes, req_id: int, resp_to: int,
                                      guard: Guard, verbose: bool,
                                      pin: list | None = None) -> bytes | None:
    """`findOneAndDelete`, which is a different command and was a real hole.

    `delete` and `findAndModify` are separate wire commands, so intercepting
    the first and not the second gave a team the guarantee for one delete
    verb and silently not for the other -- measured: `deleteOne` left the row
    on disk and `findOneAndDelete` destroyed it, under the same policy, in
    the same process. Partial enforcement that looks complete is the exact
    failure this project exists to forbid, so it was worth more than a
    footnote.

    `remove: true` becomes `update: <the forget pipeline>`, which keeps the
    verb's whole point -- the caller still gets the document back.
    """
    decoded = decode_op_msg(raw)
    if decoded is None:
        return None
    flags, body = decoded
    if body.get("findAndModify") != guard.collection or not body.get("remove"):
        return None

    pipeline = _forget_pipeline(guard.spec, "findOneAndDelete via voyd-wire")
    if not pipeline:
        return None

    body = {k: v for k, v in body.items() if k != "remove"}
    body["update"] = pipeline
    if pin is not None:
        # The cascade already resolved which document this is, honouring
        # the caller's own `sort`. Re-sending the filter would let the
        # server pick a different one, and the descendants of *that* one
        # would still be reachable.
        body["query"] = {"_id": {"$in": pin}}
        body.pop("sort", None)
    # `new: false` is what a delete means here: the caller asked for the
    # document as it was, which is also the only version that still reads.
    body.setdefault("new", False)
    if verbose:
        print(f"  voyd: {guard.collection}: findOneAndDelete -> revoke; "
              f"the row stays on disk", flush=True)
    guard.revoked += 1
    return encode_op_msg(req_id, resp_to, flags, body)


# Commands that can make a guarded fact unreachable and that this boundary
# cannot turn into a revocation. Refusing them is the whole point: a
# guarantee that covers three verbs out of four is the silent hole this
# package is named after, and the operator asked for `on_delete="revoke"`.
UNREWRITABLE = {
    "drop": "drops the whole collection, marks and all",
    "dropDatabase": "drops the database",
    "renameCollection": "moves the collection out from under the policy",
}

# Aggregation stages that write somewhere else. These are the sharpest hole
# this boundary can have, because they do not *look* destructive: the
# documents never come back to the client, so nothing on the read path ever
# sees them. Measured before it was closed --
#
#     through the boundary:  ['live']
#     after $out to another collection:  ['SECRET', 'live']
#
# -- a refused document copied itself out of the policy's reach, server-
# side, through a connection that had just declined to show it. That is
# exactly the silence this package is named after, arriving through its own
# front door.
#
# A proxy cannot make these safe. The copy happens inside the server and
# the boundary is never handed a document to refuse, so the only honest
# answer is the same one `drop` gets: say no, out loud, with a reason.
EXFILTRATING_STAGES = ("$out", "$merge")


def writes_elsewhere(body: Mapping) -> str | None:
    """Does this aggregation end by writing somewhere the policy is not?"""
    pipeline = body.get("pipeline")
    if not isinstance(pipeline, list):
        return None
    for stage in pipeline:
        if not isinstance(stage, dict):
            continue
        for name in EXFILTRATING_STAGES:
            if name in stage:
                return name
    return None


def client_vector_on_server_index(body: Mapping, embeds: Mapping) -> str | None:
    """A query carrying its own vector for an index the server embeds.

    The other half of `EmbeddedWith`, and the half nothing else in this
    system had. That rule refuses a **document** whose stored vector came
    from the wrong model. Nothing refused the **query**.

    It is the same failure and it is worse, because it is one message
    rather than one row: comparing a client-computed vector against an
    index mongot built with a different model does not error. It returns a
    number between -1 and 1 for every candidate, so the page comes back
    full, ranked, plausible and meaningless. Measured in `rules.py` against
    two generations of one vendor's model at the same width -- identical
    text scored -0.053, unrelated text scored +0.301. Unrelated text beat
    the right answer by five times, with no log and no error.

    `auto_embed` exists to remove the client-side embedder that makes this
    possible. A client still sending `queryVector` has put it back, from a
    driver that never read the policy file -- which is precisely the
    caller the wire boundary exists for. So it is refused by name rather
    than ranked.

    Returns the collection, or `None`. Pure: a body and a dict.
    """
    if not embeds:
        return None
    collection = body.get("aggregate")
    if not isinstance(collection, str) or collection not in embeds:
        return None
    pipeline = body.get("pipeline")
    if not isinstance(pipeline, list):
        return None
    for stage in pipeline:
        if not isinstance(stage, Mapping):
            continue
        search = stage.get("$vectorSearch")
        if isinstance(search, Mapping) and "queryVector" in search:
            return collection
    return None


def refuse_client_vector(raw: bytes, req_id: int, resp_to: int,
                         embeds: Mapping) -> bytes | None:
    """Answer that query with an error instead of a plausible page.

    An error is recoverable and a silently wrong ranking is not: the
    caller reads ten well-scored documents that have nothing to do with
    the question, and nothing anywhere says so.
    """
    decoded = decode_op_msg(raw, LAZY)
    if decoded is None:
        return None
    collection = client_vector_on_server_index(dict(decoded[1]), embeds)
    if collection is None:
        return None
    model = embeds[collection]
    print(f"  voyd: REFUSED a client-supplied queryVector on {collection}: "
          f"the server owns this encoding (auto_embed={model!r})", flush=True)
    return encode_op_msg(req_id, resp_to, 0, {
        "ok": 0.0, "code": 8000, "codeName": "AtlasError",
        "errmsg": (
            f"voyd-wire refuses a client-supplied queryVector on "
            f"{collection!r}: this collection declares "
            f"auto_embed={model!r}, so the index holds text the server "
            f"embedded and a vector computed anywhere else is a hit in a "
            f"different space. Comparing them does not fail, it returns a "
            f"confident score for the wrong documents. Send "
            f"$vectorSearch.query with the query text instead and let the "
            f"index embed it with the model it was built from."),
    })



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
            # This process used to be nobody. It can now ask the server who
            # the client authenticated as -- see `CallerIdentity` -- so the
            # rule gets its claims and answers as a query like any other.
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


def _refuse(req_id: int, collection: str, why: str,
            verbose: bool) -> bytes:
    """An error the driver raises, rather than a plausible wrong number."""
    if verbose:
        print(f"  voyd: REFUSED a derived read on {collection}: {why}",
              flush=True)
    # `responseTo` is the *request* id: this message answers the command,
    # it does not continue a stream. Getting it from the request's own
    # `responseTo` (which is 0) desynchronises the driver, and the failure
    # arrives as `ProtocolError: got response id 0` -- a boundary bug
    # wearing the costume of a network one, which is a shape LIMITS.md §1
    # already has an entry for.
    return encode_op_msg(req_id, req_id, 0, {
        "ok": 0.0, "code": 8000, "codeName": "AtlasError",
        "errmsg": (
            f"voyd-wire refuses this read on {collection!r}: {why}. This "
            f"boundary decides per document, so a reply it cannot trace back "
            f"to documents is one it cannot refuse -- and a forgotten fact "
            f"would be counted, grouped or listed as a value instead of "
            f"being left out. Read the documents through the boundary and "
            f"reduce them on your side."),
    })


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
# `unsuppliable_claims`, which says so at boot rather than at query time.
SUPPLIABLE_CLAIMS = frozenset({"user", "db", "groups", "roles"})


def unsuppliable_claims(guard: Guard) -> list[str]:
    """Claims this guard's rules need and the wire cannot produce.

    There are exactly four a boundary can honestly answer -- `user`, `db`,
    `groups`, `roles` -- because those are what the *server* says when
    asked `connectionStatus`, and a claim the client asserted is not
    evidence about the client.

    A rule wanting anything else is not wrong; it is enforceable where an
    application already knows the answer. Here it can only be reported,
    and it is reported **at boot**, because the alternative is correct and
    useless: no claim means the lowest clearance, which means every read
    of that collection is refused, which presents as "VOYD broke my reads"
    with nothing connecting it to a line in a policy file.

    `clearance(order=..., roles={...})` is the shape that avoids this --
    the mapping turns "how far up the ladder is this caller" into a
    question about roles, which the server does answer. A `clearance()`
    with no mapping lands here.
    """
    wanted = []
    for rule in guard.spec.rules:
        if not getattr(rule, "needs_caller", False):
            continue
        claim = getattr(rule, "claim", None)
        if isinstance(claim, str) and claim not in SUPPLIABLE_CLAIMS:
            wanted.append(claim)
    return sorted(set(wanted))


def _wants_a_caller(guards: dict[str, Guard], body: Mapping) -> bool:
    """Does this command touch a collection whose rules ask who is asking?

    The gate on paying a round trip. Cheap on purpose -- it reads the
    handful of fields a command names its collection in, and a deployment
    that declares no caller-aware rule never gets past the first line.
    """
    if not any(g.needs_caller for g in guards.values()):
        return False
    for verb in ("find", "aggregate", "distinct", "count", "getMore",
                 "findAndModify", "delete", "update", "insert"):
        target = body.get(verb)
        if isinstance(target, str) and target in guards:
            return guards[target].needs_caller
    # A `getMore` names its collection in `collection`, not in the verb.
    more = body.get("collection")
    if isinstance(more, str) and more in guards:
        return guards[more].needs_caller
    return False


def guard_for(guards: dict[str, Guard], body: Mapping,
              verb: str) -> Guard | None:
    """The guard for the collection this command names, if any.

    A command's target arrives from the wire, so it is whatever was in the
    bytes: absent, a string, or a number somebody sent on purpose. Every
    call site was spelling `guards.get(body.get(verb))`, which reads fine
    and asks a `dict[str, Guard]` to look up a value of unknown type -- five
    of this file's type errors, in the five places that decide whether a
    policy applies to a write. Narrowed once, here.

    Not called `named`, which was the first choice and was a live bug:
    `refuse_unrewritable` already binds a local `named` (a collection name)
    further down, so the name was function-scoped there and the call at the
    top of that same function raised `NameError` before reaching the
    server. `ruff` caught it in a second; `mypy` did not, which is a fair
    reminder of what each one is for.
    """
    name = body.get(verb)
    return guards.get(name) if isinstance(name, str) else None


def refuse_unrewritable(raw: bytes, req_id: int, resp_to: int,
                        guards: dict[str, Guard]) -> bytes | None:
    """Answer the client with an error rather than let the fact be destroyed.

    Only on a collection somebody declared `on_delete="revoke"` for. That
    declaration is a statement that deletes here are supposed to become
    revocations, and honouring it for `deleteOne` while passing `drop`
    through would be the boundary lying by omission.
    """
    decoded = decode_op_msg(raw)
    if decoded is None:
        return None
    _flags, body = decoded

    guard = guard_for(guards, body, "aggregate")
    stage = writes_elsewhere(body) if guard is not None else None
    if guard is not None and stage is not None:
        print(f"  voyd: REFUSED {stage} on {guard.collection}: it copies "
              f"documents server-side, past the boundary", flush=True)
        return encode_op_msg(req_id, resp_to, 0, {
            "ok": 0.0, "code": 8000, "codeName": "AtlasError",
            "errmsg": (f"voyd-wire refuses {stage} on {guard.collection!r}: "
                       f"it writes documents to another collection inside "
                       f"the server, where this boundary never sees them and "
                       f"the policy does not follow. Read through the "
                       f"boundary and write the results back instead."),
        })

    for command, why in UNREWRITABLE.items():
        target = body.get(command)
        named = (target if isinstance(target, str)
                 else next(iter(guards), None) if command == "dropDatabase"
                 else None)
        guard = guards.get(named) if named else None
        if command not in body or guard is None or guard.on_delete != "revoke":
            continue
        print(f"  voyd: REFUSED {command} on {guard.collection}: {why}, and "
              f"this collection declared on_delete='revoke'", flush=True)
        return encode_op_msg(req_id, resp_to, 0, {
            "ok": 0.0, "code": 8000, "codeName": "AtlasError",
            "errmsg": (f"voyd-wire refuses {command} on "
                       f"{guard.collection!r}: it {why}, which cannot be "
                       f"expressed as a revocation. This collection declared "
                       f"on_delete='revoke'; drop it through a direct "
                       f"connection if you mean it."),
        })
    return None


# Fields in a `hello` reply that name *other machines*. A driver reads these
# and connects to them directly, which is the whole of how a replica set
# works and the whole of how a boundary gets walked past.
TOPOLOGY_FIELDS = ("hosts", "passives", "arbiters")


def rewrite_topology(raw: bytes, req_id: int, resp_to: int,
                     advertise: str) -> bytes | None:
    """Answer `hello` with this boundary's address instead of the cluster's.

    Until this existed the boundary depended on the client passing
    `directConnection=true` -- which is *client configuration*, not
    enforcement. A driver without it reads the `hosts` array and connects to
    the real nodes, straight past the policy. Measured against a local
    deployment it does not even fail safe: the client reads the container's
    internal hostname, cannot resolve it, and gives up. Against Atlas those
    hosts resolve perfectly, so the same bug is a silent bypass rather than
    an error.

    **What is rewritten, and what is deliberately not.** This is where a
    topology rewrite goes wrong, so each field is a decision:

    - ``hosts``, ``me``, ``primary`` -> this boundary. That is the lie that
      makes the client stay.
    - ``passives``, ``arbiters`` -> emptied. They name other machines.
    - ``setName`` -> **kept**. Stripping it makes a driver treat the target
      as a standalone, which silently disables retryable writes -- a
      correctness regression handed over as a topology tidy-up.
    - ``isWritablePrimary`` / ``secondary`` -> **passed through untouched**.
      Forcing these true is the tempting version and it is the dangerous
      one: that flag is exactly the signal a driver uses to notice a
      failover, so masking it means the client keeps writing happily to a
      boundary whose upstream is now a secondary, and nothing anywhere
      notices. A boundary that lies about writability has made itself the
      outage.
    """
    decoded = decode_op_msg(raw)
    if decoded is None:
        return None
    flags, reply = decoded

    # A `hello` reply is the one that describes a server to a driver. This
    # check is a fast path and a statement of intent, *not* the safety
    # property -- deleting it changes no behaviour, which a sabotage run
    # proved rather than a reviewer guessing. The guarantee that an
    # unrelated message is forwarded byte for byte is the `out == reply`
    # comparison at the bottom: nothing is re-encoded unless a field
    # actually changed.
    if "maxWireVersion" not in reply or not (
            set(reply) & {"isWritablePrimary", "ismaster", "hosts", "me"}):
        return None

    out = dict(reply)
    for field in TOPOLOGY_FIELDS:
        if field in out:
            out[field] = [advertise] if field == "hosts" else []
    if "me" in out:
        out["me"] = advertise
    if "primary" in out:
        # Only meaningful if the upstream still believes it has one. Saying
        # "the primary is me" while the upstream says there is none would be
        # the same lie as forcing writability.
        out["primary"] = advertise
    if out == reply:
        return None
    return encode_op_msg(req_id, resp_to, flags, out)


def delete_reply(raw: bytes, req_id: int, resp_to: int) -> bytes:
    """Make an ``update`` reply look like the ``delete`` reply it answers.

    The driver issued a delete and is entitled to a delete's shape. An
    update reply carries ``nModified`` beside ``n``; a delete's does not, and
    a client that sees a field its command never produces is being told
    something true about the proxy and confusing about its own call.
    """
    decoded = decode_op_msg(raw)
    if decoded is None:
        return raw
    flags, reply = decoded
    if "nModified" not in reply:
        return raw
    reply = {k: v for k, v in reply.items() if k != "nModified"}
    return encode_op_msg(req_id, resp_to, flags, reply)


def strip_compression(raw: bytes, req_id: int, resp_to: int) -> bytes:
    """Remove ``compression`` from a handshake so replies arrive readable.

    A boundary that cannot read the traffic cannot enforce anything, and
    negotiating compression away is cheaper and far less fragile than
    recompressing every batch we rewrite. The cost is bandwidth on a demo.
    """
    decoded = decode_op_msg(raw)
    if decoded is None:
        return raw
    flags, doc = decoded
    if not ({"hello", "ismaster", "isMaster"} & set(doc)) or "compression" not in doc:
        return raw
    doc = dict(doc)
    doc["compression"] = []
    return encode_op_msg(req_id, resp_to, flags, doc)


class Budgets:
    """One running total per cursor, because the client picks the batch size.

    A cumulative rule -- `budget()`, `distinct()` -- compares a document
    against the total of the page so far. The handle opens one tab per
    `reachable()` call, and on the wire that is one call per *batch*. A
    cursor delivers one logical read in as many batches as the client asks
    for, and `batchSize` is a field in the client's own `find`.

    So without this, a declared budget of 100 tokens is a budget of 100
    tokens **per batch**, and `batchSize=2` over ten 40-token documents
    serves all ten. Nothing errors, nothing is logged, and the policy file
    says the rule is in force. That is the shape of hole this whole
    project is about, so the fix is not an optimisation and the tab is not
    optional.

    Keyed by the server's cursor id, held per connection, and dropped when
    the cursor is exhausted or killed. Per connection rather than on the
    `Guard`, which every connection shares: a tab is one client's read.

    Costs nothing when no guarded collection declares a cumulative rule,
    which is the ordinary case -- `Guard.cumulative` is the gate and the
    dict stays empty.
    """

    __slots__ = ("_open",)

    def __init__(self) -> None:
        self._open: dict[tuple[str, int], Any] = {}

    def tab_for(self, guard: Guard, cursor_id: Any) -> Any:
        """The tab this batch should be charged against.

        `_FRESH_TAB` for a read that is already whole: no cumulative rule
        to carry, or a cursor the server exhausted in one reply (`id: 0`),
        where there is no second batch for a total to span.
        """
        if not guard.cumulative:
            return _FRESH_TAB
        if not isinstance(cursor_id, int) or cursor_id == 0:
            return _FRESH_TAB
        key = (guard.collection, cursor_id)
        tab = self._open.get(key)
        if tab is None:
            tab = guard.handle.open_tab()
            self._open[key] = tab
        return tab

    def done(self, cursor_id: Any) -> None:
        """Forget a cursor's totals. Called when the server says `id: 0`.

        Without this a long-lived connection accumulates one tab per query
        it has ever run. Cursor ids are not reused while a cursor is live,
        so dropping on exhaustion is the whole of the lifecycle.
        """
        if not isinstance(cursor_id, int) or cursor_id == 0 or not self._open:
            return
        for key in [k for k in self._open if k[1] == cursor_id]:
            del self._open[key]

    def forget(self, cursor_ids: Any) -> None:
        """A client abandoned these cursors with `killCursors`."""
        if isinstance(cursor_ids, list):
            for cid in cursor_ids:
                self.done(cid)


def enforce(raw: bytes, req_id: int, resp_to: int, guards: dict[str, Guard],
            verbose: bool, caller: dict | None = None,
            budgets: "Budgets | None" = None) -> bytes:
    """Apply admission to a cursor batch on its way back to the client.

    Everything that is not a guarded cursor batch is forwarded byte for byte.
    That is deliberate: a proxy that re-encoded every message would be a new
    source of protocol bugs in exchange for nothing, and the only thing worth
    touching is the one array of documents that is about to become context.

    **Nothing is decoded until it is about to be judged.** Every reply on the
    connection arrives here, and all but a few are forwarded -- so the body is
    read lazily and the questions are asked cheapest-first: is there a cursor,
    what collection is it, is that collection guarded. A `find` on a
    collection nobody declared costs four field reads, not a Python object per
    float in every embedding it happens to carry. The documents become real
    only at ``guard.filter``, which is the first line that needs their values.
    """
    decoded = decode_op_msg(raw, LAZY)
    if decoded is None:
        return raw
    flags, reply = decoded
    cursor = reply.get("cursor")
    if not isinstance(cursor, Mapping):
        return raw
    key = "firstBatch" if "firstBatch" in cursor else (
        "nextBatch" if "nextBatch" in cursor else None)
    if key is None:
        return raw

    collection = _collection_of(reply)
    guard = guards.get(collection) if collection else None
    if guard is None:
        return raw

    batch = cursor[key]
    if not isinstance(batch, list) or not batch:
        return raw

    # The first read of the documents themselves, and only on a batch that a
    # declared guard is about to judge. Still lazy: the rules name a handful
    # of top-level fields, so a vector never becomes a list of floats -- and a
    # document that survives is re-encoded from the bytes it arrived in.
    cursor_id = cursor.get("id")
    tab = (budgets.tab_for(guard, cursor_id) if budgets is not None
           else _FRESH_TAB)
    kept = guard.filter(batch, caller, tab)
    if budgets is not None and cursor_id == 0:
        budgets.done(cursor_id)
    # The bytes are forwarded untouched only when the batch came back
    # *identical* -- same length and the same objects. Length alone was
    # the test, and it is the right test for whole-document refusal and
    # the wrong one for redaction: a collection declaring `subjects` has
    # its refused elements removed from a document that is still
    # admitted, so the count matches, the fast path returned the original
    # bytes, and the refused chapter was served with its refusal counted.
    #
    # `_admit` returns the document it was handed when it changed nothing
    # and a new one when it redacted, so identity is an exact answer and
    # costs a pointer comparison per document on the ordinary path.
    if len(kept) == len(batch) and all(a is b for a, b in zip(kept, batch)):
        return raw                      # nothing refused: do not touch the bytes

    reply = dict(reply)
    reply["cursor"] = dict(cursor)
    reply["cursor"][key] = kept
    # `reply` is now a plain dict of raw values; `bson.encode` splices the
    # untouched ones back in as bytes rather than re-serialising them.
    if verbose:
        print(f"  voyd: {collection}: refused {len(batch) - len(kept)} of "
              f"{len(batch)}  {guard.reasons()}", flush=True)
    return encode_op_msg(req_id, resp_to, flags, reply)


async def erase_first(body: Mapping, statements: list,
                      guards: dict[str, Guard],
                      vault: "seal.Vault | None", verbose: bool,
                      meter: "metrics.Meter | None" = None) -> None:
    """If this client is destroying a key, revoke its documents first.

    Sequenced here, on the request, rather than left to the operator to
    remember as two commands in the right order. Getting it backwards is
    not a style question: a key destroyed before the documents are marked
    leaves them readable for as long as a decrypting process keeps the key
    cached, which is about a minute -- the same window, in the same shape,
    as the TTL monitor this repository opens by complaining about.
    """
    if vault is None:
        return
    scopes = vault.erasing(body, statements, body.get("$db", ""))
    if not scopes:
        return
    pipelines = {name: _forget_pipeline(g.spec, "key destroyed")
                 for name, g in guards.items()}
    marked = await vault.revoke_first(scopes, pipelines)
    for name, g in guards.items():
        if vault.seals(name):
            g.revoked += marked
    if meter is not None:
        # Counted as a pair on purpose. `erasures_total` climbing while
        # `erasure_revocations_total` stays flat is the ordering being lost,
        # which is the defect this feature already shipped once -- and the
        # only way to see it from outside is that the two series diverge.
        meter.erasures_total += len(scopes)
        meter.erasure_revocations_total += marked
    if verbose:
        print(f"  voyd: erasure of {', '.join(scopes)}: revoked {marked} "
              f"document(s) first, so they are unreachable now rather than "
              f"when the key cache turns over; destroying the key next",
              flush=True)


async def cascade_first(raw: bytes, guard: Guard, database: str,
                        verbose: bool) -> list[list] | None:
    """Mark what was made out of these facts, *before* revoking the facts.

    Children first. A crash after this and before the forwarded revocation
    leaves the source still reachable and its derivations already gone --
    a half-erasure the caller fixes by re-running an idempotent delete. The
    other order leaves the source refused and the summary of it still
    answering prompts, with nothing anywhere saying so.

    Returns the ids each delete clause matched, so the revocation that
    follows is pinned to exactly the documents this cascaded from, or
    ``None`` when there is no lineage here and the bytes should be left
    alone.
    """
    downstream = guard.cascade
    if downstream is None or not guard.spec.lineage_field:
        return None
    decoded = decode_sections(raw)
    if decoded is None:
        return None
    _flags, body, ident, docs = decoded
    if body.get("delete") != guard.collection or ident != "deletes":
        return None
    pipeline = _forget_pipeline(guard.spec, "derived from a fact deleted "
                                            "via voyd-wire")
    if not pipeline:
        return None

    pins = []
    for clause in docs:
        query = clause.get("q", {})
        ids = await downstream.resolve(database, guard, query,
                                    one=clause.get("limit", 0) == 1)
        guard.cascaded += await downstream.mark_descendants(
            database, guard, ids, pipeline, query)
        pins.append(ids)
    return pins


async def cascade_first_for_one(raw: bytes, guard: Guard, database: str,
                                verbose: bool) -> list | None:
    """The same, for ``findOneAndDelete``.

    A separate wire command, and intercepting one and not the other is how
    this boundary already shipped the guarantee for `deleteOne` and
    silently not for `findOneAndDelete`. The lineage half is not going to
    repeat that on its first commit.
    """
    downstream = guard.cascade
    if downstream is None or not guard.spec.lineage_field:
        return None
    decoded = decode_op_msg(raw)
    if decoded is None:
        return None
    _flags, body = decoded
    if body.get("findAndModify") != guard.collection or not body.get("remove"):
        return None
    pipeline = _forget_pipeline(guard.spec, "derived from a fact deleted "
                                            "via voyd-wire")
    if not pipeline:
        return None
    query = body.get("query", {})
    # `findAndModify` with a `sort` means the caller cares which one, so the
    # resolution has to honour it or the cascade and the revocation pick
    # different documents -- the same defect `pins` exists to prevent.
    ids = await downstream.resolve(database, guard, query, one=True,
                                sort=body.get("sort"))
    guard.cascaded += await downstream.mark_descendants(
        database, guard, ids, pipeline, query)
    return ids


async def derive_on_insert(raw: bytes, req_id: int, resp_to: int,
                           guards: dict[str, Guard], verbose: bool
                           ) -> tuple[bytes, bytes | None]:
    """An insert that says what it was made out of, made to mean it.

    This is the other half of the claim, and without it the first half is
    a demo. ``cascade_first`` reaches everything carrying an id in
    ``lineage``, in one ``$in``, at any depth -- but only because the
    ancestry stored on each document is *transitively closed*. A client
    that writes ``{"lineage": [summary_id]}`` and nothing else has written
    a grandchild the cascade cannot see, and the erasure that looked
    complete stops one generation short. Silently.

    So the boundary closes it, from the field the application already
    writes. Nothing has to be called for the ancestry to be right, which is
    the only version of this that holds: a closure somebody has to remember
    to perform is one that is correct until the first write that forgets.

    Two things happen here, and refusing is the first:

    - a parent that is missing, out of scope, or already refused fails the
      insert. You cannot legitimately derive a new fact from one that may
      not reach a prompt, and writing the child and marking it in the same
      breath would hide the race that got you here.
    - a surviving insert has its ``lineage`` replaced by the closure and
      its deadline pulled back to the earliest among its parents.

    Returns ``(bytes, refusal)``: the command to forward, and an error to
    answer with instead if there is one.
    """
    decoded = decode_sections(raw)
    if decoded is None:
        return raw, None
    flags, body, ident, docs = decoded
    name = body.get("insert")
    guard = guards.get(name) if isinstance(name, str) else None
    if guard is None or ident != "documents" or not docs:
        return raw, None
    downstream, field = guard.cascade, guard.spec.lineage_field
    if downstream is None or not field:
        return raw, None
    if not any(isinstance(d.get(field), (list, tuple)) and d.get(field)
               for d in docs):
        return raw, None                      # ordinary inserts, untouched

    database = body.get("$db", "")
    at = guard.spec.at_field
    prepared = []
    for doc in docs:
        parents = doc.get(field)
        if not isinstance(parents, (list, tuple)) or not parents:
            prepared.append(doc)
            continue
        closure, deadlines, broken = await downstream.parentage(
            database, guard, list(parents), doc)
        if broken:
            return raw, _refuse(
                req_id, guard.collection,
                f"this document says it was derived from "
                f"{', '.join(broken)}, which cannot be reached -- missing, "
                f"out of scope, or already refused. A fact made out of a "
                f"fact that may not reach a prompt may not either",
                verbose)
        row = dict(doc)
        row[field] = closure
        if deadlines:
            own, soonest = row.get(at), min(deadlines)
            # Never overwrite a shorter one the caller set deliberately.
            row[at] = (min(own, soonest) if hasattr(own, "timestamp")
                       else soonest)
        prepared.append(row)

    if verbose:
        print(f"  voyd: {guard.collection}: closed the lineage on "
              f"{len(prepared)} derived document(s), so a revocation of any "
              f"ancestor reaches them in one query", flush=True)
    return encode_sections(req_id, resp_to, flags, body, ident,
                           prepared), None


def seal_refusal(req_id: int, resp_to: int, why: str) -> bytes:
    """Answer a write this boundary will not seal, without forwarding it.

    The error goes straight back and the server never sees the command, so
    the plaintext never leaves this process. A refused write is loud,
    harmless and fixable; a forwarded one is silent, permanent and already
    in the backup.
    """
    print(f"  voyd: REFUSED a write it cannot seal: {why}", flush=True)
    return encode_op_msg(req_id, resp_to, 0, {
        "ok": 0.0, "code": 8000, "codeName": "AtlasError",
        "errmsg": f"voyd-wire refuses this write: {why}",
    })


async def judge(raw: bytes, req_id: int, resp_to: int,
                guards: dict[str, Guard], verbose: bool,
                vault: "seal.Vault | None",
                meter: "metrics.Meter | None" = None,
                caller: dict | None = None,
                budgets: "Budgets | None" = None) -> bytes:
    """`enforce`, plus decryption for the collections that declared it.

    **The fast path is byte-for-byte the old one.** With no `--key-vault`,
    or on a collection nobody sealed, this is one dictionary lookup and
    then `enforce` -- still pure, still `bytes -> bytes`, still about 2.3
    microseconds per document. That matters because sealing is opt-in per
    collection and a deployment that seals one of twelve should pay for
    one of twelve.

    **The sealed path decrypts before it refuses, and the order is not a
    preference.** It is the order `Admission._unsealed` uses, and the two
    have to agree or one document would get two verdicts. It also costs
    something real: a
    rule that reads a sealed field is reading plaintext, which it could not
    do if refusal ran first, and a document refused by a deadline has still
    been decrypted by the time the deadline sees it. Decrypting something
    that is then refused is wasted work, not a leak -- it never leaves this
    process -- but it is wasted work worth naming.
    """
    if vault is None:
        return enforce(raw, req_id, resp_to, guards, verbose, caller, budgets)

    peek = decode_op_msg(raw, LAZY)
    if peek is None:
        return raw
    collection = _collection_of(peek[1])
    if not vault.seals(collection):
        return enforce(raw, req_id, resp_to, guards, verbose, caller, budgets)

    # Eager, unlike the fast path: these documents are about to be rebuilt
    # with a decrypted field in them, so there is no forwarding the bytes
    # they arrived in and nothing to be lazy for.
    decoded = decode_op_msg(raw)
    if decoded is None:
        return raw
    flags, reply = decoded
    cursor = reply.get("cursor")
    if not isinstance(cursor, Mapping):
        return raw
    key = "firstBatch" if "firstBatch" in cursor else (
        "nextBatch" if "nextBatch" in cursor else None)
    if key is None:
        return raw
    batch = cursor[key]
    if not isinstance(batch, list) or not batch:
        return raw

    assert collection is not None
    guard = guards.get(collection)
    plain, tally = await vault.unseal(batch, collection)
    if meter is not None:
        meter.sealed_reads_total += len(batch)
    if guard is not None:
        if tally:
            guard.note_sealed(tally)
        cursor_id = cursor.get("id")
        tab = (budgets.tab_for(guard, cursor_id) if budgets is not None
               else _FRESH_TAB)
        kept = guard.filter(plain, caller, tab)
        if budgets is not None and cursor_id == 0:
            budgets.done(cursor_id)
    else:
        kept = plain

    reply = dict(reply)
    reply["cursor"] = dict(cursor)
    reply["cursor"][key] = kept
    if verbose and (tally or len(kept) != len(batch)):
        named = guard.reasons() if guard is not None else tally
        print(f"  voyd: {collection}: refused {len(batch) - len(kept)} of "
              f"{len(batch)}  {named}", flush=True)
    return encode_op_msg(req_id, resp_to, flags, reply)
