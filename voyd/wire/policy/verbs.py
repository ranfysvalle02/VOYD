"""Rewrite a command. What a verb is allowed to mean here.

One verb carries almost all of this: a client's `delete` becomes the
revocation it should have been -- the row marked, unreachable on the next
read, still on disk, its deadline pulled in so the reaper collects it on
the schedule it already had. Opt-in, because silently redefining `delete`
for an operator who did not ask is the surprise this package exists to
remove.

Both spellings are covered, because they are different wire commands and
covering one is worse than covering neither: `deleteOne`/`deleteMany`
arrive as `delete`, and `findOneAndDelete` as `findAndModify`, which also
hands the caller the document back.

`_forget_pipeline` is the single spelling of "forgotten" the two share --
and that `erasure.py` shares with them. Two spellings that produced
different documents would be exactly the drift this package is about.
"""

from __future__ import annotations

from voyd.engine.time import now

from ..codec import (decode_op_msg, decode_sections, encode_op_msg,
                     encode_sections)
from .guarding import Guard
from .refusals import _refuse


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
    `tests/test_the_codebase_tells_the_truth_about_itself.py` is what
    holds them to it: two
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
