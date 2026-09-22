"""Refuse a command outright. The verbs no rewrite is narrow enough to cover.

A guarantee that holds for three verbs out of four is the silent hole this
package is named after, so these say no, out loud, with a reason a driver
raises.

`drop`, `dropDatabase` and `renameCollection` take the marks with them and
leave no evidence anything was ever forgotten. `$out` and `$merge` are
sharper still, because they do not *look* destructive: the copy happens
inside the server and the documents never come back to the client, so
nothing on the read path is ever handed one to refuse. Measured before it
was closed, a refused document copied itself out of the policy's reach
through a connection that had just declined to show it.

A proxy cannot make those safe. It can only decline them, which is what
this module is.

`_refuse` lives here rather than beside any one caller: an error a client
raises is itself a refusal, and three different decisions build one.
"""

from __future__ import annotations

from typing import Mapping

from ..codec import LAZY, decode_op_msg, encode_op_msg
from .guarding import Guard, guard_for


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
    # wearing the costume of a network one, which is the most expensive
    # shape a defect here can take.
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
