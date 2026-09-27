"""A short `$vectorSearch` page, filled from further down the ranking.

The egress check drops refused documents from a batch, which is the
guarantee -- and it means `limit: 10` over a collection where eight of the
ten nearest are expired returns two. The caller asked for ten admissible
neighbours and got a page shaped by how much of the index is dead.

Deadlines are not pushed into the vector index (see `voyd/engine/search.py`
for why), so the index cannot skip the refused rows itself. What the proxy
can do is ask for more and hand back fewer:

1. **Request.** A lone `$vectorSearch` on a guarded collection has its
   `limit` multiplied by the guard's `backfill` factor, and `numCandidates`
   with it, both capped at `CEILING` (the most Atlas accepts). The limit
   the client asked for is remembered against the request id.
2. **Reply.** The batch is judged exactly as before -- transforms, then the
   per-document check -- and only *then* cut to what is still owed. The
   cursor carries the remainder, so a client with a small `batchSize` gets
   the same page across `getMore`s that it would get in one batch.

Why this shape and not a retry on a short page: a retry is a second query
the client did not send, with its own latency and a cursor that has to be
stitched onto the first one. Over-fetching is one query, and the only thing
the proxy adds on the way back is a *truncation*. Truncation can remove a
document and cannot introduce one, so the terminal egress pass is still the
last word on every document the client sees and nothing here can widen a
read.

Ordering is the server's: the batch is a score-ordered list, the check
keeps order, and the cut keeps a prefix. A transform (a reranker) sees the
wider page and may reorder it; the cut then takes the first ``limit`` of
*its* order, which is what a reranker over a candidate pool is for.

Left alone, on purpose:

- **A pipeline with any stage after `$vectorSearch`.** `$match`, `$sort`,
  `$skip`, `$limit` and `$sample` all answer a different question over
  forty candidates than over ten, and a reduction (`$group`, `$project`,
  `$count`) is already rewritten by `reads.py`. Only the lone stage has a
  meaning that over-fetching preserves: "the nearest ``limit`` documents".
- **A limit already at the ceiling**, where there is nothing to widen.
- **A factor of 1**, which is how a policy turns this off.

Bounded, and still able to come back short: if more than
``(factor - 1) / factor`` of the widened page is refused, the client gets
fewer than it asked for, exactly as it would have with no backfill. The
factor is the amplification, and it is paid on every lone vector search
against the collection whether or not anything is refused.
"""

from __future__ import annotations

from typing import Any, Mapping

from ..codec import LAZY, decode_op_msg, encode_op_msg
from .guarding import Guard, guard_for

# The factor lives on the `Guard`, declared by `@guard(..., backfill=N)`.
# Four is the default: a collection with three quarters of its nearest
# neighbours refused still fills. Twenty is the most `declare.py` accepts,
# and a policy asking for more is told so at load time rather than clamped.
# Atlas refuses `numCandidates` above ten thousand, and `limit` may not
# exceed `numCandidates`, so neither is ever widened past this.
CEILING = 10_000


def _count(value: Any) -> int | None:
    # `bool` is an `int`, and `limit: true` is the client's bug to hear
    # about from the server rather than ours to read as one.
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return None
    return value


def overfetch(body: Mapping, guards: dict[str, Guard]
              ) -> tuple[dict, int] | None:
    """`(widened_body, owed)` for a lone `$vectorSearch`, else `None`.

    ``owed`` is the client's own `limit`: what the reply is cut back to
    after the refused rows are gone.
    """
    guard = guard_for(guards, body, "aggregate")
    if guard is None or guard.backfill <= 1:
        return None
    pipeline = body.get("pipeline")
    if not isinstance(pipeline, list) or len(pipeline) != 1:
        return None
    stage = pipeline[0]
    if not isinstance(stage, Mapping) or list(stage) != ["$vectorSearch"]:
        return None
    search = stage["$vectorSearch"]
    if not isinstance(search, Mapping):
        return None
    limit = _count(search.get("limit"))
    if limit is None or limit >= CEILING:
        return None

    wide = dict(search)
    wide["limit"] = min(limit * guard.backfill, CEILING)
    if search.get("exact") is not True:
        candidates = _count(search.get("numCandidates"))
        if candidates is None:
            return None             # malformed; the server says so, unwidened
        wide["numCandidates"] = min(max(candidates * guard.backfill,
                                        wide["limit"]), CEILING)
    patched = dict(body)
    patched["pipeline"] = [{"$vectorSearch": wide}]
    return patched, limit


def cut(raw: bytes, req_id: int, resp_to: int,
        owed: int) -> tuple[bytes, int, int]:
    """`(reply, still_owed, cursor_id)` -- the batch cut to ``owed``.

    Run on a reply that has *already* been judged. The bytes are untouched
    when the batch fits, which is the case on every page where the refused
    rows made room for the rest.
    """
    decoded = decode_op_msg(raw, LAZY)
    if decoded is None:
        return raw, owed, 0
    flags, reply = decoded
    cursor = reply.get("cursor")
    if not isinstance(cursor, Mapping):
        return raw, owed, 0
    key = "firstBatch" if "firstBatch" in cursor else (
        "nextBatch" if "nextBatch" in cursor else None)
    cursor_id = cursor.get("id")
    cursor_id = cursor_id if isinstance(cursor_id, int) else 0
    batch = cursor[key] if key else None
    if not isinstance(batch, list):
        return raw, owed, cursor_id
    if len(batch) <= owed:
        return raw, owed - len(batch), cursor_id
    reply = dict(reply)
    reply["cursor"] = dict(cursor)
    reply["cursor"][key] = batch[:owed]
    return encode_op_msg(req_id, resp_to, flags, reply), 0, cursor_id


class Backfill:
    """What each widened read still owes the client, per connection.

    Keyed by request id until the first reply names a cursor, then by the
    cursor, and matched on the `getMore` *request* for the same reason
    `_was_reduced` does: the reply that drains a cursor says `id: 0`.
    """

    __slots__ = ("_requests", "_cursors")

    def __init__(self) -> None:
        self._requests: dict[int, int] = {}
        self._cursors: dict[int, int] = {}

    def widen(self, body: Mapping, guards: dict[str, Guard],
              req_id: int) -> dict | None:
        """The widened command to send instead, or `None` to send as is."""
        made = overfetch(body, guards)
        if made is None:
            return None
        patched, owed = made
        self._requests[req_id] = owed
        return patched

    def continuing(self, cursor_id: Any, req_id: int) -> None:
        """A `getMore` on a widened cursor owes what the cursor still owes."""
        if isinstance(cursor_id, int) and cursor_id in self._cursors:
            # Popped, and put back by `settle` only while the server
            # still reports the cursor open -- so a drained one leaves
            # nothing behind on a long-lived connection.
            self._requests[req_id] = self._cursors.pop(cursor_id)

    def forget(self, cursor_ids: Any) -> None:
        """A client abandoned these cursors with `killCursors`."""
        if isinstance(cursor_ids, list):
            for cid in cursor_ids:
                if isinstance(cid, int):
                    self._cursors.pop(cid, None)

    def settle(self, raw: bytes, req_id: int, resp_to: int) -> bytes:
        """Cut a judged reply to what its read still owes."""
        owed = self._requests.pop(resp_to, None)
        if owed is None:
            return raw
        raw, left, cursor_id = cut(raw, req_id, resp_to, owed)
        if cursor_id:
            self._cursors[cursor_id] = left
        return raw

