"""The example policy file. This is the whole of what a team writes.

Their application is not edited: no import added, no handle wrapping a
collection, no read path rewritten. The connection string changes, and a
forgotten fact stops being reachable from any driver in any language.

``on_delete="revoke"`` is the other half. Every `deleteOne` already in their
code stops being a wish and becomes a contract: unreachable on the next read,
row still on disk for the investigation, deadline pulled in so the reaper
collects it on the schedule it already had.
"""

from voyd import deadline, guard, revocable


@guard("notes", on_delete="revoke")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
