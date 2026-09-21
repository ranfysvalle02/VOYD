"""The example policy file. This is the whole of what a team writes.

Their application is not edited: no import added, no handle wrapping a
collection, no read path rewritten. The connection string changes, and a
forgotten fact stops being reachable from any driver in any language.
"""

from voyd import deadline, guard, revocable, tenant


@guard("notes")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()
