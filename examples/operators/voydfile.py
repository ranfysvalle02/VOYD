"""A policy file that installs the whole `voyd.contrib` library. Copy it.

    voyd-wire --config examples/operators/voydfile.py --target localhost:27017

Then any driver can use `$redactPII`, `$chunk`, `$bm25`, `$mmr`,
`$contextPack`, `$cite` and the rest in an ordinary `aggregate` on the
collections guarded below. Every one runs in the boundary, on the
documents this policy admitted, and never calls a model.

Install less by naming it -- `text.install("$redactPII")` -- and keep your
own `@stage` / `@operator` functions in the same file; a name declared twice
fails the load, so a clash is found before the proxy listens. Running this
file directly only registers the names and exits.
"""

from voyd import deadline, guard, mask, revocable, tenant
from voyd.contrib import context, rank, text

text.install()        # $redactPII $chunk $wordCount $tokenEstimate
                      # $truncate $highlight $normalizeWhitespace
rank.install()        # $bm25 $mmr $dedupe $freshness $rrf
context.install()     # $contextPack $cite $stats


@guard("docs")
class Docs:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()


@guard("tickets")
class Tickets:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()
    card_number = mask()
