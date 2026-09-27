"""Create what the policy file declares. The other half of `--verify`.

`--verify` asks the cluster whether it matches the policy and creates
nothing. This is the same declaration read the same way, pointed the other
direction -- and the pair is the point, because the thing that makes a
declaration trustworthy is that one process builds it and another, written
separately, refuses to agree until it is there.

That symmetry is a checkable claim rather than a design note:
**`--ensure` then `--verify` is clean**, and
The examples run exactly that
sequence against a real `mongod`. If the two ever drift, one of them is
wrong and the pair says so.

Why it lives beside the proxy. One artifact declares the policy and the
same artifact builds what the policy depends on. Splitting those -- a
boundary that can enforce every word of a file and not create a single
index it needs -- is the seam this repository keeps finding defects in.

**It is the one mode that writes.** Everything else this proxy does is
either pure or a rewrite of somebody else's bytes; `--ensure` issues
`createIndex`, `createSearchIndex` and `createCollection` with the
operator's own credentials, then closes the connection before the listener
binds. Said plainly because "holds no database connection of its own" is a
property this file makes conditional, and a property with an exception
nobody wrote down is not one.
"""

from __future__ import annotations

from typing import Any, Mapping

# Nothing here re-implements a schema. Each of these knows how to build
# its own, so what this module contributes is the orchestration and the
# translation from a policy file's vocabulary into theirs. Two spellings
# of `createSearchIndex` is exactly the drift being avoided.
from voyd.engine.capabilities import detect
from voyd.engine.expiry import Expiry, ExpirySpec
from voyd.engine.search import SearchEngine, SearchSpec

from .policy.prefilter import index_declares, prefilter_fields


def search_specs(guards: Mapping, options: Mapping) -> dict[str, SearchSpec]:
    """A `SearchSpec` per collection the policy asks the server to embed.

    Only `auto_embed` collections get one, and that is deliberate. A vector
    index over a field this process cannot see is a guess about a
    dimensionality and a similarity nobody declared -- and a wrong guess
    builds an index that ranks confidently in the wrong space, which is the
    failure `auto_embed` exists to remove. When the server owns the
    encoding there is nothing to guess: the model names the dimensions.
    """
    out: dict[str, SearchSpec] = {}
    for name, guard in guards.items():
        opts = options.get(name) or {}
        embedded: dict = dict(opts.get("auto_embed") or {})
        if not embedded:
            continue
        # `auto_embed` is declared per *field*: the path the server reads.
        path, model = next(iter(embedded.items()))
        tenant = getattr(guard.spec, "tenant", None)
        extra: tuple[str, ...] = ()
        if opts.get("prefilter"):
            fields = prefilter_fields(guard)
            if fields is None:
                raise ValueError(
                    f"{name}: prefilter=True, and a rule's clause is not one "
                    f"a $vectorSearch filter accepts. Nothing is declared "
                    f"on the index for it")
            extra = tuple(f for f in fields if f != tenant)
        out[name] = SearchSpec(
            collection=name,
            text_paths=(path,),
            auto_embed=model,
            tenant_field=tenant,
            # A tenant id in a policy file is a string field far more often
            # than an ObjectId, and the lexical leg rejects the query when
            # the declared type does not match what is stored. `token` is
            # the one that is right for the ids people actually put in a
            # voydfile; an ObjectId tenant wants `tenant_type='objectId'`.
            tenant_type="token" if tenant else "objectId",
            # The fields the rules read, as `filter` fields on the vector
            # index, when -- and only when -- the policy asked for the
            # prefilter. Declared here, they are also what `drifted()`
            # compares, so an index built without them is stale.
            filter_fields=extra,
        )
    return out


def expiry_specs(guards: Mapping) -> list[ExpirySpec]:
    """A TTL policy per declared `deadline()`.

    The reaper is not the guarantee -- refusal is, and it is immediate --
    but a deadline with no TTL index behind it means the bytes stay
    forever, which is the half of erasure refusal cannot do.
    """
    out = []
    for name, guard in guards.items():
        at = next((getattr(r, "at_field", None) for r in guard.spec.rules
                   if type(r).__name__ == "Deadline"), None)
        if at:
            out.append(ExpirySpec(collection=name, at_field=at))
    return out


async def provision(uri: str, database: str, guards: Mapping,
                    options: Mapping, *, wait_s: float = 90.0) -> list[str]:
    """Build every schema the policy declares. Returns report lines.

    Idempotent, and safe on every boot -- each underlying `ensure()` is
    already written that way, because the alternative is a deployment step
    people are afraid to re-run.
    """
    from pymongo import AsyncMongoClient

    lines: list[str] = []
    client: Any = AsyncMongoClient(uri, serverSelectionTimeoutMS=8000,
                                   connectTimeoutMS=8000)
    try:
        db = client[database]
        caps = await detect(client, db)
        lines.append(f"  voyd: {caps.describe()}")

        # A search index cannot be created on a collection that does not
        # exist, and a policy file is usually written before any data is.
        # Creating them first turns "run it again after you write a
        # document" into a step nobody has to know about.
        existing = set(await db.list_collection_names())
        for name in sorted(guards):
            if name not in existing:
                await db.create_collection(name)
                lines.append(f"  voyd: {name}: created the collection")

        expiry = Expiry(db)
        for ttl in expiry_specs(guards):
            expiry.register(ttl)
        if expiry.specs:
            applied = await expiry.ensure()
            for ttl in expiry.specs:
                lines.append(f"  voyd: {ttl.collection}: TTL on "
                             f"{ttl.at_field!r}")
            if applied != len(expiry.specs):
                lines.append(f"  voyd: {applied} of {len(expiry.specs)} TTL "
                             f"indexes applied -- see the log above")

        # The tenant index. `--verify` demands an index *leading with* the
        # tenant, because a scan that filters the tenant after the fact is
        # a scan that read another tenant's rows to discard them.
        for name, guard in sorted(guards.items()):
            tenant = getattr(guard.spec, "tenant", None)
            if tenant:
                await db[name].create_index(tenant)
                lines.append(f"  voyd: {name}: index leading with "
                             f"{tenant!r}")

        specs = search_specs(guards, options)
        if specs and not caps.search:
            lines.append("  voyd: this deployment has no mongot, so the "
                         "auto_embed declarations were not built. Refusal "
                         "does not depend on them; ranking does")
        elif specs:
            engine = SearchEngine(db=db, capabilities=caps, specs=specs)
            ready = await engine.ensure_indexes(wait_s=wait_s)
            # What happened, not what was asked for. `ensure_indexes`
            # accepts "no" from a deployment that cannot embed and builds a
            # client-vector index instead -- correct behaviour, and
            # reporting the declaration over it would make this line
            # confidently wrong in the one place an operator is reading to
            # find out. The first run of this code did exactly that, and
            # `--verify` is what caught it.
            declined: set[str] = getattr(
                engine, "auto_embed_declined", set())
            for name, search in sorted(specs.items()):
                if name in declined:
                    lines.append(
                        f"  voyd: {name}: this deployment declined "
                        f"auto_embed({search.auto_embed!r}), so the index "
                        f"built is an ordinary vector index and the "
                        f"application must supply the vector -- which this "
                        f"boundary refuses. Run --verify: it is a "
                        f"contradiction, not a degradation")
                    continue
                lines.append(f"  voyd: {name}: vector index on "
                             f"{search.text_paths[0]!r}, embedded by the "
                             f"server with {search.auto_embed!r}")
            if not ready:
                lines.append("  voyd: the index was created and is not "
                             "queryable yet. mongot builds asynchronously, "
                             "and a query against a half-built index "
                             "returns no rows rather than an error")
        return lines
    finally:
        await client.close()


async def confirm_prefilter(uri: str, database: str, guards: Mapping,
                            options: Mapping) -> list[str]:
    """Switch the prefilter on where the live index can answer it.

    Read-only: one `$listSearchIndexes` per opted-in collection. A guard
    gets `prefilter_index` only when the live vector index declares every
    field the rules read as a `filter` field. Anything else -- no index, a
    drifted one built before the opt-in, a probe that failed -- leaves it
    `None`, and the boundary forwards `$vectorSearch` exactly as sent.
    """
    from pymongo import AsyncMongoClient

    wanted = {n: g for n, g in guards.items()
              if (options.get(n) or {}).get("prefilter")}
    if not wanted:
        return []
    specs = search_specs(wanted, options)
    lines: list[str] = []
    client: Any = AsyncMongoClient(uri, serverSelectionTimeoutMS=8000,
                                   connectTimeoutMS=8000)
    try:
        db = client[database]
        for name, guard in sorted(wanted.items()):
            spec = specs[name]
            needed = spec.filterable()
            try:
                live = {i["name"]: i async for i
                        in await db[name].list_search_indexes()}
            except Exception as exc:                          # noqa: BLE001
                lines.append(f"  voyd: {name}: prefilter off -- the search "
                             f"indexes could not be read "
                             f"({type(exc).__name__})")
                continue
            index = live.get(spec.vector_index) or {}
            if index_declares(index.get("latestDefinition"), needed):
                guard.prefilter_index = spec.vector_index
                lines.append(f"  voyd: {name}: prefilter on -- "
                             f"{spec.vector_index} declares "
                             f"{', '.join(needed)}; the reply is still "
                             f"judged on the way out")
            else:
                lines.append(f"  voyd: {name}: prefilter off -- "
                             f"{spec.vector_index} does not declare "
                             f"{', '.join(needed)} as filter fields. A "
                             f"vectorSearch index cannot be updated in "
                             f"place: declare a new vector_index or drop "
                             f"and rebuild it")
        return lines
    finally:
        await client.close()
