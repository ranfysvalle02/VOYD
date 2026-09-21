#!/usr/bin/env python3
"""Ask the deployment whether it matches the declaration.

A policy file is a set of claims about a cluster this process does not own:
*there is a TTL index on `expire_at`*, *the vector index embeds `body` with
voyage-3*, *the sealed fields are refused as plaintext by the server*. Every
one of those can be false, and when one is false nothing says so -- the
boundary keeps enforcing a policy that the storage underneath it is not
holding up.

`capabilities.py` exists because of exactly this shape of mistake, and its
docstring is the argument for this file:

    Atlas support used to be inferred from the connection string ... Every
    local run silently used a fallback path and `$vectorSearch` never
    executed at all, for months, without a single log line. Asking the
    server is the only honest question.

    A version floor is a claim about software this package does not ship,
    with no expiry and nobody responsible for it.

`auto_embed("voyage-3")` in a voydfile is a claim about software this package
does not ship, with no expiry and nobody responsible for it. So it is asked
rather than assumed.

## Read-only, and that is the whole design

This module issues `listIndexes`, `$listSearchIndexes` and `listCollections`.
It creates nothing, alters nothing and drops nothing.

That distinction is load-bearing, because conflating it with the *other*
thing -- creating the index from the declaration -- is what kept this from
being written for a while. Creating an index is a schema change against
somebody else's cluster and deserves the caution. Reading one back is a
query. The risk of the first is not a reason to skip the second, and
`LIMITS.md` §5 used to say otherwise.

## What it does not become

**A connection held for the life of the process.** `--key-vault` spends that
property deliberately and says so in capitals; this does not spend it at all.
The probe opens a client, asks its questions, closes it, and is finished
before the listener accepts anything. The purity claim in the README is about
the *read path*, and nothing here is on it.

**A reason a deploy fails when the cluster hiccups.** Unreachable is not
misconfigured. They look identical from here and mean opposite things -- the
same distinction `keyring.why_undecryptable` exists to make -- so a probe
that cannot run says why and the boundary starts anyway. Refusing to boot
because a replica was electing would be this file causing more outages than
it prevents.

## Severity is not decoration

**Fatal** is reserved for a declaration that *contradicts* what is there,
because the boundary will then enforce a policy the cluster cannot satisfy
and it will do it one query at a time. A collection declared
`auto_embed("voyage-3")` whose index is an ordinary vector index is the clear
case: every client-supplied `queryVector` is refused -- correctly, by the
declaration -- against an index that has no other way to be queried. That is
a total outage for that collection, discovered by users, and it is better to
not start and say which line of the policy file is wrong.

**Warn** is for a declaration nothing contradicts but nothing implements: a
deadline with no TTL index behind it, a tenant with no index to find it by, a
sealed field the server will still accept plaintext into. Refusal keeps
working in all three. What is missing is the layer *underneath* refusal, and
that is worth a line on stdout rather than a failed deploy -- not least
because a deployment that has been running like that for a month should not
have its next restart blocked by this file noticing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

FATAL = "fatal"
WARN = "warn"


@dataclass(frozen=True)
class Finding:
    """One disagreement between the policy file and the cluster.

    Carries a remedy because a check that reports a problem and not its fix
    is a check somebody disables. `voyd-wire` prints both.
    """

    collection: str
    check: str
    severity: str
    detail: str
    remedy: str

    def line(self) -> str:
        mark = "FATAL" if self.severity == FATAL else "warning"
        return (f"voyd-wire: preflight {mark} [{self.collection}."
                f"{self.check}]: {self.detail}\n"
                f"           remedy: {self.remedy}")


@dataclass(frozen=True)
class Declared:
    """What one collection's policy claims about the storage under it."""

    collection: str
    deadline: str | None = None
    tenant: str | None = None
    sealed: tuple[str, ...] = ()
    auto_embed: Mapping[str, str] | None = None


# --------------------------------------------------------------------------
# The analysis. Pure: dicts in, findings out, no database anywhere near it.
#
# Same discipline as `reachable()` and `client_vector_on_server_index`, and
# for the same reason -- the part that decides is testable against the exact
# index listing a cluster would have returned, including the shapes nobody
# has a cluster handy to produce.
# --------------------------------------------------------------------------

def _ttl_index(indexes: Iterable[Mapping], field: str) -> Mapping | None:
    for index in indexes:
        key = index.get("key") or {}
        if field in key and "expireAfterSeconds" in index:
            return index
    return None


def _leads_with(indexes: Iterable[Mapping], field: str) -> bool:
    """Is `field` the *first* key of some index?

    First rather than present: an index on `(other, tenant_id)` cannot serve
    a query that only knows the tenant, so counting it would report coverage
    that does not exist.
    """
    for index in indexes:
        key = list((index.get("key") or {}).keys())
        if key and key[0] == field:
            return True
    return False


def _auto_embed_fields(search_indexes: Iterable[Mapping]) -> list[Mapping]:
    out = []
    for index in search_indexes:
        definition = index.get("latestDefinition") or index.get("definition")
        for field in (definition or {}).get("fields") or ():
            if isinstance(field, Mapping):
                out.append(field)
    return out


def audit(declared: Declared, *, indexes: Iterable[Mapping],
          search_indexes: Iterable[Mapping],
          validator: Mapping | None,
          exists: bool = True,
          check_embedding: bool = True) -> list[Finding]:
    """Every way this collection's storage disagrees with its policy.

    ``check_embedding=False`` says the caller could not read the search
    indexes, which is not the same as reading them and finding none -- the
    first is ignorance and the second is a contradiction. Without the
    distinction a deployment with no mongot would be told its `auto_embed`
    declaration was fatally wrong, which is both false and the loudest
    possible way to be false.
    """
    indexes = list(indexes)
    search_indexes = list(search_indexes)
    found: list[Finding] = []

    if not exists:
        # Not fatal. A boundary in front of a collection nobody has written
        # to yet is an ordinary first deploy, and MongoDB creates it on the
        # first insert -- at which point none of the indexes below exist
        # either, which is what the warnings are for.
        found.append(Finding(
            declared.collection, "exists", WARN,
            "the policy guards this collection and it does not exist yet, "
            "so none of the checks below could run",
            "write to it, or check the name against the policy file for a "
            "typo -- a guard on a misspelled collection refuses nothing and "
            "looks identical to one that works"))
        return found

    if declared.deadline:
        if _ttl_index(indexes, declared.deadline) is None:
            found.append(Finding(
                declared.collection, "deadline", WARN,
                f"deadline() names {declared.deadline!r} and there is no TTL "
                f"index on it. Refusal still works -- an expired fact is "
                f"unreachable on the next read -- but nothing ever reclaims "
                f"the bytes, so this collection grows without bound",
                f'db.{declared.collection}.createIndex('
                f'{{"{declared.deadline}": 1}}, {{expireAfterSeconds: 0}})'))

    if declared.tenant and not _leads_with(indexes, declared.tenant):
        found.append(Finding(
            declared.collection, "tenant", WARN,
            f"tenant() names {declared.tenant!r} and no index leads with it, "
            f"so every guarded read scans the collection. Correct, and it "
            f"will not stay fast",
            f'db.{declared.collection}.createIndex('
            f'{{"{declared.tenant}": 1}})'))

    embedding_claims = (declared.auto_embed or {}) if check_embedding else {}
    for field, model in embedding_claims.items():
        embedded = _auto_embed_fields(search_indexes)
        mine = [f for f in embedded if f.get("path") == field
                and f.get("type") == "autoEmbed"]
        if not search_indexes:
            found.append(Finding(
                declared.collection, "auto_embed", FATAL,
                f"auto_embed({model!r}) on {field!r} and this collection has "
                f"no search index at all. The boundary refuses every "
                f"client-supplied queryVector here, and there is no "
                f"server-side encoding to query instead -- so vector search "
                f"on this collection cannot succeed by any route",
                "create the vector index with a field of type 'autoEmbed', "
                "or drop auto_embed() from the policy and let clients supply "
                "their own vectors"))
        elif not mine:
            found.append(Finding(
                declared.collection, "auto_embed", FATAL,
                f"auto_embed({model!r}) on {field!r} but no search index "
                f"declares an 'autoEmbed' field on that path. The index "
                f"present needs a client-supplied vector and the boundary "
                f"refuses exactly those, so every vector read here is an "
                f"error",
                f"either add an autoEmbed field on {field!r} to the search "
                f"index, or remove auto_embed() from the policy -- the "
                f"declaration and the index have to name the same owner"))
        else:
            wrong = [f.get("model") for f in mine if f.get("model") != model]
            if wrong:
                found.append(Finding(
                    declared.collection, "auto_embed", FATAL,
                    f"auto_embed({model!r}) on {field!r} but the index "
                    f"embeds it with {wrong[0]!r}. An embedding is a "
                    f"(vector, model) pair and comparing across two models "
                    f"does not fail -- it returns a confident score for the "
                    f"wrong documents, which is the failure this "
                    f"declaration exists to prevent",
                    f"make them agree: change the policy to "
                    f"auto_embed({wrong[0]!r}), or rebuild the index with "
                    f"{model!r} and re-embed what is already stored"))

    if declared.sealed:
        required = _binary_fields(validator)
        missing = [f for f in declared.sealed if f not in required]
        if missing:
            found.append(Finding(
                declared.collection, "sealed", WARN,
                f"sealed() names {', '.join(repr(f) for f in missing)} and "
                f"the collection has no validator requiring them to be "
                f"binData. Writes through this boundary are encrypted; a "
                f"writer that connects straight to the cluster can still "
                f"store plaintext, and that write succeeds silently and is "
                f"in the next backup",
                f"db.runCommand({{collMod: {declared.collection!r}, "
                f"validator: {{$jsonSchema: {{bsonType: 'object', "
                f"properties: {{" + ", ".join(
                    f"{f}: {{bsonType: 'binData'}}" for f in missing)
                + "}}}}) -- the same validator Keyring.enforce() installs "
                  "for the in-process path"))
    return found


def _binary_fields(validator: Mapping | None) -> set[str]:
    """Which fields a `$jsonSchema` validator pins to `binData`."""
    schema = (validator or {}).get("$jsonSchema") or {}
    out = set()
    for name, spec in (schema.get("properties") or {}).items():
        if isinstance(spec, Mapping) and spec.get("bsonType") == "binData":
            out.add(name)
    return out


def declarations(guards: Mapping, options: Mapping) -> list[Declared]:
    """What every guarded collection claims, from the loaded policy.

    Read off the compiled rules rather than re-parsing the file, so the
    thing being verified is the thing the boundary will actually enforce.
    """
    out = []
    for name, guard in guards.items():
        opts = options.get(name) or {}
        at = next((getattr(r, "at_field", None) for r in guard.spec.rules
                   if type(r).__name__ == "Deadline"), None)
        out.append(Declared(
            collection=name,
            deadline=at,
            tenant=getattr(guard.spec, "tenant", None),
            sealed=tuple(opts.get("sealed") or ()),
            auto_embed=dict(opts.get("auto_embed") or {})))
    return sorted(out, key=lambda d: d.collection)


# --------------------------------------------------------------------------
# The I/O. Three read-only commands, then the client is closed.
# --------------------------------------------------------------------------

async def inspect(uri: str, database: str,
                  declared: Iterable[Declared]) -> tuple[list[Finding], str | None]:
    """``(findings, why_it_could_not_run)``.

    The second element is the honest half. A probe that failed and a cluster
    that is correctly configured both produce an empty finding list, and
    reporting them the same way would make this file worse than absent --
    "preflight found nothing" on a run where preflight never happened is the
    exact shape of confidently-wrong this project is named after.
    """
    try:
        from pymongo import AsyncMongoClient
    except ImportError as exc:                      # pragma: no cover
        return [], f"pymongo is not importable ({exc})"

    client: Any = AsyncMongoClient(uri, serverSelectionTimeoutMS=8000,
                                   connectTimeoutMS=8000)
    try:
        db = client[database]
        try:
            names = set(await db.list_collection_names())
        except Exception as exc:                    # noqa: BLE001
            return [], f"{type(exc).__name__}: {exc}"

        info: dict[str, Mapping] = {}
        try:
            async for each in await db.list_collections():
                info[each["name"]] = each.get("options") or {}
        except Exception:                           # noqa: BLE001
            pass                                    # validators unreadable

        found: list[Finding] = []
        # Collections whose `auto_embed` claim could not be checked, and why.
        # Accumulated rather than returned on the spot: an early return here
        # abandoned every collection after the first unanswerable one while
        # reporting only "auto_embed could not be verified", so a policy with
        # five collections and no mongot got one collection checked and a
        # message that did not say so. Partial coverage described as a
        # narrower failure than it was.
        blind: list[str] = []
        for one in declared:
            if one.collection not in names:
                found.extend(audit(one, indexes=(), search_indexes=(),
                                   validator=None, exists=False))
                continue
            coll = db[one.collection]
            indexes = [dict(i) async for i in await coll.list_indexes()]
            search: list[Mapping] = []
            skip_embedding = False
            if one.auto_embed:
                try:
                    search = [dict(i) async for i
                              in await coll.list_search_indexes()]
                except Exception as exc:            # noqa: BLE001
                    # A deployment with no mongot cannot answer this, which
                    # is a fact about the deployment rather than a
                    # disagreement with the policy. The *other* checks on
                    # this collection are still worth running, and are.
                    blind.append(f"{one.collection} ({type(exc).__name__})")
                    skip_embedding = True
            found.extend(audit(
                one, indexes=indexes, search_indexes=search,
                validator=(info.get(one.collection) or {}).get("validator"),
                check_embedding=not skip_embedding))
        if blind:
            return found, (
                f"$listSearchIndexes could not be read for "
                f"{', '.join(blind)}, so the auto_embed declaration"
                f"{'s' if len(blind) > 1 else ''} there "
                f"{'were' if len(blind) > 1 else 'was'} not verified. "
                f"Everything else on this page was")
        return found, None
    finally:
        # Closed before the listener accepts anything. This process holds no
        # connection of its own once preflight is done, which is the
        # property the README leads with and the reason this is a startup
        # probe rather than a health check.
        await client.close()


def report(findings: list[Finding], unavailable: str | None) -> list[str]:
    """The lines `voyd-wire` prints. Worst first, then the summary."""
    lines: list[str] = []
    if unavailable:
        lines.append(
            f"voyd-wire: preflight could not run: {unavailable}. Starting "
            f"anyway -- unreachable is not misconfigured, and a probe that "
            f"blocked a deploy over a transient cluster error would cause "
            f"more outages than it prevents")
    order = {FATAL: 0, WARN: 1}
    for finding in sorted(findings, key=lambda f: order.get(f.severity, 2)):
        lines.append(finding.line())
    if not findings and not unavailable:
        lines.append("voyd-wire: preflight: the cluster matches the policy "
                     "file (TTL indexes, tenant indexes, embedding owners "
                     "and sealed-field validators all checked)")
    return lines


def fatal(findings: Iterable[Finding]) -> list[Finding]:
    return [f for f in findings if f.severity == FATAL]


def _main(argv: list[str] | None = None) -> int:      # pragma: no cover
    """Runnable on its own, because a check you can only get by starting the
    proxy is one nobody runs before a deploy."""
    import argparse
    import asyncio

    from voyd.declare import OPTIONS, load

    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--config", required=True, metavar="VOYDFILE")
    ap.add_argument("--target", required=True)
    ap.add_argument("--database", required=True)
    args = ap.parse_args(argv)

    guards: dict[str, Any] = dict(load(args.config))
    uri = (args.target if "://" in args.target
           else f"mongodb://{args.target}/?directConnection=true")

    class _Shim:
        def __init__(self, spec): self.spec = spec

    found, why = asyncio.run(inspect(
        uri, args.database,
        declarations({k: _Shim(v) for k, v in guards.items()}, OPTIONS)))
    for line in report(found, why):
        print(line)
    return 1 if fatal(found) else 0


if __name__ == "__main__":                            # pragma: no cover
    raise SystemExit(_main())
