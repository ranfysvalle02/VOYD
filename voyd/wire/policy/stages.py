"""Pipeline vocabulary mongod does not have, run on what was admitted.

    db.notes.aggregate([
        {"$match": {"tenant_id": "acme"}},
        {"$addFields": {"words": {"$wordCount": "$text"}}},    # @operator
        {"$keywordRank": {"words": ["refund"]}},                # @stage
        {"$match": {"words": {"$gt": 3}}},                      # mongod
        {"$sort": {"score": -1}},                               # mongod
    ])

`$wordCount` and `$keywordRank` are functions in a policy file, declared
with `@operator` and `@stage`. This module is what makes a pipeline naming
them work from any driver. The pipeline is split at its virtual steps:

    native prefix  ->  the server, on the client's own connection
                   ->  every rule, sanitized(), mask()   (the ordinary egress)
    virtual step   ->  this process, on the admitted documents only
                   ->  every rule again, on what it returned
    native suffix  ->  the server, on a temporary collection holding only
                       that output, through the boundary's own connection
                   ->  every rule again, on what carries a source `_id`
                   ->  the client, as one batch

**A refused document never reaches a stage or an operator.** The prefix is
drained through the same `judge` a `find` goes through, so what a stage is
handed is what this caller would have been served, field for field: the
revoked, expired and cross-tenant rows are not in its arguments, masked
values are already null, `sanitized()` text is already neutralised.

**The prefix is never `$out` to a temporary collection.** That would copy
refused documents into a namespace no policy guards, which is the hole
`refusals.py` closes for clients. The prefix comes back through the
boundary instead, and only what survived it -- and then only what a stage
produced from that -- is ever written anywhere.

**A virtual step cannot widen a read.** It may add fields, drop documents
and reorder them. It may not introduce one: every output is traced by `_id`
to an input it was handed, at most as many times as it was handed, and the
rest are dropped. Every traced output is then judged again with the fields
the verdict reads put back from the admitted source, so a stage cannot
erase a mark, move a deadline or change a tenant on the way out.

**Reductions after a virtual step are safe, and that is an argument, not a
convenience.** A `$group` *before* one is refused, because a group has
nothing left on it to judge. A `$group` *after* one runs on a temporary
collection that holds admitted, masked, neutralised documents and nothing
else -- so whatever it counts or sums is a function of what this caller was
allowed to see. It is the reduction `reads.py` tells a client to do "on
your side", done on the client's side of the boundary. Its outputs carry
no source `_id` and are served as they are; a suffix output that does carry
one is judged again like any other.

**Fields a step adds are ordinary fields to everything after it.** A later
operator reads them by path, a native `$match` on the temporary collection
filters on them, and a stage can `ctx.publish("corpus", {...})` a value
computed over the admitted set that later steps read as `$$corpus.<field>`
-- in a virtual step's arguments, or in the native suffix, where it is
passed as `let`. Published from admitted documents only, so a pipeline
variable carries nothing a refused row could have contributed.

What is refused, loudly, with a reason the driver raises:

    `explain` of a pipeline with a virtual step    no server can describe it
    a stage before the first virtual step that     nothing left to judge
      does not hand back the stored document
    `$lookup`, `$unionWith`, `$graphLookup`        another collection's rows
    `$out`, `$merge`                               a write past the boundary
    after a virtual step, a stage that reads       the suffix runs with the
      something other than its input              boundary's credentials
    an operator anywhere but a whole field value   not half-evaluated
      of `$addFields` / `$set`
    a virtual step on an unguarded collection      nothing to admit by
    more than `max_docs` documents                 never silently truncated
    a stage or operator that raises                never a partial result

The whole set is held in memory and answered as one batch with `id: 0`.
"""

from __future__ import annotations

import asyncio
import copy
import inspect
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Mapping

import bson

from ..codec import LAZY, decode_op_msg, encode_op_msg
from .guarding import Guard, guard_for
from .reads import (FOREIGN_STAGES, PRESERVING_STAGES, deciding_fields,
                    pins_the_tenant)
from .refusals import EXFILTRATING_STAGES

# Where temporary collections live. A database of their own, so "is this
# ours to drop?" is answered by a name and not by a guess.
DEFAULT_DATABASE = "__voyd_tmp"
# How old a temporary collection may be before any proxy's sweep drops it.
DEFAULT_MAX_AGE_S = 600.0
# How many documents a virtual read may hold at any step.
DEFAULT_MAX_DOCS = 1000
# A reply is one BSON document, and one BSON document is at most this.
MAX_REPLY_BYTES = 16 * 1024 * 1024

# After a virtual step the native suffix runs through the boundary's own
# connection, with its credentials. Every stage here reads something other
# than the documents it is handed -- server state, an index, a literal
# collection -- and would be reading it with somebody else's privileges.
SOURCE_STAGES = frozenset({
    "$changeStream", "$changeStreamSplitLargeEvent", "$collStats",
    "$currentOp", "$documents", "$geoNear", "$indexStats",
    "$listCatalog", "$listClusterCatalog", "$listLocalSessions",
    "$listSampledQueries", "$listSearchIndexes", "$listSessions",
    "$planCacheStats", "$querySettings", "$rankFusion", "$scoreFusion",
    "$search", "$searchMeta", "$shardedDataDistribution", "$vectorSearch",
})

# The two stages whose field values may be a registered operator call.
FIELD_STAGES = ("$addFields", "$set")

# Variable names mongod reserves. A stage may not publish one.
SYSTEM_VARIABLES = frozenset({
    "NOW", "CLUSTER_TIME", "ROOT", "CURRENT", "REMOVE", "DESCEND", "PRUNE",
    "KEEP", "USER_ROLES", "SEARCH_META",
})
_VARIABLE = re.compile(r"^[a-z][A-Za-z0-9_]*$")

# The request fields a prefix inherits from the client's command, so it is
# the same read: the same session, transaction, read concern and bounds.
_CARRIED = ("lsid", "txnNumber", "autocommit", "startTransaction",
            "readConcern", "$readPreference", "maxTimeMS", "collation",
            "let", "hint", "comment", "allowDiskUse", "$clusterTime",
            "apiVersion", "apiStrict", "apiDeprecationErrors")
_CARRIED_MORE = ("lsid", "txnNumber", "autocommit", "$clusterTime")

# A private key on a document being re-judged, so the verdicts can be
# matched back to the rows they were asked about. Taken off before anything
# leaves this module.
_ROW = "__voyd_row__"


@dataclass(frozen=True)
class Virtuals:
    """What the transport is handed: the functions and the bounds.

    Built once, from the policy file and the flags, before any fork.
    """

    stages: Mapping[str, Callable] = field(default_factory=dict)
    operators: Mapping[str, Callable] = field(default_factory=dict)
    database: str = DEFAULT_DATABASE
    max_docs: int = DEFAULT_MAX_DOCS
    max_age_s: float = DEFAULT_MAX_AGE_S

    def __post_init__(self) -> None:
        db = self.database
        if (not isinstance(db, str) or not db or len(db) > 63
                or any(c in db for c in "/\\. \"$*<>:|?")
                or db in ("admin", "local", "config")):
            raise ValueError(
                f"--virtual-db {db!r}: temporary collections need a database "
                f"of their own, named plainly, and never admin, local or "
                f"config -- the sweep drops what it finds there")
        if not isinstance(self.max_docs, int) or self.max_docs < 1:
            raise ValueError("--virtual-max-docs must be at least 1")
        if not self.max_age_s > 0:
            raise ValueError("--virtual-max-age must be positive")

    def __bool__(self) -> bool:
        return bool(self.stages or self.operators)


class VirtualContext:
    """What a stage or operator is told about the read it is part of.

    ``claims`` are the server's account of who this connection is -- from
    `connectionStatus`, never from the client. ``vars`` are the values
    earlier steps published, plus ``NOW``, one instant for the whole read.
    """

    def __init__(self, *, collection: str, database: str, name: str,
                 claims: dict | None, now: datetime, vars: dict):
        self.collection = collection
        self.database = database
        self.name = name
        self.claims = dict(claims) if claims else claims
        self.now = now
        self.vars = vars

    def publish(self, name: str, value: Any) -> None:
        """Make ``value`` readable as ``$$name`` by every later step.

        Copied, so a stage that goes on mutating its own object does not
        change what a later one reads.
        """
        if not isinstance(name, str) or not _VARIABLE.match(name):
            raise StageError(
                f"`{self.name}` published {name!r}; a pipeline variable is "
                f"a name starting with a lowercase letter, the rule mongod "
                f"applies to `let`")
        if name.upper() in SYSTEM_VARIABLES:
            raise StageError(f"`{self.name}` published {name!r}, which the "
                             f"server reserves")
        self.vars[name] = copy.deepcopy(value)


class StageError(Exception):
    """A virtual read that cannot be answered. Becomes an OP_MSG error."""


@dataclass
class Step:
    """One piece of a split pipeline."""
    kind: str                        # "stage" | "operator" | "native"
    name: str                        # the stage name, "$addFields", or ""
    spec: Any                        # its argument, or the native stages


@dataclass
class VirtualRead:
    """A pipeline, split. What goes to the server and what runs here."""
    guard: Guard
    database: str
    prefix: list
    steps: list[Step]
    body: dict = field(repr=False)


def _name(stage: Any) -> str | None:
    if isinstance(stage, Mapping) and len(stage) == 1:
        key = next(iter(stage))
        return key if isinstance(key, str) else None
    return None


def _mentions(node: Any, names: Any) -> str | None:
    """The first key anywhere under ``node`` that is one of ``names``."""
    stack = [node]
    while stack:
        here = stack.pop()
        if isinstance(here, Mapping):
            for key, value in here.items():
                if key in names:
                    return key
                stack.append(value)
        elif isinstance(here, (list, tuple)):
            stack.extend(here)
    return None


def _call_of(value: Any, operators: Mapping) -> str | None:
    """The operator this value calls, if it is exactly one operator call."""
    name = _name(value)
    return name if name is not None and name in operators else None


def _kind(stage: Any, virtuals: Virtuals) -> str | None:
    name = _name(stage)
    if name is None:
        return None
    if name in virtuals.stages:
        return "stage"
    if name in FIELD_STAGES and _mentions(stage[name], virtuals.operators):
        return "operator"
    return None


def _field_problem(spec: Any, operators: Mapping) -> str | None:
    """Why this `$addFields` cannot run here, or `None` if it can."""
    if not isinstance(spec, Mapping) or not spec:
        return "an `$addFields` naming an operator needs a document of fields"
    for key, value in spec.items():
        if not isinstance(key, str) or key.startswith("$") or "." in key:
            return (f"{key!r} is not a top-level field name; an operator "
                    f"sets whole top-level fields")
        if key == "_id":
            return ("an operator step may not set `_id`: it is what every "
                    "output is traced back to an admitted document by")
        called = _call_of(value, operators)
        if called is not None:
            nested = _mentions(value[called], operators)
            if nested is not None:
                return (f"{key!r} calls {called} with {nested} inside its "
                        f"arguments; operators here do not nest -- set one "
                        f"field per step and read it by path in the next")
            continue
        if isinstance(value, str):
            continue                       # a path, a variable, or a string
        if _name(value) == "$literal":
            continue
        if isinstance(value, (Mapping, list)):
            return (f"{key!r} is an expression, and a step that calls a "
                    f"registered operator runs in the boundary, which "
                    f"evaluates an operator call, a field path, a `$$` "
                    f"variable or a literal and nothing richer. Put the "
                    f"expression in its own `$addFields`")
    return None


def plan_virtual(body: Mapping, guards: dict[str, Guard],
                 virtuals: Virtuals) -> tuple[VirtualRead | None, str | None]:
    """The split, or why this pipeline is refused, or `(None, None)`.

    `(None, None)` is a pipeline with nothing virtual in it, which goes on
    exactly as it was -- and so is an unregistered `$foo`, which mongod
    answers the way it always would.
    """
    if not virtuals:
        return None, None
    inner = body.get("explain")
    if isinstance(inner, Mapping):
        pipe = inner.get("pipeline")
        if isinstance(pipe, list) and any(
                _kind(s, virtuals) or _mentions(s, virtuals.operators)
                for s in pipe):
            return None, ("`explain` describes a plan, and part of this plan "
                          "runs in the boundary, where no server can "
                          "describe it")
        return None, None
    pipeline = body.get("pipeline")
    if not isinstance(pipeline, list) or "aggregate" not in body:
        return None, None
    kinds = [_kind(s, virtuals) for s in pipeline]
    for stage, kind in zip(pipeline, kinds):
        if kind is None and _name(stage) not in virtuals.stages:
            stray = _mentions(stage, virtuals.operators)
            if stray is not None:
                return None, (f"{stray} is a registered operator, and the "
                              f"only place one runs is as a whole field "
                              f"value of `$addFields` or `$set`; "
                              f"`{_name(stage) or 'this stage'}` would hand "
                              f"it to a server that does not know it")
    if not any(kinds):
        return None, None
    if body.get("explain"):
        return None, ("`explain` describes a plan, and part of this plan "
                      "runs in the boundary, where no server can describe it")
    if not isinstance(body.get("aggregate"), str):
        return None, ("a virtual step runs on one guarded collection, and "
                      "`aggregate: 1` names none")
    guard = guard_for(guards, body, "aggregate")
    if guard is None:
        return None, ("a virtual step runs only on a guarded collection: its "
                      "promise is that it is shown admitted documents, and a "
                      "collection with no policy has nothing to admit them "
                      "by. Declare it with @guard")
    first = next(i for i, k in enumerate(kinds) if k)
    for at, stage in enumerate(pipeline):
        name = _name(stage)
        if name is None:
            return None, "a stage this boundary cannot read"
        if kinds[at] == "stage":
            continue                  # its argument is the function's own
        foreign = _mentions(stage, FOREIGN_STAGES)
        if foreign is not None:
            return None, (f"`{foreign}` brings back documents from another "
                          f"collection, which this guard cannot speak for")
        writes = _mentions(stage, EXFILTRATING_STAGES)
        if writes is not None:
            return None, (f"`{writes}` writes documents somewhere this "
                          f"boundary does not guard")
        if at < first and name not in PRESERVING_STAGES:
            return None, (f"`{name}` comes before the first virtual step and "
                          f"does not hand back the stored document, so there "
                          f"would be nothing to judge before a stage is "
                          f"shown it. Move it after the virtual step, where "
                          f"it runs on admitted documents only")
        if at > first and kinds[at] is None:
            source = _mentions(stage, SOURCE_STAGES)
            if source is not None:
                return None, (f"`{source}` after a virtual step would run on "
                              f"the boundary's own connection and read "
                              f"something other than the admitted documents")
        if kinds[at] == "operator":
            why = _field_problem(stage[name], virtuals.operators)
            if why is not None:
                return None, why
    tenant = guard.spec.tenant
    if tenant and not any(_name(s) == "$match"
                          and pins_the_tenant(s["$match"], tenant)
                          for s in pipeline[:first]):
        return None, (f"a virtual step summarises and ranks the documents it "
                      f"is handed, and this pipeline does not say which "
                      f"{tenant!r} it is about before the first one. Open "
                      f"with a `$match` on it")
    steps: list[Step] = []
    for stage, kind in zip(pipeline[first:], kinds[first:]):
        name = str(next(iter(stage)))
        if kind is not None:
            steps.append(Step(kind, name, stage[name]))
        elif steps and steps[-1].kind == "native":
            steps[-1].spec.append(stage)
        else:
            steps.append(Step("native", "", [stage]))
    database = body.get("$db")
    return VirtualRead(guard=guard,
                       database=database if isinstance(database, str) else "",
                       prefix=list(pipeline[:first]), steps=steps,
                       body=dict(body)), None


def split_virtual(body: Mapping, req_id: int, guards: dict[str, Guard],
                  virtuals: Virtuals, verbose: bool = False
                  ) -> tuple[VirtualRead | None, bytes | None]:
    """`(read, refusal)` -- at most one is not `None`.

    One call for both, for the reason `rewrite_derived_read` gives: a
    caller that asks "is it virtual?" and forwards on a `None` would hand
    mongod a stage it does not know, or a prefix nobody judges.
    """
    read, why = plan_virtual(body, guards, virtuals)
    if why is None:
        return read, None
    named = body.get("aggregate")
    inner = body.get("explain")
    if isinstance(inner, Mapping):
        named = inner.get("aggregate")
    return None, stage_error(req_id, named if isinstance(named, str)
                             else "this database", why, verbose)


def names_scratch(body: Mapping, database: str) -> bool:
    """Does this command address the temporary namespace, anywhere?

    `$db` is the ordinary way. The others are a string naming it -- a
    `renameCollection` source, a `$merge.into.db`, an `applyOps` `ns` --
    found by value rather than by a list of keys that would need to be
    complete. Insert, update and delete payloads are not searched: they
    are documents, and a document cannot address a namespace.
    """
    if body.get("$db") == database:
        return True
    prefix = database + "."
    stack: list = [v for k, v in body.items()
                   if k not in ("documents", "updates", "deletes")]
    while stack:
        here = stack.pop()
        if isinstance(here, str):
            if here == database or here.startswith(prefix):
                return True
        elif isinstance(here, Mapping):
            stack.extend(here.values())
        elif isinstance(here, (list, tuple)):
            stack.extend(here)
    return False


def refuse_scratch(body: Mapping, req_id: int, database: str,
                   verbose: bool = False) -> bytes | None:
    """Answer any command naming the temporary database with an error.

    Every temporary collection holds one caller's admitted, masked output,
    and none of them is guarded -- a guard would refuse nothing, because
    what is in them was already admitted, *for somebody else*. So there is
    no read of that database this boundary could judge, and it is not
    readable through here at all: not `find`, not `aggregate`, not a change
    stream, not `listCollections`. `listDatabases` still lists its name,
    which carries a proxy id, a time and a uuid and nothing else.
    """
    if not names_scratch(body, database):
        return None
    if verbose:
        print(f"  voyd: REFUSED a command naming {database!r}, where "
              f"virtual reads keep their temporary collections", flush=True)
    return encode_op_msg(req_id, req_id, 0, {
        "ok": 0.0, "code": 8000, "codeName": "AtlasError",
        "errmsg": (f"voyd-wire refuses commands naming {database!r}: it "
                   f"holds the temporary collections virtual reads run their "
                   f"native steps on, each one another caller's admitted "
                   f"output, and nothing there is readable through the "
                   f"boundary."),
    })


def stage_error(req_id: int, collection: str, why: str,
                verbose: bool) -> bytes:
    """An error the driver raises. The alternative is a partial answer."""
    if verbose:
        print(f"  voyd: REFUSED a virtual read on {collection}: {why}",
              flush=True)
    return encode_op_msg(req_id, req_id, 0, {
        "ok": 0.0, "code": 8000, "codeName": "AtlasError",
        "errmsg": f"voyd-wire could not run this pipeline on "
                  f"{collection!r}: {why}.",
    })


# ---- running one ----------------------------------------------------------

def _key(value: Any) -> bytes:
    """An `_id` as something hashable and exact. `1 == 1.0` is not enough."""
    return bson.encode({"_": value})


def _get(doc: Any, path: str) -> Any:
    here = doc
    for part in path.split("."):
        if isinstance(here, Mapping):
            here = here.get(part)
        elif isinstance(here, list):
            here = [x.get(part) if isinstance(x, Mapping) else None
                    for x in here]
        else:
            return None
    return here


def _resolve(value: Any, doc: Mapping | None, vars: Mapping) -> Any:
    """`$path` from ``doc``, `$$name` from ``vars``, `$literal` verbatim.

    ``doc=None`` for a stage's arguments, which are not per document: a
    `$path` there is left as written, for the stage to interpret.
    """
    if isinstance(value, str):
        if value.startswith("$$"):
            name, _, rest = value[2:].partition(".")
            if name not in vars:
                raise StageError(f"{value!r} names a variable no earlier "
                                 f"step published")
            got = vars[name]
            return copy.deepcopy(_get(got, rest) if rest else got)
        if value.startswith("$") and doc is not None and len(value) > 1:
            return copy.deepcopy(_get(doc, value[1:]))
        return value
    if isinstance(value, Mapping):
        if _name(value) == "$literal":
            return copy.deepcopy(value["$literal"])
        return {k: _resolve(v, doc, vars) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve(v, doc, vars) for v in value]
    return value


async def _call(fn: Callable, *args: Any) -> Any:
    """Async functions are awaited; sync ones go to a thread, because a
    function that blocks the event loop blocks every connection it serves."""
    if inspect.iscoroutinefunction(fn):
        return await fn(*args)
    got = await asyncio.to_thread(fn, *args)
    if inspect.isawaitable(got):
        got = await got
    return got


def trace(name: str, got: Any, handed: list[dict]) -> tuple[list[dict], int]:
    """What a stage returned that an input accounts for, and how many not.

    Each `_id` may come back at most as many times as it was handed, so a
    stage can drop and reorder but not multiply, fabricate, or re-inject a
    refused document from a cache.
    """
    budget: dict[bytes, int] = {}
    for doc in handed:
        k = _key(doc.get("_id"))
        budget[k] = budget.get(k, 0) + 1
    kept, dropped = [], 0
    try:
        outputs = list(got) if got is not None else []
    except TypeError as exc:
        raise StageError(f"`{name}` returned {type(got).__name__}, not an "
                         f"iterable of documents") from exc
    for doc in outputs:
        if not isinstance(doc, Mapping):
            raise StageError(f"`{name}` returned a {type(doc).__name__}, "
                             f"not a document")
        if "_id" not in doc:
            dropped += 1
            continue
        k = _key(doc["_id"])
        if budget.get(k, 0) <= 0:
            dropped += 1
            continue
        budget[k] -= 1
        kept.append(dict(doc))
    return kept, dropped


def terminal(guard: Guard, rows: list[dict], sources: Mapping[bytes, dict],
             caller: dict | None) -> list[dict]:
    """Every rule, again, on each row that descends from an admitted one.

    The fields the verdict reads are put back from the admitted source
    before the rules are asked, so a step that rewrote a mark, a deadline
    or a tenant is judged on the document it came from -- and what is
    served for those fields is the source's value, masked as it was. A
    deadline that passed while a slow stage ran is caught here too.

    One batch rather than one call per document, because a declared
    tenant is taken from the batch. Rows with no source `_id` are the
    output of a reduction over admitted documents and pass as they are.
    """
    restore = {f.split(".", 1)[0] for f in deciding_fields(guard)}
    asked: list[dict] = []
    for at, doc in enumerate(rows):
        source = sources.get(_key(doc.get("_id")))
        if source is None:
            continue
        mended = dict(doc)
        for f in restore:
            if f in source:
                mended[f] = source[f]
            else:
                mended.pop(f, None)
        mended[_ROW] = at
        asked.append(mended)
    if not asked:
        return list(rows)
    judged = {m[_ROW] for m in asked}
    survived = {s[_ROW]: {k: v for k, v in s.items() if k != _ROW}
                for s in guard.recheck(asked, caller)}
    out = []
    for at, doc in enumerate(rows):
        if at not in judged:
            out.append(doc)
            continue
        kept = survived.get(at)
        if kept is None:
            continue
        out.append({k: kept[k] for k in doc if k in kept})
    return out


async def _drain(read: VirtualRead, ask: Callable[[dict], Awaitable[Any]],
                 judge_reply: Callable[[bytes], Any],
                 max_docs: int) -> tuple[list[dict], dict]:
    """Every admitted document the native prefix produces.

    Each reply goes through ``judge_reply`` -- the proxy's own `judge`, with
    one budget tab for the whole cursor -- exactly as if the client had
    sent the command. The bound is on what came *upstream*, before judging,
    because it is a bound on memory.
    """
    carried = {k: read.body[k] for k in _CARRIED if k in read.body}
    command = {"aggregate": read.guard.collection, "pipeline": read.prefix,
               "cursor": {}, "$db": read.database, **carried}
    raw = await ask(command)
    admitted: list[dict] = []
    seen = 0
    while True:
        if raw is None:
            raise StageError("the server did not answer the native part of "
                             "this pipeline")
        peek = decode_op_msg(raw, LAZY)
        cursor = (peek[1].get("cursor") if peek else None) or {}
        batch = cursor.get("firstBatch", cursor.get("nextBatch", []))
        seen += len(batch) if isinstance(batch, list) else 0
        judged = judge_reply(raw)
        if inspect.isawaitable(judged):
            judged = await judged
        decoded = decode_op_msg(judged)
        if decoded is None:
            raise StageError("the server's reply to the native part of this "
                             "pipeline could not be read")
        reply = dict(decoded[1])
        if not reply.get("ok"):
            raise StageError(f"the server refused the native part of this "
                             f"pipeline: {reply.get('errmsg', reply)}")
        cur = reply.get("cursor") or {}
        admitted.extend(cur.get("firstBatch", cur.get("nextBatch", [])))
        cursor_id = cur.get("id") or 0
        if seen > max_docs:
            if cursor_id:
                await ask({"killCursors": read.guard.collection,
                           "cursors": [cursor_id], "$db": read.database,
                           **{k: read.body[k] for k in ("lsid",)
                              if k in read.body}})
            raise StageError(
                f"the native part before the first virtual step produced "
                f"more than {max_docs} documents, the most a virtual read may "
                f"hold (--virtual-max-docs). Narrow it with a `$match` or a "
                f"`$limit`; truncating here would answer a different "
                f"question without saying so")
        if not cursor_id:
            return admitted, reply
        more = {"getMore": cursor_id, "collection": read.guard.collection,
                "$db": read.database,
                **{k: read.body[k] for k in _CARRIED_MORE if k in read.body}}
        raw = await ask(more)


def _one_tenant(guard: Guard, docs: list[dict]) -> None:
    """A virtual step is handed one tenant's documents, or none at all.

    The ordinary egress judges each cursor batch on its own scope. A
    virtual step sees the whole cursor at once, so the scope is checked
    across the whole of it -- a pinned `$match` makes this unreachable, and
    that is the point of checking it anyway.
    """
    tenant = guard.spec.tenant
    if tenant and len({repr(d.get(tenant)) for d in docs}) > 1:
        raise StageError(f"the admitted documents span more than one "
                         f"{tenant!r}, and a virtual step is handed one "
                         f"tenant's documents or none")


async def run_virtual(read: VirtualRead, req_id: int, *,
                      ask: Callable[[dict], Awaitable[Any]],
                      judge_reply: Callable[[bytes], Any],
                      scratch: Any, virtuals: Virtuals,
                      caller: dict | None = None,
                      verbose: bool = False,
                      now: datetime | None = None) -> bytes:
    """Drain, admit, run each step, judge again, answer once.

    Always returns a reply for the client: the documents, or an error it
    raises. Never a partial result.

    ``scratch`` runs a native step on a temporary collection and is the
    only thing here that writes: ``await scratch.run(docs, stages, let=,
    collation=, max_docs=)``. It is asked only when a native step follows
    a virtual one, so a pipeline ending in a virtual step creates nothing.
    """
    guard = read.guard
    stamp = now or datetime.now(timezone.utc)
    try:
        admitted, last = await _drain(read, ask, judge_reply,
                                      virtuals.max_docs)
        _one_tenant(guard, admitted)
        sources: dict[bytes, dict] = {}
        for doc in admitted:
            if "_id" in doc:
                sources.setdefault(_key(doc["_id"]), doc)
        rows = copy.deepcopy([d for d in admitted if "_id" in d])
        vars: dict = {"NOW": stamp}
        dropped = 0
        for step in read.steps:
            ctx = VirtualContext(collection=guard.collection,
                                 database=read.database, name=step.name,
                                 claims=caller, now=stamp, vars=vars)
            if step.kind == "stage":
                args = _resolve(step.spec, None, vars)
                try:
                    got = await _call(virtuals.stages[step.name], args,
                                      copy.deepcopy(rows), ctx)
                except StageError:
                    raise
                except Exception as exc:                     # noqa: BLE001
                    raise StageError(f"`{step.name}` raised "
                                     f"{type(exc).__name__}: {exc}") from exc
                rows, lost = trace(step.name, got, rows)
                dropped += lost
            elif step.kind == "operator":
                rows = await _fields(step, rows, virtuals, ctx)
            else:
                if scratch is None:
                    raise StageError("this boundary has no connection to run "
                                     "native steps after a virtual one on")
                rows = await _native(step.spec, rows, read, scratch,
                                     virtuals, vars)
            rows = terminal(guard, rows, sources, caller)
        if dropped:
            guard.refused += dropped
            if verbose:
                print(f"  voyd: {guard.collection}: dropped {dropped} "
                      f"document(s) a virtual stage returned that no "
                      f"admitted input accounts for", flush=True)
        reply: dict = {"cursor": {"firstBatch": rows, "id": bson.Int64(0),
                                  "ns": f"{read.database}.{guard.collection}"},
                       "ok": 1.0}
        for k in ("operationTime", "$clusterTime"):
            if k in last:
                reply[k] = last[k]
        try:
            encoded = encode_op_msg(req_id, req_id, 0, reply)
        except Exception as exc:                             # noqa: BLE001
            raise StageError(f"a virtual step produced a value BSON cannot "
                             f"carry: {exc}") from exc
    except StageError as exc:
        return stage_error(req_id, guard.collection, str(exc), verbose)
    except Exception as exc:                                 # noqa: BLE001
        # A defect here is still an answer to the client, never a dropped
        # connection and never a partial result.
        return stage_error(req_id, guard.collection,
                           f"the boundary failed running it: "
                           f"{type(exc).__name__}: {exc}", verbose)
    if len(encoded) > MAX_REPLY_BYTES:
        return stage_error(req_id, guard.collection,
                           "the result is larger than one reply may be, and "
                           "a virtual read answers in one batch", verbose)
    return encoded


async def _fields(step: Step, rows: list[dict], virtuals: Virtuals,
                  ctx: VirtualContext) -> list[dict]:
    """One `$addFields` with operator calls in it, per document.

    Every value is computed from the document as it arrived, the way
    mongod evaluates the fields of one `$addFields`: a field set here is
    visible to the *next* step, not to its siblings.
    """
    spec: Mapping = step.spec
    out = []
    for doc in rows:
        made = dict(doc)
        for key, value in spec.items():
            called = _call_of(value, virtuals.operators)
            if called is None:
                made[key] = _resolve(value, doc, ctx.vars)
                continue
            ctx.name = called
            args = _resolve(value[called], doc, ctx.vars)
            try:
                made[key] = await _call(virtuals.operators[called],
                                        copy.deepcopy(doc), args, ctx)
            except StageError:
                raise
            except Exception as exc:                         # noqa: BLE001
                raise StageError(f"`{called}` raised {type(exc).__name__}: "
                                 f"{exc}") from exc
        out.append(made)
    return out


async def _native(stages: list, rows: list[dict], read: VirtualRead,
                  scratch: Any, virtuals: Virtuals, vars: dict) -> list[dict]:
    """A native step, in mongod, on a temporary collection of ``rows``."""
    published = {k: v for k, v in vars.items() if k not in SYSTEM_VARIABLES}
    client_let = read.body.get("let")
    let = dict(client_let) if isinstance(client_let, Mapping) else {}
    clash = set(let) & set(published)
    if clash:
        raise StageError(f"`let` and a virtual step both define "
                         f"{sorted(clash)}; one name, one value")
    let.update(published)
    return await scratch.run(rows, stages, let=let or None,
                             collation=read.body.get("collation"),
                             max_docs=virtuals.max_docs)
