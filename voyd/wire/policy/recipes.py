"""A recipe is a pipeline with a name: reviewed once, called by name.

    # voydfile.py
    @recipe("support_context", collection="tickets")
    def support_context(q: str, k: int = 8):
        return [{"$vectorSearch": {"index": "v", "path": "embedding",
                                   "query": q, "numCandidates": k * 10,
                                   "limit": k}},
                {"$addFields": {"clean": {"$redactPII": "$text"}}}]

    // any driver
    db.tickets.aggregate([{$recipe: {name: "support_context",
                                     params: {q: "refund", k: 5}}}])

A SQL view for retrieval. The pipeline lives in the policy file, beside
the rules, where it is reviewed and where `voyd-plan` can see it; the
client names it and hands over values.

**Expansion is the first thing that happens to the message.** Before the
scratch refusal, the masked-reference check, the virtual-stage split, the
derived-read push-down, the prefilter and the backfill. What the rest of
the pump sees is byte-for-byte the aggregate a client would have sent had
it written the expansion by hand, so a recipe gets every guarantee that
pipeline would get and every refusal that pipeline would meet. There is no
second path to keep in step with the first, because there is no second
path.

**Parameters are data, never code.** Three checks, each closing a
different door:

1. *At the gate.* A value must match the function's annotation -- ``str``,
   ``int``, ``float``, ``bool``, ``list[str]``, each optionally ``| None``.
   A document, an array of documents, a regex, anything else is refused by
   type, so ``{"$where": ...}`` cannot arrive as a parameter at all. A
   string (or list element) beginning with ``$`` is refused outright:
   in an expression it would be a field path (``"$ssn"``) or a variable
   (``"$$ROOT"``), and whether a given string lands in an expression is a
   fact about the recipe's code that this module declines to guess.
   Wrapping in ``$literal`` would be right in an expression and an error
   in a ``$match`` or a ``$vectorSearch.query``, so it is not done.
2. *As arguments.* The values reach the recipe only as keyword arguments
   to the function the policy file declared. Nothing is spliced into a
   template, so there is no string to escape.
3. *After.* The returned pipeline is re-validated: stages are one-key
   documents, no ``$out``/``$merge``/``$changeStream``, no server-side
   JavaScript (``$where``, ``$function``, ``$accumulator``) anywhere, no
   nested ``$recipe``. And its **vocabulary** -- every key, and every
   string beginning with ``$`` -- must already appear in one of the
   expansions declared at load (the defaults, or ``samples=``). A
   parameter may change a *value*; it may never change a name, an
   operator, a stage or a field path. ``{field: 1}`` or ``f"${field}"``
   built from a parameter is refused unless a declared sample already
   produced that exact name, which makes the permitted names part of what
   the plan shows.

**``recipes_only=True``** on a ``@guard`` makes the recipe the only way to
read the collection: ``find``, ``aggregate``, ``count``, ``distinct``,
``mapReduce`` and their ``explain``, and any ``$lookup``/``$unionWith``/
``$graphLookup`` reaching it from another collection, are refused unless
they arrived as a ``$recipe``. ``find`` by ``_id`` included: an
application that needs one declares it as a recipe, and then that too has
one reviewed home. Writes, ``getMore`` and ``killCursors`` are untouched.

**Grants.** ``@recipe(..., actors=("support-bot",), scopes=("tickets:read",))``
runs only for a delegated identity -- an agent acting for a user, verified
by ``policy/delegation.py`` -- and each condition given must hold: the
actor's mapped id (``act.sub`` by default) is listed, and the token holds
at least one listed scope. Both given means both. A plain read of a
granted recipe is refused. ``recipes_for(identity, guards)`` answers the
question an agent's tool list asks: which recipes may this caller run.
"""

from __future__ import annotations

import copy
import hashlib
import inspect
import types
import typing
from typing import Any, Callable, Mapping

import bson

from ..codec import decode_sections, encode_op_msg, encode_sections
from .guarding import Guard, guard_for
from .refusals import CHANGE_STREAM, EXFILTRATING_STAGES

RECIPE_STAGE = "$recipe"

# The only stages a client may put after `$recipe`. Both can only make the
# answer shorter, and neither names a field.
TRAILING = ("$limit", "$skip")

# Server-side JavaScript. A parameter reaching one of these would be code,
# which is the one thing a parameter is never allowed to be -- so a recipe
# containing one is refused at load, whatever its parameters are.
SERVER_CODE = frozenset({"$where", "$function", "$accumulator"})

# Stages a recipe may not produce. The first two write past the boundary,
# the third is a read path whose payload the rules cannot see, the fourth
# would make expansion recursive.
FORBIDDEN_STAGES = frozenset({*EXFILTRATING_STAGES, CHANGE_STREAM,
                              RECIPE_STAGE})

# The reads `recipes_only=True` closes.
AD_HOC_READS = ("find", "aggregate", "count", "distinct", "mapReduce")

# Body fields a `$recipe` aggregate may not carry. `let` defines `$$name`
# variables a recipe's expressions would read, which would be a parameter
# that arrived as an expression; `explain` is a different reply shape.
REFUSED_OPTIONS = ("let", "explain")

_SCALARS: dict[Any, str] = {str: "str", int: "int", float: "float",
                            bool: "bool"}


class RecipeError(Exception):
    """A recipe call this boundary will not expand. The message is the
    driver's error text."""


class Param:
    """One declared parameter: its name, its type and whether it has a
    default. Read from the function's signature, never from the wire."""

    def __init__(self, name: str, kind: str, nullable: bool,
                 required: bool, default: Any):
        self.name, self.kind, self.nullable = name, kind, nullable
        self.required, self.default = required, default

    def describe(self) -> str:
        kind = f"{self.kind} | None" if self.nullable else self.kind
        return f"{self.name}: {kind}" + ("" if self.required else
                                         f" = {self.default!r}")

    def accept(self, value: Any) -> Any:
        """The value as the function will receive it, or `RecipeError`."""
        if value is None:
            if self.nullable:
                return None
            raise RecipeError(f"parameter {self.name!r} is null, and is "
                              f"declared {self.kind}, not {self.kind} | None")
        k = self.kind
        if k == "bool":
            ok = type(value) is bool
        elif k == "int":
            ok = isinstance(value, int) and not isinstance(value, bool)
        elif k == "float":
            ok = (isinstance(value, (int, float))
                  and not isinstance(value, bool))
        elif k == "str":
            ok = isinstance(value, str)
        else:
            ok = (isinstance(value, list)
                  and all(isinstance(v, str) for v in value))
        if not ok:
            raise RecipeError(
                f"parameter {self.name!r} expects {k}, got "
                f"{type(value).__name__}. Parameters are values; a "
                f"document or an operator is never one")
        texts = [value] if k == "str" else value if k == "list[str]" else []
        for text in texts:
            if text.startswith("$"):
                raise RecipeError(
                    f"parameter {self.name!r} begins with '$'. In an "
                    f"expression that is a field path or a variable, not a "
                    f"value, and a parameter may only ever be a value")
        if k == "int":
            return int(value)
        if k == "float":
            return float(value)
        return list(value) if k == "list[str]" else value


def _kind_of(hint: Any) -> tuple[str, bool] | None:
    """(kind, nullable) for a supported annotation, else None."""
    nullable = False
    if typing.get_origin(hint) in (typing.Union, types.UnionType):
        args = typing.get_args(hint)
        rest = [a for a in args if a is not type(None)]
        if len(rest) != 1 or len(args) != 2:
            return None
        nullable, hint = True, rest[0]
    if hint in _SCALARS:
        return _SCALARS[hint], nullable
    if typing.get_origin(hint) is list and typing.get_args(hint) == (str,):
        return "list[str]", nullable
    return None


def vocabulary(node: Any) -> set[str]:
    """Every key, and every string beginning with `$`, anywhere in `node`.

    The names a pipeline uses: stages, operators, field names, field paths
    and variables. Values that are not `$`-strings are not in it, which is
    exactly the part a parameter is allowed to change.
    """
    out: set[str] = set()

    def walk(n: Any) -> None:
        if isinstance(n, Mapping):
            for key, value in n.items():
                out.add(str(key))
                walk(value)
        elif isinstance(n, (list, tuple)):
            for item in n:
                walk(item)
        elif isinstance(n, str) and n.startswith("$"):
            out.add(n)
    walk(node)
    return out


def check_pipeline(got: Any, where: str) -> list[dict]:
    """A recipe's return value, as a pipeline, or `RecipeError` saying why."""
    if not isinstance(got, (list, tuple)):
        raise RecipeError(f"{where} returned {type(got).__name__}, not a "
                          f"list of stages")
    stages: list[dict] = []
    for at, stage in enumerate(got):
        if (not isinstance(stage, Mapping) or len(stage) != 1
                or not str(next(iter(stage))).startswith("$")):
            raise RecipeError(f"{where}: stage {at} is not a one-key "
                              f"document naming a stage")
        name = next(iter(stage))
        if name in FORBIDDEN_STAGES:
            raise RecipeError(f"{where}: stage {at} is {name}, which no "
                              f"recipe may produce")
        stages.append(dict(stage))
    code = vocabulary(stages) & (SERVER_CODE | {RECIPE_STAGE})
    if code:
        raise RecipeError(f"{where} uses {', '.join(sorted(code))}. Server-"
                          f"side JavaScript is code, and a recipe's inputs "
                          f"are never code")
    try:
        bson.encode({"pipeline": stages})
    except Exception as exc:                                  # noqa: BLE001
        raise RecipeError(f"{where} returned something BSON cannot "
                          f"encode: {exc}") from None
    return stages


def _names(value: Any, what: str, where: str) -> tuple[str, ...]:
    """A grant's names, checked at load: a tuple of distinct plain strings."""
    if isinstance(value, str):
        raise ValueError(f"{where}: {what}= is a list of names, not one "
                         f"string -- write {what}=({value!r},). A string "
                         f"would be read as its characters")
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"{where}: {what}= is a list of names")
    out = tuple(value)
    for item in out:
        if (not isinstance(item, str) or not item.strip()
                or item != item.strip()):
            raise ValueError(f"{where}: {what}= holds {item!r}, which is not "
                             f"a plain, non-empty name")
    if len(set(out)) != len(out):
        raise ValueError(f"{where}: {what}= names something twice")
    return tuple(sorted(out))


def _source(fn: Callable) -> bytes:
    """What the version is a hash *of*: the function as written."""
    try:
        return inspect.getsource(fn).encode()
    except (OSError, TypeError):
        code = getattr(fn, "__code__", None)
        return (code.co_code + repr(code.co_consts).encode()
                if code is not None else repr(fn).encode())


class Recipe:
    """One declared recipe, compiled and checked at load."""

    def __init__(self, fn: Callable, *, name: str, collection: str,
                 samples: Any = None, actors: Any = (), scopes: Any = ()):
        where = f"@recipe({name!r})"
        self.actors = _names(actors, "actors", where)
        self.scopes = _names(scopes, "scopes", where)
        if not isinstance(name, str) or not name.strip() or "$" in name:
            raise ValueError(f"{where}: a recipe name is a plain, non-empty "
                             f"string -- the client sends it as data")
        if not isinstance(collection, str) or not collection.strip():
            raise ValueError(f"{where}: collection= must name the one "
                             f"collection this recipe reads")
        if not callable(fn):
            raise TypeError(f"{where} decorates {fn!r}, which cannot be "
                            f"called")
        self.fn, self.name, self.collection = fn, name, collection
        self.params = self._params(fn, where)
        if samples is None:
            samples = [{}]
        elif isinstance(samples, Mapping):
            samples = [samples]
        if (not isinstance(samples, (list, tuple)) or not samples
                or not all(isinstance(s, Mapping) for s in samples)):
            raise ValueError(f"{where}: samples= is a parameter document or "
                             f"a non-empty list of them")
        self.samples = [dict(s) for s in samples]
        self.expansions: list[list[dict]] = []
        self.vocab: set[str] = set()
        for sample in self.samples:
            missing = [p.name for p in self.params
                       if p.required and p.name not in sample]
            if missing:
                raise ValueError(
                    f"{where}: {', '.join(missing)} has no default and no "
                    f"value in samples=. The plan shows a recipe's "
                    f"expansion, and without a value there is none to show")
            try:
                pipeline = self._call(sample, where)
            except RecipeError as exc:
                raise ValueError(f"{where} at sample {sample!r}: {exc}") \
                    from None
            self.expansions.append(pipeline)
            self.vocab |= vocabulary(pipeline)
        digest = hashlib.sha256(b"voyd-recipe/1\x00")
        parts = [name.encode(), collection.encode(), _source(fn),
                 bson.encode({"x": self.expansions})]
        if self.actors or self.scopes:
            # Only when granted, so an ungranted recipe keeps the version
            # it has always had and a plan recorded before grants existed
            # still reads it as unchanged.
            parts.append(bson.encode({"actors": list(self.actors),
                                      "scopes": list(self.scopes)}))
        for part in parts:
            digest.update(len(part).to_bytes(8, "big") + part)
        # Stable across processes and machines: the source as written and
        # the expansions at declared values. What an audit quotes.
        self.version = digest.hexdigest()[:12]

    @staticmethod
    def _params(fn: Callable, where: str) -> list[Param]:
        try:
            hints = typing.get_type_hints(fn)
        except Exception as exc:                              # noqa: BLE001
            raise TypeError(f"{where}: its annotations do not resolve: "
                            f"{exc}") from None
        out = []
        for p in inspect.signature(fn).parameters.values():
            if p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD):
                raise TypeError(f"{where}: *{p.name} accepts parameters "
                                f"nobody declared. Name each one")
            kind = _kind_of(hints.get(p.name, inspect.Parameter.empty))
            if kind is None:
                raise TypeError(
                    f"{where}: parameter {p.name!r} must be annotated str, "
                    f"int, float, bool or list[str] (optionally | None). "
                    f"The annotation is what a value from the wire is "
                    f"checked against")
            required = p.default is inspect.Parameter.empty
            param = Param(p.name, kind[0], kind[1], required,
                          None if required else p.default)
            if not required:
                try:
                    param.accept(copy.deepcopy(p.default))
                except RecipeError as exc:
                    raise TypeError(f"{where}: the default is invalid: "
                                    f"{exc}") from None
            out.append(param)
        return out

    @property
    def granted(self) -> bool:
        """Does this recipe run only for a delegated identity?"""
        return bool(self.actors or self.scopes)

    def grant(self) -> str:
        """The grant, as a plan and a banner print it. Empty when none."""
        parts = []
        if self.actors:
            parts.append(f"actors={list(self.actors)}")
        if self.scopes:
            parts.append(f"scopes={list(self.scopes)}")
        return " and ".join(parts)

    def refuses(self, claims: Mapping | None) -> str | None:
        """Why this caller may not run this recipe, or ``None``.

        No grant: anybody the collection admits. With a grant, only a
        delegated identity, and each condition given must hold -- the
        actor's mapped id is one of ``actors``, and the token holds at
        least one of ``scopes``. Both given means both.
        """
        if not self.granted:
            return None
        if not claims or not claims.get("delegated"):
            return (f"recipe {self.name!r} is granted to {self.grant()}, and "
                    f"this read carries no delegated identity. Pass "
                    f"comment={{'voyd': token}} or authenticate with "
                    f"MONGODB-OIDC")
        if self.actors:
            actor = claims.get("actor")
            who = actor.get("user") if isinstance(actor, Mapping) else None
            if who not in self.actors:
                return (f"recipe {self.name!r} is granted to actors "
                        f"{list(self.actors)}, and this read's actor is "
                        f"{who!r}")
        if self.scopes:
            held = claims.get("scopes") or ()
            if not set(held) & set(self.scopes):
                return (f"recipe {self.name!r} needs one of the scopes "
                        f"{list(self.scopes)}, and the token grants "
                        f"{list(held) or 'none'}")
        return None

    def describe(self) -> str:
        return (f"{self.name}@{self.version}("
                + ", ".join(p.describe() for p in self.params) + ")"
                + (f" granted to {self.grant()}" if self.granted else ""))

    def _call(self, given: Mapping, where: str) -> list[dict]:
        known = {p.name for p in self.params}
        unknown = sorted(str(k) for k in given if k not in known)
        if unknown:
            raise RecipeError(
                f"unknown parameter {', '.join(map(repr, unknown))}; "
                f"{self.name} takes " + (", ".join(
                    p.describe() for p in self.params) or "none"))
        args: dict[str, Any] = {}
        missing = []
        for p in self.params:
            if p.name in given:
                args[p.name] = p.accept(given[p.name])
            elif p.required:
                missing.append(p.name)
            else:
                args[p.name] = copy.deepcopy(p.default)
        if missing:
            raise RecipeError(f"missing parameter "
                              f"{', '.join(map(repr, missing))}")
        try:
            got = self.fn(**args)
        except RecipeError:
            raise
        except Exception as exc:                              # noqa: BLE001
            raise RecipeError(f"{where} raised {type(exc).__name__}: "
                              f"{exc}") from None
        return check_pipeline(got, where)

    def bind(self, given: Any) -> list[dict]:
        """The pipeline for these parameters, or `RecipeError`."""
        where = f"recipe {self.name!r}"
        if given is None:
            given = {}
        if not isinstance(given, Mapping):
            raise RecipeError("params must be a document of named values")
        pipeline = self._call(given, where)
        extra = vocabulary(pipeline) - self.vocab
        if extra:
            shown = ", ".join(repr(x) for x in sorted(extra)[:5])
            raise RecipeError(
                f"{where} produced {shown}, which none of its declared "
                f"expansions contains. A parameter may change a value, "
                f"never a name, an operator, a stage or a field path; "
                f"declare a sample that produces it if it is meant")
        return pipeline


# ---- on the wire ----------------------------------------------------------

def has_recipes(guards: Mapping[str, Guard]) -> bool:
    """Is there anything for `expand_recipe` to do on this policy?"""
    return any(getattr(g.spec, "recipes", ()) or
               getattr(g.spec, "recipes_only", False)
               for g in guards.values())


def _book(guards: Mapping[str, Guard]) -> dict[str, Recipe]:
    return {r.name: r for g in guards.values()
            for r in getattr(g.spec, "recipes", ())}


def _names_recipe(node: Any) -> bool:
    return RECIPE_STAGE in vocabulary(node)


def _foreign(node: Any) -> set[str]:
    """Collections a pipeline reads besides its own."""
    out: set[str] = set()

    def walk(n: Any) -> None:
        if isinstance(n, Mapping):
            for key, value in n.items():
                if key in ("$lookup", "$graphLookup") and isinstance(
                        value, Mapping) and isinstance(value.get("from"), str):
                    out.add(value["from"])
                elif key == "$unionWith":
                    if isinstance(value, str):
                        out.add(value)
                    elif isinstance(value, Mapping) and isinstance(
                            value.get("coll"), str):
                        out.add(value["coll"])
                walk(value)
        elif isinstance(n, (list, tuple)):
            for item in n:
                walk(item)
    walk(node)
    return out


def _refuse(req_id: int, collection: str, why: str, verbose: bool) -> bytes:
    if verbose:
        print(f"  voyd: REFUSED a recipe read on {collection}: {why}",
              flush=True)
    return encode_op_msg(req_id, req_id, 0, {
        "ok": 0.0, "code": 8000, "codeName": "AtlasError",
        "errmsg": f"voyd-wire refuses this read on {collection!r}: {why}.",
    })


def ad_hoc_read(body: Mapping, guards: Mapping[str, Guard]
                ) -> tuple[str, str] | None:
    """(collection, why) if this is a read `recipes_only=True` closes."""
    def only(name: Any) -> bool:
        g = guards.get(name) if isinstance(name, str) else None
        return bool(g is not None and getattr(g.spec, "recipes_only", False))

    inner = body.get("explain")
    for doc, how in ((body, ""), (inner, "explain of ")):
        if not isinstance(doc, Mapping):
            continue
        for verb in AD_HOC_READS:
            g = guard_for(dict(guards), doc, verb)
            if g is not None and only(g.collection):
                return g.collection, (
                    f"{how}{verb} is not a recipe, and this collection "
                    f"declared recipes_only=True: it is read through the "
                    f"recipes its policy names, "
                    f"{sorted(r.name for r in g.spec.recipes)}, and no "
                    f"other way")
        for name in sorted(_foreign(doc.get("pipeline"))):
            if only(name):
                return name, (
                    "a pipeline on another collection reads it through "
                    "$lookup/$unionWith/$graphLookup, and it declared "
                    "recipes_only=True")
    return None


def recipes_for(identity: Any, guards: Mapping[str, Guard]) -> list[Recipe]:
    """Every recipe this caller may run, sorted by name. Pure.

    ``identity`` is a verified ``Identity``, the claims a rule reads (a
    delegated identity's ``claims()`` or a connection's), or ``None`` for
    a caller nobody vouched for. A recipe is listed when the collection it
    reads admits this kind of caller -- ``delegation=`` and ``scope=``,
    asked exactly as ``Delegations`` asks them -- and its own grant
    admits it. What a listed recipe returns is still judged per document
    on the way out; this answers only *may it be called*.
    """
    from .delegation import collection_refuses

    claims = identity.claims() if hasattr(identity, "claims") else identity
    out = []
    for recipe in sorted(_book(guards).values(), key=lambda r: r.name):
        guard = guards.get(recipe.collection)
        if guard is None or collection_refuses(guard, claims) is not None:
            continue
        if recipe.refuses(claims) is None:
            out.append(recipe)
    return out


def expand_recipe(raw: bytes, req_id: int, resp_to: int,
                  guards: Mapping[str, Guard], verbose: bool,
                  claims: Mapping | None = None
                  ) -> tuple[bytes | None, bytes | None]:
    """`(rewritten, refusal)`. `(None, None)` leaves the message alone.

    Called first on every client message when the policy declares a recipe
    or `recipes_only`, so what follows it in the pump cannot tell an
    expanded recipe from the same pipeline written by hand. ``claims`` is
    whom the command is judged as, for a recipe with a grant.
    """
    head = decode_sections(raw)
    if head is None:
        return None, None
    flags, body = head[0], head[1]
    if not isinstance(body, Mapping):
        return None, None
    pipeline = body.get("pipeline") if "aggregate" in body else None
    at = body.get("aggregate")
    target = at if isinstance(at, str) else "this database"
    if isinstance(body.get("explain"), Mapping) and _names_recipe(
            body["explain"]):
        return None, _refuse(req_id, target, "a $recipe is not explained "
                             "through the boundary; `voyd-plan` shows its "
                             "expansion", verbose)
    if not (isinstance(pipeline, list) and _names_recipe(pipeline)):
        closed = ad_hoc_read(body, guards)
        if closed is not None:
            return None, _refuse(req_id, closed[0], closed[1], verbose)
        return None, None

    first = pipeline[0] if pipeline else None
    if not (isinstance(first, Mapping) and list(first) == [RECIPE_STAGE]):
        return None, _refuse(req_id, target, "$recipe must be the first "
                             "stage of its pipeline", verbose)
    call = first[RECIPE_STAGE]
    if (not isinstance(call, Mapping) or not isinstance(call.get("name"), str)
            or set(call) - {"name", "params"}):
        return None, _refuse(req_id, target, "$recipe takes {name: <string>, "
                             "params: {...}} and nothing else", verbose)
    rest = pipeline[1:]
    for stage in rest:
        ok = (isinstance(stage, Mapping) and len(stage) == 1
              and next(iter(stage)) in TRAILING)
        value = next(iter(stage.values())) if ok else None
        if not ok or isinstance(value, bool) or not isinstance(value, int) \
                or value < (1 if "$limit" in stage else 0):
            return None, _refuse(req_id, target, "only $limit and $skip, "
                                 "with whole numbers, may follow a $recipe",
                                 verbose)
    for option in REFUSED_OPTIONS:
        if option in body:
            return None, _refuse(req_id, target, f"a $recipe aggregate may "
                                 f"not carry {option!r}", verbose)
    recipe = _book(guards).get(call["name"])
    if recipe is None:
        return None, _refuse(req_id, target, f"no recipe is named "
                             f"{call['name']!r}", verbose)
    if at != recipe.collection:
        return None, _refuse(req_id, target, f"recipe {recipe.name!r} reads "
                             f"{recipe.collection!r}, not {target!r}",
                             verbose)
    why = recipe.refuses(claims)
    if why is not None:
        return None, _refuse(req_id, recipe.collection, why, verbose)
    try:
        expanded = recipe.bind(call.get("params"))
    except RecipeError as exc:
        return None, _refuse(req_id, recipe.collection, str(exc), verbose)
    rewritten = {k: ([*expanded, *rest] if k == "pipeline" else v)
                 for k, v in body.items()}
    guard = guards[recipe.collection]
    reads = getattr(guard, "recipe_reads", None)
    if isinstance(reads, dict):
        reads[recipe.name] = reads.get(recipe.name, 0) + 1
    if verbose:
        print(f"  voyd: recipe {recipe.name}@{recipe.version} on "
              f"{recipe.collection} -> {len(expanded)} stage(s)", flush=True)
    return encode_sections(req_id, resp_to, flags, rewritten), None
