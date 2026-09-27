"""Declare the rules once, in a file that is not your application.

The whole of a policy, and the whole of what anybody has to write::

    # voydfile.py
    from voyd import guard, deadline, revocable, tenant, budget, distinct

    @guard("notes")
    class Notes:
        expire_at  = deadline()
        forgotten  = revocable()
        tenant_id  = tenant()

    @guard("prompts")
    class Prompts:
        expire_at = deadline()
        tokens    = budget(8000)
        chunk     = distinct()

Then::

    voyd-wire --config voydfile.py --target localhost:27017

Your application is not edited. No import is added to it, no handle replaces
a collection, no read path is rewritten and nobody has to remember anything.
The connection string changes and a forgotten fact stops being reachable --
from Python, from Node, from Compass, from a notebook.

**Why a class body rather than a dict.** The field name is on the left and
the rule is on the right, which is the shape of the thing being described: a
schema with a rule per field. A dict would read the same way and lose the two
properties that matter -- the name is a real identifier so a typo is visible
where you wrote it, and the decorator can raise at *load* time rather than at
the first read. A policy file that is wrong should fail when it is loaded,
not when somebody's query returns the wrong rows.

**Why this is a declaration and not a framework.** Everything here compiles
to the ``Rule`` objects in ``voyd.engine`` -- the same ones a stranger writes
by hand in ``examples/portfolio.py``. Nothing is hidden behind the decorator:
``guard`` returns the class it was given and puts an ``AdmissionSpec`` in a
registry. If the declarative form cannot express what you need, drop to the
protocol and pass rules directly; there is no cliff between the two because
there is no second mechanism.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Callable

from .engine import (Budget, Clearance, Deadline, Distinct, EmbeddedWith,
                     Marked, Restricted, revoked)
from .engine.admission.rules import Unrecoverable
from .engine.admission import AdmissionSpec
from .engine.admission.masks import Mask


@dataclass(frozen=True)
class _Field:
    """One line of a policy: what this field means, not what it contains."""
    kind: str
    build: Callable[[str], Any] | None = None
    args: tuple = ()
    kwargs: dict | None = None


def deadline() -> _Field:
    """This field holds the instant after which the fact is gone.

    Enforced on the way out as well as by the TTL index, which is the whole
    point: the monitor runs about once a minute and serving a row during that
    window is the bug class this exists to remove.
    """
    return _Field("deadline", lambda f: Deadline(at_field=f))


def revocable(reason: str = "revoked") -> _Field:
    """This field holds a mark an operator sets to forget the fact *now*.

    Irreversible, because a revocation is an instruction about the world. Use
    ``holdable()`` for the reversible kind.
    """
    return _Field("mark", lambda f: revoked(f) if reason == "revoked"
                  else Marked(field=f, reason=reason, reversible=False))


def holdable(reason: str = "quarantined") -> _Field:
    """A reversible mark: a hypothesis, not an instruction.

    Quarantine without a review loop is a graveyard, so this one can be
    lifted and the row is deliberately not given a deadline -- it is the
    evidence.
    """
    return _Field("mark", lambda f: Marked(field=f, reason=reason,
                                           reversible=True))


def tenant() -> _Field:
    """This field is the tenant id, enforced on *both* halves.

    Required in a reduction, and checked per document on the way out,
    which are two different mistakes and both of them leak. See
    ``tests/test_a_real_driver_through_a_real_boundary.py``.
    """
    return _Field("tenant")


def restricted_to(claim: str) -> _Field:
    """This field names the audience; admit only callers whose ``claim``
    overlaps it."""
    return _Field("rule", lambda f: Restricted(field=f, claim=claim))


def subjects(*, key: str) -> _Field:
    """This field is an array whose elements are subjects in their own right.

        @guard("books")
        class Books:
            expire_at = deadline()
            forgotten = revocable()
            chapters  = subjects(key="title")

    A book with chapters, a ticket with comments, a case file with notes:
    the embedded pattern MongoDB recommends, and increasingly the shape
    retrieval works over. Every rule above reads *top-level* fields, so
    without this a chapter carrying the exact mark `revocable()` writes is
    admitted with its parent, counted nowhere, and reported as "nothing
    was refused". Declaring the array makes the refusal *see* it: the
    refused elements are removed from the document and the parent is
    served without them, because a book is not erased by one retracted
    chapter.

    **`key` is required here and optional in the engine, deliberately.**
    A subdocument has no `_id`, so there are only three ways to name one
    and two are bad. Position -- `chapters.3` -- is wrong the first time
    anybody `$pull`s an element, and wrong silently, which on an erasure
    path is the worst available property. Promoting every chapter to its
    own document gives up the pattern this exists to serve. So the name is
    a field you already have, or add.

    Anonymous subjects are refusable on read and can never be
    *addressed* -- and an erasure request names a thing. A policy file that
    declared subjects without a key would ship a subject nothing can ever
    revoke, so this asks for one rather than defaulting. It is enforced,
    not conventional: an element that does not carry `key` is refused as
    `unnamed`.
    """
    if not isinstance(key, str) or not key.strip():
        raise ValueError(
            "subjects() needs key= naming the field that identifies each "
            "element. A subdocument has no _id, and a subject nothing can "
            "name is one no erasure request can reach")
    return _Field("subjects", args=(key,))


def clearance(*, order: tuple[str, ...] | list[str],
              roles: dict[str, str] | None = None,
              via: str = "roles", default: str | None = None) -> _Field:
    """This field holds a sensitivity level; admit callers cleared for it.

        classification = clearance(
            order=("public", "internal", "secret"),
            roles={"analyst": "internal", "sec-cleared": "secret"})

    ``order`` is the ladder, lowest first. ``roles`` says which rung each
    of your deployment's roles stands on, and it is not optional padding
    -- it is the whole reason this is declarable at all.

    **Where the caller's level comes from is the design.** The boundary
    does not accept a level the client asserts; a rule that believed
    ``{"clearance": "secret"}`` because it was handed one would be an
    authorisation system whose only input is the attacker's. It asks the
    deployment instead, and the deployment answers `connectionStatus`
    with **roles** -- which say who somebody is and not how far up a
    ladder they stand. Nothing in a MongoDB role carries a level, so
    somebody has to say, and a policy file is where somebody says things.

    ``via`` names the claim holding the caller's roles: ``"roles"``, or
    ``"groups"`` if you would rather write the mapping against those. A
    caller holding several is cleared to the **highest** level any of them
    maps to; a role you did not map contributes nothing, because an
    unmapped role is an unanswered question and the answer to an
    unanswered question here is no.

    **It fails closed in four directions**, and each one is a default
    somebody would otherwise get wrong on a Friday:

    - a caller with no matching role is cleared for **nothing**, not for
      the lowest rung -- so they are refused even a ``public`` document.
      This sentence used to say "the lowest level", which is the weaker
      of the two behaviours and is not the one ``Clearance._held``
      implements: an unmapped role is an unanswered question, and the
      answer to an unanswered question here is no. A reader who believed
      the old wording would size a role table expecting public documents
      to flow to everyone, and find out otherwise from a support ticket;
    - a document labelled with something not in ``order`` is refused --
      an unrecognised classification is not a low one;
    - a document with no label at all is refused unless ``default`` is
      set, because untagged is not public and untagged is exactly the
      population written before anybody thought about this;
    - and it is not bypassable. Break-glass exists to see what was
      *forgotten*; clearance is not a forgetting reason and no handle is
      entitled to waive it.

    Omit ``roles`` and the rule reads a scalar level from a claim named by
    ``via``. The boundary cannot supply one -- it will say so at boot,
    naming this collection -- so that form belongs where an application
    already knows the level.
    """
    if not order:
        raise ValueError(
            "clearance() needs an order: the levels, lowest first. Without "
            "one there is no ladder and every document is unlabelled")
    ladder = tuple(order)
    if len(set(ladder)) != len(ladder):
        raise ValueError(
            f"clearance(order={ladder!r}) repeats a level. Two rungs with "
            f"one name is not an ordering")
    mapped = tuple(sorted((roles or {}).items()))
    for role, level in mapped:
        if level not in ladder:
            raise ValueError(
                f"clearance(): role {role!r} maps to {level!r}, which is not "
                f"in order={ladder!r}. A role cleared for a level this "
                f"policy does not define is cleared for nothing, silently")
    return _Field("rule", lambda f: Clearance(
        order=ladder, field=f, claim=via, roles=mapped, default=default))


def embedded_with(model: str) -> _Field:
    """This field records which embedding model produced the vector.

    A vector from last quarter's model is not a worse hit, it is a hit in a
    different space.
    """
    return _Field("rule", lambda f: EmbeddedWith(model=model, field=f))


def budget(limit: int) -> _Field:
    """This field is the per-document cost; refuse once ``limit`` is spent.

    Set-relative: the same document is admitted alone and refused in company,
    which no index filter and no policy engine can express.
    """
    return _Field("rule", lambda f: Budget(limit=limit, cost_field=f))


def distinct() -> _Field:
    """This field is the content identity; refuse a repeat already on the page."""
    return _Field("rule", lambda f: Distinct(on=f))


def auto_embed(model: str) -> _Field:
    """This field is text the *server* embeds, with the model named here.

    The other half of `embedded_with`. That one refuses a **document** whose
    vector came from the wrong model; this one removes the way a vector
    comes to be wrong in the first place, by taking the embedder out of the
    application entirely. The index holds the text, mongot embeds it on
    write, and mongot embeds the query with the same model at read time.
    Nothing in your process ever computes a vector, so nothing in your
    process can drift from the index.

    **Declaring it here also refuses the query that would defeat it.** A
    client sending its own ``queryVector`` against a collection the
    deployment declared server-embedded is the exact drift this prevents,
    arriving through a driver that never heard of the declaration -- and
    comparing a vector to an index built by a different model does not
    fail, it returns a number between -1 and 1, which is the whole problem.
    The boundary refuses it by name. See ``voyd/wire/proxy.py``.

    Declared, not probed. A deployment that cannot do server-side
    embedding says so at index creation and ``--ensure`` falls back to an
    ordinary vector index, loudly -- so adopting this is safe before every
    deployment supports it. What is *not* safe is adopting it and then
    quietly sending client vectors anyway, which is what the boundary's
    refusal is for.
    """
    return _Field("auto_embed", args=(model,))


def sealed() -> _Field:
    """This field is ciphertext at rest, under a key scoped to the tenant.

    The one thing refusal structurally cannot do. Refusal binds *this*
    application's read path, so it has nothing to say about a replica, a
    snapshot, or the backup somebody restores next year -- none of those run
    this read path. Destroying the key binds all of them at once, and this
    is how a field opts into being destroyable that way.

    **The key is the tenant's, which is why this requires ``tenant()``.**
    A scope with no name is a scope with one key, and one key per collection
    makes erasure all-or-nothing: the subject who asked to be forgotten takes
    every other tenant with them. So ``sealed()`` without ``tenant()`` is
    refused at *load*, in the same breath as every other way a policy file
    can be wrong.

    Enforced with ``--key-vault``, which encrypts on the boundary: no
    writer in any *language* can forget -- not the shell, not the migration
    script, not the service written next year by somebody who has not read
    this file. A driver's own ``schema_map`` gets you the same ciphertext
    one process at a time; this gets it once.

    It is also what costs the boundary its purity: holding keys makes it
    a custody holder, and a sealed read decrypts before it refuses -- so a
    document a deadline was going to refuse has still been decrypted by
    the time the deadline sees it. Wasted work rather than a leak, since
    it never leaves the process, but worth naming.

    An ``Unrecoverable`` rule is attached alongside, so a sealed field that
    reaches a read path which never decrypted it is refused by name rather
    than serialised into a prompt as a ``Binary`` blob pretending to be text.
    """
    return _Field("sealed", lambda f: Unrecoverable(field=f))


def sanitized(*, on_match: str = "refuse", patterns: tuple | list = (),
              without: tuple | list = ()) -> _Field:
    """This field is text for a model; check it for instructions aimed at one.

        @guard("notes")
        class Notes:
            text = sanitized()
            body = sanitized(on_match="neutralise",
                             patterns=[("wire_money", r"wire \\$\\d+ to")])

    Two things happen to it on every document that leaves, and only the
    first is exact:

    - **invisible characters are removed** -- zero-width, bidi overrides,
      the Unicode tag block. Whether a string contains U+200B is a fact
      about its bytes, so this is a guarantee: nothing in ``INVISIBLE``
      reaches a prompt from a declared field.
    - **signatures are looked for** -- "ignore previous instructions",
      chat-template tokens, HTML comments, markdown images whose URL
      carries a query string. This is a **tripwire, not a guarantee**:
      a paraphrase, another language, or text split across two chunks
      goes straight past it, and a document that *quotes* an injection
      to discuss it is matched exactly like one that carries it.

    ``on_match="refuse"`` withholds a matching document, counted as
    ``injection_signature``. ``"neutralise"`` replaces the matched span
    with a marker and serves the rest -- unless the match was only found
    after folding (full-width letters, say) and has no exact span to cut,
    in which case the document is refused rather than served uncut.

    ``patterns`` adds ``(name, regex)`` or ``(name, regex, replacement)``
    signatures; ``without`` drops built-ins by name. Both are checked at
    load, including for a regex that matches the empty string.

    It runs in the terminal pass, after any ``@transform``, and a
    ``distinct``, ``count`` or reducing ``aggregate`` on the collection is
    refused: those return the text without the document it came from, so
    there would be nothing to neutralise it on. The list itself is in
    ``voyd/engine/admission/sanitize.py``.
    """
    from .engine.admission.sanitize import sanitizer

    # Validated now, against a placeholder path, so a bad regex fails the
    # line it was written on rather than the first `@guard` that uses it.
    sanitizer("_", on_match=on_match, patterns=patterns, without=without)
    return _Field("rule", lambda f: sanitizer(
        f, on_match=on_match, patterns=patterns, without=without,
        where=f"{f}: "))
def mask(*, strip: bool = False,
         visible_to: str | tuple[str, ...] | list[str] | None = None,
         via: str = "roles") -> _Field:
    """This field's value does not leave, even when its document does.

        @guard("contracts")
        class Contracts:
            expire_at = deadline()
            tenant_id = tenant()
            ssn       = mask()                       # served as null
            internal  = mask(strip=True)             # the key is removed
            salary    = mask(visible_to=("hr",))     # null unless roles has hr

    The document is admitted and the value is rewritten in the reply bytes
    before a driver sees them. It runs after every rule and after every
    transform, so a transform cannot put a masked value back: whatever it
    returns is masked again on the way out.

    **A masked field cannot be asked about either.** A filter, a sort, a
    ``distinct``, a ``$group`` or a ``$project`` that names it is refused,
    because each one turns the value into something else -- a yes/no, an
    order, a list, a renamed copy -- that the mask never sees. Excluding it
    (``{"ssn": 0}``, ``$unset``) is always allowed. Writing it is allowed;
    copying it into another field inside the server is not.

    ``visible_to`` names the values of the caller's ``via`` claim that see
    the field. The claim is the one the *server* reports for the
    connection, never one the client asserts, and a caller the boundary
    cannot identify sees the mask.

    Top-level fields only, by construction: the attribute name is the
    path. Mask the parent of a nested value, and note that elements of a
    ``subjects()`` array are not masked individually.
    """
    if isinstance(visible_to, str):
        visible_to = (visible_to,)
    audience = tuple(visible_to or ())
    if visible_to is not None and not audience:
        raise ValueError(
            "mask(visible_to=()) names an empty audience. Omit it to hide "
            "the value from everyone; an empty list reads as a whitelist "
            "somebody forgot to fill in")
    if not all(isinstance(a, str) and a.strip() for a in audience):
        raise ValueError(
            f"mask(visible_to={audience!r}): every entry must be a "
            f"non-empty string -- a role or group the server reports")
    if not isinstance(via, str) or not via.strip():
        raise ValueError("mask(via=...) must name a claim, e.g. 'roles'")
    return _Field("mask", lambda f: Mask(field=f, strip=bool(strip),
                                         visible_to=audience, via=via))


# Every collection declared in a loaded policy file, by name, with the
# policy choices that are not rules: what a `delete` on the wire should
# mean, and which fields are ciphertext at rest under whose key.
REGISTRY: dict[str, AdmissionSpec] = {}
OPTIONS: dict[str, dict] = {}

ON_DELETE = ("forward", "revoke")


def _as_rule(collection: str, name: str, value: Any) -> Any:
    """A rule somebody else wrote, installed straight from a policy file.

    This is the extension point reaching the wire. ``rules.py`` says a
    third-party rule is the same kind of object as a builtin one with no
    privileged path, and that was true of the *engine* and false of the
    *policy file*: the vocabulary above is a fixed set of helpers, so a
    stranger's rule had nowhere to be written. Declaring one is now a line
    that reads like every other line:

        @guard("notes")
        class Notes:
            expire_at = deadline()
            region    = Jurisdiction(allowed="eu")

    **It was worse than missing, which is why this function refuses as
    much as it accepts.** A rule object in a class body was simply not a
    ``_Field``, so it was skipped -- and the boundary came up announcing
    "refuses on [deadline, revoked]" while serving every document the
    stranger's rule was written to refuse. No error, no warning, and a
    policy file that looked exactly like a working one. That is this
    project's own named failure, in the loader that reads the file the
    whole product is.

    So anything in a class body that is *half* a rule raises here, by
    name. The protocol is three members -- ``reason``, ``refuses`` and
    ``clause`` -- and the two ways to get it wrong are to write one of
    them and to misspell one of them, which look identical from here.

    ``field`` is rebound to the attribute name when the rule carries one,
    so ``region = Jurisdiction(...)`` reads the ``region`` field without
    saying so twice. That is what every other line in a policy file does,
    and a rule that had to repeat its own name would be the one exception.
    """
    partial = [m for m in ("reason", "refuses", "clause") if hasattr(value, m)]
    if not partial:
        return None                      # a constant, a helper, a docstring
    if len(partial) < 3:
        raise ValueError(
            f"{collection}: {name!r} has {sorted(partial)} and is missing "
            f"{sorted({'reason', 'refuses', 'clause'} - set(partial))}. A "
            f"rule needs all three -- `reason` names the refusal, "
            f"`refuses(doc)` is the verdict, `clause()` is the query half "
            f"or None. Half a rule refuses nothing, and would have been "
            f"skipped in silence")
    if not isinstance(getattr(value, "reason", None), str):
        raise ValueError(
            f"{collection}: {name!r} has a `reason` that is not a string. "
            f"It is the name this refusal is counted and reported under, so "
            f"it has to be one")
    if not callable(value.refuses):
        raise ValueError(
            f"{collection}: {name!r} has a `refuses` that is not callable")
    if hasattr(value, "field"):
        try:
            return replace(value, field=name)
        except Exception:                                      # noqa: BLE001
            # Not a dataclass, or `field` is not an init argument. The rule
            # is installed as written rather than rejected: it named its
            # own field, which is merely less tidy than letting the
            # attribute name do it.
            pass
    return value


# Page-shaping declared per collection, by the same registry mechanism
# the rules use. Kept apart from REGISTRY because the two are different
# kinds of claim and must not be confusable: a rule is a guarantee that
# `voyd-plan` can reason about, and a transform is an optimisation that
# it explicitly cannot.
TRANSFORMS: dict[str, list] = {}


def transform(collection: str):
    """Declare page-shaping for one collection. Returns the class unchanged.

        @transform("notes")
        class Diversify:
            name = "mmr"

            def on_egress(self, docs, *, request):
                return mmr(docs, diversity=0.7)

    It runs **inside** the boundary, which is the entire point and the
    only reason offering this is safe. A transform is shown documents
    that have already survived every pure rule, and everything it
    returns -- reordered, merged, restored from a cache, invented --
    goes through the authoritative check afterwards. So:

        **a transform cannot widen what a read returns.** Not because it
        was reviewed. Because the boundary is downstream of it.

    The corollary is a rule about how to write one. A transform is *not*
    an enforcement point and must never be used as one. Dropping a
    document for a security reason here duplicates a rule badly: the
    rule is the place, the rule is what is re-asked terminally, and the
    rule is the half `voyd-plan` can tell you about before you ship it.
    A transform that refuses gets no credit and no attestation.

    Two members, checked at load for the same reason a half-written rule
    is: a `name` and an `on_egress`, and the two ways to get that wrong
    are to omit one and to misspell one. From a loader they look
    identical, and a skipped transform is a boundary that comes up
    announcing a page shape it is not applying.
    """
    def decorate(cls):
        made = cls() if isinstance(cls, type) else cls
        name = getattr(made, "name", None)
        egress = getattr(made, "on_egress", None)
        missing = [what for what, got in (("name", name),
                                          ("on_egress", egress))
                   if got is None]
        if missing:
            raise TypeError(
                f"{collection}: @transform on "
                f"{getattr(cls, '__name__', cls)!r} is missing "
                f"{' and '.join(missing)}. A transform is two members -- a "
                f"name to report it by and an on_egress(docs, *, request) "
                f"-- and one that is half-written would be silently skipped")
        if not callable(egress):
            raise TypeError(
                f"{collection}: {name!r}.on_egress is not callable")
        if not isinstance(name, str) or not name.strip():
            raise TypeError(
                f"{collection}: a transform's name must be a non-empty "
                f"string; it is what a skipped one is reported by")
        TRANSFORMS.setdefault(collection, []).append(made)
        # Declaration order is application order, so a transform declared
        # after a `@guard` has to reach back into the spec it belongs to.
        # Frozen, so this is a replace rather than an assignment.
        if collection in REGISTRY:
            from dataclasses import replace as _replace
            REGISTRY[collection] = _replace(
                REGISTRY[collection],
                transforms=tuple(TRANSFORMS[collection]))
        return cls
    return decorate


def rerank(collection: str, *, diversity: float = 0.3,
           vector: str = "embedding", top: int | None = None):
    """Diversify this collection's pages. A built-in transform.

        # voydfile.py
        rerank("notes", diversity=0.3, vector="embedding")

    A function rather than a decorator because there is no class body to
    write: `@transform` is for a reader's own code, and this is the one
    that ships. Both land in the same egress path and neither is an
    enforcement point.

    A vector index returns the most similar documents, which on a real
    corpus means the most similar documents *to each other* -- ten chunks
    of one contract outranking one chunk each from ten contracts. MMR
    trades a little relevance for coverage.

    ``diversity`` is ``1 - lambda``: 0 keeps the index's order, 1 ignores
    relevance entirely. Small values are the useful ones.
    """
    from .engine.admission.rerank import MMR

    made = MMR(vector_field=vector, diversity=diversity, top=top)
    return transform(collection)(made)


# Aggregation stages and expression operators mongod does not know, run by
# the boundary, by the name a pipeline calls them. Kept apart from
# TRANSFORMS for the reason TRANSFORMS is kept apart from REGISTRY: a
# transform shapes every read of a collection, and one of these runs only
# when a client's pipeline asks for it by name.
STAGES: dict[str, Callable] = {}
OPERATORS: dict[str, Callable] = {}

# Names the server already means something by. Registering one would
# silently change what an ordinary pipeline does, so both decorators refuse
# them at load. The stage list is MongoDB 8's; the operator list is the
# common expression vocabulary, not every operator there is.
NATIVE_STAGES = frozenset({
    "$addFields", "$bucket", "$bucketAuto", "$changeStream",
    "$changeStreamSplitLargeEvent", "$collStats", "$count", "$currentOp",
    "$densify", "$documents", "$facet", "$fill", "$geoNear", "$graphLookup",
    "$group", "$indexStats", "$limit", "$listLocalSessions",
    "$listSampledQueries", "$listSearchIndexes", "$listSessions", "$lookup",
    "$match", "$merge", "$out", "$planCacheStats", "$project",
    "$querySettings", "$rankFusion", "$redact", "$replaceRoot",
    "$replaceWith", "$sample", "$scoreFusion", "$search", "$searchMeta",
    "$set", "$setWindowFields", "$shardedDataDistribution", "$skip",
    "$sort", "$sortByCount", "$unionWith", "$unset", "$unwind",
    "$vectorSearch",
})
NATIVE_OPERATORS = frozenset({
    "$abs", "$accumulator", "$add", "$allElementsTrue", "$and",
    "$anyElementTrue", "$arrayElemAt", "$arrayToObject", "$avg", "$ceil",
    "$cmp", "$concat", "$concatArrays", "$cond", "$convert", "$dateAdd",
    "$dateDiff", "$dateFromString", "$dateToString", "$dateTrunc",
    "$divide", "$eq", "$exp", "$filter", "$first", "$floor", "$function",
    "$getField", "$gt", "$gte", "$ifNull", "$in", "$indexOfArray",
    "$indexOfCP", "$isArray", "$isNumber", "$last", "$let", "$literal",
    "$ln", "$log", "$lt", "$lte", "$ltrim", "$map", "$max", "$median",
    "$mergeObjects", "$meta", "$min", "$mod", "$multiply", "$ne", "$not",
    "$objectToArray", "$or", "$pow", "$range", "$reduce", "$regexFind",
    "$regexFindAll", "$regexMatch", "$replaceAll", "$replaceOne",
    "$reverseArray", "$round", "$rtrim", "$setField", "$size", "$slice",
    "$sortArray", "$split", "$sqrt", "$strLenCP", "$strcasecmp",
    "$substr", "$substrCP", "$subtract", "$sum", "$switch", "$toBool",
    "$toDate", "$toDouble", "$toInt", "$toLong", "$toLower",
    "$toObjectId", "$toString", "$toUpper", "$trim", "$trunc", "$type",
    "$unsetField", "$zip",
})


def _virtual(kind: str, name: str, native: frozenset, table: dict):
    """The one registration path both decorators share."""
    if (not isinstance(name, str) or not name.startswith("$")
            or len(name) < 2 or name.startswith("$$") or "." in name):
        raise ValueError(
            f"@{kind}({name!r}): named the way a pipeline calls it -- one "
            f"'$', then a name")
    if name in native:
        raise ValueError(
            f"@{kind}({name!r}): the server already has {name}. Declaring "
            f"it here would change what every pipeline using it means, "
            f"silently")
    if name in table:
        raise ValueError(f"@{kind}({name!r}) is declared twice. One name, "
                         f"one function")

    def decorate(fn):
        if not callable(fn):
            raise TypeError(f"@{kind}({name!r}) decorates {fn!r}, which "
                            f"cannot be called")
        table[name] = fn
        return fn
    return decorate


def stage(name: str):
    """Declare an aggregation stage the server does not know. Runs here.

        @stage("$keywordRank")
        def keyword_rank(args, docs, ctx):
            words = args["words"]
            return sorted(docs, key=lambda d: -score(d["text"], words))

    Then, from any driver::

        db.notes.aggregate([{"$match": {...}},
                            {"$keywordRank": {"words": ["refund"]}},
                            {"$limit": 3}])

    ``fn(args, docs, ctx)`` gets the stage's argument (``$$name``
    references resolved), copies of the documents the policy **admitted**
    -- already masked and neutralised, never the refused ones -- and a
    context: the collection, the database, the server-reported caller
    claims, ``ctx.now``, and ``ctx.publish(name, value)`` for a value later
    stages read as ``$$name``. It returns an iterable of documents and may
    be ``async``. It may add fields, drop documents and reorder them; it
    may not introduce one, so every output is traced by ``_id`` to an input
    it was handed and every rule is asked again on the way out. Native
    stages after it run in MongoDB on a temporary collection holding only
    its output. See ``voyd/wire/policy/stages.py``.

    Refused at load: a name that does not start with ``$``, one the server
    already uses, one declared twice, a function that is not callable.
    """
    return _virtual("stage", name, NATIVE_STAGES, STAGES)


def operator(name: str):
    """Declare an expression operator the server does not know. Runs here.

        @operator("$wordCount")
        def word_count(doc, args, ctx):
            return len(str(args).split())

    Used as the whole value of one field in an ``$addFields`` or ``$set``::

        {"$addFields": {"words": {"$wordCount": "$text"}}}

    ``fn(doc, args, ctx)`` is called once per admitted document and returns
    the field's value. ``args`` arrive resolved: ``"$field"`` is that
    document's value, ``"$$name"`` a value an earlier stage published, and
    ``{"$literal": x}`` is ``x`` untouched. The rest of that stage may only
    be field paths, variables and literals; anything richer that contains a
    registered operator is refused rather than half-evaluated. Everything
    else about a stage applies: admitted documents only, and every rule
    again after.
    """
    return _virtual("operator", name, NATIVE_OPERATORS, OPERATORS)


# Named pipelines, by name across the whole policy: a client sends only the
# name, so two collections cannot each have their own `support_context`.
RECIPES: dict[str, Any] = {}


def recipe(name: str, *, collection: str,
           samples: dict | list[dict] | None = None):
    """Declare a named, governed pipeline. Returns the function unchanged.

        @recipe("support_context", collection="tickets")
        def support_context(q: str = "refund", k: int = 8):
            return [{"$vectorSearch": {"index": "v", "path": "embedding",
                                       "query": q, "numCandidates": k * 10,
                                       "limit": k}},
                    {"$addFields": {"clean": {"$redactPII": "$text"}}}]

    Then, from any driver::

        db.tickets.aggregate([{"$recipe": {"name": "support_context",
                                           "params": {"q": "refund"}}}])

    The boundary expands it before doing anything else with the message,
    so the expansion meets every rule and every refusal a hand-written
    pipeline would. Parameters are annotated ``str``, ``int``, ``float``,
    ``bool`` or ``list[str]`` (optionally ``| None``) and checked against
    the annotation; a string beginning with ``$`` is refused; and a call
    whose expansion uses a key or ``$``-name that no declared expansion
    used is refused, so a parameter can change a value and never a name.
    ``samples=`` supplies the values a parameter with no default is
    expanded at -- at load, and in ``voyd-plan``. Only ``$limit`` and
    ``$skip`` may follow ``$recipe``. See ``voyd/wire/policy/recipes.py``.

    Refused at load: a duplicate name, a non-callable, an unannotated or
    ``*args`` parameter, a default or sample of the wrong type, an
    expansion that is not a pipeline or uses ``$out``, ``$merge``,
    ``$where`` or ``$function``, a stage name nothing declares, and -- in
    ``load`` -- a recipe on a collection with no ``@guard``.
    """
    from .wire.policy.recipes import Recipe

    if name in RECIPES:
        raise ValueError(f"@recipe({name!r}) is declared twice. A client "
                         f"sends only the name, so one name is one pipeline")

    def decorate(fn):
        made = Recipe(fn, name=name, collection=collection, samples=samples)
        RECIPES[name] = made
        if collection in REGISTRY:
            REGISTRY[collection] = replace(
                REGISTRY[collection], recipes=_recipes_for(collection))
        return fn
    return decorate


def _recipes_for(collection: str) -> tuple:
    return tuple(r for r in RECIPES.values() if r.collection == collection)


def _check_recipes() -> None:
    """What only the whole file can answer: every recipe has a guard, every
    stage it names exists, and `recipes_only` has something to read by."""
    for made in RECIPES.values():
        if made.collection not in REGISTRY:
            raise ValueError(
                f"@recipe({made.name!r}) reads {made.collection!r}, which "
                f"has no @guard. A recipe is a governed read, and on an "
                f"unguarded collection nothing would govern it")
        for pipeline in made.expansions:
            for stage_ in pipeline:
                key = next(iter(stage_))
                if key not in NATIVE_STAGES and key not in STAGES:
                    raise ValueError(
                        f"@recipe({made.name!r}) uses {key}, which is "
                        f"neither a MongoDB stage nor a declared @stage")
    for collection, spec in REGISTRY.items():
        if spec.recipes_only and not spec.recipes:
            raise ValueError(
                f"{collection}: recipes_only=True and no @recipe reads it. "
                f"That is a collection nothing can read, which is a drop "
                f"with extra steps")


def guard(collection: str, *, lineage_field: str | None = None,
          on_delete: str = "forward", backfill: int = 4,
          prefilter: bool = False, recipes_only: bool = False,
          attest: bool = False):
    """Declare the rules for one collection. Returns the class unchanged.

    ``attest=True`` has the boundary sign every document it serves from
    this collection: a ``_voyd`` stamp naming the key, the policy file's
    hash, the document's digest as served and who it was served to, so a
    client or an auditor can later prove a chunk in a prompt came through
    here unmodified. Needs ``voyd-wire --attest-key``. See
    ``voyd/attest.py``.

    ``on_delete="revoke"`` gives a client's ``delete`` the better meaning:
    the row is marked, unreachable on the next read, still on disk, its
    deadline pulled in so the reaper collects it. Opt-in, because silently
    redefining `delete` for an operator who did not ask for it is exactly the
    surprise this project exists to remove -- and because somebody, somewhere,
    means it.

    ``backfill`` is how many times a lone ``$vectorSearch`` page is
    over-fetched so the refused rows can be replaced from further down the
    ranking; the proxy cuts the reply back to the client's ``limit`` after
    the per-document check. ``1`` turns it off. Bounded at 20.

    ``prefilter=True`` asks the vector index to leave refused rows out of
    the ranking: ``--ensure`` declares every field the rules read as a
    ``filter`` field on the ``auto_embed`` index, and the boundary ANDs the
    rules into each ``$vectorSearch.filter`` once ``--ensure`` or
    ``--verify`` has confirmed the live index carries them. Opt-in, because
    a vectorSearch index cannot be updated in place -- on an index that
    already exists this is a rebuild -- and because the per-document check
    on the way out still runs and is still the guarantee. Needs an
    ``auto_embed()`` field (the one vector index this file builds) and rules
    that can all be asked as a query without knowing the caller.

    ``recipes_only=True`` makes the collection's ``@recipe`` pipelines the
    only way to read it: an ad-hoc ``find``, ``aggregate``, ``count`` or
    ``distinct`` -- a ``find`` by ``_id`` included -- is refused, so the
    retrieval logic has exactly one reviewed home. Writes are untouched.

    Raises at *load* time for a body it cannot compile -- an unknown value, a
    second deadline, no rule at all. A policy file is the one place an error
    must not wait for a query to surface it.
    """
    if on_delete not in ON_DELETE:
        raise ValueError(
            f"{collection}: on_delete={on_delete!r}; expected one of "
            f"{ON_DELETE}. 'forward' lets a delete really delete")
    if (isinstance(backfill, bool) or not isinstance(backfill, int)
            or not 1 <= backfill <= 20):
        raise ValueError(
            f"{collection}: backfill={backfill!r}; expected a whole number "
            f"from 1 (off) to 20. It multiplies every vector search's "
            f"candidate set, so past 20 it is a different workload")

    def decorate(cls):
        rules, tenant_field, seen = [], None, set()
        subject_path: str | None = None
        subject_key: str | None = None
        sealed_fields: list[str] = []
        embedded: dict[str, str] = {}
        masks: list[Mask] = []
        for name, value in vars(cls).items():
            if name.startswith("__"):
                continue
            if not isinstance(value, _Field):
                custom = _as_rule(collection, name, value)
                if custom is not None:
                    rules.append(custom)
                continue
            if value.kind == "tenant":
                if tenant_field is not None:
                    raise ValueError(
                        f"{collection}: two tenant fields ({tenant_field!r} "
                        f"and {name!r}); a scope with two keys is not a scope")
                tenant_field = name
                continue
            if value.kind == "deadline" and "deadline" in seen:
                raise ValueError(
                    f"{collection}: two deadline fields. Two clocks is the "
                    f"drift this exists to remove")
            if value.kind == "sealed":
                sealed_fields.append(name)
            if value.kind == "auto_embed":
                embedded[name] = value.args[0]
                continue        # a declaration about the index, not a rule
            if value.kind == "mask":
                if name == "_id":
                    raise ValueError(
                        f"{collection}: mask() on _id. It is how a document "
                        f"is addressed by every update and delete the "
                        f"application makes, and a boundary that nulled it "
                        f"would break the application rather than protect "
                        f"anything")
                assert value.build is not None
                masks.append(value.build(name))
                continue        # a rewrite of what is served, not a rule
            if value.kind == "subjects":
                if subject_path is not None:
                    raise ValueError(
                        f"{collection}: two subject arrays ({subject_path!r} "
                        f"and {name!r}). A document has one shape, and two "
                        f"answers to 'which thing is the subject' is no "
                        f"answer -- declare the other collection separately")
                subject_path, subject_key = name, value.args[0]
                continue        # a declaration about shape, not a rule
            seen.add(value.kind)
            assert value.build is not None
            rules.append(value.build(name))

        # A field cannot be both hidden from the server and embedded by
        # it, and there is deliberately no check for that here, because in
        # this shape the contradiction cannot be *written*. The path is the
        # attribute name, so `text = sealed()` followed by
        # `text = auto_embed(...)` is not two conflicting declarations --
        # Python binds the name once and the second wins.
        #
        # A guard here would be code that can never run. It is instead one
        # more answer to "why a class body rather than a dict", up in the
        # module docstring: a shape in which a whole class of contradiction
        # has nowhere to live beats a shape that detects it.
        #
        # What is *not* closed: sealing `text` here while an Atlas index
        # declared somewhere else auto-embeds `text`. No policy file can
        # see that -- the declaration lives in the cluster, not in this
        # file -- and the wire boundary does not create indexes.

        # Two declarations naming the same thing have to agree about it.
        for field, rule in ((r.field, r) for r in rules
                            if type(r).__name__ == "EmbeddedWith"):
            for path, model in embedded.items():
                if rule.model != model:
                    raise ValueError(
                        f"{collection}: embedded_with({rule.model!r}) on "
                        f"{field!r} and auto_embed({model!r}) on {path!r}. "
                        f"One says refuse any vector not from "
                        f"{rule.model!r}; the other says the server will "
                        f"produce them with {model!r}. Every document the "
                        f"index embeds would be refused by the rule beside "
                        f"it, and the collection would read as empty")

        if sealed_fields and tenant_field is None:
            raise ValueError(
                f"{collection}: sealed() on {', '.join(sealed_fields)} with "
                f"no tenant() field. The key is scoped to the tenant, so a "
                f"scope with no name is one key for the whole collection -- "
                f"and destroying it to forget one subject would make every "
                f"other tenant's rows unreadable at the same instant. "
                f"Declare tenant(), or encrypt with a literal keyId outside "
                f"this boundary and accept that erasure is all-or-nothing")

        if not rules and tenant_field is None and not masks:
            raise ValueError(
                f"{collection}: declared with no rules. A guard that refuses "
                f"nothing is a slower read, and naming it a guard is worse "
                f"than not having one")

        if on_delete == "revoke" and not any(
                getattr(r, "reversible", None) is False for r in rules):
            raise ValueError(
                f"{collection}: on_delete='revoke' needs a revocable() field "
                f"to write the mark into. Without one there is nowhere to "
                f"record that the fact was forgotten, and the delete would "
                f"silently do nothing at all")

        if subject_path is not None and not rules:
            raise ValueError(
                f"{collection}: subjects({subject_path!r}) with no reason to "
                f"refuse one. The array makes refusal able to see its "
                f"elements; something still has to refuse them -- a "
                f"deadline() or a revocable() beside it")

        if prefilter and not embedded:
            raise ValueError(
                f"{collection}: prefilter=True with no auto_embed() field. "
                f"The filter fields are declared on the vector index this "
                f"file builds, and without auto_embed() it builds none -- "
                f"so the prefilter would have no index to live in")
        if prefilter:
            blind = [type(r).__name__ for r in rules
                     if getattr(r, "needs_caller", False) or r.clause() is None]
            if blind:
                raise ValueError(
                    f"{collection}: prefilter=True, and {', '.join(blind)} "
                    f"cannot be asked as a query without knowing the "
                    f"caller. A prefilter missing one rule is not a "
                    f"narrower one, so there is nothing to push down")

        REGISTRY[collection] = AdmissionSpec(
            collection, rules=tuple(rules), tenant=tenant_field,
            lineage_field=lineage_field, subjects=subject_path,
            subject_key=subject_key,
            masks=tuple(masks),
            # A `@transform` declared *above* the `@guard` is already
            # registered by the time this runs; one declared below reaches
            # back. Either order works and neither is the documented one,
            # because a policy file that behaved differently depending on
            # decorator order would be the exact class of surprise this
            # loader exists to refuse.
            transforms=tuple(TRANSFORMS.get(collection, ())),
            recipes=_recipes_for(collection),
            recipes_only=bool(recipes_only),
            attest=bool(attest))
        OPTIONS[collection] = {"on_delete": on_delete,
                               "backfill": backfill,
                               "sealed": tuple(sealed_fields),
                               "scope_field": tenant_field,
                               "auto_embed": dict(embedded),
                               "prefilter": bool(prefilter),
                               "attest": bool(attest)}
        return cls
    return decorate


def load(path: str) -> dict[str, AdmissionSpec]:
    """Execute a policy file and return what it declared.

    Plain ``exec`` of a Python file, which is the same trust a ``conftest.py``
    or a ``settings.py`` already asks for: this is your file, on your disk,
    next to your deployment. It is not a sandbox and does not pretend to be.
    """
    import runpy
    REGISTRY.clear()
    OPTIONS.clear()
    TRANSFORMS.clear()
    STAGES.clear()
    OPERATORS.clear()
    RECIPES.clear()
    runpy.run_path(path, run_name="voydfile")
    if not REGISTRY:
        raise ValueError(
            f"{path} declared no collections. A policy file with no @guard in "
            f"it would start a proxy that refuses nothing, silently")
    _check_recipes()
    return dict(REGISTRY)
