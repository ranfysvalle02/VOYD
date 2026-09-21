"""Your own number: reads that can serve a fact your code already treats as gone.

    python scanner/voyd_scan path/to/your/repo
    python scanner/voyd_scan --json app/ services/ > leak_scan.json
    python scanner/voyd_scan --strict app/          # unjudged reads fail too
    python scanner/voyd_scan --claims app/          # every break-glass, reviewable
    python scanner/voyd_scan --read-verb fetch_all app/   # your wrapper's verbs

This is a separate, dependency-free package on purpose. It ships apart from
``voyd`` because the first thing a stranger runs must cost them nothing: no
install, no database, no credentials, no import of the library it is trying
to make a case for. One stdlib file -- this one -- which you may also simply
copy into your own repository and run there.

**The pattern match is not the point.** Semgrep and CodeQL can already express
"find reads on collection X that do not name field Y", and express it better
than this file does. What they cannot do is work out what Y *is* without
somebody first knowing the answer and writing it down. That inference is the
whole of this tool:

    a mark-bearing collection + a read that does not name the mark
        = a class of silent defect

Deletion is the sharpest instance of that class, not the definition of it.
``expire_at`` is one spelling of Y. So is ``valid_until``, ``is_active``,
``tombstone``, ``tenant_id``, and a name nobody has invented yet.

**How it finds Y.** Two ways, and the second is the one that generalises:

1. *Declared.* A TTL index names its own field -- ``create_index("valid_until",
   expireAfterSeconds=0)`` says what the deadline is called without this file
   having heard of ``valid_until``. A write or filter that names one of the
   usual soft-delete spellings counts too.

2. *Inferred, from your own convention.* For each collection, the fields its
   reads actually filter on are counted. A field that most reads name and some
   do not is a convention with a deviation -- and the convention is the spec,
   so the deviation is the finding. No configuration, no allowlist of field
   names, and it gets **stronger on larger codebases**, because the majority
   that establishes the convention is bigger. That inverts the usual economics
   of static analysis, where more code means more noise.

   A convention needs at least two reads that honour it and at least one that
   does not (so: three reads, minimum). A field every read names is not a
   finding, it is just a schema, and this says nothing about it.

The output is three-state -- **leak**, **filtered**, **indeterminate** -- and
the third one is load-bearing. A filter assembled by a helper cannot be read
from source, and calling it a leak would be inventing a number. But a shrug is
not a result either, so an indeterminate read is a *proof obligation* you can
discharge in the source, the way ``# type: ignore`` discharges one for mypy::

    return db.notes.find(living(user))   # voyd: filtered(expire_at) -- living() applies it

    return db.notes.find({})             # voyd: audit -- the retention report, by design

``filtered`` asserts the invisible filter does name the mark; ``audit`` names
a read that deliberately does not, and requires a reason. Neither is a way to
go quiet: both are counted and printed, a claim on a read that did not need
one is reported as **stale**, and ``--strict`` makes an undischarged
indeterminate fail the build. That is the ratchet -- the unjudged column can
be driven to zero and then held there, which a number nobody can act on
cannot be.

**What it cannot see, stated plainly so the number is defensible:**

- It reads source with ``ast``. Dynamically named collections
  (``db[name]`` where ``name`` is a variable), ORM layers, query builders and
  raw-driver wrappers are invisible. False negatives are expected. When it
  recognises *no* read at all -- the usual outcome for a team with a
  repository class -- it says so and names ``--read-verb`` rather than
  printing a reassuring nothing, because "I found no problem" and "I could
  not see anything" are the same output and different facts.
- It inspects *filter keys only*, and only in literal ``dict``/``list``
  arguments. A filter built by a helper is reported as indeterminate, not as
  a leak -- it will not manufacture a number it cannot stand behind.
- It never connects to a database. It cannot tell you the leak *fired*; it
  tells you the read *could*.

So the output is a floor, not a census. A non-zero floor is still the fastest
way to turn "refusal is a real problem" from a claim into your own incident --
with a file and a line number, in code you already own.

Exit code is the number of candidate leaks -- clamped to 254, because an exit
status is one byte and 256 leaks exiting 0 would be this tool committing the
defect it looks for. 255 means the scan could not run at all.
"""

from __future__ import annotations

import argparse
import ast
import io
import json
import re
import sys
import tokenize
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

# Reads that can hand a document to a caller. Writes are elsewhere: a write
# does not return a forgotten fact to a prompt.
READ_VERBS = frozenset({"find", "find_one", "aggregate", "distinct",
                        "count_documents"})
# Writes and index declarations, used only to learn which collections carry a
# mark field -- never reported as leaks themselves.
WRITE_VERBS = frozenset({"insert_one", "insert_many", "update_one",
                         "update_many", "replace_one", "bulk_write",
                         "create_index", "create_indexes"})

# Field names that mean "this row can stop being valid": VOYD's own deadline
# and revocation fields, plus the soft-delete conventions other teams use.
# Compared after lowercasing and dropping underscores, so ``expire_at`` and
# ``expireAt`` and ``EXPIRE_AT`` are one field.
#
# This list is a convenience, not the mechanism. It shortcuts the common
# spellings so a small repository gets an answer before it has enough reads
# to establish a convention -- but everything below works on a field name
# that is not in it, which is the point of the file. Do not add to it in
# preference to fixing the inference.
MARKS = frozenset({
    "expireat", "expireafterseconds", "forgotten", "revoked", "tombstone",
    "deleted", "isdeleted", "deletedat", "softdeleted", "removedat",
})

# A field must be named by this share of a collection's judgeable reads before
# it counts as that collection's convention. 0.6 rather than a bare majority:
# a field that half the reads name is a disagreement, not a convention, and
# this instrument's only asset is that its findings are not arguable.
CONVENTION_THRESHOLD = 0.6
# ...and by at least this many, so two reads that happen to share a key on a
# three-read repository do not become a rule. With one deviation required on
# top, the smallest collection that can produce an inferred finding has three
# judgeable reads.
CONVENTION_SUPPORT = 2

# Keys that are never a convention. ``_id`` is identity -- a lookup by primary
# key is exactly the read that can still serve a forgotten fact, so treating it
# as a filter that satisfies anything would silence the sharpest case there is.
# ``$``-prefixed keys are operators, not fields.
NEVER_A_CONVENTION = frozenset({"_id"})

# The exit code carries the count so this drops into CI, and a process exit
# status is one byte. Unclamped, a repository with exactly 256 candidate
# leaks exits 0 -- the worst possible reading, delivered to the tool whose
# entire argument is that nothing is ever wrong enough to notice. So the
# count is clamped, 255 is reserved for "the scan could not run", and the
# real number is always printed rather than inferred from the status.
EXIT_MAX = 254
EXIT_ERROR = 255


def _norm(key: str) -> str:
    """First dotted segment, lowercased, underscores dropped."""
    return key.split(".")[0].lower().replace("_", "").replace("-", "")


def _is_mark(key: str) -> bool:
    return _norm(key) in MARKS


def _collection_of(node: ast.AST) -> str | None:
    """The collection a receiver names, or ``None`` if it is not a literal.

    ``db.notes`` -> ``"notes"``; ``db["notes"]`` -> ``"notes"``;
    ``db.get_collection("notes")`` -> ``"notes"``. A variable
    (``db[name]``) is deliberately ``None``: unknowable from source.
    """
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Subscript):
        key = node.slice
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            return key.value
        return None
    if isinstance(node, ast.Call):
        fn = node.func
        if (isinstance(fn, ast.Attribute) and fn.attr == "get_collection"
                and node.args and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)):
            return node.args[0].value
    return None


def _dict_keys(node: ast.AST) -> set[str]:
    """Every string key in the literal dicts reachable from ``node``.

    Descends dicts, lists and tuples so a ``$and``/``$or`` filter or an
    aggregation pipeline is covered. Values are ignored on purpose: a filter
    is defined by what it constrains, and ``{"text": "expire_at happened"}``
    filters text, not the deadline.
    """
    keys: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Dict):
            for k in child.keys:
                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                    keys.add(k.value)
    return keys


def _fields(keys: set[str]) -> set[str]:
    """The keys that could be somebody's convention: no operators, no ``_id``."""
    return {k for k in keys
            if not k.startswith("$") and k.split(".")[0] not in NEVER_A_CONVENTION}


def _ttl_field(call: ast.Call) -> set[str]:
    """The field a TTL index puts a deadline on, if this call declares one.

    This is the generalising half of the declared path, and the reason a
    hard-coded list of names is not the mechanism. ``expireAfterSeconds`` is
    MongoDB's word, not the team's, and the index states its own field right
    next to it:

        create_index("valid_until", expireAfterSeconds=0)
        create_index([("purge_after", 1)], expireAfterSeconds=86400)

    Both give up ``Y`` without this file having ever heard of it.
    """
    if not any(kw.arg and _norm(kw.arg) == "expireafterseconds"
               for kw in call.keywords):
        return set()
    found: set[str] = set()
    for arg in call.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            found.add(arg.value)
        elif isinstance(arg, (ast.List, ast.Tuple)):
            for el in ast.walk(arg):
                if isinstance(el, ast.Constant) and isinstance(el.value, str):
                    found.add(el.value)
                    break
    return found


def _declared_marks(call: ast.Call) -> set[str]:
    """The mark fields a write or index call names, by any route.

    Broader than the read check on purpose: an index is declared as
    ``create_index("expire_at", expireAfterSeconds=60)`` or
    ``create_index([("expire_at", 1)])``, so a bare string constant, a dict
    key, or the TTL keyword's own field all count as evidence.
    """
    found = _ttl_field(call)
    for child in ast.walk(call):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            if _is_mark(child.value):
                found.add(child.value)
        if isinstance(child, ast.Dict):
            for k in child.keys:
                if (isinstance(k, ast.Constant) and isinstance(k.value, str)
                        and _is_mark(k.value)):
                    found.add(k.value)
    return found


def _filter_args(call: ast.Call) -> list[ast.AST]:
    """The dict/list arguments of a read -- its filter, or a pipeline."""
    args = list(call.args) + [kw.value for kw in call.keywords
                              if kw.arg in ("filter", "pipeline")]
    return [a for a in args if isinstance(a, (ast.Dict, ast.List, ast.Tuple))]


# Keys whose *value* is itself a filter rather than a value to compare
# against. If one of those is computed, the literal we can see is a shell
# around a sub-filter we cannot.
SUBFILTER_KEYS = frozenset({"$match", "$and", "$or", "$nor", "$not", "$expr"})

_LITERAL = (ast.Dict, ast.List, ast.Tuple, ast.Constant)


def _delegates_filter(node: ast.AST) -> bool:
    """Is part of this literal filter built somewhere this scanner cannot see?

    A literal argument is not the same as a *visible* filter. Three shapes
    hand the real constraint to an expression:

    - ``{**base_filter(), "tenant": t}`` -- unpacking, which ``ast`` records
      as a dict key of ``None``;
    - ``{"$match": handle.match({...})}`` -- an operator whose value is a
      sub-filter returned by a call;
    - ``[stage(), {"$group": ...}]`` -- a pipeline assembled from helpers.

    In all three the keys we can read are a shell, so calling the read a leak
    would be inventing a number. ``{"_id": some_var}`` is deliberately *not*
    included: a variable *value* leaves the keys fully visible, and keys are
    what the mark check reads.
    """
    for child in ast.walk(node):
        if isinstance(child, ast.Dict):
            for key, value in zip(child.keys, child.values):
                if key is None:                       # ``**helper()``
                    return True
                if (isinstance(key, ast.Constant)
                        and isinstance(key.value, str)
                        and key.value in SUBFILTER_KEYS
                        and not isinstance(value, _LITERAL)):
                    return True
        elif isinstance(child, (ast.List, ast.Tuple)):
            if any(isinstance(el, ast.Call) for el in child.elts):
                return True
    return False


# --------------------------------------------------------------------------
# Claims: an indeterminate read is a proof obligation, and this is how a team
# discharges it without leaving the file it is in.
# --------------------------------------------------------------------------

# ``# voyd: filtered(expire_at) -- living() applies the deadline``
# ``# voyd: audit -- the retention report reads everything, by design``
CLAIM_RE = re.compile(
    r"#\s*voyd:\s*(?P<verb>filtered|audit)\b"
    r"(?:\s*\(\s*(?P<field>[^)]*?)\s*\))?"
    r"(?:\s*--\s*(?P<reason>.*?))?\s*$"
)


@dataclass(frozen=True)
class Claim:
    """One ``# voyd:`` comment: what it asserts, and where it was written."""
    verb: str                 # "filtered" | "audit"
    field: str | None         # the mark the author says is applied
    reason: str | None
    line: int


def _claims(code: str) -> dict[int, Claim]:
    """Every ``# voyd:`` claim in a file, by the line it sits on.

    ``tokenize`` rather than a line-by-line regex, so a ``"# voyd: audit"``
    inside a string literal is not a claim. An instrument whose suppression
    mechanism can be triggered from inside a doctest is not one you would
    let gate a build.
    """
    out: dict[int, Claim] = {}
    try:
        tokens = tokenize.generate_tokens(io.StringIO(code).readline)
        for tok in tokens:
            if tok.type != tokenize.COMMENT:
                continue
            m = CLAIM_RE.search(tok.string)
            if m:
                out[tok.start[0]] = Claim(
                    verb=m.group("verb"),
                    field=m.group("field") or None,
                    reason=(m.group("reason") or "").strip() or None,
                    line=tok.start[0],
                )
    except (tokenize.TokenError, IndentationError, SyntaxError):
        # The file did not tokenise. ``analyze`` already tolerates a file
        # that does not parse; a claim we could not read is simply absent,
        # which fails towards reporting more rather than less.
        pass
    return out


@dataclass
class Read:
    file: str
    line: int
    collection: str
    status: str          # see STATUSES
    why: str
    end_line: int = 0
    keys: frozenset[str] = frozenset()
    judgeable: bool = False
    claim: Claim | None = None

    @property
    def reason(self) -> str | None:
        return self.claim.reason if self.claim else None


# "leak"          -- reads the collection's mark is not named by
# "filtered"      -- names every mark the collection carries
# "indeterminate" -- the filter is not visible; nobody has said anything
# "discharged"    -- indeterminate, and a `# voyd: filtered` claim covers it
# "audited"       -- deliberately unfiltered, named as such, counted
# "stale"         -- a claim on a read that did not need one: the ratchet's teeth
STATUSES = ("leak", "filtered", "indeterminate", "discharged", "audited", "stale")


@dataclass
class Mark:
    """A field a collection's reads are expected to name, and why we say so."""
    field: str
    source: str        # "declared" | "inferred"
    support: int = 0   # reads that name it (inferred only)
    total: int = 0     # judgeable reads against the collection (inferred only)

    def evidence(self) -> str:
        """The header form: what this mark is, and why we believe it."""
        if self.source == "declared":
            return f"`{self.field}` (declared by a write or index)"
        return (f"`{self.field}` (your convention: {self.support} of "
                f"{self.total} reads name it)")

    def shortly(self) -> str:
        """The form that reads well inside a finding, which is a sentence.

        The header already carries the full evidence, and a file:line whose
        parenthetical contains a second parenthetical is a finding nobody
        finishes reading.
        """
        if self.source == "declared":
            return f"`{self.field}`"
        return (f"`{self.field}`, which {self.support} of {self.total} "
                f"reads here do")


@dataclass
class Report:
    files: int = 0
    marks: dict[str, list[Mark]] = field(default_factory=dict)
    reads: list[Read] = field(default_factory=list)

    @property
    def bearing(self) -> set[str]:
        return set(self.marks)

    def _of(self, status: str) -> list[Read]:
        return [r for r in self.reads
                if r.collection in self.marks and r.status == status]

    @property
    def leaks(self) -> list[Read]:
        return self._of("leak")

    @property
    def filtered(self) -> list[Read]:
        return self._of("filtered")

    @property
    def indeterminate(self) -> list[Read]:
        return self._of("indeterminate")

    @property
    def discharged(self) -> list[Read]:
        return self._of("discharged")

    @property
    def audited(self) -> list[Read]:
        return self._of("audited")

    @property
    def stale(self) -> list[Read]:
        return self._of("stale")

    @property
    def considered(self) -> int:
        return sum(len(self._of(s)) for s in STATUSES)

    def obligations(self) -> int:
        """What ``--strict`` refuses to let through.

        Leaks, plus every read nobody has said anything about, plus every
        claim that no longer describes the code under it. The third one is
        what makes this a ratchet rather than a suppression file: an
        annotation that stops being true becomes a finding instead of
        quietly continuing to silence one.
        """
        return len(self.leaks) + len(self.indeterminate) + len(self.stale)

    def as_dict(self) -> dict:
        def rows(rs: list[Read]) -> list[dict]:
            return [{"file": r.file, "line": r.line,
                     "collection": r.collection, "why": r.why,
                     **({"reason": r.reason} if r.reason else {})} for r in rs]
        return {
            "files_scanned": self.files,
            "deadline_bearing_collections": sorted(self.marks),
            "marks": {c: [{"field": m.field, "source": m.source,
                           "support": m.support, "reads": m.total}
                          for m in ms]
                      for c, ms in sorted(self.marks.items())},
            "reads_against_them": self.considered,
            "candidate_leaks": rows(self.leaks),
            "filtered_reads": len(self.filtered),
            "indeterminate_reads": rows(self.indeterminate),
            "discharged_reads": rows(self.discharged),
            "audited_reads": rows(self.audited),
            "stale_claims": rows(self.stale),
            "strict_obligations": self.obligations(),
        }


def _gather(sources: dict[str, str], read_verbs: frozenset[str],
            write_verbs: frozenset[str]) -> tuple[list[Read], dict[str, set[str]]]:
    """Pass one: every read, and every mark a write or index *declares*.

    Nothing is classified here. Which fields a collection requires is a
    property of the whole repository -- the write that proves a deadline and
    the reads that establish a convention are routinely in other files -- so
    a read cannot be judged until every file has been seen.
    """
    reads: list[Read] = []
    declared: dict[str, set[str]] = {}

    for path, code in sources.items():
        try:
            tree = ast.parse(code)
        except SyntaxError:
            continue
        claims = _claims(code)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            if not isinstance(fn, ast.Attribute):
                continue
            collection = _collection_of(fn.value)
            if collection is None:
                continue

            if fn.attr in write_verbs:
                found = _declared_marks(node)
                if found:
                    declared.setdefault(collection, set()).update(found)
                continue
            if fn.attr not in read_verbs:
                continue

            end = node.end_lineno or node.lineno
            claim = next((claims[ln] for ln in range(node.lineno, end + 1)
                          if ln in claims), None)
            dict_args = _filter_args(node)

            if not dict_args:
                # A read with genuinely no filter argument is not unreadable,
                # it is unfiltered: ``find()`` returns everything.
                bare = (not node.args and not any(
                    kw.arg in ("filter", "pipeline") for kw in node.keywords))
                read = Read(path, node.lineno, collection,
                            "leak" if bare else "indeterminate",
                            "no filter" if bare else "filter is not a literal",
                            end_line=end, judgeable=bare, claim=claim)
            elif any(_delegates_filter(a) for a in dict_args):
                read = Read(path, node.lineno, collection, "indeterminate",
                            "filter is partly built elsewhere",
                            end_line=end, claim=claim)
            else:
                keys = set().union(*(_dict_keys(a) for a in dict_args))
                read = Read(path, node.lineno, collection, "", "",
                            end_line=end, keys=frozenset(keys),
                            judgeable=True, claim=claim)
                for k in keys:
                    if _is_mark(k):
                        declared.setdefault(collection, set()).add(k)
            reads.append(read)

    return reads, declared


def _infer(reads: list[Read], declared: dict[str, set[str]], *,
           threshold: float, support_floor: int) -> dict[str, list[Mark]]:
    """Pass two: what each collection's own reads say its rule is.

    This is the part a rule-based scanner cannot do for you. It never asks
    what a field is *called*; it asks what this collection's reads agree on
    and which ones do not. A field carried by most of them and missing from
    at least one is a convention with a deviation, and the deviation is the
    finding.

    A field that *every* read names is deliberately not reported. There is no
    deviation, so there is nothing to say, and manufacturing a mark out of a
    unanimous schema would both flood the output and -- worse -- let a real
    leak look filtered because it happened to name the unanimous field.
    """
    marks: dict[str, list[Mark]] = {}
    for collection, fields in declared.items():
        marks[collection] = [Mark(f, "declared") for f in sorted(fields)]

    judgeable: dict[str, list[Read]] = {}
    for r in reads:
        if r.judgeable:
            judgeable.setdefault(r.collection, []).append(r)

    for collection, rs in judgeable.items():
        total = len(rs)
        known = {_norm(m.field) for m in marks.get(collection, [])}
        counts: dict[str, int] = {}
        spelling: dict[str, str] = {}
        for r in rs:
            for f in _fields(set(r.keys)):
                n = _norm(f)
                counts[n] = counts.get(n, 0) + 1
                spelling.setdefault(n, f)
        for n, support in sorted(counts.items()):
            if n in known:
                continue                      # already required, by declaration
            deviations = total - support
            if (support >= support_floor and deviations >= 1
                    and support / total >= threshold):
                marks.setdefault(collection, []).append(
                    Mark(spelling[n], "inferred", support=support, total=total))

    return {c: ms for c, ms in marks.items() if ms}


def _classify(reads: list[Read], marks: dict[str, list[Mark]]) -> None:
    """Pass three: judge each read against the marks its collection carries.

    A read must name *every* mark. That is the generalisation the whole file
    is for: a deadline and a tenant key are the same defect wearing different
    clothes, and a read that remembers one and forgets the other is not half
    safe.
    """
    for r in reads:
        required = marks.get(r.collection)
        if not required:
            if r.status == "":
                r.status, r.why = "filtered", "no mark on this collection"
            continue
        if r.judgeable:
            named = {_norm(k) for k in r.keys}
            missing = [m for m in required if _norm(m.field) not in named]
            if not missing:
                r.status, r.why = "filtered", "filter names the mark"
            else:
                r.status = "leak"
                if r.why == "no filter":
                    pass                    # ``find()``: already the whole story
                elif len(missing) == 1 and missing[0].source == "declared":
                    # The wording the declared path has always used: the mark
                    # is a known spelling, so naming it adds nothing a reader
                    # cannot see. Inferred marks are the opposite -- the
                    # finding is only as good as the evidence for the
                    # convention, so that evidence is printed with it.
                    r.why = ("filter does not name the mark" if r.keys
                             else "empty filter")
                else:
                    r.why = ("filter does not name "
                             + ", ".join(m.shortly() for m in missing))
        _apply_claim(r)


def _apply_claim(r: Read) -> None:
    """Honour a ``# voyd:`` claim -- or report that it no longer describes
    the code it sits on.

    Three outcomes, and the third is the one that keeps this honest:

    - ``filtered`` on an indeterminate read discharges it. The author says
      the helper applies the mark; this tool could not see that, and now the
      assertion is in the file where the next reader will find it.
    - ``audit`` on any read names it as deliberately unfiltered. It is not
      silenced -- it is moved to a column with the author's reason next to
      it, which is exactly what ``including_refused()`` does at runtime:
      a door with an alarm rather than a permanent pass.
    - anything else is **stale**. A ``filtered`` claim on a read whose
      filter is plainly visible, or an ``audit`` with no reason given, is a
      finding in its own right. Without this an annotation added once keeps
      suppressing after the code beneath it has changed, which is how a
      suppression file rots into a lie.
    """
    claim = r.claim
    if claim is None:
        return
    if claim.verb == "audit":
        if not claim.reason:
            r.status = "stale"
            r.why = "`voyd: audit` with no reason given (write `-- why`)"
        else:
            r.status = "audited"
            r.why = "deliberately unfiltered, and named as such"
        return
    # verb == "filtered"
    if r.status == "indeterminate":
        r.status = "discharged"
        named = f" ({claim.field})" if claim.field else ""
        r.why = f"filter is built elsewhere; asserted to apply the mark{named}"
    elif r.status == "filtered":
        r.status = "stale"
        r.why = "`voyd: filtered` on a read whose filter is already visible"
    else:
        r.status = "stale"
        r.why = (f"`voyd: filtered` on a read that does not filter the mark "
                 f"({r.why}) -- use `voyd: audit -- why` if that is intended")


def analyze(sources: dict[str, str], *,
            threshold: float = CONVENTION_THRESHOLD,
            support_floor: int = CONVENTION_SUPPORT,
            read_verbs: Iterable[str] = (),
            write_verbs: Iterable[str] = ()) -> Report:
    """Classify every read in ``sources`` (path -> code). Pure; no I/O.

    Three passes, because none of the three questions can be answered from
    one file: what marks exist (any file may declare one), what the
    convention is (it is a property of all the reads at once), and whether a
    given read honours it.

    ``read_verbs``/``write_verbs`` *extend* the built-in sets rather than
    replacing them. Most teams do not call the driver directly -- they have a
    repository class, a `Store`, a `fetch_all`. To such a repository this tool
    is blind, and a blind tool that prints "nothing to check" is the exact
    failure it exists to find. Naming the wrapper's verbs is the cheap fix,
    and ``main`` now says so out loud when it sees no reads at all.
    """
    reads, declared = _gather(sources,
                              READ_VERBS | frozenset(read_verbs),
                              WRITE_VERBS | frozenset(write_verbs))
    marks = _infer(reads, declared, threshold=threshold,
                   support_floor=support_floor)
    _classify(reads, marks)
    return Report(files=len(sources), marks=marks, reads=reads)


class ScanError(Exception):
    """The scan could not be performed, as opposed to finding nothing.

    The distinction is the whole reason this class exists. A tool whose
    output is "you are clean" must never say it because it read nothing --
    a mistyped path reporting a clean bill of health is the same defect
    this scanner exists to find, committed by the instrument.
    """


def collect_sources(paths: list[Path], allow: list[Path]) -> dict[str, str]:
    """Read ``*.py`` under ``paths``, skipping anything under ``allow``.

    Raises ``ScanError`` if a path does not exist. ``rglob`` on a missing
    directory returns an empty iterator rather than raising, so without this
    check ``voyd-scan ./scr`` (for ``./src``) prints a clean result and exits
    zero -- confidently, and about nothing.
    """
    missing = [str(p) for p in paths if not p.exists()]
    if missing:
        raise ScanError(f"no such path: {', '.join(missing)}")
    allow_resolved = [a.resolve() for a in allow]
    out: dict[str, str] = {}
    for p in paths:
        files = [p] if p.is_file() else sorted(p.rglob("*.py"))
        for f in files:
            if "__pycache__" in f.parts:
                continue
            rf = f.resolve()
            if any(rf == a or a in rf.parents for a in allow_resolved):
                continue
            try:
                out[str(f)] = f.read_text()
            except (OSError, UnicodeDecodeError):
                continue
    return out


# How many individual findings to print per collection before the list stops
# being information and becomes wallpaper. Measured rather than guessed: on a
# 2,000-file repository this tool printed 1,682 findings whose message bodies
# were, all of them, the same single sentence. The inference genuinely does
# get stronger with scale -- 22,318 of 24,000 reads established that
# convention -- and the *report* got proportionally less useful, which made
# the headline claim about economics true of the analysis and false of the
# thing a human reads.
SHOWN_PER_COLLECTION = 10


def _common_prefix(rows: list[Read]) -> str:
    """The directory every finding shares, so it can be said once.

    A finding is read left to right and the useful part is on the right. When
    every path starts with the same forty characters, those forty characters
    are pushing the file and line off the edge of a terminal for no
    information at all.
    """
    if len(rows) < 2:
        return ""
    parts = [Path(r.file).parts[:-1] for r in rows]
    common: list[str] = []
    for chunk in zip(*parts):
        if len(set(chunk)) != 1:
            break
        common.append(chunk[0])
    return str(Path(*common)) + "/" if common else ""


def _by_directory(rows: list[Read], prefix: str) -> list[tuple[str, int, int]]:
    """Findings grouped by the directory they live in, worst first.

    A thousand leaks are not a thousand problems. They are usually one module
    nobody routed through the helper, and the directory histogram is what
    makes that visible in the first screenful -- a list of file:line cannot
    show a shape, however carefully it is sorted.
    """
    buckets: dict[str, list[Read]] = {}
    for r in rows:
        parent = str(Path(r.file).parent)
        buckets.setdefault(parent[len(prefix):] or ".", []).append(r)
    out = [(d, len(rs), len({r.file for r in rs})) for d, rs in buckets.items()]
    return sorted(out, key=lambda t: (-t[1], t[0]))


def _print_findings(heading: str, rows: list[Read], *, show_all: bool) -> None:
    """One findings section, at whatever size the repository turned out to be.

    Two things are said once rather than per line. The shared path prefix,
    because it is not information. And the reason, when every finding has the
    same one -- it is a fact about the collection's convention, not about the
    individual read, and repeating it 1,682 times is how a report with a true
    headline becomes one nobody scrolls to the end of.
    """
    if not rows:
        return
    prefix = _common_prefix(rows)
    whys = {r.why for r in rows}
    shared = whys.pop() if len(whys) == 1 else None

    print(f"\n{heading}" + (f" -- {shared}" if shared else "") + ":")
    if prefix:
        print(f"  (under {prefix})")
    print()

    dirs = _by_directory(rows, prefix)
    if len(rows) > SHOWN_PER_COLLECTION and len(dirs) > 1:
        print("  where they are:")
        for directory, n, files in dirs[:8]:
            print(f"    {n:>6}  in {files} file(s)  {directory}")
        if len(dirs) > 8:
            rest = sum(n for _, n, _ in dirs[8:])
            print(f"    {rest:>6}  in {len(dirs) - 8} more director"
                  f"{'y' if len(dirs) - 8 == 1 else 'ies'}")
        print()

    shown = rows if show_all else rows[:SHOWN_PER_COLLECTION]
    for r in shown:
        tail = "" if shared else f"  ({r.why})"
        print(f"  {r.file[len(prefix):]}:{r.line}  {r.collection}{tail}")
    if len(shown) < len(rows):
        print(f"\n  ... and {len(rows) - len(shown)} more. "
              "`--all` lists them; `--json` is the machine-readable form.")


def _print_claims(report: Report) -> None:
    """Every ``# voyd:`` assertion in the tree, as one reviewable list.

    This is the static half of an argument the runtime has always made. A
    break-glass read through the handle increments ``including_refused_total``
    and records who and when, because the point was never to forbid the
    unsafe thing -- it was to make sure somebody can *see* that it happened.
    A door with an alarm nobody listens to is a door.

    The claims in a source tree had no such list. Anybody could write
    ``# voyd: audit -- needed for the report`` and the finding left the count
    for good, reviewed once by whoever approved that diff and never again.
    So: name them all, with their reasons, in one place a security reviewer
    can read in a minute and `git blame` can date.
    """
    claimed = report.discharged + report.audited + report.stale
    if not claimed:
        print("\nNo `# voyd:` claims in this tree.")
        return

    print(f"\n{len(claimed)} `# voyd:` claim(s) -- every assertion that a "
          "read is safe,\nor deliberately is not. Review these the way you "
          "would review the\nbreak-glass column of an audit log, because "
          "that is what they are:\n")
    for kind, rows in (("audit ", report.audited),
                       ("filter", report.discharged),
                       ("STALE ", report.stale)):
        for r in rows:
            reason = r.reason or "(no reason given)"
            print(f"  {kind}  {r.file}:{r.line}  {r.collection}")
            print(f"           {reason}")
    if report.stale:
        print(f"\n  {len(report.stale)} of them no longer describe the code "
              "underneath. A claim\n  that outlived its read is a "
              "suppression, not an assertion.")


def _print_report(report: Report, strict: bool, show_all: bool) -> None:
    print(f"scanned {report.files} file(s).")
    print(f"{len(report.marks)} collection(s) carry a mark your code expects "
          "its reads to name:")
    for collection, ms in sorted(report.marks.items()):
        print(f"  {collection}: " + "; ".join(m.evidence() for m in ms))

    leaks = report.leaks
    if leaks:
        _print_findings(
            f"{len(leaks)} of {report.considered} read(s) against them do not",
            leaks, show_all=show_all)
    else:
        print(f"\n0 of {report.considered} read(s) against them are unfiltered.")

    if report.indeterminate:
        _print_findings(
            f"{len(report.indeterminate)} unjudged read(s) -- the filter is "
            "built elsewhere and nobody has said what it does",
            report.indeterminate, show_all=show_all)
    if report.stale:
        _print_findings(
            f"{len(report.stale)} stale claim(s) -- a `# voyd:` comment that "
            "no longer describes the code under it",
            report.stale, show_all=show_all)

    if report.discharged or report.audited:
        print(f"\n{len(report.discharged)} discharged, {len(report.audited)} "
              "audited by an explicit claim in the source. `--claims` lists "
              "them.")

    if leaks:
        print("\nEach leak is a read that can serve a document the "
              "collection's own rule says is gone. Route it through a filter "
              "on the mark -- or, if you want that enforced structurally "
              "rather than remembered, that is what VOYD is for.")
    elif report.indeterminate and not strict:
        print("\nNo unfiltered read found against a marked collection. The "
              "unjudged reads above are the honest remainder: discharge one "
              "with `# voyd: filtered(field) -- why` where the helper does "
              "apply the mark, or `# voyd: audit -- why` where it deliberately "
              "does not, and run with --strict to hold the count at zero.")
    else:
        print("\nNo unfiltered read found against a marked collection. That "
              "is a real result for the paths this can see, and the header "
              "says what it cannot -- ORM layers and dynamically named "
              "collections stay invisible.")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", type=Path,
                    help="source files or directories to scan")
    ap.add_argument("--allow", action="append", default=[], type=Path,
                    help="a path exempt from the scan (e.g. a designated audit "
                         "module); repeatable")
    ap.add_argument("--json", action="store_true",
                    help="emit the full report as JSON on stdout")
    ap.add_argument("--strict", action="store_true",
                    help="count unjudged reads and stale claims towards the "
                         "exit code, so the obligation has to be discharged in "
                         "the source rather than carried indefinitely")
    ap.add_argument("--all", action="store_true", dest="show_all",
                    help="list every finding instead of the first few per "
                         "section; the summary above them is unchanged")
    ap.add_argument("--claims", action="store_true",
                    help="list every `# voyd:` claim in the tree -- what each "
                         "one asserts and why -- so break-glass is reviewable "
                         "rather than merely written down once")
    ap.add_argument("--read-verb", action="append", default=[], metavar="NAME",
                    help="treat NAME as a read, for a repository class or "
                         "driver wrapper this does not know about "
                         "(e.g. --read-verb fetch_all); repeatable")
    ap.add_argument("--write-verb", action="append", default=[], metavar="NAME",
                    help="treat NAME as a write or index declaration; "
                         "repeatable")
    ap.add_argument("--convention-threshold", type=float,
                    default=CONVENTION_THRESHOLD, metavar="R",
                    help=f"share of a collection's reads that must name a field "
                         f"before it counts as that collection's convention "
                         f"(default {CONVENTION_THRESHOLD})")
    args = ap.parse_args(argv)

    try:
        sources = collect_sources(args.paths, args.allow)
    except ScanError as exc:
        print(f"voyd-scan: {exc}", file=sys.stderr)
        return EXIT_ERROR

    report = analyze(sources, threshold=args.convention_threshold,
                     read_verbs=args.read_verb, write_verbs=args.write_verb)
    count = report.obligations() if args.strict else len(report.leaks)

    if args.json:
        print(json.dumps(report.as_dict(), indent=2))
        return min(count, EXIT_MAX)

    if not report.files:
        # Distinct from "scanned files, found no marked collection". The
        # paths existed and held no Python at all, which is a result about
        # the invocation, not about the code.
        print(f"scanned 0 files: {', '.join(str(p) for p in args.paths)} "
              f"contains no .py to read. Nothing was checked.")
        return 0

    if not report.reads:
        # The third way this tool could report "clean" without establishing
        # anything, and the last one to be found. A missing path was fixed
        # with `ScanError`; a wrapping exit code was fixed with a clamp. This
        # is the case where every path existed, every file parsed, and the
        # scanner recognised not one single read -- because the team has a
        # repository class and never touches the driver in the code it wrote.
        #
        # "No collection carries a mark" and "I could not see a single read"
        # are the same output and completely different facts, and only one of
        # them is about the repository. Saying so is the whole difference
        # between a floor and a false all-clear.
        print(f"scanned {report.files} file(s) and recognised no database read "
              "at all.\n\n"
              "That is a fact about this scanner, not about your code. It "
              "looks for reads\nshaped like a MongoDB driver call -- "
              "`db.notes.find(...)`. If your data access\ngoes through a "
              "repository class, an ORM, or any wrapper, every read is\n"
              "invisible here and this result means nothing.\n\n"
              "  voyd-scan --read-verb <your_read_method> "
              "--write-verb <your_write_method> ...\n\n"
              "teaches it your wrapper's verbs. Until it finds a read, treat "
              "this as\nunmeasured rather than clean.")
        return 0

    if not report.marks:
        print(f"scanned {report.files} file(s) and found "
              f"{len(report.reads)} read(s), but no collection whose own code "
              "treats a field as a mark -- no deadline, no soft-delete flag, "
              "and no field its reads agree on.\n"
              "(This is a source heuristic -- dynamically named collections "
              "and ORM layers are invisible. See the header.)")
        return 0

    _print_report(report, args.strict, args.show_all)
    if args.claims:
        _print_claims(report)
    return min(count, EXIT_MAX)


if __name__ == "__main__":
    raise SystemExit(main())
