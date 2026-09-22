"""Refuse a document. The verdict, applied to a batch on its way out.

The decision every other one exists to protect. `Guard` holds one
collection's `Admission` and judges a batch per document, *whatever
produced it* -- which is the whole point, because a `$vectorSearch` hit
passed through no query and no filter this boundary could have narrowed.

Built with `db=None` on purpose: nothing here queries anything. That is
not thrift, it is the property that lets the same check run on a wire at
all, and the tests construct these exactly as the proxy does.

`Budgets` is the one piece of state that outlives a message, and it is
here because it belongs to the same decision: a cumulative rule spans a
*read* while this boundary is handed a *batch*, and the client picks how
many batches a read arrives in.

`enforce` is the fast path -- lazy decode, cheapest questions first, byte
for byte forwarding of everything that is not a guarded cursor batch.
`judge` is the same thing with decryption in front of it for collections
that declared `sealed()`.
"""

from __future__ import annotations

from typing import Any, Mapping

from voyd.engine import Deadline, revoked
from voyd.engine.admission import Admission, AdmissionSpec

from .. import cascade, metrics, seal
from ..codec import LAZY, decode_op_msg, encode_op_msg


_FRESH_TAB: Any = object()


class Guard:
    """One collection's admission handle, and the tally it has refused.

    Built with ``db=None`` on purpose: this object never queries anything. It
    is the same construction the unit tests use, which is the evidence that
    the per-document check does not depend on a database at all -- the thing
    that makes it movable to a wire in the first place.
    """

    def __init__(self, spec: AdmissionSpec, *, on_delete: str = "forward"):
        self.collection = spec.collection
        self.spec = spec
        self.on_delete = on_delete
        self.handle = Admission(None, spec)
        self.refused = 0
        self.admitted = 0
        self.revoked = 0
        # What was marked because it was *made out of* something the caller
        # revoked, as opposed to what the caller named. Two numbers rather
        # than one because "you asked to erase 2 facts and 7 things built on
        # them went too" is the sentence an auditor needs, and a single
        # total cannot say it.
        self.cascaded = 0
        # The proxy's own connection, attached per worker by `_run` and only
        # when this collection declares `lineage_field`. `None` everywhere
        # else, which is the overwhelmingly common case and costs nothing.
        # A `Guard` is still constructible with no database at all -- the
        # per-document check has never needed one, and that is what made it
        # movable to a wire.
        self.cascade: "cascade.Cascade | None" = None
        # Refusals that happened during decryption rather than during
        # `reachable()`. Counted on the guard so one collection has one
        # tally: an operator asking "what did this refuse" should not have
        # to know that `unrecoverable` is answered by a different object
        # than `expired` is.
        self.sealed_refused: dict[str, int] = {}

    @classmethod
    def defaults(cls, collection: str, *, at_field: str, mark_field: str):
        """A guard for a collection nobody wrote a policy for.

        The two rules every collection with a deadline wants, so
        ``--guard notes`` is still a complete thing to type. A policy file
        says more; this says the obvious part.
        """
        return cls(AdmissionSpec(collection,
                                 rules=(Deadline(at_field=at_field),
                                        revoked(mark_field))))

    @property
    def needs_caller(self) -> bool:
        """Does any rule here decide by *who is asking*?

        Cached nowhere on purpose: it is a tuple scan over two or three
        rules, and a boundary that memoised it would have one more piece of
        state to get stale when a policy is reloaded.
        """
        return any(getattr(r, "needs_caller", False) for r in self.spec.rules)

    @property
    def cumulative(self) -> bool:
        """Does any rule here compare a document against the page so far?

        The gate on `Budgets` doing anything at all. A `budget()` or a
        `distinct()` needs a running total that outlives one batch;
        everything else is per document and needs no state between them.
        """
        return any(getattr(r, "needs_tab", False) for r in self.spec.rules)

    def filter(self, docs: list[dict], caller: dict | None = None,
               tab: Any = _FRESH_TAB) -> list[dict]:
        handle = self.handle
        if self.needs_caller:
            # `for_caller` clones rather than assigns, and here that is
            # load-bearing: one `Guard` is shared by every connection this
            # proxy serves, so binding an identity onto `self.handle` would
            # show one client's rows to whoever asked second.
            #
            # `caller=None` -- the question could not be answered -- binds
            # empty claims rather than skipping the rules, so an unknown
            # caller is refused by them instead of waved past.
            handle = handle.for_caller(caller or {})
        if self.spec.tenant:
            # A declared tenant is enforced per document, and the proxy has
            # no filters to read it from -- so it takes the scope from the
            # batch itself. Every document in a cursor batch came from one
            # query, so they share a tenant; a batch that does not is already
            # the leak, and `off_scope` is what names it.
            scopes = {d.get(self.spec.tenant) for d in docs}
            handle = handle.for_tenant(scopes.pop() if len(scopes) == 1
                                       else object())
        # `_FRESH_TAB` means "this call is the whole read", which is true
        # of everything except a cursor batch. `Budgets` hands in a tab
        # that spans the cursor; see its docstring for why a fresh one per
        # batch is a hole rather than an inefficiency.
        kept = (handle.reachable(docs) if tab is _FRESH_TAB
                else handle.reachable(docs, tab=tab))
        self.refused += len(docs) - len(kept)
        self.admitted += len(kept)
        return kept

    def note_sealed(self, tally: dict[str, int]) -> None:
        for reason, count in tally.items():
            self.sealed_refused[reason] = self.sealed_refused.get(reason, 0) + count
        self.refused += sum(tally.values())

    def reasons(self) -> dict:
        counts = dict(self.handle.receipts().get("refused_by_reason", {}))
        for reason, count in self.sealed_refused.items():
            counts[reason] = counts.get(reason, 0) + count
        return counts


def _collection_of(reply: Mapping) -> str | None:
    """Which collection this cursor batch came from.

    ``cursor.ns`` is ``"db.collection"``, and it is the only place a reply
    names what it is. A reply without one is not a cursor batch.
    """
    ns = (reply.get("cursor") or {}).get("ns")
    if not isinstance(ns, str) or "." not in ns:
        return None
    return ns.split(".", 1)[1]


# What `claims_from` puts in front of a rule. A rule asking for anything
# else cannot be answered: there is nowhere else for a claim to come from,
# because the boundary will not believe one the caller asserts. See
# `unsuppliable_claims`, which says so at boot rather than at query time.
SUPPLIABLE_CLAIMS = frozenset({"user", "db", "groups", "roles"})


def unsuppliable_claims(guard: Guard) -> list[str]:
    """Claims this guard's rules need and the wire cannot produce.

    There are exactly four a boundary can honestly answer -- `user`, `db`,
    `groups`, `roles` -- because those are what the *server* says when
    asked `connectionStatus`, and a claim the client asserted is not
    evidence about the client.

    A rule wanting anything else is not wrong; it is enforceable where an
    application already knows the answer. Here it can only be reported,
    and it is reported **at boot**, because the alternative is correct and
    useless: no claim means the lowest clearance, which means every read
    of that collection is refused, which presents as "VOYD broke my reads"
    with nothing connecting it to a line in a policy file.

    `clearance(order=..., roles={...})` is the shape that avoids this --
    the mapping turns "how far up the ladder is this caller" into a
    question about roles, which the server does answer. A `clearance()`
    with no mapping lands here.
    """
    wanted = []
    for rule in guard.spec.rules:
        if not getattr(rule, "needs_caller", False):
            continue
        claim = getattr(rule, "claim", None)
        if isinstance(claim, str) and claim not in SUPPLIABLE_CLAIMS:
            wanted.append(claim)
    return sorted(set(wanted))


def _wants_a_caller(guards: dict[str, Guard], body: Mapping) -> bool:
    """Does this command touch a collection whose rules ask who is asking?

    The gate on paying a round trip. Cheap on purpose -- it reads the
    handful of fields a command names its collection in, and a deployment
    that declares no caller-aware rule never gets past the first line.
    """
    if not any(g.needs_caller for g in guards.values()):
        return False
    for verb in ("find", "aggregate", "distinct", "count", "getMore",
                 "findAndModify", "delete", "update", "insert"):
        target = body.get(verb)
        if isinstance(target, str) and target in guards:
            return guards[target].needs_caller
    # A `getMore` names its collection in `collection`, not in the verb.
    more = body.get("collection")
    if isinstance(more, str) and more in guards:
        return guards[more].needs_caller
    return False


def guard_for(guards: dict[str, Guard], body: Mapping,
              verb: str) -> Guard | None:
    """The guard for the collection this command names, if any.

    A command's target arrives from the wire, so it is whatever was in the
    bytes: absent, a string, or a number somebody sent on purpose. Every
    call site was spelling `guards.get(body.get(verb))`, which reads fine
    and asks a `dict[str, Guard]` to look up a value of unknown type -- five
    of this file's type errors, in the five places that decide whether a
    policy applies to a write. Narrowed once, here.

    Not called `named`, which was the first choice and was a live bug:
    `refuse_unrewritable` already binds a local `named` (a collection name)
    further down, so the name was function-scoped there and the call at the
    top of that same function raised `NameError` before reaching the
    server. `ruff` caught it in a second; `mypy` did not, which is a fair
    reminder of what each one is for.
    """
    name = body.get(verb)
    return guards.get(name) if isinstance(name, str) else None


class Budgets:
    """One running total per cursor, because the client picks the batch size.

    A cumulative rule -- `budget()`, `distinct()` -- compares a document
    against the total of the page so far. The handle opens one tab per
    `reachable()` call, and on the wire that is one call per *batch*. A
    cursor delivers one logical read in as many batches as the client asks
    for, and `batchSize` is a field in the client's own `find`.

    So without this, a declared budget of 100 tokens is a budget of 100
    tokens **per batch**, and `batchSize=2` over ten 40-token documents
    serves all ten. Nothing errors, nothing is logged, and the policy file
    says the rule is in force. That is the shape of hole this whole
    project is about, so the fix is not an optimisation and the tab is not
    optional.

    Keyed by the server's cursor id, held per connection, and dropped when
    the cursor is exhausted or killed. Per connection rather than on the
    `Guard`, which every connection shares: a tab is one client's read.

    Costs nothing when no guarded collection declares a cumulative rule,
    which is the ordinary case -- `Guard.cumulative` is the gate and the
    dict stays empty.
    """

    __slots__ = ("_open",)

    def __init__(self) -> None:
        self._open: dict[tuple[str, int], Any] = {}

    def tab_for(self, guard: Guard, cursor_id: Any) -> Any:
        """The tab this batch should be charged against.

        `_FRESH_TAB` for a read that is already whole: no cumulative rule
        to carry, or a cursor the server exhausted in one reply (`id: 0`),
        where there is no second batch for a total to span.
        """
        if not guard.cumulative:
            return _FRESH_TAB
        if not isinstance(cursor_id, int) or cursor_id == 0:
            return _FRESH_TAB
        key = (guard.collection, cursor_id)
        tab = self._open.get(key)
        if tab is None:
            tab = guard.handle.open_tab()
            self._open[key] = tab
        return tab

    def done(self, cursor_id: Any) -> None:
        """Forget a cursor's totals. Called when the server says `id: 0`.

        Without this a long-lived connection accumulates one tab per query
        it has ever run. Cursor ids are not reused while a cursor is live,
        so dropping on exhaustion is the whole of the lifecycle.
        """
        if not isinstance(cursor_id, int) or cursor_id == 0 or not self._open:
            return
        for key in [k for k in self._open if k[1] == cursor_id]:
            del self._open[key]

    def forget(self, cursor_ids: Any) -> None:
        """A client abandoned these cursors with `killCursors`."""
        if isinstance(cursor_ids, list):
            for cid in cursor_ids:
                self.done(cid)


def enforce(raw: bytes, req_id: int, resp_to: int, guards: dict[str, Guard],
            verbose: bool, caller: dict | None = None,
            budgets: "Budgets | None" = None) -> bytes:
    """Apply admission to a cursor batch on its way back to the client.

    Everything that is not a guarded cursor batch is forwarded byte for byte.
    That is deliberate: a proxy that re-encoded every message would be a new
    source of protocol bugs in exchange for nothing, and the only thing worth
    touching is the one array of documents that is about to become context.

    **Nothing is decoded until it is about to be judged.** Every reply on the
    connection arrives here, and all but a few are forwarded -- so the body is
    read lazily and the questions are asked cheapest-first: is there a cursor,
    what collection is it, is that collection guarded. A `find` on a
    collection nobody declared costs four field reads, not a Python object per
    float in every embedding it happens to carry. The documents become real
    only at ``guard.filter``, which is the first line that needs their values.
    """
    decoded = decode_op_msg(raw, LAZY)
    if decoded is None:
        return raw
    flags, reply = decoded
    cursor = reply.get("cursor")
    if not isinstance(cursor, Mapping):
        return raw
    key = "firstBatch" if "firstBatch" in cursor else (
        "nextBatch" if "nextBatch" in cursor else None)
    if key is None:
        return raw

    collection = _collection_of(reply)
    guard = guards.get(collection) if collection else None
    if guard is None:
        return raw

    batch = cursor[key]
    if not isinstance(batch, list) or not batch:
        return raw

    # The first read of the documents themselves, and only on a batch that a
    # declared guard is about to judge. Still lazy: the rules name a handful
    # of top-level fields, so a vector never becomes a list of floats -- and a
    # document that survives is re-encoded from the bytes it arrived in.
    cursor_id = cursor.get("id")
    tab = (budgets.tab_for(guard, cursor_id) if budgets is not None
           else _FRESH_TAB)
    kept = guard.filter(batch, caller, tab)
    if budgets is not None and cursor_id == 0:
        budgets.done(cursor_id)
    # The bytes are forwarded untouched only when the batch came back
    # *identical* -- same length and the same objects. Length alone was
    # the test, and it is the right test for whole-document refusal and
    # the wrong one for redaction: a collection declaring `subjects` has
    # its refused elements removed from a document that is still
    # admitted, so the count matches, the fast path returned the original
    # bytes, and the refused chapter was served with its refusal counted.
    #
    # `_admit` returns the document it was handed when it changed nothing
    # and a new one when it redacted, so identity is an exact answer and
    # costs a pointer comparison per document on the ordinary path.
    if len(kept) == len(batch) and all(a is b for a, b in zip(kept, batch)):
        return raw                      # nothing refused: do not touch the bytes

    reply = dict(reply)
    reply["cursor"] = dict(cursor)
    reply["cursor"][key] = kept
    # `reply` is now a plain dict of raw values; `bson.encode` splices the
    # untouched ones back in as bytes rather than re-serialising them.
    if verbose:
        print(f"  voyd: {collection}: refused {len(batch) - len(kept)} of "
              f"{len(batch)}  {guard.reasons()}", flush=True)
    return encode_op_msg(req_id, resp_to, flags, reply)


async def judge(raw: bytes, req_id: int, resp_to: int,
                guards: dict[str, Guard], verbose: bool,
                vault: "seal.Vault | None",
                meter: "metrics.Meter | None" = None,
                caller: dict | None = None,
                budgets: "Budgets | None" = None) -> bytes:
    """`enforce`, plus decryption for the collections that declared it.

    **The fast path is byte-for-byte the old one.** With no `--key-vault`,
    or on a collection nobody sealed, this is one dictionary lookup and
    then `enforce` -- still pure, still `bytes -> bytes`, still about 2.3
    microseconds per document. That matters because sealing is opt-in per
    collection and a deployment that seals one of twelve should pay for
    one of twelve.

    **The sealed path decrypts before it refuses, and the order is not a
    preference.** It is the order `Admission._unsealed` uses, and the two
    have to agree or one document would get two verdicts. It also costs
    something real: a
    rule that reads a sealed field is reading plaintext, which it could not
    do if refusal ran first, and a document refused by a deadline has still
    been decrypted by the time the deadline sees it. Decrypting something
    that is then refused is wasted work, not a leak -- it never leaves this
    process -- but it is wasted work worth naming.
    """
    if vault is None:
        return enforce(raw, req_id, resp_to, guards, verbose, caller, budgets)

    peek = decode_op_msg(raw, LAZY)
    if peek is None:
        return raw
    collection = _collection_of(peek[1])
    if not vault.seals(collection):
        return enforce(raw, req_id, resp_to, guards, verbose, caller, budgets)

    # Eager, unlike the fast path: these documents are about to be rebuilt
    # with a decrypted field in them, so there is no forwarding the bytes
    # they arrived in and nothing to be lazy for.
    decoded = decode_op_msg(raw)
    if decoded is None:
        return raw
    flags, reply = decoded
    cursor = reply.get("cursor")
    if not isinstance(cursor, Mapping):
        return raw
    key = "firstBatch" if "firstBatch" in cursor else (
        "nextBatch" if "nextBatch" in cursor else None)
    if key is None:
        return raw
    batch = cursor[key]
    if not isinstance(batch, list) or not batch:
        return raw

    assert collection is not None
    guard = guards.get(collection)
    plain, tally = await vault.unseal(batch, collection)
    if meter is not None:
        meter.sealed_reads_total += len(batch)
    if guard is not None:
        if tally:
            guard.note_sealed(tally)
        cursor_id = cursor.get("id")
        tab = (budgets.tab_for(guard, cursor_id) if budgets is not None
               else _FRESH_TAB)
        kept = guard.filter(plain, caller, tab)
        if budgets is not None and cursor_id == 0:
            budgets.done(cursor_id)
    else:
        kept = plain

    reply = dict(reply)
    reply["cursor"] = dict(cursor)
    reply["cursor"][key] = kept
    if verbose and (tally or len(kept) != len(batch)):
        named = guard.reasons() if guard is not None else tally
        print(f"  voyd: {collection}: refused {len(batch) - len(kept)} of "
              f"{len(batch)}  {named}", flush=True)
    return encode_op_msg(req_id, resp_to, flags, reply)
