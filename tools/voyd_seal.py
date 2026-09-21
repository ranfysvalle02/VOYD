#!/usr/bin/env python3
"""The erasure refusal cannot perform, moved to the wire.

Everything else this boundary does is a *refusal*: it is handed documents and
returns the ones a prompt may see. That is why `reachable()` is pure, why the
proxy holds no database connection of its own, and why refusal costs 2.3
microseconds per document. Those three facts are the same fact.

This file gives one of them up, deliberately and in exactly one place.

**Why it has to.** Refusal binds *this application's read path*. A replica
does not run it. Neither does a snapshot, a backup restored next year, or a
DBA with a shell. That is the honest gap, it is stated in `LIMITS.md` §2, and
no amount of refusing closes it -- the plaintext is on disk and every copy of
the disk has it. Destroying a key closes it, for every copy at once, without
visiting any of them. But a key is a thing you must *hold*, and a boundary
that holds no keys cannot destroy one.

So `--key-vault` is a trade with a price, and the price is printed at
startup rather than discovered:

    the boundary holds a connection of its own      it is no longer pure
    the boundary holds KMS credentials              it is a custody holder
    a sealed read decrypts before it refuses        it is no longer 2.3us

What is bought is where the encryption sits. A driver's `schema_map`
encrypts below the *application*, so no writer in that one process can
forget to encrypt. Here it encrypts below the *driver*, so no writer in any
language can -- not the Node service, not the migration script, not the
shell, not the notebook. That is the same upgrade this boundary gives
`delete`, applied to the stronger guarantee.

**Explicit encryption, not automatic, and that is a simplification rather
than a compromise.** Automatic encryption needs `crypt_shared` or
`mongocryptd` because the driver has to *analyse a command* to know which
fields to encrypt. This process has already parsed the command -- that is
what it is for -- and the policy file already names the fields. So it calls
`ce.encrypt()` on the values it knows are sealed, under the key it knows is
the tenant's, and needs no Enterprise download to do it. The ciphertext is
byte-identical to what `schema_map` produces: same `Random` algorithm, same
per-scope key, same vault.

That last point is the one worth testing rather than asserting, and
`tests/test_the_boundary_seals_and_shreds.py` does: a document sealed here
and one sealed by a driver's own `schema_map` are the same document
afterwards, and either can be read by the other's reader. Two spellings
that produced different rows would be exactly the drift this package is
about.

**Decryption refuses, it does not raise.** A crypto-erased document is a
normal, expected state -- it is the feature working -- so a page of fifty
containing one erased row returns forty-nine, not a 500. `unseal` in
`voyd/engine/admission/sealing.py` says this at length and this file does the
same thing for the same reason, calling the same
`keyring.why_undecryptable()` to decide whether a key that will not decrypt
was *destroyed* (an erasure) or merely *unreachable* (an outage). Those look
identical at the driver and mean opposite things, and a deployment that
reported one as the other would be paging on a success or ignoring a failure.

Deliberately outside `voyd/`, like `voyd_fanout.py`: nothing here is
importable package surface.
"""

from __future__ import annotations

import logging
from typing import Any, Mapping

# `RANDOM` is the algorithm `schema_map` uses for a `Sealed` field, and it
# is imported rather than spelled again here because the claim that this
# boundary's ciphertext is interchangeable with a driver's rests on the two
# matching.
from voyd.engine.admission.reasons import KEY_UNAVAILABLE, UNRECOVERABLE
from voyd.engine.admission.rules import _is_ciphertext
from voyd.engine.keyring import (RANDOM, Keyring, KeyringSpec,
                                 why_undecryptable)

log = logging.getLogger("voyd.seal")


class SealError(Exception):
    """A write this boundary cannot seal. Refused, never forwarded.

    There is no safe fallback. Forwarding an unsealable write puts the
    plaintext this deployment chose encryption to protect onto the disk, the
    replica and the backup, permanently and silently -- and no later fix
    reaches the copy that already has it. So the write is answered with an
    error the client can see, which is loud, harmless and reversible.
    """


class Vault:
    """The proxy's key vault, its encrypting handle, and its own credential.

    One per worker process. It is built at startup rather than lazily so a
    deployment that cannot reach its vault, or cannot unwrap its master key,
    fails at `voyd-wire` start with a message -- not on the first write that
    a client is waiting on, and certainly not by falling back to plaintext.
    """

    def __init__(self, uri: str, *, database: str, sealed: dict,
                 custody, collection: str = "__keys") -> None:
        self.uri = uri
        self.database = database
        # collection -> (fields, scope_field). Straight from the policy
        # file's OPTIONS, so the fields that get encrypted on the way in are
        # by construction the fields that get decrypted on the way out.
        self.sealed: dict[str, tuple[tuple[str, ...], str]] = sealed
        self.custody = custody
        self.collection = collection
        # Annotated rather than inferred from the initial `None`: a
        # checker reading `self._client = None` concludes the attribute is
        # always None and then flags every use of it, which is how these
        # three stayed the only type errors in this file.
        self._client: Any = None
        self._keyring: Keyring | None = None
        self._ce: Any = None
        # scope -> key id, per process. A key id is immutable and a shredded
        # key's id stays correct (it just stops resolving), so this is only
        # ever a saved round trip, never a stale verdict.
        self._keys: dict[str, Any] = {}
        # What this vault did, for the shutdown summary and the metrics
        # slab. A guarantee nobody counted is a claim about one, and the
        # write half had no series at all until these existed: a boundary
        # silently not encrypting looks exactly like one that is.
        self.sealed_writes = 0
        self.unsealed_reads = 0
        # Erasure *requests sequenced*, not keys confirmed destroyed. The
        # key dies by the client's own forwarded delete and this process
        # does not wait to see it land, so counting it as "keys destroyed"
        # would be this file claiming an outcome it never observed.
        self.erasures = 0
        self.refused_unrecoverable = 0
        self.refused_key_unavailable = 0

    def seals(self, collection: str | None) -> bool:
        return collection in self.sealed

    # ---- lifecycle -----------------------------------------------------

    async def open(self) -> None:
        """Dial the vault, ensure its indexes, and say what custody is.

        `Keyring.ensure()` is `voyd.engine.keyring`'s, not a second
        implementation:
        the `keyAltNames` unique index and -- the one that belongs to this
        project -- the TTL index that lets a key carry the same `expire_at`
        its documents carry, so the scope's deadline destroys the scope's
        key with no second scheduler.
        """
        from pymongo import AsyncMongoClient

        self._client = AsyncMongoClient(self.uri)
        db = self._client[self.database]
        self._keyring = Keyring(
            db, KeyringSpec(collection=self.collection), custody=self.custody,
            uri=self.uri)
        await self._keyring.ensure()
        self._ce = await self._keyring.encryption()
        log.info("key vault %s open; custody is %s",
                 self._keyring.namespace, self.custody.detail())

    async def aclose(self) -> None:
        if self._ce is not None:
            await self._ce.close()
            self._ce = None
        if self._client is not None:
            await self._client.close()
            self._client = None

    def describe(self) -> dict:
        """What this boundary now holds, as data.

        A proxy that quietly became a custody holder is the thing this
        repository is named after, so this is printed at startup and is
        also what `announce` below renders -- one source of truth for the
        vault namespace, the custody rung in force, and which fields of
        which collections are sealed.
        """
        return {
            "vault": f"{self.database}.{self.collection}",
            "custody": self.custody.describe(),
            "detail": self.custody.detail(),
            "durable": bool(getattr(self.custody, "durable", False)),
            "rung": type(self.custody).__name__,
            "sealed": {c: list(f) for c, (f, _s) in self.sealed.items()},
            "scope": {c: s for c, (_f, s) in self.sealed.items()},
        }

    # ---- keys ----------------------------------------------------------

    async def _key_for(self, scope: str):
        if scope not in self._keys:
            assert self._keyring is not None
            self._keys[scope] = await self._keyring.key_for(
                scope, encryption=self._ce)
        return self._keys[scope]

    # ---- the write half ------------------------------------------------

    async def _seal_value(self, value: Any, scope: str) -> Any:
        """One field, encrypted under the tenant's key.

        A value that is *already* ciphertext is left alone rather than
        double-encrypted: a client running its own CSFLE against the same
        vault is a legitimate deployment, and wrapping its ciphertext again
        would produce a document only this boundary could read.
        """
        if _is_ciphertext(value) or value is None:
            return value
        assert self._ce is not None
        return await self._ce.encrypt(
            value, RANDOM, key_id=await self._key_for(scope))

    async def _seal_document(self, doc: Mapping, fields: tuple[str, ...],
                             scope_field: str, *, where: str,
                             scope: str | None = None) -> dict:
        row = dict(doc)
        at = scope if scope is not None else row.get(scope_field)
        if at is None:
            raise SealError(
                f"{where}: no {scope_field!r} in this document, so there is "
                f"no scope and therefore no key to seal "
                f"{', '.join(repr(f) for f in fields)} under. A sealed write "
                f"with no scope has only two outcomes and both are bad: "
                f"plaintext on disk under a policy that says otherwise, or "
                f"one key for every tenant, which makes erasing one subject "
                f"erase them all. Refused instead.")
        if not isinstance(at, str):
            # Key alt names are strings in the vault. An ObjectId tenant is
            # a perfectly reasonable design; it just has to be spelled the
            # same way on both halves or the key is minted twice.
            at = str(at)
        for name in fields:
            if name in row:
                row[name] = await self._seal_value(row[name], at)
        self.sealed_writes += 1
        return row

    async def seal_command(self, body: dict, ident: str | None,
                           docs: list) -> tuple[dict, str | None, list] | None:
        """Encrypt the sealed fields of a write, wherever they are carried.

        Returns the rewritten `(body, ident, docs)`, or `None` if there was
        nothing to do -- in which case the caller forwards the original bytes
        untouched, which is the same "do not re-encode what you did not
        change" discipline the read path keeps.

        **Three commands, because they are three different wire messages and
        covering two of them is worse than covering none.** `insert` carries
        its documents in a kind-1 section (or, from some drivers, inline in
        the body); `update` carries `{q, u}` pairs whose `u` is either a
        replacement document or a `$set`; `findAndModify` carries one
        `update` in the body. A sealed field written through the one this
        file forgot would be plaintext on disk, and nothing would say so.
        """
        collection = None
        for verb in ("insert", "update", "findAndModify"):
            name = body.get(verb)
            if isinstance(name, str) and name in self.sealed:
                collection = name
                break
        else:
            return None
        assert collection is not None
        fields, scope_field = self.sealed[collection]
        where = f"{verb} on {collection}"

        if verb == "insert":
            payload = docs if ident == "documents" and docs else None
            inline = body.get("documents") if payload is None else None
            if payload is not None:
                sealed = [await self._seal_document(
                    d, fields, scope_field, where=where) for d in payload]
                return body, ident, sealed
            if isinstance(inline, list) and inline:
                body = dict(body)
                body["documents"] = [await self._seal_document(
                    d, fields, scope_field, where=where) for d in inline]
                return body, ident, docs
            return None

        if verb == "update":
            statements = docs if ident == "updates" and docs else None
            inline = body.get("updates") if statements is None else None
            source = statements if statements is not None else inline
            if not isinstance(source, list) or not source:
                return None
            rewritten = [await self._seal_update(s, fields, scope_field, where)
                         for s in source]
            if statements is not None:
                return body, ident, rewritten
            body = dict(body)
            body["updates"] = rewritten
            return body, ident, docs

        update = body.get("update")
        if not isinstance(update, dict):
            return None
        body = dict(body)
        body["update"] = await self._seal_update_doc(
            update, fields, scope_field, where,
            scope=self._scope_of_query(body.get("query"), scope_field))
        return body, ident, docs

    @staticmethod
    def _scope_of_query(query: Any, scope_field: str) -> str | None:
        """The tenant an update is aimed at, read off its own filter.

        An update's `$set` names the fields it changes and usually not the
        tenant, so the scope comes from the selector instead -- which this
        boundary already requires to carry the tenant, on every guarded
        collection, for a different reason. The two requirements happen to
        be the same requirement, which is why this is a field read rather
        than a round trip.
        """
        if not isinstance(query, Mapping):
            return None
        value = query.get(scope_field)
        if isinstance(value, Mapping):
            # `{"tenant_id": {"$eq": "acme"}}` is the same query written
            # longhand; anything else ($in, $ne) selects more than one
            # scope and has no single key.
            value = value.get("$eq")
        if value is None:
            return None
        return value if isinstance(value, str) else str(value)

    async def _seal_update(self, statement: Mapping, fields, scope_field,
                           where: str) -> dict:
        out = dict(statement)
        out["u"] = await self._seal_update_doc(
            statement.get("u"), fields, scope_field, where,
            scope=self._scope_of_query(statement.get("q"), scope_field))
        return out

    async def _seal_update_doc(self, u: Any, fields, scope_field, where: str,
                               *, scope: str | None) -> Any:
        """A replacement document, or the operators that touch sealed fields.

        A pipeline update (`u` as a list) is refused rather than guessed at:
        its stages compute values server-side, where this boundary cannot
        reach them, so a sealed field assigned inside one would be written
        as plaintext by the server itself.
        """
        if isinstance(u, list):
            touched = [f for f in fields if f in str(u)]
            if touched:
                raise SealError(
                    f"{where}: a pipeline update that may assign sealed "
                    f"field(s) {', '.join(touched)}. The stages run inside "
                    f"the server, where this boundary cannot encrypt what "
                    f"they compute, so the field would land as plaintext. "
                    f"Write the value from the client instead.")
            return u
        if not isinstance(u, Mapping):
            return u
        out = dict(u)
        # A replacement document: sealed fields sit at the top level.
        if not any(k.startswith("$") for k in out):
            return await self._seal_document(
                out, fields, scope_field, where=where, scope=scope)
        for operator, argument in list(out.items()):
            if not isinstance(argument, Mapping):
                continue
            hit = [f for f in fields if f in argument]
            if not hit:
                continue
            if operator != "$set" and operator != "$setOnInsert":
                raise SealError(
                    f"{where}: {operator} on sealed field(s) "
                    f"{', '.join(hit)}. A sealed value is opaque ciphertext, "
                    f"so incrementing, appending to or renaming it is not an "
                    f"operation that has a meaning. Set the whole value.")
            at = scope if scope is not None else argument.get(scope_field)
            if at is None:
                raise SealError(
                    f"{where}: {operator} writes sealed field(s) "
                    f"{', '.join(hit)} but neither the filter nor the update "
                    f"names {scope_field!r}, so this boundary cannot tell "
                    f"whose key to use. Include the tenant in the filter.")
            changed = dict(argument)
            for name in hit:
                changed[name] = await self._seal_value(
                    changed[name], at if isinstance(at, str) else str(at))
            out[operator] = changed
            self.sealed_writes += 1
        return out

    # ---- the read half -------------------------------------------------

    async def unseal(self, documents: list, collection: str
                     ) -> tuple[list[dict], dict[str, int]]:
        """Decrypt, refusing per document. ``(kept, tally)``.

        Per document rather than per batch, and that is the whole design
        rather than a detail. Automatic decryption raises for the *batch*
        when one key is missing, so a single crypto-erased row would turn a
        page of fifty into a 500 -- "fewer rows, or an error", which is the
        shape this codebase refuses everywhere else. A crypto-erased
        document is not an incident. It is somebody's erasure request,
        honoured.
        """
        fields, scope_field = self.sealed[collection]
        kept: list[dict] = []
        tally: dict[str, int] = {}
        verdicts: dict[Any, str] = {}
        for doc in documents:
            out = dict(doc)
            refused = False
            for name in fields:
                value = out.get(name)
                if not _is_ciphertext(value):
                    continue
                try:
                    assert self._ce is not None
                    out[name] = await self._ce.decrypt(value)
                except Exception:  # noqa: BLE001 - an answer, not an incident
                    scope = out.get(scope_field)
                    reason = await why_undecryptable(
                        self._keyring,
                        scope if scope is None or isinstance(scope, str)
                        else str(scope),
                        verdicts)
                    tally[reason] = tally.get(reason, 0) + 1
                    refused = True
                    break
            if not refused:
                kept.append(out)
        self.unsealed_reads += len(documents)
        self.refused_unrecoverable += tally.get(UNRECOVERABLE, 0)
        self.refused_key_unavailable += tally.get(KEY_UNAVAILABLE, 0)
        if tally.get(UNRECOVERABLE):
            log.info("%s: %d document(s) are unrecoverable -- their key was "
                     "destroyed, so no read path anywhere can produce the "
                     "plaintext", collection, tally[UNRECOVERABLE])
        if tally.get(KEY_UNAVAILABLE):
            # ERROR, not info: the key still exists and could not be
            # fetched, so this is an outage wearing the costume of a
            # feature, and entitled callers are being denied their rows.
            log.error("%s: %d document(s) could not be decrypted although "
                      "their key still exists. This is a KMS or key-vault "
                      "failure, not an erasure: the data is being withheld, "
                      "not destroyed", collection, tally[KEY_UNAVAILABLE])
        return kept, tally

    def targets(self, body: Mapping) -> bool:
        """Does this command write a collection somebody declared sealed?

        Asked before the body is re-decoded, so an ordinary write to an
        unsealed collection costs three dictionary reads rather than a
        parse -- the same cheapest-first discipline the read path keeps.
        """
        for verb in ("insert", "update", "findAndModify"):
            name = body.get(verb)
            if isinstance(name, str) and name in self.sealed:
                return True
        return False

    # ---- erasure -------------------------------------------------------

    async def shred(self, scope: str) -> int:
        """Destroy one scope's key. Its ciphertext is noise, everywhere."""
        assert self._keyring is not None
        self._keys.pop(scope, None)
        return await self._keyring.shred(scope, encryption=self._ce)

    def erasing(self, body: Mapping, statements: list,
                database: str) -> list[str]:
        """Is this client destroying a key? Whose?

        An erasure needs no new verb, because the key vault is an ordinary
        collection and every driver can already delete from one:

            db["__keys"].delete_one({"keyAltNames": "alice"})

        Which is the right shape -- an operator should not have to learn a
        protocol extension to honour an erasure request -- and it is also
        the reason the boundary has to *notice*. See ``revoke_first``.

        ``statements`` is the kind-1 document sequence, because that is
        where a `delete` actually carries its clauses -- the body says
        ``{"delete": "__keys"}`` and a separate section holds the
        ``{"q": ...}``. Reading only the body found nothing, forwarded the
        key's destruction, and skipped the revocation that had to come
        first: the erasure still happened and the window this exists to
        close stayed open. The same section this file's neighbours already
        had a silent bug in.

        Only an exact-match or ``$in`` on ``keyAltNames`` is recognised.
        A filter this cannot read returns no scopes, so the delete is
        forwarded and the key still dies; what is skipped is the
        revocation that should have preceded it, and ``revoke_first``
        says so out loud rather than letting it pass as handled.
        """
        if database != self.database:
            return []
        if body.get("delete") != self.collection:
            return []
        scopes: list[str] = []
        clauses = statements or body.get("deletes") or ()
        for statement in clauses:
            if not isinstance(statement, Mapping):
                continue
            named = (statement.get("q") or {}).get("keyAltNames")
            if isinstance(named, str):
                scopes.append(named)
            elif isinstance(named, Mapping) and isinstance(
                    named.get("$in"), list):
                scopes.extend(v for v in named["$in"] if isinstance(v, str))
        return scopes

    async def revoke_first(self, scopes: list[str], pipelines: Mapping) -> int:
        """Mark a scope's documents *before* its key is destroyed.

        **This is the ordering `keyring.py` argues for, and running the
        feature is what showed it was missing.** Destroying a key is not
        instant at the reader: libmongocrypt caches data keys, and a
        process that decrypted a scope a moment ago keeps decrypting it
        until that cache turns over -- measured at about 60 seconds, which
        is the same shape, and very nearly the same number, as the TTL
        window this whole project exists to complain about. A shred on its
        own therefore opens a second delete-is-a-wish window, in the
        feature whose entire purpose is to close the first one.

        Refusal has no such window. So the two halves are ordered rather
        than merely both present: the documents are revoked here, which
        makes them unreachable on the very next read, and *then* the key
        is destroyed, which makes every copy of them unreadable everywhere
        once the cache turns over. Unreachable first, erased second. The
        reverse order is the bug, and the reverse order is what this
        boundary shipped until somebody pointed a client at it.

        Returns how many documents were marked, so the caller can say.
        """
        if not scopes or self._client is None:
            return 0
        self.erasures += len(scopes)
        db = self._client[self.database]
        marked = 0
        for collection, (_fields, scope_field) in self.sealed.items():
            if not _fields:
                continue
            pipeline = pipelines.get(collection)
            if not pipeline:
                # A sealed collection with no revocable() field has nowhere
                # to record the mark. The key still dies; this says the
                # window is open rather than implying it is not.
                log.warning(
                    "%s is sealed but declares no revocable() field, so its "
                    "documents cannot be marked before the key goes. They "
                    "stay readable until the key cache turns over -- about "
                    "60s. Declare revocable() to close that window",
                    collection)
                continue
            # Only the rows the key actually protected.
            #
            # This is a real decision and it is narrow on purpose.
            # Destroying a key is a statement about *ciphertext*, and the
            # only reason to revoke ahead of it is to close the window
            # where that ciphertext still decrypts out of a cache. A row
            # carrying none of the sealed fields has no such window -- it
            # was never encrypted -- so revoking it would be the boundary
            # inventing policy out of a key deletion, and an operator
            # would be surprised to find unencrypted documents unreachable
            # because they destroyed a key.
            #
            # The operator who means "forget this tenant entirely" already
            # has a verb for it: a `delete` on the collection, which
            # `on_delete="revoke"` turns into exactly that. Two verbs, two
            # meanings, neither one redefining the other.
            #
            # `$exists` rather than `$type: "binData"`: a plaintext value
            # sitting in a field the policy declares sealed is a row
            # written while sealing was off, and an erasure for that scope
            # should still reach it. See LIMITS.md §5.
            result = await db[collection].update_many(
                {scope_field: {"$in": scopes},
                 "$or": [{field: {"$exists": True}} for field in _fields]},
                pipeline)
            marked += result.modified_count
        return marked


def sealed_from(options: Mapping) -> dict:
    """Which collections a loaded policy file wants sealed, and under what.

    Reads the same `OPTIONS` the delete rewrite reads, so there is one
    declaration and not a second place to keep in step.
    """
    return {name: (tuple(opt["sealed"]), opt["scope_field"])
            for name, opt in options.items()
            if opt.get("sealed") and opt.get("scope_field")}


def announce(spec: Mapping) -> list[str]:
    """The startup banner for a sealing boundary, as lines.

    A function rather than prints inline because it is asserted: the
    README leads with "the proxy holds no database connection of its own",
    and a deployment that switched that off is owed the retraction in the
    first screen of output rather than in a footnote. A test checks these
    lines are there, which is only possible if something returns them.

    Built from a `vault_spec` rather than from an open `Vault`, because it
    is printed in the parent before any fork and before anything has
    dialled the database -- if the vault is unreachable, the operator
    should have already read what this process was going to hold.
    """
    view = Vault(spec["uri"], database=spec["database"],
                 sealed=spec["sealed"], custody=spec["custody"],
                 collection=spec.get("collection", "__keys")).describe()
    lines = [f"voyd-wire: key vault {view['vault']}; custody is "
             f"{view['rung']} -- {view['detail']}"]
    for name, fields in sorted(view["sealed"].items()):
        lines.append(
            f"voyd-wire: sealing {name}.{{{', '.join(fields)}}} under a key "
            f"per {view['scope'][name]}; shred one and every copy of that "
            f"tenant's ciphertext is noise")
    # The property this flag spends, said out loud. Every other thing this
    # process does is pure; this one holds a connection and a credential.
    lines.append(
        "voyd-wire: THIS BOUNDARY NOW HOLDS KEYS. It has a database "
        "connection of its own and is a custody holder; sealed reads "
        "decrypt before they refuse. See LIMITS.md \u00a75")
    if not view["durable"]:
        lines.append(
            "voyd-wire: WARNING: custody is ephemeral -- the master key is "
            "in this process's memory and a restart makes every sealed "
            "document unreadable. Demo-grade. Use "
            "--kms local:/path/to/master.key to keep it")
    return lines
