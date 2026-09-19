"""Cryptographic erasure: the deadline destroys the key, not just the reach.

Refusal answers *may this fact reach a prompt?* -- immediately, on every read,
before the sweeper has done anything. It is the right answer to that question
and it is the wrong answer to a different one, which a security reviewer asks
about four minutes into the conversation:

    "So the plaintext is still on disk. What about your backups? Your
     replicas? Your snapshots from last Tuesday? The DBA?"

Refusal has nothing to say there. It is a property of *this application's read
path*, and a restored backup does not run this application's read path. That
is the honest gap, and this module closes it.

**Crypto-shredding.** Each scope gets a data encryption key. Sensitive fields
are ciphertext at rest, encrypted under it. Destroying the key makes every
copy of that ciphertext permanently unreadable -- the row, the replica, the
snapshot, the backup tape, and the one somebody exported to a laptop in March.
No sweeper visits any of them and none has to.

Three layers, and each is honest about what it costs:

    refusal          immediate, this read path only.     unreachable now
    crypto erasure   ~60s (measured), everywhere.        unreadable soon
    the TTL reaper   ~60s, this deployment only.         gone eventually

**The measured part, because this is the claim people overstate.** Destroying
a key is not instantaneous either. libmongocrypt caches data keys, and a
client that decrypted a document before the shred keeps decrypting it until
that cache turns over -- measured here at **60s**, which is the same shape,
and very nearly the same number, as the TTL monitor window this whole package
exists to talk about. Anybody who tells you crypto erasure is instant has not
measured it.

So the two halves cover each other exactly, and that is the argument for
having both rather than choosing:

    the key cache is a window in which the ciphertext is still readable
        -> refusal already refused the document, on the first read after
           the revocation, with no window at all
    refusal only binds this application's read path
        -> the key is gone, so a backup restored next year is noise

**Automatic on write, explicit on read, and the asymmetry is deliberate.**
Automatic encryption (``schema_map``, a JSON pointer at ``keyId``) means no
application code can *forget* to encrypt: the driver does it below the
application, for every writer, including the one written next year by someone
who has not read this file. That matters because forgetting to encrypt is
silent, permanent and unrecoverable -- the plaintext is on disk and no later
fix reaches the backup that already has it.

Decryption is the opposite kind of mistake. Forgetting to decrypt hands the
caller an obviously-wrong ``Binary`` blob: loud, harmless, self-correcting.
And automatic decryption has a failure mode that is *worse* than the mistake
it prevents -- a single shredded key raises ``EncryptionError`` for the whole
batch, so one crypto-erased document turns a page of fifty into a 500. That
is exactly the "fewer rows, or an error" shape this codebase refuses
everywhere else. ``unseal()`` therefore decrypts per document and **refuses**
what it cannot, under the reason ``unrecoverable``, which is the same thing
the rest of the engine does with a fact it may not serve.

**Key custody is a declared thing, not a dict.** See ``custody.py``: the
whole claim rests on who holds the key that wraps the data keys, and a
crypto claim that is vague there is marketing. The rungs go ``Ephemeral``
(demo; nothing survives a restart) -> ``LocalFile`` (durable, custody is a
file permission) -> ``Aws``/``Azure``/``Gcp``/``Kmip`` (destroying the CMK
is somebody else's audited operation). Same code path throughout -- a
provider name and a master-key document -- and ``describe()`` prints which
rung is in force, so "what is your custody story" has an answer a deployment
can produce rather than one a person recalls.

**Two protection modes, and the choice between them is a real tradeoff
rather than a preference.** Measured against MongoDB 8.2:

    CSFLE      ``keyId`` may be a JSON *pointer* (``/key_scope``), so the
    (Sealed)   driver resolves a different key per document. That is what
               makes per-scope shredding possible: erase one subject and
               nobody else's key is touched. The cost is that a Random
               field cannot be queried -- which is free here, because what
               gets searched is the embedding, and the embedding is not
               the sensitive field.

    Queryable  ``encryptedFields`` with equality (7.0+) or range (8.0+)
    (Queryable) indexes, so the *ciphertext itself* is searchable. The cost
               is measured and structural: QE **rejects a pointer keyId** --
               ``BSON field 'create.encryptedFields.fields.keyId' is the
               wrong type 'string'`` -- so a key is bound per field per
               collection at creation time. Shredding it erases that field
               for every document in the collection, not for one subject.

So the rule, stated once so nobody has to rediscover it: **if erasure must
be per-subject, use ``Sealed``; if the encrypted field must be queryable,
use ``Queryable`` and accept that your shred granularity is the collection.**
Wanting both at once means one collection per subject, and that is a
sharding decision, not an encryption one. ``Keyring.describe()`` reports
which mode is in force and what it implies, because this is the kind of
tradeoff that gets made once and misremembered forever.

**One owner, still.** The key vault is a MongoDB collection, so the key
carries the same ``expire_at`` the documents do and is collected by the same
TTL index -- the scope's deadline destroys the scope's key without a second
scheduler, a second clock, or a cron job to keep them agreeing. That is the
first claim in this repository, applied to the thing that enforces the second
one.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

from pymongo.errors import CollectionInvalid

from .custody import Custody, Ephemeral
from datetime import datetime
from typing import Any

log = logging.getLogger("engine.keyring")

# What the driver stamps on ciphertext. A BSON Binary with subtype 6 is an
# encrypted value: useful for asserting "this really is unreadable at rest"
# without having to trust a log line.
ENCRYPTED = 6

# The reason a document is refused because its key is gone. Distinct from
# ``deadline`` and ``revoked`` on purpose: those say a fact was forgotten,
# this says it is *unrecoverable*, which is a stronger statement and the one
# a security reviewer is asking for.
UNRECOVERABLE = "unrecoverable"

RANDOM = "AEAD_AES_256_CBC_HMAC_SHA_512-Random"


def _uri_of(client) -> str:
    """Reconstruct a connection string for a client we were handed.

    The encrypting client has to dial the same deployment, and asking the
    caller to pass the URI twice is a way to point them at two different
    ones. ``client.address`` is a coroutine on the async driver, so the
    seed list from the topology settings is what is available synchronously
    -- and it is the right source anyway: it is what this client was
    *configured* with, not whichever node it happens to be talking to.
    """
    try:
        seeds = client.topology_description.known_servers
        hosts = ",".join(f"{s.address[0]}:{s.address[1]}" for s in seeds)
    except Exception:  # noqa: BLE001 - fall through to the settings below
        hosts = ""
    if not hosts:
        nodes = getattr(client, "_topology_settings", None)
        hosts = ",".join(f"{h}:{p}" for h, p in
                         getattr(nodes, "seeds", [("localhost", 27017)]))
    return f"mongodb://{hosts}/?directConnection=true"


def available() -> tuple[bool, str]:
    """Can this process do automatic encryption, and if not, why not?

    Two independent requirements, reported separately because they fail for
    different reasons and are fixed in different places:

    ``pymongocrypt``   the Python binding. the ``crypto`` extra.
    ``crypt_shared``   the query-analysis library, or ``mongocryptd``. Not
                       on PyPI -- it is a MongoDB Enterprise download, which
                       is worth knowing before a deployment discovers it.

    Follows ``capabilities.py``: ask, report, never pretend. A deployment
    that silently skipped encryption would look exactly like one that had it.
    """
    try:
        import pymongocrypt  # noqa: F401
    except ImportError:
        return False, "pymongocrypt is not installed (install the crypto extra)"
    path = crypt_shared_path()
    if path:
        return True, f"crypt_shared at {path}"
    if _which("mongocryptd"):
        return True, "mongocryptd on PATH (slower than crypt_shared)"
    return False, ("neither crypt_shared nor mongocryptd found; set "
                   "CRYPT_SHARED_LIB_PATH to the MongoDB Enterprise "
                   "mongo_crypt_v1 library")


def crypt_shared_path() -> str | None:
    path = os.environ.get("CRYPT_SHARED_LIB_PATH")
    return path if path and os.path.exists(path) else None


def _which(name: str) -> str | None:
    from shutil import which
    return which(name)


@dataclass(frozen=True)
class Sealing:
    """One collection's sealing, resolved: which keyring, which fields.

    Handed to an ``Admission`` so the read path can decrypt without the
    caller passing a keyring and a field list to every call. That is not
    sugar -- three arguments a caller must remember at every read site is
    the exact shape of rule this package exists to make structural.
    """

    keyring: Any
    fields: tuple[str, ...]
    scope_field: str

    async def close(self) -> None:
        pass


@dataclass(frozen=True)
class Sealed:
    """CSFLE: a key per scope, resolved through a JSON pointer.

    The mode that makes per-subject erasure possible. ``fields`` are
    encrypted with a Random algorithm and cannot be queried -- which costs
    nothing here, because retrieval matches on the embedding and the
    embedding is not the sensitive field.
    """

    fields: tuple[str, ...] = ("text",)
    bson_type: str = "string"
    queryable: bool = False
    shred_granularity: str = "scope"


@dataclass(frozen=True)
class Queryable:
    """Queryable Encryption: the ciphertext itself is searchable.

    ``equality`` is MongoDB 7.0+; ``range`` is 8.0+. The price is measured
    and structural -- QE rejects a pointer ``keyId``, so one key covers one
    field across the whole collection and shredding it erases that field
    for everybody. Chosen deliberately or not at all.
    """

    fields: tuple[str, ...] = ()
    bson_type: str = "string"
    query_type: str = "equality"
    queryable: bool = True
    shred_granularity: str = "collection"


@dataclass(frozen=True)
class KeyringSpec:
    """Where the keys live, which field points at one, and what is protected.

    ``pointer_field`` is the document field naming the key, and the CSFLE
    schema turns it into a JSON pointer (``/key_scope``) so the driver
    resolves a *different* key per document. A static ``keyId`` would give
    one key per collection, which makes shredding all-or-nothing -- erase
    one subject and every other tenant goes with them.
    """

    collection: str = "__keys"
    pointer_field: str = "key_scope"
    at_field: str = "expire_at"
    # Collection -> how that collection is protected.
    protect: dict[str, Any] = field(default_factory=dict)

    def sealed_collections(self) -> dict:
        return {c: p for c, p in self.protect.items()
                if isinstance(p, Sealed)}

    def queryable_collections(self) -> dict:
        return {c: p for c, p in self.protect.items()
                if isinstance(p, Queryable)}


class Keyring:
    """The key vault, as a trait. ``ensure()`` gives it its two indexes."""

    kind = "keyring"

    def __init__(self, db, spec: KeyringSpec | None = None, *,
                 custody: Custody | None = None,
                 kms_providers: dict | None = None,
                 uri: str | None = None):
        self.db = db
        self.spec = spec or KeyringSpec()
        self.collection = self.spec.collection
        if kms_providers is not None and custody is not None:
            raise ValueError(
                "pass custody= or kms_providers=, not both: two answers to "
                "'who holds the master key' is the one question that must "
                "have exactly one")
        # A raw dict stays supported because the driver's vocabulary is the
        # real interface and wrapping it completely would just be a second
        # thing to keep current. It arrives as unknown custody, and
        # ``describe()`` says so rather than guessing.
        self._raw = kms_providers
        self.custody = custody or (_Declared(kms_providers) if kms_providers
                                   else Ephemeral())
        self.kms_providers = self.custody.providers()
        # The URI this keyring will dial for its own encrypting client.
        # Taken from the client it was handed, so a keyring cannot end up
        # pointing at a different deployment than the engine it belongs to
        # -- which is a failure that would look like "the keys are missing"
        # rather than like a misconfiguration.
        self._uri = uri or _uri_of(db.client)
        self._writer = None

    @property
    def namespace(self) -> str:
        return f"{self.db.name}.{self.collection}"

    # ---- schema --------------------------------------------------------

    async def ensure(self) -> bool:
        """Two indexes, and the second one is the interesting one.

        ``keyAltNames`` unique is required by the driver -- two keys
        answering to one name is a coin toss about which fact you can still
        read.

        The TTL index is the part that belongs to *this* project. The key
        vault is an ordinary collection, so a key can carry the same
        ``expire_at`` its documents carry and be collected by the same
        reaper. The scope's deadline therefore destroys the scope's key with
        no second scheduler and no cron keeping two clocks in agreement --
        which is the first claim in this repository, applied to the
        mechanism that enforces the second one.
        """
        await self.db[self.collection].create_index(
            "keyAltNames", unique=True,
            partialFilterExpression={"keyAltNames": {"$exists": True}})
        await self.db[self.collection].create_index(
            self.spec.at_field, expireAfterSeconds=0, sparse=True)
        for collection in self.spec.sealed_collections():
            await self.enforce(collection)
        self.custody.warn_if_weak(f"keyring {self.namespace}")
        return True

    # ---- keys ----------------------------------------------------------

    async def key_for(self, scope: str, *, expire_at: datetime | None = None,
                      encryption=None):
        """The data key for one scope, created on first use.

        The provider name and master key come from ``custody`` rather than
        being hardcoded, which is not a refactor for its own sake: with
        ``local`` the master key is an argument-free default, and with every
        other provider it is *required* and provider-shaped. A keyring that
        always said ``"local"`` would accept an AWS configuration and
        quietly wrap the data key with a process-local secret instead.

        ``expire_at`` is written onto the key document itself, so the TTL
        index above destroys it on the scope's own deadline. ``None`` pins
        the key exactly the way a null deadline pins a document.
        """
        existing = await self.db[self.collection].find_one(
            {"keyAltNames": scope})
        if existing is not None:
            if expire_at is not None:
                await self._never_later(existing["_id"], expire_at)
            return existing["_id"]

        ce, owned = await self._encryption(encryption)
        try:
            key_id = await ce.create_data_key(
                self.custody.provider, master_key=self.custody.master_key(),
                key_alt_names=[scope])
        finally:
            if owned:
                await ce.close()
        if expire_at is not None:
            await self.db[self.collection].update_one(
                {"_id": key_id}, {"$set": {self.spec.at_field: expire_at}})
        log.info("keyring %s minted a key for scope %r under %s (expires %s)",
                 self.namespace, scope, self.custody.detail(),
                 expire_at.isoformat() if expire_at else "never")
        return key_id

    async def _never_later(self, key_id, expire_at: datetime) -> None:
        """A key's deadline moves earlier or not at all.

        The same invariant ``revoke()`` holds for a document, for the same
        reason: extending a key's life extends the readability of
        everything it protects, and "we renewed the key so the erasure took
        a week longer" is not a sentence anybody wants to write down.
        """
        at = self.spec.at_field
        await self.db[self.collection].update_one(
            {"_id": key_id},
            [{"$set": {at: {"$cond": [
                {"$eq": [{"$type": f"${at}"}, "date"]},
                {"$min": [f"${at}", expire_at]}, expire_at]}}}])

    async def shred(self, scope: str, *, encryption=None) -> int:
        """Destroy a scope's key now. Everything it protected is noise.

        The one operation in this package where deleting is the right verb,
        and worth being precise about, since the rest of the repository
        argues the opposite. Deleting a document is a storage event:
        eventually consistent, local to this deployment, unprovable.
        Deleting a key is a storage event whose *effect* is total -- every
        copy of the ciphertext, in every backup and replica and snapshot,
        becomes unreadable at once, without any of them being visited.

        Not instantly, though. See the module docstring: a client holding a
        cached copy keeps decrypting for a while, and the turnover is not a
        contract. Refusal is what covers that window, which is the argument
        for having both.
        """
        ce, owned = await self._encryption(encryption)
        try:
            try:
                key = await ce.get_key_by_alt_name(scope)
            except Exception:  # noqa: BLE001 - absent is a normal answer
                key = None
            if key is None:
                return 0
            await ce.delete_key(key["_id"])
        finally:
            if owned:
                await ce.close()
        log.info("keyring %s destroyed the key for scope %r; its ciphertext "
                 "is unreadable everywhere, subject to a key cache whose "
                 "turnover is not a contract", self.namespace, scope)
        return 1

    async def rotate(self, *, scope: str | None = None,
                     custody: Custody | None = None, encryption=None) -> int:
        """Re-wrap data keys under a new master key. The data is untouched.

        Rotation is the half of key management that makes destruction
        credible. A key that cannot be re-wrapped is a key that will
        eventually be copied rather than rotated, and a copied key cannot be
        destroyed -- so "we shredded it" stops being true without anybody
        doing anything wrong.

        This re-encrypts the *data keys* under a new CMK. It does not touch
        a single document: the DEK is unchanged, so every ciphertext it
        protects stays readable, and the thing that moved is who can unwrap
        it. That is why rotating a CMK is cheap here and re-encrypting a
        collection is not.
        """
        target = custody or self.custody
        ce, owned = await self._encryption(encryption)
        try:
            flt = {"keyAltNames": scope} if scope else {}
            result = await ce.rewrap_many_data_key(
                flt, provider=target.provider, master_key=target.master_key())
        finally:
            if owned:
                await ce.close()
        n = getattr(getattr(result, "bulk_write_result", None),
                    "modified_count", 0) or 0
        log.info("keyring %s re-wrapped %d data key(s) under %s",
                 self.namespace, n, target.detail())
        return n

    # ---- the driver plumbing -------------------------------------------

    async def _encryption(self, given=None):
        """``(client_encryption, we_own_it)``.

        Callers that make many calls pass one in and close it themselves;
        callers that make one get a short-lived one closed on the way out.
        Returning ownership rather than assuming it is what keeps
        ``shred()`` from leaking a handle per erasure request.
        """
        if given is not None:
            return given, False
        return await self.encryption(), True

    async def encryption(self):
        """A ``ClientEncryption`` bound to this vault."""
        from bson.binary import STANDARD
        from bson.codec_options import CodecOptions
        from pymongo.asynchronous.encryption import AsyncClientEncryption

        return AsyncClientEncryption(
            self.kms_providers, self.namespace, self.db.client,
            CodecOptions(uuid_representation=STANDARD),
            kms_tls_options=self.custody.tls_options())

    def schema_map(self) -> dict:
        """The automatic-encryption schema for the ``Sealed`` collections.

        ``keyId`` is a **JSON pointer** rather than a key id, which is the
        whole reason per-scope crypto-shredding is possible. A literal id
        binds one key to the collection, so destroying it erases every
        tenant at once -- one subject's erasure request taking out
        everybody else's data is not a feature.
        """
        return {
            f"{self.db.name}.{coll}": {
                "bsonType": "object",
                "properties": {
                    name: {"encrypt": {
                        "keyId": f"/{self.spec.pointer_field}",
                        "bsonType": mode.bson_type,
                        "algorithm": RANDOM}}
                    for name in mode.fields
                },
            }
            for coll, mode in self.spec.sealed_collections().items()
        }

    async def encrypted_fields_map(self, *, encryption=None) -> dict:
        """``encryptedFields`` for the ``Queryable`` collections.

        Each field needs a real key id -- QE rejects a pointer, which is
        the measured constraint behind the whole mode -- so the keys are
        minted here, named after the field they protect. Named rather than
        anonymous because the name is what ``shred()`` is given later, and
        an operator asked to destroy ``people.ssn`` should not have to
        first work out which UUID that is.
        """
        wanted = self.spec.queryable_collections()
        if not wanted:
            return {}
        ce, owned = await self._encryption(encryption)
        try:
            out = {}
            for coll, mode in wanted.items():
                fields = []
                for name in mode.fields:
                    key_id = await self.key_for(f"{coll}.{name}",
                                                encryption=ce)
                    fields.append({
                        "path": name, "bsonType": mode.bson_type,
                        "keyId": key_id,
                        "queries": {"queryType": mode.query_type}})
                out[f"{self.db.name}.{coll}"] = {"fields": fields}
            return out
        finally:
            if owned:
                await ce.close()

    async def client_options(self, *, encryption=None) -> Any:
        """``AutoEncryptionOpts`` for the client that does the writing.

        Automatic encryption needs its own ``MongoClient`` and cannot be
        retrofitted onto one that exists, so this is handed to the
        application to construct with rather than switched on behind its
        back -- doing that quietly would change what every write in the
        process does.
        """
        from pymongo.encryption_options import AutoEncryptionOpts

        extra: dict[str, Any] = {}
        path = crypt_shared_path()
        if path:
            extra["crypt_shared_lib_path"] = path
        if self.custody.tls_options():
            extra["kms_tls_options"] = self.custody.tls_options()
        schema = self.schema_map()
        if schema:
            extra["schema_map"] = schema
        qe = await self.encrypted_fields_map(encryption=encryption)
        if qe:
            extra["encrypted_fields_map"] = qe
        return AutoEncryptionOpts(self.kms_providers, self.namespace, **extra)

    async def writer(self, collection: str):
        """The encrypting collection handle. One, owned here, built once.

        This is the piece that decides whether the whole thing is usable.
        Automatic encryption needs its own ``MongoClient`` and cannot be
        retrofitted onto one that exists -- so the naive shape is "the
        caller builds a second client and remembers which is which", and
        the failure mode of forgetting is a plaintext write that nobody
        notices until it is in a backup.

        So the keyring owns exactly one encrypting client and hands out
        collections from it. The caller never holds two clients and never
        chooses between them. (The writer that genuinely bypasses this --
        a shell, a migration, another service -- is refused by the server;
        see ``validator()``. Convenience closes the common case, the
        validator closes the rest.)

        Built lazily rather than at construction because it needs the QE
        field keys, which need a round trip, which an ``__init__`` should
        not be doing.
        """
        if self._writer is None:
            from pymongo import AsyncMongoClient
            self._writer = AsyncMongoClient(
                self._uri, auto_encryption_opts=await self.client_options())
            log.debug("keyring %s opened its encrypting client",
                      self.namespace)
        return self._writer[self.db.name][collection]

    async def aclose(self) -> None:
        """Release the encrypting client, if one was opened."""
        if self._writer is not None:
            await self._writer.close()
            self._writer = None

    async def create_queryable(self, client, collection: str, *,
                               encryption=None):
        """Create a QE collection, which cannot be created by inserting.

        Queryable Encryption needs server-side metadata collections
        (``enxcol_.<name>.esc`` and ``.ecoc``) that only
        ``create_encrypted_collection`` makes. Writing to a QE namespace
        that was never created this way does not fail loudly -- it writes
        plaintext -- which is exactly the silent, permanent, already-in-a-
        backup mistake the automatic path exists to prevent.
        """
        mode = self.spec.protect.get(collection)
        if not isinstance(mode, Queryable):
            raise ValueError(
                f"{collection} is not declared Queryable in this keyring; "
                f"declared: {sorted(self.spec.protect)}")
        ce, owned = await self._encryption(encryption)
        try:
            fields = (await self.encrypted_fields_map(encryption=ce))[
                f"{self.db.name}.{collection}"]
            coll, _ = await ce.create_encrypted_collection(
                client[self.db.name], collection, fields,
                self.custody.provider, self.custody.master_key())
            log.info("created queryable collection %s.%s (%s)",
                     self.db.name, collection,
                     ", ".join(f["path"] for f in fields["fields"]))
            return coll
        finally:
            if owned:
                await ce.close()

    def validator(self, collection: str) -> dict | None:
        """A ``$jsonSchema`` the *server* enforces: these fields are binary.

        The one piece that turns encryption from a convention into a
        guarantee, and it is worth being exact about which failure it
        closes.

        Automatic encryption protects every writer that goes through the
        encrypting client. It does nothing about a writer that does not --
        a migration script, a shell, a second service, the same application
        holding the plain client by accident. That write **succeeds**, and
        stores plaintext, and nothing raises. It is the worst failure
        available here: silent, permanent, and already in a backup before
        anybody could notice.

        Measured, because it is the whole argument:

            plain client, plaintext string  -> WriteError (rejected)
            encrypting client, same call    -> stored, subtype 6

        So the collection carries a validator requiring the sealed fields to
        be ``binData``. The driver encrypts client-side, so what reaches the
        server is already binary and passes; a plaintext write is refused by
        MongoDB, not by a code review. That is the same move as
        ``Admission`` having no unfiltered ``find``, one layer down: the
        unsafe thing is not discouraged, it is unavailable.
        """
        mode = self.spec.protect.get(collection)
        if not isinstance(mode, Sealed):
            # Queryable Encryption already refuses a plaintext write to a QE
            # namespace at the server, so a second validator would only be
            # another thing to keep in step with the first.
            return None
        return {"$jsonSchema": {
            "bsonType": "object",
            "properties": {f: {
                "bsonType": "binData",
                "description": (f"{f} is sealed: it must arrive already "
                                f"encrypted. A plaintext write here is a "
                                f"writer that bypassed the encrypting "
                                f"client.")}
                for f in mode.fields},
        }}

    async def enforce(self, collection: str) -> bool:
        """Apply the validator, creating the collection if it is new.

        ``collMod`` on a collection that does not exist yet is an error, and
        a first boot is exactly when it does not exist -- so the ordering is
        create-then-modify rather than one or the other, and both paths
        converge on the same validator.
        """
        rule = self.validator(collection)
        if rule is None:
            return False
        try:
            await self.db.create_collection(collection, validator=rule,
                                            validationLevel="strict",
                                            validationAction="error")
        except CollectionInvalid:
            await self.db.command({"collMod": collection, "validator": rule,
                                   "validationLevel": "strict",
                                   "validationAction": "error"})
        log.info("sealed %s.%s: the server now rejects a plaintext write to "
                 "%s", self.db.name, collection,
                 ", ".join(self.spec.protect[collection].fields))
        return True

    def describe(self) -> dict:
        ok, why = available()
        sealed = self.spec.sealed_collections()
        qe = self.spec.queryable_collections()
        return {
            "vault": self.namespace,
            "automatic": ok,
            "detail": why,
            "custody": self.custody.describe(),
            "sealed": {c: list(m.fields) for c, m in sealed.items()},
            "queryable": {c: list(m.fields) for c, m in qe.items()},
            # Said out loud rather than left to be inferred, because it is
            # the tradeoff people misremember: QE buys a searchable
            # ciphertext and costs per-subject erasure.
            "shred_granularity": ({"sealed": "scope"} if sealed else {}) |
                                 ({"queryable": "collection"} if qe else {}),
        }


@dataclass(frozen=True)
class _Declared(Custody):
    """Custody supplied as a raw ``kms_providers`` dict.

    Supported because the driver's vocabulary is the real interface, and
    reported as *unknown* rather than assumed safe: this object cannot tell
    whether the key behind a dict is in an HSM or in a variable two frames
    up, so it declines to claim either.
    """

    raw: dict = field(default_factory=dict)
    durable: bool = False
    audited: bool = False

    @property
    def provider(self) -> str:  # type: ignore[override]
        return next(iter(self.raw), "local")

    def credentials(self) -> dict:
        return self.raw.get(self.provider, {})

    def providers(self) -> dict:
        return dict(self.raw)

    def detail(self) -> str:
        return f"a caller-supplied {self.provider!r} provider dict"

    def warn_if_weak(self, where: str) -> None:
        log.warning(
            "%s: custody was supplied as a raw kms_providers dict, so this "
            "process cannot report where the master key lives or who may "
            "destroy it. Use custody=Aws(...)/LocalFile(...) to make that "
            "answerable.", where)
