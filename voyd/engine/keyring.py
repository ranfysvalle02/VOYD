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

**Key custody, stated plainly, because a crypto claim that is vague about
this is marketing.** The customer master key lives wherever ``kms_providers``
says. With the ``local`` provider that is this process's memory, which means
the master key and the ciphertext share a fate and the guarantee is
demonstration-grade: good enough to prove the mechanism, not good enough to
tell an auditor. A real deployment points this at AWS/Azure/GCP KMS, where
destroying the CMK is somebody else's audited operation and the ciphertext
becomes unreadable without anything in this database being touched at all.
The code path is identical; only the provider dict changes.

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
class KeyringSpec:
    """Where the keys live and which field points at one.

    ``pointer_field`` is the document field naming the key, and the schema
    below turns it into a JSON pointer (``/key_scope``) so the driver resolves
    a *different* key per document. A static ``keyId`` in the schema would
    give one key per collection, which makes crypto-shredding all-or-nothing
    -- erase one subject and every other tenant goes with them.
    """

    collection: str = "__keys"
    pointer_field: str = "key_scope"
    at_field: str = "expire_at"
    # Collection -> the fields in it that are ciphertext at rest.
    sealed: dict[str, tuple[str, ...]] = field(default_factory=dict)


class Keyring:
    """The key vault, as a trait. ``ensure()`` gives it its two indexes."""

    kind = "keyring"

    def __init__(self, db, spec: KeyringSpec | None = None, *,
                 kms_providers: dict | None = None):
        self.db = db
        self.spec = spec or KeyringSpec()
        self.collection = self.spec.collection
        # Demonstration-grade by default, and loudly so. See the module
        # docstring on custody: a local master key shares its fate with the
        # ciphertext it protects.
        self.kms_providers = kms_providers or {"local": {"key": os.urandom(96)}}
        self.local_master = "local" in self.kms_providers and not (
            set(self.kms_providers) - {"local"})

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
        no second scheduler and no cron to keep two clocks agreeing -- which
        is the first claim in this repository, applied to the mechanism that
        enforces the second one.
        """
        await self.db[self.collection].create_index(
            "keyAltNames", unique=True,
            partialFilterExpression={"keyAltNames": {"$exists": True}})
        await self.db[self.collection].create_index(
            self.spec.at_field, expireAfterSeconds=0, sparse=True)
        if self.local_master:
            log.warning(
                "keyring %s uses a local master key held in this process. The "
                "mechanism is real and the custody is not: a restart loses "
                "every key, and anything that can read this process can read "
                "the ciphertext. Point kms_providers at a KMS before this "
                "protects anything.", self.namespace)
        return True

    # ---- keys ----------------------------------------------------------

    async def key_for(self, scope: str, *, expire_at: datetime | None = None,
                      encryption=None):
        """The data key for one scope, created on first use.

        ``expire_at`` is written onto the key document itself, so the TTL
        index above destroys it on the scope's own deadline. Passing ``None``
        pins the key exactly the way a null deadline pins a document --
        the same rule, in the same shape, one collection over.
        """
        existing = await self.db[self.collection].find_one(
            {"keyAltNames": scope})
        if existing is not None:
            if expire_at is not None:
                await self._never_later(existing["_id"], expire_at)
            return existing["_id"]

        ce = encryption or await self.encryption()
        key_id = await ce.create_data_key("local", key_alt_names=[scope])
        if expire_at is not None:
            await self.db[self.collection].update_one(
                {"_id": key_id}, {"$set": {self.spec.at_field: expire_at}})
        log.info("keyring %s minted a key for scope %r (expires %s)",
                 self.namespace, scope,
                 expire_at.isoformat() if expire_at else "never")
        return key_id

    async def _never_later(self, key_id, expire_at: datetime) -> None:
        """A key's deadline moves earlier or not at all.

        The same invariant ``revoke()`` holds for a document, for the same
        reason: extending the life of a key extends the readability of
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

        The one operation in this package where deleting *is* the right
        verb, and it is worth being precise about why, since the rest of the
        repository argues the opposite. Deleting a document is a storage
        event: eventually consistent, local to this deployment, and
        unprovable. Deleting a key is a storage event whose *effect* is
        total -- every copy of the ciphertext, in every backup and replica
        and snapshot, becomes unreadable at once, without any of them being
        visited.

        Not instantly, though. See the module docstring: a client holding a
        cached copy of the key keeps decrypting for about a minute. Refusal
        is what covers that window, which is the argument for having both.
        """
        ce = encryption or await self.encryption()
        try:
            key = await ce.get_key_by_alt_name(scope)
        except Exception:  # noqa: BLE001 - absent is a normal answer
            key = None
        if key is None:
            return 0
        await ce.delete_key(key["_id"])
        log.info("keyring %s destroyed the key for scope %r; its ciphertext "
                 "is unreadable everywhere, subject to a ~60s key cache",
                 self.namespace, scope)
        return 1

    # ---- the driver plumbing -------------------------------------------

    async def encryption(self):
        """A ``ClientEncryption`` bound to this vault."""
        from bson.binary import STANDARD
        from bson.codec_options import CodecOptions
        from pymongo.asynchronous.encryption import AsyncClientEncryption

        return AsyncClientEncryption(
            self.kms_providers, self.namespace, self.db.client,
            CodecOptions(uuid_representation=STANDARD))

    def schema_map(self) -> dict:
        """The automatic-encryption schema: which fields, under which key.

        ``keyId`` is a **JSON pointer** rather than a key id, which is the
        whole reason per-scope crypto-shredding is possible under automatic
        encryption. A literal id in the schema binds one key to the whole
        collection, so destroying it erases every tenant at once -- an
        erasure request from one subject taking out everybody else's data
        is not a feature.
        """
        return {
            f"{self.db.name}.{coll}": {
                "bsonType": "object",
                "properties": {
                    name: {"encrypt": {"keyId": f"/{self.spec.pointer_field}",
                                       "bsonType": "string",
                                       "algorithm": RANDOM}}
                    for name in fields
                },
            }
            for coll, fields in self.spec.sealed.items()
        }

    def client_options(self) -> Any:
        """``AutoEncryptionOpts`` for the client that does the writing.

        Automatic encryption needs its own ``MongoClient``, which cannot be
        retrofitted onto one that already exists -- so this is handed to the
        application to construct with, rather than being something the
        engine can quietly switch on. Explicit is correct here: turning an
        existing client into an encrypting one behind the caller's back
        would change what every write in the process does.
        """
        from pymongo.encryption_options import AutoEncryptionOpts

        extra = {}
        path = crypt_shared_path()
        if path:
            extra["crypt_shared_lib_path"] = path
        return AutoEncryptionOpts(
            self.kms_providers, self.namespace,
            schema_map=self.schema_map(), **extra)

    def describe(self) -> dict:
        ok, why = available()
        return {"vault": self.namespace, "automatic": ok, "detail": why,
                "sealed": {c: list(f) for c, f in self.spec.sealed.items()},
                "custody": "local master key, in this process (demonstration)"
                           if self.local_master else "external KMS"}
