"""Who holds the key that protects the key. The whole claim rests here.

Crypto-shredding says: destroy the data key, and every copy of the ciphertext
becomes unreadable at once -- the row, the replica, the snapshot, the backup
nobody has restored. That claim is exactly as strong as the answer to one
question, which is the question a crypto claim usually skates past:

    where does the key that encrypts the data keys live, and who can destroy
    it *without asking you*?

A data key sits in a MongoDB collection, wrapped by a customer master key
held by a KMS. Wrapped is the operative word. Deleting the DEK document is a
storage event in your database. Destroying the CMK is an event in somebody
else's audited system, and it takes every DEK ever wrapped by it with it,
including the ones in backups you no longer control.

So this module makes custody a **declared, typed thing** rather than a dict
somebody assembles at a call site. Two reasons, and the second is the real
one:

- ``create_data_key`` needs a provider *name* and a provider-specific
  ``master_key`` document, and getting either wrong is not a crash. With
  AWS it is a permissions error at 3am; with ``local`` it is a silent
  downgrade to a master key that lives in the process that just started.
- An audit answer is a property of a deployment, and a deployment should be
  able to *print* it. ``describe()`` says which KMS, which key, and -- when
  the answer is "this process, in memory" -- says that too, in the same
  sentence, rather than leaving it to be inferred from an absence.

**The ladder, and it is a ladder on purpose.** A proof of concept must not
require an AWS account, and a production deployment must not accidentally
inherit a proof of concept's custody. So:

    Ephemeral()   a master key generated per process. Nothing survives a
                  restart -- including the data. Correct for a demo and
                  loudly wrong for anything else.
    LocalFile()   a master key in a file you manage. Real crypto, real
                  shredding, custody that is a filesystem permission.
                  Honest for single-node and for CI.
    Aws/Azure/Gcp/Kmip()
                  the CMK is in a KMS. Destroying it is somebody else's
                  audited operation, which is the only version of this an
                  auditor accepts.

**Two different destructions, and conflating them misstates the timing.**
Per-scope erasure here deletes a **data key** -- a document in your own key
vault -- and that is immediate. Destroying the **master key** is the
nuclear option that takes every data key it ever wrapped with it, and on a
real KMS it is *not* an immediate operation: AWS enforces a pending window
on ``ScheduleKeyDeletion`` of **7 days minimum, 30 by default**, and Azure
and GCP have their own soft-delete and destroy-scheduled periods.

That does not weaken the claim, because the claim rests on the data key.
But a project whose entire argument is about erasure *timing* has no
business being vague here: "shred the scope" is seconds, "destroy the
master key" is a week, and a compliance answer that cites the second while
meaning the first is wrong in the direction that gets noticed.

Every rung has the same code path -- the difference is a provider name and a
master key document -- and the point of typing them is that *choosing* is
deliberate rather than defaulted into.
"""

from __future__ import annotations

import base64
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger("engine.custody")

# libmongocrypt's local provider takes a 96-byte key: 32 for signing, 32 for
# encryption, 32 reserved. Not a number to round.
LOCAL_KEY_BYTES = 96


class Custody:
    """Where the customer master key lives.

    Three things every rung must answer, and nothing else -- the driver does
    the rest and a wrapper that hid the driver's vocabulary would just be a
    second thing to keep current:

    ``provider``    the ``kms_providers`` key: local, aws, azure, gcp, kmip.
    ``credentials`` what goes under that key.
    ``master_key``  which CMK to wrap new data keys with. ``None`` for local,
                    required and provider-shaped for everything else.
    """

    provider: str = "local"
    audited: bool = False       # can somebody other than this process destroy it?
    durable: bool = False       # does the key survive a restart?

    def credentials(self) -> dict:
        raise NotImplementedError

    def master_key(self) -> dict | None:
        return None

    def tls_options(self) -> dict | None:
        return None

    def providers(self) -> dict:
        return {self.provider: self.credentials()}

    def describe(self) -> dict:
        return {"provider": self.provider, "durable": self.durable,
                "audited": self.audited, "detail": self.detail()}

    def detail(self) -> str:
        return self.provider

    def warn_if_weak(self, where: str) -> None:
        """Say the quiet part at startup, once, where an operator sees it.

        A weak custody choice is not an error -- demos are legitimate -- but
        it must not be *silent*, because the failure it produces is a
        confident claim in a compliance document.
        """
        if not self.durable:
            log.warning(
                "%s: master key is %s. It is regenerated on restart, so every "
                "data key wrapped by it becomes unreadable and so does every "
                "document those keys protected. Correct for a demo; use "
                "LocalFile() or a KMS for anything you intend to read twice.",
                where, self.detail())
        elif not self.audited:
            log.warning(
                "%s: master key is %s. The mechanism is real -- shredding a "
                "data key really does make its ciphertext unreadable -- but "
                "custody is a file permission on this host, so 'the key was "
                "destroyed' is your word for it. A KMS makes it somebody "
                "else's audited operation.", where, self.detail())


@dataclass(frozen=True)
class Ephemeral(Custody):
    """A master key generated for this process. Nothing survives a restart.

    The default, deliberately, and deliberately the weakest rung: a default
    that quietly worked in production would be worse than one that visibly
    does not. Encryption is real here and so is shredding -- what is absent
    is durability, so this is the shape for a demo, a test, and the first
    ten minutes of a proof of concept.
    """

    provider: str = "local"
    audited: bool = False
    durable: bool = False
    key: bytes = field(default_factory=lambda: os.urandom(LOCAL_KEY_BYTES),
                       repr=False)

    def credentials(self) -> dict:
        return {"key": self.key}

    def detail(self) -> str:
        return "generated per process, held in memory"


@dataclass(frozen=True)
class LocalFile(Custody):
    """A master key in a file you manage. Real, durable, unaudited.

    The rung most proofs of concept should actually be on: shredding works,
    a restart keeps the data, and custody is a filesystem permission --
    which is a real answer, just not one an auditor will accept on its own.

    Created on first use with ``0600`` if absent, because the alternative is
    a README step that half of readers skip and then discover as an
    ``Ephemeral`` deployment three weeks later.
    """

    path: str | os.PathLike = "master.key"
    provider: str = "local"
    audited: bool = False
    durable: bool = True

    def credentials(self) -> dict:
        return {"key": self._material()}

    def _material(self) -> bytes:
        p = Path(self.path).expanduser()
        if p.exists():
            raw = p.read_bytes()
            # Raw bytes first, and **never stripped**. A master key is 96
            # bytes of entropy, so ~4.8% of them begin or end with a byte
            # that ``bytes.strip()`` treats as whitespace -- measured, not
            # estimated. Stripping first made one file in twenty read back
            # short and unusable, which presents as a deployment that can
            # no longer decrypt anything it wrote, intermittently, with no
            # cause visible at the point of failure.
            if len(raw) == LOCAL_KEY_BYTES:
                return raw
            # Only then as text: a key that has been through a shell, an
            # env var or a secrets manager arrives base64-shaped, and
            # *that* is worth stripping, because the whitespace around it
            # is punctuation rather than key material.
            try:
                decoded = base64.b64decode(raw.strip(), validate=True)
                if len(decoded) == LOCAL_KEY_BYTES:
                    return decoded
            except Exception:  # noqa: BLE001 - not base64 is a normal answer
                pass
            raise ValueError(
                f"{p} holds {len(raw)} bytes; a local master key is exactly "
                f"{LOCAL_KEY_BYTES} raw bytes or its base64. Refusing to "
                f"guess: a wrong key is not an error, it is every document "
                f"becoming unreadable")
        material = os.urandom(LOCAL_KEY_BYTES)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.touch(mode=0o600)
        p.write_bytes(material)
        log.warning("created a new master key at %s (0600). Back it up: "
                    "losing it is indistinguishable from shredding every "
                    "key in the vault.", p)
        return material

    def detail(self) -> str:
        return f"a file at {self.path}"


@dataclass(frozen=True)
class Aws(Custody):
    """An AWS KMS customer master key.

    ``key`` is the CMK ARN, and ``region`` is taken from it when it is an ARN
    so the two cannot disagree -- a mismatch there is an
    ``InvalidArnException`` several layers down from the line that caused it.

    Credentials are deliberately optional: omitting them selects the driver's
    *automatic* credential lookup, which is how this should run in EKS or on
    an instance profile. Baking an access key into a config file to encrypt
    something is a net loss.

    **Unverified against a live KMS.** The provider name and master-key
    shape are unit-tested and match the driver's documented contract, and
    the code path is shared with the local rung -- but "constructs the
    right document" and "works against AWS" are different claims and only
    the first is proven here. The on-demand credential path in particular
    may need a package this project does not declare. See ``docs/ISSUES.md``.
    """

    key: str = ""
    region: str = ""
    access_key_id: str | None = None
    secret_access_key: str | None = None
    session_token: str | None = None
    endpoint: str | None = None
    provider: str = "aws"
    audited: bool = True
    durable: bool = True

    def credentials(self) -> dict:
        if self.access_key_id is None:
            # Empty dict = "use the AWS credential chain". Not the same as
            # omitting the provider, which would make the KMS unreachable.
            return {}
        creds = {"accessKeyId": self.access_key_id,
                 "secretAccessKey": self.secret_access_key}
        if self.session_token:
            creds["sessionToken"] = self.session_token
        return creds

    def master_key(self) -> dict:
        region = self.region or _region_of(self.key)
        if not (self.key and region):
            raise ValueError(
                "Aws custody needs a CMK ARN (and a region, unless the ARN "
                "carries one): Aws(key='arn:aws:kms:us-east-1:...:key/...')")
        mk: dict[str, Any] = {"region": region, "key": self.key}
        if self.endpoint:
            mk["endpoint"] = self.endpoint
        return mk

    def detail(self) -> str:
        return f"AWS KMS {self.key or '<unset>'}"


def _region_of(arn: str) -> str:
    parts = arn.split(":")
    return parts[3] if len(parts) > 4 and arn.startswith("arn:") else ""


@dataclass(frozen=True)
class Azure(Custody):
    """An Azure Key Vault key."""

    key_name: str = ""
    key_vault_endpoint: str = ""
    tenant_id: str = ""
    client_id: str = ""
    client_secret: str = field(default="", repr=False)
    key_version: str | None = None
    provider: str = "azure"
    audited: bool = True
    durable: bool = True

    def credentials(self) -> dict:
        return {"tenantId": self.tenant_id, "clientId": self.client_id,
                "clientSecret": self.client_secret}

    def master_key(self) -> dict:
        if not (self.key_name and self.key_vault_endpoint):
            raise ValueError("Azure custody needs key_name and "
                             "key_vault_endpoint")
        mk = {"keyName": self.key_name,
              "keyVaultEndpoint": self.key_vault_endpoint}
        if self.key_version:
            mk["keyVersion"] = self.key_version
        return mk

    def detail(self) -> str:
        return f"Azure Key Vault {self.key_vault_endpoint}/{self.key_name}"


@dataclass(frozen=True)
class Gcp(Custody):
    """A Google Cloud KMS key."""

    project_id: str = ""
    location: str = ""
    key_ring: str = ""
    key_name: str = ""
    email: str | None = None
    private_key: str | None = field(default=None, repr=False)
    key_version: str | None = None
    provider: str = "gcp"
    audited: bool = True
    durable: bool = True

    def credentials(self) -> dict:
        if self.email is None:
            return {}          # Application Default Credentials
        return {"email": self.email, "privateKey": self.private_key}

    def master_key(self) -> dict:
        missing = [n for n in ("project_id", "location", "key_ring", "key_name")
                   if not getattr(self, n)]
        if missing:
            raise ValueError(f"Gcp custody needs {', '.join(missing)}")
        mk = {"projectId": self.project_id, "location": self.location,
              "keyRing": self.key_ring, "keyName": self.key_name}
        if self.key_version:
            mk["keyVersion"] = self.key_version
        return mk

    def detail(self) -> str:
        return (f"GCP KMS {self.project_id}/{self.location}/"
                f"{self.key_ring}/{self.key_name}")


@dataclass(frozen=True)
class Kmip(Custody):
    """A KMIP server -- Thales, Fortanix, HashiCorp, an HSM appliance.

    The rung that matters for deployments whose whole reason for encrypting
    is that the key must not be in a public cloud.
    """

    endpoint: str = ""
    key_id: str | None = None
    tls: dict | None = None
    provider: str = "kmip"
    audited: bool = True
    durable: bool = True

    def credentials(self) -> dict:
        if not self.endpoint:
            raise ValueError("Kmip custody needs endpoint='host:port'")
        return {"endpoint": self.endpoint}

    def master_key(self) -> dict:
        # No keyId asks the KMIP server to generate and own a new one, which
        # is the shape most appliances expect.
        return {"keyId": self.key_id} if self.key_id else {}

    def tls_options(self) -> dict | None:
        return {"kmip": self.tls} if self.tls else None

    def detail(self) -> str:
        return f"KMIP {self.endpoint}"


def from_env(prefix: str) -> Custody:
    """Custody from the environment, for deployments configured that way.

    ``<prefix>_PROVIDER`` selects the rung; the rest are read per provider.
    The prefix is a required argument rather than a default, because this
    module is the generic engine and the application owns its own
    namespace -- a library that claimed ``KMS_PROVIDER`` for itself would
    be squatting on every other library's configuration.

    Falls back to ``Ephemeral`` and says so. An unset environment is a demo,
    and a demo that silently claimed to be audited is the worst outcome
    available here.
    """
    provider = os.environ.get(f"{prefix}_PROVIDER", "").lower()
    get = lambda n: os.environ.get(f"{prefix}_{n}")  # noqa: E731
    if provider == "aws":
        return Aws(key=get("KEY") or "", region=get("REGION") or "",
                   access_key_id=get("ACCESS_KEY_ID"),
                   secret_access_key=get("SECRET_ACCESS_KEY"),
                   session_token=get("SESSION_TOKEN"))
    if provider == "azure":
        return Azure(key_name=get("KEY_NAME") or "",
                     key_vault_endpoint=get("VAULT_ENDPOINT") or "",
                     tenant_id=get("TENANT_ID") or "",
                     client_id=get("CLIENT_ID") or "",
                     client_secret=get("CLIENT_SECRET") or "")
    if provider == "gcp":
        return Gcp(project_id=get("PROJECT_ID") or "",
                   location=get("LOCATION") or "",
                   key_ring=get("KEY_RING") or "",
                   key_name=get("KEY_NAME") or "",
                   email=get("EMAIL"), private_key=get("PRIVATE_KEY"))
    if provider == "kmip":
        return Kmip(endpoint=get("ENDPOINT") or "", key_id=get("KEY_ID"))
    if provider == "local":
        path = get("KEY_PATH")
        return LocalFile(path=path) if path else Ephemeral()
    log.info("%s_PROVIDER is unset; using ephemeral custody (demo-grade)",
             prefix)
    return Ephemeral()
