"""A plan somebody can still believe next year.

A plan printed to a terminal answers a question once, for whoever was
watching. An auditor asks a different question -- *what did the check say
at the moment that change merged, and has anyone edited it since?* -- and
a log line cannot answer it.

So a plan can be written out as an envelope: the result, the SHA-256 of
each policy file it compared, when it ran, what ran it, and a signature
over the whole thing.

**What this proves, exactly.** The signature proves the envelope has not
changed since something holding the key produced it. Combined with the
policy digests, that ties a verdict to the exact bytes of the two files
it was a verdict about -- so a policy edited after the check passed no
longer matches its own attestation, and `verify` says so by name.

**What it does not prove, and the list is the point.** It does not prove
the plan was run against a real cluster, or against production rather
than an empty staging copy, or that the sample was representative, or
that the key stayed secret. It is a symmetric MAC: anyone who can verify
can also forge. That makes it evidence of *integrity*, not of origin, and
this file is not going to let a reader infer the second from the first --
the whole project's complaint is about claims that quietly exceed what
was checked.

Unsigned envelopes are supported and are marked ``signed: false``. They
carry the digest, so `verify` still catches a truncated file or an edited
number, which is a real thing to catch. They catch nothing deliberate.

Pure: no I/O, no clock unless one is handed in, no environment.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any, Mapping

# Bumped when the envelope's shape changes in a way a verifier must know
# about. A version is how an old artifact stays readable instead of
# becoming a parse error somebody deletes.
SCHEMA = 1

UTC = timezone.utc

# The one thing both signer and verifier have to agree on byte for byte.
# Sorted keys and no incidental whitespace, because a signature over
# "whatever json.dumps did on that machine" is a signature that stops
# verifying when somebody upgrades Python.
_CANONICAL: dict[str, Any] = {"sort_keys": True,
                              "separators": (",", ":"),
                              "ensure_ascii": True,
                              "default": str}


def canonical(payload: Mapping) -> bytes:
    """The exact bytes that get signed and hashed."""
    return json.dumps(payload, **_CANONICAL).encode("utf-8")


def digest(data: bytes | str) -> str:
    """SHA-256, hex. Used for policy files and for the payload itself."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def envelope(*, plan: Mapping,
             policies: Mapping[str, str],
             tool: str,
             at: datetime | None = None,
             context: Mapping | None = None) -> dict:
    """Wrap a plan in everything needed to check it later.

    ``policies`` maps a label -- ``current``, ``proposed`` -- to the
    *contents* of that file, not its path. A path is not evidence: it
    names a file that may since have been edited, moved or deleted, and
    the digest is the only part of this that survives the branch being
    thrown away.
    """
    payload = {
        "schema": SCHEMA,
        "tool": tool,
        "at": (at or datetime.now(UTC)).astimezone(UTC).isoformat(),
        "policies": {label: digest(text)
                     for label, text in sorted(policies.items())},
        "context": dict(context or {}),
        "plan": json.loads(json.dumps(plan, **_CANONICAL)),
    }
    return {"payload": payload,
            "payload_sha256": digest(canonical(payload)),
            "signed": False,
            "signature": None}


def sign(doc: Mapping, key: bytes) -> dict:
    """HMAC-SHA256 the payload. Returns a new envelope; never mutates."""
    if not key:
        raise ValueError(
            "sign() needs a key. An empty one would produce a signature "
            "anybody can reproduce, which is worse than no signature "
            "because it looks like one")
    signed = dict(doc)
    signed["signed"] = True
    signed["signature"] = hmac.new(
        key, canonical(doc["payload"]), hashlib.sha256).hexdigest()
    return signed


def verify(doc: Mapping, key: bytes | None = None) -> tuple[bool, str]:
    """Is this envelope intact, and does it say what it appears to say?

    Two checks with different strengths, and the second sentence of the
    return value is where the difference is written down rather than left
    for a reader to assume.

    The digest catches an edited number or a truncated file, and catches
    it without a key. The signature catches an edit by somebody who
    thought to recompute the digest, and needs the key. An envelope that
    was never signed cannot acquire the second property by being verified
    carefully, so a key handed to an unsigned envelope is an error rather
    than a pass.
    """
    for field in ("payload", "payload_sha256"):
        if field not in doc:
            return False, f"not an attestation: no {field!r}"
    payload = doc["payload"]
    if not isinstance(payload, Mapping):
        return False, "payload is not an object"
    if payload.get("schema") != SCHEMA:
        return False, (f"schema {payload.get('schema')!r}, this build "
                       f"verifies {SCHEMA}")
    if digest(canonical(payload)) != doc["payload_sha256"]:
        return False, "payload does not match its digest: it has been edited"
    if key is None:
        if doc.get("signed"):
            return True, ("digest intact; signature present and not "
                          "checked, because no key was supplied")
        return True, "digest intact; unsigned, so nothing deliberate is ruled out"
    if not doc.get("signed") or not doc.get("signature"):
        return False, ("a key was supplied and this envelope is unsigned. "
                       "Verifying it against one would report a pass for a "
                       "document nobody signed")
    expected = hmac.new(key, canonical(payload), hashlib.sha256).hexdigest()
    # Constant time, because the alternative leaks the signature one byte
    # at a time to anyone who can time the verifier.
    if not hmac.compare_digest(expected, str(doc["signature"])):
        return False, "signature does not match: wrong key, or altered"
    return True, "digest and signature both check out"


def policies_match(doc: Mapping, policies: Mapping[str, str]) -> tuple[bool, str]:
    """Do these files still hash to what the attestation was about?

    Separate from ``verify`` on purpose. An intact attestation of a policy
    that has since changed is not a corrupt artifact -- it is a *stale*
    one, which is a different finding and usually a more interesting one.
    """
    recorded = dict(doc.get("payload", {}).get("policies", {}))
    now = {label: digest(text) for label, text in policies.items()}
    if recorded == now:
        return True, "the attested policies are the ones on disk"
    drifted = sorted(label for label in set(recorded) | set(now)
                     if recorded.get(label) != now.get(label))
    return False, ("attested a different version of: " + ", ".join(drifted))
