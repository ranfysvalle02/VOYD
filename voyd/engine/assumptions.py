"""What this code believes about systems it does not control.

Every other guard in this repository checks an *intrinsic* property: the
import graph does not invert, the export list was agreed to, no symbol is
orphaned, no document names a file that was deleted. All decidable from the
tree alone, offline, forever. That is why they work, and it is also the blind
spot -- because the bugs that actually shipped were none of those.

Four, found in one afternoon:

- a version floor for an aggregation stage, hardcoded one minor release too
  high, silently demoting every deployment on the lower version to a worse
  retrieval tier;
- a mechanism that destroys derived encodings on erasure, reaching for a
  field that a server-side embedding feature had moved out of the document;
- two declarations, each individually valid, that became a contradiction when
  the server learned to embed;
- an embedding model default that went two generations stale.

Not one is a logic error. Every one is an **assertion about the outside
world, encoded in the source, with no expiry and no owner.** The suite had
nothing to say because there was nothing to say it about.

Which is this repository's own complaint, turned around. *A guarantee that
must be remembered is not enforced, it is suggested.* A fact about software
this package does not ship, which must be remembered, is not verified -- it
is folklore.

----

**Two kinds, and the split is the whole design.**

``probeable``   a fact about the live deployment -- does this stage exist, is
                this capability present. The rule is absolute: **probe it,
                never encode it.** ``capabilities.py`` argues this at length,
                having been bitten by inferring Atlas support from a
                connection string, and then hardcoded a version floor three
                lines below the argument. There is no registry entry for a
                probeable fact, because the correct number of them in source
                is zero.

``standing``    a fact that cannot be asked of a running system -- a vendor's
                model lineup, an error string, a format constant. These are
                registered here.

----

**On the date that was not good enough.**

The first version of this file had every entry carry ``checked: date`` -- the
day a human last confirmed it -- and a test that failed the build six months
later. It had a hole big enough to make the whole file decorative, and the
docstring admitted it rather than fixing it:

    moving the date without re-reading the source is available, and is the
    one thing that makes this file worthless.

That is not a caveat. A self-attested date is *exactly* the artifact this
repository refuses everywhere else. ``ledger.py`` spends forty lines
explaining that the party holding the log is the party being audited;
``perimeter.py`` will not claim a cache forgot anything merely because it was
told to. Then this file asked a human to type a date attesting to an action
nobody witnessed, and believed it.

So the date is **gone from the source**. It was the wrong primitive: a date
records an action, and actions are unwitnessed. What can be witnessed is
*content*, so an assumption now carries a ``Check`` -- a URL and the
substrings that must and must not appear in it -- and the verification record
lives in ``assumptions.lock.json`` beside this file, written by the verifier
and never by hand.

Three properties follow, and the third is the one that closes the hole:

1. **The claim is re-establishable by a stranger.** ``Check`` is runnable.
   "model X is the recommendation" stops being a memory and becomes a
   fetch and two substring tests, which anyone can repeat.
2. **Staleness is measured from the machine's record**, not from a number a
   human typed, so there is no date in source to bump.
3. **The record is bound to the claim it verified.** Each entry stores the
   fingerprint of the claim text *and* the check that was run. Edit either
   one and the record stops matching, and the build fails until the check is
   re-run. You cannot change what you believe and keep the old attestation --
   which the date version could not even detect.

**What this still does not achieve, stated plainly.** It is not unforgeable.
Somebody can hand-edit ``assumptions.lock.json``. What changes is the
*character* of that act: it is no longer the silent default -- editing one
integer in a source file nobody reads closely -- but a deliberate edit to a
machine-written artifact, containing a content digest that would have to be
fabricated, arriving in a diff that says so. That is the same ceiling
``ledger.py`` reaches and names: a chain is only as strong as the most recent
hash somebody else is holding. Make forgery visible, and stop pretending the
remaining gap is closed.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

log = logging.getLogger("engine.assumptions")

# How long a verification stands before the build asks for a fresh one.
# Six months: long enough not to be a chore, short enough that a generation
# of embedding models cannot pass unnoticed -- which is what happened.
SHELF_LIFE = timedelta(days=180)

# Written by ``verify``, read by everything else, hand-edited by nobody.
RECORD = Path(__file__).with_name("assumptions.lock.json")


@dataclass(frozen=True)
class Check:
    """How a stranger re-establishes a claim, without trusting anybody.

    Deliberately crude -- fetch a document, assert some substrings are
    present and some are absent. A richer predicate would be a scraper, and
    a scraper breaks when a page is restyled, which trains people to ignore
    the failure. Substrings break when the *words* change, which is roughly
    when the claim needs re-reading.

    ``absent`` is the half that catches the failure this mechanism exists
    for. Asserting that a model still appears on a vendor's page stays true
    for years after it stops being the recommendation, so a check built only
    from ``present`` passes forever. Naming the words whose *arrival* would
    falsify the claim -- a successor's name, a deprecation notice -- is what
    actually expires.
    """

    url: str
    present: tuple[str, ...] = ()
    absent: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.url.startswith("http"):
            raise ValueError(
                f"a check needs a fetchable url, got {self.url!r}. An "
                f"assumption whose evidence cannot be retrieved is a "
                f"memory with a dataclass around it")
        if not (self.present or self.absent):
            raise ValueError(
                f"{self.url}: a check that asserts nothing passes forever. "
                f"Name the substrings that must appear, or the ones that "
                f"must not")

    def evaluate(self, text: str) -> tuple[bool, list[str]]:
        """Returns (ok, complaints). Never raises: a check is not a rule."""
        body = text.lower()
        complaints = [f"missing {s!r}" for s in self.present
                      if s.lower() not in body]
        complaints += [f"found {s!r}" for s in self.absent
                       if s.lower() in body]
        return not complaints, complaints

    def fingerprint(self) -> str:
        return _digest({"url": self.url,
                        "present": sorted(self.present),
                        "absent": sorted(self.absent)})


@dataclass(frozen=True)
class Assumption:
    """One thing this code believes about a system it does not control."""

    name: str
    # The belief, as a sentence with a truth value. Not "the embedding
    # models" but "model X is the current recommendation": a claim is
    # falsifiable and a topic is not.
    claim: str
    # Why this is not a probe. The field that keeps the registry from
    # becoming a place to put things instead of checking them: an assumption
    # that *could* be probed and is not is a bug waiting for somebody else's
    # next release.
    why_not_probed: str
    # What breaks when it turns out to be false. The blast radius decides
    # whether a stale entry is a chore or an incident, and nobody wants to
    # establish that during the incident.
    breaks: str
    # How a stranger re-establishes it. Required: an assumption with no
    # runnable check is the self-attested date this file was rewritten to
    # remove.
    check: Check

    def __post_init__(self) -> None:
        for field_name in ("name", "claim", "why_not_probed", "breaks"):
            if not str(getattr(self, field_name, "")).strip():
                raise ValueError(
                    f"an assumption needs a non-empty {field_name}. The "
                    f"fields are the mechanism: an entry that cannot say "
                    f"what it believes, why it is not probed, and what "
                    f"breaks is a comment with a dataclass around it")

    def fingerprint(self) -> str:
        """Binds a verification record to the exact claim it verified.

        The property the date version could not have. If somebody edits the
        claim -- widens it, softens it, changes which model it names -- the
        fingerprint moves, the stored record stops matching, and the build
        asks for a fresh check. Re-verification is therefore required by
        *changing your mind*, not only by the passage of time.
        """
        return _digest({"claim": self.claim, "check": self.check.fingerprint()})


def _digest(body: dict) -> str:
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=False).encode("utf-8")).hexdigest()


# ---- the registry ------------------------------------------------------
#
# Standing assumptions only. A fact that can be asked of a running
# deployment belongs in ``capabilities.detect``, which probes every one of
# them and is where a new one goes.
#
# Note what is *not* here: anything naming an embedding vendor. This package
# is a database library, and the standalone test fails the build if a vendor
# appears anywhere in its source -- so vendor-facing beliefs are declared by
# the layer that chose the vendor, in the application package's own
# registry, and one test checks both. The split follows the
# engine/application boundary rather than carving an exception into it.

WORLD: tuple[Assumption, ...] = (
    Assumption(
        name="search.automated_embedding_requirements",
        claim="Server-side automated embedding on a self-managed deployment "
              "requires mongot 1.70.1 or later and MongoDB 8.3 or later, and "
              "calls a remote endpoint rather than downloading a model.",
        why_not_probed="ensure() probes the *outcome* -- it attempts the "
                       "autoEmbed index and falls back loudly when the "
                       "deployment rejects it. What cannot be probed is the "
                       "requirement itself, which is what an operator needs "
                       "before they build the cluster.",
        breaks="A deployment is built to the wrong floor and the autoEmbed "
               "index silently falls back to client-side embedding, which "
               "is correct and is not what was paid for.",
        check=Check(
            url="https://www.mongodb.com/docs/search/self-managed/current/"
                "configuration/automated-embedding/",
            present=("mongot", "embedding"),
        ),
    ),
    Assumption(
        name="search.rank_fusion_is_probed_not_versioned",
        claim="$rankFusion is available from MongoDB 8.0, which is why this "
              "package probes the stage instead of comparing a version.",
        why_not_probed="The capability *is* probed -- see "
                       "capabilities._supports_rank_fusion. What is "
                       "registered here is the documentation that made the "
                       "old hardcoded floor of 8.1 wrong, so that anybody "
                       "tempted to reintroduce one finds the evidence "
                       "first.",
        breaks="Nothing at runtime: the probe does not consult this. It is "
               "a tombstone for a bug, and it goes stale if the stage's "
               "availability story changes under it.",
        check=Check(
            url="https://www.mongodb.com/docs/manual/reference/operator/"
                "aggregation/rankFusion/",
            present=("$rankfusion", "8.0"),
        ),
    ),
)


# ---- the verification record -------------------------------------------

def load_record(path: Path | None = None) -> dict:
    """The machine's notes. Missing is a legitimate state and says so."""
    path = path or RECORD
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        log.warning("assumption record at %s is unreadable", path)
        return {}


def status(assumptions, record: dict, *, now: datetime | None = None) -> list[dict]:
    """What is known about each belief, and how stale the knowledge is.

    Four states, and they are deliberately not collapsed into a boolean:

    ``unverified``  no record. Not the same as failing, and not the same as
                    passing -- it is the state a fresh checkout is in, and
                    reporting it as either would be a lie in one direction.
    ``changed``     a record exists for this name, but the fingerprint does
                    not match. Somebody edited the claim or the check after
                    it was verified.
    ``failed``      the check ran and disagreed with the claim.
    ``verified``    the check ran and agreed, with an age beside it.
    """
    now = now or datetime.now(timezone.utc)
    out = []
    for assumption in assumptions:
        entry = record.get(assumption.name)
        row = {"name": assumption.name, "claim": assumption.claim,
               "url": assumption.check.url}
        if entry is None:
            out.append({**row, "state": "unverified", "age_days": None})
            continue
        if entry.get("fingerprint") != assumption.fingerprint():
            out.append({**row, "state": "changed", "age_days": None})
            continue
        at = datetime.fromisoformat(entry["verified_at"])
        age = now - at
        out.append({**row,
                    "state": "verified" if entry.get("ok") else "failed",
                    "verified_at": entry["verified_at"],
                    "age_days": age.days,
                    "stale": age > SHELF_LIFE,
                    "evidence": entry.get("evidence"),
                    "complaints": entry.get("complaints") or []})
    return out


def unsettled(assumptions, record: dict, *,
              now: datetime | None = None) -> list[dict]:
    """Everything a build should stop for: unverified, changed, failed, stale."""
    return [row for row in status(assumptions, record, now=now)
            if row["state"] != "verified" or row.get("stale")]


def report_assumptions(assumptions=WORLD, record: dict | None = None) -> dict:
    """What ``health()`` says about the beliefs behind its own answers.

    Reported even when everything is fine, for the reason
    ``Perimeter.describe()`` prints sealed claims nobody has verified: a
    deployment whose assumptions are fresh and one whose assumptions have
    never been checked look identical unless the absence is printed.
    """
    record = load_record() if record is None else record
    rows = status(assumptions, record)
    return {
        "shelf_life_days": SHELF_LIFE.days,
        "declared": len(rows),
        "unsettled": [r["name"] for r in rows
                      if r["state"] != "verified" or r.get("stale")],
        "entries": rows,
    }


# ---- running the checks ------------------------------------------------

def verify(assumptions, *, fetch, now: datetime | None = None) -> dict:
    """Run every check and return a record. Network lives in ``fetch``.

    Injected rather than imported so this stays testable without a network
    and without a mocking library: the caller supplies ``fetch(url) -> str``,
    and the CLI below is the only thing that hands over one that reaches the
    internet. A verifier that could only be exercised against the live web
    would be a verifier nobody runs in CI.

    ``evidence`` is a digest of the fetched text, not the text. Storing the
    page would put somebody else's documentation in this repository, and the
    digest is enough to answer the question a record needs to answer: *is
    this the same document the claim was checked against?*
    """
    now = now or datetime.now(timezone.utc)
    record: dict = {}
    for assumption in assumptions:
        try:
            text = fetch(assumption.check.url)
            ok, complaints = assumption.check.evaluate(text)
            evidence = _digest({"text": text})
        except Exception as exc:  # noqa: BLE001 - a fetch failure is a result
            ok, complaints, evidence = False, [f"fetch failed: {exc}"], None
        record[assumption.name] = {
            "fingerprint": assumption.fingerprint(),
            "verified_at": now.isoformat(),
            "ok": ok,
            "complaints": complaints,
            "evidence": evidence,
        }
        log.info("assumption %s: %s", assumption.name,
                 "ok" if ok else f"FAILED ({'; '.join(complaints)})")
    return record
