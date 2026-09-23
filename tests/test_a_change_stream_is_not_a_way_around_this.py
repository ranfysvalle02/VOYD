"""The quietest hole this boundary had, and why it is refused rather than filtered.

A change stream on a guarded collection *is* matched to its guard --
``cursor.ns`` names the collection, so the events reach the rules. They
are simply not documents. An event is

    {_id: <token>, operationType: "update", ns: {...},
     documentKey: {...}, fullDocument: {the entire document}}

and every rule in this package reads **top-level** fields. There is no
``expire_at`` at the top of that and no ``forgotten``, so a deadline
reads as "no deadline, pinned" and a mark reads as absent. Both admit,
and the whole forgotten document rides out inside ``fullDocument``.

That is the same shape as the ``subjects`` bug one level up: the subject
moved and the rules kept reading the old place. The first test below is
the measurement that found it, kept as a test so the reasoning stays
attached to the fix.

**Why refused and not unwrapped.** Reading ``fullDocument`` would fix one
field and leave three: ``fullDocumentBeforeChange`` carries the prior
copy, ``updateDescription.updatedFields`` carries changed values
verbatim, and a ``delete`` event carries ``documentKey`` for a row whose
deletion is the very thing a revocation exists to hide. Each is a
separate leak with separate semantics, and a partial fix here would be
the thing this repository is named after -- a guarantee that looks total
with a hole nothing announces.

So it takes the same answer as ``$out``: a proxy cannot make it safe, so
it says no, out loud, and says what to do instead.

Pure: no cluster, no driver, no network.
"""

from __future__ import annotations

import datetime as dt

import pytest

from voyd.engine.admission import AdmissionSpec
from voyd.engine.admission.core import AdmissionCore
from voyd.engine.admission.rules import Deadline, revoked
from voyd.wire.codec import LAZY, decode_op_msg, encode_op_msg
from voyd.wire.policy import Guard, refuse_change_stream, streams_changes

NOW = dt.datetime.now(dt.timezone.utc)
FORGOTTEN = {"_id": 1, "text": "SENSITIVE",
             "expire_at": NOW - dt.timedelta(days=7),
             "forgotten": "gdpr-4411"}


def guards(*names: str) -> dict[str, Guard]:
    return {name: Guard(AdmissionSpec(
        name, rules=(Deadline("expire_at"), revoked("forgotten"))))
        for name in names}


def command(body: dict) -> bytes:
    return encode_op_msg(7, 0, 0, body)


def stream(collection="notes", **extra) -> dict:
    return {"aggregate": collection, "cursor": {},
            "pipeline": [{"$changeStream": extra}]}


# ---- the measurement that found it -------------------------------------

def test_the_rules_cannot_see_inside_a_change_event():
    """Why this needs refusing at all. Kept as a test, not a comment.

    The same document, twice: once in the shape the rules were written
    for, once in the shape a change stream delivers. Only one of them is
    refused, and it is not the dangerous one.
    """
    spec = AdmissionSpec("notes",
                         rules=(Deadline("expire_at"), revoked("forgotten")))
    core = AdmissionCore(db=None, spec=spec)

    assert core.reachable([dict(FORGOTTEN)], when=NOW) == [], (
        "as an ordinary document it is refused twice over")

    event = {"_id": {"_data": "82F0"}, "operationType": "update",
             "ns": {"db": "app", "coll": "notes"},
             "documentKey": {"_id": 1},
             "fullDocument": dict(FORGOTTEN)}
    served = core.reachable([event], when=NOW)
    assert served and served[0]["fullDocument"]["text"] == "SENSITIVE", (
        "this is the hole: the rules read top-level fields, and an event "
        "has none of them. If this assertion ever fails because the "
        "engine learned to unwrap events, delete it and the refusal "
        "together -- but not one without the other")


# ---- so the command is refused -----------------------------------------

def test_a_change_stream_on_a_guarded_collection_is_refused():
    reply = refuse_change_stream(command(stream()), 7, 0, guards("notes"))
    assert reply is not None
    body = decode_op_msg(reply, LAZY)[1]
    assert body["ok"] == 0.0
    said = body["errmsg"]
    assert "notes" in said
    # The error has to carry the *reason*, because a refusal nobody can
    # act on becomes an argument for removing the boundary.
    assert "fullDocument" in said
    assert "fullDocumentBeforeChange" in said and "updateDescription" in said
    assert "straight to the deployment" in said, "and what to do instead"


def test_a_change_stream_somewhere_unguarded_is_forwarded():
    # This boundary declines what it cannot judge. It has nothing to say
    # about a collection no policy names, and refusing there would be an
    # outage caused by an opinion nobody asked for.
    assert streams_changes(stream("audit_log"), guards("notes")) is None
    assert refuse_change_stream(command(stream("audit_log")), 7, 0,
                                guards("notes")) is None


def test_a_whole_database_stream_is_refused_when_anything_is_guarded():
    # `aggregate: 1` delivers events for every collection, and the
    # namespace is chosen by the server per event rather than by the
    # client up front -- so there is no name to check against the policy
    # and no moment at which to check it.
    body = {"aggregate": 1, "cursor": {}, "pipeline": [{"$changeStream": {}}]}
    assert streams_changes(body, guards("notes")) == "the whole database"
    assert refuse_change_stream(command(body), 7, 0, guards("notes"))
    # With no policy at all there is nothing to protect and nothing to say.
    assert streams_changes(body, {}) is None


@pytest.mark.parametrize("options", [
    {},
    {"fullDocument": "updateLookup"},
    {"fullDocumentBeforeChange": "whenAvailable"},
    {"showExpandedEvents": True},
])
def test_every_flavour_of_change_stream_is_refused(options):
    # `fullDocument` is off by default, and a reader may reasonably think
    # that makes the default shape safe. It does not: `updateDescription`
    # carries changed values verbatim and `documentKey` identifies a row
    # whose deletion a revocation was meant to hide. The refusal does not
    # depend on which options were asked for.
    assert streams_changes(stream(**options), guards("notes")) == "notes"


def test_an_ordinary_aggregation_is_not_mistaken_for_one():
    for pipeline in ([{"$match": {"a": 1}}],
                     [{"$match": {"a": 1}}, {"$changeStream": {}}],
                     []):
        body = {"aggregate": "notes", "cursor": {}, "pipeline": pipeline}
        assert streams_changes(body, guards("notes")) is None, pipeline


def test_a_malformed_pipeline_is_not_a_change_stream():
    # Whatever was in the bytes. A refusal that raised on a junk pipeline
    # would turn a client's bad command into a boundary crash.
    for pipeline in (None, "nope", [None], [{"$changeStream": None}, 1], 7):
        body = {"aggregate": "notes", "cursor": {}, "pipeline": pipeline}
        got = streams_changes(body, guards("notes"))
        assert got in (None, "notes"), pipeline
