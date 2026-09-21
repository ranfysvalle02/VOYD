"""The one claim everything else rests on, tested without a database.

`reachable()` is handed documents and returns the ones a prompt may see. It
is a pure function -- no query, no connection, no clock but the one it is
given -- and that is not an implementation detail. It is the property that
lets the same check run in a library, in a proxy, and anywhere else, and the
reason the wire boundary needs no credentials of its own.

If these five fail, nothing above them means anything.
"""

from __future__ import annotations

from datetime import timedelta

from voyd.engine import Deadline, revoked
from voyd.engine.admission import Admission, AdmissionSpec
from voyd.engine.time import now

PAST = now() - timedelta(days=1)
FUTURE = now() + timedelta(days=1)


def handle(*, tenant=None):
    """A boundary with no database behind it. `db=None` is the assertion."""
    return Admission(None, AdmissionSpec(
        "notes", rules=(Deadline(), revoked()), tenant=tenant))


def test_a_live_document_is_admitted():
    """The direction that is easy to lose: a rule that refuses everything
    passes every other test in this file."""
    docs = [{"text": "live"}, {"text": "pinned", "expire_at": None},
            {"text": "later", "expire_at": FUTURE}]
    assert handle().reachable(docs) == docs


def test_an_expired_document_is_refused():
    kept = handle().reachable([{"text": "gone", "expire_at": PAST}])
    assert kept == []


def test_a_revoked_document_is_refused():
    kept = handle().reachable(
        [{"text": "leaked", "forgotten": {"at": PAST, "reason": "leak"}}])
    assert kept == []


def test_an_unreadable_deadline_fails_closed():
    """A fact whose lifetime cannot be established has no business in a
    prompt. The open direction would be the safe-looking one and is wrong."""
    assert handle().reachable([{"text": "?", "expire_at": "not a date"}]) == []


def test_the_refusals_are_counted():
    """"Unreachable" is a claim; a count is what makes it checkable. The
    number is exact here precisely because these documents never went
    through a query that could have dropped them first."""
    h = handle()
    h.reachable([{"text": "a", "expire_at": PAST},
                 {"text": "b", "forgotten": {"at": PAST, "reason": "x"}},
                 {"text": "c"}])
    assert h.receipts()["refused_by_reason"] == {"deadline": 1, "revoked": 1}


def test_a_scoped_boundary_refuses_a_foreign_document():
    """The tenant is enforced per document, not only in the query -- a
    `$vectorSearch` hit never passed through a query at all."""
    h = handle(tenant="tenant_id").for_tenant("acme")
    kept = h.reachable([{"tenant_id": "acme", "text": "mine"},
                        {"tenant_id": "globex", "text": "theirs"}])
    assert [d["text"] for d in kept] == ["mine"]
    assert h.receipts()["refused_by_reason"] == {"off_scope": 1}


def test_a_scoped_boundary_refuses_to_guess():
    """An unbound read on a scoped collection raises rather than returning
    every tenant. Returning the batch would be the leak; returning one
    tenant's rows would be a guess about which read this was."""
    import pytest

    from voyd.engine import ScopeRequired

    with pytest.raises(ScopeRequired):
        handle(tenant="tenant_id").reachable([{"tenant_id": "acme"}])
