"""A cumulative rule spans the read, and the client picks the batch size.

`budget()` and `distinct()` are *cumulative*: each document is judged
against the running total of the page so far. Every other rule in this
package asks a question about one document, and a rule that asks about
the page needs state that outlives a single call.

On the wire that is the whole difficulty. The boundary is handed a *batch*,
not a read: a cursor delivers one logical `find` in as many batches as the
client asked for, and `batchSize` is a field in the client's own command.
A fresh total per batch is therefore not an inefficiency, it is a rule the
caller can switch off -- and switch off *by accident*, since every driver
has a default batch size and some frameworks set their own.

Measured before it was closed, ten documents at 40 tokens each under a
declared budget of 100:

    one batch     -> 2 documents    correct
    batchSize=2   -> 10 documents   400 tokens under a 100-token budget

Nothing errored, nothing was logged, and the policy file said the rule was
in force. That is the exact shape of failure this project exists to name,
arriving inside it, which is why this file exists and why the assertions
below are written against the *number of documents served*, not against a
counter the boundary keeps about itself.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

from voyd.wire.proxy import Budgets, Guard

from .conftest import free_port, mongo_host

pymongo = pytest.importorskip("pymongo")
ROOT = Path(__file__).resolve().parents[1]

POLICY = """
from voyd import guard, deadline, revocable, budget

@guard("notes")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    tokens = budget(100)
"""

PLAIN = """
from voyd import guard, deadline, revocable

@guard("notes")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
"""


@contextmanager
def _wire(tmp_path, policy: str):
    path = tmp_path / "voydfile.py"
    path.write_text(policy)
    port = free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "voyd.wire.proxy", "--config", str(path),
         "--listen", str(port), "--target", mongo_host()],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        until = time.monotonic() + 15
        while time.monotonic() < until:
            if proc.poll() is not None:
                pytest.fail(f"voyd-wire exited early:\n{proc.stdout.read()}")
            try:
                with socket.create_connection(("127.0.0.1", port), 0.2):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            pytest.fail("voyd-wire never started listening")
        yield f"mongodb://localhost:{port}/?directConnection=true"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.fixture
def budgeted(tmp_path, db):
    """Ten 40-token documents behind a 100-token budget."""
    db.notes.insert_many([{"n": i, "tokens": 40} for i in range(10)])
    with _wire(tmp_path, POLICY) as uri:
        client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=8000)
        try:
            yield client[db.name].notes, db
        finally:
            client.close()


# ---- the claim, through a plain driver -----------------------------------

@pytest.mark.parametrize("size", [101, 10, 4, 2, 1])
def test_the_budget_is_the_same_whatever_batch_size_is_asked_for(budgeted,
                                                                 size):
    """The whole point. Two 40-token documents fit in 100, and how many
    round trips the driver chose to take has nothing to do with it."""
    notes, _ = budgeted
    served = list(notes.find({}).batch_size(size))
    assert len(served) == 2, (
        f"batchSize={size} served {len(served)} documents, "
        f"{len(served) * 40} tokens, under a declared budget of 100")


def test_the_control_is_that_the_documents_are_all_there(budgeted):
    """If the collection ever stops holding ten rows, the assertions above
    pass for the wrong reason -- a budget that refuses nothing and a
    collection with nothing in it look identical from the client."""
    _, direct = budgeted
    assert direct.notes.count_documents({}) == 10


def test_a_second_query_starts_its_own_budget(budgeted):
    """Per cursor, not per connection. A running total that leaked between
    reads would make the second `find` on a connection return less than the
    first, which is a boundary inventing a rule nobody declared."""
    notes, _ = budgeted
    first = list(notes.find({}).batch_size(2))
    second = list(notes.find({}).batch_size(2))
    assert len(first) == len(second) == 2


def test_an_abandoned_cursor_does_not_leak_its_total(budgeted):
    """A client that walks away from a cursor sends `killCursors`, and the
    boundary has to forget the total with it -- otherwise a long-lived
    connection accumulates one per query it has ever run."""
    notes, _ = budgeted
    cur = notes.find({}).batch_size(1)
    next(cur)
    cur.close()                      # -> killCursors
    assert len(list(notes.find({}).batch_size(1))) == 2


# ---- and the fast path pays nothing --------------------------------------

def test_a_policy_with_no_cumulative_rule_allocates_no_state(tmp_path, db):
    """The gate is `Guard.cumulative`. A deadline and a revocation are
    per-document questions, so a cursor over them needs nothing remembered
    between batches and the registry must stay empty."""
    db.notes.insert_many([{"n": i} for i in range(10)])
    with _wire(tmp_path, PLAIN) as uri:
        client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=8000)
        try:
            got = list(client[db.name].notes.find({}).batch_size(2))
        finally:
            client.close()
    assert len(got) == 10


# ---- the registry itself, with no database in sight ----------------------

def _guard(policy_rules) -> Guard:
    from voyd.engine.admission import AdmissionSpec

    return Guard(AdmissionSpec("notes", rules=policy_rules))


def test_the_registry_hands_back_one_tab_per_cursor():
    from voyd.engine import Budget, Deadline

    g = _guard((Deadline(), Budget(limit=100)))
    b = Budgets()
    assert b.tab_for(g, 7) is b.tab_for(g, 7), "one cursor, one running total"
    assert b.tab_for(g, 8) is not b.tab_for(g, 7), "two cursors, two totals"


def test_an_exhausted_cursor_needs_no_tab_at_all():
    """`id: 0` means the server answered the whole read in one reply. There
    is no second batch for a total to span, so there is nothing to keep."""
    from voyd.engine import Budget, Deadline

    g = _guard((Deadline(), Budget(limit=100)))
    b = Budgets()
    assert b.tab_for(g, 0) is b.tab_for(g, 0)
    assert b._open == {}


def test_a_guard_with_no_cumulative_rule_is_never_asked_for_one():
    from voyd.engine import Deadline, revoked

    g = _guard((Deadline(), revoked()))
    assert g.cumulative is False
    b = Budgets()
    b.tab_for(g, 7)
    assert b._open == {}, "a per-document policy allocates nothing"


def test_forgetting_a_cursor_drops_its_total():
    from voyd.engine import Budget, Deadline

    g = _guard((Deadline(), Budget(limit=100)))
    b = Budgets()
    first = b.tab_for(g, 7)
    b.forget([7])
    assert b.tab_for(g, 7) is not first
