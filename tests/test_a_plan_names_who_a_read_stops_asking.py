"""`voyd-plan` reports what a change does to delegated reads, before it ships.

Every finding here is structural -- it is a fact about two policy files,
not an estimate from a sample -- and each one says which direction it
moves. A rule that stops asking the actor, a `delegation=` that admits a
kind of identity it refused, a scope removed, an issuer added: each of
those widens what an agent can read, and each is marked fail-open.
"""

from __future__ import annotations

import pytest

pytest.importorskip("cryptography")

from voyd.declare import ISSUERS, load
from voyd.engine.plan import (DELEGATION_LOOSENED, DELEGATION_TIGHTENED,
                              ISSUER_ADDED, ISSUER_CHANGED, ISSUER_REMOVED,
                              SCOPE_ADDED, SCOPE_CHANGED, SCOPE_REMOVED,
                              VIA_NARROWED_TO_ONE_SIDE, VIA_WIDENED_TO_BOTH,
                              issuers, plan, structural)
from voyd.wire.plan import main

HEAD = '''
from voyd import guard, issuer, mask, restricted_to, tenant, clearance, deadline
{issuer}
@guard("notes"{opts})
class Notes:
    expire_at = deadline()
    org       = tenant({tenant})
    audience  = restricted_to("roles"{via})
    level     = clearance(order=("public", "secret"),
                          roles={{"sec": "secret"}}{cvia})
    salary    = mask(visible_to=("hr",){mvia})
'''

ISSUER = ('issuer("https://login.test", audience="voyd://t", '
          'jwks="k.json", connection_users={users}{extra})')


def policy(tmp_path, name, *, opts="", tenant="", via="", cvia="", mvia="",
           issuer=True, users='("svc",)', extra=""):
    path = tmp_path / f"{name}.py"     # a stem, so call sites are not citations
    path.write_text(HEAD.format(
        issuer=ISSUER.format(users=users, extra=extra) if issuer else "",
        opts=opts, tenant=tenant, via=via, cvia=cvia, mvia=mvia))
    specs = load(str(path))
    return specs, dict(ISSUERS), str(path)


def kinds(found) -> dict[str, bool]:
    return {s.kind: s.fails_open for s in found}


@pytest.mark.parametrize("before, after, loosens", [
    ("required", "allowed", True),
    ("forbidden", "allowed", True),
    ("forbidden", "required", True),
    ("required", "forbidden", True),        # plain reads come back
    ("allowed", "required", False),
    ("allowed", "forbidden", False),
])
def test_delegation_that_admits_a_kind_it_refused_fails_open(
        tmp_path, before, after, loosens):
    was, _i, _ = policy(tmp_path, "a", opts=f', delegation="{before}"')
    now, _i, _ = policy(tmp_path, "b", opts=f', delegation="{after}"')
    got = kinds(structural(was, now))
    kind = DELEGATION_LOOSENED if loosens else DELEGATION_TIGHTENED
    assert got == {kind: loosens}


def test_a_scope_removed_or_changed_fails_open_and_added_does_not(tmp_path):
    none, _i, _ = policy(tmp_path, "a")
    read, _i, _ = policy(tmp_path, "b", opts=', scope="notes:read"')
    all_, _i, _ = policy(tmp_path, "c", opts=', scope="notes:all"')
    assert kinds(structural(read, none)) == {SCOPE_REMOVED: True}
    assert kinds(structural(none, read)) == {SCOPE_ADDED: False}
    assert kinds(structural(read, all_)) == {SCOPE_CHANGED: True}


@pytest.mark.parametrize("field", ["via", "cvia", "mvia", "tenant"])
def test_a_rule_that_stops_asking_one_side_fails_open(tmp_path, field):
    both, _i, _ = policy(tmp_path, "a")
    one = {field: ('via="principal"' if field == "tenant"
                   else ', via="principal"')}
    narrowed, _i, _ = policy(tmp_path, "b", **one)
    found = structural(both, narrowed)
    assert [s.kind for s in found] == [VIA_NARROWED_TO_ONE_SIDE]
    assert found[0].fails_open and "actor" in found[0].detail
    back = structural(narrowed, both)
    assert kinds(back) == {VIA_WIDENED_TO_BOTH: False}


def test_switching_sides_fails_open(tmp_path):
    user, _i, _ = policy(tmp_path, "a", via=', via="principal"')
    agent, _i, _ = policy(tmp_path, "b", via=', via="actor"')
    assert kinds(structural(user, agent)) == {VIA_NARROWED_TO_ONE_SIDE: True}


def test_issuers_added_removed_and_changed(tmp_path):
    _s, none, _ = policy(tmp_path, "a", issuer=False)
    _s, one, _ = policy(tmp_path, "b")
    _s, anyone, _ = policy(tmp_path, "c", users='("*",)')
    _s, fewer_algs, _ = policy(tmp_path, "d",
                               extra=', algorithms=("EdDSA",)')
    _s, new_keys, _ = policy(tmp_path, "e", extra=', skew=10')
    assert kinds(issuers(none, one)) == {ISSUER_ADDED: True}
    assert kinds(issuers(one, none)) == {ISSUER_REMOVED: False}
    assert kinds(issuers(one, anyone)) == {ISSUER_CHANGED: True}
    assert kinds(issuers(one, fewer_algs)) == {ISSUER_CHANGED: False}
    assert kinds(issuers(one, new_keys)) == {ISSUER_CHANGED: False}
    assert kinds(issuers(new_keys, one)) == {ISSUER_CHANGED: True}


def test_the_plan_carries_the_issuer_findings_and_fails_open_on_them(tmp_path):
    was, before, _ = policy(tmp_path, "a", issuer=False)
    now, after, _ = policy(tmp_path, "b")
    result = plan(was, now, lambda _c: iter(()), trusted=(before, after),
                  collections=["other"])
    assert [s.kind for s in result.structural] == [ISSUER_ADDED]
    assert result.fails_open


def test_voyd_plan_exits_one_on_a_loosened_delegation(tmp_path, capsys):
    _s, _i, was = policy(tmp_path, "a", opts=', delegation="required"')
    _s, _i, now = policy(tmp_path, "b")
    assert main(["--current", was, "--proposed", now]) == 1
    assert DELEGATION_LOOSENED in capsys.readouterr().out
    assert main(["--current", now, "--proposed", now]) == 0
