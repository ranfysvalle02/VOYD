"""An agent reads as two callers at once.

    docker compose up -d
    uv run python examples/delegation.py    # ~3 seconds, no network, no IdP

A support agent runs as one service account and serves every user, so the
account can see everything -- and the user it is acting for this second is
a fact the database never hears about. The usual answers are to let the
agent over-share, or to re-implement per-user filtering in the agent's
code, one tool at a time.

Here the user rides in the request. The agent passes the delegated token
its runtime already holds as the command's `comment`, which every driver
forwards verbatim, and the boundary does the rest:

1. **One connection, two users, the same query, different rows.** The
   token is verified by the boundary against the identity provider's
   public keys, the read is judged as the principal *and* the actor, the
   tenant is pinned from the token, and the token is stripped before the
   command goes upstream.
2. **The intersection, shown with a mask.** HR's salary column is
   unmasked only when the user *and* the agent are both HR. An HR user
   asking through a support agent sees it masked: the agent's roles can
   only narrow its user's view.
3. **An agent without the scope is refused**, by name, before anything
   is read.

The identity provider is `voyd.testing.TestIssuer`, which mints tokens
locally. In a deployment it is Okta, Entra, Auth0 or your own; the
boundary only ever holds the public half of its keys.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from pymongo import MongoClient
from pymongo.errors import OperationFailure

from _boundary import boundary, deployment
from voyd.testing import TestIssuer

IDP = TestIssuer("https://login.example.test", alg="EdDSA",
                 audience="voyd://example")

CORPUS = [
    {"_id": 1, "org": "acme", "audience": ["hr"], "who": "offer letter",
     "salary": 185_000},
    {"_id": 2, "org": "acme", "audience": ["support"], "who": "refund policy",
     "salary": None},
    {"_id": 3, "org": "acme", "audience": ["support", "hr"],
     "who": "on-call rota", "salary": 92_000},
    {"_id": 4, "org": "globex", "audience": ["support", "hr"],
     "who": "globex escalation", "salary": 120_000},
]

POLICY = '''
from voyd import guard, issuer, mask, restricted_to, tenant

issuer("https://login.example.test", audience="voyd://example",
       jwks="{jwks}", connection_users=("*",),
       roles="roles", tenant="org", actor_roles="act.roles")

@guard("notes", scope="notes:read")
class Notes:
    org      = tenant()
    audience = restricted_to("roles")
    salary   = mask(visible_to=("hr",))
'''


def token(user: str, roles: list[str], agent_roles: list[str], *,
          scope: str = "notes:read") -> dict:
    """What an agent runtime holds for one user, as a `comment`."""
    return {"voyd": IDP.mint(user, actor="support-bot", scope=scope,
                             org="acme", roles=roles,
                             actor_claims={"roles": agent_roles})}


def show(rows: list[dict]) -> list[str]:
    return [f"{d['who']} (salary={d['salary']})" for d in rows]


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp, \
            deployment("delegation") as (direct, name):
        jwks = IDP.write_jwks(str(Path(tmp) / "jwks.json"))
        direct[name].notes.insert_many([dict(d) for d in CORPUS])

        with boundary(POLICY.format(jwks=jwks)) as uri:
            # One pooled connection, as an agent runtime holds it.
            client = MongoClient(uri, serverSelectionTimeoutMS=8000)
            notes = client[name].notes
            try:
                agent = ["support", "hr"]
                print("\n  One service connection. The same query, twice.\n")
                dana = show(notes.find({}, sort=[("_id", 1)],
                                       comment=token("dana", ["hr", "support"],
                                                     agent)))
                sam = show(notes.find({}, sort=[("_id", 1)],
                                      comment=token("sam", ["support"],
                                                    agent)))
                print(f"  1. dana (hr) through the agent -> {dana}")
                print(f"     sam (support) through the agent -> {sam}")
                print("     Globex's row reaches neither: the tenant is the "
                      "token's.")
                assert dana == ["offer letter (salary=185000)",
                                "refund policy (salary=None)",
                                "on-call rota (salary=92000)"]
                assert sam == ["refund policy (salary=None)",
                               "on-call rota (salary=None)"]

                print("\n  2. the intersection: dana asks through an agent "
                      "that is not hr")
                narrow = show(notes.find({}, sort=[("_id", 1)],
                                         comment=token("dana",
                                                       ["hr", "support"],
                                                       ["support"])))
                print(f"     -> {narrow}")
                print("     The offer letter needs hr on both sides, and the "
                      "rota's")
                print("     salary stays masked: the agent narrows its user, "
                      "never lifts.")
                assert narrow == ["refund policy (salary=None)",
                                  "on-call rota (salary=None)"]

                print("\n  3. an agent granted a different scope")
                try:
                    list(notes.find({}, comment=token(
                        "dana", ["hr"], agent, scope="tickets:read")))
                except OperationFailure as exc:
                    said = str(exc).split(", full error")[0]
                    print(f"     -> refused: {said}")
                    assert "notes:read" in said
                else:
                    raise AssertionError("a scope-less agent was served")
            finally:
                client.close()
    print()


if __name__ == "__main__":
    main()
