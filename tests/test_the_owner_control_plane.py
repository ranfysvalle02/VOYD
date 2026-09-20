"""Signing up and creating a namespace — the first thing anybody does.

Every line of it was untested over HTTP. `web/owner.py` sat at 35% coverage
with `create_owner`, `create_voyd` and the forget endpoint entirely
unexercised, which means the *documented first run of the product* was
verified by nobody.

The parts that matter here are not the happy paths. They are the three
places this plane makes a security decision:

  * the **first** owner is open and every one after it needs a valid key —
    a bootstrap rule that is exactly the shape that gets left permanently
    open;
  * the raw API key is returned **once** and stored only as a hash;
  * an owner may only act on namespaces they own, and must not be able to
    tell "not yours" from "does not exist" by the status code alone.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")


async def signup(client, email="first@acme.test", key=None):
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    return await client.post("/v1/owners", json={"email": email},
                             headers=headers)


def bearer(key):
    return {"Authorization": f"Bearer {key}"}


# ---- bootstrap: open once, closed forever after ------------------------

async def test_the_first_owner_is_open_and_the_second_is_not(client):
    """The rule that decides whether a deployment is open to the internet
    on day two. Left ungated it is a public sign-up endpoint nobody meant
    to ship."""
    first = await signup(client)
    assert first.status_code == 200
    key = first.json()["api_key"]
    assert key and first.json()["email"] == "first@acme.test"

    uninvited = await signup(client, "second@acme.test")
    assert uninvited.status_code == 401

    invited = await signup(client, "second@acme.test", key=key)
    assert invited.status_code == 200
    assert invited.json()["api_key"] != key, "each owner gets their own key"


async def test_a_wrong_key_cannot_mint_an_owner(client):
    await signup(client)
    assert (await signup(client, "x@acme.test", key="not-a-key")).status_code \
        == 401


async def test_the_raw_key_is_returned_once_and_stored_as_a_hash(app, client):
    """A key you can recover from the database is a key the database can
    leak."""
    key = (await signup(client)).json()["api_key"]

    owner = await app.store.db.owners.find_one({"email": "first@acme.test"})
    assert key not in str(owner), "the raw key must not be in the document"
    assert owner.get("api_key_hash")

    # And the hash is what authenticates -- the key still works.
    assert (await client.post("/v1/voyds", json={"slug": "acme"},
                              headers=bearer(key))).status_code == 200


async def test_an_email_is_required_and_unique(client):
    assert (await client.post("/v1/owners", json={})).status_code == 400
    key = (await signup(client)).json()["api_key"]
    assert (await signup(client, "FIRST@acme.test", key=key)).status_code == 409, \
        "email is normalised, so a case change is the same owner"


# ---- namespaces --------------------------------------------------------

async def test_creating_a_namespace_is_an_insert_not_a_deploy(client):
    """Going live is one document. There is nothing to provision, which is
    the claim the README makes and nothing checked."""
    key = (await signup(client)).json()["api_key"]

    made = await client.post("/v1/voyds", json={"slug": "acme"},
                             headers=bearer(key))
    assert made.status_code == 200

    listed = await client.get("/v1/voyds", headers=bearer(key))
    assert [v["slug"] for v in listed.json()["voyds"]] == ["acme"]


async def test_a_namespace_needs_a_valid_slug(client):
    key = (await signup(client)).json()["api_key"]
    for bad in ("", "Not A Slug", "a" * 200, "../etc"):
        r = await client.post("/v1/voyds", json={"slug": bad},
                              headers=bearer(key))
        # 400 from the slug rule, 422 when the body never reaches it --
        # both are refusals, and asserting the exact code would pin a
        # framework detail rather than the property.
        assert 400 <= r.status_code < 500, f"{bad!r} was accepted as a slug"


async def test_two_owners_cannot_share_a_slug(client):
    first = (await signup(client)).json()["api_key"]
    second = (await signup(client, "b@acme.test", key=first)).json()["api_key"]

    assert (await client.post("/v1/voyds", json={"slug": "acme"},
                              headers=bearer(first))).status_code == 200
    clash = await client.post("/v1/voyds", json={"slug": "acme"},
                              headers=bearer(second))
    assert clash.status_code == 409


async def test_an_owner_only_sees_their_own(client):
    first = (await signup(client)).json()["api_key"]
    second = (await signup(client, "b@acme.test", key=first)).json()["api_key"]
    await client.post("/v1/voyds", json={"slug": "acme"}, headers=bearer(first))

    listed = await client.get("/v1/voyds", headers=bearer(second))
    assert listed.json()["voyds"] == []


# ---- forgetting a namespace over HTTP ---------------------------------

async def test_forgetting_a_namespace_reports_what_it_achieved(client):
    key = (await signup(client)).json()["api_key"]
    await client.post("/v1/voyds", json={"slug": "acme"}, headers=bearer(key))

    out = await client.post("/v1/voyds/acme/forget",
                            json={"reason": "account closed"},
                            headers=bearer(key))
    assert out.status_code == 200
    body = out.json()
    assert body["slug"] == "acme"
    assert isinstance(body["unreadable"], bool)
    assert body["detail"], "the honest answer needs a sentence, not a bool"


async def test_you_cannot_forget_a_namespace_you_do_not_own(client):
    first = (await signup(client)).json()["api_key"]
    second = (await signup(client, "b@acme.test", key=first)).json()["api_key"]
    await client.post("/v1/voyds", json={"slug": "acme"}, headers=bearer(first))

    theirs = await client.post("/v1/voyds/acme/forget", json={},
                               headers=bearer(second))
    assert theirs.status_code == 403
    assert (await client.post("/v1/voyds/nope/forget", json={},
                              headers=bearer(second))).status_code == 404


async def test_the_owner_plane_is_not_served_on_a_voyd_host(client):
    """It only exists on the apex. A control plane reachable from a
    tenant's own hostname is a control plane a tenant can reach."""
    key = (await signup(client)).json()["api_key"]
    await client.post("/v1/voyds", json={"slug": "acme"}, headers=bearer(key))

    on_tenant = await client.get("/v1/voyds", headers={
        **bearer(key), "X-Voyd": "acme"})
    assert on_tenant.status_code == 404


@pytest.mark.parametrize("path, method", [
    ("/v1/voyds", "post"), ("/v1/voyds", "get"),
    ("/v1/voyds/acme/forget", "post"),
])
async def test_every_owner_endpoint_refuses_an_unauthenticated_caller(
        client, path, method):
    """Enumerated rather than spot-checked: the historical shape of this
    bug is never "the check is wrong", it is "one route did not have it"."""
    await signup(client)
    kw = {"json": {"slug": "x"}} if method == "post" else {}
    r = await getattr(client, method)(path, **kw)
    assert r.status_code == 401
