"""Forgetting a namespace: the same verb, one tier up.

There are four tiers here -- owner, voyd, void, document -- and until now
only the bottom two obeyed this package's own thesis. A *customer's*
erasure request was honoured in milliseconds, on a hash chain, with
per-subject crypto-shredding. The *account holder's* had a
``DELETE /v1/voyds/{slug}`` that was untested, undocumented, and cascaded
through a hardcoded ``("voids", "documents")`` written before three more
collections existed.

The guarantee was strongest at the leaf and absent at the root, which is
backwards: the root is where all of the data is.

The fix is not a longer cascade. **A cascade enumerates kinds of thing, and
new kinds appear** -- that is not carelessness, it is what the shape does.
So the namespace stops being a folder and becomes what it already was: a
key scope, because ``voyd_id`` is already the tenant on every document.
Destroying one key makes everything sealed under it unreadable in every
copy of the data that has ever existed, without visiting a row and without
knowing which collections exist.

The cascade list was not incomplete. It was unnecessary.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")


async def a_namespace(store, slug="acme", *, owner="o1"):
    voyd = await store.create_voyd(slug, owner, guard_defaults={})
    void = await store.create_void(voyd["_id"], f"tok-{slug}", {}, None)
    await store.add_document(voyd["_id"], void["token"], f"d-{slug}",
                             text=f"{slug} secret", name=f"{slug}.txt")
    return voyd


# ---- the namespace finally has the deadline every tier below it had ----

async def test_the_voyds_collection_declares_a_deadline(app):
    """Its absence was the whole bug. Three tiers declared a TTL and the
    one holding the other two did not."""
    s = app.store
    declared = {spec.collection for spec in s.engine.expiry.specs}
    assert {"voyds", "voids", "documents"} <= declared


async def test_forgetting_a_namespace_reaches_every_declared_collection(app):
    """Taken from ``engine.expiry.specs`` -- the engine's own registry of
    what declared a TTL -- rather than a literal somebody has to remember
    to extend. A collection added next year is included by having been
    declared."""
    s, db = app.store, app.store.db
    voyd = await a_namespace(s)

    out = await s.forget_voyd("acme", reason="owner request", actor="alice")

    assert set(out["scoped"]) == {"voyds", "voids", "documents"}
    for coll in ("voyds", "voids", "documents"):
        key = "_id" if coll == "voyds" else "voyd_id"
        row = await db[coll].find_one({key: voyd["_id"]})
        assert row["expire_at"] is not None, f"{coll} kept no deadline"


async def test_a_neighbouring_namespace_is_untouched(app):
    """One erasure request must not be everybody's."""
    s, db = app.store, app.store.db
    await a_namespace(s, "acme")
    other = await a_namespace(s, "globex")

    await s.forget_voyd("acme", reason="owner request")

    kept = await db.documents.find_one({"voyd_id": other["_id"]})
    assert kept.get("expire_at") is None


async def test_it_reports_what_it_actually_achieved(app):
    """The two halves are not equally strong and a caller reporting an
    erasure to a regulator should not have to guess which one they got."""
    s = app.store
    await a_namespace(s)

    out = await s.forget_voyd("acme", reason="owner request")

    assert set(out) == {"slug", "unreadable", "detail", "scoped"}
    assert isinstance(out["unreadable"], bool)
    assert out["detail"], "an honest answer needs a sentence, not just a bool"
    if not out["unreadable"]:
        assert "keep the plaintext" in out["detail"] or \
               "nothing was sealed" in out["detail"], \
            "when only the deadline ran, say so rather than implying more"


async def test_forgetting_an_unknown_namespace_is_not_an_error(app):
    s = app.store
    assert await s.forget_voyd("never-existed", reason="x") == {}


# ---- it goes on the chain, with a name attached -----------------------

async def test_the_namespace_erasure_is_witnessed(app):
    """The tier that had no mechanism now has the same one as the others:
    an instruction, recorded, attributable."""
    s = app.store
    voyd = await a_namespace(s)

    await s.forget_voyd("acme", reason="account closed", actor="alice@acme")

    entry = (await s.refusals.entries(tenant=voyd["_id"]))[-1]
    assert entry["event"] == "forgotten"
    assert entry["reason"] == "account closed"
    assert entry["actor"] == "alice@acme"
    assert entry["detail"]["scoped"]["documents"] == 1
    assert (await s.refusals.verify(tenant=voyd["_id"]))["intact"] is True


async def test_an_unwritable_chain_does_not_undo_the_forgetting(app):
    """The namespace is already unreachable before the record is written.
    An unrecorded erasure is an audit gap; an un-erased namespace is a
    breach, and they are not the same size."""
    s = app.store
    await a_namespace(s)

    class Broken:
        async def append(self, *a, **kw):
            raise RuntimeError("chain unavailable")
        async def entries(self, **kw):
            return []
    s.refusals = Broken()

    out = await s.forget_voyd("acme", reason="owner request")
    assert out["scoped"]["documents"] == 1


# ---- and the endpoint hands back no obligation ------------------------

def test_the_endpoint_is_a_post_not_a_delete():
    """Not a loophole around the reclaiming test -- the point it exists to
    protect. A delete hands the caller a cleanup obligation; this hands
    back none, and the deadline that was already the mechanism stays it."""
    from voyd.web import owner

    routes = {r.path: set(r.methods) for r in owner.router.routes}
    assert routes["/v1/voyds/{slug}/forget"] == {"POST"}
    assert not any("DELETE" in m for m in routes.values())


def test_forget_is_the_same_word_at_every_tier():
    """One verb, three scales, identical semantics: unreachable now,
    unreadable soon, gone eventually."""
    from voyd.web import owner, vault

    paths = {r.path for r in owner.router.routes} | \
            {r.path for r in vault.router.routes}
    assert "/v1/voyds/{slug}/forget" in paths
    assert "/v1/voids/{token}/forget" in paths
