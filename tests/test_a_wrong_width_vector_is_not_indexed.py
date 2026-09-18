"""A vector of the wrong width is an invisible document, not a bad one.

The README promises the one distinction that matters when embedding is
asynchronous:

    | "Added" is not "searchable" | describe reports pending vs indexed
      separately |

``set_embedding`` broke that promise for a case nobody had tried. It wrote
whatever vector it was handed and marked the row ``indexed: True``. mongot
silently skips a vector whose width does not match the index definition -- no
error, no exception, and no ``degraded_searches`` increment, because nothing
degraded. Measured, before the fix, on a 1024-dimension index holding one
512-wide row:

    describe() reported   total=2  indexed=2  pending=0  failed=0
    search could return   only the other row -- permanently

Not "still building". Silent forever, while the API reported full confidence.
That is the same shape as a cold index looking empty, which this codebase
blocks startup to avoid, arriving through a different door.

The realistic cause is not an attacker. It is ``VOYAGE_MODEL`` being changed
under an index that was built for the old model's width, which is a one-line
config edit with no visible consequence.
"""

from __future__ import annotations

import random
import uuid

import pytest

pytest.importorskip("fastapi")


@pytest.fixture
async def void(app):
    """An owner, a namespace and a void, straight through the store."""
    owner_id = await app.store.create_owner("dims@example.com", "keyhash")
    voyd = await app.store.create_voyd("dims", owner_id, {}, name="dims")
    await app.store.create_void(voyd_id=voyd["_id"], token="tok", policy={},
                                expire_at=None)
    return app, voyd["_id"], "tok"


async def _add(app, voyd_id, token, text):
    return await app.store.add_document(voyd_id, token, uuid.uuid4().hex[:8],
                                        text=text, name=f"{text}.md")


def vector(n: int) -> list[float]:
    rng = random.Random(n)
    return [rng.random() for _ in range(n)]


async def test_a_correct_width_vector_is_indexed(void):
    """The fix must not reject the normal case."""
    app, voyd_id, token = void
    dims = app.store.engine.search_engine.specs["documents"].dimensions

    doc = await _add(app, voyd_id, token, "right")
    await app.store.set_embedding(doc["_id"], vector(dims))

    row = await app.store.db.documents.find_one({"_id": doc["_id"]})
    assert row["indexed"] is True
    assert row["embedding"] is not None
    assert len(row["embedding"]) == dims


@pytest.mark.parametrize("delta", [-512, -1, 1, 512])
async def test_a_wrong_width_vector_is_parked_not_stored(void, delta):
    """Off by one or off by half: either way mongot will not index it, so
    storing it would be storing a document that can never be found."""
    app, voyd_id, token = void
    dims = app.store.engine.search_engine.specs["documents"].dimensions

    doc = await _add(app, voyd_id, token, "wrong")
    await app.store.set_embedding(doc["_id"], vector(dims + delta))

    row = await app.store.db.documents.find_one({"_id": doc["_id"]})
    assert row["indexed"] == "error", \
        "a vector mongot cannot index was recorded as indexed"
    assert row["embedding"] is None, \
        "an unusable vector was stored anyway"


async def test_describe_reports_it_as_failed_rather_than_indexed(void):
    """The number a caller acts on.

    ``failed`` means "stop waiting, go look". ``indexed`` means "this is
    searchable now". Reporting the first as the second is the lie.
    """
    app, voyd_id, token = void
    dims = app.store.engine.search_engine.specs["documents"].dimensions

    good = await _add(app, voyd_id, token, "good")
    bad = await _add(app, voyd_id, token, "bad")
    await app.store.set_embedding(good["_id"], vector(dims))
    await app.store.set_embedding(bad["_id"], vector(dims // 2))

    counts = await app.store.count_indexed(voyd_id, token)
    assert counts["total"] == 2
    assert counts["indexed"] == 1
    assert counts["failed"] == 1, f"the invisible document was hidden: {counts}"
    assert counts["pending"] == 0, "a parked document must not look pending"


async def test_the_mismatch_is_logged_with_both_numbers(void, caplog):
    """An operator needs to know which two numbers disagree, or the fix --
    usually a changed embedding model -- is guesswork."""
    app, voyd_id, token = void
    dims = app.store.engine.search_engine.specs["documents"].dimensions

    doc = await _add(app, voyd_id, token, "loud")
    with caplog.at_level("ERROR"):
        await app.store.set_embedding(doc["_id"], vector(dims // 2))

    assert str(dims) in caplog.text, caplog.text
    assert str(dims // 2) in caplog.text, caplog.text


async def test_a_deliberate_none_is_still_a_permanent_failure(void):
    """``set_embedding(None)`` already meant "this document is unembeddable"
    -- an empty blob, a missing bucket. The width check must not change what
    that path records."""
    app, voyd_id, token = void

    doc = await _add(app, voyd_id, token, "empty")
    await app.store.set_embedding(doc["_id"], None)

    row = await app.store.db.documents.find_one({"_id": doc["_id"]})
    assert row["indexed"] == "error"
    assert row["embedding"] is None
