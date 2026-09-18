import pytest

# ``voyd.guards`` imports argon2 (the ``app`` extra). This is a service-layer test;
# an engine-only install skips it rather than failing collection.
pytest.importorskip("argon2")

from voyd.guards import (
    Guard,
    GuardError,
    build_void_policy,
    compile_guard_defaults,
    enforce_download,
)
from voyd.store.mongo import cosine, is_text_like


def test_compile_guard_defaults():
    defaults = compile_guard_defaults(
        [Guard.require_passcode(), Guard.max_downloads(limit=5)]
    )
    assert defaults["require_passcode"] is True
    assert defaults["max_downloads"] == 5
    assert defaults["passcode_hash"] is None


def test_build_void_policy_requires_passcode_when_voyd_requires_it():
    voyd_defaults = compile_guard_defaults([Guard.require_passcode()])
    with pytest.raises(GuardError):
        build_void_policy(voyd_defaults, passcode=None, max_downloads=None)

    policy = build_void_policy(voyd_defaults, passcode="hunter2", max_downloads=None)
    assert policy["require_passcode"] is True
    assert policy["passcode_hash"]  # argon2 hash present


def test_enforce_download_passcode_and_limit():
    policy = build_void_policy(
        compile_guard_defaults([Guard.require_passcode(), Guard.max_downloads(limit=2)]),
        passcode="open-sesame",
        max_downloads=None,
    )
    # wrong passcode
    with pytest.raises(GuardError):
        enforce_download(policy, 0, passcode="nope")
    # right passcode, under limit -> ok
    enforce_download(policy, 1, passcode="open-sesame")
    # right passcode, at limit -> blocked
    with pytest.raises(GuardError):
        enforce_download(policy, 2, passcode="open-sesame")


def test_void_override_max_downloads():
    policy = build_void_policy({}, passcode=None, max_downloads=3)
    assert policy["max_downloads"] == 3
    assert policy["require_passcode"] is False


def test_cosine():
    assert cosine([1, 0], [1, 0]) == pytest.approx(1.0)
    assert cosine([1, 0], [0, 1]) == pytest.approx(0.0)
    assert cosine([1, 0], [-1, 0]) == pytest.approx(-1.0)
    assert cosine([], [1]) == -1.0


def test_is_text_like():
    assert is_text_like("text/markdown")
    assert is_text_like("application/json; charset=utf-8")
    assert not is_text_like("image/png")
    assert not is_text_like(None)
