import pytest

# ``voyd.guards`` imports argon2 (the ``app`` extra). This is a service-layer test;
# an engine-only install skips it rather than failing collection.
pytest.importorskip("argon2")

from voyd.guards import (
    Guard,
    GuardError,
    build_void_policy,
    compile_guard_defaults,
    enforce_query,
)
from voyd.store.mongo import cosine


def test_compile_guard_defaults():
    defaults = compile_guard_defaults([Guard.require_passcode()])
    assert defaults["require_passcode"] is True
    assert defaults["passcode_hash"] is None


def test_build_void_policy_requires_passcode_when_voyd_requires_it():
    voyd_defaults = compile_guard_defaults([Guard.require_passcode()])
    with pytest.raises(GuardError):
        build_void_policy(voyd_defaults, passcode=None)

    policy = build_void_policy(voyd_defaults, passcode="hunter2")
    assert policy["require_passcode"] is True
    assert policy["passcode_hash"]  # argon2 hash present


def test_a_query_is_a_read_and_the_passcode_gates_it():
    """There is one door now. It used to also guard a byte path, and the rule
    was that gating one and not the other made search the way around the
    lock; with the bytes gone the rule is simply that reading needs the
    passcode."""
    policy = build_void_policy(
        compile_guard_defaults([Guard.require_passcode()]),
        passcode="open-sesame")
    with pytest.raises(GuardError):
        enforce_query(policy, passcode="nope")
    with pytest.raises(GuardError):
        enforce_query(policy, passcode=None)
    enforce_query(policy, passcode="open-sesame")  # no raise



def test_cosine():
    assert cosine([1, 0], [1, 0]) == pytest.approx(1.0)
    assert cosine([1, 0], [0, 1]) == pytest.approx(0.0)
    assert cosine([1, 0], [-1, 0]) == pytest.approx(-1.0)
    assert cosine([], [1]) == -1.0

