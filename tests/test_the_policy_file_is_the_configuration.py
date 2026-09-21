"""The policy file is the product's whole configuration surface.

It is not in the application, nobody reviews it alongside a code change, and
it decides what a database will and will not serve. So the bar is that a file
which is wrong fails when it is **loaded** -- not when a query comes back with
the wrong rows, and never silently.
"""

from __future__ import annotations

import pytest

from voyd.declare import OPTIONS, load

GOOD = """
from voyd import guard, deadline, revocable, tenant

@guard("notes", on_delete="revoke")
class Notes:
    expire_at = deadline()
    forgotten = revocable()
    tenant_id = tenant()
"""


def write(tmp_path, body):
    path = tmp_path / "voydfile.py"
    path.write_text(body)
    return str(path)


def test_a_policy_file_compiles_to_the_same_objects_the_library_uses(tmp_path):
    """A spelling, not a second mechanism. There is no cliff between
    declaring a rule and writing one, because the declaration *is* the rule."""
    spec = load(write(tmp_path, GOOD))["notes"]
    assert spec.tenant == "tenant_id"
    assert [type(r).__name__ for r in spec.rules] == ["Deadline", "Marked"]
    assert spec.rules[0].at_field == "expire_at"
    assert spec.rules[1].field == "forgotten"
    assert spec.rules[1].reversible is False, "a revocation is not a hypothesis"
    assert OPTIONS["notes"] == {"on_delete": "revoke", "sealed": (),
                                "scope_field": "tenant_id"}, (
        "OPTIONS carries the policy choices that are not rules; asserting "
        "the whole dict rather than one key is deliberate, so a new one "
        "cannot be added without a reader of this file finding out")


def test_the_whole_vocabulary_compiles(tmp_path):
    """Every word the README offers has to actually work. A documented
    declaration that raises is worse than an undocumented one."""
    spec = load(write(tmp_path, """
from voyd import (guard, deadline, revocable, holdable, tenant,
                  restricted_to, embedded_with, budget, distinct, sealed)

@guard("everything")
class E:
    expire_at  = deadline()
    forgotten  = revocable()
    held       = holdable()
    tenant_id  = tenant()
    audience   = restricted_to("groups")
    model      = embedded_with("voyage-3")
    tokens     = budget(8000)
    chunk      = distinct()
    secret     = sealed()
"""))["everything"]
    assert spec.tenant == "tenant_id"
    assert [type(r).__name__ for r in spec.rules] == [
        "Deadline", "Marked", "Marked", "Restricted", "EmbeddedWith",
        "Budget", "Distinct", "Unrecoverable"], (
        "eight rules; tenant is a scope, not a rule. sealed() contributes "
        "an Unrecoverable so a ciphertext field that reaches a read path "
        "which never decrypted it is refused by name rather than "
        "serialised into a prompt as a Binary pretending to be text")


@pytest.mark.parametrize("body,why", [
    ("@guard('n')\nclass N:\n    pass",
     "a guard that refuses nothing is a slower read"),
    ("from voyd import deadline\n@guard('n')\nclass N:\n"
     "    a = deadline()\n    b = deadline()",
     "two clocks is the drift this exists to remove"),
    ("from voyd import tenant\n@guard('n')\nclass N:\n"
     "    a = tenant()\n    b = tenant()",
     "a scope with two keys is not a scope"),
    ("from voyd import deadline\n@guard('n', on_delete='revoke')\nclass N:\n"
     "    a = deadline()",
     "nowhere to write the mark, so the delete would do nothing"),
    ("from voyd import deadline\n@guard('n', on_delete='yolo')\nclass N:\n"
     "    a = deadline()",
     "an unknown on_delete is a typo, not a policy"),
], ids=["no rules", "two deadlines", "two tenants",
        "revoke with no mark", "unknown on_delete"])
def test_a_policy_file_that_is_wrong_fails_at_load(tmp_path, body, why):
    with pytest.raises(ValueError):
        load(write(tmp_path, "from voyd import guard\n" + body))


def test_an_empty_policy_file_is_refused(tmp_path):
    """A file with no `@guard` would start a boundary that refuses nothing,
    silently. That is this project's one unforgivable failure, committed by
    its own front door."""
    with pytest.raises(ValueError, match="declared no collections"):
        load(write(tmp_path, "x = 1\n"))


def test_the_shipped_example_policy_file_is_valid():
    """`voydfile.py` is the first thing anybody copies."""
    specs = load("voydfile.py")
    assert "notes" in specs
    assert OPTIONS["notes"]["on_delete"] == "revoke"
