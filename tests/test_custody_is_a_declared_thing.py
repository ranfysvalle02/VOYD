"""Who holds the key that wraps the keys. No database required.

Crypto-shredding is exactly as strong as the answer to that question, and
the usual answer is a ``kms_providers`` dict assembled at a call site --
which is not an answer, it is a shape. These tests pin the two failures
that shape produces:

  * a keyring that always said ``"local"`` would accept an AWS configuration
    and quietly wrap the data key with a process-local secret instead. The
    deployment believes its keys are in KMS. They are in a variable.
  * a ``local`` default that is regenerated per process loses every key on
    restart, which is indistinguishable from having shredded all of them --
    so the default has to be *loud*, not merely documented.

Pure logic, so it runs without Mongo and without the encryption stack.
"""

from __future__ import annotations

import base64
import logging
import os

import pytest

from voyd.engine.custody import (LOCAL_KEY_BYTES, Aws, Azure, Ephemeral, Gcp,
                                 Kmip, LocalFile, from_env)


# ---- the ladder ranks itself ------------------------------------------

@pytest.mark.parametrize("custody, durable, audited", [
    (Ephemeral(), False, False),
    (LocalFile(path="/nonexistent/never-read"), True, False),
    (Aws(key="arn:aws:kms:us-east-1:1:key/k"), True, True),
    (Azure(key_name="k", key_vault_endpoint="https://v"), True, True),
    (Gcp(project_id="p", location="l", key_ring="r", key_name="k"), True, True),
    (Kmip(endpoint="host:5696"), True, True),
])
def test_every_rung_declares_what_it_actually_offers(custody, durable, audited):
    """``durable`` and ``audited`` are the two properties that decide
    whether a crypto claim can be written into a compliance document, so
    they are attributes rather than prose somebody has to interpret."""
    assert custody.durable is durable
    assert custody.audited is audited
    assert custody.describe()["detail"]


# ---- the bug this module exists to make impossible --------------------

def test_a_kms_custody_carries_the_provider_and_the_master_key():
    """The failure that was live before this existed.

    ``create_data_key`` takes a provider *name* and a provider-shaped
    ``master_key``. Hardcoding ``"local"`` means an AWS-configured
    deployment wraps its data keys with a process-local secret and never
    finds out -- there is no error, only a belief.
    """
    aws = Aws(key="arn:aws:kms:eu-west-1:123456789012:key/abc")
    assert aws.provider == "aws"
    assert aws.master_key() == {
        "region": "eu-west-1",
        "key": "arn:aws:kms:eu-west-1:123456789012:key/abc"}
    assert Ephemeral().master_key() is None, "local needs no master key"


def test_the_aws_region_comes_from_the_arn_so_they_cannot_disagree():
    """A region/ARN mismatch surfaces as an ``InvalidArnException`` several
    layers below the line that caused it."""
    assert Aws(key="arn:aws:kms:ap-south-1:1:key/k").master_key()["region"] \
        == "ap-south-1"
    # An explicit region still wins, for a non-ARN key id.
    assert Aws(key="alias/mine", region="us-west-2").master_key()["region"] \
        == "us-west-2"
    with pytest.raises(ValueError, match="CMK ARN"):
        Aws(key="alias/mine").master_key()


def test_omitting_aws_credentials_selects_the_credential_chain():
    """Not an oversight, the correct production shape: on EKS or an
    instance profile, baking an access key into a config file in order to
    encrypt something is a net loss."""
    assert Aws(key="arn:aws:kms:us-east-1:1:key/k").credentials() == {}
    keyed = Aws(key="arn:aws:kms:us-east-1:1:key/k",
                access_key_id="AK", secret_access_key="SK", session_token="T")
    assert keyed.credentials() == {"accessKeyId": "AK",
                                   "secretAccessKey": "SK",
                                   "sessionToken": "T"}


@pytest.mark.parametrize("custody, missing", [
    (Azure(key_name="k"), "key_vault_endpoint"),
    (Gcp(project_id="p"), "location"),
])
def test_an_incomplete_kms_custody_raises_at_construction_not_at_3am(
        custody, missing):
    with pytest.raises(ValueError, match=missing):
        custody.master_key()


# ---- the weak rungs are loud -------------------------------------------

def test_ephemeral_custody_warns_that_a_restart_loses_the_data(caplog):
    """The default must not be quietly wrong. Losing the master key is
    indistinguishable from having shredded every key in the vault, and a
    deployment that discovers that on its first restart discovers it with
    the data already unreadable."""
    with caplog.at_level(logging.WARNING):
        Ephemeral().warn_if_weak("keyring test.__keys")
    assert "regenerated on restart" in caplog.text


def test_a_file_backed_key_warns_about_custody_rather_than_durability(caplog):
    """A different warning, because it is a different problem: the
    mechanism is real and 'the key was destroyed' is still your word."""
    with caplog.at_level(logging.WARNING):
        LocalFile(path="/tmp/x").warn_if_weak("keyring test.__keys")
    assert "your word for it" in caplog.text
    assert "regenerated on restart" not in caplog.text


def test_a_kms_custody_warns_about_nothing(caplog):
    with caplog.at_level(logging.WARNING):
        Aws(key="arn:aws:kms:us-east-1:1:key/k").warn_if_weak("keyring x")
    assert caplog.text == ""


# ---- the durable local rung -------------------------------------------

def test_a_local_key_file_is_created_once_and_reused(tmp_path):
    """The rung most proofs of concept should be on. Created on first use
    rather than documented as a setup step, because a README step that half
    of readers skip becomes an ``Ephemeral`` deployment three weeks later.
    """
    path = tmp_path / "nested" / "master.key"
    first = LocalFile(path=path).credentials()["key"]
    assert len(first) == LOCAL_KEY_BYTES
    assert path.stat().st_mode & 0o777 == 0o600
    assert LocalFile(path=path).credentials()["key"] == first, \
        "a second process must get the same key, or the data is gone"


def test_a_base64_key_file_is_accepted_because_secrets_arrive_text_shaped(
        tmp_path):
    """Through a shell, an env var or a secrets manager, a key is text.
    Hashing it into the wrong 96 bytes would be a deployment that cannot
    read yesterday's data and cannot say why."""
    material = os.urandom(LOCAL_KEY_BYTES)
    path = tmp_path / "b64.key"
    path.write_bytes(base64.b64encode(material))
    assert LocalFile(path=path).credentials()["key"] == material


def test_a_wrong_length_key_file_refuses_rather_than_guessing(tmp_path):
    path = tmp_path / "short.key"
    path.write_bytes(b"too short to be a master key")
    with pytest.raises(ValueError, match="Refusing to guess"):
        LocalFile(path=path).credentials()


# ---- configuration from the environment --------------------------------

def test_from_env_falls_back_to_ephemeral_and_never_claims_audited(
        monkeypatch):
    """An unset environment is a demo. A demo that claimed to be audited is
    the worst outcome available in this module."""
    monkeypatch.delenv("T_PROVIDER", raising=False)
    assert from_env("T").audited is False


def test_from_env_builds_a_real_kms_custody(monkeypatch):
    monkeypatch.setenv("T_PROVIDER", "aws")
    monkeypatch.setenv("T_KEY", "arn:aws:kms:eu-central-1:1:key/k")
    custody = from_env("T")
    assert custody.provider == "aws" and custody.audited
    assert custody.master_key()["region"] == "eu-central-1"


def test_from_env_takes_a_required_prefix_rather_than_squatting():
    """This module is the generic engine. A library that claimed
    ``KMS_PROVIDER`` for itself would be squatting on every other
    library's configuration."""
    import inspect
    assert inspect.signature(from_env).parameters["prefix"].default \
        is inspect.Parameter.empty
