"""Regression tests for the master key source.

The master key must never be read from, or written to, the source
tree. It comes from the ``BLNCS_MASTER_KEY`` environment variable
(base64-encoded) or from ``~/.blncs/master.key`` — the same outside
location BLNCS already uses for its database, logs and backups.
"""

import base64
import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import blncs.core.unified_security as unified_security
from blncs.core.unified_security import EncryptionManager, get_security_manager

REPO_ROOT = Path(__file__).resolve().parents[2]
KNOWN_KEY = bytes(range(32))


@pytest.fixture(autouse=True)
def clean_master_key_env(monkeypatch):
    monkeypatch.delenv("BLNCS_MASTER_KEY", raising=False)
    yield


def test_env_var_supplies_master_key(monkeypatch):
    encoded = base64.urlsafe_b64encode(KNOWN_KEY).decode()
    monkeypatch.setenv("BLNCS_MASTER_KEY", encoded)

    manager = EncryptionManager()

    assert manager.master_key == KNOWN_KEY
    token = manager.encrypt_string("secret payload")
    assert manager.decrypt_string(token) == "secret payload"


def test_env_var_accepts_standard_base64_without_padding(monkeypatch):
    encoded = base64.b64encode(KNOWN_KEY).decode().rstrip("=")
    monkeypatch.setenv("BLNCS_MASTER_KEY", encoded)

    assert EncryptionManager().master_key == KNOWN_KEY


def test_invalid_env_var_fails_with_reason(monkeypatch):
    monkeypatch.setenv("BLNCS_MASTER_KEY", "!!! not base64 !!!")

    with pytest.raises(ValueError, match="BLNCS_MASTER_KEY"):
        EncryptionManager()


def test_data_encrypted_with_old_key_readable_via_env_var(monkeypatch):
    # Data encrypted with the previously used key bytes stays readable
    # when the same key is supplied through the environment (migration
    # path documented in README_PERSONAL.md).
    legacy = EncryptionManager(master_key=KNOWN_KEY)
    token = legacy.encrypt_string("legacy data")

    monkeypatch.setenv("BLNCS_MASTER_KEY", base64.urlsafe_b64encode(KNOWN_KEY).decode())
    migrated = EncryptionManager()

    assert migrated.decrypt_string(token) == "legacy data"


def test_key_generated_outside_repo_and_reused(monkeypatch, tmp_path):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(tmp_path)

    first = EncryptionManager()
    key_file = home / ".blncs" / "master.key"

    assert key_file.exists()
    assert key_file.read_bytes() == first.master_key
    assert stat.S_IMODE(os.stat(key_file).st_mode) == 0o600

    # Nothing is created inside the working tree.
    assert not (tmp_path / "config" / "master.key").exists()

    second = EncryptionManager()
    assert second.master_key == first.master_key
    token = first.encrypt_string("round trip")
    assert second.decrypt_string(token) == "round trip"


def test_existing_key_file_outside_repo_is_loaded(monkeypatch, tmp_path):
    home = tmp_path / "home"
    key_dir = home / ".blncs"
    key_dir.mkdir(parents=True)
    (key_dir / "master.key").write_bytes(KNOWN_KEY)
    monkeypatch.setenv("HOME", str(home))

    assert EncryptionManager().master_key == KNOWN_KEY


def test_env_var_takes_precedence_over_key_file(monkeypatch, tmp_path):
    home = tmp_path / "home"
    key_dir = home / ".blncs"
    key_dir.mkdir(parents=True)
    (key_dir / "master.key").write_bytes(b"\xff" * 32)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("BLNCS_MASTER_KEY", base64.urlsafe_b64encode(KNOWN_KEY).decode())

    assert EncryptionManager().master_key == KNOWN_KEY


def test_security_manager_startup_path_uses_outside_key(monkeypatch, tmp_path):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(unified_security, "_security_manager", None)

    manager = get_security_manager()

    token = manager.encryption.encrypt_string("via manager")
    assert manager.encryption.decrypt_string(token) == "via manager"
    assert (home / ".blncs" / "master.key").exists()

    monkeypatch.setattr(unified_security, "_security_manager", None)


def test_no_key_files_tracked_in_repo_tree():
    assert not (REPO_ROOT / "config" / "master.key").exists()
    assert not (REPO_ROOT / "config" / "encryption.key").exists()
