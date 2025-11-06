import os
import json
import time
import sys
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import tempfile
from pathlib import Path

import pytest

from blncs.core.simple_auth import SimpleAuth, AuthToken


@pytest.fixture()
def temp_auth_file(tmp_path: Path):
    auth_path = tmp_path / "auth.json"
    yield auth_path


def load_auth_json(path: Path):
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def test_generate_api_key_stores_hashed_secret(temp_auth_file):
    auth = SimpleAuth(str(temp_auth_file))

    api_key = auth.generate_api_key("service")
    token = auth.validate_api_key(api_key)

    assert token is not None
    assert token.api_key is None
    assert token.api_key_hash
    assert token.salt
    assert token.iterations >= 200000

    persisted = load_auth_json(temp_auth_file)
    assert persisted is not None
    stored_tokens = persisted["tokens"]
    assert stored_tokens
    stored_entry = stored_tokens[0]
    assert "api_key" not in stored_entry
    assert stored_entry["api_key_hash"] == token.api_key_hash


def test_rotate_api_key_invalidates_old_key(temp_auth_file):
    auth = SimpleAuth(str(temp_auth_file))
    original_key = auth.generate_api_key("operator", permissions={"read": True, "write": True})

    new_key = auth.rotate_api_key(original_key, expires_in=10)
    assert new_key != original_key

    assert auth.validate_api_key(original_key) is None

    rotated = auth.validate_api_key(new_key)
    assert rotated is not None
    assert rotated.usage_count == 1
    assert rotated.expires_at is not None


def test_require_auth_enforces_permissions(temp_auth_file):
    auth = SimpleAuth(str(temp_auth_file))
    read_only_key = auth.generate_api_key("reader", permissions={"read": True, "write": False})
    writer_key = auth.generate_api_key("writer", permissions={"read": True, "write": True})

    protected_fn_calls = {"read": 0, "write": 0}

    @auth.require_auth("read")
    def read_endpoint(*, auth_token: AuthToken):
        protected_fn_calls["read"] += 1
        return {"ok": True, "token": auth_token.token_id}

    @auth.require_auth("write")
    def write_endpoint(*, auth_token: AuthToken):
        protected_fn_calls["write"] += 1
        return {"ok": True, "token": auth_token.token_id}

    # Read should pass for both tokens
    response = read_endpoint(api_key=read_only_key)
    assert response[0]["ok"] is True

    response = read_endpoint(api_key=writer_key)
    assert response[0]["ok"] is True

    # Write should fail for read-only
    response = write_endpoint(api_key=read_only_key)
    assert isinstance(response, tuple)
    assert response[1] == 403

    response = write_endpoint(api_key=writer_key)
    assert response[0]["ok"] is True
    assert protected_fn_calls["write"] == 1


def test_session_invalidated_after_token_revocation(temp_auth_file):
    auth = SimpleAuth(str(temp_auth_file))
    key = auth.generate_api_key("session_user")
    token = auth.validate_api_key(key)

    session_id = auth.create_session(token)
    assert auth.validate_session(session_id) is not None

    auth.revoke_api_key(key)
    assert auth.validate_session(session_id) is None


def test_env_api_token_loaded_and_updated(monkeypatch, temp_auth_file):
    monkeypatch.setenv("BLNCS_API_TOKEN", "blncs_envtoken_sample")
    monkeypatch.setenv("BLNCS_API_TOKEN_ID", "ops_env")
    monkeypatch.setenv("BLNCS_API_TOKEN_PERMISSIONS", "read,write")
    monkeypatch.setenv("BLNCS_API_TOKEN_TTL", "120")

    auth = SimpleAuth(str(temp_auth_file))
    token = auth.validate_api_key("blncs_envtoken_sample")
    assert token is not None
    assert token.token_id == "ops_env"
    assert token.permissions == {"read": True, "write": True, "admin": False}
    assert token.expires_at is not None
    assert token.api_key_hash and token.salt

    stored = load_auth_json(temp_auth_file)
    assert stored is not None
    assert stored["tokens"][0]["token_id"] == "ops_env"

    future = datetime.now(timezone.utc) + timedelta(hours=1)
    iso_expiration = future.isoformat()
    monkeypatch.setenv("BLNCS_API_TOKEN_PERMISSIONS", "read")
    monkeypatch.delenv("BLNCS_API_TOKEN_TTL", raising=False)
    monkeypatch.setenv("BLNCS_API_TOKEN_EXPIRES_AT", iso_expiration)

    auth_reload = SimpleAuth(str(temp_auth_file))
    updated = auth_reload.validate_api_key("blncs_envtoken_sample")
    assert updated is not None
    assert updated.permissions == {"read": True, "write": False, "admin": False}
    assert pytest.approx(updated.expires_at, rel=0.0, abs=1.0) == future.timestamp()


def test_env_cli_token_loaded_and_updated(monkeypatch, temp_auth_file):
    monkeypatch.setenv("BLNCS_CLI_TOKEN", "blncs_cli_env_token")
    monkeypatch.setenv("BLNCS_CLI_TOKEN_ID", "cli_ops")
    monkeypatch.setenv("BLNCS_CLI_TOKEN_PERMISSIONS", "read,write")
    monkeypatch.setenv("BLNCS_CLI_TOKEN_TTL", "90")

    auth = SimpleAuth(str(temp_auth_file))
    token = auth.validate_api_key("blncs_cli_env_token")
    assert token is not None
    assert token.token_id == "cli_ops"
    assert token.permissions == {"read": True, "write": True, "admin": False}
    assert token.expires_at is not None

    stored = load_auth_json(temp_auth_file)
    assert stored is not None
    identifiers = {entry["token_id"] for entry in stored["tokens"]}
    assert "cli_ops" in identifiers

    expiry_epoch = str(int(time.time()) + 300)
    monkeypatch.setenv("BLNCS_CLI_TOKEN_PERMISSIONS", "admin")
    monkeypatch.delenv("BLNCS_CLI_TOKEN_TTL", raising=False)
    monkeypatch.setenv("BLNCS_CLI_TOKEN_EXPIRES_AT", expiry_epoch)

    auth_reload = SimpleAuth(str(temp_auth_file))
    updated = auth_reload.validate_api_key("blncs_cli_env_token")
    assert updated is not None
    assert updated.permissions == {"read": False, "write": False, "admin": True}
    assert pytest.approx(updated.expires_at, rel=0.0, abs=1.0) == float(expiry_epoch)


def test_collect_request_metadata_generates_correlation(monkeypatch, temp_auth_file):
    monkeypatch.delenv("BLNCS_API_TOKEN", raising=False)
    auth = SimpleAuth(str(temp_auth_file))
    metadata = auth._collect_request_metadata()
    assert metadata["correlation_id"] is not None
    assert len(metadata["correlation_id"]) == 32


def test_collect_request_metadata_prefers_request_header(monkeypatch, temp_auth_file):
    dummy_request = SimpleNamespace(
        path="/api/test",
        method="GET",
        headers={
            "X-Request-ID": "req-123",
            "X-Forwarded-For": "10.0.0.2",
        },
        remote_addr="10.0.0.1",
        environ={"REQUEST_ID": "fallback-id"},
    )

    class DummyFlaskModule:
        request = dummy_request

    original_flask = sys.modules.get("flask")
    monkeypatch.setitem(sys.modules, "flask", DummyFlaskModule())

    try:
        auth = SimpleAuth(str(temp_auth_file))
        metadata = auth._collect_request_metadata()
        assert metadata["endpoint"] == "/api/test"
        assert metadata["method"] == "GET"
        assert metadata["client_ip"] == "10.0.0.2"
        assert metadata["correlation_id"] == "req-123"
    finally:
        if original_flask is not None:
            monkeypatch.setitem(sys.modules, "flask", original_flask)
        else:
            monkeypatch.delitem(sys.modules, "flask", raising=False)


def test_export_statistics_reports_counts(temp_auth_file):
    auth = SimpleAuth(str(temp_auth_file))
    now = time.time()
    active_key = auth.generate_api_key(
        "active",
        permissions={"read": True},
        expires_at=now + 1_800,
    )
    auth.validate_api_key(active_key)
    auth.generate_api_key(
        "expired",
        permissions={"read": True},
        expires_at=now - 60,
    )

    stats = auth.export_statistics(window_seconds=2_000)
    assert stats["total_tokens"] == 2
    assert stats["active_tokens"] == 1
    assert stats["expired_tokens"] == 1
    assert "active" in stats["expiring_soon"]
    assert stats["never_used_tokens"] == 1
    assert stats["max_usage_count"] >= 1


def test_prune_tokens_supports_dry_run_and_execution(temp_auth_file):
    auth = SimpleAuth(str(temp_auth_file))
    now = time.time()
    auth.generate_api_key("idle", permissions={"read": True})
    auth.generate_api_key(
        "expired",
        permissions={"read": True},
        expires_at=now - 60,
    )

    with auth._lock:
        idle_token = auth._tokens["idle"]
        idle_token.updated_at = now - 3_600
        idle_token.last_used_at = None

    dry = auth.prune_tokens(include_expired=True, idle_seconds=1_800, dry_run=True)
    assert dry["dry_run"] is True
    assert {entry["token_id"] for entry in dry["matched"]} == {"idle", "expired"}
    assert dry["pruned"] == []

    result = auth.prune_tokens(include_expired=True, idle_seconds=1_800, dry_run=False)
    assert result["dry_run"] is False
    assert set(result["pruned"]) == {"idle", "expired"}
    assert auth.list_tokens() == []
