import asyncio
import json
from pathlib import Path

import pytest

from blncs.core.simple_auth import SimpleAuth
from blncs_fast import BLNCSCLIOptimized


@pytest.fixture()
def auth_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for env_var in (
        "BLNCS_API_TOKEN",
        "BLNCS_API_TOKEN_ID",
        "BLNCS_API_TOKEN_PERMISSIONS",
        "BLNCS_API_TOKEN_TTL",
        "BLNCS_API_TOKEN_EXPIRES_AT",
        "BLNCS_CLI_TOKEN",
        "BLNCS_CLI_TOKEN_ID",
        "BLNCS_CLI_TOKEN_PERMISSIONS",
        "BLNCS_CLI_TOKEN_TTL",
        "BLNCS_CLI_TOKEN_EXPIRES_AT",
    ):
        monkeypatch.delenv(env_var, raising=False)

    return tmp_path / "auth.json"


def _run_cli(args: list[str], capsys) -> str:
    cli = BLNCSCLIOptimized()
    parsed = cli.parser.parse_args(args)
    asyncio.run(cli.execute_command(parsed))
    captured = capsys.readouterr()
    return captured.out


def test_auth_list_empty_returns_empty_array(auth_file: Path, capsys):
    output = _run_cli(["auth", "--auth-file", str(auth_file), "list"], capsys)
    assert json.loads(output) == []


def test_auth_create_generates_key_and_persists(auth_file: Path, capsys):
    output = _run_cli(
        [
            "auth",
            "--auth-file",
            str(auth_file),
            "create",
            "ops",
            "--permissions",
            "read,write",
            "--expires-in",
            "120",
        ],
        capsys,
    )
    lines = [line.strip() for line in output.strip().splitlines() if line.strip()]
    assert lines[0] == "API key created successfully."
    assert lines[1] == "Token ID: ops"
    api_key = lines[2].split(": ", 1)[1]

    auth = SimpleAuth(str(auth_file))
    token = auth.validate_api_key(api_key)
    assert token is not None
    assert token.permissions["write"] is True

    list_output = _run_cli(["auth", "--auth-file", str(auth_file), "list"], capsys)
    listed = json.loads(list_output)
    assert listed[0]["token_id"] == "ops"
    assert "api_key_hash" not in listed[0]


def test_auth_create_emits_audit_log(auth_file: Path, capsys, caplog):
    caplog.set_level("INFO", logger="blncs.auth")
    _run_cli(
        [
            "auth",
            "--auth-file",
            str(auth_file),
            "create",
            "ops",
        ],
        capsys,
    )

    messages = [record.getMessage() for record in caplog.records if record.name == "blncs.auth"]
    assert any("AUTH_KEY_CREATED" in msg and "token_id=ops" in msg for msg in messages)


def test_auth_revoke_removes_token(auth_file: Path, capsys):
    create_output = _run_cli(
        ["auth", "--auth-file", str(auth_file), "create", "ops"],
        capsys,
    )
    api_key = [line for line in create_output.splitlines() if line.startswith("API Key:")][0].split(": ", 1)[1]

    revoke_output = _run_cli(["auth", "--auth-file", str(auth_file), "revoke", "ops"], capsys)
    assert "revoked successfully" in revoke_output

    auth = SimpleAuth(str(auth_file))
    assert auth.validate_api_key(api_key) is None

    missing_output = _run_cli(["auth", "--auth-file", str(auth_file), "revoke", "ops"], capsys)
    assert "No matching API key found" in missing_output


def test_auth_rotate_by_token_id(auth_file: Path, capsys):
    create_output = _run_cli(
        [
            "auth",
            "--auth-file",
            str(auth_file),
            "create",
            "ops",
            "--permissions",
            "read",
        ],
        capsys,
    )
    original_key = [line for line in create_output.splitlines() if line.startswith("API Key:")][0].split(": ", 1)[1]

    rotate_output = _run_cli(
        [
            "auth",
            "--auth-file",
            str(auth_file),
            "rotate",
            "--token-id",
            "ops",
            "--permissions",
            "read,write",
            "--expires-in",
            "300",
        ],
        capsys,
    )
    new_key = [line for line in rotate_output.splitlines() if line.startswith("New API Key:")][0].split(": ", 1)[1]
    assert new_key != original_key

    auth = SimpleAuth(str(auth_file))
    assert auth.validate_api_key(original_key) is None
    rotated_token = auth.validate_api_key(new_key)
    assert rotated_token is not None
    assert rotated_token.permissions["write"] is True


def test_auth_rotate_by_api_key(auth_file: Path, capsys):
    create_output = _run_cli(
        ["auth", "--auth-file", str(auth_file), "create", "ops"],
        capsys,
    )
    original_key = [line for line in create_output.splitlines() if line.startswith("API Key:")][0].split(": ", 1)[1]

    rotate_output = _run_cli(
        [
            "auth",
            "--auth-file",
            str(auth_file),
            "rotate",
            "--api-key",
            original_key,
        ],
        capsys,
    )
    new_key = [line for line in rotate_output.splitlines() if line.startswith("New API Key:")][0].split(": ", 1)[1]
    assert new_key != original_key

    auth = SimpleAuth(str(auth_file))
    assert auth.validate_api_key(original_key) is None
    rotated_token = auth.validate_api_key(new_key)
    assert rotated_token is not None
    assert rotated_token.permissions["read"] is True
    assert rotated_token.permissions["write"] is False


def test_auth_rotate_emits_audit_log(auth_file: Path, capsys, caplog):
    caplog.set_level("INFO", logger="blncs.auth")
    create_output = _run_cli(
        ["auth", "--auth-file", str(auth_file), "create", "ops"],
        capsys,
    )
    original_key = [line for line in create_output.splitlines() if line.startswith("API Key:")][0].split(": ", 1)[1]

    _run_cli(
        [
            "auth",
            "--auth-file",
            str(auth_file),
            "rotate",
            "--api-key",
            original_key,
        ],
        capsys,
    )

    messages = [record.getMessage() for record in caplog.records if record.name == "blncs.auth"]
    assert any("AUTH_KEY_ROTATED" in msg and "token_id=ops" in msg for msg in messages)


def test_auth_show_existing_token(auth_file: Path, capsys):
    _run_cli(["auth", "--auth-file", str(auth_file), "create", "ops"], capsys)

    show_output = _run_cli(["auth", "--auth-file", str(auth_file), "show", "ops"], capsys)
    data = json.loads(show_output)
    assert data["token_id"] == "ops"
    assert "api_key_hash" not in data


def test_auth_show_missing_token(auth_file: Path, capsys):
    output = _run_cli(["auth", "--auth-file", str(auth_file), "show", "missing"], capsys)
    assert output.strip() == "Token not found."


def test_auth_audit_reads_recent_events(tmp_path: Path, capsys):
    log_file = tmp_path / "blncs.log"
    log_file.write_text(
        """
2024-01-01 INFO something else
2024-01-01 INFO AUTH_KEY_CREATED token_id=ops
2024-01-01 INFO AUTH_KEY_ROTATED token_id=ops
2024-01-01 INFO AUTH_KEY_REVOKED token_id=ops
""".strip(),
        encoding="utf-8",
    )

    output = _run_cli(
        [
            "auth",
            "audit",
            "--log-file",
            str(log_file),
            "--limit",
            "2",
        ],
        capsys,
    )
    events = json.loads(output)
    assert len(events) == 2
    assert events[0]["event"].endswith("AUTH_KEY_ROTATED token_id=ops")
    assert events[1]["event"].endswith("AUTH_KEY_REVOKED token_id=ops")


def test_auth_audit_handles_missing_file(capsys):
    output = _run_cli(
        [
            "auth",
            "audit",
            "--log-file",
            "non-existent.log",
        ],
        capsys,
    )
    assert output.strip() == "No audit events found."


def test_auth_stats_outputs_inventory(auth_file: Path, capsys):
    _run_cli([
        "auth",
        "--auth-file",
        str(auth_file),
        "create",
        "ops",
        "--expires-in",
        "60",
    ], capsys)

    output = _run_cli([
        "auth",
        "--auth-file",
        str(auth_file),
        "stats",
        "--window-seconds",
        "120",
    ], capsys)

    data = json.loads(output)
    assert data["total_tokens"] == 1
    assert data["active_tokens"] == 1
    assert data["expired_tokens"] == 0
    assert data["expiring_within_seconds"] == 120


def test_auth_prune_removes_tokens(auth_file: Path, capsys):
    create_output = _run_cli([
        "auth",
        "--auth-file",
        str(auth_file),
        "create",
        "ops",
        "--expires-in",
        "1",
    ], capsys)

    lines = [line.strip() for line in create_output.splitlines() if line.strip()]
    assert any(line.startswith("API Key:") for line in lines)

    result = _run_cli([
        "auth",
        "--auth-file",
        str(auth_file),
        "prune",
        "--include-expired",
        "--dry-run",
    ], capsys)
    dry = json.loads(result)
    assert dry["dry_run"] is True

    result = _run_cli([
        "auth",
        "--auth-file",
        str(auth_file),
        "prune",
        "--include-expired",
    ], capsys)
    pruned = json.loads(result)
    assert pruned["dry_run"] is False
    assert pruned["pruned"] == ["ops"]
    assert pruned["remaining_tokens"] == 0
