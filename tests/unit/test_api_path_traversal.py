"""
Regression tests for path traversal in the unified REST API.

Covers T-03 / T-04 from the CodeQL triage
(~/workspace/tmp-work/blncs-codeql-triage.md):

- ``GET /api/logs/analyze`` and ``GET /api/logs/report`` used to open any
  path given in the ``path`` query parameter. They are now confined to
  the log manager's log directory.
- ``POST /api/metrics/export`` only rejected ``..`` and non-.json names,
  so an absolute path could write JSON anywhere the process can write.
  Exports are now confined to an ``exports`` directory under the
  working directory.

Rejection must be fail-secure: nothing is read back and nothing is
written when validation fails.
"""

import json
import os

import pytest

SECRET_MARKER = "TOP-SECRET-OUTSIDE-CONTENT"


@pytest.fixture()
def api_env(tmp_path, monkeypatch):
    import blncs.api.unified_rest_api as api_module
    import blncs.core.unified_logging as logging_module
    from blncs.core.simple_auth import SimpleAuth
    from blncs.core.unified_logging import LogManager

    auth = SimpleAuth(storage_path=str(tmp_path / "auth.json"))
    monkeypatch.setattr(api_module, "_auth", auth)
    read_key = auth.generate_api_key("reader", {"read": True, "write": False})
    write_key = auth.generate_api_key("writer", {"read": True, "write": True})

    # Point the log manager singleton at an isolated log directory and
    # run the process from tmp_path so the exports directory lands there.
    logs_dir = tmp_path / "logs"
    manager = LogManager(logs_dir=str(logs_dir))
    monkeypatch.setattr(logging_module, "_log_manager", manager)
    monkeypatch.chdir(tmp_path)

    app = api_module.create_app()
    app.testing = True
    return app.test_client(), read_key, write_key, tmp_path, logs_dir


def _auth_header(key):
    return {"Authorization": f"Bearer {key}"}


def _write_log(path):
    entry = {
        "timestamp": "2999-01-01T00:00:00+00:00",
        "level": "INFO",
        "logger": "test",
        "message": "hello from inside the log directory",
    }
    path.write_text(json.dumps(entry) + "\n", encoding="utf-8")


def _write_secret_outside(tmp_path):
    secret = tmp_path / "secret.log"
    secret.write_text(SECRET_MARKER + "\n", encoding="utf-8")
    return secret


# --- /api/logs/analyze -------------------------------------------------------


def test_analyze_default_log_file_inside_log_dir(api_env):
    client, read_key, _, _, logs_dir = api_env
    _write_log(logs_dir / "blncs.log")

    resp = client.get("/api/logs/analyze", headers=_auth_header(read_key))

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["file_info"]["size"] > 0
    assert body["statistics"]["total_entries"] == 1


def test_analyze_absolute_path_inside_log_dir(api_env):
    client, read_key, _, _, logs_dir = api_env
    log_file = logs_dir / "blncs.log"
    _write_log(log_file)

    resp = client.get(
        f"/api/logs/analyze?path={log_file}", headers=_auth_header(read_key)
    )

    assert resp.status_code == 200


def test_analyze_absolute_path_outside_is_rejected(api_env):
    client, read_key, _, tmp_path, _ = api_env
    secret = _write_secret_outside(tmp_path)

    resp = client.get(
        f"/api/logs/analyze?path={secret}", headers=_auth_header(read_key)
    )

    assert resp.status_code == 400
    assert SECRET_MARKER not in resp.get_data(as_text=True)


def test_analyze_dotdot_escape_is_rejected(api_env):
    client, read_key, _, tmp_path, _ = api_env
    _write_secret_outside(tmp_path)

    resp = client.get(
        "/api/logs/analyze?path=../secret.log", headers=_auth_header(read_key)
    )

    assert resp.status_code == 400
    assert SECRET_MARKER not in resp.get_data(as_text=True)


def test_analyze_symlink_escape_is_rejected(api_env):
    client, read_key, _, tmp_path, logs_dir = api_env
    secret = _write_secret_outside(tmp_path)
    link = logs_dir / "linked.log"
    try:
        os.symlink(secret, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available in this environment")

    resp = client.get(
        "/api/logs/analyze?path=linked.log", headers=_auth_header(read_key)
    )

    assert resp.status_code == 400
    assert SECRET_MARKER not in resp.get_data(as_text=True)


def test_analyze_missing_file_inside_log_dir_still_reports_error(api_env):
    client, read_key, _, _, _ = api_env

    resp = client.get(
        "/api/logs/analyze?path=no-such.log", headers=_auth_header(read_key)
    )

    assert resp.status_code == 400
    assert "does not exist" in resp.get_json()["error"]


# --- /api/logs/report --------------------------------------------------------


def test_report_inside_log_dir(api_env):
    client, read_key, _, _, logs_dir = api_env
    _write_log(logs_dir / "blncs.log")

    resp = client.get("/api/logs/report", headers=_auth_header(read_key))

    assert resp.status_code == 200
    assert resp.get_json()["statistics"]["total_entries"] == 1


def test_report_dotdot_escape_is_rejected(api_env):
    client, read_key, _, tmp_path, _ = api_env
    _write_secret_outside(tmp_path)

    resp = client.get(
        "/api/logs/report?path=../secret.log", headers=_auth_header(read_key)
    )

    assert resp.status_code == 400
    assert SECRET_MARKER not in resp.get_data(as_text=True)


# --- /api/metrics/export -----------------------------------------------------


def test_export_default_name_writes_into_exports_dir(api_env):
    client, _, write_key, tmp_path, _ = api_env

    resp = client.post("/api/metrics/export", headers=_auth_header(write_key))

    assert resp.status_code == 200
    exported = tmp_path / "exports" / "metrics_export.json"
    assert exported.exists()
    json.loads(exported.read_text(encoding="utf-8"))


def test_export_subdirectory_inside_exports_dir(api_env):
    client, _, write_key, tmp_path, _ = api_env

    resp = client.post(
        "/api/metrics/export?path=sub/report.json",
        headers=_auth_header(write_key),
    )

    assert resp.status_code == 200
    assert (tmp_path / "exports" / "sub" / "report.json").exists()


def test_export_absolute_path_outside_is_rejected_and_writes_nothing(api_env):
    client, _, write_key, tmp_path, _ = api_env
    target = tmp_path / "evil.json"

    resp = client.post(
        f"/api/metrics/export?path={target}", headers=_auth_header(write_key)
    )

    assert resp.status_code == 400
    assert not target.exists()


def test_export_dotdot_escape_is_rejected_and_writes_nothing(api_env):
    client, _, write_key, tmp_path, _ = api_env
    target = tmp_path / "evil.json"

    resp = client.post(
        "/api/metrics/export?path=../evil.json", headers=_auth_header(write_key)
    )

    assert resp.status_code == 400
    assert not target.exists()


def test_export_symlink_escape_is_rejected_and_writes_nothing(api_env):
    client, _, write_key, tmp_path, _ = api_env
    exports_dir = tmp_path / "exports"
    exports_dir.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        os.symlink(outside, exports_dir / "link", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available in this environment")

    resp = client.post(
        "/api/metrics/export?path=link/evil.json",
        headers=_auth_header(write_key),
    )

    assert resp.status_code == 400
    assert not (outside / "evil.json").exists()


def test_export_non_json_extension_is_rejected(api_env):
    client, _, write_key, tmp_path, _ = api_env

    resp = client.post(
        "/api/metrics/export?path=notes.txt", headers=_auth_header(write_key)
    )

    assert resp.status_code == 400
    assert not (tmp_path / "exports" / "notes.txt").exists()
