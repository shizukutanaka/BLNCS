import importlib
from types import SimpleNamespace

import pytest


class AuthStub:
    def __init__(self):
        self.limits = {'max_attempts': 5, 'window_seconds': 60}
        self.export_calls = 0
        self.update_calls = []
        self.cleared = 0

    def export_failure_limits(self):
        self.export_calls += 1
        return self.limits.copy()

    def update_failure_limits(self, max_attempts=None, window_seconds=None):
        self.update_calls.append((max_attempts, window_seconds))
        if max_attempts is not None:
            self.limits['max_attempts'] = max_attempts
        if window_seconds is not None:
            self.limits['window_seconds'] = window_seconds

    def clear_all_failures(self):
        self.cleared += 1


class LoggerStub:
    def __init__(self):
        self.entries = []

    def info(self, msg, *args):
        message = msg % args if args else msg
        self.entries.append(('info', message))


class TokenStub:
    def __init__(self, permissions):
        self.permissions = permissions
        self.update_usage_calls = 0

    def has_permission(self, permission):
        return self.permissions.get(permission, False)

    def update_usage(self):
        self.update_usage_calls += 1


@pytest.fixture()
def security_cli(monkeypatch):
    module = importlib.import_module('blncs_main')
    auth_stub = AuthStub()
    monkeypatch.setattr('blncs.core.simple_auth.get_auth', lambda: auth_stub)
    logger_stub = LoggerStub()
    return module, auth_stub, logger_stub


def test_security_show_limits(security_cli, capsys):
    module, auth_stub, logger_stub = security_cli
    args = SimpleNamespace(
        show_auth_limits=True,
        set_auth_limits=None,
        reset_auth_failures=False
    )

    module.cmd_security(args, config=None, logger=logger_stub)

    captured = capsys.readouterr()
    assert 'Authentication failure limiter settings:' in captured.out
    assert 'Max attempts: 5' in captured.out
    assert 'Window seconds: 60' in captured.out
    assert auth_stub.export_calls == 1
    assert logger_stub.entries == []


def test_security_set_limits(security_cli, capsys):
    module, auth_stub, logger_stub = security_cli
    args = SimpleNamespace(
        show_auth_limits=False,
        set_auth_limits=(3, 120),
        reset_auth_failures=False
    )

    module.cmd_security(args, config=None, logger=logger_stub)

    assert auth_stub.update_calls == [(3, 120)]
    assert auth_stub.limits == {'max_attempts': 3, 'window_seconds': 120}
    assert ('info', 'Authentication failure limits updated: max_attempts=3 window_seconds=120') in logger_stub.entries

    captured = capsys.readouterr()
    assert 'Updated authentication failure limits.' in captured.out


def test_security_reset_failures(security_cli, capsys):
    module, auth_stub, logger_stub = security_cli
    args = SimpleNamespace(
        show_auth_limits=False,
        set_auth_limits=None,
        reset_auth_failures=True
    )

    module.cmd_security(args, config=None, logger=logger_stub)

    assert auth_stub.cleared == 1
    assert ('info', 'Authentication failure counters cleared') in logger_stub.entries

    captured = capsys.readouterr()
    assert 'Cleared authentication failure counters.' in captured.out


def test_security_no_action(security_cli, capsys):
    module, auth_stub, logger_stub = security_cli
    args = SimpleNamespace(
        show_auth_limits=False,
        set_auth_limits=None,
        reset_auth_failures=False
    )

    module.cmd_security(args, config=None, logger=logger_stub)

    captured = capsys.readouterr()
    assert 'No security action specified' in captured.out
    assert auth_stub.export_calls == 0
    assert auth_stub.update_calls == []
    assert auth_stub.cleared == 0
    assert logger_stub.entries == []


def test_determine_cli_permission_mapping(monkeypatch):
    module = importlib.import_module('blncs_main')

    cases = [
        ('invoice', SimpleNamespace(), 'write'),
        ('pay', SimpleNamespace(), 'write'),
        ('server', SimpleNamespace(), 'admin'),
        ('backup', SimpleNamespace(auto='start'), 'write'),
        ('backup', SimpleNamespace(auto=None, interval=120), 'write'),
        ('backup', SimpleNamespace(create=True), 'write'),
        ('backup', SimpleNamespace(list=True), None),
        ('backup', SimpleNamespace(restore=True), 'admin'),
        ('backup', SimpleNamespace(cleanup=True), 'write'),
        ('config', SimpleNamespace(set=('x', '1')), 'write'),
        ('config', SimpleNamespace(template=True), 'write'),
        ('cache', SimpleNamespace(clear=True, db_optimize=False), 'write'),
        ('logs', SimpleNamespace(action='rotate'), 'write'),
        ('maintenance', SimpleNamespace(run=['daily']), 'admin'),
        ('maintenance', SimpleNamespace(run=None, bundle='high'), 'admin'),
        ('security', SimpleNamespace(set_auth_limits=(5, 60), reset_auth_failures=False), 'admin'),
        ('unknown', SimpleNamespace(), None),
    ]

    for command, args, expected in cases:
        assert module._determine_cli_permission(command, args) == expected


def test_enforce_cli_permission_requires_token(monkeypatch):
    module = importlib.import_module('blncs_main')
    monkeypatch.delenv('BLNCS_CLI_TOKEN', raising=False)

    args = SimpleNamespace(auth_token=None)

    class AuthMock:
        def validate_api_key(self, value):  # pragma: no cover - interface stub
            return None

    monkeypatch.setattr('blncs.core.simple_auth.get_auth', lambda: AuthMock())

    with pytest.raises(SystemExit):
        module._enforce_cli_permission(args, 'write')


def test_enforce_cli_permission_denied(monkeypatch):
    module = importlib.import_module('blncs_main')

    args = SimpleNamespace(auth_token='bad')

    class AuthMock:
        def validate_api_key(self, value):
            return TokenStub({'write': False})

    monkeypatch.setattr('blncs.core.simple_auth.get_auth', lambda: AuthMock())

    with pytest.raises(SystemExit):
        module._enforce_cli_permission(args, 'write')


def test_enforce_cli_permission_success(monkeypatch):
    module = importlib.import_module('blncs_main')

    args = SimpleNamespace(auth_token='good')

    token = TokenStub({'write': True})

    class AuthMock:
        def validate_api_key(self, value):
            return token

    monkeypatch.setattr('blncs.core.simple_auth.get_auth', lambda: AuthMock())

    module._enforce_cli_permission(args, 'write')

    assert getattr(args, '_validated_auth_token') is token
