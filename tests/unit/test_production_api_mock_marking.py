"""Tests pinning the mock marking on production_api's Lightning endpoints.

``blncs.api.production_api`` presents itself as a production API, but
its Lightning endpoints are demonstrations: POST
/api/v1/lightning/payments used to return a fabricated ``SUCCEEDED``
payment and POST /api/v1/lightning/invoices a fabricated invoice,
with nothing in the responses revealing that no real payment or
invoice was ever involved.  Following the marking applied to
``blncs.api.commercial_unified_api`` in the payment-guard change,
those responses must carry ``"simulated": True`` and the module must
warn about the mock endpoints in its docstring.  These tests pin
that marking so it cannot silently disappear.

Test scaffolding note: production_api imports four sibling modules.
Three of them (blncs.core.production_security /
production_performance / production_stability) do not exist in this
repository, and blncs.monitoring.production_monitoring's
``monitor_api_request`` decorator drops the wrapped function's
``__name__``, which makes Flask route registration fail.  Until those
modules are restored, this test module installs minimal stand-ins for
the four imports *before* importing production_api, so the endpoint
code under test is the real thing.  No real payment is ever made:
the endpoints are simulations by construction.
"""

import functools
import sys
import types
from unittest.mock import MagicMock

import pytest


def _passthrough_factory(*dargs, **dkwargs):
    def deco(f):
        return f

    return deco


def _install_sibling_stubs():
    """Stand-ins for production_api's sibling imports (see docstring)."""
    if "blncs.core.production_security" not in sys.modules:
        sec = types.ModuleType("blncs.core.production_security")
        sec_manager = MagicMock()
        sec_manager.validate_session.return_value = True
        sec_manager.security_headers.return_value = {}
        sec_manager.create_secure_session.return_value = {
            "session_id": "test-session-id"
        }
        sec.get_security_manager = lambda: sec_manager
        sec.SecurityEvent = object
        sec.ErrorSeverity = object
        sys.modules["blncs.core.production_security"] = sec

    if "blncs.core.production_performance" not in sys.modules:
        perf = types.ModuleType("blncs.core.production_performance")
        perf_manager = MagicMock()
        perf_manager.optimize_all.return_value = []
        perf.get_performance_manager = lambda: perf_manager
        perf.monitor_performance = _passthrough_factory
        sys.modules["blncs.core.production_performance"] = perf

    if "blncs.core.production_stability" not in sys.modules:
        stab = types.ModuleType("blncs.core.production_stability")
        stab_manager = MagicMock()
        stab_manager.get_stability_report.return_value = {
            "system_state": "stable",
            "stability_score": 1.0,
        }
        stab.get_stability_manager = lambda: stab_manager
        stab.with_circuit_breaker = _passthrough_factory
        stab.with_retry = _passthrough_factory
        sys.modules["blncs.core.production_stability"] = stab

    if "blncs.monitoring.production_monitoring" not in sys.modules:
        mon = types.ModuleType("blncs.monitoring.production_monitoring")
        mon_system = MagicMock()
        mon_system.create_dashboard_data.return_value = {}
        mon.get_monitoring_system = lambda: mon_system

        def monitor_api_request(endpoint):
            def deco(f):
                @functools.wraps(f)
                def wrapper(*args, **kwargs):
                    return f(*args, **kwargs)

                return wrapper

            return deco

        mon.monitor_api_request = monitor_api_request
        sys.modules["blncs.monitoring.production_monitoring"] = mon


_install_sibling_stubs()

import blncs.api.production_api as production_api  # noqa: E402
from blncs.api.production_api import ProductionAPI  # noqa: E402


@pytest.fixture(scope="module")
def client():
    api = ProductionAPI({"SECRET_KEY": "test-secret-key"})
    return api.app.test_client()


@pytest.fixture(scope="module")
def auth_headers(client):
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "secure_password"},
    )
    assert resp.status_code == 200
    token = resp.get_json()["data"]["token"]
    return {"Authorization": f"Bearer {token}"}


def test_module_docstring_warns_about_mock_lightning_endpoints():
    doc = production_api.__doc__ or ""
    assert "MOCK" in doc
    assert "never execute" in doc
    assert "unified_rest_api" in doc  # points at the canonical payment API


def test_payment_response_is_marked_simulated(client, auth_headers):
    resp = client.post(
        "/api/v1/lightning/payments",
        json={"payment_request": "lnbc1example", "amount": 500},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.get_json()["data"]
    assert data["simulated"] is True


def test_payment_marking_is_additive(client, auth_headers):
    """The marking must not change the rest of the response shape."""
    resp = client.post(
        "/api/v1/lightning/payments",
        json={"payment_request": "lnbc1example", "amount": 500},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["success"] is True
    assert body["data"]["status"] == "SUCCEEDED"
    assert body["data"]["payment_hash"]
    assert body["data"]["payment_preimage"]


def test_invoice_response_is_marked_simulated(client, auth_headers):
    resp = client.post(
        "/api/v1/lightning/invoices",
        json={"amount": 1000, "memo": "test"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    data = resp.get_json()["data"]
    assert data["simulated"] is True
    assert data["payment_request"]


def test_payment_endpoint_still_requires_auth(client):
    resp = client.post(
        "/api/v1/lightning/payments",
        json={"payment_request": "lnbc1example", "amount": 500},
    )
    assert resp.status_code == 401
