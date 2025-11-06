"""
Unified REST API for BLNCS
Simple Flask-based API server with caching
"""

from flask import Flask, jsonify, request, g
from flask_cors import CORS
import logging
import time
from functools import wraps
import threading
import re
from uuid import uuid4
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from pathlib import Path
from dataclasses import asdict

from ipaddress import ip_address, ip_network, IPv4Address, IPv4Network, IPv6Address, IPv6Network

from werkzeug.exceptions import BadRequest, HTTPException

from blncs.core.simple_auth import get_auth
from blncs.core.security_validator import get_security_validator, ValidationResult
from blncs.core.config_manager import UnifiedConfigManager
from blncs.core.rate_limiter import RateLimiter
from blncs.core.unified_logging import get_logger

# 超高速グローバルキャッシュ
from collections import OrderedDict
_response_cache = OrderedDict()
_cache_stats = {'hits': 0, 'misses': 0, 'bypass': 0}
_cache_lock = threading.RLock()


logger = get_logger(__name__)
_auth = get_auth()

IPAddress = IPv4Address | IPv6Address
IPNetwork = IPv4Network | IPv6Network


def _prepare_ip_whitelist(entries: Iterable[Any], logger: logging.Logger) -> Tuple[Set[IPAddress], List[IPNetwork]]:
    addresses: Set[IPAddress] = set()
    networks: List[IPNetwork] = []

    for raw in entries or []:
        if raw is None:
            continue
        entry = str(raw).strip()
        if not entry:
            continue

        try:
            if '/' in entry:
                networks.append(ip_network(entry, strict=False))
            else:
                addresses.add(ip_address(entry))
        except ValueError:
            logger.warning("Ignoring invalid IP whitelist entry", extra={'entry': entry})

    return addresses, networks


def _extract_json_body(required: bool = True) -> Tuple[Optional[Dict[str, Any]], Optional[Tuple[str, int]]]:
    """Safely extract JSON from the request and return (data, error)."""
    try:
        payload = request.get_json(force=False, silent=False)
    except BadRequest:
        return None, ("Invalid JSON payload", 400)

    if payload is None:
        if required:
            return None, ("JSON body required", 400)
        return None, None

    if not isinstance(payload, dict):
        return None, ("JSON object expected", 400)

    return payload, None


def _config_get(config_obj, path, default=None):
    """Safely retrieve nested configuration values using dot notation."""
    if config_obj is None:
        return default

    if hasattr(config_obj, "get"):
        try:
            return config_obj.get(path, default)
        except TypeError:
            # Some config managers expect different arguments
            pass

    current = config_obj
    for segment in path.split('.'):
        if isinstance(current, dict) and segment in current:
            current = current[segment]
        else:
            return default
    return current


def _parse_size_to_bytes(value):
    """Convert size strings like '10MB' to integer bytes."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        match = re.match(r"^\s*(\d+(?:\.\d+)?)\s*([kmgt]?b)?\s*$", value, re.IGNORECASE)
        if not match:
            return None
        number, unit = match.groups()
        number = float(number)
        unit = (unit or 'b').lower()
        scale = {
            'b': 1,
            'kb': 1024,
            'mb': 1024 ** 2,
            'gb': 1024 ** 3,
            'tb': 1024 ** 4,
        }.get(unit, 1)
        return int(number * scale)
    return None

def cache_response(ttl=30, max_size=50):
    """最適化されたAPIレスポンスキャッシュ"""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # GETリクエストのみキャッシュ
            if request.method != 'GET':
                return f(*args, **kwargs)

            # キャッシュキー生成 (軽量)
            key = f"{request.endpoint}:{str(sorted(request.args.items()))}"

            now = time.time()
            cached_payload = None
            ttl_remaining = None

            with _cache_lock:
                cached_entry = _response_cache.get(key)
                if cached_entry:
                    payload, expires_at = cached_entry
                    if expires_at > now:
                        _response_cache.move_to_end(key)
                        cached_payload = payload
                        ttl_remaining = max(0, int(expires_at - now))
                    else:
                        # 期限切れキャッシュ削除
                        del _response_cache[key]

            if cached_payload is not None:
                with _cache_lock:
                    _cache_stats['hits'] += 1
                response = jsonify(cached_payload)
                response.headers['X-Cache'] = 'HIT'
                if ttl_remaining is not None:
                    response.headers['X-Cache-TTL'] = str(ttl_remaining)
                    response.headers.setdefault('Cache-Control', f'public, max-age={ttl_remaining}')
                return response

            result = f(*args, **kwargs)

            # JSON応答のみキャッシュ (高速化)
            cacheable = False
            payload = None
            status_code = getattr(result, 'status_code', 200)
            if hasattr(result, 'get_json') and status_code == 200:
                try:
                    payload = result.get_json()
                except Exception:
                    payload = None
                else:
                    if payload is not None and getattr(result, 'is_json', True):
                        cacheable = True

            if cacheable:
                response_ttl = ttl
                result.headers['X-Cache'] = 'MISS'
                result.headers['X-Cache-TTL'] = str(response_ttl)
                result.headers.setdefault('Cache-Control', f'public, max-age={response_ttl}')

                with _cache_lock:
                    _cache_stats['misses'] += 1
                    _response_cache[key] = (payload, time.time() + ttl)

                    # LRU キャッシュサイズ制限 (O(1) 削除)
                    while len(_response_cache) > max_size:
                        _response_cache.popitem(last=False)  # Remove oldest
            else:
                # 非キャッシュ応答にも MISS を明示
                if hasattr(result, 'headers'):
                    result.headers.setdefault('X-Cache', 'BYPASS')
                    result.headers.setdefault('Cache-Control', 'no-store')
                with _cache_lock:
                    _cache_stats['bypass'] += 1

            return result
        return wrapper
    return decorator

def create_app(config=None):
    """Create Flask application"""
    config_source = config or UnifiedConfigManager()

    app = Flask(__name__)

    app.config['JSON_SORT_KEYS'] = False
    app.config.setdefault('TRAP_BAD_REQUEST_ERRORS', False)

    cors_enabled = bool(_config_get(config_source, 'api.cors_enabled', True))
    cors_origins_raw = _config_get(config_source, 'api.cors_allowed_origins', []) or []
    cors_supports_credentials = bool(_config_get(config_source, 'api.cors_supports_credentials', False))

    cors_origins: List[str] = []
    for origin in cors_origins_raw:
        if origin is None:
            continue
        origin_str = str(origin).strip()
        if not origin_str:
            continue
        if origin_str.lower().startswith(('http://', 'https://')):
            cors_origins.append(origin_str)
        else:
            logger.warning("Ignoring invalid CORS origin", extra={'origin': origin_str})

    if cors_supports_credentials and not cors_origins:
        cors_enabled = False
        logger.warning("Disabling CORS credentials support due to missing allowed origins")

    trusted_hosts = set(_config_get(config_source, 'security.trusted_hosts', []) or [])
    request_timeout_seconds = int(_config_get(config_source, 'security.request_timeout', 60) or 60)
    whitelist_addresses, whitelist_networks = _prepare_ip_whitelist(
        _config_get(config_source, 'security.ip_whitelist', []), logger
    )

    enforce_https = bool(_config_get(config_source, 'security.enforce_https', False))

    # Enable CORS if configured
    if cors_enabled:
        cors_kwargs: Dict[str, Any] = {
            'supports_credentials': cors_supports_credentials,
        }
        if cors_origins:
            cors_kwargs['origins'] = cors_origins
        CORS(app, **cors_kwargs)

    max_query_length = int(_config_get(config_source, 'security.max_query_length', 4096) or 4096)

    max_request_size = _parse_size_to_bytes(_config_get(config_source, 'security.max_request_size'))
    if max_request_size:
        app.config['MAX_CONTENT_LENGTH'] = max_request_size

    rate_limiter = None
    rate_limit_window = int(_config_get(config_source, 'api.rate_limiting.window_seconds', 60) or 60)
    if _config_get(config_source, 'api.rate_limiting.enabled', False):
        requests_per_minute = int(_config_get(config_source, 'api.rate_limiting.requests_per_minute', 60) or 60)
        burst_size = int(_config_get(config_source, 'api.rate_limiting.burst_size', requests_per_minute) or requests_per_minute)
        max_requests = max(requests_per_minute, burst_size, 1)
        rate_limiter = RateLimiter(max_requests=max_requests, window_seconds=rate_limit_window)

    @app.before_request
    def _apply_request_guards():
        g.request_id = request.headers.get('X-Request-ID') or str(uuid4())
        g.request_start_time = time.perf_counter()

        if trusted_hosts:
            host_header = request.host.split(':')[0] if request.host else ''
            if host_header not in trusted_hosts:
                logger.warning(
                    "Rejected request due to untrusted host",
                    extra={
                        'request_id': g.request_id,
                        'remote_addr': request.remote_addr,
                        'host': host_header,
                    }
                )
                return jsonify({'error': 'Unrecognised host', 'request_id': g.request_id}), 400

        if enforce_https:
            forwarded_proto = (request.headers.get('X-Forwarded-Proto') or '').split(',')[0].strip().lower()
            if not (request.is_secure or forwarded_proto == 'https'):
                logger.warning(
                    "Rejected request due to insecure transport",
                    extra={
                        'request_id': g.request_id,
                        'remote_addr': request.remote_addr,
                        'forwarded_proto': forwarded_proto,
                    }
                )
                return jsonify({'error': 'HTTPS required', 'request_id': g.request_id}), 403

        raw_forwarded = request.headers.get('X-Forwarded-For', '')
        forwarded_ip = raw_forwarded.split(',')[0].strip() if raw_forwarded else ''
        client_ip = forwarded_ip or request.remote_addr or ''
        g.client_ip = client_ip or 'unknown'

        if whitelist_addresses or whitelist_networks:
            try:
                client_ip_obj = ip_address(client_ip)
            except ValueError:
                logger.warning(
                    "Rejected request due to invalid client IP",
                    extra={
                        'request_id': g.request_id,
                        'remote_addr': client_ip,
                    }
                )
                return jsonify({'error': 'Access denied', 'request_id': g.request_id}), 403

            allowed = client_ip_obj in whitelist_addresses or any(
                client_ip_obj in network for network in whitelist_networks
            )

            if not allowed:
                logger.warning(
                    "Rejected request due to IP whitelist",
                    extra={
                        'request_id': g.request_id,
                        'remote_addr': client_ip,
                    }
                )
                return jsonify({'error': 'Access denied', 'request_id': g.request_id}), 403

        if max_query_length and len(request.query_string or b"") > max_query_length:
            logger.warning(
                "Query string length exceeded",
                extra={
                    'request_id': g.request_id,
                    'remote_addr': client_ip,
                    'length': len(request.query_string or b""),
                }
            )
            return jsonify({'error': 'Query string too long', 'request_id': g.request_id}), 414

        if rate_limiter:
            identifier = g.client_ip

            if not rate_limiter.is_allowed(identifier):
                retry_after = rate_limiter.reset_time(identifier) or rate_limit_window
                response = jsonify({
                    'error': 'Rate limit exceeded',
                    'retry_after': retry_after
                })
                response.status_code = 429
                response.headers['Retry-After'] = str(int(max(1, retry_after)))
                return response

            g.rate_limit_identifier = identifier
            g.rate_limit_remaining = rate_limiter.remaining_requests(identifier)
            g.rate_limit_reset = int(time.time() + (rate_limiter.reset_time(identifier) or 0))
        else:
            g.rate_limit_identifier = None

        if request.method in {'POST', 'PUT', 'PATCH'}:
            content_length = request.content_length or 0

            if content_length > 0 and not request.is_json:
                return jsonify({'error': 'JSON body required'}), 415

            if request_timeout_seconds:
                g.request_deadline = g.request_start_time + request_timeout_seconds

            if app.config.get('MAX_CONTENT_LENGTH') and content_length:
                if content_length > app.config['MAX_CONTENT_LENGTH']:
                    return jsonify({'error': 'Request body too large'}), 413

    @app.after_request
    def _apply_security_headers(response):
        security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'no-referrer',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
            'Cross-Origin-Resource-Policy': 'same-origin',
            'Cross-Origin-Opener-Policy': 'same-origin'
        }
        if request.is_secure or enforce_https:
            security_headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        security_headers['Content-Security-Policy'] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"

        for header, value in security_headers.items():
            response.headers.setdefault(header, value)

        response.headers['X-Request-ID'] = getattr(g, 'request_id', 'unknown')
        if request.endpoint == 'health':
            response.headers.setdefault('Cache-Control', 'no-store, max-age=0, must-revalidate')

        if rate_limiter and getattr(g, 'rate_limit_identifier', None):
            response.headers['X-RateLimit-Limit'] = str(rate_limiter.max_requests)
            response.headers['X-RateLimit-Remaining'] = str(max(0, getattr(g, 'rate_limit_remaining', 0)))
            response.headers['X-RateLimit-Reset'] = str(max(0, getattr(g, 'rate_limit_reset', 0)))

        return response

    @app.after_request
    def _log_request(response):
        try:
            duration_ms = None
            if hasattr(g, 'request_start_time'):
                duration_ms = (time.perf_counter() - g.request_start_time) * 1000
                response.headers.setdefault('Server-Timing', f'app;dur={round(duration_ms, 3)}')

            if hasattr(g, 'request_deadline') and time.perf_counter() > g.request_deadline:
                logger.warning(
                    "Request handling exceeded configured timeout",
                    extra={
                        'request_id': getattr(g, 'request_id', 'unknown'),
                        'method': request.method,
                        'path': request.path,
                        'duration_ms': round(duration_ms, 3) if duration_ms is not None else None,
                    }
                )

            logger.info(
                "Handled request",
                extra={
                    'request_id': getattr(g, 'request_id', 'unknown'),
                    'method': request.method,
                    'path': request.path,
                    'status_code': response.status_code,
                    'duration_ms': round(duration_ms, 3) if duration_ms is not None else None,
                    'remote_addr': getattr(g, 'client_ip', request.remote_addr),
                }
            )
        except Exception:
            pass
        return response

    @app.errorhandler(HTTPException)
    def _handle_http_exception(error: HTTPException):
        payload = {
            'error': error.name,
            'description': error.description,
        }
        request_id = getattr(g, 'request_id', None)
        if request_id:
            payload['request_id'] = request_id

        client_ip = getattr(g, 'client_ip', None)
        if client_ip:
            payload['client_ip'] = client_ip

        response = jsonify(payload)
        response.status_code = error.code or 500
        for header, value in error.get_headers():
            response.headers.setdefault(header, value)
        return response

    @app.errorhandler(Exception)
    def _handle_unexpected_exception(error: Exception):
        logger.exception(
            "Unhandled exception while processing request",
            extra={
                'request_id': getattr(g, 'request_id', 'unknown'),
                'remote_addr': getattr(g, 'client_ip', request.remote_addr),
            }
        )

        payload = {
            'error': 'Internal Server Error',
            'description': 'An unexpected error occurred. Please retry later.',
        }

        request_id = getattr(g, 'request_id', None)
        if request_id:
            payload['request_id'] = request_id

        client_ip = getattr(g, 'client_ip', None)
        if client_ip:
            payload['client_ip'] = client_ip

        response = jsonify(payload)
        response.status_code = 500
        return response

    @app.route('/health', methods=['GET'])
    def health():
        """Health check endpoint - no caching for real-time status"""
        health_status = {
            'status': 'healthy',
            'timestamp': time.time(),
            'checks': {}
        }

        # Check database
        try:
            from blncs.core.unified_database import UnifiedDatabase
            db = UnifiedDatabase(':memory:')  # Quick test
            db.close()
            health_status['checks']['database'] = 'ok'
        except Exception as e:
            health_status['checks']['database'] = 'error'
            health_status['status'] = 'degraded'

        # Check cache
        try:
            from blncs.core.simple_cache import get_simple_cache
            cache = get_simple_cache()
            cache.set('health_test', 1)
            if cache.get('health_test') == 1:
                health_status['checks']['cache'] = 'ok'
            else:
                health_status['checks']['cache'] = 'error'
        except:
            health_status['checks']['cache'] = 'error'
            health_status['status'] = 'degraded'

        # Check Lightning client
        try:
            from blncs.lightning.simple_client import SimpleLightningClient
            client = SimpleLightningClient()
            health_status['checks']['lightning'] = 'available'
        except:
            health_status['checks']['lightning'] = 'unavailable'

        # Return appropriate status code
        if health_status['status'] == 'healthy':
            return jsonify(health_status), 200
        else:
            return jsonify(health_status), 503

    @app.route('/api/info', methods=['GET'])
    @cache_response(ttl=300)  # Cache for 5 minutes
    @_auth.require_auth('read')
    def info(auth_token):
        """Get system information"""
        return jsonify({
            'name': 'BLNCS',
            'version': '1.0.0',
            'description': 'Bitcoin Lightning Network Control System'
        })

    @app.route('/api/cache/stats', methods=['GET'])
    @cache_response(ttl=5)  # Cache for 5 seconds
    @_auth.require_auth('read')
    def cache_stats(auth_token):
        """Get cache statistics"""
        try:
            from blncs.core import get_cache
            cache = get_cache()
            return jsonify(cache.stats())
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/cache/clear', methods=['POST'])
    @_auth.require_auth('write')
    def cache_clear(auth_token):
        """Clear cache"""
        try:
            from blncs.core import get_cache
            cache = get_cache()
            cache.clear()
            return jsonify({'status': 'success', 'message': 'Cache cleared'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/config', methods=['GET'])
    @_auth.require_auth('read')
    def get_config(auth_token):
        """Get configuration (non-sensitive only)"""
        try:
            from blncs.core import get_config
            config = get_config()

            # Filter out sensitive data
            safe_config = {
                'api': config.get_section('api'),
                'monitoring': config.get_section('monitoring'),
                'cache': config.get_section('cache')
            }
            return jsonify(safe_config)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    # Lightning Network endpoints
    @app.route('/api/lightning/info', methods=['GET'])
    @_auth.require_auth('read')
    def lightning_info(auth_token):
        """Get Lightning node information"""
        try:
            from blncs.lightning.simple_client import SimpleLightningClient
            client = SimpleLightningClient()

            if not client.connected:
                client.connect()

            info = client.get_info()
            return jsonify(info)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/lightning/balance', methods=['GET'])
    @_auth.require_auth('read')
    def lightning_balance(auth_token):
        """Get Lightning wallet balance"""
        try:
            from blncs.lightning.simple_client import SimpleLightningClient
            client = SimpleLightningClient()

            if not client.connected:
                client.connect()

            balance = client.get_balance()
            return jsonify(balance)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/lightning/invoice', methods=['POST'])
    @_auth.require_auth('write')
    def create_invoice(auth_token):
        """Create Lightning invoice"""
        try:
            from blncs.lightning.simple_client import SimpleLightningClient

            data, error = _extract_json_body()
            if error:
                return jsonify({'error': error[0]}), error[1]

            if 'amount' not in data:
                return jsonify({'error': 'Amount required'}), 400

            validator = get_security_validator()

            amount_result = validator.validate_amount(data.get('amount'), min_value=1)
            if not amount_result.valid:
                return jsonify({'error': 'Invalid amount', 'details': amount_result.errors}), 400

            memo_result = validator.validate_memo(data.get('memo', ''))
            if not memo_result.valid:
                return jsonify({'error': 'Invalid memo', 'details': memo_result.errors}), 400

            if memo_result.warnings:
                for warning in memo_result.warnings:
                    logger.warning("Invoice memo sanitized warning: %s", warning)

            amount = amount_result.sanitized_value
            memo = memo_result.sanitized_value

            client = SimpleLightningClient()
            if not client.connected:
                client.connect()

            invoice = client.create_invoice(amount, memo)

            # Notify WebSocket clients
            try:
                from blncs.api.websocket_server import notify_clients
                notify_clients('invoice_created', invoice)
            except:
                pass

            return jsonify(invoice)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/lightning/pay', methods=['POST'])
    @_auth.require_auth('write')
    def pay_invoice(auth_token):
        """Pay Lightning invoice"""
        try:
            from blncs.lightning.simple_client import SimpleLightningClient

            data, error = _extract_json_body()
            if error:
                return jsonify({'error': error[0]}), error[1]

            if 'payment_request' not in data:
                return jsonify({'error': 'Payment request required'}), 400

            validator = get_security_validator()
            invoice_result = validator.validate_lightning_invoice(data.get('payment_request'))
            if not invoice_result.valid:
                return jsonify({'error': 'Invalid payment request', 'details': invoice_result.errors}), 400

            payment_request = invoice_result.sanitized_value

            client = SimpleLightningClient()
            if not client.connected:
                client.connect()

            result = client.pay_invoice(payment_request)

            # Notify WebSocket clients
            try:
                from blncs.api.websocket_server import notify_clients
                notify_clients('payment_sent', result)
            except:
                pass

            return jsonify(result)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/lightning/channels', methods=['GET'])
    @_auth.require_auth('read')
    def lightning_channels(auth_token):
        """Get Lightning Network channels"""
        try:
            from blncs.lightning.simple_client import SimpleLightningClient
            client = SimpleLightningClient()

            if not client.connected:
                client.connect()

            channels = client.list_channels()
            return jsonify({'channels': channels})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/analytics/sustainability', methods=['GET'])
    @_auth.require_auth('read')
    def get_sustainability_analytics(auth_token):
        """Get comprehensive sustainability analytics"""
        try:
            from blncs.lightning.simple_client import SimpleLightningClient
            client = SimpleLightningClient()

            if not client.connected:
                client.connect()

            sustainability_data = client.get_sustainability_metrics()
            return jsonify(sustainability_data)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/analytics/predictive', methods=['GET'])
    @_auth.require_auth('read')
    def get_predictive_analytics(auth_token):
        """Get AI/ML predictive analytics"""
        try:
            from blncs.lightning.simple_client import SimpleLightningClient

            time_horizon = request.args.get('horizon', default='24h', type=str)
            client = SimpleLightningClient()

            if not client.connected:
                client.connect()

            analytics_data = client.get_predictive_analytics(time_horizon)
            return jsonify(analytics_data)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/analytics/interop', methods=['GET'])
    @_auth.require_auth('read')
    def get_blockchain_interop_analytics(auth_token):
        """Get blockchain interoperability analytics"""
        try:
            from blncs.lightning.simple_client import SimpleLightningClient
            client = SimpleLightningClient()

            if not client.connected:
                client.connect()

            return jsonify({'interop_status': 'active'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/analytics/mobile', methods=['GET'])
    @_auth.require_auth('read')
    def get_mobile_compatibility_analytics(auth_token):
        """Get mobile and cross-platform compatibility analytics"""
        try:
            from blncs.lightning.simple_client import SimpleLightningClient
            client = SimpleLightningClient()

            if not client.connected:
                client.connect()

            mobile_data = client.get_mobile_compatibility_status()
            return jsonify(mobile_data)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/compliance/status', methods=['GET'])
    @_auth.require_auth('read')
    def get_compliance_status(auth_token):
        """Get comprehensive compliance monitoring and regulatory reporting status"""
        try:
            from blncs.lightning.simple_client import SimpleLightningClient
            client = SimpleLightningClient()

            if not client.connected:
                client.connect()

            compliance_data = client.get_compliance_status()
            return jsonify(compliance_data)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/security/zero-trust', methods=['GET'])
    @_auth.require_auth('read')
    def get_zero_trust_status(auth_token):
        """Get zero-trust security architecture and continuous monitoring status"""
        try:
            from blncs.lightning.simple_client import SimpleLightningClient
            client = SimpleLightningClient()

            if not client.connected:
                client.connect()

            zero_trust_data = client.get_zero_trust_status()
            return jsonify(zero_trust_data)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/analytics/enhanced', methods=['GET'])
    @_auth.require_auth('read')
    def get_enhanced_analytics(auth_token):
        """Get enhanced analytics with custom dashboards and automated reporting"""
        try:
            from blncs.lightning.simple_client import SimpleLightningClient

            dashboard_type = request.args.get('type', default='comprehensive', type=str)
            client = SimpleLightningClient()

            if not client.connected:
                client.connect()

            analytics_data = client.get_enhanced_analytics(dashboard_type)
            return jsonify(analytics_data)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/ai/insights', methods=['GET'])
    @_auth.require_auth('read')
    def get_advanced_ai_insights(auth_token):
        """Get advanced AI/ML capabilities for automated optimization and intelligent routing"""
        try:
            from blncs.lightning.simple_client import SimpleLightningClient
            client = SimpleLightningClient()

            if not client.connected:
                client.connect()

    @app.route('/api/edge/status', methods=['GET'])
    @_auth.require_auth('read')
    def get_edge_computing_status(auth_token):
        """Get edge computing and decentralized processing capabilities"""
        try:
            from blncs.lightning.simple_client import SimpleLightningClient
            client = SimpleLightningClient()

            if not client.connected:
                client.connect()

            edge_data = client.get_edge_computing_status()
            return jsonify(edge_data)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/quantum/status', methods=['GET'])
    @_auth.require_auth('read')
    def get_quantum_computing_status(auth_token):
        """Get quantum computing preparedness and quantum-resistant features"""
        try:
            from blncs.lightning.simple_client import SimpleLightningClient
            client = SimpleLightningClient()

            if not client.connected:
                client.connect()

            quantum_data = client.get_quantum_computing_status()
            return jsonify(quantum_data)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/blockchain/advanced', methods=['GET'])
    @_auth.require_auth('read')
    def get_advanced_blockchain_integration(auth_token):
        """Get advanced blockchain interoperability with cross-chain protocols and DeFi integration"""
        try:
            from blncs.lightning.simple_client import SimpleLightningClient
            client = SimpleLightningClient()

            if not client.connected:
                client.connect()

            blockchain_data = client.get_advanced_blockchain_integration()
            return jsonify(blockchain_data)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/sustainability/comprehensive', methods=['GET'])
    @_auth.require_auth('read')
    def get_comprehensive_sustainability(auth_token):
        """Get comprehensive sustainability tracking with carbon footprint analysis and green optimization"""
        try:
            from blncs.lightning.simple_client import SimpleLightningClient
            client = SimpleLightningClient()

            if not client.connected:
                client.connect()

            sustainability_data = client.get_comprehensive_sustainability()
            return jsonify(sustainability_data)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/ai/federated', methods=['GET'])
    @_auth.require_auth('read')
    def get_federated_learning_status(auth_token):
        """Get federated learning and privacy-preserving AI techniques status"""
        try:
            from blncs.lightning.simple_client import SimpleLightningClient
            client = SimpleLightningClient()

            if not client.connected:
                client.connect()

    @app.route('/api/observability/status', methods=['GET'])
    @_auth.require_auth('read')
    def get_observability_status(auth_token):
        """Get advanced observability features including distributed tracing and comprehensive monitoring"""
        try:
            from blncs.lightning.simple_client import SimpleLightningClient
            client = SimpleLightningClient()

            if not client.connected:
                client.connect()

            observability_data = client.get_observability_status()
            return jsonify(observability_data)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/scaling/status', methods=['GET'])
    @_auth.require_auth('read')
    def get_auto_scaling_status(auth_token):
        """Get auto-scaling and self-healing capabilities for dynamic resource management"""
        try:
            from blncs.lightning.simple_client import SimpleLightningClient
            client = SimpleLightningClient()

            if not client.connected:
                client.connect()

            scaling_data = client.get_auto_scaling_status()
            return jsonify(scaling_data)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/collaboration/status', methods=['GET'])
    @_auth.require_auth('read')
    def get_collaboration_status(auth_token):
        """Get real-time collaboration features for multi-user Lightning Network management"""
        try:
            from blncs.lightning.simple_client import SimpleLightningClient
            client = SimpleLightningClient()

            if not client.connected:
                client.connect()

    @app.route('/api/ux/advanced', methods=['GET'])
    @_auth.require_auth('read')
    def get_advanced_ux_status(auth_token):
        """Get advanced user experience features including voice commands and AR/VR interfaces"""
        try:
            from blncs.lightning.simple_client import SimpleLightningClient
            client = SimpleLightningClient()

            if not client.connected:
                client.connect()

            ux_data = client.get_advanced_ux_status()
            return jsonify(ux_data)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/qa/testing', methods=['GET'])
    @_auth.require_auth('read')
    def get_testing_qa_status(auth_token):
        """Get comprehensive testing and quality assurance features including automated testing and CI/CD"""
        try:
            from blncs.lightning.simple_client import SimpleLightningClient
            client = SimpleLightningClient()

            if not client.connected:
                client.connect()

            qa_data = client.get_testing_qa_status()
            return jsonify(qa_data)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/performance/optimization', methods=['GET'])
    @_auth.require_auth('read')
    def get_performance_optimization_status(auth_token):
        """Get additional performance optimizations including caching strategies and load balancing"""
        try:
            from blncs.lightning.simple_client import SimpleLightningClient
            client = SimpleLightningClient()

            if not client.connected:
                client.connect()

            perf_data = client.get_performance_optimization_status()
            return jsonify(perf_data)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    # System management endpoints
    @_auth.require_auth('write')
    def create_backup(auth_token):
        """Create system backup"""
        try:
            from blncs.utils.lightweight_backup import auto_backup

            request_data, error = _extract_json_body(required=False)
            if error:
                return jsonify({'error': error[0]}), error[1]

            requested_paths = []
            if request_data and 'paths' in request_data:
                raw_paths = request_data['paths']
                if not isinstance(raw_paths, list):
                    return jsonify({'error': 'paths must be a list of filesystem paths'}), 400
                requested_paths = [str(Path(p).expanduser()) for p in raw_paths if isinstance(p, str) and p.strip()]

            configured_paths = _config_get(config_source, 'backup.source_paths', []) or []
            if not isinstance(configured_paths, list):
                configured_paths = []

            candidate_paths = requested_paths or configured_paths
            viable_sources = [path for path in candidate_paths if Path(path).expanduser().exists()]

            if not viable_sources:
                return jsonify({'error': 'No valid backup sources found'}), 400

            backup_root = _config_get(config_source, 'backup.destinations.local.path')
            created_backups = auto_backup(
                include_paths=viable_sources,
                backup_root=backup_root,
                backup_type='api'
            )

            payload = [asdict(entry) for entry in created_backups]
            return jsonify({'status': 'success', 'backups': payload})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/system/metrics', methods=['GET'])
    @_auth.require_auth('read')
    def get_metrics(auth_token):
        """Get system metrics"""
        try:
            from blncs.core.metrics import get_stats as get_metric_stats
            stats = get_metric_stats()
            return jsonify(stats)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/system/optimize', methods=['POST'])
    @_auth.require_auth('write')
    def optimize_system(auth_token):
        """Optimize system performance"""
        try:
            from blncs.core.fast_startup import PerformanceOptimizer
            optimizer = PerformanceOptimizer()
            result = optimizer.apply_all_optimizations()
            return jsonify(result)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    # WebSocket status endpoint
    @app.route('/api/websocket/status', methods=['GET'])
    @_auth.require_auth('read')
    def websocket_status(auth_token):
        """Get WebSocket server status"""
        try:
            from blncs.api.websocket_server import get_websocket_manager
            manager = get_websocket_manager()
            stats = manager.get_stats()
            return jsonify(stats)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/logs/analyze', methods=['GET'])
    @_auth.require_auth('read')
    def analyze_logs(auth_token):
        """Analyze system logs and generate statistics"""
        try:
            from blncs.core.unified_logging import get_log_manager

            # Get query parameters
            hours = request.args.get('hours', default=24, type=int)
            log_path = request.args.get('path', default='blncs.log', type=str)

            log_manager = get_log_manager()
            analysis = log_manager.analyze_log_file(log_path, hours=hours)

            if 'error' in analysis:
                return jsonify({'error': analysis['error']}), 400

            return jsonify(analysis)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/logs/report', methods=['GET'])
    @_auth.require_auth('read')
    def generate_log_report(auth_token):
        """Generate human-readable log analysis report"""
        try:
            from blncs.core.unified_logging import get_log_manager

            # Get query parameters
            hours = request.args.get('hours', default=24, type=int)
            log_path = request.args.get('path', default='blncs.log', type=str)
            format_type = request.args.get('format', default='json', type=str)

            log_manager = get_log_manager()
            report = log_manager.generate_log_report(log_path, output_format=format_type)

            if format_type.lower() == 'text':
                return report, 200, {'Content-Type': 'text/plain; charset=utf-8'}
            else:
                return jsonify(json.loads(report))
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/config', methods=['GET'])
    @_auth.require_auth('read')
    def get_configuration(auth_token):
        """Get current configuration (sanitized)"""
        try:
            from blncs.core.config import get_config

            config = get_config()
            config_dict = config.to_dict()

            # Remove sensitive information
            sensitive_keys = ['jwt_secret', 'api_key', 'encryption_key']
            for section in config_dict.values():
                if isinstance(section, dict):
                    for key in sensitive_keys:
                        if key in section:
                            section[key] = "***REDACTED***"

            return jsonify(config_dict)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/config/validate', methods=['POST'])
    @_auth.require_auth('read')
    def validate_configuration(auth_token):
        """Validate current configuration"""
        try:
            from blncs.core.config import get_config

            config = get_config()
            validation = config.validate_configuration_integrity()

            return jsonify(validation)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/system/diagnostics', methods=['GET'])
    @_auth.require_auth('read')
    def system_diagnostics(auth_token):
        """Get comprehensive system diagnostics"""
        try:
            diagnostics = {}

            # Configuration status
            from blncs.core.config import get_config
            config = get_config()
            diagnostics['config'] = {
                'valid': True,
                'path': config.config_path,
                'environment': config.environment
            }

            try:
                validation = config.validate_configuration_integrity()
                diagnostics['config'].update(validation)
            except Exception as e:
                diagnostics['config']['error'] = str(e)

            # Lightning Network status
            try:
                from blncs.lightning.simple_client import get_lightning_client
                lightning = get_lightning_client()
                diagnostics['lightning'] = {
                    'connected': lightning.connected,
                    'node_type': lightning.node_type,
                    'network': lightning.network
                }

                if lightning.connected:
                    info = lightning.get_info()
                    diagnostics['lightning']['info'] = info

                    # Add Taproot channel count
                    try:
                        channels = lightning.list_channels()
                        taproot_channels = sum(1 for ch in channels if ch.get('is_taproot', False))
                        diagnostics['lightning']['taproot_channels'] = taproot_channels
                    except:
                        diagnostics['lightning']['taproot_channels'] = 0

            except Exception as e:
                diagnostics['lightning'] = {'error': str(e)}

            # System resources
            try:
                import psutil
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')

                diagnostics['system'] = {
                    'memory': {
                        'total_gb': round(memory.total / (1024**3), 2),
                        'used_gb': round(memory.used / (1024**3), 2),
                        'percent': memory.percent
                    },
                    'disk': {
                        'total_gb': round(disk.total / (1024**3), 2),
                        'used_gb': round(disk.used / (1024**3), 2),
                        'percent': disk.percent
                    },
                    'cpu_percent': psutil.cpu_percent(interval=1)
                }
            except ImportError:
                diagnostics['system'] = {'error': 'psutil not available'}
            except Exception as e:
                diagnostics['system'] = {'error': str(e)}

            # API server status
            diagnostics['api'] = {
                'status': 'running',
                'endpoints': [
                    '/health',
                    '/api/system/metrics',
                    '/api/system/optimize',
                    '/api/logs/analyze',
                    '/api/logs/report',
                    '/api/config',
                    '/api/config/validate',
                    '/api/system/diagnostics'
                ]
            }
            return jsonify(diagnostics)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/metrics/realtime', methods=['GET'])
    @_auth.require_auth('read')
    def get_realtime_metrics(auth_token):
        """Get real-time system and application metrics"""
        try:
            from blncs.core.lightweight_metrics import get_metrics_collector

            collector = get_metrics_collector()

            # Get current metrics
            current = collector.get_current_metrics()
            alerts = collector.get_alerts()

            # Get summary for last hour
            summary = collector.get_metrics_summary(hours=1)

            response = {
                'current': current,
                'summary': summary,
                'alerts': alerts,
                'timestamp': time.time()
            }

            return jsonify(response)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/metrics/summary', methods=['GET'])
    @_auth.require_auth('read')
    def get_metrics_summary(auth_token):
        """Get metrics summary for specified time period"""
        try:
            from blncs.core.lightweight_metrics import get_metrics_collector

            hours = request.args.get('hours', default=1, type=int)
            collector = get_metrics_collector()
            summary = collector.get_metrics_summary(hours=hours)

            return jsonify(summary)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/metrics/export', methods=['POST'])
    @_auth.require_auth('write')
    def export_metrics(auth_token):
        """Export metrics to file"""
        try:
            from blncs.core.lightweight_metrics import get_metrics_collector

            file_path = request.args.get('path', default='metrics_export.json', type=str)

            # Ensure path is safe
            if '..' in file_path or not file_path.endswith('.json'):
                return jsonify({'error': 'Invalid file path'}), 400

            collector = get_metrics_collector()
            collector.export_metrics(file_path)

            return jsonify({
                'status': 'success',
                'file': file_path,
                'message': f'Metrics exported to {file_path}'
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.errorhandler(404)
    def not_found(error):
        payload = {'error': 'Not found'}
        request_id = getattr(g, 'request_id', None)
        if request_id:
            payload['request_id'] = request_id
        return jsonify(payload), 404

    @app.errorhandler(500)
    def internal_error(error):
        payload = {'error': 'Internal server error'}
        request_id = getattr(g, 'request_id', None)
        if request_id is not None:
            payload['request_id'] = request_id
        return jsonify(payload), 500

    return app


    @app.route('/api/docs/openapi.json', methods=['GET'])
    @_auth.require_auth('read')
    def openapi_spec(auth_token):
        """Generate OpenAPI specification"""
        return jsonify(generate_openapi_spec())

    @app.route('/api/docs', methods=['GET'])
    @_auth.require_auth('read')
    def api_docs(auth_token):
        """Serve API documentation (HTML)"""
        spec = generate_openapi_spec()
        html = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>BLNCS API Documentation</title>
            <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.10.3/swagger-ui.css">
            <style>
                body {{ margin: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }}
                .topbar {{ display: none; }}
                .swagger-ui .info .title {{ color: #667eea; }}
            </style>
        </head>
        <body>
            <div id="swagger-ui"></div>
            <script src="https://unpkg.com/swagger-ui-dist@5.10.3/swagger-ui-bundle.js"></script>
            <script src="https://unpkg.com/swagger-ui-dist@5.10.3/swagger-ui-standalone-preset.js"></script>
            <script>
                window.onload = function() {{
                    const ui = SwaggerUIBundle({{
                        spec: {json.dumps(spec)},
                        dom_id: '#swagger-ui',
                        deepLinking: true,
                        presets: [
                            SwaggerUIBundle.presets.apis,
                            SwaggerUIStandalonePreset
                        ],
                        plugins: [
                            SwaggerUIBundle.plugins.DownloadUrl
                        ],
                        layout: "StandaloneLayout"
                    }});
                }};
            </script>
        </body>
        </html>
        '''
        return html, 200, {'Content-Type': 'text/html; charset=utf-8'}


def generate_openapi_spec():
    """Generate OpenAPI 3.0 specification for BLNCS API"""
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "BLNCS API",
            "description": "Bitcoin Lightning Network Control System API",
            "version": "2.0.0",
            "contact": {
                "name": "BLNCS Support"
            },
            "license": {
                "name": "MIT"
            }
        },
        "servers": [
            {
                "url": "http://localhost:8080",
                "description": "Local development server"
            }
        ],
        "security": [
            {
                "bearerAuth": []
            }
        ],
        "paths": {
            "/health": {
                "get": {
                    "summary": "Health Check",
                    "description": "Check if the API server is healthy",
                    "responses": {
                        "200": {
                            "description": "Server is healthy",
                            "content": {
                                "application/json": {
                                    "example": {"status": "healthy", "timestamp": "2024-01-01T00:00:00Z"}
                                }
                            }
                        }
                    }
                }
            },
            "/api/system/diagnostics": {
                "get": {
                    "summary": "System Diagnostics",
                    "description": "Get comprehensive system diagnostics",
                    "responses": {
                        "200": {
                            "description": "System diagnostics",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "config": {"type": "object"},
                                            "lightning": {"type": "object"},
                                            "system": {"type": "object"},
                                            "api": {"type": "object"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/api/metrics/realtime": {
                "get": {
                    "summary": "Real-time Metrics",
                    "description": "Get real-time system and application metrics",
                    "responses": {
                        "200": {
                            "description": "Real-time metrics data",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "current": {"type": "object"},
                                            "summary": {"type": "object"},
                                            "alerts": {"type": "array"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/api/logs/analyze": {
                "get": {
                    "summary": "Log Analysis",
                    "description": "Analyze system logs and generate statistics",
                    "parameters": [
                        {
                            "name": "hours",
                            "in": "query",
                            "schema": {"type": "integer", "default": 24},
                            "description": "Hours to analyze"
                        },
                        {
                            "name": "path",
                            "in": "query",
                            "schema": {"type": "string", "default": "blncs.log"},
                            "description": "Log file path"
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Log analysis results",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "total_events": {"type": "integer"},
                                            "categories": {"type": "object"},
                                            "timeline": {"type": "array"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/api/config": {
                "get": {
                    "summary": "Get Configuration",
                    "description": "Get current configuration (sanitized)",
                    "responses": {
                        "200": {
                            "description": "Configuration data",
                            "content": {
                                "application/json": {
                                    "schema": {"type": "object"}
                                }
                            }
                        }
                    }
                }
            },
            "/api/lightning/info": {
                "get": {
                    "summary": "Lightning Node Info",
                    "description": "Get Lightning Network node information",
                    "responses": {
                        "200": {
                            "description": "Node information",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "node_id": {"type": "string"},
                                            "alias": {"type": "string"},
                                            "num_channels": {"type": "integer"},
                                            "network": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/api/lightning/invoice": {
                "post": {
                    "summary": "Create Invoice",
                    "description": "Create a new Lightning Network invoice",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["amount"],
                                    "properties": {
                                        "amount": {"type": "integer", "description": "Amount in satoshis"},
                                        "memo": {"type": "string", "description": "Invoice description"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Invoice created",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "payment_request": {"type": "string"},
                                            "payment_hash": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/api/analytics/sustainability": {
                "get": {
                    "summary": "Sustainability Analytics",
                    "description": "Get comprehensive sustainability and environmental impact metrics",
                    "responses": {
                        "200": {
                            "description": "Sustainability analytics data",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "energy_consumption": {"type": "object"},
                                            "efficiency_metrics": {"type": "object"},
                                            "sustainability_features": {"type": "object"},
                                            "recommendations": {"type": "array"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/api/analytics/predictive": {
                "get": {
                    "summary": "Predictive Analytics",
                    "description": "Get AI/ML-powered predictive analytics for Lightning Network operations",
                    "parameters": [
                        {
                            "name": "horizon",
                            "in": "query",
                            "schema": {"type": "string", "default": "24h"},
                            "description": "Prediction time horizon"
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Predictive analytics data",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "predictions": {"type": "object"},
                                            "ai_insights": {"type": "object"},
                                            "ml_models": {"type": "object"},
                                            "recommendations": {"type": "array"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/api/analytics/mobile": {
                "get": {
                    "summary": "Mobile Compatibility Analytics",
                    "description": "Get mobile and cross-platform compatibility status",
                    "responses": {
                        "200": {
                            "description": "Mobile compatibility data",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "mobile_support": {"type": "object"},
                                            "cross_platform_features": {"type": "object"},
                                            "compatibility_metrics": {"type": "object"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/api/compliance/status": {
                "get": {
                    "summary": "Compliance Status",
                    "description": "Get comprehensive compliance monitoring and regulatory reporting status",
                    "responses": {
                        "200": {
                            "description": "Compliance status data",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "regulatory_frameworks": {"type": "object"},
                                            "compliance_reports": {"type": "object"},
                                            "risk_assessment": {"type": "object"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/api/security/zero-trust": {
                "get": {
                    "summary": "Zero-Trust Security Status",
                    "description": "Get zero-trust security architecture and continuous monitoring status",
                    "responses": {
                        "200": {
                            "description": "Zero-trust security data",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "zero_trust_principles": {"type": "object"},
                                            "security_monitoring": {"type": "object"},
                                            "security_score": {"type": "object"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/api/analytics/enhanced": {
                "get": {
                    "summary": "Enhanced Analytics",
                    "description": "Get enhanced analytics with custom dashboards and automated reporting",
                    "parameters": [
                        {
                            "name": "type",
                            "in": "query",
                            "schema": {"type": "string", "default": "comprehensive"},
                            "description": "Dashboard type (comprehensive, security, performance, compliance)"
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Enhanced analytics data",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "dashboard_type": {"type": "string"},
                                            "data": {"type": "object"},
                                            "reports": {"type": "object"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/api/ai/insights": {
                "get": {
                    "summary": "Advanced AI Insights",
                    "description": "Get advanced AI/ML capabilities for automated optimization and intelligent routing",
                    "responses": {
                        "200": {
                            "description": "Advanced AI insights data",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "intelligent_routing": {"type": "object"},
                                            "automated_optimization": {"type": "object"},
                                            "machine_learning_models": {"type": "object"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/api/edge/status": {
                "get": {
                    "summary": "Edge Computing Status",
                    "description": "Get edge computing and decentralized processing capabilities",
                    "responses": {
                        "200": {
                            "description": "Edge computing data",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "edge_nodes": {"type": "object"},
                                            "decentralized_processing": {"type": "object"},
                                            "performance_optimizations": {"type": "object"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/api/quantum/status": {
                "get": {
                    "summary": "Quantum Computing Status",
                    "description": "Get quantum computing preparedness and quantum-resistant features",
                    "responses": {
                        "200": {
                            "description": "Quantum computing data",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "quantum_resistance": {"type": "object"},
                                            "quantum_simulation": {"type": "object"},
                                            "quantum_optimization": {"type": "object"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/api/blockchain/advanced": {
                "get": {
                    "summary": "Advanced Blockchain Integration",
                    "description": "Get advanced blockchain interoperability with cross-chain protocols and DeFi integration",
                    "responses": {
                        "200": {
                            "description": "Advanced blockchain integration data",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "cross_chain_protocols": {"type": "object"},
                                            "defi_integration": {"type": "object"},
                                            "cross_chain_analytics": {"type": "object"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/api/sustainability/comprehensive": {
                "get": {
                    "summary": "Comprehensive Sustainability",
                    "description": "Get comprehensive sustainability tracking with carbon footprint analysis and green optimization",
                    "responses": {
                        "200": {
                            "description": "Comprehensive sustainability data",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "carbon_footprint_analysis": {"type": "object"},
                                            "green_optimization": {"type": "object"},
                                            "environmental_impact_metrics": {"type": "object"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/api/ai/federated": {
                "get": {
                    "summary": "Federated Learning Status",
                    "description": "Get federated learning and privacy-preserving AI techniques status",
                    "responses": {
                        "200": {
                            "description": "Federated learning data",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "federated_learning_network": {"type": "object"},
                                            "privacy_preserving_techniques": {"type": "object"},
                                            "federated_ai_models": {"type": "object"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/api/observability/status": {
                "get": {
                    "summary": "Observability Status",
                    "description": "Get advanced observability features including distributed tracing and comprehensive monitoring",
                    "responses": {
                        "200": {
                            "description": "Observability data",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "distributed_tracing": {"type": "object"},
                                            "comprehensive_monitoring": {"type": "object"},
                                            "monitoring_dashboards": {"type": "object"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/api/scaling/status": {
                "get": {
                    "summary": "Auto-Scaling Status",
                    "description": "Get auto-scaling and self-healing capabilities for dynamic resource management",
                    "responses": {
                        "200": {
                            "description": "Auto-scaling data",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "auto_scaling_capabilities": {"type": "object"},
                                            "self_healing_systems": {"type": "object"},
                                            "resource_optimization": {"type": "object"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/api/ux/advanced": {
                "get": {
                    "summary": "Advanced UX Status",
                    "description": "Get advanced user experience features including voice commands and AR/VR interfaces",
                    "responses": {
                        "200": {
                            "description": "Advanced UX data",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "voice_commands": {"type": "object"},
                                            "ar_vr_interfaces": {"type": "object"},
                                            "advanced_interactions": {"type": "object"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/api/qa/testing": {
                "get": {
                    "summary": "Testing and QA Status",
                    "description": "Get comprehensive testing and quality assurance features including automated testing and CI/CD",
                    "responses": {
                        "200": {
                            "description": "Testing and QA data",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "automated_testing": {"type": "object"},
                                            "continuous_integration": {"type": "object"},
                                            "quality_assurance": {"type": "object"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/api/performance/optimization": {
                "get": {
                    "summary": "Performance Optimization Status",
                    "description": "Get additional performance optimizations including caching strategies and load balancing",
                    "responses": {
                        "200": {
                            "description": "Performance optimization data",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "caching_strategies": {"type": "object"},
                                            "load_balancing": {"type": "object"},
                                            "performance_monitoring": {"type": "object"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
        },
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT"
                }
            }
        }
    }


def create_dashboard_app(config=None):
    """Create dashboard web application with API docs"""
    app = create_app(config)

    @app.route('/')
    @app.route('/dashboard')
    def dashboard():
        """Serve the main dashboard"""
        try:
            from pathlib import Path
            dashboard_path = Path(__file__).parent.parent / 'web' / 'dashboard.html'

            if dashboard_path.exists():
                with open(dashboard_path, 'r', encoding='utf-8') as f:
                    return f.read(), 200, {'Content-Type': 'text/html; charset=utf-8'}
            else:
                return f'''
                <!DOCTYPE html>
                <html>
                <head>
                    <title>BLNCS Dashboard</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
                        .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                        h1 {{ color: #667eea; }}
                        .links {{ margin-top: 20px; }}
                        .links a {{ display: inline-block; margin: 10px; padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; }}
                        .links a:hover {{ background: #5a67d8; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>⚡ BLNCS Dashboard</h1>
                        <p>Welcome to the BLNCS Web Dashboard. The full dashboard interface is not available, but you can access the API directly.</p>

                        <div class="links">
                            <a href="/api/system/diagnostics">🔍 System Diagnostics</a>
                            <a href="/api/metrics/realtime">📊 Real-time Metrics</a>
                            <a href="/api/docs">📖 API Documentation</a>
                            <a href="/health">🏥 Health Check</a>
                        </div>
                    </div>
                </body>
                </html>
                ''', 200, {'Content-Type': 'text/html; charset=utf-8'}
        except Exception as e:
            return f'''
            <html>
            <head><title>BLNCS Dashboard - Error</title></head>
            <body>
                <h1>Dashboard Error</h1>
                <p>Failed to load dashboard: {str(e)}</p>
                <a href="/api/system/diagnostics">View API Diagnostics</a>
            </body>
            </html>
            ''', 500, {'Content-Type': 'text/html; charset=utf-8'}

    return app


class UnifiedAPIServer:
    """Flask-based API server wrapper"""

    def __init__(self, config=None, host='127.0.0.1', port=3000, debug=False):
        self.config = config
        self.host = host
        self.port = port
        self.debug = debug
        self.app = create_app(config)
        self.server = None

    def start(self):
        """Start the API server"""
        try:
            self.app.run(
                host=self.host,
                port=self.port,
                debug=self.debug,
                threaded=True,
                use_reloader=False
            )
        except KeyboardInterrupt:
            self.stop()
        except Exception as e:
            logger.error(f"Failed to start API server: {e}")

    def stop(self):
        """Stop the API server"""
        if self.server:
            self.server.shutdown()
        logger.info("API server stopped")

    def get_app(self):
        """Get the Flask app instance"""
        return self.app

    def add_route(self, rule, endpoint=None, view_func=None, **options):
        """Add a route to the Flask app"""
        self.app.add_url_rule(rule, endpoint, view_func, **options)

    def get_wsgi_application(self):
        """Get WSGI application for deployment"""
        return self.app