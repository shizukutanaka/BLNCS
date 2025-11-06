"""
Mobile-Friendly API for BLNCS
モバイル向け軽量APIレスポンス
"""

import time
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from flask import request, jsonify


@dataclass
class MobileResponse:
    """Standardized mobile API response"""
    success: bool
    data: Any = None
    error: Optional[str] = None
    timestamp: float = None
    meta: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()

    def to_dict(self) -> Dict[str, Any]:
        response = {
            'success': self.success,
            'timestamp': self.timestamp
        }

        if self.success:
            response['data'] = self.data
        else:
            response['error'] = self.error

        if self.meta:
            response['meta'] = self.meta

        return response


class MobileAPIFormatter:
    """Format API responses for mobile consumption"""

    @staticmethod
    def success(data: Any, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Create successful mobile response"""
        return MobileResponse(success=True, data=data, meta=meta).to_dict()

    @staticmethod
    def error(message: str, code: Optional[str] = None) -> Dict[str, Any]:
        """Create error mobile response"""
        meta = {'code': code} if code else None
        return MobileResponse(success=False, error=message, meta=meta).to_dict()

    @staticmethod
    def paginated(items: List[Any], page: int = 1, per_page: int = 20, total: Optional[int] = None) -> Dict[str, Any]:
        """Create paginated mobile response"""
        if total is None:
            total = len(items)

        meta = {
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page if total > 0 else 0
            }
        }

        # Calculate slice for current page
        start = (page - 1) * per_page
        end = start + per_page
        page_items = items[start:end] if isinstance(items, list) else items

        return MobileResponse(success=True, data=page_items, meta=meta).to_dict()

    @staticmethod
    def compress_lightning_info(info: Dict[str, Any]) -> Dict[str, Any]:
        """Compress Lightning node info for mobile"""
        return {
            'alias': info.get('alias', 'Unknown'),
            'network': info.get('network', 'unknown'),
            'connected': info.get('connected', False),
            'version': info.get('version', '0.0.0'),
            'block_height': info.get('block_height', 0)
        }

    @staticmethod
    def compress_balance(balance: Dict[str, Any]) -> Dict[str, Any]:
        """Compress balance info for mobile"""
        return {
            'total': balance.get('total_balance', 0),
            'confirmed': balance.get('confirmed_balance', 0),
            'unconfirmed': balance.get('unconfirmed_balance', 0)
        }

    @staticmethod
    def compress_invoice(invoice: Dict[str, Any]) -> Dict[str, Any]:
        """Compress invoice for mobile"""
        return {
            'payment_request': invoice.get('payment_request', ''),
            'amount': invoice.get('amount', 0),
            'memo': invoice.get('memo', ''),
            'created_at': invoice.get('created_at', time.time()),
            'expires_at': invoice.get('created_at', time.time()) + 3600  # Default 1 hour
        }

    @staticmethod
    def compress_payment(payment: Dict[str, Any]) -> Dict[str, Any]:
        """Compress payment info for mobile"""
        return {
            'payment_hash': payment.get('payment_hash', ''),
            'status': payment.get('status', 'unknown'),
            'amount': payment.get('amount', 0),
            'fee': payment.get('fee', 0),
            'timestamp': payment.get('timestamp', time.time())
        }


def detect_mobile_client() -> bool:
    """Detect if request is from mobile client"""
    user_agent = request.headers.get('User-Agent', '').lower()
    mobile_indicators = [
        'mobile', 'android', 'iphone', 'ipad', 'ipod',
        'blackberry', 'windows phone', 'webos'
    ]
    return any(indicator in user_agent for indicator in mobile_indicators)


def get_client_preferences() -> Dict[str, Any]:
    """Get client preferences from headers"""
    return {
        'compress': request.headers.get('X-Compress-Response', 'false').lower() == 'true',
        'mobile': detect_mobile_client(),
        'version': request.headers.get('X-Client-Version', '1.0'),
        'locale': request.headers.get('Accept-Language', 'en')[:2],
        'timezone': request.headers.get('X-Timezone', 'UTC')
    }


def mobile_response_wrapper(include_meta: bool = True):
    """Decorator to wrap responses for mobile clients"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            preferences = get_client_preferences()

            try:
                result = func(*args, **kwargs)

                # If already a Response object, return as-is
                if hasattr(result, 'status_code'):
                    return result

                # Handle tuple responses (data, status_code)
                if isinstance(result, tuple):
                    data, status_code = result[:2]
                else:
                    data = result
                    status_code = 200

                # Format for mobile if requested
                if preferences['mobile'] or preferences['compress']:
                    meta = None
                    if include_meta:
                        meta = {
                            'client': preferences,
                            'server_time': time.time(),
                            'response_time': 0  # Could be calculated
                        }

                    formatted_data = MobileAPIFormatter.success(data, meta)
                    return jsonify(formatted_data), status_code
                else:
                    return jsonify(data), status_code

            except Exception as e:
                error_response = MobileAPIFormatter.error(str(e), 'internal_error')
                return jsonify(error_response), 500

        return wrapper
    return decorator


def create_mobile_endpoints(app):
    """Add mobile-specific endpoints to Flask app"""

    @app.route('/api/mobile/lightning/info', methods=['GET'])
    @mobile_response_wrapper()
    def mobile_lightning_info():
        """Get compressed Lightning info for mobile"""
        try:
            from blncs.lightning.simple_client import SimpleLightningClient
            client = SimpleLightningClient()

            if not client.connected:
                client.connect()

            info = client.get_info()
            compressed = MobileAPIFormatter.compress_lightning_info(info)
            return compressed
        except Exception as e:
            return MobileAPIFormatter.error(str(e), 'lightning_error'), 500

    @app.route('/api/mobile/lightning/balance', methods=['GET'])
    @mobile_response_wrapper()
    def mobile_lightning_balance():
        """Get compressed balance for mobile"""
        try:
            from blncs.lightning.simple_client import SimpleLightningClient
            client = SimpleLightningClient()

            if not client.connected:
                client.connect()

            balance = client.get_balance()
            compressed = MobileAPIFormatter.compress_balance(balance)
            return compressed
        except Exception as e:
            return MobileAPIFormatter.error(str(e), 'lightning_error'), 500

    @app.route('/api/mobile/lightning/invoice', methods=['POST'])
    @mobile_response_wrapper()
    def mobile_create_invoice():
        """Create invoice with mobile-friendly response"""
        try:
            from blncs.lightning.simple_client import SimpleLightningClient

            data = request.get_json()
            if not data or 'amount' not in data:
                return MobileAPIFormatter.error('Amount required', 'invalid_input'), 400

            amount = int(data['amount'])
            memo = data.get('memo', '')

            client = SimpleLightningClient()
            if not client.connected:
                client.connect()

            invoice = client.create_invoice(amount, memo)
            compressed = MobileAPIFormatter.compress_invoice(invoice)

            # Notify WebSocket clients
            try:
                from blncs.api.websocket_server import notify_clients
                notify_clients('invoice_created', compressed)
            except:
                pass

            return compressed
        except Exception as e:
            return MobileAPIFormatter.error(str(e), 'lightning_error'), 500

    @app.route('/api/mobile/system/status', methods=['GET'])
    @mobile_response_wrapper()
    def mobile_system_status():
        """Get compressed system status for mobile"""
        try:
            from blncs.core.health_monitor import quick_health_check

            health = quick_health_check()

            # Compress for mobile
            mobile_status = {
                'status': health['status'],
                'timestamp': health['timestamp'],
                'components': {}
            }

            # Simplify component statuses
            for name, check in health['checks'].items():
                mobile_status['components'][name] = {
                    'status': check['status'],
                    'message': check['message'][:50] + '...' if len(check['message']) > 50 else check['message']
                }

            return mobile_status
        except Exception as e:
            return MobileAPIFormatter.error(str(e), 'system_error'), 500

    @app.route('/api/mobile/transactions', methods=['GET'])
    @mobile_response_wrapper()
    def mobile_transactions():
        """Get paginated transactions for mobile"""
        try:
            page = int(request.args.get('page', 1))
            per_page = min(int(request.args.get('per_page', 10)), 50)  # Limit to 50 for mobile

            # Mock transaction data (replace with real database query)
            transactions = [
                {
                    'id': f'tx_{i}',
                    'type': 'incoming' if i % 2 == 0 else 'outgoing',
                    'amount': 1000 + i * 100,
                    'status': 'confirmed',
                    'timestamp': time.time() - (i * 3600)
                }
                for i in range(1, 101)  # 100 mock transactions
            ]

            return MobileAPIFormatter.paginated(transactions, page, per_page, len(transactions))
        except Exception as e:
            return MobileAPIFormatter.error(str(e), 'data_error'), 500

    @app.route('/api/mobile/qr/<payment_request>', methods=['GET'])
    @mobile_response_wrapper()
    def mobile_qr_code(payment_request):
        """Generate QR code data for mobile (SVG or base64)"""
        try:
            # Simple QR code generation (could use qrcode library)
            qr_data = {
                'payment_request': payment_request,
                'format': 'text',  # Mobile apps can generate QR from text
                'size': request.args.get('size', 'medium'),
                'url': f"lightning:{payment_request}"
            }

            return qr_data
        except Exception as e:
            return MobileAPIFormatter.error(str(e), 'qr_error'), 500

    @app.route('/api/mobile/config', methods=['GET'])
    @mobile_response_wrapper()
    def mobile_config():
        """Get mobile-safe configuration"""
        try:
            from blncs.core.unified_config import get_config
            config = get_config()

            # Only return safe, public configuration
            mobile_config = {
                'network': config.get('lightning.network', 'testnet'),
                'api_version': '1.0',
                'features': {
                    'websockets': True,
                    'qr_codes': True,
                    'push_notifications': False
                },
                'limits': {
                    'max_invoice_amount': 1000000,  # sats
                    'min_invoice_amount': 1,
                    'max_memo_length': 200
                }
            }

            return mobile_config
        except Exception as e:
            return MobileAPIFormatter.error(str(e), 'config_error'), 500

    return app


# Utility functions for mobile optimization
def optimize_for_mobile(data: Dict[str, Any]) -> Dict[str, Any]:
    """Optimize data structure for mobile consumption"""
    if isinstance(data, dict):
        optimized = {}
        for key, value in data.items():
            # Truncate long strings
            if isinstance(value, str) and len(value) > 100:
                optimized[key] = value[:97] + "..."
            # Round floats to reasonable precision
            elif isinstance(value, float):
                optimized[key] = round(value, 6)
            # Recursively optimize nested objects
            elif isinstance(value, dict):
                optimized[key] = optimize_for_mobile(value)
            # Limit array sizes
            elif isinstance(value, list) and len(value) > 50:
                optimized[key] = value[:50]
            else:
                optimized[key] = value
        return optimized
    return data


__all__ = [
    'MobileResponse', 'MobileAPIFormatter', 'mobile_response_wrapper',
    'create_mobile_endpoints', 'detect_mobile_client', 'get_client_preferences',
    'optimize_for_mobile'
]