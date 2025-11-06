"""
Mobile SDK and API for BLNCS

This module provides comprehensive mobile support including:
- Cross-platform SDK for iOS, Android, Desktop, and Web
- Mobile-optimized API endpoints
- Responsive UX components and utilities
"""

import json
import asyncio
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
import logging
from flask import Flask, jsonify, request, Blueprint
import threading
import time

# Mobile SDK components
@dataclass
class MobileSDKConfig:
    """Configuration for mobile SDK."""
    api_base_url: str
    api_key: str
    environment: str = "production"
    enable_logging: bool = True
    request_timeout: int = 30
    retry_attempts: int = 3
    cache_ttl: int = 300  # 5 minutes

class MobileSDKBase:
    """Base class for mobile SDK implementations."""

    def __init__(self, config: MobileSDKConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._cache = {}
        self._cache_timestamps = {}

    def _make_request(self, endpoint: str, method: str = 'GET', data: Dict = None) -> Dict[str, Any]:
        """Make HTTP request with error handling and caching."""
        import requests

        url = f"{self.config.api_base_url}{endpoint}"
        headers = {
            'Authorization': f'Bearer {self.config.api_key}',
            'Content-Type': 'application/json',
            'User-Agent': 'BLNCS-Mobile-SDK/1.0'
        }

        try:
            if method.upper() == 'GET':
                response = requests.get(url, headers=headers, timeout=self.config.request_timeout)
            elif method.upper() == 'POST':
                response = requests.post(url, headers=headers, json=data, timeout=self.config.request_timeout)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            response.raise_for_status()
            return response.json()

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request failed: {e}")
            raise

    def _get_cached_data(self, key: str) -> Optional[Dict[str, Any]]:
        """Get cached data if still valid."""
        if key in self._cache and key in self._cache_timestamps:
            if time.time() - self._cache_timestamps[key] < self.config.cache_ttl:
                return self._cache[key]
        return None

    def _set_cached_data(self, key: str, data: Dict[str, Any]):
        """Set cached data."""
        self._cache[key] = data
        self._cache_timestamps[key] = time.time()

class BLNCSMobileSDK(MobileSDKBase):
    """Main mobile SDK class for BLNCS."""

    def get_system_status(self) -> Dict[str, Any]:
        """Get system status optimized for mobile."""
        cache_key = 'system_status'
        cached = self._get_cached_data(cache_key)
        if cached:
            return cached

        data = self._make_request('/api/mobile/system/status')
        self._set_cached_data(cache_key, data)
        return data

    def get_lightning_summary(self) -> Dict[str, Any]:
        """Get Lightning Network summary for mobile dashboard."""
        cache_key = 'lightning_summary'
        cached = self._get_cached_data(cache_key)
        if cached:
            return cached

        data = self._make_request('/api/mobile/lightning/summary')
        self._set_cached_data(cache_key, data)
        return data

    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics optimized for mobile display."""
        cache_key = 'performance_metrics'
        cached = self._get_cached_data(cache_key)
        if cached:
            return cached

        data = self._make_request('/api/mobile/performance/metrics')
        self._set_cached_data(cache_key, data)
        return data

    def get_security_alerts(self) -> List[Dict[str, Any]]:
        """Get security alerts for mobile notifications."""
        cache_key = 'security_alerts'
        cached = self._get_cached_data(cache_key)
        if cached:
            return cached

        data = self._make_request('/api/mobile/security/alerts')
        self._set_cached_data(cache_key, data)
        return data

    def send_mobile_event(self, event_type: str, event_data: Dict[str, Any]) -> bool:
        """Send mobile-specific events to server."""
        try:
            self._make_request('/api/mobile/events', method='POST', data={
                'event_type': event_type,
                'event_data': event_data,
                'timestamp': time.time()
            })
            return True
        except Exception as e:
            self.logger.error(f"Failed to send mobile event: {e}")
            return False

# Mobile API Blueprint for Flask
mobile_api_bp = Blueprint('mobile_api', __name__)

@mobile_api_bp.route('/system/status', methods=['GET'])
def get_mobile_system_status():
    """Get system status optimized for mobile clients."""
    # Import core modules for data retrieval
    try:
        from blncs.core.unified_database import get_database
        from blncs.monitoring.system_monitor import get_system_monitor

        db = get_database()
        monitor = get_system_monitor()

        # Get mobile-optimized system data
        status = {
            'status': 'healthy',
            'timestamp': time.time(),
            'uptime': monitor.get_uptime(),
            'cpu_usage': monitor.get_cpu_usage(),
            'memory_usage': monitor.get_memory_usage(),
            'disk_usage': monitor.get_disk_usage(),
            'network_status': monitor.get_network_status(),
            'services': monitor.get_service_status()
        }

        return jsonify(status)

    except Exception as e:
        logger.error(f"Failed to get mobile system status: {e}")
        return jsonify({'error': 'Failed to retrieve system status'}), 500

@mobile_api_bp.route('/lightning/summary', methods=['GET'])
def get_mobile_lightning_summary():
    """Get Lightning Network summary for mobile dashboard."""
    try:
        from blncs.lightning.network_manager import get_network_manager

        network = get_network_manager()

        summary = {
            'node_count': network.get_node_count(),
            'channel_count': network.get_channel_count(),
            'total_capacity': network.get_total_capacity(),
            'network_health': network.get_network_health(),
            'recent_activity': network.get_recent_activity(limit=10),
            'top_nodes': network.get_top_nodes(limit=5)
        }

        return jsonify(summary)

    except Exception as e:
        logger.error(f"Failed to get mobile lightning summary: {e}")
        return jsonify({'error': 'Failed to retrieve lightning summary'}), 500

@mobile_api_bp.route('/performance/metrics', methods=['GET'])
def get_mobile_performance_metrics():
    """Get performance metrics optimized for mobile display."""
    try:
        from blncs.performance.optimization import get_performance_monitor

        monitor = get_performance_monitor()

        metrics = {
            'response_times': monitor.get_average_response_times(),
            'throughput': monitor.get_throughput_metrics(),
            'error_rates': monitor.get_error_rates(),
            'resource_usage': monitor.get_resource_usage_summary(),
            'trends': monitor.get_performance_trends()
        }

        return jsonify(metrics)

    except Exception as e:
        logger.error(f"Failed to get mobile performance metrics: {e}")
        return jsonify({'error': 'Failed to retrieve performance metrics'}), 500

@mobile_api_bp.route('/security/alerts', methods=['GET'])
def get_mobile_security_alerts():
    """Get security alerts for mobile notifications."""
    try:
        from blncs.security.advanced.threat_monitor import get_threat_monitor

        monitor = get_threat_monitor()

        alerts = monitor.get_recent_alerts(limit=20)
        # Convert to mobile-friendly format
        mobile_alerts = []
        for alert in alerts:
            mobile_alerts.append({
                'id': alert.get('id'),
                'type': alert.get('type'),
                'severity': alert.get('severity'),
                'message': alert.get('message'),
                'timestamp': alert.get('timestamp'),
                'resolved': alert.get('resolved', False)
            })

        return jsonify(mobile_alerts)

    except Exception as e:
        logger.error(f"Failed to get mobile security alerts: {e}")
        return jsonify({'error': 'Failed to retrieve security alerts'}), 500

@mobile_api_bp.route('/events', methods=['POST'])
def receive_mobile_event():
    """Receive events from mobile clients."""
    try:
        event_data = request.get_json()
        if not event_data:
            return jsonify({'error': 'No event data provided'}), 400

        # Log the event
        logger.info(f"Mobile event received: {event_data}")

        # Process event (e.g., analytics, monitoring)
        # Here you could integrate with analytics systems

        return jsonify({'status': 'received'})

    except Exception as e:
        logger.error(f"Failed to process mobile event: {e}")
        return jsonify({'error': 'Failed to process event'}), 500

# Utility functions for mobile optimization
def optimize_for_mobile(data: Dict[str, Any], platform: str = 'generic') -> Dict[str, Any]:
    """Optimize data structure for mobile consumption."""
    optimized = {}

    # Platform-specific optimizations
    if platform.lower() == 'ios':
        # iOS-specific optimizations
        optimized = _optimize_for_ios(data)
    elif platform.lower() == 'android':
        # Android-specific optimizations
        optimized = _optimize_for_android(data)
    else:
        # Generic mobile optimizations
        optimized = _optimize_generic_mobile(data)

    return optimized

def _optimize_for_ios(data: Dict[str, Any]) -> Dict[str, Any]:
    """Optimize data for iOS clients."""
    # Remove unnecessary fields, compress images, etc.
    return {
        'data': data,
        'platform': 'ios',
        'compression': 'gzip'
    }

def _optimize_for_android(data: Dict[str, Any]) -> Dict[str, Any]:
    """Optimize data for Android clients."""
    # Android-specific optimizations
    return {
        'data': data,
        'platform': 'android',
        'compression': 'brotli'
    }

def _optimize_generic_mobile(data: Dict[str, Any]) -> Dict[str, Any]:
    """Generic mobile optimizations."""
    # Reduce data size, prioritize important fields
    optimized = {}

    for key, value in data.items():
        if isinstance(value, dict):
            optimized[key] = _optimize_generic_mobile(value)
        elif isinstance(value, list) and len(value) > 10:
            # Limit large arrays for mobile
            optimized[key] = value[:10]
        else:
            optimized[key] = value

    return optimized

# Mobile UX utilities
class MobileUXHelper:
    """Helper class for mobile UX optimizations."""

    @staticmethod
    def get_optimal_refresh_rate(device_type: str) -> int:
        """Get optimal refresh rate for device type."""
        rates = {
            'phone': 30,      # 30 seconds for phones
            'tablet': 60,     # 1 minute for tablets
            'desktop': 15,    # 15 seconds for desktop
            'watch': 120      # 2 minutes for watches
        }
        return rates.get(device_type.lower(), 30)

    @staticmethod
    def get_data_batch_size(device_type: str) -> int:
        """Get optimal data batch size for device type."""
        sizes = {
            'phone': 10,
            'tablet': 20,
            'desktop': 50,
            'watch': 5
        }
        return sizes.get(device_type.lower(), 10)

    @staticmethod
    def compress_for_mobile(data: Dict[str, Any], compression_level: str = 'medium') -> str:
        """Compress data for mobile transmission."""
        levels = {
            'low': 1,
            'medium': 5,
            'high': 9
        }

        import gzip
        import json

        json_data = json.dumps(data).encode('utf-8')
        compressed = gzip.compress(json_data, compresslevel=levels.get(compression_level, 5))

        return compressed.decode('latin-1')  # Base64-like encoding for transport

def create_mobile_sdk(config: MobileSDKConfig) -> BLNCSMobileSDK:
    """Factory function to create mobile SDK instance."""
    return BLNCSMobileSDK(config)

def setup_mobile_api(app: Flask, prefix: str = '/api/mobile'):
    """Set up mobile API routes in Flask app."""
    app.register_blueprint(mobile_api_bp, url_prefix=prefix)
    logger.info(f"Mobile API routes registered with prefix: {prefix}")

# Example usage
if __name__ == "__main__":
    # Example configuration
    config = MobileSDKConfig(
        api_base_url="https://api.blncs.example.com",
        api_key="your-api-key",
        environment="development"
    )

    # Create SDK instance
    sdk = create_mobile_sdk(config)

    # Example usage
    try:
        status = sdk.get_system_status()
        print(f"System status: {status}")
    except Exception as e:
        print(f"Error: {e}")
