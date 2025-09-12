#!/usr/bin/env python3
"""
BLNCS API Client
Python client for interfacing with BLNCS REST API from web dashboard.
"""

import requests
import json
from typing import Dict, Any, List, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class BLNCSAPIClient:
    """Client for BLNCS REST API"""
    
    def __init__(self, base_url: str, api_key: str = None, timeout: int = 30):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.timeout = timeout
        
        # Create session with default headers
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'BLNCS-WebDashboard/1.0'
        })
        
        if self.api_key:
            self.session.headers.update({
                'X-API-Key': self.api_key
            })
    
    def set_api_key(self, api_key: str):
        """Set API key for authentication"""
        self.api_key = api_key
        self.session.headers.update({
            'X-API-Key': api_key
        })
    
    def _request(self, method: str, endpoint: str, data: Optional[Dict] = None, 
                params: Optional[Dict] = None) -> Dict[str, Any]:
        """Make HTTP request to API"""
        url = f"{self.base_url}{endpoint}"
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                json=data,
                params=params,
                timeout=self.timeout
            )
            
            # Log request details
            logger.debug(f"{method} {url} - Status: {response.status_code}")
            
            # Handle different response types
            if response.headers.get('content-type', '').startswith('application/json'):
                result = response.json()
            else:
                result = {'raw_response': response.text}
            
            # Add HTTP status to result
            result['_http_status'] = response.status_code
            result['_success'] = 200 <= response.status_code < 300
            
            return result
            
        except requests.exceptions.Timeout:
            logger.error(f"Request timeout: {method} {url}")
            return {
                'success': False,
                'error': 'Request timeout',
                '_http_status': 408
            }
        except requests.exceptions.ConnectionError:
            logger.error(f"Connection error: {method} {url}")
            return {
                'success': False,
                'error': 'Connection failed',
                '_http_status': 0
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {method} {url} - {e}")
            return {
                'success': False,
                'error': str(e),
                '_http_status': 0
            }
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON response: {method} {url}")
            return {
                'success': False,
                'error': 'Invalid JSON response',
                '_http_status': response.status_code if 'response' in locals() else 0
            }
    
    def test_connection(self) -> bool:
        """Test API connection and authentication"""
        try:
            result = self._request('GET', '/health')
            return result.get('_success', False)
        except Exception:
            return False
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get system status information"""
        return self._request('GET', '/api/v1')
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get system metrics"""
        return self._request('GET', '/api/v1/monitoring/metrics')
    
    def get_detailed_metrics(self) -> Dict[str, Any]:
        """Get detailed system metrics for monitoring dashboard"""
        metrics = self._request('GET', '/api/v1/monitoring/metrics')
        health = self._request('GET', '/api/v1/monitoring/health')
        
        return {
            'metrics': metrics.get('data', {}),
            'health': health.get('data', {}),
            'timestamp': datetime.now().isoformat()
        }
    
    def get_backup_list(self, page: int = 1, per_page: int = 20) -> Dict[str, Any]:
        """Get list of backup items"""
        params = {'page': page, 'per_page': per_page}
        return self._request('GET', '/api/v1/backup/items', params=params)
    
    def get_backup_details(self, backup_id: str) -> Dict[str, Any]:
        """Get detailed information about a backup"""
        return self._request('GET', f'/api/v1/backup/{backup_id}')
    
    def create_backup(self, backup_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new backup"""
        return self._request('POST', '/api/v1/backup/create', data=backup_data)
    
    def create_backup_item(self, item_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new backup item configuration"""
        return self._request('POST', '/api/v1/backup/items', data=item_data)
    
    def validate_backup(self, backup_id: str) -> Dict[str, Any]:
        """Validate backup integrity"""
        return self._request('POST', '/api/v1/backup/validate', 
                           data={'backup_id': backup_id})
    
    def get_schedules(self) -> Dict[str, Any]:
        """Get list of backup schedules"""
        return self._request('GET', '/api/v1/scheduler/schedules')
    
    def create_schedule(self, schedule_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new backup schedule"""
        return self._request('POST', '/api/v1/scheduler/schedules', data=schedule_data)
    
    def delete_schedule(self, schedule_id: str) -> Dict[str, Any]:
        """Delete a backup schedule"""
        return self._request('DELETE', f'/api/v1/scheduler/{schedule_id}')
    
    def start_scheduler(self) -> Dict[str, Any]:
        """Start the backup scheduler"""
        return self._request('POST', '/api/v1/scheduler/start')
    
    def stop_scheduler(self) -> Dict[str, Any]:
        """Stop the backup scheduler"""
        return self._request('POST', '/api/v1/scheduler/stop')
    
    def get_available_backups(self) -> Dict[str, Any]:
        """Get list of backups available for recovery"""
        return self._request('GET', '/api/v1/recovery/backups')
    
    def execute_recovery(self, recovery_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute recovery operation"""
        return self._request('POST', '/api/v1/recovery/execute', data=recovery_data)
    
    def get_storage_backends(self) -> Dict[str, Any]:
        """Get list of storage backends"""
        return self._request('GET', '/api/v1/storage/backends')
    
    def create_storage_backend(self, backend_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new storage backend"""
        return self._request('POST', '/api/v1/storage/backends', data=backend_data)
    
    def get_configuration(self) -> Dict[str, Any]:
        """Get system configuration"""
        return self._request('GET', '/api/v1/config')
    
    def generate_api_key(self, name: str, permissions: List[str]) -> Dict[str, Any]:
        """Generate new API key"""
        return self._request('POST', '/api/v1/auth/generate-key', 
                           data={'name': name, 'permissions': permissions})
    
    def get_auth_stats(self) -> Dict[str, Any]:
        """Get authentication statistics"""
        return self._request('GET', '/api/v1/auth/stats')
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get detailed health status"""
        return self._request('GET', '/api/v1/monitoring/health')
    
    def get_recent_operations(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent operations/activity log"""
        # This would typically come from a dedicated endpoint
        # For now, we'll construct from various status calls
        operations = []
        
        try:
            # Get recent backup activity
            backups = self.get_backup_list(per_page=limit//2)
            if backups.get('success') and backups.get('data'):
                for backup in backups['data']:
                    operations.append({
                        'type': 'backup',
                        'action': 'created' if backup.get('status') == 'completed' else 'failed',
                        'resource': backup.get('name', 'Unknown'),
                        'timestamp': backup.get('created_at', datetime.now().isoformat()),
                        'status': backup.get('status', 'unknown'),
                        'details': f"Size: {backup.get('size_bytes', 0)} bytes"
                    })
            
            # Get recent schedule activity
            schedules = self.get_schedules()
            if schedules.get('success') and schedules.get('data'):
                for schedule in schedules['data'][:limit//2]:
                    operations.append({
                        'type': 'schedule',
                        'action': 'enabled' if schedule.get('enabled') else 'disabled',
                        'resource': schedule.get('name', 'Unknown'),
                        'timestamp': schedule.get('created_at', datetime.now().isoformat()),
                        'status': 'active' if schedule.get('enabled') else 'inactive',
                        'details': f"Type: {schedule.get('schedule_type', 'unknown')}"
                    })
            
            # Sort by timestamp (most recent first)
            operations.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            
        except Exception as e:
            logger.error(f"Failed to get recent operations: {e}")
        
        return operations[:limit]
    
    def get_dashboard_summary(self) -> Dict[str, Any]:
        """Get dashboard summary data"""
        try:
            # Collect data from multiple endpoints
            system_status = self.get_system_status()
            metrics = self.get_metrics()
            health = self.get_health_status()
            backups = self.get_backup_list(per_page=5)
            schedules = self.get_schedules()
            recent_ops = self.get_recent_operations(limit=10)
            
            # Extract key metrics
            backup_count = len(backups.get('data', [])) if backups.get('success') else 0
            schedule_count = len(schedules.get('data', [])) if schedules.get('success') else 0
            active_schedules = sum(1 for s in schedules.get('data', []) 
                                 if s.get('enabled')) if schedules.get('success') else 0
            
            # System health
            overall_health = 'healthy'
            if not health.get('success') or health.get('_http_status', 0) >= 400:
                overall_health = 'unhealthy'
            elif any(component.get('status') != 'healthy' 
                    for component in health.get('data', {}).get('checks', {}).values()):
                overall_health = 'warning'
            
            return {
                'success': True,
                'data': {
                    'system_status': {
                        'health': overall_health,
                        'version': system_status.get('data', {}).get('version', '2.0.0'),
                        'uptime': metrics.get('data', {}).get('system', {}).get('uptime', 0)
                    },
                    'backup_stats': {
                        'total_backups': backup_count,
                        'recent_backups': backups.get('data', [])[:3],
                        'last_backup': backups.get('data', [{}])[0].get('created_at') if backup_count > 0 else None
                    },
                    'schedule_stats': {
                        'total_schedules': schedule_count,
                        'active_schedules': active_schedules,
                        'next_scheduled': None  # Would need additional API endpoint
                    },
                    'resource_usage': {
                        'cpu_percent': metrics.get('data', {}).get('system', {}).get('cpu_percent', 0),
                        'memory_percent': metrics.get('data', {}).get('system', {}).get('memory_percent', 0),
                        'disk_usage': metrics.get('data', {}).get('system', {}).get('disk_usage', 0)
                    },
                    'recent_activity': recent_ops,
                    'alerts': []  # Would be populated from monitoring system
                },
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get dashboard summary: {e}")
            return {
                'success': False,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }