#!/usr/bin/env python3
"""
BLNCS System Health Monitor

Lightweight system health monitoring and alerting.
"""

import asyncio
import time
import psutil
import logging
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from collections import defaultdict, deque

from ..core.exceptions import MonitoringError, PerformanceError

logger = logging.getLogger(__name__)


@dataclass
class HealthCheck:
    """Health check definition"""
    name: str
    check_func: Callable
    interval: int = 30  # seconds
    threshold: Optional[float] = None
    enabled: bool = True


@dataclass
class HealthStatus:
    """Health status for a component"""
    name: str
    status: str  # 'healthy', 'warning', 'critical', 'unknown'
    message: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metrics: Dict[str, Any] = field(default_factory=dict)
    response_time: Optional[float] = None


class SystemHealthMonitor:
    """Lightweight system health monitoring"""

    def __init__(self,
                 check_interval: int = 30,
                 alert_thresholds: Optional[Dict[str, float]] = None):
        self.check_interval = check_interval
        self.alert_thresholds = alert_thresholds or {
            'cpu_percent': 80.0,
            'memory_percent': 85.0,
            'disk_percent': 90.0,
            'response_time': 5.0
        }

        self.health_checks: List[HealthCheck] = []
        self.health_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.alert_callbacks: List[Callable] = []
        self._running = False
        self._monitor_task: Optional[asyncio.Task] = None

        # Register default health checks
        self._register_default_checks()

    def _register_default_checks(self):
        """Register default system health checks"""

        # CPU usage check
        self.add_health_check(
            HealthCheck(
                name="cpu_usage",
                check_func=self._check_cpu_usage,
                interval=30,
                threshold=self.alert_thresholds['cpu_percent']
            )
        )

        # Memory usage check
        self.add_health_check(
            HealthCheck(
                name="memory_usage",
                check_func=self._check_memory_usage,
                interval=30,
                threshold=self.alert_thresholds['memory_percent']
            )
        )

        # Disk usage check
        self.add_health_check(
            HealthCheck(
                name="disk_usage",
                check_func=self._check_disk_usage,
                interval=60,
                threshold=self.alert_thresholds['disk_percent']
            )
        )

        # Network connectivity check
        self.add_health_check(
            HealthCheck(
                name="network_connectivity",
                check_func=self._check_network_connectivity,
                interval=60
            )
        )

    def add_health_check(self, check: HealthCheck):
        """Add a custom health check"""
        self.health_checks.append(check)

    def add_alert_callback(self, callback: Callable[[str, HealthStatus], None]):
        """Add an alert callback function"""
        self.alert_callbacks.append(callback)

    async def start_monitoring(self):
        """Start the health monitoring"""
        if self._running:
            return

        self._running = True
        self._monitor_task = asyncio.create_task(self._monitor_loop())

    async def stop_monitoring(self):
        """Stop the health monitoring"""
        self._running = False
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass

    async def _monitor_loop(self):
        """Main monitoring loop"""
        while self._running:
            try:
                await self._run_health_checks()
                await asyncio.sleep(self.check_interval)
            except Exception as e:
                logger.error(f"Health monitoring error: {e}")
                await asyncio.sleep(self.check_interval)

    async def _run_health_checks(self):
        """Run all enabled health checks"""
        for check in self.health_checks:
            if not check.enabled:
                continue

            try:
                start_time = time.time()
                status = await self._execute_check(check)
                response_time = time.time() - start_time

                status.response_time = response_time
                self.health_history[check.name].append(status)

                # Check if alert should be triggered
                if self._should_alert(status):
                    await self._trigger_alert(check.name, status)

            except Exception as e:
                error_status = HealthStatus(
                    name=check.name,
                    status="critical",
                    message=f"Check failed: {e}",
                    response_time=time.time() - start_time
                )
                self.health_history[check.name].append(error_status)
                await self._trigger_alert(check.name, error_status)

    async def _execute_check(self, check: HealthCheck) -> HealthStatus:
        """Execute a single health check"""
        try:
            if asyncio.iscoroutinefunction(check.check_func):
                result = await check.check_func()
            else:
                result = check.check_func()

            return HealthStatus(
                name=check.name,
                status=result.get('status', 'unknown'),
                message=result.get('message', ''),
                metrics=result.get('metrics', {})
            )

        except Exception as e:
            return HealthStatus(
                name=check.name,
                status="critical",
                message=str(e)
            )

    def _should_alert(self, status: HealthStatus) -> bool:
        """Check if an alert should be triggered"""
        if status.status == "healthy":
            return False

        # Check against thresholds for warning/critical statuses
        if status.name in self.alert_thresholds:
            threshold = self.alert_thresholds[status.name]
            if status.name.endswith('_percent') and status.metrics.get('percent', 0) > threshold:
                return True

        return status.status in ["critical"]

    async def _trigger_alert(self, check_name: str, status: HealthStatus):
        """Trigger alerts for health issues"""
        for callback in self.alert_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(check_name, status)
                else:
                    callback(check_name, status)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")

    def get_current_status(self) -> Dict[str, HealthStatus]:
        """Get current health status for all checks"""
        current_status = {}

        for check_name in [check.name for check in self.health_checks]:
            history = self.health_history[check_name]
            if history:
                current_status[check_name] = history[-1]
            else:
                current_status[check_name] = HealthStatus(
                    name=check_name,
                    status="unknown",
                    message="No data available"
                )

        return current_status

    def get_overall_health(self) -> str:
        """Get overall system health"""
        current_status = self.get_current_status()

        if not current_status:
            return "unknown"

        # Count status types
        status_counts = defaultdict(int)
        for status in current_status.values():
            status_counts[status.status] += 1

        # Determine overall health
        if status_counts["critical"] > 0:
            return "critical"
        elif status_counts["warning"] > 0:
            return "warning"
        elif status_counts["healthy"] == len(current_status):
            return "healthy"
        else:
            return "unknown"

    def _check_cpu_usage(self) -> Dict[str, Any]:
        """Check CPU usage"""
        cpu_percent = psutil.cpu_percent(interval=1)

        if cpu_percent > self.alert_thresholds['cpu_percent']:
            status = "warning"
            message = f"High CPU usage: {cpu_percent:.1f}%"
        else:
            status = "healthy"
            message = f"CPU usage: {cpu_percent:.1f}%"

        return {
            'status': status,
            'message': message,
            'metrics': {
                'percent': cpu_percent,
                'cores': psutil.cpu_count()
            }
        }

    def _check_memory_usage(self) -> Dict[str, Any]:
        """Check memory usage"""
        memory = psutil.virtual_memory()
        memory_percent = memory.percent

        if memory_percent > self.alert_thresholds['memory_percent']:
            status = "warning"
            message = f"High memory usage: {memory_percent:.1f}%"
        else:
            status = "healthy"
            message = f"Memory usage: {memory_percent:.1f}%"

        return {
            'status': status,
            'message': message,
            'metrics': {
                'percent': memory_percent,
                'used': memory.used,
                'available': memory.available,
                'total': memory.total
            }
        }

    def _check_disk_usage(self) -> Dict[str, Any]:
        """Check disk usage"""
        disk = psutil.disk_usage('/')
        disk_percent = disk.percent

        if disk_percent > self.alert_thresholds['disk_percent']:
            status = "warning"
            message = f"High disk usage: {disk_percent:.1f}%"
        else:
            status = "healthy"
            message = f"Disk usage: {disk_percent:.1f}%"

        return {
            'status': status,
            'message': message,
            'metrics': {
                'percent': disk_percent,
                'used': disk.used,
                'free': disk.free,
                'total': disk.total
            }
        }

    def _check_network_connectivity(self) -> Dict[str, Any]:
        """Check network connectivity"""
        try:
            # Simple connectivity check
            network = psutil.net_if_addrs()
            if not network:
                return {
                    'status': 'critical',
                    'message': 'No network interfaces found'
                }

            # Check if we can resolve DNS
            import socket
            try:
                socket.gethostbyname('google.com')
                status = "healthy"
                message = "Network connectivity OK"
            except socket.gaierror:
                status = "warning"
                message = "DNS resolution failed"

        except Exception as e:
            status = "critical"
            message = f"Network check failed: {e}"

        return {
            'status': status,
            'message': message
        }


class HealthAlertManager:
    """Lightweight alert management"""

    def __init__(self):
        self.alert_history: List[Dict[str, Any]] = []
        self.max_history = 1000

    def log_alert(self, check_name: str, status: HealthStatus):
        """Log an alert"""
        alert = {
            'timestamp': status.timestamp,
            'check_name': check_name,
            'status': status.status,
            'message': status.message,
            'metrics': status.metrics
        }

        self.alert_history.append(alert)

        # Trim history if needed
        if len(self.alert_history) > self.max_history:
            self.alert_history = self.alert_history[-self.max_history:]

    def get_recent_alerts(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent alerts"""
        return self.alert_history[-limit:]

    def get_alert_summary(self) -> Dict[str, Any]:
        """Get alert summary"""
        if not self.alert_history:
            return {'total_alerts': 0}

        recent_alerts = self.alert_history[-100:]  # Last 100 alerts

        status_counts = defaultdict(int)
        for alert in recent_alerts:
            status_counts[alert['status']] += 1

        return {
            'total_alerts': len(self.alert_history),
            'recent_alerts': len(recent_alerts),
            'status_counts': dict(status_counts),
            'last_alert': recent_alerts[-1] if recent_alerts else None
        }


# Global instances
_health_monitor = None
_alert_manager = None

def get_health_monitor() -> SystemHealthMonitor:
    """Get global health monitor instance"""
    global _health_monitor
    if _health_monitor is None:
        _health_monitor = SystemHealthMonitor()
    return _health_monitor

def get_alert_manager() -> HealthAlertManager:
    """Get global alert manager instance"""
    global _alert_manager
    if _alert_manager is None:
        _alert_manager = HealthAlertManager()
    return _alert_manager
