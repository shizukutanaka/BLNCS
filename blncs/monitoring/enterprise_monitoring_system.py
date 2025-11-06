#!/usr/bin/env python3
"""
Enterprise Monitoring System
Comprehensive monitoring, alerting, and observability platform
"""

import time
import json
import threading
import logging
from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from collections import deque, defaultdict
import hashlib
import statistics
import os
import socket
import psutil

class MetricType(Enum):
    """Types of metrics collected"""
    COUNTER = "counter"      # Monotonically increasing value
    GAUGE = "gauge"          # Point-in-time value
    HISTOGRAM = "histogram"  # Distribution of values
    SUMMARY = "summary"      # Statistical summary

class AlertSeverity(Enum):
    """Alert severity levels"""
    INFO = 1
    WARNING = 2
    ERROR = 3
    CRITICAL = 4
    EMERGENCY = 5

class ServiceStatus(Enum):
    """Service health status"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    CRITICAL = "critical"
    UNKNOWN = "unknown"

@dataclass
class MetricPoint:
    """Single metric data point"""
    timestamp: datetime
    value: float
    tags: Dict[str, str] = field(default_factory=dict)

@dataclass
class Alert:
    """Alert configuration and state"""
    id: str
    name: str
    condition: str
    threshold: float
    severity: AlertSeverity
    message: str
    cooldown: int  # Seconds before re-alerting
    last_triggered: Optional[datetime] = None
    triggered_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ServiceHealth:
    """Service health status"""
    name: str
    status: ServiceStatus
    last_check: datetime
    response_time: float
    error_rate: float
    uptime: float
    metadata: Dict[str, Any] = field(default_factory=dict)

class MetricCollector:
    """Collects and aggregates metrics"""

    def __init__(self, retention_hours: int = 24):
        self.metrics: Dict[str, List[MetricPoint]] = defaultdict(list)
        self.retention_hours = retention_hours
        self._lock = threading.Lock()

    def record(
        self,
        name: str,
        value: float,
        metric_type: MetricType = MetricType.GAUGE,
        tags: Optional[Dict[str, str]] = None
    ):
        """Record a metric value"""
        with self._lock:
            point = MetricPoint(
                timestamp=datetime.now(),
                value=value,
                tags=tags or {}
            )
            self.metrics[name].append(point)
            self._cleanup_old_metrics(name)

    def _cleanup_old_metrics(self, name: str):
        """Remove metrics older than retention period"""
        cutoff = datetime.now() - timedelta(hours=self.retention_hours)
        self.metrics[name] = [
            p for p in self.metrics[name]
            if p.timestamp > cutoff
        ]

    def get_metrics(
        self,
        name: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[MetricPoint]:
        """Get metrics within time range"""
        with self._lock:
            points = self.metrics.get(name, [])

            if start_time:
                points = [p for p in points if p.timestamp >= start_time]
            if end_time:
                points = [p for p in points if p.timestamp <= end_time]

            return points

    def get_aggregated(
        self,
        name: str,
        window_minutes: int = 5
    ) -> Dict[str, float]:
        """Get aggregated metrics for time window"""
        cutoff = datetime.now() - timedelta(minutes=window_minutes)
        points = self.get_metrics(name, start_time=cutoff)

        if not points:
            return {}

        values = [p.value for p in points]
        return {
            "count": len(values),
            "sum": sum(values),
            "avg": statistics.mean(values),
            "min": min(values),
            "max": max(values),
            "p50": statistics.median(values),
            "p95": statistics.quantiles(values, n=20)[18] if len(values) > 1 else values[0],
            "p99": statistics.quantiles(values, n=100)[98] if len(values) > 1 else values[0],
            "stddev": statistics.stdev(values) if len(values) > 1 else 0
        }

class AlertManager:
    """Manages alerts and notifications"""

    def __init__(self):
        self.alerts: Dict[str, Alert] = {}
        self.alert_history: deque = deque(maxlen=1000)
        self.notification_handlers: List[Callable] = []
        self._lock = threading.Lock()
        self.logger = logging.getLogger(__name__)

    def register_alert(self, alert: Alert):
        """Register a new alert"""
        with self._lock:
            self.alerts[alert.id] = alert

    def check_alert(
        self,
        alert_id: str,
        current_value: float
    ) -> Optional[Alert]:
        """Check if alert should trigger"""
        with self._lock:
            alert = self.alerts.get(alert_id)
            if not alert:
                return None

            # Check cooldown
            if alert.last_triggered:
                elapsed = (datetime.now() - alert.last_triggered).total_seconds()
                if elapsed < alert.cooldown:
                    return None

            # Evaluate condition
            should_trigger = self._evaluate_condition(
                alert.condition,
                current_value,
                alert.threshold
            )

            if should_trigger:
                alert.last_triggered = datetime.now()
                alert.triggered_count += 1
                self._trigger_alert(alert, current_value)
                return alert

            return None

    def _evaluate_condition(
        self,
        condition: str,
        value: float,
        threshold: float
    ) -> bool:
        """Evaluate alert condition"""
        conditions = {
            "gt": value > threshold,
            "gte": value >= threshold,
            "lt": value < threshold,
            "lte": value <= threshold,
            "eq": value == threshold,
            "ne": value != threshold
        }
        return conditions.get(condition, False)

    def _trigger_alert(self, alert: Alert, value: float):
        """Trigger alert and notify handlers"""
        alert_data = {
            "id": alert.id,
            "name": alert.name,
            "severity": alert.severity.name,
            "message": alert.message.format(value=value, threshold=alert.threshold),
            "timestamp": datetime.now().isoformat(),
            "value": value,
            "threshold": alert.threshold,
            "triggered_count": alert.triggered_count,
            "metadata": alert.metadata
        }

        # Add to history
        self.alert_history.append(alert_data)

        # Log alert
        if alert.severity == AlertSeverity.EMERGENCY:
            self.logger.critical(f"EMERGENCY ALERT: {alert_data['message']}")
        elif alert.severity == AlertSeverity.CRITICAL:
            self.logger.error(f"CRITICAL ALERT: {alert_data['message']}")
        elif alert.severity == AlertSeverity.ERROR:
            self.logger.error(f"ERROR ALERT: {alert_data['message']}")
        elif alert.severity == AlertSeverity.WARNING:
            self.logger.warning(f"WARNING ALERT: {alert_data['message']}")
        else:
            self.logger.info(f"INFO ALERT: {alert_data['message']}")

        # Notify handlers
        for handler in self.notification_handlers:
            try:
                handler(alert_data)
            except Exception as e:
                self.logger.error(f"Alert notification handler failed: {e}")

    def register_notification_handler(self, handler: Callable):
        """Register alert notification handler"""
        self.notification_handlers.append(handler)

    def get_alert_history(self, limit: int = 100) -> List[Dict]:
        """Get recent alert history"""
        with self._lock:
            return list(self.alert_history)[-limit:]

class ServiceMonitor:
    """Monitors service health and availability"""

    def __init__(self):
        self.services: Dict[str, ServiceHealth] = {}
        self.health_checks: Dict[str, Callable] = {}
        self._lock = threading.Lock()
        self.logger = logging.getLogger(__name__)

    def register_service(
        self,
        name: str,
        health_check: Callable[[], Tuple[bool, float]]
    ):
        """Register a service for monitoring"""
        with self._lock:
            self.health_checks[name] = health_check
            self.services[name] = ServiceHealth(
                name=name,
                status=ServiceStatus.UNKNOWN,
                last_check=datetime.now(),
                response_time=0,
                error_rate=0,
                uptime=0
            )

    def check_service(self, name: str) -> ServiceHealth:
        """Check service health"""
        if name not in self.health_checks:
            return None

        start_time = time.time()
        try:
            is_healthy, response_time = self.health_checks[name]()
            elapsed = time.time() - start_time

            with self._lock:
                service = self.services[name]
                service.last_check = datetime.now()
                service.response_time = response_time or elapsed

                # Update status
                if is_healthy:
                    service.status = ServiceStatus.HEALTHY
                    service.error_rate = max(0, service.error_rate - 0.1)
                else:
                    service.status = ServiceStatus.UNHEALTHY
                    service.error_rate = min(1, service.error_rate + 0.2)

                # Calculate uptime
                if service.status == ServiceStatus.HEALTHY:
                    service.uptime = min(1, service.uptime + 0.01)
                else:
                    service.uptime = max(0, service.uptime - 0.05)

                return service

        except Exception as e:
            self.logger.error(f"Health check failed for {name}: {e}")
            with self._lock:
                service = self.services[name]
                service.status = ServiceStatus.CRITICAL
                service.error_rate = 1.0
                return service

    def get_all_services(self) -> Dict[str, ServiceHealth]:
        """Get all service statuses"""
        with self._lock:
            return dict(self.services)

class EnterpriseMonitoringSystem:
    """Complete enterprise monitoring solution"""

    def __init__(self):
        self.metrics = MetricCollector()
        self.alerts = AlertManager()
        self.services = ServiceMonitor()
        self.logger = logging.getLogger(__name__)

        # System metrics
        self.system_monitor_thread = None
        self.monitoring_enabled = False

        # Dashboard data
        self.dashboard_data = {
            "system": {},
            "services": {},
            "alerts": [],
            "metrics": {}
        }

        self._setup_default_alerts()
        self._setup_default_services()

    def _setup_default_alerts(self):
        """Setup default system alerts"""
        # CPU usage alert
        self.alerts.register_alert(Alert(
            id="cpu_high",
            name="High CPU Usage",
            condition="gt",
            threshold=80,
            severity=AlertSeverity.WARNING,
            message="CPU usage is {value:.1f}% (threshold: {threshold}%)",
            cooldown=300
        ))

        # Memory usage alert
        self.alerts.register_alert(Alert(
            id="memory_high",
            name="High Memory Usage",
            condition="gt",
            threshold=85,
            severity=AlertSeverity.WARNING,
            message="Memory usage is {value:.1f}% (threshold: {threshold}%)",
            cooldown=300
        ))

        # Disk usage alert
        self.alerts.register_alert(Alert(
            id="disk_high",
            name="High Disk Usage",
            condition="gt",
            threshold=90,
            severity=AlertSeverity.ERROR,
            message="Disk usage is {value:.1f}% (threshold: {threshold}%)",
            cooldown=600
        ))

        # Response time alert
        self.alerts.register_alert(Alert(
            id="response_slow",
            name="Slow Response Time",
            condition="gt",
            threshold=1000,  # milliseconds
            severity=AlertSeverity.WARNING,
            message="Response time is {value:.0f}ms (threshold: {threshold}ms)",
            cooldown=180
        ))

        # Error rate alert
        self.alerts.register_alert(Alert(
            id="error_rate_high",
            name="High Error Rate",
            condition="gt",
            threshold=5,  # percent
            severity=AlertSeverity.ERROR,
            message="Error rate is {value:.1f}% (threshold: {threshold}%)",
            cooldown=300
        ))

    def _setup_default_services(self):
        """Setup default service monitors"""
        # API service
        def check_api():
            try:
                # In production, make actual API call
                return True, 50  # Healthy, 50ms response
            except:
                return False, 0

        self.services.register_service("api", check_api)

        # Database service
        def check_database():
            try:
                # In production, check database connection
                return True, 10  # Healthy, 10ms response
            except:
                return False, 0

        self.services.register_service("database", check_database)

        # Lightning service
        def check_lightning():
            try:
                # In production, check Lightning node
                return True, 100  # Healthy, 100ms response
            except:
                return False, 0

        self.services.register_service("lightning", check_lightning)

    def start_monitoring(self):
        """Start monitoring system"""
        if self.monitoring_enabled:
            return

        self.monitoring_enabled = True
        self.system_monitor_thread = threading.Thread(
            target=self._system_monitor_loop,
            daemon=True
        )
        self.system_monitor_thread.start()
        self.logger.info("Enterprise monitoring started")

    def stop_monitoring(self):
        """Stop monitoring system"""
        self.monitoring_enabled = False
        if self.system_monitor_thread:
            self.system_monitor_thread.join(timeout=5)
        self.logger.info("Enterprise monitoring stopped")

    def _system_monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring_enabled:
            try:
                # Collect system metrics
                self._collect_system_metrics()

                # Check services
                self._check_services()

                # Check alerts
                self._check_alerts()

                # Update dashboard
                self._update_dashboard()

                time.sleep(5)  # Check every 5 seconds

            except Exception as e:
                self.logger.error(f"Monitoring loop error: {e}")
                time.sleep(10)

    def _collect_system_metrics(self):
        """Collect system-level metrics"""
        # CPU metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        self.metrics.record("system.cpu.usage", cpu_percent)

        # Memory metrics
        memory = psutil.virtual_memory()
        self.metrics.record("system.memory.usage", memory.percent)
        self.metrics.record("system.memory.available", memory.available / (1024**3))  # GB

        # Disk metrics
        disk = psutil.disk_usage('/')
        self.metrics.record("system.disk.usage", disk.percent)
        self.metrics.record("system.disk.free", disk.free / (1024**3))  # GB

        # Network metrics
        net_io = psutil.net_io_counters()
        self.metrics.record("system.network.bytes_sent", net_io.bytes_sent)
        self.metrics.record("system.network.bytes_recv", net_io.bytes_recv)

        # Process metrics
        process = psutil.Process()
        self.metrics.record("process.cpu.percent", process.cpu_percent())
        self.metrics.record("process.memory.rss", process.memory_info().rss / (1024**2))  # MB
        self.metrics.record("process.threads", process.num_threads())

    def _check_services(self):
        """Check all registered services"""
        for name in list(self.services.health_checks.keys()):
            health = self.services.check_service(name)

            # Record metrics
            self.metrics.record(f"service.{name}.response_time", health.response_time)
            self.metrics.record(f"service.{name}.error_rate", health.error_rate * 100)
            self.metrics.record(f"service.{name}.uptime", health.uptime * 100)

            # Check response time alert
            self.alerts.check_alert("response_slow", health.response_time)

            # Check error rate alert
            if health.error_rate > 0:
                self.alerts.check_alert("error_rate_high", health.error_rate * 100)

    def _check_alerts(self):
        """Check system alerts"""
        # Check CPU alert
        cpu_metrics = self.metrics.get_aggregated("system.cpu.usage", window_minutes=1)
        if cpu_metrics:
            self.alerts.check_alert("cpu_high", cpu_metrics["avg"])

        # Check memory alert
        mem_metrics = self.metrics.get_aggregated("system.memory.usage", window_minutes=1)
        if mem_metrics:
            self.alerts.check_alert("memory_high", mem_metrics["avg"])

        # Check disk alert
        disk_metrics = self.metrics.get_aggregated("system.disk.usage", window_minutes=1)
        if disk_metrics:
            self.alerts.check_alert("disk_high", disk_metrics["avg"])

    def _update_dashboard(self):
        """Update dashboard data"""
        # System metrics
        self.dashboard_data["system"] = {
            "cpu": self.metrics.get_aggregated("system.cpu.usage", window_minutes=5),
            "memory": self.metrics.get_aggregated("system.memory.usage", window_minutes=5),
            "disk": self.metrics.get_aggregated("system.disk.usage", window_minutes=5),
            "network": {
                "bytes_sent": self.metrics.get_aggregated("system.network.bytes_sent", window_minutes=5),
                "bytes_recv": self.metrics.get_aggregated("system.network.bytes_recv", window_minutes=5)
            }
        }

        # Service health
        self.dashboard_data["services"] = {
            name: {
                "status": health.status.value,
                "response_time": health.response_time,
                "error_rate": health.error_rate,
                "uptime": health.uptime,
                "last_check": health.last_check.isoformat()
            }
            for name, health in self.services.get_all_services().items()
        }

        # Recent alerts
        self.dashboard_data["alerts"] = self.alerts.get_alert_history(limit=10)

        # Key metrics
        self.dashboard_data["metrics"] = {
            "total_alerts": len(self.dashboard_data["alerts"]),
            "services_healthy": sum(
                1 for s in self.dashboard_data["services"].values()
                if s["status"] == "healthy"
            ),
            "services_total": len(self.dashboard_data["services"]),
            "timestamp": datetime.now().isoformat()
        }

    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get dashboard display data"""
        return self.dashboard_data

    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get comprehensive metrics summary"""
        return {
            "system": {
                "cpu": self.metrics.get_aggregated("system.cpu.usage", window_minutes=60),
                "memory": self.metrics.get_aggregated("system.memory.usage", window_minutes=60),
                "disk": self.metrics.get_aggregated("system.disk.usage", window_minutes=60)
            },
            "services": {
                name: {
                    "response_time": self.metrics.get_aggregated(
                        f"service.{name}.response_time",
                        window_minutes=60
                    ),
                    "error_rate": self.metrics.get_aggregated(
                        f"service.{name}.error_rate",
                        window_minutes=60
                    ),
                    "uptime": self.metrics.get_aggregated(
                        f"service.{name}.uptime",
                        window_minutes=60
                    )
                }
                for name in self.services.services.keys()
            },
            "alerts": {
                "total": len(self.alerts.alert_history),
                "by_severity": defaultdict(int, {
                    alert.get("severity"): count
                    for alert in self.alerts.alert_history
                    for count in [1]
                })
            }
        }

# Global monitoring instance
_global_monitor = None

def get_global_monitor() -> EnterpriseMonitoringSystem:
    """Get global monitoring instance"""
    global _global_monitor
    if _global_monitor is None:
        _global_monitor = EnterpriseMonitoringSystem()
    return _global_monitor

def setup_enterprise_monitoring():
    """Setup and start enterprise monitoring"""
    monitor = get_global_monitor()

    # Setup notification handlers
    def email_alert_handler(alert_data):
        # In production, send email
        logging.info(f"Would send email for alert: {alert_data['name']}")

    def slack_alert_handler(alert_data):
        # In production, send to Slack
        logging.info(f"Would send to Slack: {alert_data['message']}")

    monitor.alerts.register_notification_handler(email_alert_handler)
    monitor.alerts.register_notification_handler(slack_alert_handler)

    # Start monitoring
    monitor.start_monitoring()

    return monitor

if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Setup and start monitoring
    monitor = setup_enterprise_monitoring()

    # Simulate some activity
    import random
    for i in range(10):
        # Record some metrics
        monitor.metrics.record("api.requests", random.randint(50, 200))
        monitor.metrics.record("api.latency", random.uniform(10, 500))
        monitor.metrics.record("api.errors", random.randint(0, 5))

        time.sleep(2)

    # Display dashboard
    print("\nDashboard Data:")
    print(json.dumps(monitor.get_dashboard_data(), indent=2, default=str))

    # Display metrics summary
    print("\nMetrics Summary:")
    print(json.dumps(monitor.get_metrics_summary(), indent=2, default=str))

    # Stop monitoring
    monitor.stop_monitoring()