"""
Production-Grade Monitoring and Alerting System
Comprehensive monitoring for enterprise deployments
"""

import asyncio
import json
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Union
from dataclasses import dataclass, asdict
from enum import Enum
import psutil
import socket
import requests
from prometheus_client import CollectorRegistry, Counter, Histogram, Gauge, start_http_server
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily, HistogramMetricFamily


class AlertSeverity(Enum):
    """Alert severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AlertStatus(Enum):
    """Alert status"""
    ACTIVE = "active"
    RESOLVED = "resolved"
    SILENCED = "silenced"


@dataclass
class Alert:
    """Alert definition"""
    alert_id: str
    timestamp: datetime
    severity: AlertSeverity
    title: str
    description: str
    component: str
    metric_name: str
    current_value: float
    threshold_value: float
    status: AlertStatus = AlertStatus.ACTIVE
    resolved_at: Optional[datetime] = None
    metadata: Dict[str, Any] = None


@dataclass
class MetricThreshold:
    """Metric threshold definition"""
    metric_name: str
    warning_threshold: Optional[float] = None
    critical_threshold: Optional[float] = None
    operator: str = ">"  # >, <, ==, !=
    check_interval: int = 60  # seconds
    evaluation_window: int = 300  # seconds


class MetricsCollector:
    """Prometheus metrics collector for BLNCS"""

    def __init__(self):
        self.registry = CollectorRegistry()

        # System metrics
        self.cpu_usage = Gauge('blncs_cpu_usage_percent', 'CPU usage percentage', registry=self.registry)
        self.memory_usage = Gauge('blncs_memory_usage_percent', 'Memory usage percentage', registry=self.registry)
        self.memory_usage_bytes = Gauge('blncs_memory_usage_bytes', 'Memory usage in bytes', registry=self.registry)
        self.disk_usage = Gauge('blncs_disk_usage_percent', 'Disk usage percentage', registry=self.registry)
        self.network_io = Gauge('blncs_network_io_bytes_total', 'Network I/O bytes', ['direction'], registry=self.registry)

        # Application metrics
        self.api_requests_total = Counter('blncs_api_requests_total', 'Total API requests', ['method', 'endpoint', 'status'], registry=self.registry)
        self.api_request_duration = Histogram('blncs_api_request_duration_seconds', 'API request duration', ['method', 'endpoint'], registry=self.registry)
        self.active_connections = Gauge('blncs_active_connections', 'Active connections count', registry=self.registry)

        # Lightning Network metrics
        self.lightning_channels_total = Gauge('blncs_lightning_channels_total', 'Total Lightning channels', registry=self.registry)
        self.lightning_channels_active = Gauge('blncs_lightning_channels_active', 'Active Lightning channels', registry=self.registry)
        self.lightning_balance_satoshis = Gauge('blncs_lightning_balance_satoshis', 'Lightning balance in satoshis', registry=self.registry)
        self.lightning_payments_total = Counter('blncs_lightning_payments_total', 'Total Lightning payments', ['status'], registry=self.registry)
        self.lightning_payment_amount = Histogram('blncs_lightning_payment_amount_satoshis', 'Lightning payment amounts', registry=self.registry)

        # Database metrics
        self.database_connections = Gauge('blncs_database_connections', 'Database connections', ['state'], registry=self.registry)
        self.database_query_duration = Histogram('blncs_database_query_duration_seconds', 'Database query duration', ['operation'], registry=self.registry)
        self.database_size_bytes = Gauge('blncs_database_size_bytes', 'Database size in bytes', registry=self.registry)

        # Cache metrics
        self.cache_hits_total = Counter('blncs_cache_hits_total', 'Cache hits', registry=self.registry)
        self.cache_misses_total = Counter('blncs_cache_misses_total', 'Cache misses', registry=self.registry)
        self.cache_size = Gauge('blncs_cache_size', 'Cache size', registry=self.registry)

        # Error metrics
        self.errors_total = Counter('blncs_errors_total', 'Total errors', ['component', 'error_type'], registry=self.registry)
        self.recovery_attempts_total = Counter('blncs_recovery_attempts_total', 'Recovery attempts', ['component', 'success'], registry=self.registry)

    def collect_system_metrics(self):
        """Collect system-level metrics"""
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        self.cpu_usage.set(cpu_percent)

        # Memory usage
        memory = psutil.virtual_memory()
        self.memory_usage.set(memory.percent)
        self.memory_usage_bytes.set(memory.used)

        # Disk usage
        disk = psutil.disk_usage('/')
        disk_percent = (disk.used / disk.total) * 100
        self.disk_usage.set(disk_percent)

        # Network I/O
        net_io = psutil.net_io_counters()
        self.network_io.labels(direction='sent').set(net_io.bytes_sent)
        self.network_io.labels(direction='received').set(net_io.bytes_recv)

    def record_api_request(self, method: str, endpoint: str, status: int, duration: float):
        """Record API request metrics"""
        self.api_requests_total.labels(method=method, endpoint=endpoint, status=str(status)).inc()
        self.api_request_duration.labels(method=method, endpoint=endpoint).observe(duration)

    def record_lightning_payment(self, amount_satoshis: int, success: bool):
        """Record Lightning payment metrics"""
        status = "success" if success else "failed"
        self.lightning_payments_total.labels(status=status).inc()
        if success:
            self.lightning_payment_amount.observe(amount_satoshis)

    def record_database_query(self, operation: str, duration: float):
        """Record database query metrics"""
        self.database_query_duration.labels(operation=operation).observe(duration)

    def record_cache_operation(self, hit: bool):
        """Record cache operation metrics"""
        if hit:
            self.cache_hits_total.inc()
        else:
            self.cache_misses_total.inc()

    def record_error(self, component: str, error_type: str):
        """Record error metrics"""
        self.errors_total.labels(component=component, error_type=error_type).inc()

    def record_recovery_attempt(self, component: str, success: bool):
        """Record recovery attempt metrics"""
        success_str = "success" if success else "failed"
        self.recovery_attempts_total.labels(component=component, success=success_str).inc()


class AlertManager:
    """Alert management system"""

    def __init__(self):
        self.alerts = {}  # alert_id -> Alert
        self.thresholds = {}  # metric_name -> MetricThreshold
        self.notification_channels = []
        self.silenced_alerts = set()
        self.alert_history = []
        self._lock = threading.Lock()

    def add_threshold(self, threshold: MetricThreshold):
        """Add metric threshold"""
        self.thresholds[threshold.metric_name] = threshold

    def add_notification_channel(self, channel: Callable):
        """Add notification channel"""
        self.notification_channels.append(channel)

    def evaluate_thresholds(self, metrics: Dict[str, float]):
        """Evaluate thresholds against current metrics"""
        current_time = datetime.now()

        for metric_name, value in metrics.items():
            if metric_name not in self.thresholds:
                continue

            threshold = self.thresholds[metric_name]

            # Check critical threshold
            if threshold.critical_threshold is not None:
                if self._evaluate_condition(value, threshold.critical_threshold, threshold.operator):
                    self._create_or_update_alert(
                        metric_name, AlertSeverity.CRITICAL, value,
                        threshold.critical_threshold, current_time
                    )
                    continue

            # Check warning threshold
            if threshold.warning_threshold is not None:
                if self._evaluate_condition(value, threshold.warning_threshold, threshold.operator):
                    self._create_or_update_alert(
                        metric_name, AlertSeverity.WARNING, value,
                        threshold.warning_threshold, current_time
                    )
                    continue

            # Resolve alert if conditions are no longer met
            self._resolve_alert_if_exists(metric_name, current_time)

    def _evaluate_condition(self, value: float, threshold: float, operator: str) -> bool:
        """Evaluate threshold condition"""
        if operator == ">":
            return value > threshold
        elif operator == "<":
            return value < threshold
        elif operator == "==":
            return abs(value - threshold) < 0.001
        elif operator == "!=":
            return abs(value - threshold) >= 0.001
        return False

    def _create_or_update_alert(self, metric_name: str, severity: AlertSeverity,
                              current_value: float, threshold_value: float, timestamp: datetime):
        """Create or update alert"""
        alert_id = f"{metric_name}_{severity.value}"

        with self._lock:
            if alert_id in self.alerts and self.alerts[alert_id].status == AlertStatus.ACTIVE:
                # Update existing alert
                self.alerts[alert_id].current_value = current_value
                self.alerts[alert_id].timestamp = timestamp
            else:
                # Create new alert
                alert = Alert(
                    alert_id=alert_id,
                    timestamp=timestamp,
                    severity=severity,
                    title=f"{metric_name} {severity.value.upper()}",
                    description=f"{metric_name} is {current_value}, exceeds {severity.value} threshold of {threshold_value}",
                    component="system",
                    metric_name=metric_name,
                    current_value=current_value,
                    threshold_value=threshold_value,
                    status=AlertStatus.ACTIVE
                )

                self.alerts[alert_id] = alert
                self.alert_history.append(alert)

                # Send notifications
                if alert_id not in self.silenced_alerts:
                    self._send_notifications(alert)

    def _resolve_alert_if_exists(self, metric_name: str, timestamp: datetime):
        """Resolve alert if it exists and is active"""
        for severity in AlertSeverity:
            alert_id = f"{metric_name}_{severity.value}"

            with self._lock:
                if alert_id in self.alerts and self.alerts[alert_id].status == AlertStatus.ACTIVE:
                    self.alerts[alert_id].status = AlertStatus.RESOLVED
                    self.alerts[alert_id].resolved_at = timestamp

    def _send_notifications(self, alert: Alert):
        """Send alert notifications"""
        for channel in self.notification_channels:
            try:
                channel(alert)
            except Exception as e:
                logging.error(f"Failed to send notification: {e}")

    def silence_alert(self, alert_id: str, duration_hours: int = 1):
        """Silence alert for specified duration"""
        self.silenced_alerts.add(alert_id)

        # Auto-remove from silenced list after duration
        def unsilence():
            time.sleep(duration_hours * 3600)
            self.silenced_alerts.discard(alert_id)

        threading.Thread(target=unsilence, daemon=True).start()

    def get_active_alerts(self) -> List[Alert]:
        """Get all active alerts"""
        return [alert for alert in self.alerts.values() if alert.status == AlertStatus.ACTIVE]

    def get_alert_summary(self) -> Dict[str, Any]:
        """Get alert summary"""
        active_alerts = self.get_active_alerts()

        severity_counts = {severity.value: 0 for severity in AlertSeverity}
        for alert in active_alerts:
            severity_counts[alert.severity.value] += 1

        return {
            "total_active": len(active_alerts),
            "severity_breakdown": severity_counts,
            "recent_alerts": [asdict(alert) for alert in self.alert_history[-10:]],
            "silenced_count": len(self.silenced_alerts)
        }


class NotificationChannel:
    """Base class for notification channels"""

    def send(self, alert: Alert):
        """Send alert notification"""
        raise NotImplementedError


class EmailNotificationChannel(NotificationChannel):
    """Email notification channel"""

    def __init__(self, smtp_server: str, smtp_port: int, username: str, password: str, recipients: List[str]):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.recipients = recipients

    def send(self, alert: Alert):
        """Send email notification"""
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        subject = f"BLNCS Alert: {alert.title}"
        body = f"""
        Alert Details:
        - Severity: {alert.severity.value.upper()}
        - Component: {alert.component}
        - Metric: {alert.metric_name}
        - Current Value: {alert.current_value}
        - Threshold: {alert.threshold_value}
        - Time: {alert.timestamp}
        - Description: {alert.description}
        """

        msg = MIMEMultipart()
        msg['From'] = self.username
        msg['To'] = ", ".join(self.recipients)
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.send_message(msg)
        except Exception as e:
            logging.error(f"Failed to send email notification: {e}")


class SlackNotificationChannel(NotificationChannel):
    """Slack notification channel"""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def send(self, alert: Alert):
        """Send Slack notification"""
        color_map = {
            AlertSeverity.INFO: "#36a64f",
            AlertSeverity.WARNING: "#ff9000",
            AlertSeverity.ERROR: "#ff0000",
            AlertSeverity.CRITICAL: "#ff0000"
        }

        payload = {
            "attachments": [{
                "color": color_map.get(alert.severity, "#ff0000"),
                "title": f"BLNCS Alert: {alert.title}",
                "fields": [
                    {"title": "Severity", "value": alert.severity.value.upper(), "short": True},
                    {"title": "Component", "value": alert.component, "short": True},
                    {"title": "Metric", "value": alert.metric_name, "short": True},
                    {"title": "Current Value", "value": str(alert.current_value), "short": True},
                    {"title": "Threshold", "value": str(alert.threshold_value), "short": True},
                    {"title": "Time", "value": alert.timestamp.strftime("%Y-%m-%d %H:%M:%S"), "short": True}
                ],
                "text": alert.description,
                "ts": int(alert.timestamp.timestamp())
            }]
        }

        try:
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            response.raise_for_status()
        except Exception as e:
            logging.error(f"Failed to send Slack notification: {e}")


class WebhookNotificationChannel(NotificationChannel):
    """Generic webhook notification channel"""

    def __init__(self, webhook_url: str, headers: Dict[str, str] = None):
        self.webhook_url = webhook_url
        self.headers = headers or {}

    def send(self, alert: Alert):
        """Send webhook notification"""
        payload = {
            "alert_id": alert.alert_id,
            "timestamp": alert.timestamp.isoformat(),
            "severity": alert.severity.value,
            "title": alert.title,
            "description": alert.description,
            "component": alert.component,
            "metric_name": alert.metric_name,
            "current_value": alert.current_value,
            "threshold_value": alert.threshold_value,
            "status": alert.status.value
        }

        try:
            response = requests.post(
                self.webhook_url,
                json=payload,
                headers=self.headers,
                timeout=10
            )
            response.raise_for_status()
        except Exception as e:
            logging.error(f"Failed to send webhook notification: {e}")


class ProductionMonitoringSystem:
    """Main production monitoring system"""

    def __init__(self):
        self.metrics_collector = MetricsCollector()
        self.alert_manager = AlertManager()
        self.monitoring_active = False
        self.monitoring_thread = None
        self.prometheus_port = 8090

        # Setup default thresholds
        self._setup_default_thresholds()

    def _setup_default_thresholds(self):
        """Setup default monitoring thresholds"""
        thresholds = [
            MetricThreshold("cpu_usage_percent", warning_threshold=80.0, critical_threshold=95.0),
            MetricThreshold("memory_usage_percent", warning_threshold=85.0, critical_threshold=95.0),
            MetricThreshold("disk_usage_percent", warning_threshold=85.0, critical_threshold=95.0),
            MetricThreshold("api_request_duration_p95", warning_threshold=1.0, critical_threshold=5.0),
            MetricThreshold("lightning_channels_active", warning_threshold=5, critical_threshold=2, operator="<"),
            MetricThreshold("database_connections_idle", warning_threshold=20, critical_threshold=30),
            MetricThreshold("error_rate_per_minute", warning_threshold=10, critical_threshold=50)
        ]

        for threshold in thresholds:
            self.alert_manager.add_threshold(threshold)

    def start_monitoring(self):
        """Start monitoring system"""
        if self.monitoring_active:
            return

        self.monitoring_active = True

        # Start Prometheus metrics server
        start_http_server(self.prometheus_port, registry=self.metrics_collector.registry)

        # Start monitoring thread
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()

        logging.info(f"Production monitoring started on port {self.prometheus_port}")

    def stop_monitoring(self):
        """Stop monitoring system"""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)

    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                # Collect system metrics
                self.metrics_collector.collect_system_metrics()

                # Get current metric values for threshold evaluation
                current_metrics = self._get_current_metrics()

                # Evaluate thresholds
                self.alert_manager.evaluate_thresholds(current_metrics)

                # Sleep for monitoring interval
                time.sleep(60)  # Monitor every minute

            except Exception as e:
                logging.error(f"Monitoring loop error: {e}")
                time.sleep(30)  # Back off on error

    def _get_current_metrics(self) -> Dict[str, float]:
        """Get current metric values"""
        # This would collect current values from various sources
        # For now, return basic system metrics

        metrics = {}

        # System metrics
        metrics["cpu_usage_percent"] = psutil.cpu_percent()
        metrics["memory_usage_percent"] = psutil.virtual_memory().percent

        disk = psutil.disk_usage('/')
        metrics["disk_usage_percent"] = (disk.used / disk.total) * 100

        # Application metrics (would be collected from actual sources)
        metrics["api_request_duration_p95"] = 0.5  # Example value
        metrics["lightning_channels_active"] = 10  # Example value
        metrics["database_connections_idle"] = 5  # Example value
        metrics["error_rate_per_minute"] = 2  # Example value

        return metrics

    def add_notification_channel(self, channel: NotificationChannel):
        """Add notification channel"""
        self.alert_manager.add_notification_channel(channel.send)

    def setup_email_notifications(self, smtp_server: str, smtp_port: int,
                                 username: str, password: str, recipients: List[str]):
        """Setup email notifications"""
        channel = EmailNotificationChannel(smtp_server, smtp_port, username, password, recipients)
        self.add_notification_channel(channel)

    def setup_slack_notifications(self, webhook_url: str):
        """Setup Slack notifications"""
        channel = SlackNotificationChannel(webhook_url)
        self.add_notification_channel(channel)

    def setup_webhook_notifications(self, webhook_url: str, headers: Dict[str, str] = None):
        """Setup webhook notifications"""
        channel = WebhookNotificationChannel(webhook_url, headers)
        self.add_notification_channel(channel)

    def get_monitoring_status(self) -> Dict[str, Any]:
        """Get comprehensive monitoring status"""
        return {
            "monitoring_active": self.monitoring_active,
            "prometheus_port": self.prometheus_port,
            "alert_summary": self.alert_manager.get_alert_summary(),
            "thresholds_configured": len(self.alert_manager.thresholds),
            "notification_channels": len(self.alert_manager.notification_channels),
            "uptime_seconds": time.time() if self.monitoring_active else 0
        }

    def create_dashboard_data(self) -> Dict[str, Any]:
        """Create data for monitoring dashboard"""
        return {
            "timestamp": datetime.now().isoformat(),
            "system_metrics": {
                "cpu_percent": psutil.cpu_percent(),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_percent": (psutil.disk_usage('/').used / psutil.disk_usage('/').total) * 100,
                "network_io": {
                    "bytes_sent": psutil.net_io_counters().bytes_sent,
                    "bytes_recv": psutil.net_io_counters().bytes_recv
                }
            },
            "alerts": {
                "active": [asdict(alert) for alert in self.alert_manager.get_active_alerts()],
                "summary": self.alert_manager.get_alert_summary()
            },
            "application_health": {
                "status": "healthy",  # This would be determined by health checks
                "version": "1.0.0",  # Application version
                "uptime": time.time()  # Application uptime
            }
        }


# Global monitoring system instance
_monitoring_system = None
_monitoring_lock = threading.Lock()

def get_monitoring_system() -> ProductionMonitoringSystem:
    """Get global monitoring system instance"""
    global _monitoring_system
    if _monitoring_system is None:
        with _monitoring_lock:
            if _monitoring_system is None:
                _monitoring_system = ProductionMonitoringSystem()
    return _monitoring_system


# Monitoring decorators

def monitor_api_request(endpoint: str):
    """Decorator to monitor API requests"""
    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            start_time = time.time()
            method = "GET"  # Default, should be determined from request
            status = 200    # Default, should be determined from response

            try:
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                status = 500
                raise
            finally:
                duration = time.time() - start_time
                monitoring = get_monitoring_system()
                monitoring.metrics_collector.record_api_request(method, endpoint, status, duration)

        return wrapper
    return decorator


def monitor_database_operation(operation: str):
    """Decorator to monitor database operations"""
    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            start_time = time.time()

            try:
                result = func(*args, **kwargs)
                return result
            finally:
                duration = time.time() - start_time
                monitoring = get_monitoring_system()
                monitoring.metrics_collector.record_database_query(operation, duration)

        return wrapper
    return decorator