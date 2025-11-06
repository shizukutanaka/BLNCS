"""Enterprise Observability and Monitoring System

National-grade monitoring with real-time alerting and deep analytics.
"""

import asyncio
import json
import logging
import time
import threading
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Set, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict, deque
import psutil
import socket
import hashlib
from queue import Queue
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


class AlertSeverity(Enum):
    """Alert severity levels"""
    INFO = 1
    WARNING = 2
    ERROR = 3
    CRITICAL = 4


class MetricType(Enum):
    """Metric data types"""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


@dataclass
class Metric:
    """Individual metric measurement"""
    name: str
    value: Union[int, float]
    metric_type: MetricType
    timestamp: float = field(default_factory=time.time)
    labels: Dict[str, str] = field(default_factory=dict)
    unit: str = ""


@dataclass
class Alert:
    """Alert notification"""
    id: str
    severity: AlertSeverity
    title: str
    message: str
    source: str
    timestamp: float = field(default_factory=time.time)
    resolved: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HealthStatus:
    """System health status"""
    component: str
    status: str  # "healthy", "degraded", "unhealthy"
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


class MetricsCollector:
    """High-performance metrics collection system"""

    def __init__(self, max_metrics: int = 100000):
        self.metrics: deque = deque(maxlen=max_metrics)
        self.metric_aggregates: Dict[str, List[float]] = defaultdict(list)
        self.counters: Dict[str, float] = defaultdict(float)
        self.gauges: Dict[str, float] = {}
        self._lock = threading.RLock()
        self.logger = logging.getLogger(self.__class__.__name__)

    def record_metric(self, metric: Metric):
        """Record a metric measurement"""
        with self._lock:
            self.metrics.append(metric)

            # Update aggregates based on metric type
            if metric.metric_type == MetricType.COUNTER:
                self.counters[metric.name] += metric.value
            elif metric.metric_type == MetricType.GAUGE:
                self.gauges[metric.name] = metric.value
            elif metric.metric_type in [MetricType.HISTOGRAM, MetricType.TIMER]:
                self.metric_aggregates[metric.name].append(metric.value)
                # Keep only recent values for aggregation
                if len(self.metric_aggregates[metric.name]) > 1000:
                    self.metric_aggregates[metric.name] = self.metric_aggregates[metric.name][-1000:]

    def increment_counter(self, name: str, value: float = 1, labels: Optional[Dict] = None):
        """Increment counter metric"""
        metric = Metric(
            name=name,
            value=value,
            metric_type=MetricType.COUNTER,
            labels=labels or {}
        )
        self.record_metric(metric)

    def set_gauge(self, name: str, value: float, labels: Optional[Dict] = None):
        """Set gauge metric"""
        metric = Metric(
            name=name,
            value=value,
            metric_type=MetricType.GAUGE,
            labels=labels or {}
        )
        self.record_metric(metric)

    def record_timer(self, name: str, duration: float, labels: Optional[Dict] = None):
        """Record timing metric"""
        metric = Metric(
            name=name,
            value=duration,
            metric_type=MetricType.TIMER,
            labels=labels or {},
            unit="seconds"
        )
        self.record_metric(metric)

    def get_summary(self, name: str) -> Optional[Dict[str, float]]:
        """Get statistical summary of metric"""
        with self._lock:
            if name not in self.metric_aggregates:
                return None

            values = self.metric_aggregates[name]
            if not values:
                return None

            values.sort()
            n = len(values)

            return {
                'count': n,
                'min': min(values),
                'max': max(values),
                'mean': sum(values) / n,
                'median': values[n // 2],
                'p95': values[int(0.95 * n)] if n > 0 else 0,
                'p99': values[int(0.99 * n)] if n > 0 else 0
            }

    def get_current_values(self) -> Dict[str, Any]:
        """Get current metric values"""
        with self._lock:
            return {
                'counters': dict(self.counters),
                'gauges': dict(self.gauges),
                'histogram_summaries': {
                    name: self.get_summary(name)
                    for name in self.metric_aggregates
                    if self.get_summary(name) is not None
                }
            }


class SystemMonitor:
    """Comprehensive system resource monitoring"""

    def __init__(self, collection_interval: float = 10.0):
        self.collection_interval = collection_interval
        self.monitoring = False
        self._monitor_thread = None
        self._stop_event = threading.Event()
        self.metrics_collector = MetricsCollector()
        self.logger = logging.getLogger(self.__class__.__name__)

    def start(self):
        """Start system monitoring"""
        if self.monitoring:
            return

        self.monitoring = True
        self._stop_event.clear()
        self._monitor_thread = threading.Thread(target=self._monitor_system)
        self._monitor_thread.daemon = True
        self._monitor_thread.start()
        self.logger.info("System monitoring started")

    def stop(self):
        """Stop system monitoring"""
        if not self.monitoring:
            return

        self.monitoring = False
        self._stop_event.set()

        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)

        self.logger.info("System monitoring stopped")

    def _monitor_system(self):
        """Monitor system resources continuously"""
        while self.monitoring and not self._stop_event.is_set():
            try:
                # CPU metrics
                cpu_percent = psutil.cpu_percent(interval=1)
                self.metrics_collector.set_gauge("system.cpu.usage_percent", cpu_percent)

                # Memory metrics
                memory = psutil.virtual_memory()
                self.metrics_collector.set_gauge("system.memory.usage_percent", memory.percent)
                self.metrics_collector.set_gauge("system.memory.available_gb", memory.available / (1024**3))
                self.metrics_collector.set_gauge("system.memory.used_gb", memory.used / (1024**3))

                # Disk metrics
                disk = psutil.disk_usage('/')
                self.metrics_collector.set_gauge("system.disk.usage_percent", (disk.used / disk.total) * 100)
                self.metrics_collector.set_gauge("system.disk.free_gb", disk.free / (1024**3))

                # Network metrics
                network = psutil.net_io_counters()
                self.metrics_collector.increment_counter("system.network.bytes_sent", network.bytes_sent)
                self.metrics_collector.increment_counter("system.network.bytes_recv", network.bytes_recv)

                # Process metrics
                process = psutil.Process()
                self.metrics_collector.set_gauge("process.memory.rss_mb", process.memory_info().rss / (1024**2))
                self.metrics_collector.set_gauge("process.cpu.percent", process.cpu_percent())

                # Load average (Unix-like systems)
                if hasattr(os, 'getloadavg'):
                    load1, load5, load15 = os.getloadavg()
                    self.metrics_collector.set_gauge("system.load.1m", load1)
                    self.metrics_collector.set_gauge("system.load.5m", load5)
                    self.metrics_collector.set_gauge("system.load.15m", load15)

            except Exception as e:
                self.logger.error(f"Error collecting system metrics: {e}")

            self._stop_event.wait(self.collection_interval)

    def get_health_status(self) -> HealthStatus:
        """Get overall system health status"""
        try:
            # Determine health based on resource usage
            cpu_percent = psutil.cpu_percent()
            memory_percent = psutil.virtual_memory().percent
            disk_percent = (psutil.disk_usage('/').used / psutil.disk_usage('/').total) * 100

            # Health thresholds
            if cpu_percent > 90 or memory_percent > 90 or disk_percent > 95:
                status = "unhealthy"
            elif cpu_percent > 70 or memory_percent > 70 or disk_percent > 85:
                status = "degraded"
            else:
                status = "healthy"

            return HealthStatus(
                component="system",
                status=status,
                details={
                    'cpu_percent': cpu_percent,
                    'memory_percent': memory_percent,
                    'disk_percent': disk_percent
                }
            )
        except Exception as e:
            return HealthStatus(
                component="system",
                status="unhealthy",
                details={'error': str(e)}
            )


class AlertManager:
    """Intelligent alert management with escalation"""

    def __init__(self):
        self.active_alerts: Dict[str, Alert] = {}
        self.alert_history: deque = deque(maxlen=10000)
        self.notification_rules: List[Callable] = []
        self.escalation_rules: Dict[AlertSeverity, List[Callable]] = defaultdict(list)
        self.suppression_rules: List[Callable] = []
        self._lock = threading.RLock()
        self.logger = logging.getLogger(self.__class__.__name__)

    def add_notification_rule(self, rule: Callable):
        """Add notification rule"""
        self.notification_rules.append(rule)

    def add_escalation_rule(self, severity: AlertSeverity, escalation: Callable):
        """Add escalation rule for specific severity"""
        self.escalation_rules[severity].append(escalation)

    def add_suppression_rule(self, rule: Callable):
        """Add alert suppression rule"""
        self.suppression_rules.append(rule)

    def raise_alert(self, alert: Alert) -> bool:
        """Raise new alert"""
        with self._lock:
            # Check suppression rules
            for rule in self.suppression_rules:
                if rule(alert):
                    self.logger.debug(f"Alert {alert.id} suppressed by rule")
                    return False

            # Check for duplicate alerts
            if alert.id in self.active_alerts:
                existing = self.active_alerts[alert.id]
                if existing.severity < alert.severity:
                    # Escalate severity
                    existing.severity = alert.severity
                    self._notify_escalation(alert)
                return True

            # Add new alert
            self.active_alerts[alert.id] = alert
            self.alert_history.append(alert)

            # Send notifications
            self._send_notifications(alert)

            # Handle escalations
            if alert.severity in self.escalation_rules:
                for escalation in self.escalation_rules[alert.severity]:
                    try:
                        escalation(alert)
                    except Exception as e:
                        self.logger.error(f"Escalation failed: {e}")

            self.logger.warning(f"Alert raised: {alert.title} ({alert.severity.name})")
            return True

    def resolve_alert(self, alert_id: str) -> bool:
        """Resolve active alert"""
        with self._lock:
            if alert_id not in self.active_alerts:
                return False

            alert = self.active_alerts[alert_id]
            alert.resolved = True
            del self.active_alerts[alert_id]

            self.logger.info(f"Alert resolved: {alert.title}")
            return True

    def _send_notifications(self, alert: Alert):
        """Send alert notifications"""
        for rule in self.notification_rules:
            try:
                rule(alert)
            except Exception as e:
                self.logger.error(f"Notification failed: {e}")

    def _notify_escalation(self, alert: Alert):
        """Notify about alert escalation"""
        self.logger.warning(f"Alert escalated: {alert.title} to {alert.severity.name}")

    def get_active_alerts(self) -> List[Alert]:
        """Get all active alerts"""
        with self._lock:
            return list(self.active_alerts.values())

    def get_alert_summary(self) -> Dict[str, Any]:
        """Get alert statistics"""
        with self._lock:
            severity_counts = defaultdict(int)
            for alert in self.active_alerts.values():
                severity_counts[alert.severity.name] += 1

            return {
                'active_count': len(self.active_alerts),
                'total_history': len(self.alert_history),
                'by_severity': dict(severity_counts)
            }


class LogAnalyzer:
    """Intelligent log analysis and pattern detection"""

    def __init__(self, max_logs: int = 50000):
        self.logs: deque = deque(maxlen=max_logs)
        self.error_patterns: Dict[str, int] = defaultdict(int)
        self.anomaly_threshold = 10  # Anomaly detection threshold
        self._lock = threading.RLock()
        self.logger = logging.getLogger(self.__class__.__name__)

    def analyze_log(self, log_entry: str, level: str = "INFO"):
        """Analyze log entry for patterns and anomalies"""
        with self._lock:
            timestamp = time.time()
            entry = {
                'timestamp': timestamp,
                'level': level,
                'message': log_entry
            }

            self.logs.append(entry)

            # Pattern detection
            if level in ['ERROR', 'CRITICAL']:
                self._detect_error_patterns(log_entry)

            # Anomaly detection
            self._detect_anomalies(level)

    def _detect_error_patterns(self, message: str):
        """Detect common error patterns"""
        # Extract error signatures
        words = message.lower().split()
        error_signature = ' '.join(words[:5])  # First 5 words as signature

        self.error_patterns[error_signature] += 1

        # Alert on frequent errors
        if self.error_patterns[error_signature] >= self.anomaly_threshold:
            alert = Alert(
                id=f"error_pattern_{hashlib.md5(error_signature.encode()).hexdigest()[:8]}",
                severity=AlertSeverity.WARNING,
                title="Frequent Error Pattern Detected",
                message=f"Error pattern '{error_signature}' occurred {self.error_patterns[error_signature]} times",
                source="log_analyzer"
            )
            # This would be sent to AlertManager
            self.logger.warning(f"Error pattern detected: {error_signature}")

    def _detect_anomalies(self, level: str):
        """Detect logging anomalies"""
        if len(self.logs) < 100:
            return

        # Check error rate in last minute
        one_minute_ago = time.time() - 60
        recent_logs = [log for log in self.logs if log['timestamp'] > one_minute_ago]
        error_logs = [log for log in recent_logs if log['level'] in ['ERROR', 'CRITICAL']]

        error_rate = len(error_logs) / len(recent_logs) if recent_logs else 0

        # Alert on high error rate
        if error_rate > 0.1:  # More than 10% errors
            self.logger.warning(f"High error rate detected: {error_rate:.2%}")

    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get log analysis summary"""
        with self._lock:
            level_counts = defaultdict(int)
            for log in self.logs:
                level_counts[log['level']] += 1

            return {
                'total_logs': len(self.logs),
                'by_level': dict(level_counts),
                'top_error_patterns': dict(list(self.error_patterns.items())[:10])
            }


class EnterpriseObservability:
    """Main observability and monitoring system"""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.metrics_collector = MetricsCollector()
        self.system_monitor = SystemMonitor()
        self.alert_manager = AlertManager()
        self.log_analyzer = LogAnalyzer()
        self.health_checks: Dict[str, Callable] = {}
        self.dashboards: Dict[str, Dict] = {}
        self.logger = logging.getLogger(self.__class__.__name__)

        # Setup default alert rules
        self._setup_default_alerts()

    def _setup_default_alerts(self):
        """Setup default system alerts"""
        def cpu_alert_rule():
            cpu_percent = psutil.cpu_percent()
            if cpu_percent > 90:
                return Alert(
                    id="high_cpu",
                    severity=AlertSeverity.WARNING,
                    title="High CPU Usage",
                    message=f"CPU usage at {cpu_percent:.1f}%",
                    source="system_monitor"
                )
            return None

        def memory_alert_rule():
            memory_percent = psutil.virtual_memory().percent
            if memory_percent > 90:
                return Alert(
                    id="high_memory",
                    severity=AlertSeverity.CRITICAL,
                    title="High Memory Usage",
                    message=f"Memory usage at {memory_percent:.1f}%",
                    source="system_monitor"
                )
            return None

        self._alert_rules = [cpu_alert_rule, memory_alert_rule]

    def start(self):
        """Start observability system"""
        self.system_monitor.start()
        self.logger.info("Enterprise observability system started")

        # Start alert monitoring
        self._start_alert_monitoring()

    def stop(self):
        """Stop observability system"""
        self.system_monitor.stop()
        self._stop_alert_monitoring()
        self.logger.info("Enterprise observability system stopped")

    def _start_alert_monitoring(self):
        """Start automated alert monitoring"""
        def monitor_alerts():
            while getattr(self, '_alert_monitoring', True):
                try:
                    for rule in self._alert_rules:
                        alert = rule()
                        if alert:
                            self.alert_manager.raise_alert(alert)
                except Exception as e:
                    self.logger.error(f"Alert monitoring error: {e}")

                time.sleep(30)  # Check every 30 seconds

        self._alert_monitoring = True
        self._alert_thread = threading.Thread(target=monitor_alerts)
        self._alert_thread.daemon = True
        self._alert_thread.start()

    def _stop_alert_monitoring(self):
        """Stop alert monitoring"""
        self._alert_monitoring = False
        if hasattr(self, '_alert_thread'):
            self._alert_thread.join(timeout=5)

    def register_health_check(self, name: str, check_func: Callable):
        """Register custom health check"""
        self.health_checks[name] = check_func
        self.logger.info(f"Registered health check: {name}")

    def create_dashboard(self, name: str, metrics: List[str]):
        """Create monitoring dashboard"""
        self.dashboards[name] = {
            'created': time.time(),
            'metrics': metrics,
            'views': 0
        }
        self.logger.info(f"Created dashboard: {name}")

    def get_dashboard_data(self, dashboard_name: str) -> Dict[str, Any]:
        """Get dashboard data"""
        if dashboard_name not in self.dashboards:
            return {}

        dashboard = self.dashboards[dashboard_name]
        dashboard['views'] += 1

        # Collect metric data
        data = {}
        current_metrics = self.metrics_collector.get_current_values()

        for metric_name in dashboard['metrics']:
            # Find metric in current values
            for category, metrics in current_metrics.items():
                if metric_name in metrics:
                    data[metric_name] = metrics[metric_name]
                    break

        return {
            'dashboard': dashboard_name,
            'data': data,
            'timestamp': time.time()
        }

    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        # System health
        system_health = self.system_monitor.get_health_status()

        # Run custom health checks
        custom_health = {}
        for name, check in self.health_checks.items():
            try:
                custom_health[name] = check()
            except Exception as e:
                custom_health[name] = HealthStatus(
                    component=name,
                    status="unhealthy",
                    details={'error': str(e)}
                )

        return {
            'system_health': asdict(system_health),
            'custom_health': {name: asdict(status) for name, status in custom_health.items()},
            'metrics': self.metrics_collector.get_current_values(),
            'alerts': self.alert_manager.get_alert_summary(),
            'logs': self.log_analyzer.get_analysis_summary(),
            'dashboards': list(self.dashboards.keys())
        }

    def export_metrics(self, format: str = "json") -> str:
        """Export metrics in specified format"""
        data = {
            'timestamp': time.time(),
            'metrics': self.metrics_collector.get_current_values(),
            'system_status': self.get_system_status()
        }

        if format == "json":
            return json.dumps(data, indent=2)
        elif format == "prometheus":
            # Convert to Prometheus format
            lines = []
            for metric_name, value in data['metrics']['gauges'].items():
                lines.append(f"{metric_name.replace('.', '_')} {value}")
            return '\n'.join(lines)
        else:
            raise ValueError(f"Unsupported format: {format}")