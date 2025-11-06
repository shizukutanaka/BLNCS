"""
BLNCS Practical Lightning Monitor
Real-world monitoring for Lightning Network operations
"""

import time
import json
import logging
import threading
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
from pathlib import Path
from collections import deque, defaultdict
from enum import Enum


class AlertLevel(Enum):
    """Alert severity levels"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


@dataclass
class LightningMetric:
    """Lightning-specific metric data point"""
    name: str
    value: float
    unit: str
    timestamp: float
    node_id: Optional[str] = None
    channel_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class Alert:
    """System alert"""
    alert_id: str
    level: AlertLevel
    title: str
    description: str
    timestamp: float
    source: str
    resolved: bool = False
    resolved_at: Optional[float] = None


class MetricCollector:
    """Collect Lightning Network metrics"""

    def __init__(self):
        self.metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.lock = threading.RLock()
        self.logger = logging.getLogger("BLNCS_MetricCollector")

    def record_metric(self, name: str, value: float, unit: str = "",
                     node_id: str = None, channel_id: str = None,
                     metadata: Dict[str, Any] = None):
        """Record a metric data point"""
        metric = LightningMetric(
            name=name,
            value=value,
            unit=unit,
            timestamp=time.time(),
            node_id=node_id,
            channel_id=channel_id,
            metadata=metadata or {}
        )

        with self.lock:
            self.metrics[name].append(metric)

    def get_recent_metrics(self, name: str, minutes: int = 60) -> List[LightningMetric]:
        """Get recent metrics for a given name"""
        cutoff_time = time.time() - (minutes * 60)

        with self.lock:
            return [
                metric for metric in self.metrics[name]
                if metric.timestamp >= cutoff_time
            ]

    def get_metric_summary(self, name: str, minutes: int = 60) -> Dict[str, Any]:
        """Get statistical summary of metrics"""
        recent_metrics = self.get_recent_metrics(name, minutes)

        if not recent_metrics:
            return {"count": 0}

        values = [m.value for m in recent_metrics]

        return {
            "count": len(values),
            "min": min(values),
            "max": max(values),
            "avg": sum(values) / len(values),
            "latest": values[-1] if values else 0,
            "unit": recent_metrics[0].unit if recent_metrics else ""
        }


class AlertManager:
    """Manage system alerts and notifications"""

    def __init__(self, max_alerts: int = 500):
        self.alerts: Dict[str, Alert] = {}
        self.alert_history: deque = deque(maxlen=max_alerts)
        self.alert_handlers: List[Callable] = []
        self.lock = threading.RLock()
        self.logger = logging.getLogger("BLNCS_AlertManager")

    def add_alert_handler(self, handler: Callable[[Alert], None]):
        """Add alert notification handler"""
        self.alert_handlers.append(handler)

    def create_alert(self, level: AlertLevel, title: str, description: str,
                    source: str = "system") -> Alert:
        """Create and process a new alert"""
        alert_id = f"alert_{int(time.time() * 1000)}"

        alert = Alert(
            alert_id=alert_id,
            level=level,
            title=title,
            description=description,
            timestamp=time.time(),
            source=source
        )

        with self.lock:
            self.alerts[alert_id] = alert
            self.alert_history.append(alert)

        # Log alert
        log_method = {
            AlertLevel.INFO: self.logger.info,
            AlertLevel.WARNING: self.logger.warning,
            AlertLevel.CRITICAL: self.logger.critical,
            AlertLevel.EMERGENCY: self.logger.critical
        }.get(level, self.logger.info)

        log_method(f"ALERT [{level.value.upper()}]: {title} - {description}")

        # Notify handlers
        for handler in self.alert_handlers:
            try:
                handler(alert)
            except Exception as e:
                self.logger.error(f"Alert handler error: {e}")

        return alert

    def resolve_alert(self, alert_id: str) -> bool:
        """Mark alert as resolved"""
        with self.lock:
            alert = self.alerts.get(alert_id)
            if alert and not alert.resolved:
                alert.resolved = True
                alert.resolved_at = time.time()
                self.logger.info(f"Alert resolved: {alert_id}")
                return True

        return False

    def get_active_alerts(self, level: AlertLevel = None) -> List[Alert]:
        """Get active (unresolved) alerts"""
        with self.lock:
            alerts = [alert for alert in self.alerts.values() if not alert.resolved]

            if level:
                alerts = [alert for alert in alerts if alert.level == level]

            return sorted(alerts, key=lambda a: a.timestamp, reverse=True)


class HealthChecker:
    """Monitor system health and trigger alerts"""

    def __init__(self, metric_collector: MetricCollector, alert_manager: AlertManager):
        self.metric_collector = metric_collector
        self.alert_manager = alert_manager
        self.health_checks: Dict[str, Callable] = {}
        self.check_intervals: Dict[str, float] = {}
        self.last_checks: Dict[str, float] = {}
        self.running = False
        self.check_thread: Optional[threading.Thread] = None
        self.logger = logging.getLogger("BLNCS_HealthChecker")

    def register_check(self, name: str, check_func: Callable[[], bool],
                      interval_seconds: float = 60):
        """Register a health check function"""
        self.health_checks[name] = check_func
        self.check_intervals[name] = interval_seconds
        self.last_checks[name] = 0

    def start_monitoring(self):
        """Start background health monitoring"""
        if self.running:
            return

        self.running = True
        self.check_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.check_thread.start()
        self.logger.info("Health monitoring started")

    def stop_monitoring(self):
        """Stop background health monitoring"""
        self.running = False
        if self.check_thread:
            self.check_thread.join(timeout=5)
        self.logger.info("Health monitoring stopped")

    def _monitoring_loop(self):
        """Background monitoring loop"""
        while self.running:
            current_time = time.time()

            for check_name, check_func in self.health_checks.items():
                last_check = self.last_checks[check_name]
                interval = self.check_intervals[check_name]

                if current_time - last_check >= interval:
                    try:
                        healthy = check_func()
                        self.last_checks[check_name] = current_time

                        if not healthy:
                            self.alert_manager.create_alert(
                                AlertLevel.WARNING,
                                f"Health check failed: {check_name}",
                                f"System health check '{check_name}' reported unhealthy status",
                                "health_checker"
                            )

                    except Exception as e:
                        self.logger.error(f"Health check '{check_name}' error: {e}")
                        self.alert_manager.create_alert(
                            AlertLevel.CRITICAL,
                            f"Health check error: {check_name}",
                            f"Health check '{check_name}' raised exception: {str(e)}",
                            "health_checker"
                        )

            time.sleep(1)  # Check every second for due health checks


class PracticalMonitor:
    """Comprehensive Lightning Network monitoring system"""

    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)

        self.metric_collector = MetricCollector()
        self.alert_manager = AlertManager()
        self.health_checker = HealthChecker(self.metric_collector, self.alert_manager)

        self.monitor_file = self.data_dir / "monitor_data.json"
        self.logger = logging.getLogger("BLNCS_PracticalMonitor")

        self._register_default_checks()
        self._setup_default_alerts()

    def _register_default_checks(self):
        """Register default health checks"""
        # Channel connectivity check
        def check_channel_connectivity():
            # Simplified check - in real implementation would check actual channels
            channel_metrics = self.metric_collector.get_recent_metrics("active_channels", 5)
            return len(channel_metrics) > 0 or True  # Default to healthy for demo

        # Payment success rate check
        def check_payment_success_rate():
            successful = self.metric_collector.get_recent_metrics("payment_success", 60)
            failed = self.metric_collector.get_recent_metrics("payment_failure", 60)

            if not successful and not failed:
                return True  # No payments, healthy

            total = len(successful) + len(failed)
            success_rate = len(successful) / total if total > 0 else 1.0

            return success_rate >= 0.8  # 80% success rate threshold

        # Node synchronization check
        def check_node_sync():
            sync_metrics = self.metric_collector.get_recent_metrics("sync_height", 10)
            if not sync_metrics:
                return True  # No sync data available, assume healthy

            # Check if sync height is recent
            latest_sync = sync_metrics[-1]
            return time.time() - latest_sync.timestamp < 300  # 5 minute threshold

        self.health_checker.register_check("channel_connectivity", check_channel_connectivity, 60)
        self.health_checker.register_check("payment_success_rate", check_payment_success_rate, 300)
        self.health_checker.register_check("node_sync", check_node_sync, 120)

    def _setup_default_alerts(self):
        """Setup default alert handlers"""
        def console_alert_handler(alert: Alert):
            severity_icons = {
                AlertLevel.INFO: "ℹ️",
                AlertLevel.WARNING: "⚠️",
                AlertLevel.CRITICAL: "🚨",
                AlertLevel.EMERGENCY: "🔥"
            }
            icon = severity_icons.get(alert.level, "📢")
            print(f"{icon} [{alert.level.value.upper()}] {alert.title}: {alert.description}")

        self.alert_manager.add_alert_handler(console_alert_handler)

    def record_payment_attempt(self, amount_sats: int, success: bool,
                              fee_sats: int = 0, duration_ms: int = 0):
        """Record payment attempt metrics"""
        timestamp = time.time()

        self.metric_collector.record_metric("payment_amount", amount_sats, "sats")
        self.metric_collector.record_metric("payment_fee", fee_sats, "sats")
        self.metric_collector.record_metric("payment_duration", duration_ms, "ms")

        if success:
            self.metric_collector.record_metric("payment_success", 1, "count")
        else:
            self.metric_collector.record_metric("payment_failure", 1, "count")

    def record_channel_event(self, channel_id: str, event_type: str,
                            balance_local: int = 0, balance_remote: int = 0):
        """Record channel-related events"""
        self.metric_collector.record_metric(
            f"channel_{event_type}", 1, "count",
            channel_id=channel_id
        )

        if balance_local > 0:
            self.metric_collector.record_metric(
                "channel_balance_local", balance_local, "sats",
                channel_id=channel_id
            )

        if balance_remote > 0:
            self.metric_collector.record_metric(
                "channel_balance_remote", balance_remote, "sats",
                channel_id=channel_id
            )

    def record_node_metrics(self, node_id: str, sync_height: int = 0,
                           peer_count: int = 0, channel_count: int = 0):
        """Record node operational metrics"""
        if sync_height > 0:
            self.metric_collector.record_metric(
                "sync_height", sync_height, "blocks",
                node_id=node_id
            )

        if peer_count > 0:
            self.metric_collector.record_metric(
                "peer_count", peer_count, "count",
                node_id=node_id
            )

        if channel_count > 0:
            self.metric_collector.record_metric(
                "active_channels", channel_count, "count",
                node_id=node_id
            )

    def get_system_health(self) -> Dict[str, Any]:
        """Get overall system health status"""
        active_alerts = self.alert_manager.get_active_alerts()

        # Count alerts by severity
        alert_counts = defaultdict(int)
        for alert in active_alerts:
            alert_counts[alert.level.value] += 1

        # Get key metrics summaries
        payment_success = self.metric_collector.get_metric_summary("payment_success", 60)
        payment_failure = self.metric_collector.get_metric_summary("payment_failure", 60)
        channel_count = self.metric_collector.get_metric_summary("active_channels", 5)

        # Calculate health score (0-100)
        health_score = 100
        if alert_counts["critical"] > 0:
            health_score -= 30
        if alert_counts["warning"] > 0:
            health_score -= 10
        if alert_counts["emergency"] > 0:
            health_score -= 50

        health_score = max(0, health_score)

        return {
            "health_score": health_score,
            "status": "healthy" if health_score >= 80 else "degraded" if health_score >= 50 else "unhealthy",
            "active_alerts": len(active_alerts),
            "alert_breakdown": dict(alert_counts),
            "recent_payments": payment_success.get("count", 0) + payment_failure.get("count", 0),
            "payment_success_rate": (
                payment_success.get("count", 0) /
                max(1, payment_success.get("count", 0) + payment_failure.get("count", 0)) * 100
            ),
            "active_channels": channel_count.get("latest", 0),
            "monitoring_active": self.health_checker.running
        }

    def start_monitoring(self):
        """Start all monitoring subsystems"""
        self.health_checker.start_monitoring()
        self.logger.info("Practical monitoring started")

    def stop_monitoring(self):
        """Stop all monitoring subsystems"""
        self.health_checker.stop_monitoring()
        self.logger.info("Practical monitoring stopped")

    def export_metrics(self, hours: int = 24) -> Dict[str, Any]:
        """Export metrics for external analysis"""
        cutoff_time = time.time() - (hours * 3600)

        exported_data = {
            "export_timestamp": time.time(),
            "hours_included": hours,
            "metrics": {}
        }

        for metric_name, metric_history in self.metric_collector.metrics.items():
            recent_metrics = [
                asdict(metric) for metric in metric_history
                if metric.timestamp >= cutoff_time
            ]
            exported_data["metrics"][metric_name] = recent_metrics

        return exported_data


def create_practical_monitor(data_dir: str = "data") -> PracticalMonitor:
    """Create practical monitoring system"""
    return PracticalMonitor(data_dir)


if __name__ == "__main__":
    # Test practical monitoring
    print("📊 Testing Practical Lightning Monitor...")

    monitor = create_practical_monitor("test_data")

    # Start monitoring
    monitor.start_monitoring()

    # Simulate some events
    monitor.record_payment_attempt(100000, True, 1000, 5000)
    monitor.record_payment_attempt(50000, False, 0, 30000)
    monitor.record_channel_event("channel123", "update", 800000, 200000)
    monitor.record_node_metrics("node1", 750000, 10, 5)

    # Create test alert
    monitor.alert_manager.create_alert(
        AlertLevel.WARNING,
        "Test Alert",
        "This is a test alert for demonstration",
        "test_system"
    )

    # Get health status
    health = monitor.get_system_health()
    print(f"🏥 System health: {health['status']} (score: {health['health_score']})")
    print(f"📈 Recent payments: {health['recent_payments']}")
    print(f"✅ Success rate: {health['payment_success_rate']:.1f}%")
    print(f"📊 Active alerts: {health['active_alerts']}")

    # Export metrics
    metrics_export = monitor.export_metrics(1)
    print(f"📤 Exported metrics: {len(metrics_export['metrics'])} types")

    # Stop monitoring
    monitor.stop_monitoring()

    # Cleanup
    import shutil
    shutil.rmtree("test_data", ignore_errors=True)

    print("✅ Practical monitor test completed!")