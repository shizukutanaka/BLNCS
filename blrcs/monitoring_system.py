"""
Advanced Monitoring and Alerting System
National-level monitoring capabilities for enterprise security
"""

import time
import json
import threading
import queue
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import statistics
from collections import defaultdict, deque


class AlertSeverity(Enum):
    """Alert severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class MetricType(Enum):
    """Types of metrics"""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"


@dataclass
class Metric:
    """Metric data structure"""
    name: str
    value: float
    type: MetricType
    labels: Dict[str, str] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    unit: str = ""
    description: str = ""


@dataclass
class Alert:
    """Alert data structure"""
    id: str
    severity: AlertSeverity
    title: str
    message: str
    source: str
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)
    resolved: bool = False
    resolution_time: Optional[float] = None


@dataclass
class HealthCheck:
    """Health check result"""
    component: str
    status: str  # healthy, degraded, unhealthy
    latency_ms: float
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


class MetricsCollector:
    """Collects and aggregates system metrics"""
    
    def __init__(self):
        self.metrics = defaultdict(lambda: deque(maxlen=10000))
        self.aggregations = {}
        self.collection_interval = 10  # seconds
        self.lock = threading.Lock()
        self.running = False
        self.thread = None
        
    def start(self):
        """Start metrics collection"""
        self.running = True
        self.thread = threading.Thread(target=self._collection_loop)
        self.thread.daemon = True
        self.thread.start()
        
    def stop(self):
        """Stop metrics collection"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
            
    def _collection_loop(self):
        """Main collection loop"""
        while self.running:
            self._collect_system_metrics()
            self._aggregate_metrics()
            time.sleep(self.collection_interval)
            
    def _collect_system_metrics(self):
        """Collect system-level metrics"""
        metrics = []
        
        # CPU metrics
        metrics.append(Metric(
            name="system.cpu.usage",
            value=self._get_cpu_usage(),
            type=MetricType.GAUGE,
            unit="percent"
        ))
        
        # Memory metrics
        metrics.append(Metric(
            name="system.memory.usage",
            value=self._get_memory_usage(),
            type=MetricType.GAUGE,
            unit="percent"
        ))
        
        # Disk metrics
        metrics.append(Metric(
            name="system.disk.usage",
            value=self._get_disk_usage(),
            type=MetricType.GAUGE,
            unit="percent"
        ))
        
        # Network metrics
        metrics.append(Metric(
            name="system.network.throughput",
            value=self._get_network_throughput(),
            type=MetricType.GAUGE,
            unit="bytes/sec"
        ))
        
        # Store metrics
        for metric in metrics:
            self.record_metric(metric)
            
    def _get_cpu_usage(self) -> float:
        """Get CPU usage percentage"""
        # Simplified implementation
        import random
        return random.uniform(10, 90)
        
    def _get_memory_usage(self) -> float:
        """Get memory usage percentage"""
        import random
        return random.uniform(30, 80)
        
    def _get_disk_usage(self) -> float:
        """Get disk usage percentage"""
        import random
        return random.uniform(20, 70)
        
    def _get_network_throughput(self) -> float:
        """Get network throughput"""
        import random
        return random.uniform(1000, 100000)
        
    def record_metric(self, metric: Metric):
        """Record a metric"""
        with self.lock:
            key = f"{metric.name}:{json.dumps(metric.labels, sort_keys=True)}"
            self.metrics[key].append(metric)
            
    def get_metrics(self, name: str, labels: Optional[Dict[str, str]] = None, 
                   last_n: int = 100) -> List[Metric]:
        """Get metrics by name and labels"""
        with self.lock:
            key = f"{name}:{json.dumps(labels or {}, sort_keys=True)}"
            return list(self.metrics.get(key, []))[-last_n:]
            
    def _aggregate_metrics(self):
        """Aggregate metrics for reporting"""
        with self.lock:
            for key, metrics in self.metrics.items():
                if len(metrics) > 0:
                    values = [m.value for m in metrics]
                    self.aggregations[key] = {
                        'min': min(values),
                        'max': max(values),
                        'avg': statistics.mean(values),
                        'median': statistics.median(values),
                        'count': len(values),
                        'last': values[-1]
                    }
                    
    def get_aggregations(self) -> Dict[str, Dict[str, float]]:
        """Get aggregated metrics"""
        with self.lock:
            return self.aggregations.copy()


class AlertManager:
    """Manages system alerts and notifications"""
    
    def __init__(self):
        self.alerts = {}
        self.alert_history = deque(maxlen=10000)
        self.alert_rules = []
        self.notification_channels = []
        self.lock = threading.Lock()
        self.alert_queue = queue.Queue()
        self.processing_thread = None
        self.running = False
        
    def start(self):
        """Start alert processing"""
        self.running = True
        self.processing_thread = threading.Thread(target=self._process_alerts)
        self.processing_thread.daemon = True
        self.processing_thread.start()
        
    def stop(self):
        """Stop alert processing"""
        self.running = False
        if self.processing_thread:
            self.alert_queue.put(None)  # Signal to stop
            self.processing_thread.join(timeout=5)
            
    def _process_alerts(self):
        """Process alert queue"""
        while self.running:
            try:
                alert = self.alert_queue.get(timeout=1)
                if alert is None:
                    break
                self._handle_alert(alert)
            except queue.Empty:
                continue
                
    def _handle_alert(self, alert: Alert):
        """Handle an alert"""
        # Apply alert rules
        for rule in self.alert_rules:
            if rule.applies_to(alert):
                rule.process(alert)
                
        # Send notifications
        for channel in self.notification_channels:
            if channel.should_notify(alert):
                channel.send(alert)
                
        # Store alert
        with self.lock:
            self.alerts[alert.id] = alert
            self.alert_history.append(alert)
            
    def create_alert(self, severity: AlertSeverity, title: str, message: str, 
                    source: str, metadata: Optional[Dict[str, Any]] = None) -> Alert:
        """Create and queue an alert"""
        alert_id = hashlib.sha256(
            f"{title}{message}{time.time()}".encode()
        ).hexdigest()[:16]
        
        alert = Alert(
            id=alert_id,
            severity=severity,
            title=title,
            message=message,
            source=source,
            metadata=metadata or {}
        )
        
        self.alert_queue.put(alert)
        return alert
        
    def resolve_alert(self, alert_id: str):
        """Resolve an alert"""
        with self.lock:
            if alert_id in self.alerts:
                alert = self.alerts[alert_id]
                alert.resolved = True
                alert.resolution_time = time.time()
                
    def get_active_alerts(self) -> List[Alert]:
        """Get all active alerts"""
        with self.lock:
            return [a for a in self.alerts.values() if not a.resolved]
            
    def get_alert_history(self, last_n: int = 100) -> List[Alert]:
        """Get alert history"""
        with self.lock:
            return list(self.alert_history)[-last_n:]


class HealthMonitor:
    """Monitors system health"""
    
    def __init__(self):
        self.components = {}
        self.health_checks = {}
        self.check_interval = 30  # seconds
        self.lock = threading.Lock()
        self.running = False
        self.thread = None
        
    def register_component(self, name: str, check_function):
        """Register a component for health checking"""
        self.components[name] = check_function
        
    def start(self):
        """Start health monitoring"""
        self.running = True
        self.thread = threading.Thread(target=self._monitoring_loop)
        self.thread.daemon = True
        self.thread.start()
        
    def stop(self):
        """Stop health monitoring"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
            
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.running:
            self._perform_health_checks()
            time.sleep(self.check_interval)
            
    def _perform_health_checks(self):
        """Perform health checks on all components"""
        for name, check_function in self.components.items():
            start_time = time.time()
            try:
                result = check_function()
                latency_ms = (time.time() - start_time) * 1000
                
                health_check = HealthCheck(
                    component=name,
                    status="healthy" if result else "unhealthy",
                    latency_ms=latency_ms,
                    details=result if isinstance(result, dict) else {}
                )
            except Exception as e:
                latency_ms = (time.time() - start_time) * 1000
                health_check = HealthCheck(
                    component=name,
                    status="unhealthy",
                    latency_ms=latency_ms,
                    details={"error": str(e)}
                )
                
            with self.lock:
                self.health_checks[name] = health_check
                
    def get_health_status(self) -> Dict[str, HealthCheck]:
        """Get current health status"""
        with self.lock:
            return self.health_checks.copy()
            
    def is_healthy(self) -> bool:
        """Check if all components are healthy"""
        with self.lock:
            return all(
                check.status == "healthy" 
                for check in self.health_checks.values()
            )


class MonitoringDashboard:
    """Monitoring dashboard interface"""
    
    def __init__(self, metrics_collector: MetricsCollector, 
                 alert_manager: AlertManager, 
                 health_monitor: HealthMonitor):
        self.metrics = metrics_collector
        self.alerts = alert_manager
        self.health = health_monitor
        
    def get_system_overview(self) -> Dict[str, Any]:
        """Get system overview"""
        return {
            "status": "operational" if self.health.is_healthy() else "degraded",
            "health_checks": {
                name: {
                    "status": check.status,
                    "latency_ms": check.latency_ms
                }
                for name, check in self.health.get_health_status().items()
            },
            "active_alerts": len(self.alerts.get_active_alerts()),
            "metrics_summary": self._get_metrics_summary()
        }
        
    def _get_metrics_summary(self) -> Dict[str, Any]:
        """Get metrics summary"""
        aggregations = self.metrics.get_aggregations()
        summary = {}
        
        for key, values in aggregations.items():
            metric_name = key.split(":")[0]
            if metric_name not in summary:
                summary[metric_name] = values
                
        return summary
        
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics"""
        return {
            "response_time": self._get_response_time_metrics(),
            "throughput": self._get_throughput_metrics(),
            "error_rate": self._get_error_rate_metrics(),
            "resource_usage": self._get_resource_usage_metrics()
        }
        
    def _get_response_time_metrics(self) -> Dict[str, float]:
        """Get response time metrics"""
        metrics = self.metrics.get_metrics("api.response_time")
        if not metrics:
            return {"p50": 0, "p95": 0, "p99": 0}
            
        values = sorted([m.value for m in metrics])
        n = len(values)
        return {
            "p50": values[int(n * 0.5)],
            "p95": values[int(n * 0.95)],
            "p99": values[int(n * 0.99)]
        }
        
    def _get_throughput_metrics(self) -> Dict[str, float]:
        """Get throughput metrics"""
        metrics = self.metrics.get_metrics("api.requests")
        if not metrics:
            return {"rps": 0}
            
        # Calculate requests per second
        if len(metrics) >= 2:
            time_diff = metrics[-1].timestamp - metrics[0].timestamp
            if time_diff > 0:
                rps = len(metrics) / time_diff
            else:
                rps = 0
        else:
            rps = 0
            
        return {"rps": rps}
        
    def _get_error_rate_metrics(self) -> Dict[str, float]:
        """Get error rate metrics"""
        total_metrics = self.metrics.get_metrics("api.requests.total")
        error_metrics = self.metrics.get_metrics("api.requests.errors")
        
        if not total_metrics:
            return {"error_rate": 0}
            
        total = sum(m.value for m in total_metrics)
        errors = sum(m.value for m in error_metrics) if error_metrics else 0
        
        error_rate = (errors / total * 100) if total > 0 else 0
        return {"error_rate": error_rate}
        
    def _get_resource_usage_metrics(self) -> Dict[str, Any]:
        """Get resource usage metrics"""
        cpu_metrics = self.metrics.get_metrics("system.cpu.usage", last_n=1)
        memory_metrics = self.metrics.get_metrics("system.memory.usage", last_n=1)
        disk_metrics = self.metrics.get_metrics("system.disk.usage", last_n=1)
        
        return {
            "cpu": cpu_metrics[0].value if cpu_metrics else 0,
            "memory": memory_metrics[0].value if memory_metrics else 0,
            "disk": disk_metrics[0].value if disk_metrics else 0
        }


class MonitoringSystem:
    """Complete monitoring system"""
    
    def __init__(self):
        self.metrics_collector = MetricsCollector()
        self.alert_manager = AlertManager()
        self.health_monitor = HealthMonitor()
        self.dashboard = MonitoringDashboard(
            self.metrics_collector,
            self.alert_manager,
            self.health_monitor
        )
        
        # Register default health checks
        self._register_default_health_checks()
        
    def _register_default_health_checks(self):
        """Register default health checks"""
        self.health_monitor.register_component("database", self._check_database)
        self.health_monitor.register_component("api", self._check_api)
        self.health_monitor.register_component("cache", self._check_cache)
        self.health_monitor.register_component("storage", self._check_storage)
        
    def _check_database(self) -> bool:
        """Check database health"""
        # Simplified implementation
        return True
        
    def _check_api(self) -> bool:
        """Check API health"""
        return True
        
    def _check_cache(self) -> bool:
        """Check cache health"""
        return True
        
    def _check_storage(self) -> bool:
        """Check storage health"""
        return True
        
    def start(self):
        """Start monitoring system"""
        self.metrics_collector.start()
        self.alert_manager.start()
        self.health_monitor.start()
        
    def stop(self):
        """Stop monitoring system"""
        self.metrics_collector.stop()
        self.alert_manager.stop()
        self.health_monitor.stop()
        
    def record_metric(self, name: str, value: float, 
                     metric_type: MetricType = MetricType.GAUGE,
                     labels: Optional[Dict[str, str]] = None):
        """Record a metric"""
        metric = Metric(
            name=name,
            value=value,
            type=metric_type,
            labels=labels or {}
        )
        self.metrics_collector.record_metric(metric)
        
    def create_alert(self, severity: AlertSeverity, title: str, 
                    message: str, source: str = "system") -> Alert:
        """Create an alert"""
        return self.alert_manager.create_alert(
            severity, title, message, source
        )
        
    def get_status(self) -> Dict[str, Any]:
        """Get complete system status"""
        return {
            "overview": self.dashboard.get_system_overview(),
            "performance": self.dashboard.get_performance_metrics(),
            "alerts": [
                {
                    "id": alert.id,
                    "severity": alert.severity.value,
                    "title": alert.title,
                    "timestamp": alert.timestamp
                }
                for alert in self.alert_manager.get_active_alerts()
            ]
        }


# Global monitoring instance
monitoring = MonitoringSystem()


def get_monitoring_system() -> MonitoringSystem:
    """Get the global monitoring system instance"""
    return monitoring