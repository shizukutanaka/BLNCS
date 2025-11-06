"""
Advanced Observability and Monitoring System for BLNCS

This module provides comprehensive observability including:
- Distributed tracing (OpenTelemetry/Jaeger)
- Log aggregation and analysis
- Metrics aggregation and alerting
- Anomaly detection and predictive monitoring
- Real-time dashboards and reporting
"""

import time
import json
import logging
import threading
import asyncio
import multiprocessing
from typing import Dict, List, Optional, Any, Callable, Set, Tuple, Union
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
from datetime import datetime, timedelta
import random
import statistics
import numpy as np

# Try to import observability libraries
try:
    import opentelemetry
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
    HAS_OPENTELEMETRY = True
except ImportError:
    HAS_OPENTELEMETRY = False

logger = logging.getLogger(__name__)

@dataclass
class TraceSpan:
    """Distributed trace span."""
    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    operation_name: str
    start_time: float
    end_time: Optional[float]
    duration: Optional[float]
    tags: Dict[str, str]
    logs: List[Dict[str, Any]]
    service_name: str
    status: str = "ok"

@dataclass
class LogEntry:
    """Enhanced log entry."""
    timestamp: float
    level: str
    message: str
    source: str
    service: str
    trace_id: Optional[str]
    span_id: Optional[str]
    metadata: Dict[str, Any]

@dataclass
class MetricPoint:
    """Metric data point."""
    timestamp: float
    value: float
    labels: Dict[str, str]
    metric_name: str

@dataclass
class AnomalyDetectionResult:
    """Anomaly detection result."""
    timestamp: float
    metric_name: str
    current_value: float
    predicted_value: float
    anomaly_score: float
    severity: str  # low, medium, high, critical
    description: str

class DistributedTracer:
    """Distributed tracing system."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.DistributedTracer")
        self.traces: Dict[str, List[TraceSpan]] = defaultdict(list)
        self.active_spans: Dict[str, TraceSpan] = {}
        self.trace_export_active = False
        self.export_thread = None

        if HAS_OPENTELEMETRY:
            self._initialize_opentelemetry()

    def _initialize_opentelemetry(self):
        """Initialize OpenTelemetry tracing."""
        try:
            trace.set_tracer_provider(TracerProvider())
            tracer = trace.get_tracer(__name__)

            # Add console exporter for demo
            span_processor = BatchSpanProcessor(ConsoleSpanExporter())
            trace.get_tracer_provider().add_span_processor(span_processor)

            self.tracer = tracer
            self.logger.info("OpenTelemetry tracing initialized")

        except Exception as e:
            self.logger.warning(f"OpenTelemetry initialization failed: {e}")

    def start_span(self, operation_name: str, parent_span_id: str = None, service_name: str = "blncs") -> str:
        """Start a new trace span."""
        span_id = f"span_{secrets.token_hex(8)}"
        trace_id = parent_span_id or f"trace_{secrets.token_hex(8)}"

        span = TraceSpan(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            operation_name=operation_name,
            start_time=time.time(),
            end_time=None,
            duration=None,
            tags={'service': service_name},
            logs=[],
            service_name=service_name
        )

        self.traces[trace_id].append(span)
        self.active_spans[span_id] = span

        self.logger.debug(f"Started span: {operation_name} ({span_id})")
        return span_id

    def end_span(self, span_id: str, status: str = "ok", error_message: str = None):
        """End a trace span."""
        if span_id not in self.active_spans:
            return

        span = self.active_spans[span_id]
        span.end_time = time.time()
        span.duration = span.end_time - span.start_time
        span.status = status

        if error_message:
            span.logs.append({
                'timestamp': time.time(),
                'level': 'error',
                'message': error_message
            })

        del self.active_spans[span_id]

        self.logger.debug(f"Ended span: {span.operation_name} ({span.duration:.3f}s)")

    def add_span_tag(self, span_id: str, key: str, value: str):
        """Add tag to span."""
        if span_id in self.active_spans:
            self.active_spans[span_id].tags[key] = value

    def add_span_log(self, span_id: str, message: str, level: str = "info"):
        """Add log entry to span."""
        if span_id in self.active_spans:
            self.active_spans[span_id].logs.append({
                'timestamp': time.time(),
                'level': level,
                'message': message
            })

    def get_trace(self, trace_id: str) -> List[Dict[str, Any]]:
        """Get complete trace."""
        return [asdict(span) for span in self.traces.get(trace_id, [])]

    def export_traces(self, format: str = 'jaeger') -> str:
        """Export traces in specified format."""
        if format.lower() == 'jaeger':
            return self._export_jaeger_format()
        else:
            return json.dumps({
                'traces': {tid: [asdict(span) for span in spans] for tid, spans in self.traces.items()}
            }, indent=2)

    def _export_jaeger_format(self) -> str:
        """Export traces in Jaeger format."""
        # Simplified Jaeger format export
        jaeger_data = {
            'data': [
                {
                    'traceID': trace_id,
                    'spans': [
                        {
                            'traceID': span.trace_id,
                            'spanID': span.span_id,
                            'operationName': span.operation_name,
                            'startTime': int(span.start_time * 1000000),  # microseconds
                            'duration': int(span.duration * 1000000) if span.duration else 0,
                            'tags': [{'key': k, 'value': v} for k, v in span.tags.items()],
                            'logs': span.logs
                        } for span in spans
                    ]
                } for trace_id, spans in self.traces.items()
            ]
        }

        return json.dumps(jaeger_data, indent=2)

class LogAggregator:
    """Advanced log aggregation and analysis."""

    def __init__(self, max_entries: int = 100000):
        self.logger = logging.getLogger(f"{__name__}.LogAggregator")
        self.log_entries: deque = deque(maxlen=max_entries)
        self.log_patterns = defaultdict(int)
        self.error_patterns = defaultdict(list)
        self.aggregation_active = False
        self.aggregation_thread = None

    def add_log_entry(self, entry: LogEntry):
        """Add log entry for aggregation."""
        self.log_entries.append(entry)

        # Analyze patterns
        self._analyze_log_patterns(entry)

    def _analyze_log_patterns(self, entry: LogEntry):
        """Analyze log entry for patterns."""
        # Extract patterns from message
        words = entry.message.lower().split()
        for word in words:
            if len(word) > 3:  # Only meaningful words
                self.log_patterns[word] += 1

        # Track error patterns
        if entry.level in ['ERROR', 'CRITICAL']:
            self.error_patterns[entry.level].append({
                'message': entry.message,
                'timestamp': entry.timestamp,
                'source': entry.source
            })

    def search_logs(self, query: str, time_range: Tuple[float, float] = None,
                   level: str = None, source: str = None) -> List[Dict[str, Any]]:
        """Search logs with filters."""
        results = []

        for entry in self.log_entries:
            # Time range filter
            if time_range and not (time_range[0] <= entry.timestamp <= time_range[1]):
                continue

            # Level filter
            if level and entry.level != level:
                continue

            # Source filter
            if source and entry.source != source:
                continue

            # Query filter
            if query.lower() not in entry.message.lower():
                continue

            results.append(asdict(entry))

        return results

    def get_log_statistics(self) -> Dict[str, Any]:
        """Get log statistics."""
        if not self.log_entries:
            return {}

        levels = [entry.level for entry in self.log_entries]
        sources = [entry.source for entry in self.log_entries]

        # Calculate statistics
        level_counts = defaultdict(int)
        for level in levels:
            level_counts[level] += 1

        source_counts = defaultdict(int)
        for source in sources:
            source_counts[source] += 1

        return {
            'total_entries': len(self.log_entries),
            'level_distribution': dict(level_counts),
            'source_distribution': dict(source_counts),
            'top_patterns': dict(list(self.log_patterns.most_common(10))),
            'error_patterns': dict(list(self.error_patterns.keys())[:5])
        }

class MetricsAggregator:
    """Metrics aggregation and alerting."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.MetricsAggregator")
        self.metric_points: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.alert_rules = []
        self.alerts_triggered = []

    def add_metric_point(self, point: MetricPoint):
        """Add metric data point."""
        self.metric_points[point.metric_name].append(point)

    def define_alert_rule(self, metric_name: str, threshold: float, operator: str,
                         duration: int = 60, severity: str = "warning"):
        """Define alerting rule."""
        rule = {
            'metric_name': metric_name,
            'threshold': threshold,
            'operator': operator,  # 'gt', 'lt', 'eq'
            'duration': duration,  # seconds
            'severity': severity,
            'last_triggered': 0
        }

        self.alert_rules.append(rule)

    def evaluate_alerts(self) -> List[Dict[str, Any]]:
        """Evaluate all alert rules."""
        current_time = time.time()
        new_alerts = []

        for rule in self.alert_rules:
            metric_name = rule['metric_name']
            if metric_name not in self.metric_points:
                continue

            points = list(self.metric_points[metric_name])

            # Check if we have enough data points
            if len(points) < 2:
                continue

            # Get recent points within duration window
            cutoff_time = current_time - rule['duration']
            recent_points = [p for p in points if p.timestamp >= cutoff_time]

            if not recent_points:
                continue

            # Calculate current value (average of recent points)
            current_value = statistics.mean(p.value for p in recent_points)

            # Check threshold
            threshold_breached = False
            if rule['operator'] == 'gt' and current_value > rule['threshold']:
                threshold_breached = True
            elif rule['operator'] == 'lt' and current_value < rule['threshold']:
                threshold_breached = True
            elif rule['operator'] == 'eq' and abs(current_value - rule['threshold']) < 0.01:
                threshold_breached = True

            if threshold_breached and (current_time - rule['last_triggered']) > rule['duration']:
                alert = {
                    'id': f"alert_{int(current_time)}_{metric_name}",
                    'timestamp': current_time,
                    'metric_name': metric_name,
                    'current_value': current_value,
                    'threshold': rule['threshold'],
                    'operator': rule['operator'],
                    'severity': rule['severity'],
                    'message': f"{metric_name} {rule['operator']} {rule['threshold']} (current: {current_value:.2f})"
                }

                new_alerts.append(alert)
                rule['last_triggered'] = current_time

        self.alerts_triggered.extend(new_alerts)
        return new_alerts

class AnomalyDetector:
    """Anomaly detection using statistical methods."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.AnomalyDetector")
        self.baselines: Dict[str, Dict[str, float]] = {}
        self.anomaly_history: List[AnomalyDetectionResult] = []

    def establish_baseline(self, metric_name: str, data_points: List[float], window_size: int = 100):
        """Establish baseline for metric."""
        if len(data_points) < window_size:
            return

        recent_data = data_points[-window_size:]

        baseline = {
            'mean': statistics.mean(recent_data),
            'std': statistics.stdev(recent_data) if len(recent_data) > 1 else 0,
            'min': min(recent_data),
            'max': max(recent_data),
            'median': statistics.median(recent_data),
            'window_size': window_size,
            'last_updated': time.time()
        }

        self.baselines[metric_name] = baseline
        self.logger.info(f"Established baseline for {metric_name}")

    def detect_anomalies(self, metric_name: str, current_value: float,
                        sensitivity: float = 2.0) -> Optional[AnomalyDetectionResult]:
        """Detect anomalies in metric value."""
        if metric_name not in self.baselines:
            return None

        baseline = self.baselines[metric_name]
        mean = baseline['mean']
        std = baseline['std']

        if std == 0:
            return None

        # Calculate z-score
        z_score = abs(current_value - mean) / std

        # Check if anomalous
        if z_score > sensitivity:
            anomaly_score = z_score

            # Determine severity
            if z_score > 4.0:
                severity = "critical"
            elif z_score > 3.0:
                severity = "high"
            elif z_score > 2.0:
                severity = "medium"
            else:
                severity = "low"

            # Generate prediction (simple moving average)
            predicted_value = mean

            anomaly = AnomalyDetectionResult(
                timestamp=time.time(),
                metric_name=metric_name,
                current_value=current_value,
                predicted_value=predicted_value,
                anomaly_score=anomaly_score,
                severity=severity,
                description=f"Anomaly detected: {current_value:.2f} (expected: {predicted_value:.2f})"
            )

            self.anomaly_history.append(anomaly)

            # Keep only recent anomalies
            if len(self.anomaly_history) > 1000:
                self.anomaly_history = self.anomaly_history[-1000:]

            self.logger.warning(f"Anomaly detected: {anomaly.description}")
            return anomaly

        return None

class ObservabilityManager:
    """Main observability management system."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.ObservabilityManager")
        self.tracer = DistributedTracer()
        self.log_aggregator = LogAggregator()
        self.metrics_aggregator = MetricsAggregator()
        self.anomaly_detector = AnomalyDetector()

        self.observability_active = False
        self.observability_thread = None

    def start_observability(self):
        """Start observability collection."""
        if self.observability_active:
            return

        self.observability_active = True
        self.observability_thread = threading.Thread(target=self._observability_loop, daemon=True)
        self.observability_thread.start()
        self.logger.info("Observability system started")

    def stop_observability(self):
        """Stop observability collection."""
        self.observability_active = False
        if self.observability_thread:
            self.observability_thread.join(timeout=5)
        self.logger.info("Observability system stopped")

    def _observability_loop(self):
        """Main observability collection loop."""
        while self.observability_active:
            try:
                # Collect metrics
                self._collect_system_metrics()

                # Evaluate alerts
                alerts = self.metrics_aggregator.evaluate_alerts()
                if alerts:
                    self.logger.warning(f"Alerts triggered: {len(alerts)}")

                # Detect anomalies
                self._detect_metric_anomalies()

                time.sleep(30)  # Collect every 30 seconds

            except Exception as e:
                self.logger.error(f"Observability loop error: {e}")
                time.sleep(60)

    def _collect_system_metrics(self):
        """Collect system metrics."""
        # In a real implementation, collect from various sources
        metrics_to_collect = [
            ('cpu_usage', 45.2),
            ('memory_usage', 67.8),
            ('disk_usage', 23.4),
            ('network_io', 1024.5),
            ('response_time', 150.2)
        ]

        for metric_name, value in metrics_to_collect:
            point = MetricPoint(
                timestamp=time.time(),
                value=value,
                labels={'service': 'blncs'},
                metric_name=metric_name
            )

            self.metrics_aggregator.add_metric_point(point)

    def _detect_metric_anomalies(self):
        """Detect anomalies in collected metrics."""
        for metric_name in ['cpu_usage', 'memory_usage', 'response_time']:
            if metric_name in self.metrics_aggregator.metric_points:
                points = list(self.metrics_aggregator.metric_points[metric_name])
                if len(points) >= 20:  # Need baseline data
                    values = [p.value for p in points[-20:]]  # Last 20 points
                    self.anomaly_detector.establish_baseline(metric_name, values)

                    current_value = points[-1].value
                    anomaly = self.anomaly_detector.detect_anomalies(metric_name, current_value)

                    if anomaly:
                        self.logger.warning(f"Anomaly detected: {anomaly.description}")

    def get_observability_dashboard(self) -> Dict[str, Any]:
        """Get data for observability dashboard."""
        return {
            'distributed_traces': len(self.tracer.traces),
            'log_entries': len(self.log_aggregator.log_entries),
            'metric_points': sum(len(points) for points in self.metrics_aggregator.metric_points.values()),
            'alerts_triggered': len(self.metrics_aggregator.alerts_triggered),
            'anomalies_detected': len(self.anomaly_detector.anomaly_history),
            'log_statistics': self.log_aggregator.get_log_statistics(),
            'recent_traces': [self.tracer.get_trace(tid) for tid in list(self.tracer.traces.keys())[-5:]],
            'active_alerts': self.metrics_aggregator.alerts_triggered[-10:] if self.metrics_aggregator.alerts_triggered else []
        }

def create_observability_manager() -> ObservabilityManager:
    """Factory function to create observability manager."""
    return ObservabilityManager()

# Example usage
if __name__ == "__main__":
    # Create observability manager
    obs_manager = create_observability_manager()

    # Start observability
    obs_manager.start_observability()

    # Create some sample traces
    span1 = obs_manager.tracer.start_span("api_request", service_name="api_gateway")
    obs_manager.tracer.add_span_tag(span1, "http.method", "GET")
    obs_manager.tracer.add_span_tag(span1, "http.url", "/api/status")

    time.sleep(0.1)  # Simulate processing

    span2 = obs_manager.tracer.start_span("database_query", span1, service_name="database")
    obs_manager.tracer.add_span_tag(span2, "db.operation", "SELECT")
    obs_manager.tracer.add_span_tag(span2, "db.table", "users")

    time.sleep(0.05)  # Simulate query

    obs_manager.tracer.end_span(span2)
    obs_manager.tracer.end_span(span1)

    # Add some log entries
    for i in range(10):
        log_entry = LogEntry(
            timestamp=time.time(),
            level=random.choice(['INFO', 'WARNING', 'ERROR']),
            message=f"Sample log message {i}",
            source="demo_service",
            service="blncs",
            trace_id="demo_trace"
        )
        obs_manager.log_aggregator.add_log_entry(log_entry)

    # Define alert rules
    obs_manager.metrics_aggregator.define_alert_rule("cpu_usage", 80, "gt", severity="high")
    obs_manager.metrics_aggregator.define_alert_rule("memory_usage", 90, "gt", severity="critical")

    # Get observability dashboard
    dashboard = obs_manager.get_observability_dashboard()
    print(f"Observability dashboard: {json.dumps(dashboard, indent=2)}")

    print("Advanced observability system setup complete!")
