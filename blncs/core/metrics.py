"""
Lightweight metrics collection system for BLNCS
Tracks performance, usage, and system health metrics.
"""

import time
import threading
from typing import Dict, Any, Optional, List, Callable
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import statistics

from .logger import get_logger
from .fast_cache import get_fast_cache


class MetricType(Enum):
    """Types of metrics"""
    COUNTER = "counter"     # Cumulative count
    GAUGE = "gauge"         # Current value
    HISTOGRAM = "histogram" # Distribution of values
    TIMER = "timer"         # Timing measurements


@dataclass
class MetricPoint:
    """Single metric data point"""
    timestamp: datetime
    value: float
    labels: Dict[str, str] = field(default_factory=dict)


@dataclass
class MetricSummary:
    """Summary statistics for a metric"""
    name: str
    type: MetricType
    count: int
    sum: float
    min: float
    max: float
    mean: float
    median: float
    p95: float
    p99: float
    labels: Dict[str, str] = field(default_factory=dict)


class Metric:
    """Base metric class"""
    
    def __init__(self, name: str, metric_type: MetricType, labels: Optional[Dict[str, str]] = None):
        self.name = name
        self.type = metric_type
        self.labels = labels or {}
        self.points: deque = deque(maxlen=1000)  # Keep last 1000 points
        self._lock = threading.Lock()
    
    def add_point(self, value: float, timestamp: Optional[datetime] = None):
        """Add a data point"""
        with self._lock:
            point = MetricPoint(
                timestamp=timestamp or datetime.now(),
                value=value,
                labels=self.labels.copy()
            )
            self.points.append(point)
    
    def get_summary(self, time_window: Optional[timedelta] = None) -> MetricSummary:
        """Get summary statistics for the metric"""
        with self._lock:
            if not self.points:
                return MetricSummary(
                    name=self.name,
                    type=self.type,
                    count=0, sum=0, min=0, max=0,
                    mean=0, median=0, p95=0, p99=0,
                    labels=self.labels
                )
            
            # Filter by time window if specified
            if time_window:
                cutoff = datetime.now() - time_window
                values = [p.value for p in self.points if p.timestamp >= cutoff]
            else:
                values = [p.value for p in self.points]
            
            if not values:
                return MetricSummary(
                    name=self.name,
                    type=self.type,
                    count=0, sum=0, min=0, max=0,
                    mean=0, median=0, p95=0, p99=0,
                    labels=self.labels
                )
            
            sorted_values = sorted(values)
            count = len(values)
            
            return MetricSummary(
                name=self.name,
                type=self.type,
                count=count,
                sum=sum(values),
                min=sorted_values[0],
                max=sorted_values[-1],
                mean=statistics.mean(values),
                median=statistics.median(values),
                p95=sorted_values[int(count * 0.95)] if count > 1 else sorted_values[0],
                p99=sorted_values[int(count * 0.99)] if count > 1 else sorted_values[0],
                labels=self.labels
            )


class Counter(Metric):
    """Counter metric - only increases"""
    
    def __init__(self, name: str, labels: Optional[Dict[str, str]] = None):
        super().__init__(name, MetricType.COUNTER, labels)
        self.value = 0
    
    def increment(self, amount: float = 1.0):
        """Increment counter"""
        with self._lock:
            self.value += amount
            self.add_point(self.value)
    
    def get_value(self) -> float:
        """Get current counter value"""
        return self.value


class Gauge(Metric):
    """Gauge metric - can go up or down"""
    
    def __init__(self, name: str, labels: Optional[Dict[str, str]] = None):
        super().__init__(name, MetricType.GAUGE, labels)
        self.value = 0
    
    def set(self, value: float):
        """Set gauge value"""
        with self._lock:
            self.value = value
            self.add_point(value)
    
    def increment(self, amount: float = 1.0):
        """Increment gauge"""
        with self._lock:
            self.value += amount
            self.add_point(self.value)
    
    def decrement(self, amount: float = 1.0):
        """Decrement gauge"""
        with self._lock:
            self.value -= amount
            self.add_point(self.value)
    
    def get_value(self) -> float:
        """Get current gauge value"""
        return self.value


class Histogram(Metric):
    """Histogram metric - tracks distribution of values"""
    
    def __init__(self, name: str, buckets: Optional[List[float]] = None, 
                 labels: Optional[Dict[str, str]] = None):
        super().__init__(name, MetricType.HISTOGRAM, labels)
        self.buckets = buckets or [0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0]
        self.bucket_counts = defaultdict(int)
        self.sum_value = 0
        self.count = 0
    
    def observe(self, value: float):
        """Record an observation"""
        with self._lock:
            self.add_point(value)
            self.sum_value += value
            self.count += 1
            
            # Update bucket counts
            for bucket in self.buckets:
                if value <= bucket:
                    self.bucket_counts[bucket] += 1


class Timer(Histogram):
    """Timer metric - specialized histogram for timing measurements"""
    
    def __init__(self, name: str, labels: Optional[Dict[str, str]] = None):
        # Default buckets for timing in seconds
        super().__init__(name, 
                        buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
                        labels=labels)
        self.type = MetricType.TIMER
    
    def __enter__(self):
        """Context manager entry"""
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        elapsed = time.time() - self.start_time
        self.observe(elapsed)
    
    def time_func(self, func: Callable) -> Callable:
        """Decorator to time function execution"""
        def wrapper(*args, **kwargs):
            with self:
                return func(*args, **kwargs)
        return wrapper


class MetricsCollector:
    """Central metrics collection system"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.metrics: Dict[str, Metric] = {}
        self._lock = threading.Lock()
        self.cache = get_fast_cache()
        
        # Initialize default metrics
        self._initialize_default_metrics()
    
    def _initialize_default_metrics(self):
        """Initialize default system metrics"""
        # Request metrics
        self.counter("requests_total", labels={"type": "lightning"})
        self.counter("requests_success", labels={"type": "lightning"})
        self.counter("requests_failed", labels={"type": "lightning"})
        
        # Performance metrics
        self.timer("request_duration_seconds")
        self.histogram("response_size_bytes")
        
        # System metrics
        self.gauge("active_connections")
        self.gauge("cache_hit_ratio")
        self.gauge("memory_usage_mb")
    
    def counter(self, name: str, description: str = "", labels: Optional[Dict[str, str]] = None) -> Counter:
        """Get or create a counter metric"""
        key = self._metric_key(name, labels)
        with self._lock:
            if key not in self.metrics:
                self.metrics[key] = Counter(name, labels)
            return self.metrics[key]
    
    def gauge(self, name: str, description: str = "", labels: Optional[Dict[str, str]] = None) -> Gauge:
        """Get or create a gauge metric"""
        key = self._metric_key(name, labels)
        with self._lock:
            if key not in self.metrics:
                self.metrics[key] = Gauge(name, labels)
            return self.metrics[key]
    
    def histogram(self, name: str, description: str = "", buckets: Optional[List[float]] = None,
                  labels: Optional[Dict[str, str]] = None) -> Histogram:
        """Get or create a histogram metric"""
        key = self._metric_key(name, labels)
        with self._lock:
            if key not in self.metrics:
                self.metrics[key] = Histogram(name, buckets, labels)
            return self.metrics[key]
    
    def timer(self, name: str, labels: Optional[Dict[str, str]] = None) -> Timer:
        """Get or create a timer metric"""
        key = self._metric_key(name, labels)
        with self._lock:
            if key not in self.metrics:
                self.metrics[key] = Timer(name, labels)
            return self.metrics[key]
    
    def _metric_key(self, name: str, labels: Optional[Dict[str, str]] = None) -> str:
        """Generate unique key for metric"""
        if not labels:
            return name
        
        label_str = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"
    
    def get_all_metrics(self) -> Dict[str, Any]:
        """Get all metrics and their current values"""
        with self._lock:
            result = {}
            for key, metric in self.metrics.items():
                if isinstance(metric, (Counter, Gauge)):
                    result[key] = {
                        "type": metric.type.value,
                        "value": metric.get_value(),
                        "labels": metric.labels
                    }
                else:
                    summary = metric.get_summary()
                    result[key] = {
                        "type": metric.type.value,
                        "count": summary.count,
                        "mean": summary.mean,
                        "median": summary.median,
                        "p95": summary.p95,
                        "p99": summary.p99,
                        "labels": metric.labels
                    }
            return result
    
    def export_prometheus(self) -> str:
        """Export metrics in Prometheus format"""
        lines = []
        
        with self._lock:
            for key, metric in self.metrics.items():
                # Add metric type comment
                lines.append(f"# TYPE {metric.name} {metric.type.value}")
                
                if isinstance(metric, Counter):
                    lines.append(f"{key} {metric.get_value()}")
                elif isinstance(metric, Gauge):
                    lines.append(f"{key} {metric.get_value()}")
                elif isinstance(metric, Histogram):
                    summary = metric.get_summary()
                    lines.append(f"{key}_count {summary.count}")
                    lines.append(f"{key}_sum {summary.sum}")
                    # Add bucket lines
                    for bucket in metric.buckets:
                        bucket_key = f"{metric.name}_bucket{{le=\"{bucket}\"}}"
                        lines.append(f"{bucket_key} {metric.bucket_counts.get(bucket, 0)}")
        
        return "\n".join(lines)
    
    def reset_all(self):
        """Reset all metrics"""
        with self._lock:
            self.metrics.clear()
            self._initialize_default_metrics()


# Global metrics collector
_metrics_collector = None


def get_metrics_collector() -> MetricsCollector:
    """Get global metrics collector"""
    global _metrics_collector
    if _metrics_collector is None:
        _metrics_collector = MetricsCollector()
    return _metrics_collector


# Convenience functions
def increment_counter(name: str, amount: float = 1.0, labels: Optional[Dict[str, str]] = None):
    """Increment a counter metric"""
    collector = get_metrics_collector()
    collector.counter(name, labels).increment(amount)


def set_gauge(name: str, value: float, labels: Optional[Dict[str, str]] = None):
    """Set a gauge metric"""
    collector = get_metrics_collector()
    collector.gauge(name, labels).set(value)


def observe_histogram(name: str, value: float, labels: Optional[Dict[str, str]] = None):
    """Record a histogram observation"""
    collector = get_metrics_collector()
    collector.histogram(name, labels=labels).observe(value)


def record_histogram(metric_name: str, value: float, labels: Optional[Dict[str, str]] = None):
    """Record a histogram value (alias for observe_histogram for compatibility)"""
    observe_histogram(metric_name, value, labels)


def timed(name: str = None, labels: Optional[Dict[str, str]] = None):
    """Decorator to time function execution"""
    def decorator(func: Callable) -> Callable:
        metric_name = name or f"{func.__module__}.{func.__name__}_duration"
        
        def wrapper(*args, **kwargs):
            collector = get_metrics_collector()
            with collector.timer(metric_name, labels):
                return func(*args, **kwargs)
        return wrapper
    return decorator