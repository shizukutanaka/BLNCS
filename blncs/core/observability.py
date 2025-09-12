"""
Comprehensive Observability System for BLNCS
Provides metrics, tracing, and monitoring capabilities.
"""

import time
import threading
import uuid
from typing import Dict, Any, Optional, List, Callable, Union
from dataclasses import dataclass, field
from contextlib import contextmanager
from collections import defaultdict, deque
from enum import Enum
import json

from .logger import get_logger
from .cache_unified import get_cache_manager, CacheType


class MetricType(Enum):
    """Types of metrics"""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


@dataclass
class Metric:
    """Metric data structure"""
    name: str
    type: MetricType
    value: Union[int, float]
    labels: Dict[str, str] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    description: str = ""


@dataclass
class Span:
    """Distributed tracing span"""
    span_id: str
    trace_id: str
    parent_span_id: Optional[str]
    operation_name: str
    start_time: float
    end_time: Optional[float] = None
    duration: Optional[float] = None
    tags: Dict[str, Any] = field(default_factory=dict)
    logs: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "started"


class ObservabilityCollector:
    """Collects and manages observability data"""
    
    def __init__(self, buffer_size: int = 10000):
        self.logger = get_logger(__name__)
        self.cache_manager = get_cache_manager()
        self.buffer_size = buffer_size
        
        # Metrics storage
        self._metrics: Dict[str, Metric] = {}
        self._metrics_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._metrics_lock = threading.RLock()
        
        # Distributed tracing
        self._spans: Dict[str, Span] = {}
        self._traces: Dict[str, List[str]] = defaultdict(list)  # trace_id -> span_ids
        self._spans_lock = threading.RLock()
        
        # Performance monitoring
        self._performance_data: deque = deque(maxlen=buffer_size)
        self._perf_lock = threading.RLock()
        
        # Business metrics
        self._business_metrics: Dict[str, Any] = {}
        self._business_lock = threading.RLock()
        
        # Alert thresholds
        self._alert_thresholds: Dict[str, Dict[str, Any]] = {}
        self._alert_callbacks: List[Callable] = []
    
    def record_metric(self, name: str, value: Union[int, float], 
                     metric_type: MetricType = MetricType.GAUGE,
                     labels: Dict[str, str] = None, description: str = "") -> None:
        """Record a metric"""
        labels = labels or {}
        
        with self._metrics_lock:
            metric = Metric(
                name=name,
                type=metric_type,
                value=value,
                labels=labels,
                description=description
            )
            
            # Update current value
            self._metrics[name] = metric
            
            # Add to history
            self._metrics_history[name].append({
                'value': value,
                'timestamp': metric.timestamp,
                'labels': labels
            })
        
        # Check alert thresholds
        self._check_alert_thresholds(name, value)
        
        self.logger.debug(f"Recorded metric: {name} = {value} ({metric_type.value})")
    
    def increment_counter(self, name: str, value: int = 1, 
                         labels: Dict[str, str] = None) -> None:
        """Increment a counter metric"""
        labels = labels or {}
        
        with self._metrics_lock:
            current_metric = self._metrics.get(name)
            if current_metric and current_metric.type == MetricType.COUNTER:
                new_value = current_metric.value + value
            else:
                new_value = value
            
            self.record_metric(name, new_value, MetricType.COUNTER, labels)
    
    def set_gauge(self, name: str, value: Union[int, float], 
                  labels: Dict[str, str] = None) -> None:
        """Set a gauge metric"""
        self.record_metric(name, value, MetricType.GAUGE, labels)
    
    def record_timer(self, name: str, duration: float, 
                    labels: Dict[str, str] = None) -> None:
        """Record a timer metric"""
        self.record_metric(name, duration, MetricType.TIMER, labels)
    
    @contextmanager
    def timer(self, name: str, labels: Dict[str, str] = None):
        """Context manager for timing operations"""
        start_time = time.time()
        try:
            yield
        finally:
            duration = time.time() - start_time
            self.record_timer(name, duration, labels)
    
    def start_span(self, operation_name: str, trace_id: str = None, 
                   parent_span_id: str = None, tags: Dict[str, Any] = None) -> str:
        """Start a new tracing span"""
        span_id = str(uuid.uuid4())
        trace_id = trace_id or str(uuid.uuid4())
        tags = tags or {}
        
        span = Span(
            span_id=span_id,
            trace_id=trace_id,
            parent_span_id=parent_span_id,
            operation_name=operation_name,
            start_time=time.time(),
            tags=tags
        )
        
        with self._spans_lock:
            self._spans[span_id] = span
            self._traces[trace_id].append(span_id)
        
        self.logger.debug(f"Started span: {operation_name} (span_id: {span_id[:8]}, trace_id: {trace_id[:8]})")
        return span_id
    
    def finish_span(self, span_id: str, status: str = "completed", 
                   tags: Dict[str, Any] = None) -> None:
        """Finish a tracing span"""
        with self._spans_lock:
            span = self._spans.get(span_id)
            if not span:
                self.logger.warning(f"Span not found: {span_id}")
                return
            
            span.end_time = time.time()
            span.duration = span.end_time - span.start_time
            span.status = status
            
            if tags:
                span.tags.update(tags)
        
        self.logger.debug(f"Finished span: {span.operation_name} ({span.duration:.3f}s)")
    
    def add_span_log(self, span_id: str, message: str, level: str = "info", 
                    fields: Dict[str, Any] = None) -> None:
        """Add log to a span"""
        with self._spans_lock:
            span = self._spans.get(span_id)
            if span:
                log_entry = {
                    'timestamp': time.time(),
                    'message': message,
                    'level': level,
                    'fields': fields or {}
                }
                span.logs.append(log_entry)
    
    @contextmanager
    def trace(self, operation_name: str, trace_id: str = None, 
             parent_span_id: str = None, tags: Dict[str, Any] = None):
        """Context manager for tracing operations"""
        span_id = self.start_span(operation_name, trace_id, parent_span_id, tags)
        try:
            yield span_id
            self.finish_span(span_id, "completed")
        except Exception as e:
            self.finish_span(span_id, "error", {"error": str(e)})
            raise
    
    def record_performance_data(self, component: str, operation: str, 
                              duration: float, success: bool = True,
                              metadata: Dict[str, Any] = None) -> None:
        """Record performance data"""
        metadata = metadata or {}
        
        perf_data = {
            'timestamp': time.time(),
            'component': component,
            'operation': operation,
            'duration': duration,
            'success': success,
            'metadata': metadata
        }
        
        with self._perf_lock:
            self._performance_data.append(perf_data)
        
        # Also record as metrics
        self.record_timer(f"{component}.{operation}.duration", duration)
        self.increment_counter(f"{component}.{operation}.total")
        if success:
            self.increment_counter(f"{component}.{operation}.success")
        else:
            self.increment_counter(f"{component}.{operation}.error")
    
    def record_business_metric(self, name: str, value: Any, 
                             category: str = "general") -> None:
        """Record business-specific metrics"""
        with self._business_lock:
            if category not in self._business_metrics:
                self._business_metrics[category] = {}
            
            self._business_metrics[category][name] = {
                'value': value,
                'timestamp': time.time()
            }
        
        self.logger.debug(f"Recorded business metric: {category}.{name} = {value}")
    
    def set_alert_threshold(self, metric_name: str, threshold_type: str, 
                          threshold_value: Union[int, float],
                          callback: Optional[Callable] = None) -> None:
        """Set alert threshold for a metric"""
        self._alert_thresholds[metric_name] = {
            'type': threshold_type,  # 'greater_than', 'less_than', 'equals'
            'value': threshold_value,
            'callback': callback
        }
        
        self.logger.info(f"Set alert threshold: {metric_name} {threshold_type} {threshold_value}")
    
    def add_alert_callback(self, callback: Callable) -> None:
        """Add global alert callback"""
        self._alert_callbacks.append(callback)
    
    def _check_alert_thresholds(self, metric_name: str, value: Union[int, float]) -> None:
        """Check if metric value crosses alert threshold"""
        threshold = self._alert_thresholds.get(metric_name)
        if not threshold:
            return
        
        threshold_type = threshold['type']
        threshold_value = threshold['value']
        triggered = False
        
        if threshold_type == 'greater_than' and value > threshold_value:
            triggered = True
        elif threshold_type == 'less_than' and value < threshold_value:
            triggered = True
        elif threshold_type == 'equals' and value == threshold_value:
            triggered = True
        
        if triggered:
            alert_data = {
                'metric_name': metric_name,
                'current_value': value,
                'threshold_type': threshold_type,
                'threshold_value': threshold_value,
                'timestamp': time.time()
            }
            
            # Call specific callback
            if threshold.get('callback'):
                try:
                    threshold['callback'](alert_data)
                except Exception as e:
                    self.logger.error(f"Error in alert callback: {e}")
            
            # Call global callbacks
            for callback in self._alert_callbacks:
                try:
                    callback(alert_data)
                except Exception as e:
                    self.logger.error(f"Error in global alert callback: {e}")
            
            self.logger.warning(f"Alert triggered: {metric_name} = {value} ({threshold_type} {threshold_value})")
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of all metrics"""
        with self._metrics_lock:
            return {
                'total_metrics': len(self._metrics),
                'counters': {name: metric.value for name, metric in self._metrics.items() 
                           if metric.type == MetricType.COUNTER},
                'gauges': {name: metric.value for name, metric in self._metrics.items() 
                          if metric.type == MetricType.GAUGE},
                'timers': {name: metric.value for name, metric in self._metrics.items() 
                          if metric.type == MetricType.TIMER}
            }
    
    def get_trace_summary(self, trace_id: str) -> Dict[str, Any]:
        """Get summary of a trace"""
        with self._spans_lock:
            span_ids = self._traces.get(trace_id, [])
            if not span_ids:
                return {}
            
            spans = [self._spans.get(span_id) for span_id in span_ids]
            spans = [s for s in spans if s]  # Remove None values
            
            total_duration = sum(s.duration or 0 for s in spans if s.duration)
            
            return {
                'trace_id': trace_id,
                'total_spans': len(spans),
                'total_duration': total_duration,
                'spans': [
                    {
                        'span_id': s.span_id,
                        'operation_name': s.operation_name,
                        'duration': s.duration,
                        'status': s.status,
                        'tags': s.tags
                    }
                    for s in spans
                ]
            }
    
    def get_performance_summary(self, component: Optional[str] = None,
                              time_window: int = 3600) -> Dict[str, Any]:
        """Get performance summary for a component"""
        current_time = time.time()
        cutoff_time = current_time - time_window
        
        with self._perf_lock:
            relevant_data = [
                data for data in self._performance_data
                if data['timestamp'] >= cutoff_time and
                (component is None or data['component'] == component)
            ]
        
        if not relevant_data:
            return {}
        
        # Calculate statistics
        durations = [data['duration'] for data in relevant_data]
        success_count = sum(1 for data in relevant_data if data['success'])
        
        return {
            'component': component or 'all',
            'time_window_hours': time_window / 3600,
            'total_operations': len(relevant_data),
            'success_rate': f"{(success_count / len(relevant_data) * 100):.1f}%",
            'avg_duration': f"{sum(durations) / len(durations):.3f}s",
            'min_duration': f"{min(durations):.3f}s",
            'max_duration': f"{max(durations):.3f}s",
            'operations_per_hour': len(relevant_data) / (time_window / 3600)
        }
    
    def export_metrics_prometheus(self) -> str:
        """Export metrics in Prometheus format"""
        lines = []
        
        with self._metrics_lock:
            for name, metric in self._metrics.items():
                # Add description
                if metric.description:
                    lines.append(f"# HELP {name} {metric.description}")
                
                lines.append(f"# TYPE {name} {metric.type.value}")
                
                # Add labels
                if metric.labels:
                    label_str = ','.join([f'{k}="{v}"' for k, v in metric.labels.items()])
                    lines.append(f"{name}{{{label_str}}} {metric.value}")
                else:
                    lines.append(f"{name} {metric.value}")
        
        return '\n'.join(lines)
    
    def clear_old_data(self, max_age_hours: int = 24) -> None:
        """Clear old observability data"""
        cutoff_time = time.time() - (max_age_hours * 3600)
        
        # Clear old spans
        with self._spans_lock:
            old_spans = [
                span_id for span_id, span in self._spans.items()
                if span.start_time < cutoff_time
            ]
            
            for span_id in old_spans:
                span = self._spans.pop(span_id, None)
                if span:
                    # Remove from traces
                    trace_spans = self._traces.get(span.trace_id, [])
                    if span_id in trace_spans:
                        trace_spans.remove(span_id)
                    
                    # Remove empty traces
                    if not trace_spans:
                        self._traces.pop(span.trace_id, None)
        
        # Clear old performance data
        with self._perf_lock:
            self._performance_data = deque(
                (data for data in self._performance_data if data['timestamp'] >= cutoff_time),
                maxlen=self.buffer_size
            )
        
        self.logger.info(f"Cleared observability data older than {max_age_hours} hours")


# Global observability collector
_observability_collector: Optional[ObservabilityCollector] = None
_collector_lock = threading.Lock()


def get_observability_collector() -> ObservabilityCollector:
    """Get global observability collector"""
    global _observability_collector
    if _observability_collector is None:
        with _collector_lock:
            if _observability_collector is None:
                _observability_collector = ObservabilityCollector()
    return _observability_collector


# Convenience functions
def record_metric(name: str, value: Union[int, float], 
                 metric_type: MetricType = MetricType.GAUGE,
                 labels: Dict[str, str] = None, description: str = "") -> None:
    """Record a metric"""
    collector = get_observability_collector()
    collector.record_metric(name, value, metric_type, labels, description)


def increment_counter(name: str, value: int = 1, labels: Dict[str, str] = None) -> None:
    """Increment a counter"""
    collector = get_observability_collector()
    collector.increment_counter(name, value, labels)


def set_gauge(name: str, value: Union[int, float], labels: Dict[str, str] = None) -> None:
    """Set a gauge value"""
    collector = get_observability_collector()
    collector.set_gauge(name, value, labels)


def timer(name: str, labels: Dict[str, str] = None):
    """Timer context manager"""
    collector = get_observability_collector()
    return collector.timer(name, labels)


def trace(operation_name: str, trace_id: str = None, 
         parent_span_id: str = None, tags: Dict[str, Any] = None):
    """Tracing context manager"""
    collector = get_observability_collector()
    return collector.trace(operation_name, trace_id, parent_span_id, tags)


def record_performance(component: str, operation: str, duration: float, 
                      success: bool = True, metadata: Dict[str, Any] = None) -> None:
    """Record performance data"""
    collector = get_observability_collector()
    collector.record_performance_data(component, operation, duration, success, metadata)