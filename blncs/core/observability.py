#!/usr/bin/env python3
"""
Structured Logging and Observability
Implements OpenTelemetry-compatible observability patterns
Three pillars: Logs, Metrics, Traces
"""

import logging
import json
import time
import uuid
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from contextlib import contextmanager
import contextvars

logger = logging.getLogger(__name__)


# Context variables for request/span tracking
request_id: contextvars.ContextVar[str] = contextvars.ContextVar('request_id', default='')
span_id: contextvars.ContextVar[str] = contextvars.ContextVar('span_id', default='')
trace_id: contextvars.ContextVar[str] = contextvars.ContextVar('trace_id', default='')


@dataclass
class LogContext:
    """Structured log context with all relevant fields"""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    level: str = "INFO"
    message: str = ""
    logger_name: str = ""
    request_id: str = ""
    trace_id: str = ""
    span_id: str = ""
    service_name: str = "blncs"
    environment: str = "production"
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    exception: Optional[str] = None
    error_code: Optional[str] = None
    context_data: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            **asdict(self),
            'timestamp': self.timestamp.isoformat()
        }

    def to_json(self) -> str:
        """Convert to JSON"""
        return json.dumps(self.to_dict(), default=str)


class LogLevel(Enum):
    """Log levels"""
    TRACE = "TRACE"
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class StructuredLogger:
    """
    Structured logging following OpenTelemetry patterns
    Emits logs with context, correlation IDs, and structured fields
    """

    def __init__(self, name: str, service_name: str = "blncs", environment: str = "production"):
        self.logger = logging.getLogger(name)
        self.service_name = service_name
        self.environment = environment
        self.logger_name = name

    def _create_context(
        self,
        message: str,
        level: str,
        **kwargs
    ) -> LogContext:
        """Create log context"""
        return LogContext(
            level=level,
            message=message,
            logger_name=self.logger_name,
            request_id=request_id.get(),
            trace_id=trace_id.get(),
            span_id=span_id.get(),
            service_name=self.service_name,
            environment=self.environment,
            context_data=kwargs
        )

    def info(self, message: str, **kwargs) -> None:
        """Log info"""
        ctx = self._create_context(message, "INFO", **kwargs)
        self.logger.info(ctx.to_json())

    def debug(self, message: str, **kwargs) -> None:
        """Log debug"""
        ctx = self._create_context(message, "DEBUG", **kwargs)
        self.logger.debug(ctx.to_json())

    def warning(self, message: str, **kwargs) -> None:
        """Log warning"""
        ctx = self._create_context(message, "WARNING", **kwargs)
        self.logger.warning(ctx.to_json())

    def error(self, message: str, exception: Optional[Exception] = None, **kwargs) -> None:
        """Log error"""
        ctx = self._create_context(message, "ERROR", **kwargs)
        ctx.exception = str(exception) if exception else None
        self.logger.error(ctx.to_json())

    def critical(self, message: str, exception: Optional[Exception] = None, **kwargs) -> None:
        """Log critical"""
        ctx = self._create_context(message, "CRITICAL", **kwargs)
        ctx.exception = str(exception) if exception else None
        self.logger.critical(ctx.to_json())


@dataclass
class Metric:
    """
    Metric data point
    Represents a single measurement
    """
    name: str
    value: float
    unit: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    tags: Dict[str, str] = field(default_factory=dict)
    service_name: str = "blncs"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            **asdict(self),
            'timestamp': self.timestamp.isoformat()
        }


class MetricsCollector:
    """
    Collects and aggregates metrics
    Supports counters, gauges, histograms
    """

    def __init__(self, service_name: str = "blncs"):
        self.service_name = service_name
        self.counters: Dict[str, int] = {}
        self.gauges: Dict[str, float] = {}
        self.histograms: Dict[str, List[float]] = {}
        self.metrics_history: List[Metric] = []
        self.max_history = 1000

    def increment_counter(self, name: str, tags: Optional[Dict[str, str]] = None) -> None:
        """Increment counter"""
        key = self._make_key(name, tags)
        self.counters[key] = self.counters.get(key, 0) + 1
        self._record_metric(Metric(name, float(self.counters[key]), tags=tags or {}))

    def set_gauge(self, name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None:
        """Set gauge value"""
        key = self._make_key(name, tags)
        self.gauges[key] = value
        self._record_metric(Metric(name, value, tags=tags or {}))

    def record_histogram(self, name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None:
        """Record histogram value"""
        key = self._make_key(name, tags)
        if key not in self.histograms:
            self.histograms[key] = []
        self.histograms[key].append(value)
        self._record_metric(Metric(name, value, tags=tags or {}))

    def _make_key(self, name: str, tags: Optional[Dict[str, str]]) -> str:
        """Create unique key for metric"""
        if not tags:
            return name
        tag_str = ",".join(f"{k}={v}" for k, v in sorted(tags.items()))
        return f"{name}:{tag_str}"

    def _record_metric(self, metric: Metric) -> None:
        """Record metric to history"""
        self.metrics_history.append(metric)
        if len(self.metrics_history) > self.max_history:
            self.metrics_history = self.metrics_history[-self.max_history:]

    def get_counter(self, name: str, tags: Optional[Dict[str, str]] = None) -> int:
        """Get counter value"""
        key = self._make_key(name, tags)
        return self.counters.get(key, 0)

    def get_gauge(self, name: str, tags: Optional[Dict[str, str]] = None) -> float:
        """Get gauge value"""
        key = self._make_key(name, tags)
        return self.gauges.get(key, 0.0)

    def get_histogram_stats(self, name: str, tags: Optional[Dict[str, str]] = None) -> Dict[str, float]:
        """Get histogram statistics"""
        key = self._make_key(name, tags)
        values = self.histograms.get(key, [])

        if not values:
            return {'count': 0, 'min': 0, 'max': 0, 'avg': 0, 'p99': 0}

        sorted_values = sorted(values)
        count = len(values)

        return {
            'count': count,
            'min': sorted_values[0],
            'max': sorted_values[-1],
            'avg': sum(values) / count,
            'p50': sorted_values[count // 2],
            'p99': sorted_values[int(count * 0.99)]
        }

    def export_metrics(self) -> List[Dict[str, Any]]:
        """Export all metrics"""
        return [m.to_dict() for m in self.metrics_history]


@dataclass
class Span:
    """
    Distributed trace span
    Represents a unit of work within a trace
    """
    trace_id: str
    span_id: str
    parent_span_id: Optional[str] = None
    operation_name: str = ""
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    duration_ms: float = 0.0
    status: str = "UNSET"  # UNSET, OK, ERROR
    tags: Dict[str, Any] = field(default_factory=dict)
    events: List[Dict[str, Any]] = field(default_factory=list)


class TracingManager:
    """
    Manages distributed tracing
    Creates and tracks spans across service boundaries
    """

    def __init__(self):
        self.spans: Dict[str, Span] = {}
        self.spans_history: List[Span] = []
        self.max_history = 1000

    def start_span(
        self,
        operation_name: str,
        parent_span_id: Optional[str] = None,
        tags: Optional[Dict[str, Any]] = None
    ) -> Span:
        """Start a new span"""
        span_trace_id = trace_id.get() or str(uuid.uuid4())
        span_id_val = str(uuid.uuid4())

        span = Span(
            trace_id=span_trace_id,
            span_id=span_id_val,
            parent_span_id=parent_span_id,
            operation_name=operation_name,
            tags=tags or {}
        )

        self.spans[span_id_val] = span
        trace_id.set(span_trace_id)
        span_id.set(span_id_val)

        logger.debug(f"Started span: {operation_name} ({span_id_val})")
        return span

    def end_span(self, span_id_val: str, status: str = "OK") -> None:
        """End a span"""
        if span_id_val not in self.spans:
            return

        span = self.spans[span_id_val]
        span.end_time = datetime.utcnow()
        span.duration_ms = (span.end_time - span.start_time).total_seconds() * 1000
        span.status = status

        self.spans_history.append(span)
        del self.spans[span_id_val]

        if len(self.spans_history) > self.max_history:
            self.spans_history = self.spans_history[-self.max_history:]

        logger.debug(f"Ended span: {span.operation_name} ({span_id_val}) - {span.duration_ms}ms")

    def add_event(self, span_id_val: str, event_name: str, data: Optional[Dict] = None) -> None:
        """Add event to span"""
        if span_id_val not in self.spans:
            return

        span = self.spans[span_id_val]
        span.events.append({
            'name': event_name,
            'timestamp': datetime.utcnow().isoformat(),
            'data': data or {}
        })

    def get_trace(self, trace_id_val: str) -> List[Span]:
        """Get all spans for a trace"""
        return [s for s in self.spans_history if s.trace_id == trace_id_val]


@contextmanager
def log_operation(
    logger_instance: StructuredLogger,
    operation_name: str,
    **context_data
):
    """
    Context manager for logging an operation
    Automatically logs start, end, and duration
    """
    start_time = time.time()

    try:
        logger_instance.info(
            f"Starting operation: {operation_name}",
            **context_data
        )
        yield

    except Exception as e:
        logger_instance.error(
            f"Operation failed: {operation_name}",
            exception=e,
            **context_data
        )
        raise

    finally:
        duration_ms = (time.time() - start_time) * 1000
        logger_instance.info(
            f"Completed operation: {operation_name}",
            duration_ms=duration_ms,
            **context_data
        )


@contextmanager
def trace_operation(
    tracing_manager: TracingManager,
    operation_name: str,
    tags: Optional[Dict[str, Any]] = None
):
    """
    Context manager for tracing an operation
    Automatically creates and closes span
    """
    span = tracing_manager.start_span(operation_name, tags=tags)

    try:
        yield span
        tracing_manager.end_span(span.span_id, status="OK")

    except Exception as e:
        tracing_manager.end_span(span.span_id, status="ERROR")
        span.tags['error'] = str(e)
        raise


__all__ = [
    'LogContext',
    'LogLevel',
    'StructuredLogger',
    'Metric',
    'MetricsCollector',
    'Span',
    'TracingManager',
    'log_operation',
    'trace_operation',
    'request_id',
    'trace_id',
    'span_id',
]
