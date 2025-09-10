"""
Distributed Tracing and Observability Manager
OpenTelemetry integration with Jaeger, distributed logging, and performance monitoring.
"""

import asyncio
import json
import logging
import time
import uuid
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Callable
from enum import Enum
from dataclasses import dataclass, field, asdict
from contextlib import asynccontextmanager
import contextvars
from pathlib import Path

# OpenTelemetry imports
from opentelemetry import trace, metrics, baggage
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.exporter.prometheus import PrometheusMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.resources import Resource
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.instrumentation.asyncio import AsyncIOInstrumentor
from opentelemetry.instrumentation.logging import LoggingInstrumentor
from opentelemetry.propagate import set_global_textmap
from opentelemetry.propagators.b3 import B3MultiFormat
import structlog

logger = structlog.get_logger(__name__)

class TracingBackend(Enum):
    JAEGER = "jaeger"
    ZIPKIN = "zipkin"
    CONSOLE = "console"
    OTLP = "otlp"

class LogLevel(Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

@dataclass
class ObservabilityConfig:
    service_name: str = "blncs"
    service_version: str = "1.0.0"
    environment: str = "production"
    tracing_backend: TracingBackend = TracingBackend.JAEGER
    jaeger_endpoint: str = "http://localhost:14268/api/traces"
    zipkin_endpoint: str = "http://localhost:9411/api/v2/spans"
    otlp_endpoint: str = "http://localhost:4317"
    sampling_ratio: float = 1.0
    enable_metrics: bool = True
    enable_logging: bool = True
    log_level: LogLevel = LogLevel.INFO
    custom_attributes: Dict[str, str] = field(default_factory=dict)
    performance_monitoring: bool = True
    distributed_logging: bool = True

@dataclass
class TraceContext:
    trace_id: str
    span_id: str
    parent_span_id: Optional[str] = None
    baggage: Dict[str, str] = field(default_factory=dict)
    attributes: Dict[str, Any] = field(default_factory=dict)
    start_time: datetime = field(default_factory=datetime.utcnow)
    operation_name: str = ""
    service_name: str = ""

@dataclass
class SpanBuilder:
    operation_name: str
    parent_context: Optional[TraceContext] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    kind: str = "internal"
    start_time: Optional[datetime] = None
    
    def with_attribute(self, key: str, value: Any) -> 'SpanBuilder':
        self.attributes[key] = value
        return self
    
    def with_kind(self, kind: str) -> 'SpanBuilder':
        self.kind = kind
        return self
    
    def with_parent(self, parent: TraceContext) -> 'SpanBuilder':
        self.parent_context = parent
        return self

class TraceProcessor:
    def __init__(self):
        self.processors = []
        self.filters = []
    
    def add_processor(self, processor: Callable[[TraceContext], TraceContext]):
        self.processors.append(processor)
    
    def add_filter(self, filter_func: Callable[[TraceContext], bool]):
        self.filters.append(filter_func)
    
    def process_trace(self, context: TraceContext) -> Optional[TraceContext]:
        # Apply filters
        for filter_func in self.filters:
            if not filter_func(context):
                return None
        
        # Apply processors
        for processor in self.processors:
            context = processor(context)
        
        return context

class DistributedTracer:
    def __init__(self, tracer_provider: TracerProvider, service_name: str):
        self.tracer = trace.get_tracer(service_name)
        self.service_name = service_name
        self.current_context = contextvars.ContextVar('trace_context')
    
    def start_span(self, operation_name: str, parent_context: Optional[TraceContext] = None,
                   attributes: Optional[Dict[str, Any]] = None) -> TraceContext:
        """Start a new span"""
        span = self.tracer.start_span(
            operation_name,
            attributes=attributes or {}
        )
        
        trace_context = TraceContext(
            trace_id=format(span.get_span_context().trace_id, '032x'),
            span_id=format(span.get_span_context().span_id, '016x'),
            parent_span_id=parent_context.span_id if parent_context else None,
            operation_name=operation_name,
            service_name=self.service_name,
            attributes=attributes or {}
        )
        
        self.current_context.set(trace_context)
        return trace_context
    
    def finish_span(self, context: TraceContext, status: str = "ok", 
                   error: Optional[Exception] = None):
        """Finish a span"""
        span = trace.get_current_span()
        
        if error:
            span.set_status(trace.Status(trace.StatusCode.ERROR, str(error)))
            span.record_exception(error)
        else:
            span.set_status(trace.Status(trace.StatusCode.OK))
        
        span.end()
    
    @asynccontextmanager
    async def trace_async(self, operation_name: str, 
                         attributes: Optional[Dict[str, Any]] = None):
        """Async context manager for tracing"""
        context = self.start_span(operation_name, attributes=attributes)
        try:
            yield context
        except Exception as e:
            self.finish_span(context, status="error", error=e)
            raise
        else:
            self.finish_span(context)

class MetricsCollector:
    def __init__(self, meter_provider: MeterProvider):
        self.meter = metrics.get_meter("blncs.metrics")
        self.counters = {}
        self.gauges = {}
        self.histograms = {}
        self.custom_metrics = {}
    
    def create_counter(self, name: str, description: str = "", unit: str = "1"):
        """Create a counter metric"""
        counter = self.meter.create_counter(
            name=name,
            description=description,
            unit=unit
        )
        self.counters[name] = counter
        return counter
    
    def create_gauge(self, name: str, description: str = "", unit: str = "1"):
        """Create a gauge metric"""
        gauge = self.meter.create_up_down_counter(
            name=name,
            description=description,
            unit=unit
        )
        self.gauges[name] = gauge
        return gauge
    
    def create_histogram(self, name: str, description: str = "", unit: str = "ms"):
        """Create a histogram metric"""
        histogram = self.meter.create_histogram(
            name=name,
            description=description,
            unit=unit
        )
        self.histograms[name] = histogram
        return histogram
    
    def increment_counter(self, name: str, value: int = 1, 
                         attributes: Optional[Dict[str, str]] = None):
        """Increment counter"""
        if name in self.counters:
            self.counters[name].add(value, attributes or {})
    
    def set_gauge(self, name: str, value: float, 
                  attributes: Optional[Dict[str, str]] = None):
        """Set gauge value"""
        if name in self.gauges:
            self.gauges[name].add(value, attributes or {})
    
    def record_histogram(self, name: str, value: float,
                        attributes: Optional[Dict[str, str]] = None):
        """Record histogram value"""
        if name in self.histograms:
            self.histograms[name].record(value, attributes or {})

class LogAggregator:
    def __init__(self, config: ObservabilityConfig):
        self.config = config
        self.log_buffer = []
        self.buffer_lock = threading.Lock()
        self.structured_logger = self._setup_structured_logging()
    
    def _setup_structured_logging(self):
        """Setup structured logging with OpenTelemetry integration"""
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.UnicodeDecoder(),
                self._add_trace_context,
                structlog.processors.JSONRenderer()
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
        
        return structlog.get_logger()
    
    def _add_trace_context(self, logger, method_name, event_dict):
        """Add trace context to log entries"""
        span = trace.get_current_span()
        if span.is_recording():
            span_context = span.get_span_context()
            event_dict["trace_id"] = format(span_context.trace_id, '032x')
            event_dict["span_id"] = format(span_context.span_id, '016x')
        
        return event_dict
    
    def log(self, level: LogLevel, message: str, 
           extra: Optional[Dict[str, Any]] = None):
        """Log with trace correlation"""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": level.value,
            "message": message,
            "service": self.config.service_name,
            "version": self.config.service_version,
            "environment": self.config.environment
        }
        
        if extra:
            log_entry.update(extra)
        
        # Add to buffer for batch processing
        with self.buffer_lock:
            self.log_buffer.append(log_entry)
        
        # Log using structured logger
        getattr(self.structured_logger, level.value)(message, **extra or {})
    
    async def flush_logs(self):
        """Flush log buffer"""
        with self.buffer_lock:
            if self.log_buffer:
                # Process logs (send to external system, etc.)
                logs_to_process = self.log_buffer.copy()
                self.log_buffer.clear()
                
                # Here you would send logs to your log aggregation system
                await self._send_logs_to_aggregator(logs_to_process)
    
    async def _send_logs_to_aggregator(self, logs: List[Dict[str, Any]]):
        """Send logs to external aggregation system"""
        # Implementation would depend on your log aggregation system
        # (e.g., Elasticsearch, Fluentd, etc.)
        pass

class PerformanceMonitor:
    def __init__(self, metrics_collector: MetricsCollector):
        self.metrics = metrics_collector
        self.performance_data = {}
        self.thresholds = {
            "response_time_p95": 1000,  # ms
            "response_time_p99": 2000,  # ms
            "error_rate": 0.01,  # 1%
            "throughput_min": 100  # requests/sec
        }
        
        # Create performance metrics
        self._setup_performance_metrics()
    
    def _setup_performance_metrics(self):
        """Setup performance monitoring metrics"""
        self.metrics.create_histogram(
            "http_request_duration",
            "HTTP request duration in milliseconds",
            "ms"
        )
        
        self.metrics.create_counter(
            "http_requests_total",
            "Total HTTP requests",
            "1"
        )
        
        self.metrics.create_counter(
            "http_request_errors_total",
            "Total HTTP request errors",
            "1"
        )
        
        self.metrics.create_gauge(
            "system_cpu_usage",
            "System CPU usage percentage",
            "%"
        )
        
        self.metrics.create_gauge(
            "system_memory_usage",
            "System memory usage percentage", 
            "%"
        )
    
    async def record_request_duration(self, duration_ms: float, 
                                    method: str, endpoint: str, status_code: int):
        """Record HTTP request duration"""
        attributes = {
            "method": method,
            "endpoint": endpoint,
            "status_code": str(status_code)
        }
        
        self.metrics.record_histogram("http_request_duration", duration_ms, attributes)
        self.metrics.increment_counter("http_requests_total", 1, attributes)
        
        if status_code >= 400:
            self.metrics.increment_counter("http_request_errors_total", 1, attributes)
    
    async def record_system_metrics(self, cpu_usage: float, memory_usage: float):
        """Record system resource metrics"""
        self.metrics.set_gauge("system_cpu_usage", cpu_usage)
        self.metrics.set_gauge("system_memory_usage", memory_usage)
    
    def check_performance_thresholds(self) -> Dict[str, bool]:
        """Check if performance metrics exceed thresholds"""
        violations = {}
        
        for metric, threshold in self.thresholds.items():
            # Implementation would check actual metric values against thresholds
            violations[metric] = False  # Placeholder
        
        return violations

class TracingManager:
    def __init__(self, config: ObservabilityConfig):
        self.config = config
        self.tracer_provider = None
        self.meter_provider = None
        self.distributed_tracer = None
        self.metrics_collector = None
        self.log_aggregator = None
        self.performance_monitor = None
        self.trace_processor = TraceProcessor()
        self.initialized = False
    
    async def initialize(self):
        """Initialize observability components"""
        try:
            # Setup resource
            resource = Resource.create({
                "service.name": self.config.service_name,
                "service.version": self.config.service_version,
                "deployment.environment": self.config.environment,
                **self.config.custom_attributes
            })
            
            # Setup tracing
            await self._setup_tracing(resource)
            
            # Setup metrics
            if self.config.enable_metrics:
                await self._setup_metrics(resource)
            
            # Setup logging
            if self.config.enable_logging:
                await self._setup_logging()
            
            # Setup performance monitoring
            if self.config.performance_monitoring:
                await self._setup_performance_monitoring()
            
            # Initialize instrumentations
            await self._setup_instrumentations()
            
            self.initialized = True
            logger.info("Observability initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize observability: {e}")
            raise
    
    async def _setup_tracing(self, resource: Resource):
        """Setup distributed tracing"""
        self.tracer_provider = TracerProvider(
            resource=resource,
            sampler=trace.TraceIdRatioBasedSampler(self.config.sampling_ratio)
        )
        
        # Configure exporter based on backend
        if self.config.tracing_backend == TracingBackend.JAEGER:
            exporter = JaegerExporter(
                agent_host_name="localhost",
                agent_port=6831,
                collector_endpoint=self.config.jaeger_endpoint,
            )
        elif self.config.tracing_backend == TracingBackend.CONSOLE:
            exporter = ConsoleSpanExporter()
        else:
            # Default to console for unsupported backends
            exporter = ConsoleSpanExporter()
        
        # Add span processor
        span_processor = BatchSpanProcessor(exporter)
        self.tracer_provider.add_span_processor(span_processor)
        
        # Set global tracer provider
        trace.set_tracer_provider(self.tracer_provider)
        
        # Setup distributed tracer
        self.distributed_tracer = DistributedTracer(
            self.tracer_provider, 
            self.config.service_name
        )
        
        # Setup propagation
        set_global_textmap(B3MultiFormat())
    
    async def _setup_metrics(self, resource: Resource):
        """Setup metrics collection"""
        # Setup Prometheus reader
        prometheus_reader = PrometheusMetricReader()
        
        self.meter_provider = MeterProvider(
            resource=resource,
            metric_readers=[prometheus_reader]
        )
        
        metrics.set_meter_provider(self.meter_provider)
        
        # Setup metrics collector
        self.metrics_collector = MetricsCollector(self.meter_provider)
    
    async def _setup_logging(self):
        """Setup structured logging"""
        self.log_aggregator = LogAggregator(self.config)
        
        # Configure logging instrumentation
        LoggingInstrumentor().instrument(set_logging_format=True)
    
    async def _setup_performance_monitoring(self):
        """Setup performance monitoring"""
        if self.metrics_collector:
            self.performance_monitor = PerformanceMonitor(self.metrics_collector)
    
    async def _setup_instrumentations(self):
        """Setup automatic instrumentations"""
        # HTTP requests instrumentation
        RequestsInstrumentor().instrument()
        
        # AsyncIO instrumentation  
        AsyncIOInstrumentor().instrument()
    
    def create_span_builder(self, operation_name: str) -> SpanBuilder:
        """Create a span builder"""
        return SpanBuilder(operation_name)
    
    def get_tracer(self) -> DistributedTracer:
        """Get distributed tracer"""
        return self.distributed_tracer
    
    def get_metrics_collector(self) -> MetricsCollector:
        """Get metrics collector"""
        return self.metrics_collector
    
    def get_log_aggregator(self) -> LogAggregator:
        """Get log aggregator"""
        return self.log_aggregator
    
    def get_performance_monitor(self) -> PerformanceMonitor:
        """Get performance monitor"""
        return self.performance_monitor
    
    async def shutdown(self):
        """Shutdown observability components"""
        try:
            if self.tracer_provider:
                self.tracer_provider.shutdown()
            
            if self.meter_provider:
                self.meter_provider.shutdown()
            
            if self.log_aggregator:
                await self.log_aggregator.flush_logs()
            
            logger.info("Observability shutdown completed")
            
        except Exception as e:
            logger.error(f"Error during observability shutdown: {e}")

# Global tracing manager instance
_tracing_manager_instance = None

async def get_tracing_manager(config: Optional[ObservabilityConfig] = None) -> TracingManager:
    """Get or create tracing manager"""
    global _tracing_manager_instance
    
    if _tracing_manager_instance is None:
        if config is None:
            config = ObservabilityConfig()
        
        _tracing_manager_instance = TracingManager(config)
        await _tracing_manager_instance.initialize()
    
    return _tracing_manager_instance

async def initialize_observability(config: ObservabilityConfig) -> TracingManager:
    """Initialize observability with custom config"""
    manager = TracingManager(config)
    await manager.initialize()
    return manager