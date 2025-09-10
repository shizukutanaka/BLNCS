"""
OpenTelemetry Integration for BLNCS
Distributed tracing, metrics, and observability with OpenTelemetry standard.
"""

import asyncio
import time
from typing import Dict, Any, Optional, List, Union, Callable
from dataclasses import dataclass
from contextlib import contextmanager, asynccontextmanager
import json
from datetime import datetime

try:
    # OpenTelemetry imports
    from opentelemetry import trace, metrics
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, SimpleSpanProcessor
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.exporter.jaeger.thrift import JaegerExporter
    from opentelemetry.exporter.prometheus import PrometheusMetricReader
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
    from opentelemetry.instrumentation.requests import RequestsInstrumentor
    from opentelemetry.instrumentation.sqlite3 import SQLite3Instrumentor
    from opentelemetry.instrumentation.asyncio import AsyncioInstrumentor
    from opentelemetry.sdk.resources import Resource, SERVICE_NAME, SERVICE_VERSION
    from opentelemetry.semconv.trace import SpanAttributes
    from opentelemetry.trace.status import Status, StatusCode
    
    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False
    
    # Fallback stubs
    class trace:
        @staticmethod
        def get_tracer(name: str): return None
    
    class metrics:
        @staticmethod
        def get_meter(name: str): return None

from .logger import get_logger
from .structured_logging import get_structured_logger, LogCategory


@dataclass
class TelemetryConfig:
    """Configuration for telemetry system"""
    service_name: str = "blncs"
    service_version: str = "2.0.0"
    environment: str = "production"
    
    # Tracing configuration
    enable_tracing: bool = True
    jaeger_endpoint: Optional[str] = None
    otlp_endpoint: Optional[str] = None
    trace_sample_rate: float = 1.0
    
    # Metrics configuration
    enable_metrics: bool = True
    prometheus_port: int = 9090
    metrics_export_interval: int = 30
    
    # Instrumentation
    auto_instrument_requests: bool = True
    auto_instrument_database: bool = True
    auto_instrument_asyncio: bool = True
    
    # Performance
    batch_span_processor: bool = True
    max_export_batch_size: int = 512
    export_timeout_millis: int = 30000


class TelemetryManager:
    """Manager for OpenTelemetry instrumentation"""
    
    def __init__(self, config: Optional[TelemetryConfig] = None):
        self.config = config or TelemetryConfig()
        self.logger = get_structured_logger(__name__, category=LogCategory.SYSTEM)
        
        self.tracer_provider = None
        self.meter_provider = None
        self.tracer = None
        self.meter = None
        
        self.initialized = False
        self.instrumentors: List[Any] = []
    
    def initialize(self):
        """Initialize OpenTelemetry instrumentation"""
        if not OTEL_AVAILABLE:
            self.logger.warning(
                "OpenTelemetry not available - install with: pip install opentelemetry-distro[otlp]",
                category=LogCategory.SYSTEM
            )
            return False
        
        try:
            # Create resource
            resource = Resource.create({
                SERVICE_NAME: self.config.service_name,
                SERVICE_VERSION: self.config.service_version,
                "environment": self.config.environment,
                "component": "lightning_network_manager"
            })
            
            # Initialize tracing
            if self.config.enable_tracing:
                self._initialize_tracing(resource)
            
            # Initialize metrics
            if self.config.enable_metrics:
                self._initialize_metrics(resource)
            
            # Auto-instrumentation
            self._setup_auto_instrumentation()
            
            self.initialized = True
            self.logger.info(
                "OpenTelemetry initialized successfully",
                category=LogCategory.SYSTEM,
                data={
                    "service_name": self.config.service_name,
                    "tracing_enabled": self.config.enable_tracing,
                    "metrics_enabled": self.config.enable_metrics
                }
            )
            
            return True
            
        except Exception as e:
            self.logger.error(
                "Failed to initialize OpenTelemetry",
                category=LogCategory.SYSTEM,
                exception=e
            )
            return False
    
    def _initialize_tracing(self, resource: Resource):
        """Initialize distributed tracing"""
        # Create tracer provider
        self.tracer_provider = TracerProvider(resource=resource)
        
        # Setup exporters
        exporters = []
        
        if self.config.jaeger_endpoint:
            jaeger_exporter = JaegerExporter(
                agent_host_name="localhost",
                agent_port=14268,
                collector_endpoint=self.config.jaeger_endpoint
            )
            exporters.append(jaeger_exporter)
        
        if self.config.otlp_endpoint:
            otlp_exporter = OTLPSpanExporter(
                endpoint=self.config.otlp_endpoint,
                headers={}
            )
            exporters.append(otlp_exporter)
        
        # Add span processors
        for exporter in exporters:
            if self.config.batch_span_processor:
                processor = BatchSpanProcessor(
                    exporter,
                    max_export_batch_size=self.config.max_export_batch_size,
                    export_timeout_millis=self.config.export_timeout_millis
                )
            else:
                processor = SimpleSpanProcessor(exporter)
            
            self.tracer_provider.add_span_processor(processor)
        
        # Set global tracer provider
        trace.set_tracer_provider(self.tracer_provider)
        self.tracer = trace.get_tracer(__name__)
    
    def _initialize_metrics(self, resource: Resource):
        """Initialize metrics collection"""
        readers = []
        
        # Prometheus metrics reader
        if self.config.prometheus_port:
            try:
                prometheus_reader = PrometheusMetricReader(
                    port=self.config.prometheus_port
                )
                readers.append(prometheus_reader)
            except Exception as e:
                self.logger.warning(
                    f"Failed to setup Prometheus metrics: {e}",
                    category=LogCategory.SYSTEM
                )
        
        # OTLP metrics exporter
        if self.config.otlp_endpoint:
            otlp_metric_exporter = OTLPMetricExporter(
                endpoint=f"{self.config.otlp_endpoint}/v1/metrics"
            )
            otlp_reader = PeriodicExportingMetricReader(
                exporter=otlp_metric_exporter,
                export_interval_millis=self.config.metrics_export_interval * 1000
            )
            readers.append(otlp_reader)
        
        # Create meter provider
        self.meter_provider = MeterProvider(
            resource=resource,
            metric_readers=readers
        )
        
        # Set global meter provider
        metrics.set_meter_provider(self.meter_provider)
        self.meter = metrics.get_meter(__name__)
    
    def _setup_auto_instrumentation(self):
        """Setup automatic instrumentation"""
        
        if self.config.auto_instrument_requests:
            try:
                requests_instrumentor = RequestsInstrumentor()
                requests_instrumentor.instrument()
                self.instrumentors.append(requests_instrumentor)
            except Exception as e:
                self.logger.warning(f"Failed to instrument requests: {e}")
        
        if self.config.auto_instrument_database:
            try:
                sqlite_instrumentor = SQLite3Instrumentor()
                sqlite_instrumentor.instrument()
                self.instrumentors.append(sqlite_instrumentor)
            except Exception as e:
                self.logger.warning(f"Failed to instrument SQLite: {e}")
        
        if self.config.auto_instrument_asyncio:
            try:
                asyncio_instrumentor = AsyncioInstrumentor()
                asyncio_instrumentor.instrument()
                self.instrumentors.append(asyncio_instrumentor)
            except Exception as e:
                self.logger.warning(f"Failed to instrument asyncio: {e}")
    
    def get_tracer(self, name: str = None):
        """Get tracer instance"""
        if not self.initialized or not self.tracer:
            return None
        
        if name:
            return trace.get_tracer(name)
        return self.tracer
    
    def get_meter(self, name: str = None):
        """Get meter instance"""
        if not self.initialized or not self.meter:
            return None
        
        if name:
            return metrics.get_meter(name)
        return self.meter
    
    def shutdown(self):
        """Shutdown telemetry system"""
        try:
            # Uninstrument auto-instrumentation
            for instrumentor in self.instrumentors:
                try:
                    instrumentor.uninstrument()
                except Exception as e:
                    self.logger.warning(f"Failed to uninstrument: {e}")
            
            # Shutdown tracer provider
            if self.tracer_provider:
                self.tracer_provider.shutdown()
            
            # Shutdown meter provider
            if self.meter_provider:
                self.meter_provider.shutdown()
            
            self.logger.info("Telemetry system shutdown completed")
            
        except Exception as e:
            self.logger.error("Error during telemetry shutdown", exception=e)


class TracingMixin:
    """Mixin for adding distributed tracing to classes"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._tracer = None
        self._telemetry_manager = None
    
    @property
    def tracer(self):
        """Get tracer instance"""
        if not self._tracer:
            self._tracer = get_telemetry_manager().get_tracer(
                self.__class__.__module__
            )
        return self._tracer
    
    @contextmanager
    def trace_operation(
        self,
        operation_name: str,
        attributes: Optional[Dict[str, Any]] = None,
        record_exception: bool = True
    ):
        """Context manager for tracing operations"""
        if not self.tracer:
            yield None
            return
        
        with self.tracer.start_as_current_span(operation_name) as span:
            try:
                # Set attributes
                if attributes:
                    for key, value in attributes.items():
                        span.set_attribute(key, value)
                
                # Set component attribute
                span.set_attribute("component", self.__class__.__name__)
                
                yield span
                
                # Mark as successful
                span.set_status(Status(StatusCode.OK))
                
            except Exception as e:
                # Record exception
                if record_exception:
                    span.record_exception(e)
                    span.set_status(
                        Status(StatusCode.ERROR, str(e))
                    )
                raise
    
    @asynccontextmanager
    async def async_trace_operation(
        self,
        operation_name: str,
        attributes: Optional[Dict[str, Any]] = None,
        record_exception: bool = True
    ):
        """Async context manager for tracing operations"""
        if not self.tracer:
            yield None
            return
        
        with self.tracer.start_as_current_span(operation_name) as span:
            try:
                # Set attributes
                if attributes:
                    for key, value in attributes.items():
                        span.set_attribute(key, value)
                
                # Set component attribute
                span.set_attribute("component", self.__class__.__name__)
                
                yield span
                
                # Mark as successful
                span.set_status(Status(StatusCode.OK))
                
            except Exception as e:
                # Record exception
                if record_exception:
                    span.record_exception(e)
                    span.set_status(
                        Status(StatusCode.ERROR, str(e))
                    )
                raise


# Decorators for tracing

def trace_function(
    operation_name: Optional[str] = None,
    attributes: Optional[Dict[str, Any]] = None,
    record_args: bool = False,
    record_result: bool = False
):
    """Decorator for tracing functions"""
    def decorator(func):
        nonlocal operation_name
        if operation_name is None:
            operation_name = f"{func.__module__}.{func.__name__}"
        
        def sync_wrapper(*args, **kwargs):
            tracer = get_telemetry_manager().get_tracer()
            if not tracer:
                return func(*args, **kwargs)
            
            with tracer.start_as_current_span(operation_name) as span:
                try:
                    # Set attributes
                    if attributes:
                        for key, value in attributes.items():
                            span.set_attribute(key, value)
                    
                    # Record arguments
                    if record_args:
                        span.set_attribute("function.args.count", len(args))
                        span.set_attribute("function.kwargs.count", len(kwargs))
                    
                    # Execute function
                    result = func(*args, **kwargs)
                    
                    # Record result
                    if record_result and result is not None:
                        span.set_attribute("function.result.type", type(result).__name__)
                    
                    span.set_status(Status(StatusCode.OK))
                    return result
                    
                except Exception as e:
                    span.record_exception(e)
                    span.set_status(Status(StatusCode.ERROR, str(e)))
                    raise
        
        async def async_wrapper(*args, **kwargs):
            tracer = get_telemetry_manager().get_tracer()
            if not tracer:
                return await func(*args, **kwargs)
            
            with tracer.start_as_current_span(operation_name) as span:
                try:
                    # Set attributes
                    if attributes:
                        for key, value in attributes.items():
                            span.set_attribute(key, value)
                    
                    # Record arguments
                    if record_args:
                        span.set_attribute("function.args.count", len(args))
                        span.set_attribute("function.kwargs.count", len(kwargs))
                    
                    # Execute function
                    result = await func(*args, **kwargs)
                    
                    # Record result
                    if record_result and result is not None:
                        span.set_attribute("function.result.type", type(result).__name__)
                    
                    span.set_status(Status(StatusCode.OK))
                    return result
                    
                except Exception as e:
                    span.record_exception(e)
                    span.set_status(Status(StatusCode.ERROR, str(e)))
                    raise
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


def trace_lightning_operation(operation_type: str):
    """Decorator for tracing Lightning Network operations"""
    def decorator(func):
        operation_name = f"lightning.{operation_type}"
        
        def wrapper(*args, **kwargs):
            tracer = get_telemetry_manager().get_tracer()
            if not tracer:
                return func(*args, **kwargs)
            
            with tracer.start_as_current_span(operation_name) as span:
                try:
                    # Set Lightning-specific attributes
                    span.set_attribute("lightning.operation", operation_type)
                    span.set_attribute("lightning.protocol", "bolt")
                    
                    # Extract relevant parameters
                    if 'amount' in kwargs:
                        span.set_attribute("lightning.amount_sats", kwargs['amount'])
                    
                    if 'channel_id' in kwargs:
                        span.set_attribute("lightning.channel_id", kwargs['channel_id'])
                    
                    if 'node_pubkey' in kwargs:
                        pubkey = kwargs['node_pubkey']
                        if isinstance(pubkey, str) and len(pubkey) > 10:
                            span.set_attribute("lightning.peer_pubkey", pubkey[:10] + "...")
                    
                    result = func(*args, **kwargs)
                    
                    # Record success
                    span.set_attribute("lightning.success", True)
                    span.set_status(Status(StatusCode.OK))
                    
                    return result
                    
                except Exception as e:
                    span.set_attribute("lightning.success", False)
                    span.set_attribute("lightning.error", str(e))
                    span.record_exception(e)
                    span.set_status(Status(StatusCode.ERROR, str(e)))
                    raise
        
        return wrapper
    
    return decorator


# Global telemetry manager
_global_telemetry_manager: Optional[TelemetryManager] = None


def get_telemetry_manager() -> TelemetryManager:
    """Get global telemetry manager"""
    global _global_telemetry_manager
    if _global_telemetry_manager is None:
        _global_telemetry_manager = TelemetryManager()
    return _global_telemetry_manager


def initialize_telemetry(config: Optional[TelemetryConfig] = None) -> bool:
    """Initialize global telemetry"""
    manager = get_telemetry_manager()
    if config:
        manager.config = config
    return manager.initialize()


def shutdown_telemetry():
    """Shutdown global telemetry"""
    manager = get_telemetry_manager()
    manager.shutdown()


# Convenience functions

def get_tracer(name: str = None):
    """Get tracer instance"""
    manager = get_telemetry_manager()
    return manager.get_tracer(name)


def get_meter(name: str = None):
    """Get meter instance"""
    manager = get_telemetry_manager()
    return manager.get_meter(name)


@contextmanager
def trace_span(name: str, attributes: Optional[Dict[str, Any]] = None):
    """Simple span context manager"""
    tracer = get_tracer()
    if not tracer:
        yield None
        return
    
    with tracer.start_as_current_span(name) as span:
        try:
            if attributes:
                for key, value in attributes.items():
                    span.set_attribute(key, value)
            
            yield span
            span.set_status(Status(StatusCode.OK))
            
        except Exception as e:
            span.record_exception(e)
            span.set_status(Status(StatusCode.ERROR, str(e)))
            raise


__all__ = [
    'TelemetryConfig',
    'TelemetryManager',
    'TracingMixin',
    'trace_function',
    'trace_lightning_operation',
    'get_telemetry_manager',
    'initialize_telemetry',
    'shutdown_telemetry',
    'get_tracer',
    'get_meter',
    'trace_span'
]