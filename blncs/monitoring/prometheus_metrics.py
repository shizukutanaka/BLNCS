"""
Enterprise Prometheus Metrics Collection System
Comprehensive monitoring for Lightning Network operations and system health.
"""

import asyncio
import time
import logging
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import json
from datetime import datetime, timedelta
from pathlib import Path
import psutil
import threading
from concurrent.futures import ThreadPoolExecutor

try:
    from prometheus_client import (
        Counter, Gauge, Histogram, Summary, Info,
        CollectorRegistry, generate_latest, start_http_server,
        multiprocess, values
    )
    HAS_PROMETHEUS = True
except ImportError:
    HAS_PROMETHEUS = False
    # Mock classes for graceful degradation
    class Counter:
        def __init__(self, *args, **kwargs): pass
        def inc(self, amount=1): pass
        def labels(self, **kwargs): return self
    class Gauge:
        def __init__(self, *args, **kwargs): pass
        def set(self, value): pass
        def inc(self, amount=1): pass
        def dec(self, amount=1): pass
        def labels(self, **kwargs): return self
    class Histogram:
        def __init__(self, *args, **kwargs): pass
        def observe(self, value): pass
        def labels(self, **kwargs): return self
    class Summary:
        def __init__(self, *args, **kwargs): pass
        def observe(self, value): pass
        def labels(self, **kwargs): return self
    class Info:
        def __init__(self, *args, **kwargs): pass
        def info(self, value): pass

logger = logging.getLogger(__name__)

class MetricType(Enum):
    """Metric types supported by the monitoring system."""
    COUNTER = "counter"
    GAUGE = "gauge" 
    HISTOGRAM = "histogram"
    SUMMARY = "summary"
    INFO = "info"

@dataclass
class MetricDefinition:
    """Definition of a metric with metadata."""
    name: str
    metric_type: MetricType
    description: str
    labels: List[str] = field(default_factory=list)
    buckets: Optional[List[float]] = None
    unit: Optional[str] = None
    namespace: str = "blncs"

@dataclass
class MetricValue:
    """Value container for metric updates."""
    name: str
    value: float
    labels: Dict[str, str] = field(default_factory=dict)
    timestamp: Optional[datetime] = None

class LightningNetworkMetrics:
    """Lightning Network specific metrics definitions."""
    
    PAYMENT_TOTAL = MetricDefinition(
        name="lightning_payments_total",
        metric_type=MetricType.COUNTER,
        description="Total number of Lightning payments processed",
        labels=["status", "direction", "node_id"]
    )
    
    PAYMENT_AMOUNT = MetricDefinition(
        name="lightning_payment_amount_satoshis",
        metric_type=MetricType.HISTOGRAM,
        description="Lightning payment amounts in satoshis",
        labels=["direction", "node_id"],
        buckets=[100, 1000, 10000, 100000, 1000000, 10000000]
    )
    
    PAYMENT_DURATION = MetricDefinition(
        name="lightning_payment_duration_seconds",
        metric_type=MetricType.HISTOGRAM,
        description="Lightning payment processing duration",
        labels=["status", "node_id"],
        buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0]
    )
    
    CHANNEL_COUNT = MetricDefinition(
        name="lightning_channels_total",
        metric_type=MetricType.GAUGE,
        description="Current number of Lightning channels",
        labels=["state", "node_id"]
    )
    
    CHANNEL_BALANCE = MetricDefinition(
        name="lightning_channel_balance_satoshis",
        metric_type=MetricType.GAUGE,
        description="Channel balance in satoshis",
        labels=["channel_id", "balance_type", "node_id"]
    )
    
    FEE_REVENUE = MetricDefinition(
        name="lightning_fee_revenue_satoshis_total",
        metric_type=MetricType.COUNTER,
        description="Total fee revenue earned in satoshis",
        labels=["node_id", "fee_type"]
    )
    
    ROUTING_SUCCESS_RATE = MetricDefinition(
        name="lightning_routing_success_rate",
        metric_type=MetricType.GAUGE,
        description="Payment routing success rate (0-1)",
        labels=["node_id", "time_window"]
    )
    
    NODE_CONNECTIVITY = MetricDefinition(
        name="lightning_node_connectivity_score",
        metric_type=MetricType.GAUGE,
        description="Node connectivity score (0-1)",
        labels=["node_id", "measurement_type"]
    )

class SystemMetrics:
    """System performance metrics definitions."""
    
    CPU_USAGE = MetricDefinition(
        name="system_cpu_usage_percent",
        metric_type=MetricType.GAUGE,
        description="Current CPU usage percentage",
        labels=["core"]
    )
    
    MEMORY_USAGE = MetricDefinition(
        name="system_memory_usage_bytes",
        metric_type=MetricType.GAUGE,
        description="Current memory usage in bytes",
        labels=["type"]
    )
    
    DISK_USAGE = MetricDefinition(
        name="system_disk_usage_bytes",
        metric_type=MetricType.GAUGE,
        description="Current disk usage in bytes",
        labels=["device", "mountpoint", "type"]
    )
    
    NETWORK_IO = MetricDefinition(
        name="system_network_io_bytes_total",
        metric_type=MetricType.COUNTER,
        description="Network I/O bytes transferred",
        labels=["interface", "direction"]
    )
    
    DATABASE_CONNECTIONS = MetricDefinition(
        name="database_connections_total",
        metric_type=MetricType.GAUGE,
        description="Current database connection count",
        labels=["state", "database"]
    )
    
    HTTP_REQUESTS = MetricDefinition(
        name="http_requests_total",
        metric_type=MetricType.COUNTER,
        description="Total HTTP requests processed",
        labels=["method", "endpoint", "status"]
    )
    
    HTTP_REQUEST_DURATION = MetricDefinition(
        name="http_request_duration_seconds",
        metric_type=MetricType.HISTOGRAM,
        description="HTTP request processing duration",
        labels=["method", "endpoint"],
        buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    )

class PrometheusMetricsCollector:
    """Enterprise Prometheus metrics collection system."""
    
    def __init__(self, 
                 registry: Optional[CollectorRegistry] = None,
                 namespace: str = "blncs",
                 enable_system_metrics: bool = True,
                 collection_interval: float = 10.0):
        """Initialize the metrics collector."""
        self.namespace = namespace
        self.registry = registry or CollectorRegistry()
        self.enable_system_metrics = enable_system_metrics
        self.collection_interval = collection_interval
        
        # Metric storage
        self.metrics: Dict[str, Any] = {}
        self.metric_definitions: Dict[str, MetricDefinition] = {}
        
        # Threading
        self.collection_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="metrics")
        
        # System monitoring
        self.last_network_io: Dict[str, Dict[str, int]] = {}
        self.startup_time = time.time()
        
        # Initialize metrics
        self._initialize_lightning_metrics()
        self._initialize_system_metrics()
        
        logger.info(f"Prometheus metrics collector initialized with namespace '{namespace}'")
    
    def _initialize_lightning_metrics(self) -> None:
        """Initialize Lightning Network metrics."""
        ln_metrics = [
            LightningNetworkMetrics.PAYMENT_TOTAL,
            LightningNetworkMetrics.PAYMENT_AMOUNT,
            LightningNetworkMetrics.PAYMENT_DURATION,
            LightningNetworkMetrics.CHANNEL_COUNT,
            LightningNetworkMetrics.CHANNEL_BALANCE,
            LightningNetworkMetrics.FEE_REVENUE,
            LightningNetworkMetrics.ROUTING_SUCCESS_RATE,
            LightningNetworkMetrics.NODE_CONNECTIVITY
        ]
        
        for metric_def in ln_metrics:
            self.register_metric(metric_def)
    
    def _initialize_system_metrics(self) -> None:
        """Initialize system performance metrics."""
        if not self.enable_system_metrics:
            return
            
        system_metrics = [
            SystemMetrics.CPU_USAGE,
            SystemMetrics.MEMORY_USAGE,
            SystemMetrics.DISK_USAGE,
            SystemMetrics.NETWORK_IO,
            SystemMetrics.DATABASE_CONNECTIONS,
            SystemMetrics.HTTP_REQUESTS,
            SystemMetrics.HTTP_REQUEST_DURATION
        ]
        
        for metric_def in system_metrics:
            self.register_metric(metric_def)
    
    def register_metric(self, metric_def: MetricDefinition) -> None:
        """Register a new metric definition."""
        full_name = f"{metric_def.namespace}_{metric_def.name}"
        
        if full_name in self.metrics:
            logger.warning(f"Metric {full_name} already registered, skipping")
            return
        
        try:
            if metric_def.metric_type == MetricType.COUNTER:
                metric = Counter(
                    full_name,
                    metric_def.description,
                    metric_def.labels,
                    registry=self.registry
                )
            elif metric_def.metric_type == MetricType.GAUGE:
                metric = Gauge(
                    full_name,
                    metric_def.description,
                    metric_def.labels,
                    registry=self.registry
                )
            elif metric_def.metric_type == MetricType.HISTOGRAM:
                metric = Histogram(
                    full_name,
                    metric_def.description,
                    metric_def.labels,
                    buckets=metric_def.buckets,
                    registry=self.registry
                )
            elif metric_def.metric_type == MetricType.SUMMARY:
                metric = Summary(
                    full_name,
                    metric_def.description,
                    metric_def.labels,
                    registry=self.registry
                )
            elif metric_def.metric_type == MetricType.INFO:
                metric = Info(
                    full_name,
                    metric_def.description,
                    registry=self.registry
                )
            else:
                logger.error(f"Unsupported metric type: {metric_def.metric_type}")
                return
            
            self.metrics[full_name] = metric
            self.metric_definitions[full_name] = metric_def
            
            logger.debug(f"Registered metric: {full_name}")
            
        except Exception as e:
            logger.error(f"Failed to register metric {full_name}: {e}")
    
    def update_metric(self, metric_value: MetricValue) -> None:
        """Update a metric value."""
        full_name = f"{self.namespace}_{metric_value.name}"
        
        if full_name not in self.metrics:
            logger.warning(f"Metric {full_name} not found, ignoring update")
            return
        
        try:
            metric = self.metrics[full_name]
            metric_def = self.metric_definitions[full_name]
            
            # Apply labels if any
            if metric_value.labels and metric_def.labels:
                metric = metric.labels(**metric_value.labels)
            
            # Update based on metric type
            if metric_def.metric_type == MetricType.COUNTER:
                metric.inc(metric_value.value)
            elif metric_def.metric_type == MetricType.GAUGE:
                metric.set(metric_value.value)
            elif metric_def.metric_type in [MetricType.HISTOGRAM, MetricType.SUMMARY]:
                metric.observe(metric_value.value)
            
        except Exception as e:
            logger.error(f"Failed to update metric {full_name}: {e}")
    
    def record_payment(self, 
                      amount_sats: int,
                      direction: str,
                      status: str,
                      duration_seconds: float,
                      node_id: str) -> None:
        """Record Lightning payment metrics."""
        # Payment count
        self.update_metric(MetricValue(
            name="lightning_payments_total",
            value=1,
            labels={"status": status, "direction": direction, "node_id": node_id}
        ))
        
        # Payment amount
        self.update_metric(MetricValue(
            name="lightning_payment_amount_satoshis",
            value=amount_sats,
            labels={"direction": direction, "node_id": node_id}
        ))
        
        # Payment duration
        self.update_metric(MetricValue(
            name="lightning_payment_duration_seconds",
            value=duration_seconds,
            labels={"status": status, "node_id": node_id}
        ))
    
    def record_fee_revenue(self, amount_sats: int, fee_type: str, node_id: str) -> None:
        """Record fee revenue."""
        self.update_metric(MetricValue(
            name="lightning_fee_revenue_satoshis_total",
            value=amount_sats,
            labels={"node_id": node_id, "fee_type": fee_type}
        ))
    
    def update_channel_metrics(self, 
                              channel_id: str,
                              local_balance: int,
                              remote_balance: int,
                              state: str,
                              node_id: str) -> None:
        """Update channel metrics."""
        # Channel count by state
        self.update_metric(MetricValue(
            name="lightning_channels_total",
            value=1,
            labels={"state": state, "node_id": node_id}
        ))
        
        # Channel balances
        self.update_metric(MetricValue(
            name="lightning_channel_balance_satoshis",
            value=local_balance,
            labels={"channel_id": channel_id, "balance_type": "local", "node_id": node_id}
        ))
        
        self.update_metric(MetricValue(
            name="lightning_channel_balance_satoshis",
            value=remote_balance,
            labels={"channel_id": channel_id, "balance_type": "remote", "node_id": node_id}
        ))
    
    def record_http_request(self, 
                           method: str,
                           endpoint: str,
                           status_code: int,
                           duration_seconds: float) -> None:
        """Record HTTP request metrics."""
        # Request count
        self.update_metric(MetricValue(
            name="http_requests_total",
            value=1,
            labels={"method": method, "endpoint": endpoint, "status": str(status_code)}
        ))
        
        # Request duration
        self.update_metric(MetricValue(
            name="http_request_duration_seconds",
            value=duration_seconds,
            labels={"method": method, "endpoint": endpoint}
        ))
    
    def _collect_system_metrics(self) -> None:
        """Collect system performance metrics."""
        if not self.enable_system_metrics:
            return
        
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=None, percpu=True)
            for i, cpu_usage in enumerate(cpu_percent):
                self.update_metric(MetricValue(
                    name="system_cpu_usage_percent",
                    value=cpu_usage,
                    labels={"core": str(i)}
                ))
            
            # Memory usage
            memory = psutil.virtual_memory()
            self.update_metric(MetricValue(
                name="system_memory_usage_bytes",
                value=memory.used,
                labels={"type": "used"}
            ))
            self.update_metric(MetricValue(
                name="system_memory_usage_bytes",
                value=memory.available,
                labels={"type": "available"}
            ))
            self.update_metric(MetricValue(
                name="system_memory_usage_bytes",
                value=memory.total,
                labels={"type": "total"}
            ))
            
            # Disk usage
            for partition in psutil.disk_partitions():
                try:
                    disk_usage = psutil.disk_usage(partition.mountpoint)
                    device = partition.device.replace('/', '_').replace('\\', '_')
                    mountpoint = partition.mountpoint.replace('/', '_').replace('\\', '_')
                    
                    self.update_metric(MetricValue(
                        name="system_disk_usage_bytes",
                        value=disk_usage.used,
                        labels={"device": device, "mountpoint": mountpoint, "type": "used"}
                    ))
                    self.update_metric(MetricValue(
                        name="system_disk_usage_bytes",
                        value=disk_usage.free,
                        labels={"device": device, "mountpoint": mountpoint, "type": "free"}
                    ))
                except (PermissionError, OSError):
                    continue
            
            # Network I/O
            net_io = psutil.net_io_counters(pernic=True)
            for interface, stats in net_io.items():
                # Calculate delta for counter metrics
                if interface in self.last_network_io:
                    last_stats = self.last_network_io[interface]
                    
                    bytes_sent_delta = max(0, stats.bytes_sent - last_stats["bytes_sent"])
                    bytes_recv_delta = max(0, stats.bytes_recv - last_stats["bytes_recv"])
                    
                    if bytes_sent_delta > 0:
                        self.update_metric(MetricValue(
                            name="system_network_io_bytes_total",
                            value=bytes_sent_delta,
                            labels={"interface": interface, "direction": "sent"}
                        ))
                    
                    if bytes_recv_delta > 0:
                        self.update_metric(MetricValue(
                            name="system_network_io_bytes_total",
                            value=bytes_recv_delta,
                            labels={"interface": interface, "direction": "received"}
                        ))
                
                # Store current values for next iteration
                self.last_network_io[interface] = {
                    "bytes_sent": stats.bytes_sent,
                    "bytes_recv": stats.bytes_recv
                }
                
        except Exception as e:
            logger.error(f"Failed to collect system metrics: {e}")
    
    def start_collection(self) -> None:
        """Start the metrics collection thread."""
        if self.collection_thread and self.collection_thread.is_alive():
            logger.warning("Metrics collection already running")
            return
        
        self.stop_event.clear()
        self.collection_thread = threading.Thread(
            target=self._collection_loop,
            name="metrics-collector",
            daemon=True
        )
        self.collection_thread.start()
        
        logger.info(f"Started metrics collection (interval: {self.collection_interval}s)")
    
    def stop_collection(self) -> None:
        """Stop the metrics collection thread."""
        if not self.collection_thread or not self.collection_thread.is_alive():
            return
        
        self.stop_event.set()
        self.collection_thread.join(timeout=5.0)
        
        if self.collection_thread.is_alive():
            logger.warning("Metrics collection thread did not stop gracefully")
        else:
            logger.info("Stopped metrics collection")
    
    def _collection_loop(self) -> None:
        """Main collection loop running in separate thread."""
        while not self.stop_event.is_set():
            try:
                self._collect_system_metrics()
                
                # Wait for next collection interval
                if self.stop_event.wait(self.collection_interval):
                    break
                    
            except Exception as e:
                logger.error(f"Error in metrics collection loop: {e}")
                # Wait before retrying
                if self.stop_event.wait(min(self.collection_interval, 30.0)):
                    break
    
    def get_metrics_text(self) -> str:
        """Get metrics in Prometheus text format."""
        try:
            if HAS_PROMETHEUS:
                return generate_latest(self.registry).decode('utf-8')
            else:
                return "# Prometheus not available\n"
        except Exception as e:
            logger.error(f"Failed to generate metrics text: {e}")
            return f"# Error generating metrics: {e}\n"
    
    def start_http_server(self, port: int = 8000, addr: str = "0.0.0.0") -> None:
        """Start HTTP server for metrics endpoint."""
        try:
            if HAS_PROMETHEUS:
                start_http_server(port, addr, registry=self.registry)
                logger.info(f"Prometheus metrics server started on {addr}:{port}")
            else:
                logger.warning("Prometheus not available, cannot start HTTP server")
        except Exception as e:
            logger.error(f"Failed to start metrics HTTP server: {e}")
            raise
    
    async def shutdown(self) -> None:
        """Shutdown the metrics collector."""
        logger.info("Shutting down metrics collector...")
        
        self.stop_collection()
        self.executor.shutdown(wait=True, timeout=10.0)
        
        logger.info("Metrics collector shutdown complete")

# Singleton instance
_metrics_collector: Optional[PrometheusMetricsCollector] = None

def get_metrics_collector() -> PrometheusMetricsCollector:
    """Get the global metrics collector instance."""
    global _metrics_collector
    
    if _metrics_collector is None:
        _metrics_collector = PrometheusMetricsCollector()
    
    return _metrics_collector

def initialize_metrics(namespace: str = "blncs",
                      enable_system_metrics: bool = True,
                      collection_interval: float = 10.0,
                      start_collection: bool = True) -> PrometheusMetricsCollector:
    """Initialize the global metrics collector."""
    global _metrics_collector
    
    _metrics_collector = PrometheusMetricsCollector(
        namespace=namespace,
        enable_system_metrics=enable_system_metrics,
        collection_interval=collection_interval
    )
    
    if start_collection:
        _metrics_collector.start_collection()
    
    logger.info(f"Initialized global metrics collector with namespace '{namespace}'")
    return _metrics_collector

# Context manager for timing operations
class MetricsTimer:
    """Context manager for timing operations and recording metrics."""
    
    def __init__(self, metric_name: str, labels: Optional[Dict[str, str]] = None):
        self.metric_name = metric_name
        self.labels = labels or {}
        self.start_time: Optional[float] = None
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.start_time is not None:
            duration = time.time() - self.start_time
            
            collector = get_metrics_collector()
            collector.update_metric(MetricValue(
                name=self.metric_name,
                value=duration,
                labels=self.labels
            ))

# Decorator for automatic function timing
def timed_operation(metric_name: str, labels: Optional[Dict[str, str]] = None):
    """Decorator to automatically time function execution."""
    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            with MetricsTimer(metric_name, labels):
                return func(*args, **kwargs)
        return wrapper
    return decorator

async def async_timed_operation(metric_name: str, labels: Optional[Dict[str, str]] = None):
    """Decorator to automatically time async function execution."""
    def decorator(func: Callable) -> Callable:
        async def wrapper(*args, **kwargs):
            with MetricsTimer(metric_name, labels):
                return await func(*args, **kwargs)
        return wrapper
    return decorator