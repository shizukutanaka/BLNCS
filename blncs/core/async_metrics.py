"""
Asynchronous metrics collection system for BLNCS
High-performance async metrics tracking with batching and persistence.
"""

import asyncio
import time
from typing import Dict, Any, Optional, List, Callable, Union, AsyncIterator
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import statistics
import json
from contextlib import asynccontextmanager

from .logger import get_logger
from .error_handler import get_error_handler, ErrorContext
from .async_database import get_async_db_manager


class MetricType(Enum):
    """Types of metrics"""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"
    SUMMARY = "summary"


@dataclass
class MetricPoint:
    """Single metric data point"""
    timestamp: datetime
    value: float
    labels: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MetricSummary:
    """Summary statistics for a metric"""
    name: str
    type: MetricType
    count: int
    sum_value: float
    min_value: float
    max_value: float
    mean: float
    median: float
    p95: float
    p99: float
    labels: Dict[str, str] = field(default_factory=dict)
    start_time: datetime = field(default_factory=datetime.now)
    end_time: datetime = field(default_factory=datetime.now)


@dataclass
class MetricBatch:
    """Batch of metrics for efficient processing"""
    metrics: List[MetricPoint] = field(default_factory=list)
    batch_id: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


class AsyncCounter:
    """Asynchronous counter metric"""
    
    def __init__(self, name: str, description: str = "", labels: Dict[str, str] = None):
        self.name = name
        self.description = description
        self.labels = labels or {}
        self.value = 0.0
        self._lock = asyncio.Lock()
    
    async def inc(self, amount: float = 1.0):
        """Increment counter"""
        async with self._lock:
            self.value += amount
    
    async def get(self) -> float:
        """Get current value"""
        async with self._lock:
            return self.value
    
    async def reset(self):
        """Reset counter to zero"""
        async with self._lock:
            self.value = 0.0


class AsyncGauge:
    """Asynchronous gauge metric"""
    
    def __init__(self, name: str, description: str = "", labels: Dict[str, str] = None):
        self.name = name
        self.description = description
        self.labels = labels or {}
        self.value = 0.0
        self._lock = asyncio.Lock()
    
    async def set(self, value: float):
        """Set gauge value"""
        async with self._lock:
            self.value = value
    
    async def inc(self, amount: float = 1.0):
        """Increment gauge"""
        async with self._lock:
            self.value += amount
    
    async def dec(self, amount: float = 1.0):
        """Decrement gauge"""
        async with self._lock:
            self.value -= amount
    
    async def get(self) -> float:
        """Get current value"""
        async with self._lock:
            return self.value


class AsyncHistogram:
    """Asynchronous histogram metric"""
    
    def __init__(
        self,
        name: str,
        description: str = "",
        labels: Dict[str, str] = None,
        buckets: List[float] = None
    ):
        self.name = name
        self.description = description
        self.labels = labels or {}
        self.buckets = buckets or [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
        
        self._observations: deque = deque(maxlen=10000)  # Keep recent observations
        self._bucket_counts = defaultdict(int)
        self._count = 0
        self._sum = 0.0
        self._lock = asyncio.Lock()
    
    async def observe(self, value: float):
        """Add observation to histogram"""
        async with self._lock:
            self._observations.append(value)
            self._count += 1
            self._sum += value
            
            # Update bucket counts
            for bucket in self.buckets:
                if value <= bucket:
                    self._bucket_counts[bucket] += 1
    
    async def get_summary(self) -> MetricSummary:
        """Get histogram summary statistics"""
        async with self._lock:
            if not self._observations:
                return MetricSummary(
                    name=self.name,
                    type=MetricType.HISTOGRAM,
                    count=0,
                    sum_value=0,
                    min_value=0,
                    max_value=0,
                    mean=0,
                    median=0,
                    p95=0,
                    p99=0,
                    labels=self.labels
                )
            
            values = list(self._observations)
            values.sort()
            
            return MetricSummary(
                name=self.name,
                type=MetricType.HISTOGRAM,
                count=len(values),
                sum_value=sum(values),
                min_value=min(values),
                max_value=max(values),
                mean=statistics.mean(values),
                median=statistics.median(values),
                p95=self._percentile(values, 95),
                p99=self._percentile(values, 99),
                labels=self.labels
            )
    
    def _percentile(self, values: List[float], percentile: float) -> float:
        """Calculate percentile"""
        if not values:
            return 0.0
        
        k = (len(values) - 1) * percentile / 100
        f = int(k)
        c = k - f
        
        if f == len(values) - 1:
            return values[f]
        
        return values[f] * (1 - c) + values[f + 1] * c


class AsyncTimer:
    """Asynchronous timer metric (context manager)"""
    
    def __init__(self, histogram: AsyncHistogram):
        self.histogram = histogram
        self.start_time: Optional[float] = None
    
    async def __aenter__(self):
        self.start_time = time.time()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.start_time is not None:
            duration = time.time() - self.start_time
            await self.histogram.observe(duration)


class AsyncMetricsCollector:
    """High-performance async metrics collection system"""
    
    def __init__(self, batch_size: int = 100, flush_interval: float = 30.0):
        self.logger = get_logger(__name__)
        self.error_handler = get_error_handler()
        
        # Configuration
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        
        # Metric storage
        self.counters: Dict[str, AsyncCounter] = {}
        self.gauges: Dict[str, AsyncGauge] = {}
        self.histograms: Dict[str, AsyncHistogram] = {}
        
        # Batching system
        self.metric_queue: asyncio.Queue = asyncio.Queue(maxsize=10000)
        self.current_batch: List[MetricPoint] = []
        
        # Background tasks
        self.batch_processor_task: Optional[asyncio.Task] = None
        self.flush_task: Optional[asyncio.Task] = None
        
        # Statistics
        self.total_metrics_collected = 0
        self.total_batches_processed = 0
        self.last_flush_time = datetime.now()
        
        # Locks
        self._lock = asyncio.Lock()
        
        # Database manager
        self.db_manager = None
    
    async def initialize(self):
        """Initialize metrics collector"""
        try:
            # Get database manager
            self.db_manager = await get_async_db_manager()
            
            # Start background tasks
            self.batch_processor_task = asyncio.create_task(self._batch_processor())
            self.flush_task = asyncio.create_task(self._periodic_flush())
            
            self.logger.info("Async metrics collector initialized")
            
        except Exception as e:
            self.error_handler.handle_error(
                e,
                ErrorContext(
                    component="metrics_collector",
                    operation="initialize",
                    severity="high"
                )
            )
            raise
    
    async def shutdown(self):
        """Shutdown metrics collector"""
        try:
            # Cancel background tasks
            if self.batch_processor_task:
                self.batch_processor_task.cancel()
            if self.flush_task:
                self.flush_task.cancel()
            
            # Flush remaining metrics
            await self._flush_batch()
            
            self.logger.info("Async metrics collector shutdown complete")
            
        except Exception as e:
            self.logger.error(f"Error during metrics collector shutdown: {e}")
    
    # Metric creation methods
    
    def counter(
        self,
        name: str,
        description: str = "",
        labels: Dict[str, str] = None
    ) -> AsyncCounter:
        """Create or get counter metric"""
        if name not in self.counters:
            self.counters[name] = AsyncCounter(name, description, labels)
        return self.counters[name]
    
    def gauge(
        self,
        name: str,
        description: str = "",
        labels: Dict[str, str] = None
    ) -> AsyncGauge:
        """Create or get gauge metric"""
        if name not in self.gauges:
            self.gauges[name] = AsyncGauge(name, description, labels)
        return self.gauges[name]
    
    def histogram(
        self,
        name: str,
        description: str = "",
        labels: Dict[str, str] = None,
        buckets: List[float] = None
    ) -> AsyncHistogram:
        """Create or get histogram metric"""
        if name not in self.histograms:
            self.histograms[name] = AsyncHistogram(name, description, labels, buckets)
        return self.histograms[name]
    
    def timer(self, name: str, labels: Dict[str, str] = None) -> AsyncTimer:
        """Create timer context manager"""
        hist = self.histogram(f"{name}_duration_seconds", labels=labels)
        return AsyncTimer(hist)
    
    # Manual metric recording
    
    async def record_counter(
        self,
        name: str,
        value: float = 1.0,
        labels: Dict[str, str] = None,
        timestamp: Optional[datetime] = None
    ):
        """Record counter metric"""
        await self._queue_metric(MetricPoint(
            timestamp=timestamp or datetime.now(),
            value=value,
            labels={"name": name, "type": "counter", **(labels or {})}
        ))
    
    async def record_gauge(
        self,
        name: str,
        value: float,
        labels: Dict[str, str] = None,
        timestamp: Optional[datetime] = None
    ):
        """Record gauge metric"""
        await self._queue_metric(MetricPoint(
            timestamp=timestamp or datetime.now(),
            value=value,
            labels={"name": name, "type": "gauge", **(labels or {})}
        ))
    
    async def record_histogram(
        self,
        name: str,
        value: float,
        labels: Dict[str, str] = None,
        timestamp: Optional[datetime] = None
    ):
        """Record histogram observation"""
        await self._queue_metric(MetricPoint(
            timestamp=timestamp or datetime.now(),
            value=value,
            labels={"name": name, "type": "histogram", **(labels or {})}
        ))
    
    async def _queue_metric(self, metric: MetricPoint):
        """Queue metric for batch processing"""
        try:
            await self.metric_queue.put(metric)
            self.total_metrics_collected += 1
        except asyncio.QueueFull:
            self.logger.warning("Metrics queue full, dropping metric")
    
    async def _batch_processor(self):
        """Background task to process metric batches"""
        while True:
            try:
                # Collect metrics into batch
                metrics = []
                start_time = time.time()
                
                while len(metrics) < self.batch_size and (time.time() - start_time) < 1.0:
                    try:
                        metric = await asyncio.wait_for(self.metric_queue.get(), timeout=0.1)
                        metrics.append(metric)
                    except asyncio.TimeoutError:
                        break
                
                if metrics:
                    await self._process_batch(metrics)
                else:
                    # No metrics, sleep briefly
                    await asyncio.sleep(0.1)
                
            except Exception as e:
                self.error_handler.handle_error(
                    e,
                    ErrorContext(
                        component="metrics_collector",
                        operation="batch_processing",
                        severity="medium"
                    )
                )
                await asyncio.sleep(1.0)  # Error backoff
    
    async def _process_batch(self, metrics: List[MetricPoint]):
        """Process a batch of metrics"""
        try:
            if not self.db_manager:
                return
            
            # Prepare batch for database insertion
            batch_data = []
            for metric in metrics:
                batch_data.append({
                    'metric_name': metric.labels.get('name', 'unknown'),
                    'metric_value': metric.value,
                    'metric_type': metric.labels.get('type', 'gauge'),
                    'labels': json.dumps(metric.labels),
                    'timestamp': metric.timestamp.isoformat()
                })
            
            # Insert batch into database
            if batch_data:
                queries = [
                    (
                        "INSERT INTO metrics (metric_name, metric_value, metric_type, labels, timestamp) VALUES (?, ?, ?, ?, ?)",
                        (
                            item['metric_name'],
                            item['metric_value'],
                            item['metric_type'],
                            item['labels'],
                            item['timestamp']
                        )
                    )
                    for item in batch_data
                ]
                
                await self.db_manager.execute_batch(queries)
                self.total_batches_processed += 1
        
        except Exception as e:
            self.error_handler.handle_error(
                e,
                ErrorContext(
                    component="metrics_collector",
                    operation="process_batch",
                    severity="medium"
                )
            )
    
    async def _periodic_flush(self):
        """Periodic flush of metrics to persistent storage"""
        while True:
            try:
                await asyncio.sleep(self.flush_interval)
                await self._flush_batch()
                
            except Exception as e:
                self.error_handler.handle_error(
                    e,
                    ErrorContext(
                        component="metrics_collector",
                        operation="periodic_flush",
                        severity="low"
                    )
                )
    
    async def _flush_batch(self):
        """Flush current batch to storage"""
        async with self._lock:
            if self.current_batch:
                await self._process_batch(self.current_batch)
                self.current_batch.clear()
                self.last_flush_time = datetime.now()
    
    # Query and reporting methods
    
    async def get_metric_summary(
        self,
        name: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> Optional[MetricSummary]:
        """Get summary statistics for a metric"""
        try:
            if not self.db_manager:
                return None
            
            # Build query with time range
            where_clause = "metric_name = ?"
            params = [name]
            
            if start_time:
                where_clause += " AND timestamp >= ?"
                params.append(start_time.isoformat())
            
            if end_time:
                where_clause += " AND timestamp <= ?"
                params.append(end_time.isoformat())
            
            # Query metrics
            query = f"""
                SELECT metric_value, timestamp, metric_type, labels
                FROM metrics 
                WHERE {where_clause}
                ORDER BY timestamp
            """
            
            rows = await self.db_manager.fetch_all(query, tuple(params))
            
            if not rows:
                return None
            
            # Calculate summary statistics
            values = [row['metric_value'] for row in rows]
            metric_type = rows[0]['metric_type']
            
            if not values:
                return None
            
            values.sort()
            
            return MetricSummary(
                name=name,
                type=MetricType(metric_type),
                count=len(values),
                sum_value=sum(values),
                min_value=min(values),
                max_value=max(values),
                mean=statistics.mean(values),
                median=statistics.median(values),
                p95=self._percentile(values, 95),
                p99=self._percentile(values, 99),
                start_time=start_time or datetime.min,
                end_time=end_time or datetime.max
            )
            
        except Exception as e:
            self.error_handler.handle_error(
                e,
                ErrorContext(
                    component="metrics_collector",
                    operation="get_metric_summary",
                    severity="low"
                )
            )
            return None
    
    def _percentile(self, values: List[float], percentile: float) -> float:
        """Calculate percentile"""
        if not values:
            return 0.0
        
        k = (len(values) - 1) * percentile / 100
        f = int(k)
        c = k - f
        
        if f == len(values) - 1:
            return values[f]
        
        return values[f] * (1 - c) + values[f + 1] * c
    
    async def get_all_metrics(self) -> Dict[str, Any]:
        """Get all current metric values"""
        result = {
            'counters': {},
            'gauges': {},
            'histograms': {}
        }
        
        # Get counter values
        for name, counter in self.counters.items():
            result['counters'][name] = await counter.get()
        
        # Get gauge values
        for name, gauge in self.gauges.items():
            result['gauges'][name] = await gauge.get()
        
        # Get histogram summaries
        for name, histogram in self.histograms.items():
            summary = await histogram.get_summary()
            result['histograms'][name] = {
                'count': summary.count,
                'sum': summary.sum_value,
                'mean': summary.mean,
                'median': summary.median,
                'p95': summary.p95,
                'p99': summary.p99
            }
        
        return result
    
    async def stream_metrics(
        self,
        name_pattern: str = "*",
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        batch_size: int = 1000
    ) -> AsyncIterator[List[MetricPoint]]:
        """Stream metrics matching pattern"""
        try:
            if not self.db_manager:
                return
            
            # Build query
            where_clause = "1=1"
            params = []
            
            if name_pattern != "*":
                where_clause += " AND metric_name LIKE ?"
                params.append(name_pattern.replace("*", "%"))
            
            if start_time:
                where_clause += " AND timestamp >= ?"
                params.append(start_time.isoformat())
            
            if end_time:
                where_clause += " AND timestamp <= ?"
                params.append(end_time.isoformat())
            
            query = f"""
                SELECT metric_name, metric_value, metric_type, labels, timestamp
                FROM metrics 
                WHERE {where_clause}
                ORDER BY timestamp
            """
            
            # Stream results in batches
            async for batch_rows in self.db_manager.stream_results(query, tuple(params), batch_size):
                metrics = []
                for row in batch_rows:
                    try:
                        labels = json.loads(row['labels']) if row['labels'] else {}
                    except json.JSONDecodeError:
                        labels = {}
                    
                    metrics.append(MetricPoint(
                        timestamp=datetime.fromisoformat(row['timestamp']),
                        value=row['metric_value'],
                        labels=labels
                    ))
                
                yield metrics
                
        except Exception as e:
            self.error_handler.handle_error(
                e,
                ErrorContext(
                    component="metrics_collector",
                    operation="stream_metrics",
                    severity="low"
                )
            )
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get collector statistics"""
        return {
            'total_metrics_collected': self.total_metrics_collected,
            'total_batches_processed': self.total_batches_processed,
            'queue_size': self.metric_queue.qsize(),
            'counters_count': len(self.counters),
            'gauges_count': len(self.gauges),
            'histograms_count': len(self.histograms),
            'last_flush_time': self.last_flush_time.isoformat(),
            'batch_size': self.batch_size,
            'flush_interval': self.flush_interval
        }


# Global metrics collector
_global_metrics_collector: Optional[AsyncMetricsCollector] = None


async def get_metrics_collector() -> AsyncMetricsCollector:
    """Get global async metrics collector"""
    global _global_metrics_collector
    if _global_metrics_collector is None:
        _global_metrics_collector = AsyncMetricsCollector()
        await _global_metrics_collector.initialize()
    return _global_metrics_collector


# Convenience functions for common metrics patterns

@asynccontextmanager
async def measure_time(metric_name: str, labels: Dict[str, str] = None):
    """Context manager for measuring execution time"""
    collector = await get_metrics_collector()
    async with collector.timer(metric_name, labels) as timer:
        yield timer


async def increment_counter(name: str, amount: float = 1.0, labels: Dict[str, str] = None):
    """Convenience function to increment counter"""
    collector = await get_metrics_collector()
    await collector.record_counter(name, amount, labels)


async def set_gauge(name: str, value: float, labels: Dict[str, str] = None):
    """Convenience function to set gauge value"""
    collector = await get_metrics_collector()
    await collector.record_gauge(name, value, labels)


async def observe_histogram(name: str, value: float, labels: Dict[str, str] = None):
    """Convenience function to observe histogram value"""
    collector = await get_metrics_collector()
    await collector.record_histogram(name, value, labels)


# Alias for backward compatibility
record_histogram = observe_histogram


__all__ = [
    'AsyncMetricsCollector',
    'AsyncCounter',
    'AsyncGauge',
    'AsyncHistogram',
    'AsyncTimer',
    'MetricType',
    'MetricPoint',
    'MetricSummary',
    'MetricBatch',
    'get_metrics_collector',
    'measure_time',
    'increment_counter',
    'set_gauge',
    'observe_histogram',
    'record_histogram'
]