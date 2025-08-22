# BLRCS Performance Monitor
# Real-time performance monitoring and optimization system
import time
import threading
import psutil
import asyncio
from datetime import datetime, timedelta
from typing import (
    Dict, List, Any, Optional, Callable, Union, TypeVar,
    NamedTuple, Protocol, runtime_checkable
)
from dataclasses import dataclass, field
from enum import Enum
from collections import deque, defaultdict
import statistics
import json
import sqlite3
from pathlib import Path
import functools
import contextvars
import inspect

T = TypeVar('T')

class MetricType(Enum):
    """Types of performance metrics"""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"
    TIMER = "timer"

class AlertLevel(Enum):
    """Performance alert levels"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"

@dataclass
class PerformanceMetric:
    """Individual performance metric"""
    name: str
    value: Union[int, float]
    metric_type: MetricType
    timestamp: datetime = field(default_factory=datetime.now)
    tags: Dict[str, str] = field(default_factory=dict)
    unit: str = ""
    help_text: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'name': self.name,
            'value': self.value,
            'type': self.metric_type.value,
            'timestamp': self.timestamp.isoformat(),
            'tags': self.tags,
            'unit': self.unit,
            'help_text': self.help_text
        }

@dataclass
class PerformanceSnapshot:
    """Complete performance snapshot"""
    timestamp: datetime = field(default_factory=datetime.now)
    
    # System metrics
    cpu_percent: float = 0.0
    memory_usage: float = 0.0
    disk_io: Dict[str, float] = field(default_factory=dict)
    network_io: Dict[str, float] = field(default_factory=dict)
    
    # Process metrics
    process_cpu: float = 0.0
    process_memory: int = 0
    thread_count: int = 0
    file_descriptors: int = 0
    
    # Application metrics
    active_connections: int = 0
    request_rate: float = 0.0
    error_rate: float = 0.0
    avg_response_time: float = 0.0
    
    # Custom metrics
    custom_metrics: Dict[str, float] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'system': {
                'cpu_percent': self.cpu_percent,
                'memory_usage': self.memory_usage,
                'disk_io': self.disk_io,
                'network_io': self.network_io
            },
            'process': {
                'cpu_percent': self.process_cpu,
                'memory_bytes': self.process_memory,
                'thread_count': self.thread_count,
                'file_descriptors': self.file_descriptors
            },
            'application': {
                'active_connections': self.active_connections,
                'request_rate': self.request_rate,
                'error_rate': self.error_rate,
                'avg_response_time': self.avg_response_time
            },
            'custom': self.custom_metrics
        }

class MetricCollector:
    """Collects and aggregates performance metrics"""
    
    def __init__(self, max_samples: int = 10000):
        self.max_samples = max_samples
        self.metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=max_samples))
        self.counters: Dict[str, float] = defaultdict(float)
        self.gauges: Dict[str, float] = defaultdict(float)
        self.histograms: Dict[str, List[float]] = defaultdict(list)
        self.timers: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.lock = threading.RLock()
    
    def record_metric(self, metric: PerformanceMetric):
        """Record a performance metric"""
        with self.lock:
            key = self._get_metric_key(metric)
            
            if metric.metric_type == MetricType.COUNTER:
                self.counters[key] += metric.value
            
            elif metric.metric_type == MetricType.GAUGE:
                self.gauges[key] = metric.value
            
            elif metric.metric_type == MetricType.HISTOGRAM:
                self.histograms[key].append(metric.value)
                # Keep histogram size manageable
                if len(self.histograms[key]) > 10000:
                    self.histograms[key] = self.histograms[key][-5000:]
            
            elif metric.metric_type == MetricType.TIMER:
                self.timers[key].append(metric.value)
            
            # Always store in time series
            self.metrics[key].append((metric.timestamp, metric.value))
    
    def _get_metric_key(self, metric: PerformanceMetric) -> str:
        """Generate unique key for metric"""
        if metric.tags:
            tags_str = ",".join(f"{k}={v}" for k, v in sorted(metric.tags.items()))
            return f"{metric.name}[{tags_str}]"
        return metric.name
    
    def get_counter(self, name: str, tags: Dict[str, str] = None) -> float:
        """Get counter value"""
        key = self._get_metric_key(PerformanceMetric(name, 0, MetricType.COUNTER, tags=tags or {}))
        return self.counters.get(key, 0.0)
    
    def get_gauge(self, name: str, tags: Dict[str, str] = None) -> float:
        """Get gauge value"""
        key = self._get_metric_key(PerformanceMetric(name, 0, MetricType.GAUGE, tags=tags or {}))
        return self.gauges.get(key, 0.0)
    
    def get_histogram_stats(self, name: str, tags: Dict[str, str] = None) -> Dict[str, float]:
        """Get histogram statistics"""
        key = self._get_metric_key(PerformanceMetric(name, 0, MetricType.HISTOGRAM, tags=tags or {}))
        values = self.histograms.get(key, [])
        
        if not values:
            return {}
        
        return {
            'count': len(values),
            'min': min(values),
            'max': max(values),
            'mean': statistics.mean(values),
            'median': statistics.median(values),
            'p95': self._percentile(values, 0.95),
            'p99': self._percentile(values, 0.99),
            'std_dev': statistics.stdev(values) if len(values) > 1 else 0
        }
    
    def get_timer_stats(self, name: str, tags: Dict[str, str] = None) -> Dict[str, float]:
        """Get timer statistics"""
        key = self._get_metric_key(PerformanceMetric(name, 0, MetricType.TIMER, tags=tags or {}))
        values = list(self.timers.get(key, []))
        
        if not values:
            return {}
        
        return {
            'count': len(values),
            'min_ms': min(values) * 1000,
            'max_ms': max(values) * 1000,
            'mean_ms': statistics.mean(values) * 1000,
            'median_ms': statistics.median(values) * 1000,
            'p95_ms': self._percentile(values, 0.95) * 1000,
            'p99_ms': self._percentile(values, 0.99) * 1000
        }
    
    def _percentile(self, values: List[float], percentile: float) -> float:
        """Calculate percentile"""
        if not values:
            return 0.0
        
        sorted_values = sorted(values)
        index = int(len(sorted_values) * percentile)
        index = min(index, len(sorted_values) - 1)
        return sorted_values[index]
    
    def get_time_series(self, name: str, tags: Dict[str, str] = None, 
                       duration: timedelta = None) -> List[Tuple[datetime, float]]:
        """Get time series data"""
        key = self._get_metric_key(PerformanceMetric(name, 0, MetricType.GAUGE, tags=tags or {}))
        series = list(self.metrics.get(key, []))
        
        if duration:
            cutoff_time = datetime.now() - duration
            series = [(ts, val) for ts, val in series if ts > cutoff_time]
        
        return series
    
    def clear_metrics(self):
        """Clear all collected metrics"""
        with self.lock:
            self.metrics.clear()
            self.counters.clear()
            self.gauges.clear()
            self.histograms.clear()
            self.timers.clear()

class SystemMetricsCollector:
    """Collects system-level performance metrics"""
    
    def __init__(self):
        self.process = psutil.Process()
        self.last_cpu_times = None
        self.last_io_counters = None
        self.last_net_io = None
        self.last_timestamp = None
    
    def collect_snapshot(self) -> PerformanceSnapshot:
        """Collect current performance snapshot"""
        current_time = time.time()
        
        # System metrics
        cpu_percent = psutil.cpu_percent(interval=None)
        memory = psutil.virtual_memory()
        
        # Disk I/O
        disk_io = {}
        try:
            disk_counters = psutil.disk_io_counters()
            if disk_counters and self.last_io_counters and self.last_timestamp:
                time_delta = current_time - self.last_timestamp
                if time_delta > 0:
                    disk_io = {
                        'read_bytes_per_sec': (disk_counters.read_bytes - self.last_io_counters.read_bytes) / time_delta,
                        'write_bytes_per_sec': (disk_counters.write_bytes - self.last_io_counters.write_bytes) / time_delta,
                        'read_ops_per_sec': (disk_counters.read_count - self.last_io_counters.read_count) / time_delta,
                        'write_ops_per_sec': (disk_counters.write_count - self.last_io_counters.write_count) / time_delta
                    }
            self.last_io_counters = disk_counters
        except:
            pass
        
        # Network I/O
        network_io = {}
        try:
            net_counters = psutil.net_io_counters()
            if net_counters and self.last_net_io and self.last_timestamp:
                time_delta = current_time - self.last_timestamp
                if time_delta > 0:
                    network_io = {
                        'bytes_sent_per_sec': (net_counters.bytes_sent - self.last_net_io.bytes_sent) / time_delta,
                        'bytes_recv_per_sec': (net_counters.bytes_recv - self.last_net_io.bytes_recv) / time_delta,
                        'packets_sent_per_sec': (net_counters.packets_sent - self.last_net_io.packets_sent) / time_delta,
                        'packets_recv_per_sec': (net_counters.packets_recv - self.last_net_io.packets_recv) / time_delta
                    }
            self.last_net_io = net_counters
        except:
            pass
        
        # Process metrics
        try:
            process_cpu = self.process.cpu_percent()
            process_memory = self.process.memory_info().rss
            thread_count = self.process.num_threads()
            
            # File descriptors (Unix only)
            file_descriptors = 0
            try:
                file_descriptors = self.process.num_fds()
            except:
                pass
        except:
            process_cpu = 0.0
            process_memory = 0
            thread_count = 0
            file_descriptors = 0
        
        self.last_timestamp = current_time
        
        return PerformanceSnapshot(
            cpu_percent=cpu_percent,
            memory_usage=memory.percent,
            disk_io=disk_io,
            network_io=network_io,
            process_cpu=process_cpu,
            process_memory=process_memory,
            thread_count=thread_count,
            file_descriptors=file_descriptors
        )

class PerformanceAlert:
    """Performance alert configuration and checking"""
    
    def __init__(self, 
                 name: str,
                 metric_name: str,
                 threshold: float,
                 operator: str = 'gt',  # gt, lt, gte, lte, eq, ne
                 level: AlertLevel = AlertLevel.WARNING,
                 duration: timedelta = timedelta(minutes=1),
                 callback: Optional[Callable] = None):
        
        self.name = name
        self.metric_name = metric_name
        self.threshold = threshold
        self.operator = operator
        self.level = level
        self.duration = duration
        self.callback = callback
        
        # State tracking
        self.triggered = False
        self.trigger_time: Optional[datetime] = None
        self.trigger_count = 0
        self.last_check = datetime.now()
    
    def check(self, current_value: float) -> bool:
        """Check if alert should trigger"""
        now = datetime.now()
        self.last_check = now
        
        # Evaluate condition
        condition_met = self._evaluate_condition(current_value)
        
        if condition_met:
            if not self.triggered:
                # First time triggering
                self.trigger_time = now
                self.triggered = True
                self.trigger_count += 1
                
                # Check if duration requirement is met
                if self.duration.total_seconds() == 0:
                    self._fire_alert(current_value)
                    return True
            else:
                # Already triggered, check duration
                if now - self.trigger_time >= self.duration:
                    self._fire_alert(current_value)
                    return True
        else:
            # Condition not met, reset
            if self.triggered:
                self.triggered = False
                self.trigger_time = None
        
        return False
    
    def _evaluate_condition(self, value: float) -> bool:
        """Evaluate alert condition"""
        if self.operator == 'gt':
            return value > self.threshold
        elif self.operator == 'gte':
            return value >= self.threshold
        elif self.operator == 'lt':
            return value < self.threshold
        elif self.operator == 'lte':
            return value <= self.threshold
        elif self.operator == 'eq':
            return abs(value - self.threshold) < 1e-9
        elif self.operator == 'ne':
            return abs(value - self.threshold) >= 1e-9
        else:
            return False
    
    def _fire_alert(self, current_value: float):
        """Fire the alert"""
        if self.callback:
            try:
                self.callback(self, current_value)
            except Exception as e:
                print(f"Alert callback error: {e}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'name': self.name,
            'metric_name': self.metric_name,
            'threshold': self.threshold,
            'operator': self.operator,
            'level': self.level.value,
            'duration_seconds': self.duration.total_seconds(),
            'triggered': self.triggered,
            'trigger_time': self.trigger_time.isoformat() if self.trigger_time else None,
            'trigger_count': self.trigger_count,
            'last_check': self.last_check.isoformat()
        }

class PerformanceMonitor:
    """Main performance monitoring system"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Core components
        self.metric_collector = MetricCollector(
            max_samples=self.config.get('max_samples', 10000)
        )
        self.system_collector = SystemMetricsCollector()
        
        # Monitoring state
        self.monitoring = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.collection_interval = self.config.get('collection_interval', 5.0)
        
        # Performance snapshots
        self.snapshots: deque[PerformanceSnapshot] = deque(
            maxlen=self.config.get('max_snapshots', 1000)
        )
        
        # Alerts
        self.alerts: Dict[str, PerformanceAlert] = {}
        self.alert_history: deque[Dict[str, Any]] = deque(maxlen=1000)
        
        # Performance baselines
        self.baselines: Dict[str, float] = {}
        self.baseline_percentile = 0.95
        
        # Database storage (optional)
        self.db_path = self.config.get('db_path')
        self.db_connection: Optional[sqlite3.Connection] = None
        
        if self.db_path:
            self._init_database()
    
    def _init_database(self):
        """Initialize database for metric storage"""
        try:
            self.db_connection = sqlite3.connect(
                self.db_path, 
                check_same_thread=False,
                timeout=30.0
            )
            
            # Create tables
            self.db_connection.execute('''
                CREATE TABLE IF NOT EXISTS performance_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    data TEXT NOT NULL
                )
            ''')
            
            self.db_connection.execute('''
                CREATE TABLE IF NOT EXISTS performance_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    value REAL NOT NULL,
                    type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    tags TEXT
                )
            ''')
            
            # Create indexes
            self.db_connection.execute('''
                CREATE INDEX IF NOT EXISTS idx_snapshots_timestamp 
                ON performance_snapshots(timestamp)
            ''')
            
            self.db_connection.execute('''
                CREATE INDEX IF NOT EXISTS idx_metrics_name_timestamp 
                ON performance_metrics(name, timestamp)
            ''')
            
            self.db_connection.commit()
            
        except Exception as e:
            print(f"Database initialization error: {e}")
            self.db_connection = None
    
    def start_monitoring(self):
        """Start performance monitoring"""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True
        )
        self.monitor_thread.start()
        
        print(f"Performance monitoring started (interval: {self.collection_interval}s)")
    
    def stop_monitoring(self):
        """Stop performance monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=10.0)
        
        if self.db_connection:
            self.db_connection.close()
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                # Collect system snapshot
                snapshot = self.system_collector.collect_snapshot()
                self.snapshots.append(snapshot)
                
                # Store metrics
                self._store_snapshot_metrics(snapshot)
                
                # Check alerts
                self._check_alerts(snapshot)
                
                # Update baselines
                self._update_baselines(snapshot)
                
                # Store in database
                if self.db_connection:
                    self._store_snapshot_in_db(snapshot)
                
                time.sleep(self.collection_interval)
                
            except Exception as e:
                print(f"Monitor loop error: {e}")
                time.sleep(self.collection_interval)
    
    def _store_snapshot_metrics(self, snapshot: PerformanceSnapshot):
        """Store snapshot as individual metrics"""
        timestamp = snapshot.timestamp
        
        # System metrics
        self.record_gauge('system.cpu_percent', snapshot.cpu_percent, timestamp)
        self.record_gauge('system.memory_usage_percent', snapshot.memory_usage, timestamp)
        
        # Process metrics
        self.record_gauge('process.cpu_percent', snapshot.process_cpu, timestamp)
        self.record_gauge('process.memory_bytes', snapshot.process_memory, timestamp)
        self.record_gauge('process.thread_count', snapshot.thread_count, timestamp)
        self.record_gauge('process.file_descriptors', snapshot.file_descriptors, timestamp)
        
        # I/O metrics
        for key, value in snapshot.disk_io.items():
            self.record_gauge(f'disk.{key}', value, timestamp)
        
        for key, value in snapshot.network_io.items():
            self.record_gauge(f'network.{key}', value, timestamp)
        
        # Application metrics
        self.record_gauge('app.active_connections', snapshot.active_connections, timestamp)
        self.record_gauge('app.request_rate', snapshot.request_rate, timestamp)
        self.record_gauge('app.error_rate', snapshot.error_rate, timestamp)
        self.record_gauge('app.avg_response_time', snapshot.avg_response_time, timestamp)
        
        # Custom metrics
        for key, value in snapshot.custom_metrics.items():
            self.record_gauge(f'custom.{key}', value, timestamp)
    
    def _check_alerts(self, snapshot: PerformanceSnapshot):
        """Check all alerts against current snapshot"""
        # Extract metric values from snapshot
        metric_values = {
            'system.cpu_percent': snapshot.cpu_percent,
            'system.memory_usage_percent': snapshot.memory_usage,
            'process.cpu_percent': snapshot.process_cpu,
            'process.memory_bytes': snapshot.process_memory,
            'process.thread_count': snapshot.thread_count,
            'app.request_rate': snapshot.request_rate,
            'app.error_rate': snapshot.error_rate,
            'app.avg_response_time': snapshot.avg_response_time
        }
        
        for alert in self.alerts.values():
            if alert.metric_name in metric_values:
                current_value = metric_values[alert.metric_name]
                if alert.check(current_value):
                    self._log_alert(alert, current_value)
    
    def _log_alert(self, alert: PerformanceAlert, current_value: float):
        """Log alert firing"""
        alert_record = {
            'timestamp': datetime.now().isoformat(),
            'alert_name': alert.name,
            'metric_name': alert.metric_name,
            'current_value': current_value,
            'threshold': alert.threshold,
            'level': alert.level.value
        }
        
        self.alert_history.append(alert_record)
        
        print(f"ALERT [{alert.level.value.upper()}] {alert.name}: "
              f"{alert.metric_name} = {current_value} (threshold: {alert.threshold})")
    
    def _update_baselines(self, snapshot: PerformanceSnapshot):
        """Update performance baselines"""
        if len(self.snapshots) < 100:  # Need enough data
            return
        
        # Calculate baselines for key metrics
        recent_snapshots = list(self.snapshots)[-100:]  # Last 100 snapshots
        
        metrics_to_baseline = [
            ('cpu_percent', [s.cpu_percent for s in recent_snapshots]),
            ('memory_usage', [s.memory_usage for s in recent_snapshots]),
            ('process_cpu', [s.process_cpu for s in recent_snapshots]),
            ('avg_response_time', [s.avg_response_time for s in recent_snapshots if s.avg_response_time > 0])
        ]
        
        for metric_name, values in metrics_to_baseline:
            if values:
                baseline = self._calculate_baseline(values)
                self.baselines[metric_name] = baseline
    
    def _calculate_baseline(self, values: List[float]) -> float:
        """Calculate performance baseline"""
        if not values:
            return 0.0
        
        # Use specified percentile as baseline
        sorted_values = sorted(values)
        index = int(len(sorted_values) * self.baseline_percentile)
        index = min(index, len(sorted_values) - 1)
        
        return sorted_values[index]
    
    def _store_snapshot_in_db(self, snapshot: PerformanceSnapshot):
        """Store snapshot in database"""
        try:
            data_json = json.dumps(snapshot.to_dict())
            
            self.db_connection.execute(
                "INSERT INTO performance_snapshots (timestamp, data) VALUES (?, ?)",
                (snapshot.timestamp.isoformat(), data_json)
            )
            
            self.db_connection.commit()
            
        except Exception as e:
            print(f"Database storage error: {e}")
    
    # Public API methods
    def record_counter(self, name: str, value: float = 1.0, 
                      tags: Dict[str, str] = None, timestamp: datetime = None):
        """Record counter metric"""
        metric = PerformanceMetric(
            name=name,
            value=value,
            metric_type=MetricType.COUNTER,
            timestamp=timestamp or datetime.now(),
            tags=tags or {}
        )
        self.metric_collector.record_metric(metric)
    
    def record_gauge(self, name: str, value: float, 
                    tags: Dict[str, str] = None, timestamp: datetime = None):
        """Record gauge metric"""
        metric = PerformanceMetric(
            name=name,
            value=value,
            metric_type=MetricType.GAUGE,
            timestamp=timestamp or datetime.now(),
            tags=tags or {}
        )
        self.metric_collector.record_metric(metric)
    
    def record_histogram(self, name: str, value: float, 
                        tags: Dict[str, str] = None, timestamp: datetime = None):
        """Record histogram metric"""
        metric = PerformanceMetric(
            name=name,
            value=value,
            metric_type=MetricType.HISTOGRAM,
            timestamp=timestamp or datetime.now(),
            tags=tags or {}
        )
        self.metric_collector.record_metric(metric)
    
    def record_timer(self, name: str, duration: float, 
                    tags: Dict[str, str] = None, timestamp: datetime = None):
        """Record timer metric"""
        metric = PerformanceMetric(
            name=name,
            value=duration,
            metric_type=MetricType.TIMER,
            timestamp=timestamp or datetime.now(),
            tags=tags or {}
        )
        self.metric_collector.record_metric(metric)
    
    def add_alert(self, alert: PerformanceAlert):
        """Add performance alert"""
        self.alerts[alert.name] = alert
    
    def remove_alert(self, name: str):
        """Remove performance alert"""
        if name in self.alerts:
            del self.alerts[name]
    
    def get_current_snapshot(self) -> Optional[PerformanceSnapshot]:
        """Get most recent performance snapshot"""
        return self.snapshots[-1] if self.snapshots else None
    
    def get_metric_stats(self, name: str, metric_type: MetricType, 
                        tags: Dict[str, str] = None) -> Dict[str, Any]:
        """Get statistics for a metric"""
        if metric_type == MetricType.HISTOGRAM:
            return self.metric_collector.get_histogram_stats(name, tags)
        elif metric_type == MetricType.TIMER:
            return self.metric_collector.get_timer_stats(name, tags)
        elif metric_type == MetricType.COUNTER:
            return {'value': self.metric_collector.get_counter(name, tags)}
        elif metric_type == MetricType.GAUGE:
            return {'value': self.metric_collector.get_gauge(name, tags)}
        else:
            return {}
    
    def get_performance_report(self, duration: timedelta = None) -> Dict[str, Any]:
        """Get comprehensive performance report"""
        if duration is None:
            duration = timedelta(hours=1)
        
        cutoff_time = datetime.now() - duration
        recent_snapshots = [s for s in self.snapshots if s.timestamp > cutoff_time]
        
        if not recent_snapshots:
            return {}
        
        # Calculate statistics
        cpu_values = [s.cpu_percent for s in recent_snapshots]
        memory_values = [s.memory_usage for s in recent_snapshots]
        process_cpu_values = [s.process_cpu for s in recent_snapshots]
        
        return {
            'period': {
                'start': recent_snapshots[0].timestamp.isoformat(),
                'end': recent_snapshots[-1].timestamp.isoformat(),
                'duration_seconds': duration.total_seconds(),
                'sample_count': len(recent_snapshots)
            },
            'system': {
                'cpu_percent': {
                    'min': min(cpu_values) if cpu_values else 0,
                    'max': max(cpu_values) if cpu_values else 0,
                    'avg': statistics.mean(cpu_values) if cpu_values else 0,
                    'p95': self.metric_collector._percentile(cpu_values, 0.95) if cpu_values else 0
                },
                'memory_usage_percent': {
                    'min': min(memory_values) if memory_values else 0,
                    'max': max(memory_values) if memory_values else 0,
                    'avg': statistics.mean(memory_values) if memory_values else 0,
                    'p95': self.metric_collector._percentile(memory_values, 0.95) if memory_values else 0
                }
            },
            'process': {
                'cpu_percent': {
                    'min': min(process_cpu_values) if process_cpu_values else 0,
                    'max': max(process_cpu_values) if process_cpu_values else 0,
                    'avg': statistics.mean(process_cpu_values) if process_cpu_values else 0
                }
            },
            'baselines': self.baselines.copy(),
            'alerts': {
                'active_count': len([a for a in self.alerts.values() if a.triggered]),
                'total_count': len(self.alerts),
                'recent_alerts': list(self.alert_history)[-10:]  # Last 10 alerts
            }
        }

# Performance monitoring decorators
def monitor_performance(metric_name: str = None, tags: Dict[str, str] = None):
    """Decorator to monitor function performance"""
    def decorator(func):
        nonlocal metric_name
        if metric_name is None:
            metric_name = f"{func.__module__}.{func.__qualname__}"
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            start_time = time.perf_counter()
            try:
                result = func(*args, **kwargs)
                success = True
                return result
            except Exception as e:
                success = False
                raise
            finally:
                duration = time.perf_counter() - start_time
                
                # Record metrics if monitor is available
                try:
                    monitor = get_performance_monitor()
                    monitor.record_timer(f"{metric_name}.duration", duration, tags)
                    monitor.record_counter(f"{metric_name}.calls", 1.0, tags)
                    
                    if not success:
                        monitor.record_counter(f"{metric_name}.errors", 1.0, tags)
                except:
                    pass  # Don't let monitoring break the function
        
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            start_time = time.perf_counter()
            try:
                result = await func(*args, **kwargs)
                success = True
                return result
            except Exception as e:
                success = False
                raise
            finally:
                duration = time.perf_counter() - start_time
                
                # Record metrics if monitor is available
                try:
                    monitor = get_performance_monitor()
                    monitor.record_timer(f"{metric_name}.duration", duration, tags)
                    monitor.record_counter(f"{metric_name}.calls", 1.0, tags)
                    
                    if not success:
                        monitor.record_counter(f"{metric_name}.errors", 1.0, tags)
                except:
                    pass
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    
    return decorator

# Context manager for performance timing
class performance_timer:
    """Context manager for timing operations"""
    
    def __init__(self, metric_name: str, tags: Dict[str, str] = None):
        self.metric_name = metric_name
        self.tags = tags or {}
        self.start_time = 0
        self.duration = 0
    
    def __enter__(self):
        self.start_time = time.perf_counter()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.duration = time.perf_counter() - self.start_time
        
        try:
            monitor = get_performance_monitor()
            monitor.record_timer(self.metric_name, self.duration, self.tags)
        except:
            pass

# Global performance monitor instance
_performance_monitor: Optional[PerformanceMonitor] = None

def get_performance_monitor(config: Dict[str, Any] = None) -> PerformanceMonitor:
    """Get or create global performance monitor"""
    global _performance_monitor
    
    if _performance_monitor is None:
        _performance_monitor = PerformanceMonitor(config)
    
    return _performance_monitor

# Export main classes and functions
__all__ = [
    'MetricType', 'AlertLevel', 'PerformanceMetric', 'PerformanceSnapshot',
    'PerformanceAlert', 'PerformanceMonitor', 'MetricCollector',
    'SystemMetricsCollector', 'get_performance_monitor', 'monitor_performance',
    'performance_timer'
]