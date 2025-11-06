"""
BLNCS Performance Profiler
Real-time performance monitoring and bottleneck detection
"""

import time
import threading
import logging
import psutil
import functools
from typing import Any, Callable, Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime, timezone
from contextlib import contextmanager
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


@dataclass
class PerformanceMetrics:
    """Performance metrics for a function or operation"""
    name: str
    call_count: int = 0
    total_time: float = 0.0
    min_time: float = float('inf')
    max_time: float = 0.0
    avg_time: float = 0.0
    p50_time: float = 0.0
    p95_time: float = 0.0
    p99_time: float = 0.0
    recent_times: deque = field(default_factory=lambda: deque(maxlen=1000))
    errors: int = 0
    last_called: Optional[str] = None

    def record_call(self, duration: float, error: bool = False):
        """Record a function call"""
        self.call_count += 1
        self.total_time += duration
        self.min_time = min(self.min_time, duration)
        self.max_time = max(self.max_time, duration)
        self.avg_time = self.total_time / self.call_count
        self.recent_times.append(duration)
        self.last_called = datetime.now(timezone.utc).isoformat()

        if error:
            self.errors += 1

        # Update percentiles
        if self.recent_times:
            sorted_times = sorted(self.recent_times)
            n = len(sorted_times)
            self.p50_time = sorted_times[int(n * 0.50)]
            self.p95_time = sorted_times[int(n * 0.95)]
            self.p99_time = sorted_times[int(n * 0.99)]


@dataclass
class ResourceSnapshot:
    """System resource snapshot"""
    timestamp: str
    cpu_percent: float
    memory_percent: float
    memory_mb: float
    disk_io_read_mb: float
    disk_io_write_mb: float
    network_sent_mb: float
    network_recv_mb: float
    thread_count: int
    open_files: int


class PerformanceProfiler:
    """
    Production-grade performance profiler with:
    - Function execution timing
    - Resource usage monitoring
    - Bottleneck detection
    - Performance regression detection
    - Real-time alerting
    """

    def __init__(
        self,
        slow_threshold: float = 1.0,
        monitoring_interval: float = 5.0,
        enable_resource_monitoring: bool = True
    ):
        self.slow_threshold = slow_threshold
        self.monitoring_interval = monitoring_interval
        self.enable_resource_monitoring = enable_resource_monitoring

        self._metrics: Dict[str, PerformanceMetrics] = {}
        self._resource_history: deque = deque(maxlen=1000)
        self._lock = threading.RLock()

        # Baseline metrics for regression detection
        self._baselines: Dict[str, float] = {}

        # Start resource monitoring
        if self.enable_resource_monitoring:
            self._start_resource_monitoring()

    def _start_resource_monitoring(self):
        """Start background resource monitoring"""
        def monitor():
            process = psutil.Process()
            last_disk_io = process.io_counters()
            last_net_io = psutil.net_io_counters()

            while True:
                try:
                    time.sleep(self.monitoring_interval)

                    # Get current metrics
                    cpu = process.cpu_percent(interval=0.1)
                    mem_info = process.memory_info()
                    mem_percent = process.memory_percent()

                    # Disk I/O
                    current_disk_io = process.io_counters()
                    disk_read_mb = (current_disk_io.read_bytes - last_disk_io.read_bytes) / (1024 * 1024)
                    disk_write_mb = (current_disk_io.write_bytes - last_disk_io.write_bytes) / (1024 * 1024)
                    last_disk_io = current_disk_io

                    # Network I/O
                    current_net_io = psutil.net_io_counters()
                    net_sent_mb = (current_net_io.bytes_sent - last_net_io.bytes_sent) / (1024 * 1024)
                    net_recv_mb = (current_net_io.bytes_recv - last_net_io.bytes_recv) / (1024 * 1024)
                    last_net_io = current_net_io

                    # Create snapshot
                    snapshot = ResourceSnapshot(
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        cpu_percent=cpu,
                        memory_percent=mem_percent,
                        memory_mb=mem_info.rss / (1024 * 1024),
                        disk_io_read_mb=disk_read_mb / self.monitoring_interval,
                        disk_io_write_mb=disk_write_mb / self.monitoring_interval,
                        network_sent_mb=net_sent_mb / self.monitoring_interval,
                        network_recv_mb=net_recv_mb / self.monitoring_interval,
                        thread_count=threading.active_count(),
                        open_files=len(process.open_files())
                    )

                    with self._lock:
                        self._resource_history.append(snapshot)

                    # Alert on high resource usage
                    if cpu > 90:
                        logger.warning("High CPU usage: %.1f%%", cpu)
                    if mem_percent > 90:
                        logger.warning("High memory usage: %.1f%%", mem_percent)

                except Exception as e:
                    logger.exception("Error in resource monitoring: %s", e)

        thread = threading.Thread(target=monitor, daemon=True, name="ResourceMonitor")
        thread.start()

    @contextmanager
    def profile(self, name: str):
        """
        Context manager for profiling code blocks

        Usage:
            with profiler.profile('my_operation'):
                # code to profile
                pass
        """
        start_time = time.perf_counter()
        error = False

        try:
            yield
        except Exception:
            error = True
            raise
        finally:
            duration = time.perf_counter() - start_time
            self._record_metric(name, duration, error)

    def profile_function(self, func: Optional[Callable] = None, *, name: Optional[str] = None):
        """
        Decorator for profiling functions

        Usage:
            @profiler.profile_function
            def my_function():
                pass

            @profiler.profile_function(name='custom_name')
            def my_function():
                pass
        """
        def decorator(f: Callable) -> Callable:
            metric_name = name or f"{f.__module__}.{f.__name__}"

            @functools.wraps(f)
            def wrapper(*args, **kwargs):
                start_time = time.perf_counter()
                error = False

                try:
                    result = f(*args, **kwargs)
                    return result
                except Exception:
                    error = True
                    raise
                finally:
                    duration = time.perf_counter() - start_time
                    self._record_metric(metric_name, duration, error)

            return wrapper

        if func is None:
            return decorator
        else:
            return decorator(func)

    def _record_metric(self, name: str, duration: float, error: bool = False):
        """Record performance metric"""
        with self._lock:
            if name not in self._metrics:
                self._metrics[name] = PerformanceMetrics(name=name)

            self._metrics[name].record_call(duration, error)

            # Check for slow operation
            if duration >= self.slow_threshold:
                logger.warning(
                    "Slow operation detected: %s took %.3fs (threshold: %.3fs)",
                    name, duration, self.slow_threshold
                )

            # Check for performance regression
            if name in self._baselines:
                baseline = self._baselines[name]
                if duration > baseline * 1.5:  # 50% slower than baseline
                    logger.warning(
                        "Performance regression: %s took %.3fs (baseline: %.3fs)",
                        name, duration, baseline
                    )

    def set_baseline(self, name: str, duration: Optional[float] = None):
        """
        Set performance baseline for regression detection

        Args:
            name: Metric name
            duration: Baseline duration (uses current avg if not provided)
        """
        with self._lock:
            if duration is None:
                if name in self._metrics:
                    duration = self._metrics[name].avg_time
                else:
                    logger.warning("No metrics found for %s", name)
                    return

            self._baselines[name] = duration
            logger.info("Baseline set for %s: %.3fs", name, duration)

    def get_metrics(self, name: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Get performance metrics

        Args:
            name: Specific metric name (or all if None)

        Returns:
            Metrics dictionary
        """
        with self._lock:
            if name:
                metric = self._metrics.get(name)
                if not metric:
                    return None

                return {
                    'name': metric.name,
                    'call_count': metric.call_count,
                    'avg_time': round(metric.avg_time, 4),
                    'min_time': round(metric.min_time, 4),
                    'max_time': round(metric.max_time, 4),
                    'p50_time': round(metric.p50_time, 4),
                    'p95_time': round(metric.p95_time, 4),
                    'p99_time': round(metric.p99_time, 4),
                    'errors': metric.errors,
                    'last_called': metric.last_called
                }
            else:
                return {
                    name: {
                        'call_count': m.call_count,
                        'avg_time': round(m.avg_time, 4),
                        'p95_time': round(m.p95_time, 4),
                        'errors': m.errors
                    }
                    for name, m in self._metrics.items()
                }

    def get_slow_operations(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get slowest operations by average time"""
        with self._lock:
            sorted_metrics = sorted(
                self._metrics.values(),
                key=lambda m: m.avg_time,
                reverse=True
            )

            return [
                {
                    'name': m.name,
                    'avg_time': round(m.avg_time, 4),
                    'call_count': m.call_count,
                    'p95_time': round(m.p95_time, 4),
                    'max_time': round(m.max_time, 4)
                }
                for m in sorted_metrics[:limit]
            ]

    def get_bottlenecks(self) -> List[Dict[str, Any]]:
        """Identify performance bottlenecks"""
        with self._lock:
            bottlenecks = []

            for name, metric in self._metrics.items():
                # High average time
                if metric.avg_time > self.slow_threshold:
                    bottlenecks.append({
                        'name': name,
                        'type': 'high_latency',
                        'avg_time': round(metric.avg_time, 4),
                        'severity': 'high' if metric.avg_time > self.slow_threshold * 2 else 'medium'
                    })

                # High variance (p99 >> p50)
                if metric.call_count > 10 and metric.p99_time > metric.p50_time * 3:
                    bottlenecks.append({
                        'name': name,
                        'type': 'high_variance',
                        'p50': round(metric.p50_time, 4),
                        'p99': round(metric.p99_time, 4),
                        'severity': 'medium'
                    })

                # High error rate
                if metric.call_count > 0:
                    error_rate = metric.errors / metric.call_count
                    if error_rate > 0.05:  # 5% error rate
                        bottlenecks.append({
                            'name': name,
                            'type': 'high_error_rate',
                            'error_rate': round(error_rate * 100, 2),
                            'severity': 'high'
                        })

            return bottlenecks

    def get_resource_stats(self) -> Dict[str, Any]:
        """Get current resource statistics"""
        with self._lock:
            if not self._resource_history:
                return {}

            recent = list(self._resource_history)[-100:]  # Last 100 samples

            return {
                'current': {
                    'cpu_percent': recent[-1].cpu_percent,
                    'memory_percent': recent[-1].memory_percent,
                    'memory_mb': round(recent[-1].memory_mb, 2),
                    'thread_count': recent[-1].thread_count
                },
                'avg': {
                    'cpu_percent': round(sum(s.cpu_percent for s in recent) / len(recent), 2),
                    'memory_mb': round(sum(s.memory_mb for s in recent) / len(recent), 2)
                },
                'max': {
                    'cpu_percent': max(s.cpu_percent for s in recent),
                    'memory_mb': round(max(s.memory_mb for s in recent), 2)
                }
            }

    def export_report(self, output_file: str):
        """Export performance report"""
        import json

        with self._lock:
            report = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'metrics': self.get_metrics(),
                'slow_operations': self.get_slow_operations(),
                'bottlenecks': self.get_bottlenecks(),
                'resource_stats': self.get_resource_stats()
            }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        logger.info("Performance report exported to %s", output_file)

    def reset(self):
        """Reset all metrics"""
        with self._lock:
            self._metrics.clear()
            self._baselines.clear()

        logger.info("Performance metrics reset")


# Global profiler instance
_profiler: Optional[PerformanceProfiler] = None


def get_performance_profiler() -> PerformanceProfiler:
    """Get or create global performance profiler"""
    global _profiler

    if _profiler is None:
        _profiler = PerformanceProfiler()

    return _profiler


# Convenience decorators
def profile(func: Optional[Callable] = None, *, name: Optional[str] = None):
    """Convenience decorator using global profiler"""
    profiler = get_performance_profiler()
    return profiler.profile_function(func, name=name)


__all__ = [
    'PerformanceProfiler',
    'PerformanceMetrics',
    'ResourceSnapshot',
    'get_performance_profiler',
    'profile'
]
