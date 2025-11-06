#!/usr/bin/env python3
"""
Unified Performance Management System for BLNCS
統一されたパフォーマンス管理システム

Consolidates functionality from:
- high_performance_engine.py
- performance_optimizer.py
- performance_optimizations.py
- ultra_performance_optimizer.py
- ultra_performance_system.py
"""

import os
import sys
import time
import psutil
import asyncio
import threading
from collections import defaultdict, deque
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Callable, Union
import logging
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import weakref
import gc
import tracemalloc
from collections import Counter

try:
    import GPUtil
    HAS_GPU = True
except ImportError:
    GPUtil = None
    HAS_GPU = False

@dataclass
class PerformanceMetrics:
    """Unified performance metrics collection"""
    operation_name: str = ""
    start_time: float = 0.0
    end_time: float = 0.0
    duration: float = 0.0
    cpu_usage_before: float = 0.0
    cpu_usage_after: float = 0.0
    memory_usage_before: float = 0.0
    memory_usage_after: float = 0.0
    io_counters_before: Optional[Any] = None
    io_counters_after: Optional[Any] = None
    gpu_usage_before: Optional[List[float]] = None
    gpu_usage_after: Optional[List[float]] = None
    custom_metrics: Dict[str, Any] = field(default_factory=dict)

    @property
    def cpu_delta(self) -> float:
        return self.cpu_usage_after - self.cpu_usage_before

    @property
    def memory_delta(self) -> float:
        return self.memory_usage_after - self.memory_usage_before

    @property
    def gpu_delta(self) -> List[float]:
        """Calculate GPU usage delta"""
        if self.gpu_usage_before and self.gpu_usage_after:
            return [
                after - before
                for before, after in zip(self.gpu_usage_before, self.gpu_usage_after)
            ]
        return []

class PerformanceProfiler:
    """Advanced performance profiler with context management"""

    def __init__(self, max_history: int = 1000):
        self.max_history = max_history
        self.metrics_history: deque = deque(maxlen=max_history)
        self.active_operations: Dict[str, PerformanceMetrics] = {}
        self.operation_stats: Dict[str, List[float]] = defaultdict(list)
        self.lock = threading.Lock()
        self.enabled = True

    def start_operation(self, operation_name: str) -> PerformanceMetrics:
        """Start profiling an operation"""
        if not self.enabled:
            return PerformanceMetrics(operation_name=operation_name)

        metrics = PerformanceMetrics(operation_name=operation_name)
        metrics.start_time = time.time()
        metrics.cpu_usage_before = psutil.cpu_percent()
        metrics.memory_usage_before = psutil.virtual_memory().percent

        # Collect GPU usage if available
        if HAS_GPU and GPUtil:
            try:
                gpus = GPUtil.getGPUs()
                metrics.gpu_usage_before = [gpu.load * 100 for gpu in gpus]
            except Exception:
                metrics.gpu_usage_before = []

        try:
            process = psutil.Process()
            metrics.io_counters_before = process.io_counters()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        with self.lock:
            self.active_operations[operation_name] = metrics

        return metrics

    def end_operation(self, operation_name: str) -> Optional[PerformanceMetrics]:
        """End profiling an operation"""
        if not self.enabled:
            return None

        with self.lock:
            if operation_name not in self.active_operations:
                return None

            metrics = self.active_operations.pop(operation_name)

        metrics.end_time = time.time()
        metrics.duration = metrics.end_time - metrics.start_time
        metrics.cpu_usage_after = psutil.cpu_percent()
        metrics.memory_usage_after = psutil.virtual_memory().percent

        # Collect GPU usage if available
        if HAS_GPU and GPUtil:
            try:
                gpus = GPUtil.getGPUs()
                metrics.gpu_usage_after = [gpu.load * 100 for gpu in gpus]
            except Exception:
                metrics.gpu_usage_after = []

        try:
            process = psutil.Process()
            metrics.io_counters_after = process.io_counters()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        # Store in history
        self.metrics_history.append(metrics)
        self.operation_stats[operation_name].append(metrics.duration)

        # Keep operation stats reasonable in size
        if len(self.operation_stats[operation_name]) > 100:
            self.operation_stats[operation_name] = self.operation_stats[operation_name][-50:]

        return metrics

    @contextmanager
    def profile_operation(self, operation_name: str):
        """Context manager for profiling operations"""
        metrics = self.start_operation(operation_name)
        try:
            yield metrics
        finally:
            self.end_operation(operation_name)

    def get_operation_stats(self, operation_name: str) -> Dict[str, float]:
        """Get statistics for a specific operation"""
        durations = self.operation_stats.get(operation_name, [])
        if not durations:
            return {}

        return {
            'count': len(durations),
            'total_time': sum(durations),
            'avg_time': sum(durations) / len(durations),
            'min_time': min(durations),
            'max_time': max(durations),
            'latest_time': durations[-1] if durations else 0
        }

    def get_all_stats(self) -> Dict[str, Dict[str, float]]:
        """Get statistics for all operations"""
        return {op: self.get_operation_stats(op) for op in self.operation_stats.keys()}

class CacheOptimizer:
    """Advanced cache optimization"""

    def __init__(self):
        self.cache_stats = defaultdict(lambda: {'hits': 0, 'misses': 0, 'size': 0})
        self.cache_references = weakref.WeakSet()

    def register_cache(self, cache_instance: Any):
        """Register a cache instance for optimization"""
        self.cache_references.add(cache_instance)

    def optimize_caches(self) -> Dict[str, Any]:
        """Optimize all registered caches"""
        results = {}

        for cache in list(self.cache_references):
            try:
                cache_name = getattr(cache, 'name', str(type(cache).__name__))

                # Get cache statistics
                if hasattr(cache, 'size'):
                    size = cache.size()
                elif hasattr(cache, '__len__'):
                    size = len(cache)
                else:
                    size = 'unknown'

                # Basic optimization
                if hasattr(cache, 'clear'):
                    # Clear cache if it's getting too large
                    if isinstance(size, int) and size > 10000:
                        cache.clear()
                        results[cache_name] = 'cleared_oversized'
                    else:
                        results[cache_name] = f'size_{size}'

            except Exception as e:
                logger.warning(f"Failed to optimize cache: {e}")

        return results

class DatabaseOptimizer:
    """Database performance optimization"""

    def __init__(self):
        self.query_stats = defaultdict(lambda: {'count': 0, 'total_time': 0, 'avg_time': 0})

    def track_query(self, query: str, duration: float):
        """Track query performance"""
        # Simple query normalization
        normalized_query = query.strip().split()[0].upper() if query.strip() else 'UNKNOWN'

        stats = self.query_stats[normalized_query]
        stats['count'] += 1
        stats['total_time'] += duration
        stats['avg_time'] = stats['total_time'] / stats['count']

    def get_slow_queries(self, threshold: float = 1.0) -> Dict[str, Dict]:
        """Get queries slower than threshold"""
        return {
            query: stats for query, stats in self.query_stats.items()
            if stats['avg_time'] > threshold
        }

    def optimize_recommendations(self) -> List[str]:
        """Get optimization recommendations"""
        recommendations = []

        slow_queries = self.get_slow_queries()
        if slow_queries:
            recommendations.append(f"Consider optimizing {len(slow_queries)} slow query types")

        total_queries = sum(stats['count'] for stats in self.query_stats.values())
        if total_queries > 10000:
            recommendations.append("High query volume detected, consider connection pooling")

        return recommendations

class UnifiedPerformanceOptimizer:
    """
    Main performance optimization system that unifies all performance-related functionality
    """

    def __init__(
        self,
        enable_profiling: bool = True,
        max_history: int = 1000,
        optimization_interval: int = 300  # 5 minutes
    ):
        self.enabled = enable_profiling
        self.profiler = PerformanceProfiler(max_history)
        self.cache_optimizer = CacheOptimizer()
        self.database_optimizer = DatabaseOptimizer()

        self.optimization_interval = optimization_interval
        self.last_optimization = 0
        self.shutdown_event = threading.Event()
        self.async_monitoring_task: Optional[asyncio.Task] = None
        self.async_enabled = False

        # Memory leak detection
        self.memory_traces_enabled = False
        self.memory_snapshots: deque = deque(maxlen=10)  # Keep last 10 snapshots
        self.leak_threshold_mb = 100  # Alert if memory growth exceeds this

        # Network I/O optimization
        self.network_monitoring_enabled = False
        self.network_stats_history: deque = deque(maxlen=100)
        self.connection_pool_stats: Dict[str, Any] = {}

        # System metrics
        self.system_metrics = {
            'cpu_count': psutil.cpu_count(),
            'memory_total': psutil.virtual_memory().total,
            'disk_usage': {},
            'network_stats': {}
        }

        self._update_system_metrics()

        # Start background optimization if enabled
        if self.enabled:
            self.start_background_optimization()

    def _update_system_metrics(self):
        """Update system-level metrics"""
        try:
            # Disk usage
            for disk in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(disk.mountpoint)
                    self.system_metrics['disk_usage'][disk.device] = {
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': usage.used / usage.total * 100
                    }
                except (PermissionError, FileNotFoundError):
                    pass

            # Network stats
            net_stats = psutil.net_io_counters()
            if net_stats:
                self.system_metrics['network_stats'] = {
                    'bytes_sent': net_stats.bytes_sent,
                    'bytes_recv': net_stats.bytes_recv,
                    'packets_sent': net_stats.packets_sent,
                    'packets_recv': net_stats.packets_recv
                }

        except Exception as e:
            logger.warning(f"Failed to update system metrics: {e}")

    @contextmanager
    def profile(self, operation_name: str):
        """Profile an operation"""
        with self.profiler.profile_operation(operation_name) as metrics:
            yield metrics

    def track_database_query(self, query: str, duration: float):
        """Track database query performance"""
        self.database_optimizer.track_query(query, duration)

    def register_cache(self, cache_instance: Any):
        """Register a cache for optimization"""
        self.cache_optimizer.register_cache(cache_instance)

    def optimize_system(self) -> Dict[str, Any]:
        """Run comprehensive system optimization"""
        if not self.enabled:
            return {'status': 'disabled'}

        results = {
            'timestamp': time.time(),
            'cache_optimization': {},
            'database_recommendations': [],
            'system_health': {},
            'performance_summary': {}
        }

        # Cache optimization
        try:
            results['cache_optimization'] = self.cache_optimizer.optimize_caches()
        except Exception as e:
            logger.error(f"Cache optimization failed: {e}")
            results['cache_optimization'] = {'error': str(e)}

        # Database recommendations
        try:
            results['database_recommendations'] = self.database_optimizer.optimize_recommendations()
        except Exception as e:
            logger.error(f"Database optimization failed: {e}")
            results['database_recommendations'] = [f"Error: {e}"]

        # System health
        try:
            results['system_health'] = self.get_system_health()
        except Exception as e:
            logger.error(f"System health check failed: {e}")
            results['system_health'] = {'error': str(e)}

        # Performance summary
        try:
            results['performance_summary'] = self.profiler.get_all_stats()
        except Exception as e:
            logger.error(f"Performance summary failed: {e}")
            results['performance_summary'] = {'error': str(e)}

        self.last_optimization = time.time()
        return results

    def get_system_health(self) -> Dict[str, Any]:
        """Get current system health metrics"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk_usage = psutil.disk_usage('/')

            health_data = {
                'cpu_percent': cpu_percent,
                'cpu_healthy': cpu_percent < 80,
                'memory_percent': memory.percent,
                'memory_healthy': memory.percent < 85,
                'memory_available_gb': memory.available / (1024**3),
                'disk_percent': disk_usage.percent,
                'disk_healthy': disk_usage.percent < 90,
                'disk_free_gb': disk_usage.free / (1024**3),
                'load_average': os.getloadavg() if hasattr(os, 'getloadavg') else None,
                'uptime_seconds': time.time() - psutil.boot_time()
            }

            # Add GPU health if available
            if HAS_GPU and GPUtil:
                try:
                    gpus = GPUtil.getGPUs()
                    gpu_health = []
                    for i, gpu in enumerate(gpus):
                        gpu_data = {
                            'id': i,
                            'name': gpu.name,
                            'usage': gpu.load * 100,
                            'memory_used': gpu.memoryUsed,
                            'memory_total': gpu.memoryTotal,
                            'temperature': gpu.temperature,
                            'healthy': gpu.load < 90  # GPU usage below 90%
                        }
                        gpu_health.append(gpu_data)

                    health_data['gpu_health'] = gpu_health
                    health_data['gpu_available'] = True
                except Exception as e:
                    health_data['gpu_health'] = []
                    health_data['gpu_available'] = False
                    health_data['gpu_error'] = str(e)
            else:
                health_data['gpu_available'] = False

            return health_data
        except Exception as e:
            logger.error(f"Failed to get system health: {e}")
            return {'error': str(e)}

    def get_performance_report(self) -> Dict[str, Any]:
        """Get comprehensive performance report"""
        return {
            'timestamp': time.time(),
            'enabled': self.enabled,
            'profiler_stats': self.profiler.get_all_stats(),
            'system_health': self.get_system_health(),
            'system_metrics': self.system_metrics,
            'database_stats': dict(self.database_optimizer.query_stats),
            'cache_stats': dict(self.cache_optimizer.cache_stats),
            'last_optimization': self.last_optimization,
            'metrics_history_size': len(self.profiler.metrics_history)
        }

    def start_async_monitoring(self, interval: float = 1.0):
        """Start asynchronous performance monitoring"""
        if self.async_enabled:
            return

        self.async_enabled = True
        try:
            # Create event loop if not exists
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            self.async_monitoring_task = asyncio.create_task(
                self._async_monitoring_loop(interval)
            )
            logger.info("Started asynchronous performance monitoring")
        except Exception as e:
            logger.error(f"Failed to start async monitoring: {e}")
            self.async_enabled = False

    def stop_async_monitoring(self):
        """Stop asynchronous performance monitoring"""
        if not self.async_enabled:
            return

        self.async_enabled = False
        if self.async_monitoring_task:
            self.async_monitoring_task.cancel()
            try:
                # Wait for task to complete
                if asyncio.iscoroutinefunction(asyncio.wait_for):
                    asyncio.wait_for(self.async_monitoring_task, timeout=5.0)
                else:
                    # Handle case where wait_for might not be available
                    pass
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass
        logger.info("Stopped asynchronous performance monitoring")

    async def _async_monitoring_loop(self, interval: float):
        """Asynchronous monitoring loop"""
        while self.async_enabled:
            try:
                # Collect real-time metrics
                await self._collect_async_metrics()

                # Run lightweight optimizations
                await self._run_async_optimizations()

                # Wait for next interval
                await asyncio.sleep(interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Async monitoring error: {e}")
                await asyncio.sleep(interval)

    async def _collect_async_metrics(self):
        """Collect metrics asynchronously"""
        try:
            # CPU and memory metrics
            cpu_percent = await asyncio.get_event_loop().run_in_executor(
                None, psutil.cpu_percent, 0.1
            )
            memory = await asyncio.get_event_loop().run_in_executor(
                None, psutil.virtual_memory
            )

            # GPU metrics if available
            gpu_usage = []
            if HAS_GPU and GPUtil:
                try:
                    gpus = await asyncio.get_event_loop().run_in_executor(
                        None, GPUtil.getGPUs
                    )
                    gpu_usage = [gpu.load * 100 for gpu in gpus]
                except Exception:
                    gpu_usage = []

            # Update system health
            self.system_metrics.update({
                'cpu_percent_async': cpu_percent,
                'memory_percent_async': memory.percent,
                'memory_available_async': memory.available,
                'gpu_usage_async': gpu_usage,
                'last_async_update': time.time()
            })

        except Exception as e:
            logger.warning(f"Failed to collect async metrics: {e}")

    async def _run_async_optimizations(self):
        """Run lightweight asynchronous optimizations"""
        try:
            # Memory optimization check
            memory = psutil.virtual_memory()
            if memory.percent > 90:
                # Trigger garbage collection
                await asyncio.get_event_loop().run_in_executor(None, gc.collect)

            # Memory leak detection snapshot
            if self.memory_traces_enabled:
                await asyncio.get_event_loop().run_in_executor(None, self.take_memory_snapshot)

            # Network stats collection
            if self.network_monitoring_enabled:
                await asyncio.get_event_loop().run_in_executor(None, self._collect_network_stats)

            # Check for optimization triggers
            current_time = time.time()
            if current_time - self.last_optimization > self.optimization_interval:
                await asyncio.get_event_loop().run_in_executor(None, self.optimize_system)

        except Exception as e:
            logger.warning(f"Failed to run async optimizations: {e}")

    def start_background_optimization(self):
        """Start background optimization thread"""
        if hasattr(self, '_background_thread') and self._background_thread and self._background_thread.is_alive():
            return

        self._background_thread = threading.Thread(target=self._background_optimization_loop, daemon=True)
        self._background_thread.start()
        logger.info("Started background performance optimization")

    def _background_optimization_loop(self):
        """Background optimization loop"""
        while not self.shutdown_event.is_set():
            try:
                current_time = time.time()
                if current_time - self.last_optimization > self.optimization_interval:
                    self.optimize_system()
                time.sleep(60)  # Check every minute
            except Exception as e:
                logger.error(f"Background optimization error: {e}")
                time.sleep(60)

    def enable(self):
        """Enable performance optimization"""
        self.enabled = True
        self.profiler.enabled = True
        self.start_background_optimization()
        self.start_async_monitoring()
        self.start_memory_tracing()
        self.start_network_monitoring()

    def disable(self):
        """Disable performance optimization"""
        self.enabled = False
        self.profiler.enabled = False
        self.stop_background_optimization()
        self.stop_async_monitoring()
        self.stop_memory_tracing()
        self.stop_network_monitoring()

    def start_network_monitoring(self):
        """Start network I/O monitoring"""
        if self.network_monitoring_enabled:
            return

        self.network_monitoring_enabled = True
        # Take initial network stats
        self._collect_network_stats()
        logger.info("Started network I/O monitoring")

    def stop_network_monitoring(self):
        """Stop network I/O monitoring"""
        self.network_monitoring_enabled = False
        self.network_stats_history.clear()
        logger.info("Stopped network I/O monitoring")

    def _collect_network_stats(self):
        """Collect current network statistics"""
        if not self.network_monitoring_enabled:
            return

        try:
            net_stats = psutil.net_io_counters()
            if net_stats:
                stats = {
                    'timestamp': time.time(),
                    'bytes_sent': net_stats.bytes_sent,
                    'bytes_recv': net_stats.bytes_recv,
                    'packets_sent': net_stats.packets_sent,
                    'packets_recv': net_stats.packets_recv,
                    'errin': getattr(net_stats, 'errin', 0),
                    'errout': getattr(net_stats, 'errout', 0),
                    'dropin': getattr(net_stats, 'dropin', 0),
                    'dropout': getattr(net_stats, 'dropout', 0)
                }

                self.network_stats_history.append(stats)
                self.system_metrics['network_stats'] = stats

        except Exception as e:
            logger.warning(f"Failed to collect network stats: {e}")

    def get_network_performance_report(self) -> Dict[str, Any]:
        """Get network performance analysis"""
        if not self.network_monitoring_enabled or len(self.network_stats_history) < 2:
            return {'error': 'Network monitoring not enabled or insufficient data'}

        try:
            # Calculate rates and trends
            recent_stats = list(self.network_stats_history)[-10:]  # Last 10 measurements

            if len(recent_stats) < 2:
                return {'error': 'Need more data points for analysis'}

            # Calculate throughput rates
            time_diff = recent_stats[-1]['timestamp'] - recent_stats[0]['timestamp']
            if time_diff > 0:
                bytes_sent_rate = (recent_stats[-1]['bytes_sent'] - recent_stats[0]['bytes_sent']) / time_diff
                bytes_recv_rate = (recent_stats[-1]['bytes_recv'] - recent_stats[0]['bytes_recv']) / time_diff
                packets_sent_rate = (recent_stats[-1]['packets_sent'] - recent_stats[0]['packets_sent']) / time_diff
                packets_recv_rate = (recent_stats[-1]['packets_recv'] - recent_stats[0]['packets_recv']) / time_diff
            else:
                bytes_sent_rate = bytes_recv_rate = packets_sent_rate = packets_recv_rate = 0

            # Error rates
            total_packets = sum(stat['packets_sent'] + stat['packets_recv'] for stat in recent_stats)
            total_errors = sum(stat['errin'] + stat['errout'] for stat in recent_stats)
            error_rate = (total_errors / total_packets * 100) if total_packets > 0 else 0

            # Network health assessment
            health_score = 100
            issues = []

            if error_rate > 1:
                health_score -= 20
                issues.append(f"High error rate: {error_rate:.2f}%")

            if bytes_recv_rate < 1000:  # Less than 1KB/s
                health_score -= 10
                issues.append("Low network utilization")

            # Detect network congestion
            if len(recent_stats) >= 5:
                recent_drops = sum(stat['dropin'] + stat['dropout'] for stat in recent_stats[-5:])
                if recent_drops > 10:
                    health_score -= 15
                    issues.append("Network packet drops detected")

            return {
                'health_score': max(0, health_score),
                'throughput_mbps': {
                    'send': bytes_sent_rate * 8 / (1024 * 1024),
                    'receive': bytes_recv_rate * 8 / (1024 * 1024)
                },
                'packet_rate_pps': {
                    'send': packets_sent_rate,
                    'receive': packets_recv_rate
                },
                'error_rate_percent': error_rate,
                'issues': issues,
                'recommendations': self._get_network_recommendations(issues),
                'sample_count': len(self.network_stats_history)
            }

        except Exception as e:
            logger.error(f"Failed to generate network report: {e}")
            return {'error': str(e)}

    def _get_network_recommendations(self, issues: List[str]) -> List[str]:
        """Generate network optimization recommendations"""
        recommendations = []

        if any("error rate" in issue.lower() for issue in issues):
            recommendations.append("Consider checking network cable quality and connections")
            recommendations.append("Review network interface settings and MTU configuration")

        if any("utilization" in issue.lower() for issue in issues):
            recommendations.append("Network bandwidth may be underutilized - consider connection pooling")

        if any("drops" in issue.lower() for issue in issues):
            recommendations.append("Packet drops detected - check for network congestion or buffer issues")
            recommendations.append("Consider increasing socket buffer sizes")

        if not recommendations:
            recommendations.append("Network performance appears healthy")

        return recommendations

    def register_connection_pool(self, pool_name: str, pool_instance: Any):
        """Register a connection pool for monitoring"""
        try:
            self.connection_pool_stats[pool_name] = {
                'instance': weakref.ref(pool_instance),
                'connections_created': 0,
                'connections_active': 0,
                'connections_idle': 0,
                'last_updated': time.time()
            }
            logger.info(f"Registered connection pool: {pool_name}")
        except Exception as e:
            logger.warning(f"Failed to register connection pool {pool_name}: {e}")

    def update_connection_pool_stats(self, pool_name: str, stats: Dict[str, Any]):
        """Update connection pool statistics"""
        if pool_name in self.connection_pool_stats:
            self.connection_pool_stats[pool_name].update({
                **stats,
                'last_updated': time.time()
            })

    def get_connection_pool_report(self) -> Dict[str, Any]:
        """Get connection pool utilization report"""
        report = {}

        for pool_name, pool_data in self.connection_pool_stats.items():
            try:
                pool_ref = pool_data.get('instance')
                if pool_ref and pool_ref():
                    # Pool still exists
                    stats = {k: v for k, v in pool_data.items() if k != 'instance'}
                    report[pool_name] = stats
                else:
                    # Pool was garbage collected
                    report[pool_name] = {'status': 'garbage_collected'}
            except Exception as e:
                report[pool_name] = {'error': str(e)}

        return report

    def start_memory_tracing(self):
        """Start memory leak detection"""
        if self.memory_traces_enabled:
            return

        try:
            tracemalloc.start()
            self.memory_traces_enabled = True
            # Take initial snapshot
            self.memory_snapshots.append(tracemalloc.take_snapshot())
            logger.info("Started memory leak detection")
        except Exception as e:
            logger.error(f"Failed to start memory tracing: {e}")

    def stop_memory_tracing(self):
        """Stop memory leak detection"""
        if not self.memory_traces_enabled:
            return

        try:
            tracemalloc.stop()
            self.memory_traces_enabled = False
            self.memory_snapshots.clear()
            logger.info("Stopped memory leak detection")
        except Exception as e:
            logger.error(f"Failed to stop memory tracing: {e}")

    def take_memory_snapshot(self) -> Optional[Any]:
        """Take a memory snapshot for leak detection"""
        if not self.memory_traces_enabled:
            return None

        try:
            snapshot = tracemalloc.take_snapshot()
            self.memory_snapshots.append(snapshot)
            return snapshot
        except Exception as e:
            logger.error(f"Failed to take memory snapshot: {e}")
            return None

    def detect_memory_leaks(self) -> Dict[str, Any]:
        """Detect potential memory leaks"""
        if not self.memory_traces_enabled or len(self.memory_snapshots) < 2:
            return {'error': 'Memory tracing not enabled or insufficient snapshots'}

        try:
            # Compare latest snapshot with oldest
            oldest = self.memory_snapshots[0]
            latest = self.memory_snapshots[-1]

            # Get statistics
            stats = latest.compare_to(oldest, 'lineno')

            # Filter significant growth
            significant_growth = []
            total_growth = 0

            for stat in stats:
                if stat.size_diff > 1024 * 1024:  # More than 1MB growth
                    significant_growth.append({
                        'file': stat.traceback[0].filename,
                        'line': stat.traceback[0].lineno,
                        'size_diff': stat.size_diff,
                        'size_diff_mb': stat.size_diff / (1024 * 1024),
                        'count_diff': stat.count_diff
                    })
                    total_growth += stat.size_diff

            leak_detected = total_growth > (self.leak_threshold_mb * 1024 * 1024)

            return {
                'leak_detected': leak_detected,
                'total_growth_mb': total_growth / (1024 * 1024),
                'significant_growth': significant_growth,
                'snapshot_count': len(self.memory_snapshots),
                'threshold_mb': self.leak_threshold_mb
            }

        except Exception as e:
            logger.error(f"Failed to detect memory leaks: {e}")
            return {'error': str(e)}

    def get_memory_usage_report(self) -> Dict[str, Any]:
        """Get detailed memory usage report"""
        if not self.memory_traces_enabled:
            return {'error': 'Memory tracing not enabled'}

        try:
            # Get current memory usage
            current = tracemalloc.get_traced_memory()
            peak = tracemalloc.get_peak_traced_memory()

            # Get top memory consumers
            snapshot = tracemalloc.take_snapshot()
            top_stats = snapshot.statistics('lineno')[:10]

            top_consumers = []
            for stat in top_stats:
                top_consumers.append({
                    'file': stat.traceback[0].filename,
                    'line': stat.traceback[0].lineno,
                    'size': stat.size,
                    'size_mb': stat.size / (1024 * 1024),
                    'count': stat.count
                })

            return {
                'current_memory_mb': current[0] / (1024 * 1024),
                'peak_memory_mb': peak[0] / (1024 * 1024),
                'top_consumers': top_consumers,
                'snapshot_count': len(self.memory_snapshots)
            }

        except Exception as e:
            logger.error(f"Failed to get memory usage report: {e}")
            return {'error': str(e)}

    def clear_history(self):
        """Clear all performance history"""
        self.profiler.metrics_history.clear()
        self.profiler.operation_stats.clear()
        self.profiler.active_operations.clear()
        self.database_optimizer.query_stats.clear()
        self.cache_optimizer.cache_stats.clear()


def get_performance_monitor() -> PerformanceMonitor:
    """Get global performance monitor instance"""
    global _performance_monitor
    if _performance_monitor is None:
        _performance_monitor = PerformanceMonitor()
    return _performance_monitor

def get_performance_optimizer() -> UnifiedPerformanceOptimizer:
    """Get or create global performance optimizer"""
    global _performance_optimizer
    if _performance_optimizer is None:
        enable_profiling = os.getenv('BLNCS_PERFORMANCE_PROFILING', 'true').lower() in ['true', '1', 'yes']
        _performance_optimizer = UnifiedPerformanceOptimizer(enable_profiling=enable_profiling)
    return _performance_optimizer

def profile_operation(operation_name: str):
    """Decorator for profiling operations"""
    def decorator(func: Callable):
        def wrapper(*args, **kwargs):
            optimizer = get_performance_optimizer()
            with optimizer.profile(operation_name):
                return func(*args, **kwargs)
        return wrapper
    return decorator

@contextmanager
def performance_monitor(operation_name: str):
    """Context manager for performance monitoring"""
    optimizer = get_performance_optimizer()
    with optimizer.profile(operation_name) as metrics:
        yield metrics

def track_database_query(query: str, duration: float):
    """Track database query performance"""
    optimizer = get_performance_optimizer()
    optimizer.track_database_query(query, duration)

def register_cache(cache_instance: Any):
    """Register cache instance for optimization"""
    optimizer = get_performance_optimizer()
    optimizer.register_cache(cache_instance)

def optimize_system() -> Dict[str, Any]:
    """Run system optimization"""
    optimizer = get_performance_optimizer()
    return optimizer.optimize_system()

def get_performance_report() -> Dict[str, Any]:
    """Get performance report"""
    optimizer = get_performance_optimizer()
    return optimizer.get_performance_report()

def get_system_health() -> Dict[str, Any]:
    """Get system health status"""
    optimizer = get_performance_optimizer()
    return optimizer.get_system_health()

# Cleanup on shutdown
import atexit
def _cleanup_performance_optimizer():
    global _performance_optimizer
    if _performance_optimizer:

def stop_network_monitoring():
    """Stop network monitoring"""
    optimizer = get_performance_optimizer()
    optimizer.stop_network_monitoring()

def get_network_performance_report() -> Dict[str, Any]:
    """Get network performance report"""
    optimizer = get_performance_optimizer()
    return optimizer.get_network_performance_report()

def register_connection_pool(pool_name: str, pool_instance: Any):
    """Register connection pool for monitoring"""
    optimizer = get_performance_optimizer()
    optimizer.register_connection_pool(pool_name, pool_instance)

def update_connection_pool_stats(pool_name: str, stats: Dict[str, Any]):
    """Update connection pool statistics"""
    optimizer = get_performance_optimizer()
    optimizer.update_connection_pool_stats(pool_name, stats)

def get_connection_pool_report() -> Dict[str, Any]:
    """Get connection pool report"""
    optimizer = get_performance_optimizer()
    return optimizer.get_connection_pool_report()

def start_memory_tracing():
    """Start memory leak detection"""
    optimizer = get_performance_optimizer()
    optimizer.start_memory_tracing()

def stop_memory_tracing():
    """Stop memory leak detection"""
    optimizer = get_performance_optimizer()
    optimizer.stop_memory_tracing()

def detect_memory_leaks() -> Dict[str, Any]:
    """Detect memory leaks"""
    optimizer = get_performance_optimizer()
    return optimizer.detect_memory_leaks()

def get_memory_usage_report() -> Dict[str, Any]:
    """Get memory usage report"""
    optimizer = get_performance_optimizer()
    return optimizer.get_memory_usage_report()


__all__ = [
    'UnifiedPerformanceOptimizer',
    'PerformanceMetrics',
    'PerformanceProfiler',
    'CacheOptimizer',
    'DatabaseOptimizer',
    'PerformanceMonitor',
    'get_performance_optimizer',
    'get_performance_monitor',
    'profile_operation',
    'performance_monitor',
    'track_database_query',
    'register_cache',
    'optimize_system',
    'get_performance_report',
    'get_system_health',
    'start_network_monitoring',
    'stop_network_monitoring',
    'get_network_performance_report',
    'register_connection_pool',
    'update_connection_pool_stats',
    'get_connection_pool_report',
    'start_memory_tracing',
    'stop_memory_tracing',
    'detect_memory_leaks',
    'get_memory_usage_report'
]


class PerformanceMonitor:
    """Simple performance monitoring class"""

    def __init__(self):
        self.metrics = defaultdict(list)
        self.monitoring_active = False

    def start(self):
        """Start monitoring"""
        self.monitoring_active = True

    def stop(self):
        """Stop monitoring"""
        self.monitoring_active = False

    def collect_metric(self, name: str, value: Any):
        """Collect a metric"""
        if self.monitoring_active:
            self.metrics[name].append((time.time(), value))
            # Keep only last 1000 metrics
            if len(self.metrics[name]) > 1000:
                self.metrics[name] = self.metrics[name][-1000:]


# Global instances
_performance_optimizer: Optional[UnifiedPerformanceOptimizer] = None
_performance_monitor: Optional[PerformanceMonitor] = None

# Cleanup on shutdown
import atexit
def _cleanup_performance_optimizer():
    global _performance_optimizer
    if _performance_optimizer:
        _performance_optimizer.stop_background_optimization()

atexit.register(_cleanup_performance_optimizer)