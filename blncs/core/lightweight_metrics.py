#!/usr/bin/env python3
"""
Lightweight Performance Metrics Collector for BLNCS
Real-time system and application performance monitoring
"""

import time
import threading
import psutil
from typing import Dict, List, Any, Optional, Callable
from collections import defaultdict, deque
from datetime import datetime, timedelta
import json
import os
from pathlib import Path

try:
    import resource
    HAS_RESOURCE = True
except ImportError:
    HAS_RESOURCE = False

try:
    import gc
    HAS_GC = True
except ImportError:
    HAS_GC = False


class RealtimeMetricsCollector:
    """
    Lightweight real-time metrics collector with minimal overhead
    """

    def __init__(self, collection_interval: float = 5.0, retention_period: int = 3600):
        """
        Initialize metrics collector

        Args:
            collection_interval: How often to collect metrics (seconds)
            retention_period: How long to keep historical data (seconds)
        """
        self.collection_interval = collection_interval
        self.retention_period = retention_period
        self._running = False
        self._thread = None
        self._lock = threading.RLock()

        # Metrics storage
        self.system_metrics = deque(maxlen=int(retention_period / collection_interval))
        self.api_metrics = defaultdict(lambda: deque(maxlen=1000))
        self.database_metrics = defaultdict(lambda: deque(maxlen=1000))
        self.cache_metrics = deque(maxlen=int(retention_period / collection_interval))

        # Performance counters
        self.api_requests_total = 0
        self.api_requests_success = 0
        self.api_requests_error = 0
        self.database_queries_total = 0
        self.database_queries_success = 0
        self.database_queries_error = 0
        self.cache_hits = 0
        self.cache_misses = 0

        # Thresholds for alerting
        self.alert_thresholds = {
            'cpu_percent': 80.0,
            'memory_percent': 85.0,
            'disk_percent': 90.0,
            'api_response_time': 1.0,  # seconds
            'db_query_time': 0.1  # seconds
        }

        # Alert callbacks
        self.alert_callbacks: List[Callable] = []

        # Initialize baseline
        self._collect_system_metrics()

    def start_collection(self):
        """Start real-time metrics collection"""
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(target=self._collection_loop, daemon=True)
        self._thread.start()

    def stop_collection(self):
        """Stop real-time metrics collection"""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

    def _collection_loop(self):
        """Main collection loop"""
        while self._running:
            try:
                self._collect_system_metrics()
                self._collect_cache_metrics()
                self._check_alerts()
            except Exception as e:
                # Log error but continue collection
                print(f"Metrics collection error: {e}")

            time.sleep(self.collection_interval)

    def _collect_system_metrics(self):
        """Collect system-level metrics"""
        try:
            timestamp = time.time()

            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()
            load_avg = psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None

            # Memory metrics
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            memory_used_gb = memory.used / (1024**3)
            memory_total_gb = memory.total / (1024**3)

            # Disk metrics
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent
            disk_used_gb = disk.used / (1024**3)
            disk_total_gb = disk.total / (1024**3)

            # Network metrics
            network = psutil.net_io_counters()
            bytes_sent_mb = network.bytes_sent / (1024**2)
            bytes_recv_mb = network.bytes_recv / (1024**2)

            # Process metrics (if available)
            process_memory_mb = 0
            process_cpu_percent = 0
            if HAS_RESOURCE:
                try:
                    rusage = resource.getrusage(resource.RUSAGE_SELF)
                    process_memory_mb = rusage.ru_maxrss / 1024 if rusage.ru_maxrss > 100000 else rusage.ru_maxrss / 1024 / 1024
                except:
                    pass

            try:
                process_cpu_percent = psutil.Process().cpu_percent()
            except:
                pass

            metrics = {
                'timestamp': timestamp,
                'cpu': {
                    'percent': cpu_percent,
                    'count': cpu_count,
                    'load_avg': load_avg
                },
                'memory': {
                    'percent': memory_percent,
                    'used_gb': round(memory_used_gb, 2),
                    'total_gb': round(memory_total_gb, 2),
                    'process_mb': round(process_memory_mb, 2)
                },
                'disk': {
                    'percent': disk_percent,
                    'used_gb': round(disk_used_gb, 2),
                    'total_gb': round(disk_total_gb, 2)
                },
                'network': {
                    'bytes_sent_mb': round(bytes_sent_mb, 2),
                    'bytes_recv_mb': round(bytes_recv_mb, 2)
                },
                'process': {
                    'cpu_percent': process_cpu_percent
                }
            }

            with self._lock:
                self.system_metrics.append(metrics)

        except Exception as e:
            print(f"System metrics collection error: {e}")

    def _collect_cache_metrics(self):
        """Collect cache performance metrics"""
        try:
            from blncs.core.simple_cache import get_simple_cache

            cache = get_simple_cache()
            stats = cache.stats()

            metrics = {
                'timestamp': time.time(),
                'cache_size': stats.get('size', 0),
                'cache_max_size': stats.get('max_size', 1000),
                'cache_hit_rate': stats.get('hit_rate', 0),
                'cache_hits': getattr(self, 'cache_hits', 0),
                'cache_misses': getattr(self, 'cache_misses', 0)
            }

            with self._lock:
                self.cache_metrics.append(metrics)

        except Exception as e:
            # Cache might not be available
            pass

    def record_api_request(self, endpoint: str, method: str, response_time: float, status_code: int):
        """Record API request metrics"""
        with self._lock:
            self.api_requests_total += 1
            if 200 <= status_code < 400:
                self.api_requests_success += 1
            else:
                self.api_requests_error += 1

            metrics = {
                'timestamp': time.time(),
                'endpoint': endpoint,
                'method': method,
                'response_time': response_time,
                'status_code': status_code,
                'success': 200 <= status_code < 400
            }

            self.api_metrics[endpoint].append(metrics)

    def record_database_query(self, operation: str, table: str, query_time: float, success: bool):
        """Record database query metrics"""
        with self._lock:
            self.database_queries_total += 1
            if success:
                self.database_queries_success += 1
            else:
                self.database_queries_error += 1

            metrics = {
                'timestamp': time.time(),
                'operation': operation,
                'table': table,
                'query_time': query_time,
                'success': success
            }

            self.database_metrics[operation].append(metrics)

    def record_cache_operation(self, hit: bool):
        """Record cache operation"""
        with self._lock:
            if hit:
                self.cache_hits += 1
            else:
                self.cache_misses += 1

    def get_current_metrics(self) -> Dict[str, Any]:
        """Get current system metrics"""
        with self._lock:
            if not self.system_metrics:
                return {}

            return self.system_metrics[-1].copy()

    def get_metrics_summary(self, hours: int = 1) -> Dict[str, Any]:
        """Get metrics summary for the last N hours"""
        cutoff_time = time.time() - (hours * 3600)

        with self._lock:
            # Filter recent metrics
            recent_system = [m for m in self.system_metrics if m['timestamp'] > cutoff_time]
            recent_cache = [m for m in self.cache_metrics if m['timestamp'] > cutoff_time]

            if not recent_system:
                return {'error': 'No recent metrics available'}

            summary = {
                'time_range': {
                    'start': datetime.fromtimestamp(recent_system[0]['timestamp']).isoformat(),
                    'end': datetime.fromtimestamp(recent_system[-1]['timestamp']).isoformat(),
                    'hours': hours
                },
                'system': {
                    'cpu_avg_percent': round(sum(m['cpu']['percent'] for m in recent_system) / len(recent_system), 2),
                    'cpu_peak_percent': max(m['cpu']['percent'] for m in recent_system),
                    'memory_avg_percent': round(sum(m['memory']['percent'] for m in recent_system) / len(recent_system), 2),
                    'memory_peak_percent': max(m['memory']['percent'] for m in recent_system),
                    'disk_percent': recent_system[-1]['disk']['percent']
                },
                'performance': {
                    'api_requests_total': self.api_requests_total,
                    'api_requests_success': self.api_requests_success,
                    'api_requests_error': self.api_requests_error,
                    'api_success_rate': round((self.api_requests_success / max(self.api_requests_total, 1)) * 100, 2),
                    'db_queries_total': self.database_queries_total,
                    'db_queries_success': self.database_queries_success,
                    'db_queries_error': self.database_queries_error,
                    'db_success_rate': round((self.database_queries_success / max(self.database_queries_total, 1)) * 100, 2)
                }
            }

            # Cache metrics if available
            if recent_cache:
                summary['cache'] = {
                    'avg_hit_rate': round(sum(m.get('cache_hit_rate', 0) for m in recent_cache) / len(recent_cache), 2),
                    'current_size': recent_cache[-1].get('cache_size', 0),
                    'max_size': recent_cache[-1].get('cache_max_size', 1000)
                }

            # API response time statistics
            api_times = []
            for endpoint_metrics in self.api_metrics.values():
                api_times.extend([m['response_time'] for m in endpoint_metrics if m['timestamp'] > cutoff_time])

            if api_times:
                summary['api_performance'] = {
                    'avg_response_time': round(sum(api_times) / len(api_times), 4),
                    'min_response_time': round(min(api_times), 4),
                    'max_response_time': round(max(api_times), 4),
                    'p95_response_time': round(sorted(api_times)[int(len(api_times) * 0.95)], 4)
                }

            return summary

    def get_alerts(self) -> List[Dict[str, Any]]:
        """Get current alerts based on thresholds"""
        alerts = []
        current = self.get_current_metrics()

        if not current:
            return alerts

        # CPU alert
        if current['cpu']['percent'] > self.alert_thresholds['cpu_percent']:
            alerts.append({
                'type': 'cpu_high',
                'level': 'warning',
                'message': f"CPU usage is {current['cpu']['percent']:.1f}% (threshold: {self.alert_thresholds['cpu_percent']}%)",
                'value': current['cpu']['percent'],
                'threshold': self.alert_thresholds['cpu_percent']
            })

        # Memory alert
        if current['memory']['percent'] > self.alert_thresholds['memory_percent']:
            alerts.append({
                'type': 'memory_high',
                'level': 'warning',
                'message': f"Memory usage is {current['memory']['percent']:.1f}% (threshold: {self.alert_thresholds['memory_percent']}%)",
                'value': current['memory']['percent'],
                'threshold': self.alert_thresholds['memory_percent']
            })

        # Disk alert
        if current['disk']['percent'] > self.alert_thresholds['disk_percent']:
            alerts.append({
                'type': 'disk_high',
                'level': 'critical',
                'message': f"Disk usage is {current['disk']['percent']:.1f}% (threshold: {self.alert_thresholds['disk_percent']}%)",
                'value': current['disk']['percent'],
                'threshold': self.alert_thresholds['disk_percent']
            })

        return alerts

    def _check_alerts(self):
        """Check for alerts and trigger callbacks"""
        alerts = self.get_alerts()

        for alert in alerts:
            # Trigger callbacks
            for callback in self.alert_callbacks:
                try:
                    callback(alert)
                except Exception as e:
                    print(f"Alert callback error: {e}")

    def add_alert_callback(self, callback: Callable):
        """Add alert callback function"""
        self.alert_callbacks.append(callback)

    def export_metrics(self, file_path: str):
        """Export metrics to JSON file"""
        data = {
            'summary': self.get_metrics_summary(),
            'current': self.get_current_metrics(),
            'alerts': self.get_alerts(),
            'exported_at': datetime.now().isoformat()
        }

        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)

    def __repr__(self) -> str:
        current = self.get_current_metrics()
        if current:
            return f"RealtimeMetricsCollector(cpu={current['cpu']['percent']:.1f}%, memory={current['memory']['percent']:.1f}%)"
        return "RealtimeMetricsCollector(empty)"


# Global instance
_metrics_collector = None

def get_metrics_collector() -> RealtimeMetricsCollector:
    """Get global metrics collector instance"""
    global _metrics_collector
    if _metrics_collector is None:
        _metrics_collector = RealtimeMetricsCollector()
    return _metrics_collector

def start_system_monitoring():
    """Start system monitoring"""
    collector = get_metrics_collector()
    collector.start_collection()

def stop_system_monitoring():
    """Stop system monitoring"""
    collector = get_metrics_collector()
    collector.stop_collection()

def record_metric(name: str, value: Any, tags: Optional[Dict] = None):
    """Record a custom metric"""
    # Placeholder for custom metrics
    pass

def increment_counter(name: str, value: int = 1, tags: Optional[Dict] = None):
    """Increment a counter metric"""
    # Placeholder for counter metrics
    pass

def get_metric(name: str):
    """Get metric value"""
    # Placeholder for metric retrieval
    return None

# Compatibility aliases
LightweightMetrics = RealtimeMetricsCollector

__all__ = [
    'RealtimeMetricsCollector',
    'get_metrics_collector',
    'start_system_monitoring',
    'stop_system_monitoring',
    'record_metric',
    'increment_counter',
    'get_metric',
    'LightweightMetrics'
]
