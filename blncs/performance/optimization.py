"""
Performance Optimization Module for BLNCS Enterprise
Provides advanced caching, query optimization, and resource pooling
"""

import time
import threading
from typing import Dict, List, Optional, Any, Callable
import functools
import sqlite3
import json
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
import psutil
import os
import logging

logger = logging.getLogger(__name__)

class LRUCache:
    """Thread-safe LRU Cache with TTL support"""

    def __init__(self, max_size: int = 1000, ttl_seconds: int = 3600):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self.cache = OrderedDict()
        self.timestamps = {}
        self.lock = threading.RLock()

    def get(self, key: str) -> Any:
        """Get item from cache"""
        with self.lock:
            if key not in self.cache:
                return None

            # Check TTL
            if time.time() - self.timestamps[key] > self.ttl_seconds:
                del self.cache[key]
                del self.timestamps[key]
                return None

            # Move to end (most recently used)
            self.cache.move_to_end(key)
            return self.cache[key]

    def put(self, key: str, value: Any):
        """Put item in cache"""
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
            else:
                if len(self.cache) >= self.max_size:
                    # Remove oldest item
                    oldest_key, _ = self.cache.popitem(last=False)
                    del self.timestamps[oldest_key]

            self.cache[key] = value
            self.timestamps[key] = time.time()

    def clear(self):
        """Clear all cache entries"""
        with self.lock:
            self.cache.clear()
            self.timestamps.clear()

class QueryOptimizer:
    """Database query optimization utilities"""

    def __init__(self, db_connection: sqlite3.Connection):
        self.db = db_connection
        self.query_stats = {}
        self.lock = threading.Lock()

    def optimize_query(self, query: str, params: tuple = None) -> sqlite3.Cursor:
        """Execute optimized query with statistics"""
        start_time = time.time()

        try:
            if params:
                cursor = self.db.execute(query, params)
            else:
                cursor = self.db.execute(query)

            execution_time = time.time() - start_time

            # Record statistics
            with self.lock:
                if query not in self.query_stats:
                    self.query_stats[query] = {'count': 0, 'total_time': 0}
                self.query_stats[query]['count'] += 1
                self.query_stats[query]['total_time'] += execution_time

            return cursor

        except Exception as e:
            logger.error(f"Query optimization error: {e}")
            raise

    def get_query_stats(self) -> Dict[str, Dict[str, float]]:
        """Get query performance statistics"""
        with self.lock:
            return {
                query: {
                    'avg_time': stats['total_time'] / stats['count'],
                    'count': stats['count']
                }
                for query, stats in self.query_stats.items()
            }

    def create_index_if_needed(self, table: str, column: str):
        """Create database index if beneficial"""
        try:
            # Check if index already exists
            cursor = self.db.execute("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name=? AND name LIKE ?", (table, f"%{column}%"))
            if cursor.fetchone():
                return

            # Create index
            index_name = f"idx_{table}_{column}"
            self.db.execute(f"CREATE INDEX IF NOT EXISTS {index_name} ON {table}({column})")
            self.db.commit()
            logger.info(f"Created index {index_name}")

        except Exception as e:
            logger.error(f"Error creating index: {e}")

class ConnectionPool:
    """Database connection pooling"""

    def __init__(self, db_path: str, max_connections: int = 10):
        self.db_path = db_path
        self.max_connections = max_connections
        self.pool = []
        self.in_use = []
        self.lock = threading.Lock()

    def get_connection(self) -> sqlite3.Connection:
        """Get connection from pool"""
        with self.lock:
            if self.pool:
                conn = self.pool.pop()
                self.in_use.append(conn)
                return conn
            else:
                # Create new connection if pool not full
                if len(self.in_use) < self.max_connections:
                    conn = sqlite3.connect(self.db_path)
                    conn.row_factory = sqlite3.Row
                    self.in_use.append(conn)
                    return conn
                else:
                    # Wait for available connection
                    return self._wait_for_connection()

    def _wait_for_connection(self) -> sqlite3.Connection:
        """Wait for available connection"""
        while True:
            with self.lock:
                if self.pool:
                    conn = self.pool.pop()
                    self.in_use.append(conn)
                    return conn
            time.sleep(0.1)

    def return_connection(self, conn: sqlite3.Connection):
        """Return connection to pool"""
        with self.lock:
            if conn in self.in_use:
                self.in_use.remove(conn)
                self.pool.append(conn)

    def close_all(self):
        """Close all connections"""
        with self.lock:
            for conn in self.pool + self.in_use:
                try:
                    conn.close()
                except:
                    pass
            self.pool.clear()
            self.in_use.clear()

class AsyncTaskManager:
    """Asynchronous task execution with resource management"""

    def __init__(self, max_workers: int = None):
        if max_workers is None:
            max_workers = min(32, (os.cpu_count() or 1) + 4)
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.tasks = {}

    def submit_task(self, task_id: str, func: Callable, *args, **kwargs) -> str:
        """Submit asynchronous task"""
        future = self.executor.submit(func, *args, **kwargs)
        self.tasks[task_id] = {
            'future': future,
            'start_time': time.time(),
            'status': 'running'
        }
        return task_id

    def get_task_result(self, task_id: str, timeout: int = 30) -> Any:
        """Get task result with timeout"""
        if task_id not in self.tasks:
            raise ValueError(f"Task {task_id} not found")

        task_info = self.tasks[task_id]
        future = task_info['future']

        try:
            result = future.result(timeout=timeout)
            task_info['status'] = 'completed'
            task_info['end_time'] = time.time()
            return result
        except Exception as e:
            task_info['status'] = 'failed'
            task_info['error'] = str(e)
            raise

    def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """Get task status"""
        if task_id not in self.tasks:
            return {'status': 'not_found'}

        task_info = self.tasks[task_id]
        future = task_info['future']

        status = {
            'status': task_info['status'],
            'start_time': task_info['start_time']
        }

        if 'end_time' in task_info:
            status['end_time'] = task_info['end_time']
            status['duration'] = task_info['end_time'] - task_info['start_time']

        if future.done():
            if future.cancelled():
                status['status'] = 'cancelled'
            elif future.exception():
                status['status'] = 'failed'
                status['error'] = str(future.exception())
            else:
                status['status'] = 'completed'

        return status

    def cancel_task(self, task_id: str) -> bool:
        """Cancel running task"""
        if task_id not in self.tasks:
            return False

        task_info = self.tasks[task_id]
        return task_info['future'].cancel()

    def shutdown(self, wait: bool = True):
        """Shutdown task manager"""
        self.executor.shutdown(wait=wait)

class MemoryManager:
    """System memory monitoring and management"""

    def __init__(self):
        self.baseline_memory = self.get_memory_usage()

    def get_memory_usage(self) -> Dict[str, float]:
        """Get current memory usage"""
        process = psutil.Process()
        memory_info = process.memory_info()
        system_memory = psutil.virtual_memory()

        return {
            'rss_mb': memory_info.rss / 1024 / 1024,  # Resident Set Size
            'vms_mb': memory_info.vms / 1024 / 1024,  # Virtual Memory Size
            'system_percent': system_memory.percent,
            'system_available_mb': system_memory.available / 1024 / 1024
        }

    def log_memory_usage(self, context: str = "general"):
        """Log current memory usage"""
        memory = self.get_memory_usage()
        logger.info(f"Memory usage ({context}): RSS={memory['rss_mb']".1f"}MB, "
                   f"VMS={memory['vms_mb']".1f"}MB, "
                   f"System={memory['system_percent']".1f"}%")

    def check_memory_threshold(self, threshold_mb: float = 1000) -> bool:
        """Check if memory usage exceeds threshold"""
        memory = self.get_memory_usage()
        return memory['rss_mb'] > threshold_mb

class PerformanceMonitor:
    """Comprehensive performance monitoring"""

    def __init__(self):
        self.metrics = defaultdict(list)
        self.start_time = time.time()
        self.lock = threading.Lock()

    def record_metric(self, name: str, value: float, unit: str = "ms"):
        """Record performance metric"""
        with self.lock:
            self.metrics[name].append({
                'value': value,
                'unit': unit,
                'timestamp': time.time()
            })

            # Keep only last 1000 records per metric
            if len(self.metrics[name]) > 1000:
                self.metrics[name] = self.metrics[name][-1000:]

    def get_metrics_summary(self) -> Dict[str, Dict[str, float]]:
        """Get summary of all metrics"""
        summary = {}

        with self.lock:
            for name, records in self.metrics.items():
                if not records:
                    continue

                values = [r['value'] for r in records]
                summary[name] = {
                    'count': len(values),
                    'avg': sum(values) / len(values),
                    'min': min(values),
                    'max': max(values),
                    'latest': values[-1]
                }

        return summary

    def get_uptime(self) -> float:
        """Get system uptime in seconds"""
        return time.time() - self.start_time

# Global performance instances
cache_manager = LRUCache()
query_optimizer = None
connection_pool = None
task_manager = AsyncTaskManager()
memory_manager = MemoryManager()
performance_monitor = PerformanceMonitor()

def init_performance_system(db_path: str = None):
    """Initialize performance optimization systems"""
    global query_optimizer, connection_pool

    if db_path:
        # Initialize database optimization
        conn = sqlite3.connect(db_path)
        query_optimizer = QueryOptimizer(conn)
        connection_pool = ConnectionPool(db_path)

def cached(ttl_seconds: int = 3600):
    """Decorator for caching function results"""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Create cache key from function name and arguments
            key_parts = [func.__name__]
            key_parts.extend(str(arg) for arg in args)
            key_parts.extend(f"{k}:{v}" for k, v in sorted(kwargs.items()))
            cache_key = hashlib.md5("|".join(key_parts).encode()).hexdigest()

            # Try to get from cache
            result = cache_manager.get(cache_key)
            if result is not None:
                performance_monitor.record_metric('cache_hit', 1, 'count')
                return result

            # Execute function and cache result
            performance_monitor.record_metric('cache_miss', 1, 'count')
            start_time = time.time()

            try:
                result = func(*args, **kwargs)
                cache_manager.put(cache_key, result)

                execution_time = (time.time() - start_time) * 1000
                performance_monitor.record_metric('function_execution', execution_time, 'ms')

                return result
            except Exception as e:
                # Don't cache exceptions
                raise e

        return wrapper
    return decorator

def async_task(task_id: str = None):
    """Decorator for async task execution"""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if task_id is None:
                task_id = f"{func.__name__}_{int(time.time())}"

            return task_manager.submit_task(task_id, func, *args, **kwargs)
        return wrapper
    return decorator
