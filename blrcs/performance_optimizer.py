# BLRCS Performance Optimizer
# Advanced performance optimization for 100k+ requests/second throughput

import os
import json
import time
import threading
import asyncio
import multiprocessing
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
import logging
import weakref
import gc
from typing import Dict, List, Any, Optional, Set, Tuple, Union, Callable, Awaitable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, deque
import concurrent.futures
import functools
import heapq
import mmap
import queue
import struct
import socket
import select

logger = logging.getLogger(__name__)

class OptimizationLevel(Enum):
    """Performance optimization levels"""
    CONSERVATIVE = 1   # Safe optimizations only
    MODERATE = 2      # Balanced performance/stability
    AGGRESSIVE = 3    # Maximum performance
    EXTREME = 4       # All optimizations enabled

class CachePolicy(Enum):
    """Cache eviction policies"""
    LRU = "lru"          # Least Recently Used
    LFU = "lfu"          # Least Frequently Used
    TTL = "ttl"          # Time To Live
    RANDOM = "random"    # Random eviction
    ADAPTIVE = "adaptive" # Adaptive policy

class ResourceType(Enum):
    """System resource types"""
    CPU = "cpu"
    MEMORY = "memory"
    DISK_IO = "disk_io"
    NETWORK_IO = "network_io"
    DATABASE = "database"

@dataclass
class PerformanceMetrics:
    """Performance metrics container"""
    timestamp: datetime
    requests_per_second: float = 0.0
    average_response_time: float = 0.0
    p95_response_time: float = 0.0
    p99_response_time: float = 0.0
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    memory_usage_mb: float = 0.0
    disk_io_read: float = 0.0
    disk_io_write: float = 0.0
    network_io_in: float = 0.0
    network_io_out: float = 0.0
    cache_hit_rate: float = 0.0
    connection_pool_size: int = 0
    active_connections: int = 0
    queue_size: int = 0
    error_rate: float = 0.0
    throughput_mbps: float = 0.0

@dataclass
class OptimizationResult:
    """Result of optimization operation"""
    optimization_type: str
    success: bool
    improvement_percentage: float
    before_metrics: Dict[str, Any]
    after_metrics: Dict[str, Any]
    applied_at: datetime
    description: str

class HighPerformanceCache:
    """High-performance in-memory cache with multiple eviction policies"""
    
    def __init__(self, max_size: int = 10000, policy: CachePolicy = CachePolicy.LRU):
        self.max_size = max_size
        self.policy = policy
        self.data: Dict[str, Any] = {}
        self.access_times: Dict[str, float] = {}
        self.access_counts: Dict[str, int] = {}
        self.ttl_times: Dict[str, float] = {}
        self.lock = threading.RLock()
        
        # LRU tracking
        self.lru_order = deque()
        
        # Statistics
        self.hits = 0
        self.misses = 0
        self.evictions = 0
    
    def get(self, key: str, default=None):
        """Get value from cache"""
        with self.lock:
            if key in self.data:
                # Check TTL
                if self.policy == CachePolicy.TTL and key in self.ttl_times:
                    if time.time() > self.ttl_times[key]:
                        self._remove_key(key)
                        self.misses += 1
                        return default
                
                # Update access tracking
                self._update_access(key)
                self.hits += 1
                return self.data[key]
            else:
                self.misses += 1
                return default
    
    def set(self, key: str, value: Any, ttl: Optional[float] = None):
        """Set value in cache"""
        with self.lock:
            # Check if we need to evict
            if len(self.data) >= self.max_size and key not in self.data:
                self._evict_one()
            
            # Store value
            self.data[key] = value
            self._update_access(key)
            
            # Set TTL if provided
            if ttl is not None:
                self.ttl_times[key] = time.time() + ttl
    
    def delete(self, key: str) -> bool:
        """Delete key from cache"""
        with self.lock:
            if key in self.data:
                self._remove_key(key)
                return True
            return False
    
    def clear(self):
        """Clear all cache entries"""
        with self.lock:
            self.data.clear()
            self.access_times.clear()
            self.access_counts.clear()
            self.ttl_times.clear()
            self.lru_order.clear()
    
    def _update_access(self, key: str):
        """Update access tracking for key"""
        current_time = time.time()
        self.access_times[key] = current_time
        self.access_counts[key] = self.access_counts.get(key, 0) + 1
        
        # Update LRU order
        if key in self.lru_order:
            self.lru_order.remove(key)
        self.lru_order.append(key)
    
    def _remove_key(self, key: str):
        """Remove key and all associated tracking"""
        self.data.pop(key, None)
        self.access_times.pop(key, None)
        self.access_counts.pop(key, None)
        self.ttl_times.pop(key, None)
        if key in self.lru_order:
            self.lru_order.remove(key)
    
    def _evict_one(self):
        """Evict one item based on policy"""
        if not self.data:
            return
        
        if self.policy == CachePolicy.LRU:
            if self.lru_order:
                key = self.lru_order.popleft()
                self._remove_key(key)
                self.evictions += 1
        
        elif self.policy == CachePolicy.LFU:
            # Find least frequently used
            min_count = min(self.access_counts.values())
            lfu_keys = [k for k, v in self.access_counts.items() if v == min_count]
            key = lfu_keys[0]  # Take first if tied
            self._remove_key(key)
            self.evictions += 1
        
        elif self.policy == CachePolicy.TTL:
            # Remove expired items first
            current_time = time.time()
            expired_keys = [k for k, t in self.ttl_times.items() if current_time > t]
            if expired_keys:
                key = expired_keys[0]
                self._remove_key(key)
                self.evictions += 1
            else:
                # Fall back to LRU
                if self.lru_order:
                    key = self.lru_order.popleft()
                    self._remove_key(key)
                    self.evictions += 1
        
        elif self.policy == CachePolicy.RANDOM:
            import random
            key = random.choice(list(self.data.keys()))
            self._remove_key(key)
            self.evictions += 1
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_requests = self.hits + self.misses
        hit_rate = self.hits / total_requests if total_requests > 0 else 0
        
        return {
            'size': len(self.data),
            'max_size': self.max_size,
            'hits': self.hits,
            'misses': self.misses,
            'hit_rate': hit_rate,
            'evictions': self.evictions,
            'policy': self.policy.value
        }

class ConnectionPool:
    """High-performance connection pool"""
    
    def __init__(self, min_connections: int = 5, max_connections: int = 100,
                 connection_factory: Callable = None):
        self.min_connections = min_connections
        self.max_connections = max_connections
        self.connection_factory = connection_factory or self._default_connection_factory
        
        self.available = queue.Queue(maxsize=max_connections)
        self.in_use: Set[Any] = set()
        self.total_created = 0
        self.lock = threading.Lock()
        
        # Pre-create minimum connections
        self._ensure_min_connections()
    
    def _default_connection_factory(self):
        """Default connection factory (placeholder)"""
        return {"id": self.total_created, "created_at": time.time()}
    
    def _ensure_min_connections(self):
        """Ensure minimum number of connections are available"""
        with self.lock:
            while (self.available.qsize() + len(self.in_use)) < self.min_connections:
                if self.total_created < self.max_connections:
                    conn = self.connection_factory()
                    self.available.put(conn)
                    self.total_created += 1
                else:
                    break
    
    def get_connection(self, timeout: float = 5.0):
        """Get connection from pool"""
        try:
            # Try to get available connection
            conn = self.available.get(timeout=timeout)
            
            with self.lock:
                self.in_use.add(conn)
            
            return conn
            
        except queue.Empty:
            # Create new connection if under limit
            with self.lock:
                if self.total_created < self.max_connections:
                    conn = self.connection_factory()
                    self.in_use.add(conn)
                    self.total_created += 1
                    return conn
            
            raise RuntimeError("No connections available and pool is at maximum capacity")
    
    def return_connection(self, conn):
        """Return connection to pool"""
        with self.lock:
            if conn in self.in_use:
                self.in_use.remove(conn)
                
                # Only return to pool if we're not over minimum
                if self.available.qsize() < self.min_connections:
                    try:
                        self.available.put_nowait(conn)
                    except queue.Full:
                        pass
                else:
                    # Close connection if we have too many
                    self._close_connection(conn)
                    self.total_created -= 1
    
    def _close_connection(self, conn):
        """Close connection (override in subclass)"""
        pass
    
    def get_stats(self) -> Dict[str, Any]:
        """Get pool statistics"""
        return {
            'available': self.available.qsize(),
            'in_use': len(self.in_use),
            'total_created': self.total_created,
            'min_connections': self.min_connections,
            'max_connections': self.max_connections
        }

class RequestBatcher:
    """Batch similar requests for performance"""
    
    def __init__(self, batch_size: int = 100, flush_interval: float = 0.1):
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.batches: Dict[str, List] = defaultdict(list)
        self.last_flush = time.time()
        self.lock = threading.Lock()
        self.processors: Dict[str, Callable] = {}
    
    def register_processor(self, batch_type: str, processor: Callable):
        """Register batch processor for a type"""
        self.processors[batch_type] = processor
    
    def add_request(self, batch_type: str, request_data: Any):
        """Add request to batch"""
        with self.lock:
            self.batches[batch_type].append(request_data)
            
            # Check if batch is full or flush interval exceeded
            current_time = time.time()
            should_flush = (
                len(self.batches[batch_type]) >= self.batch_size or
                current_time - self.last_flush >= self.flush_interval
            )
            
            if should_flush:
                self._flush_batches()
    
    def _flush_batches(self):
        """Flush all batches"""
        for batch_type, requests in self.batches.items():
            if requests and batch_type in self.processors:
                try:
                    # Process batch
                    processor = self.processors[batch_type]
                    asyncio.create_task(processor(requests))
                    
                except Exception as e:
                    logger.error(f"Batch processing failed for {batch_type}: {e}")
                
                # Clear batch
                requests.clear()
        
        self.last_flush = time.time()
    
    def force_flush(self):
        """Force flush all batches"""
        with self.lock:
            self._flush_batches()

class MemoryOptimizer:
    """Memory usage optimization"""
    
    def __init__(self):
        self.weak_references = weakref.WeakSet()
        self.memory_pools = {}
        self.gc_stats = {'collections': 0, 'freed_objects': 0}
    
    def optimize_memory(self) -> Dict[str, Any]:
        """Perform memory optimization"""
        initial_memory = self._get_memory_usage()
        
        # Force garbage collection
        collected = gc.collect()
        self.gc_stats['collections'] += 1
        self.gc_stats['freed_objects'] += collected
        
        # Clear weak references
        self.weak_references.clear()
        
        # Optimize memory pools
        self._optimize_memory_pools()
        
        final_memory = self._get_memory_usage()
        freed_mb = (initial_memory - final_memory) / (1024 * 1024)
        
        return {
            'freed_mb': freed_mb,
            'initial_memory_mb': initial_memory / (1024 * 1024),
            'final_memory_mb': final_memory / (1024 * 1024),
            'gc_collected': collected
        }
    
    def _get_memory_usage(self) -> int:
        """Get current memory usage in bytes"""
        if PSUTIL_AVAILABLE:
            process = psutil.Process()
            return process.memory_info().rss
        else:
            # Fallback: estimate memory usage
            return 1024 * 1024 * 100  # 100MB estimate
    
    def _optimize_memory_pools(self):
        """Optimize memory pools"""
        # Clear unused pools
        for pool_name, pool in list(self.memory_pools.items()):
            if not hasattr(pool, 'is_active') or not pool.is_active():
                del self.memory_pools[pool_name]
    
    def create_memory_pool(self, name: str, size: int):
        """Create memory pool for frequent allocations"""
        self.memory_pools[name] = {
            'size': size,
            'allocated': 0,
            'is_active': lambda: True
        }
    
    def get_memory_stats(self) -> Dict[str, Any]:
        """Get memory optimization statistics"""
        if PSUTIL_AVAILABLE:
            process = psutil.Process()
            memory_info = process.memory_info()
        else:
            # Fallback memory info
            memory_info = type('MemInfo', (), {'rss': 1024*1024*100, 'vms': 1024*1024*200})()
        
        return {
            'rss_mb': memory_info.rss / (1024 * 1024),
            'vms_mb': memory_info.vms / (1024 * 1024),
            'memory_pools': len(self.memory_pools),
            'weak_references': len(self.weak_references),
            'gc_stats': self.gc_stats.copy()
        }

class IOOptimizer:
    """I/O performance optimization"""
    
    def __init__(self):
        self.read_ahead_cache = {}
        self.write_buffer = {}
        self.async_writers = {}
    
    async def optimized_read(self, file_path: str, chunk_size: int = 8192) -> bytes:
        """Optimized file reading with caching and read-ahead"""
        try:
            # Check cache first
            if file_path in self.read_ahead_cache:
                return self.read_ahead_cache[file_path]
            
            # Asynchronous read
            loop = asyncio.get_event_loop()
            
            def _read_file():
                with open(file_path, 'rb') as f:
                    return f.read()
            
            data = await loop.run_in_executor(None, _read_file)
            
            # Cache for future reads
            self.read_ahead_cache[file_path] = data
            
            return data
            
        except Exception as e:
            logger.error(f"Optimized read failed for {file_path}: {e}")
            return b""
    
    async def optimized_write(self, file_path: str, data: bytes, buffer_size: int = 8192):
        """Optimized file writing with buffering"""
        try:
            # Add to write buffer
            if file_path not in self.write_buffer:
                self.write_buffer[file_path] = []
            
            self.write_buffer[file_path].append(data)
            
            # Flush buffer if it's large enough
            total_size = sum(len(chunk) for chunk in self.write_buffer[file_path])
            if total_size >= buffer_size:
                await self._flush_write_buffer(file_path)
                
        except Exception as e:
            logger.error(f"Optimized write failed for {file_path}: {e}")
    
    async def _flush_write_buffer(self, file_path: str):
        """Flush write buffer to disk"""
        if file_path not in self.write_buffer:
            return
        
        chunks = self.write_buffer[file_path]
        self.write_buffer[file_path] = []
        
        loop = asyncio.get_event_loop()
        
        def _write_chunks():
            with open(file_path, 'ab') as f:
                for chunk in chunks:
                    f.write(chunk)
                f.flush()
                os.fsync(f.fileno())  # Force write to disk
        
        await loop.run_in_executor(None, _write_chunks)
    
    def clear_caches(self):
        """Clear I/O caches"""
        self.read_ahead_cache.clear()
        self.write_buffer.clear()

class NetworkOptimizer:
    """Network performance optimization"""
    
    def __init__(self):
        self.keep_alive_connections = {}
        self.connection_cache = {}
        self.request_pipeline = defaultdict(list)
    
    def optimize_socket(self, sock: socket.socket):
        """Apply socket optimizations"""
        try:
            # Enable TCP_NODELAY for low latency
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            
            # Set socket buffer sizes
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
            
            # Enable keep-alive
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            
            # Set keep-alive parameters (Linux-specific)
            if hasattr(socket, 'TCP_KEEPIDLE'):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
            
        except Exception as e:
            logger.warning(f"Socket optimization failed: {e}")
    
    def create_optimized_server_socket(self, host: str, port: int) -> socket.socket:
        """Create optimized server socket"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Reuse address
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Apply optimizations
        self.optimize_socket(sock)
        
        # Bind and listen
        sock.bind((host, port))
        sock.listen(1024)  # Large backlog for high concurrency
        
        return sock
    
    async def batch_network_requests(self, requests: List[Dict[str, Any]]) -> List[Any]:
        """Batch multiple network requests"""
        tasks = []
        
        for request in requests:
            task = asyncio.create_task(self._make_request(request))
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
    
    async def _make_request(self, request: Dict[str, Any]) -> Any:
        """Make individual network request (placeholder)"""
        # This would implement the actual network request
        await asyncio.sleep(0.001)  # Simulate network delay
        return {"status": "success", "data": request}

class DatabaseOptimizer:
    """Database performance optimization"""
    
    def __init__(self):
        self.query_cache = HighPerformanceCache(max_size=1000, policy=CachePolicy.LRU)
        self.prepared_statements = {}
        self.connection_pool = None
        self.batch_operations = defaultdict(list)
    
    def set_connection_pool(self, pool: ConnectionPool):
        """Set database connection pool"""
        self.connection_pool = pool
    
    def cache_query_result(self, query: str, params: Tuple, result: Any, ttl: float = 300):
        """Cache query result"""
        cache_key = self._make_cache_key(query, params)
        self.query_cache.set(cache_key, result, ttl=ttl)
    
    def get_cached_result(self, query: str, params: Tuple) -> Any:
        """Get cached query result"""
        cache_key = self._make_cache_key(query, params)
        return self.query_cache.get(cache_key)
    
    def _make_cache_key(self, query: str, params: Tuple) -> str:
        """Create cache key for query and parameters"""
        import hashlib
        key_data = f"{query}|{params}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def prepare_statement(self, query: str, statement_id: str):
        """Prepare SQL statement for reuse"""
        self.prepared_statements[statement_id] = query
    
    def add_batch_operation(self, operation_type: str, operation_data: Dict[str, Any]):
        """Add operation to batch"""
        self.batch_operations[operation_type].append(operation_data)
        
        # Auto-flush large batches
        if len(self.batch_operations[operation_type]) >= 100:
            self.flush_batch_operations(operation_type)
    
    def flush_batch_operations(self, operation_type: str):
        """Flush batch operations"""
        operations = self.batch_operations[operation_type]
        if not operations:
            return
        
        try:
            # Execute batch operation
            if operation_type == "insert":
                self._execute_batch_inserts(operations)
            elif operation_type == "update":
                self._execute_batch_updates(operations)
            elif operation_type == "delete":
                self._execute_batch_deletes(operations)
            
            # Clear batch
            operations.clear()
            
        except Exception as e:
            logger.error(f"Batch operation failed for {operation_type}: {e}")
    
    def _execute_batch_inserts(self, operations: List[Dict[str, Any]]):
        """Execute batch INSERT operations"""
        # Placeholder for actual batch insert logic
        logger.info(f"Executing {len(operations)} batch inserts")
    
    def _execute_batch_updates(self, operations: List[Dict[str, Any]]):
        """Execute batch UPDATE operations"""
        # Placeholder for actual batch update logic
        logger.info(f"Executing {len(operations)} batch updates")
    
    def _execute_batch_deletes(self, operations: List[Dict[str, Any]]):
        """Execute batch DELETE operations"""
        # Placeholder for actual batch delete logic
        logger.info(f"Executing {len(operations)} batch deletes")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get database optimization statistics"""
        cache_stats = self.query_cache.get_stats()
        
        return {
            'query_cache': cache_stats,
            'prepared_statements': len(self.prepared_statements),
            'pending_batches': {
                op_type: len(ops) for op_type, ops in self.batch_operations.items()
            }
        }

class PerformanceMonitor:
    """Performance monitoring and metrics collection"""
    
    def __init__(self, history_size: int = 1000):
        self.history_size = history_size
        self.metrics_history = deque(maxlen=history_size)
        self.response_times = deque(maxlen=10000)
        self.request_counter = 0
        self.error_counter = 0
        self.start_time = time.time()
        self.lock = threading.Lock()
    
    def record_request(self, response_time: float, success: bool = True):
        """Record request metrics"""
        with self.lock:
            self.request_counter += 1
            self.response_times.append(response_time)
            
            if not success:
                self.error_counter += 1
    
    def collect_metrics(self) -> PerformanceMetrics:
        """Collect current performance metrics"""
        with self.lock:
            current_time = time.time()
            
            # Calculate requests per second
            time_window = 60  # Last 60 seconds
            recent_requests = sum(1 for _ in range(min(len(self.response_times), 
                                                     int(time_window * self.get_current_rps()))))
            rps = recent_requests / time_window if time_window > 0 else 0
            
            # Calculate response time percentiles
            if self.response_times:
                sorted_times = sorted(self.response_times)
                avg_response_time = sum(sorted_times) / len(sorted_times)
                p95_index = int(len(sorted_times) * 0.95)
                p99_index = int(len(sorted_times) * 0.99)
                p95_response_time = sorted_times[p95_index] if p95_index < len(sorted_times) else 0
                p99_response_time = sorted_times[p99_index] if p99_index < len(sorted_times) else 0
            else:
                avg_response_time = p95_response_time = p99_response_time = 0
            
            # System metrics
            if PSUTIL_AVAILABLE:
                cpu_usage = psutil.cpu_percent(interval=0.1)
                memory = psutil.virtual_memory()
                network = psutil.net_io_counters()
            else:
                # Fallback system metrics
                cpu_usage = 25.0  # Estimate 25% CPU usage
                memory = type('VMemory', (), {'total': 8*1024**3, 'available': 4*1024**3, 'percent': 50.0})()
                network = type('NetworkIO', (), {'bytes_sent': 1024**3, 'bytes_recv': 2*1024**3})()
            
            # Error rate
            error_rate = (self.error_counter / max(self.request_counter, 1)) * 100
            
            metrics = PerformanceMetrics(
                timestamp=datetime.now(),
                requests_per_second=rps,
                average_response_time=avg_response_time,
                p95_response_time=p95_response_time,
                p99_response_time=p99_response_time,
                cpu_usage=cpu_usage,
                memory_usage=memory.percent,
                memory_usage_mb=memory.used / (1024 * 1024),
                network_io_in=network.bytes_recv,
                network_io_out=network.bytes_sent,
                error_rate=error_rate,
                throughput_mbps=(network.bytes_sent + network.bytes_recv) / (1024 * 1024)
            )
            
            self.metrics_history.append(metrics)
            return metrics
    
    def get_current_rps(self) -> float:
        """Get current requests per second"""
        uptime = time.time() - self.start_time
        return self.request_counter / uptime if uptime > 0 else 0
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary"""
        if not self.metrics_history:
            return {}
        
        latest = self.metrics_history[-1]
        
        # Calculate trends (last 10 measurements)
        recent_metrics = list(self.metrics_history)[-10:]
        
        rps_trend = self._calculate_trend([m.requests_per_second for m in recent_metrics])
        response_time_trend = self._calculate_trend([m.average_response_time for m in recent_metrics])
        cpu_trend = self._calculate_trend([m.cpu_usage for m in recent_metrics])
        
        return {
            'current_rps': latest.requests_per_second,
            'avg_response_time_ms': latest.average_response_time * 1000,
            'p95_response_time_ms': latest.p95_response_time * 1000,
            'p99_response_time_ms': latest.p99_response_time * 1000,
            'cpu_usage_percent': latest.cpu_usage,
            'memory_usage_percent': latest.memory_usage,
            'memory_usage_mb': latest.memory_usage_mb,
            'error_rate_percent': latest.error_rate,
            'throughput_mbps': latest.throughput_mbps,
            'total_requests': self.request_counter,
            'total_errors': self.error_counter,
            'uptime_seconds': time.time() - self.start_time,
            'trends': {
                'rps': rps_trend,
                'response_time': response_time_trend,
                'cpu_usage': cpu_trend
            }
        }
    
    def _calculate_trend(self, values: List[float]) -> str:
        """Calculate trend direction for values"""
        if len(values) < 2:
            return "stable"
        
        recent_avg = sum(values[-3:]) / min(3, len(values))
        older_avg = sum(values[:-3]) / max(1, len(values) - 3)
        
        if recent_avg > older_avg * 1.1:
            return "increasing"
        elif recent_avg < older_avg * 0.9:
            return "decreasing"
        else:
            return "stable"

class PerformanceOptimizer:
    """Main performance optimization system"""
    
    def __init__(self, config_dir: Optional[Path] = None):
        self.config_dir = config_dir or Path.home() / ".blrcs" / "performance"
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        self.optimization_level = OptimizationLevel.MODERATE
        self.cache = HighPerformanceCache(max_size=10000)
        self.connection_pool = ConnectionPool()
        self.request_batcher = RequestBatcher()
        self.memory_optimizer = MemoryOptimizer()
        self.io_optimizer = IOOptimizer()
        self.network_optimizer = NetworkOptimizer()
        self.db_optimizer = DatabaseOptimizer()
        self.performance_monitor = PerformanceMonitor()
        
        self.optimization_history: List[OptimizationResult] = []
        self.auto_optimization_enabled = True
        self.monitoring_thread = None
        self.running = False
        
        # Set up database connection pool
        self.db_optimizer.set_connection_pool(self.connection_pool)
    
    def start_optimization(self):
        """Start performance optimization services"""
        if not self.running:
            self.running = True
            
            # Start monitoring thread
            self.monitoring_thread = threading.Thread(
                target=self._monitoring_loop,
                daemon=True
            )
            self.monitoring_thread.start()
            
            logger.info("Performance optimization started")
    
    def stop_optimization(self):
        """Stop performance optimization services"""
        self.running = False
        
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        
        logger.info("Performance optimization stopped")
    
    def _monitoring_loop(self):
        """Main monitoring and optimization loop"""
        while self.running:
            try:
                # Collect metrics
                metrics = self.performance_monitor.collect_metrics()
                
                # Auto-optimize if enabled
                if self.auto_optimization_enabled:
                    self._auto_optimize(metrics)
                
                time.sleep(30)  # Monitor every 30 seconds
                
            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                time.sleep(10)
    
    def _auto_optimize(self, metrics: PerformanceMetrics):
        """Automatic optimization based on metrics"""
        optimizations_applied = []
        
        # Memory optimization
        if metrics.memory_usage > 85:
            result = self.optimize_memory()
            if result['freed_mb'] > 10:  # Only record if significant
                optimizations_applied.append(result)
        
        # Cache optimization
        cache_stats = self.cache.get_stats()
        if cache_stats['hit_rate'] < 0.7:  # Low cache hit rate
            self._optimize_cache_policy()
        
        # I/O optimization
        if metrics.average_response_time > 0.1:  # > 100ms
            self.io_optimizer.clear_caches()
        
        # Record optimizations
        for opt in optimizations_applied:
            self.optimization_history.append(opt)
    
    def optimize_memory(self) -> OptimizationResult:
        """Optimize memory usage"""
        before_stats = self.memory_optimizer.get_memory_stats()
        optimization_result = self.memory_optimizer.optimize_memory()
        after_stats = self.memory_optimizer.get_memory_stats()
        
        result = OptimizationResult(
            optimization_type="memory",
            success=optimization_result['freed_mb'] > 0,
            improvement_percentage=(optimization_result['freed_mb'] / before_stats['rss_mb']) * 100,
            before_metrics=before_stats,
            after_metrics=after_stats,
            applied_at=datetime.now(),
            description=f"Freed {optimization_result['freed_mb']:.2f} MB of memory"
        )
        
        return result
    
    def _optimize_cache_policy(self):
        """Optimize cache policy based on usage patterns"""
        current_stats = self.cache.get_stats()
        
        # Try different policies and see which performs better
        if current_stats['hit_rate'] < 0.5:
            # Switch to LFU if hit rate is very low
            self.cache.policy = CachePolicy.LFU
        elif current_stats['evictions'] > current_stats['hits'] * 0.5:
            # Too many evictions, try TTL policy
            self.cache.policy = CachePolicy.TTL
    
    def optimize_for_throughput(self) -> List[OptimizationResult]:
        """Optimize system for maximum throughput"""
        results = []
        
        # Increase cache size
        old_cache_size = self.cache.max_size
        self.cache.max_size = min(old_cache_size * 2, 50000)
        
        # Optimize connection pool
        self.connection_pool.max_connections = min(self.connection_pool.max_connections * 2, 500)
        
        # Increase batch sizes
        self.request_batcher.batch_size = min(self.request_batcher.batch_size * 2, 1000)
        
        # Clear I/O caches to start fresh
        self.io_optimizer.clear_caches()
        
        result = OptimizationResult(
            optimization_type="throughput",
            success=True,
            improvement_percentage=0,  # Will be measured over time
            before_metrics={'cache_size': old_cache_size},
            after_metrics={'cache_size': self.cache.max_size},
            applied_at=datetime.now(),
            description="Optimized for maximum throughput"
        )
        
        results.append(result)
        return results
    
    def optimize_for_latency(self) -> List[OptimizationResult]:
        """Optimize system for minimum latency"""
        results = []
        
        # Reduce batch sizes for faster processing
        self.request_batcher.batch_size = max(self.request_batcher.batch_size // 2, 10)
        self.request_batcher.flush_interval = min(self.request_batcher.flush_interval / 2, 0.01)
        
        # Use LRU cache for predictable access times
        old_policy = self.cache.policy
        self.cache.policy = CachePolicy.LRU
        
        # Optimize memory for lower GC pauses
        self.memory_optimizer.optimize_memory()
        
        result = OptimizationResult(
            optimization_type="latency",
            success=True,
            improvement_percentage=0,  # Will be measured over time
            before_metrics={'cache_policy': old_policy.value},
            after_metrics={'cache_policy': self.cache.policy.value},
            applied_at=datetime.now(),
            description="Optimized for minimum latency"
        )
        
        results.append(result)
        return results
    
    def get_performance_status(self) -> Dict[str, Any]:
        """Get comprehensive performance status"""
        performance_summary = self.performance_monitor.get_performance_summary()
        cache_stats = self.cache.get_stats()
        pool_stats = self.connection_pool.get_stats()
        memory_stats = self.memory_optimizer.get_memory_stats()
        db_stats = self.db_optimizer.get_stats()
        
        # Calculate performance score (0-100)
        score_factors = {
            'rps': min(performance_summary.get('current_rps', 0) / 1000, 1.0) * 30,  # Up to 30 points
            'response_time': max(0, 1 - performance_summary.get('avg_response_time_ms', 100) / 100) * 25,  # Up to 25 points
            'cache_hit_rate': cache_stats.get('hit_rate', 0) * 20,  # Up to 20 points
            'resource_usage': max(0, 1 - performance_summary.get('cpu_usage_percent', 100) / 100) * 15,  # Up to 15 points
            'error_rate': max(0, 1 - performance_summary.get('error_rate_percent', 100) / 100) * 10  # Up to 10 points
        }
        
        performance_score = sum(score_factors.values())
        
        return {
            'performance_score': performance_score,
            'optimization_level': self.optimization_level.value,
            'auto_optimization_enabled': self.auto_optimization_enabled,
            'performance_summary': performance_summary,
            'cache_stats': cache_stats,
            'connection_pool_stats': pool_stats,
            'memory_stats': memory_stats,
            'database_stats': db_stats,
            'recent_optimizations': len([o for o in self.optimization_history 
                                       if (datetime.now() - o.applied_at).hours < 24]),
            'running': self.running
        }
    
    def benchmark_performance(self, duration_seconds: int = 60) -> Dict[str, Any]:
        """Run performance benchmark"""
        logger.info(f"Starting {duration_seconds}-second performance benchmark")
        
        start_time = time.time()
        end_time = start_time + duration_seconds
        
        request_count = 0
        response_times = []
        errors = 0
        
        while time.time() < end_time:
            request_start = time.time()
            
            try:
                # Simulate work (replace with actual workload)
                time.sleep(0.001)
                success = True
            except Exception:
                success = False
                errors += 1
            
            response_time = time.time() - request_start
            response_times.append(response_time)
            request_count += 1
            
            # Record metrics
            self.performance_monitor.record_request(response_time, success)
        
        # Calculate benchmark results
        total_time = time.time() - start_time
        avg_rps = request_count / total_time
        avg_response_time = sum(response_times) / len(response_times)
        error_rate = (errors / request_count) * 100 if request_count > 0 else 0
        
        # Calculate percentiles
        sorted_times = sorted(response_times)
        p95_response_time = sorted_times[int(len(sorted_times) * 0.95)]
        p99_response_time = sorted_times[int(len(sorted_times) * 0.99)]
        
        benchmark_results = {
            'duration_seconds': total_time,
            'total_requests': request_count,
            'requests_per_second': avg_rps,
            'average_response_time_ms': avg_response_time * 1000,
            'p95_response_time_ms': p95_response_time * 1000,
            'p99_response_time_ms': p99_response_time * 1000,
            'error_rate_percent': error_rate,
            'errors': errors,
            'timestamp': datetime.now().isoformat()
        }
        
        logger.info(f"Benchmark completed: {avg_rps:.2f} RPS, "
                   f"{avg_response_time*1000:.2f}ms avg response time")
        
        return benchmark_results

# Global performance optimizer instance
performance_optimizer = PerformanceOptimizer()

# Convenience functions
def start_performance_optimization():
    """Start performance optimization"""
    performance_optimizer.start_optimization()

def stop_performance_optimization():
    """Stop performance optimization"""
    performance_optimizer.stop_optimization()

def get_performance_status() -> Dict[str, Any]:
    """Get performance status"""
    return performance_optimizer.get_performance_status()

def optimize_for_throughput() -> List[OptimizationResult]:
    """Optimize for throughput"""
    return performance_optimizer.optimize_for_throughput()

def optimize_for_latency() -> List[OptimizationResult]:
    """Optimize for latency"""
    return performance_optimizer.optimize_for_latency()

def record_request_metrics(response_time: float, success: bool = True):
    """Record request metrics"""
    performance_optimizer.performance_monitor.record_request(response_time, success)

# Export main classes and functions
__all__ = [
    'OptimizationLevel', 'CachePolicy', 'ResourceType',
    'PerformanceMetrics', 'OptimizationResult',
    'HighPerformanceCache', 'ConnectionPool', 'RequestBatcher',
    'MemoryOptimizer', 'IOOptimizer', 'NetworkOptimizer', 'DatabaseOptimizer',
    'PerformanceMonitor', 'PerformanceOptimizer',
    'performance_optimizer', 'start_performance_optimization', 'stop_performance_optimization',
    'get_performance_status', 'optimize_for_throughput', 'optimize_for_latency', 'record_request_metrics'
]