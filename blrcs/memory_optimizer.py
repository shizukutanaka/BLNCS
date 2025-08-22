# BLRCS Memory Optimizer
# Advanced memory management system following Carmack's optimization principles
import gc
import sys
import psutil
import threading
import weakref
import mmap
import os
import ctypes
import time
from datetime import datetime, timedelta
from typing import (
    Dict, List, Any, Optional, Set, Tuple, TypeVar, Generic,
    Callable, Union, Protocol, runtime_checkable
)
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import tracemalloc
import linecache

T = TypeVar('T')

class MemoryEventType(Enum):
    """Memory event types for monitoring"""
    ALLOCATION = "allocation"
    DEALLOCATION = "deallocation"
    LEAK_DETECTED = "leak_detected"
    PRESSURE_HIGH = "pressure_high"
    PRESSURE_CRITICAL = "pressure_critical"
    GC_TRIGGERED = "gc_triggered"
    CACHE_EVICTION = "cache_eviction"
    POOL_EXHAUSTED = "pool_exhausted"

class MemoryPool(Generic[T]):
    """High-performance object pool for memory optimization"""
    
    def __init__(self, 
                 factory: Callable[[], T],
                 reset_func: Optional[Callable[[T], None]] = None,
                 max_size: int = 1000,
                 min_size: int = 10,
                 shrink_factor: float = 0.5):
        
        self.factory = factory
        self.reset_func = reset_func
        self.max_size = max_size
        self.min_size = min_size
        self.shrink_factor = shrink_factor
        
        # Pool storage
        self.available: deque[T] = deque()
        self.in_use: Set[int] = set()
        self.lock = threading.RLock()
        
        # Statistics
        self.stats = {
            'created': 0,
            'borrowed': 0,
            'returned': 0,
            'destroyed': 0,
            'peak_size': 0,
            'current_size': 0,
            'hits': 0,
            'misses': 0
        }
        
        # Pre-populate pool
        self._populate_pool(min_size)
    
    def _populate_pool(self, count: int):
        """Pre-populate pool with objects"""
        for _ in range(count):
            if len(self.available) < self.max_size:
                obj = self.factory()
                self.available.append(obj)
                self.stats['created'] += 1
                self.stats['current_size'] += 1
    
    def acquire(self) -> T:
        """Acquire object from pool"""
        with self.lock:
            if self.available:
                # Reuse existing object
                obj = self.available.popleft()
                self.in_use.add(id(obj))
                self.stats['borrowed'] += 1
                self.stats['hits'] += 1
                
                # Reset object if reset function provided
                if self.reset_func:
                    self.reset_func(obj)
                
                return obj
            else:
                # Create new object
                obj = self.factory()
                self.in_use.add(id(obj))
                self.stats['created'] += 1
                self.stats['borrowed'] += 1
                self.stats['misses'] += 1
                self.stats['current_size'] += 1
                
                # Update peak size
                if self.stats['current_size'] > self.stats['peak_size']:
                    self.stats['peak_size'] = self.stats['current_size']
                
                return obj
    
    def release(self, obj: T):
        """Release object back to pool"""
        with self.lock:
            obj_id = id(obj)
            
            if obj_id not in self.in_use:
                return  # Object not from this pool
            
            self.in_use.remove(obj_id)
            self.stats['returned'] += 1
            
            # Return to pool if not full
            if len(self.available) < self.max_size:
                self.available.append(obj)
            else:
                # Pool is full, destroy object
                self.stats['destroyed'] += 1
                self.stats['current_size'] -= 1
                del obj
    
    def shrink(self):
        """Shrink pool to reduce memory usage"""
        with self.lock:
            target_size = max(self.min_size, int(len(self.available) * self.shrink_factor))
            
            while len(self.available) > target_size:
                obj = self.available.pop()
                self.stats['destroyed'] += 1
                self.stats['current_size'] -= 1
                del obj
    
    def clear(self):
        """Clear all objects from pool"""
        with self.lock:
            destroyed_count = len(self.available)
            self.available.clear()
            self.in_use.clear()
            self.stats['destroyed'] += destroyed_count
            self.stats['current_size'] = 0
    
    def get_stats(self) -> Dict[str, Any]:
        """Get pool statistics"""
        with self.lock:
            hit_rate = (
                self.stats['hits'] / max(1, self.stats['hits'] + self.stats['misses']) * 100
            )
            
            return {
                **self.stats.copy(),
                'available_count': len(self.available),
                'in_use_count': len(self.in_use),
                'hit_rate': hit_rate,
                'pool_efficiency': len(self.available) / max(1, self.stats['current_size']) * 100
            }

@dataclass
class MemorySnapshot:
    """Memory usage snapshot"""
    timestamp: datetime = field(default_factory=datetime.now)
    total_memory: int = 0
    available_memory: int = 0
    used_memory: int = 0
    process_memory: int = 0
    gc_stats: Dict[str, Any] = field(default_factory=dict)
    top_allocators: List[Tuple[str, int]] = field(default_factory=list)
    
    def memory_usage_percentage(self) -> float:
        """Calculate memory usage percentage"""
        if self.total_memory > 0:
            return (self.used_memory / self.total_memory) * 100
        return 0.0

class MemoryTracker:
    """Advanced memory tracking and leak detection"""
    
    def __init__(self, enable_tracemalloc: bool = True):
        self.enable_tracemalloc = enable_tracemalloc
        self.snapshots: deque[MemorySnapshot] = deque(maxlen=1000)
        self.leak_threshold = 1.5  # 50% increase threshold
        self.monitoring = False
        self.monitor_thread: Optional[threading.Thread] = None
        
        # Object tracking
        self.tracked_objects: Dict[type, int] = defaultdict(int)
        self.object_creation_times: Dict[int, datetime] = {}
        self.potential_leaks: Set[int] = set()
        
        # Memory pressure tracking
        self.pressure_callbacks: List[Callable[[float], None]] = []
        self.last_gc_time = time.time()
        
        if enable_tracemalloc:
            tracemalloc.start()
    
    def start_monitoring(self, interval: float = 5.0):
        """Start continuous memory monitoring"""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval,),
            daemon=True
        )
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop memory monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5.0)
    
    def _monitor_loop(self, interval: float):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                snapshot = self.take_snapshot()
                self.snapshots.append(snapshot)
                
                # Check for memory pressure
                self._check_memory_pressure(snapshot)
                
                # Check for potential leaks
                self._check_for_leaks()
                
                time.sleep(interval)
                
            except Exception as e:
                print(f"Memory monitoring error: {e}")
                time.sleep(interval)
    
    def take_snapshot(self) -> MemorySnapshot:
        """Take a memory usage snapshot"""
        # System memory info
        memory_info = psutil.virtual_memory()
        process = psutil.Process()
        process_memory = process.memory_info().rss
        
        # GC statistics
        gc_stats = {
            'collections': gc.get_stats(),
            'objects': len(gc.get_objects()),
            'uncollectable': len(gc.garbage)
        }
        
        # Top memory allocators
        top_allocators = []
        if self.enable_tracemalloc and tracemalloc.is_tracing():
            current, peak = tracemalloc.get_traced_memory()
            snapshot = tracemalloc.take_snapshot()
            top_stats = snapshot.statistics('lineno')[:10]
            
            for stat in top_stats:
                filename = stat.traceback.format()[-1] if stat.traceback else "unknown"
                top_allocators.append((filename, stat.size))
        
        return MemorySnapshot(
            total_memory=memory_info.total,
            available_memory=memory_info.available,
            used_memory=memory_info.used,
            process_memory=process_memory,
            gc_stats=gc_stats,
            top_allocators=top_allocators
        )
    
    def _check_memory_pressure(self, snapshot: MemorySnapshot):
        """Check for memory pressure and trigger callbacks"""
        usage_percentage = snapshot.memory_usage_percentage()
        
        # Trigger pressure callbacks
        for callback in self.pressure_callbacks:
            try:
                callback(usage_percentage)
            except Exception:
                pass
        
        # Auto-trigger GC under pressure
        if usage_percentage > 85.0:
            current_time = time.time()
            if current_time - self.last_gc_time > 30:  # Don't GC too frequently
                gc.collect()
                self.last_gc_time = current_time
    
    def _check_for_leaks(self):
        """Check for potential memory leaks"""
        if len(self.snapshots) < 5:
            return
        
        # Compare recent snapshots
        recent_snapshots = list(self.snapshots)[-5:]
        memory_trend = []
        
        for i in range(1, len(recent_snapshots)):
            prev_memory = recent_snapshots[i-1].process_memory
            curr_memory = recent_snapshots[i].process_memory
            
            if prev_memory > 0:
                growth_rate = (curr_memory - prev_memory) / prev_memory
                memory_trend.append(growth_rate)
        
        # Check for consistent memory growth
        if memory_trend and all(growth > 0.05 for growth in memory_trend):  # 5% growth
            avg_growth = sum(memory_trend) / len(memory_trend)
            if avg_growth > 0.1:  # 10% average growth
                print(f"Potential memory leak detected: {avg_growth:.2%} average growth")
    
    def add_pressure_callback(self, callback: Callable[[float], None]):
        """Add memory pressure callback"""
        self.pressure_callbacks.append(callback)
    
    def get_memory_report(self) -> Dict[str, Any]:
        """Get comprehensive memory report"""
        if not self.snapshots:
            return {}
        
        latest = self.snapshots[-1]
        
        # Calculate trends
        if len(self.snapshots) >= 2:
            prev = self.snapshots[-2]
            memory_change = latest.process_memory - prev.process_memory
            memory_change_rate = (memory_change / prev.process_memory * 100) if prev.process_memory > 0 else 0
        else:
            memory_change = 0
            memory_change_rate = 0
        
        return {
            'current': {
                'total_memory': latest.total_memory,
                'available_memory': latest.available_memory,
                'used_memory': latest.used_memory,
                'process_memory': latest.process_memory,
                'usage_percentage': latest.memory_usage_percentage()
            },
            'trend': {
                'memory_change_bytes': memory_change,
                'memory_change_rate': memory_change_rate,
                'snapshots_count': len(self.snapshots)
            },
            'gc_info': latest.gc_stats,
            'top_allocators': latest.top_allocators[:5]
        }

class CacheManager:
    """Intelligent cache management with memory-aware eviction"""
    
    def __init__(self, 
                 max_memory_mb: int = 100,
                 eviction_policy: str = 'lru',
                 cleanup_threshold: float = 0.8):
        
        self.max_memory_bytes = max_memory_mb * 1024 * 1024
        self.eviction_policy = eviction_policy
        self.cleanup_threshold = cleanup_threshold
        
        # Cache storage
        self.cache: Dict[str, Any] = {}
        self.access_times: Dict[str, datetime] = {}
        self.access_counts: Dict[str, int] = defaultdict(int)
        self.sizes: Dict[str, int] = {}
        self.lock = threading.RLock()
        
        # Statistics
        self.stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'memory_used': 0,
            'items_count': 0
        }
    
    def get(self, key: str) -> Optional[Any]:
        """Get item from cache"""
        with self.lock:
            if key in self.cache:
                # Update access tracking
                self.access_times[key] = datetime.now()
                self.access_counts[key] += 1
                self.stats['hits'] += 1
                return self.cache[key]
            else:
                self.stats['misses'] += 1
                return None
    
    def put(self, key: str, value: Any, size_hint: Optional[int] = None):
        """Put item in cache with automatic eviction"""
        with self.lock:
            # Calculate size
            if size_hint is not None:
                size = size_hint
            else:
                size = sys.getsizeof(value)
            
            # Check if we need to evict items
            if self._should_evict(size):
                self._evict_items(size)
            
            # Store item
            if key in self.cache:
                # Update existing item
                old_size = self.sizes.get(key, 0)
                self.stats['memory_used'] -= old_size
            else:
                self.stats['items_count'] += 1
            
            self.cache[key] = value
            self.sizes[key] = size
            self.access_times[key] = datetime.now()
            self.access_counts[key] += 1
            self.stats['memory_used'] += size
    
    def _should_evict(self, new_item_size: int) -> bool:
        """Check if eviction is needed"""
        total_size_after = self.stats['memory_used'] + new_item_size
        return total_size_after > self.max_memory_bytes * self.cleanup_threshold
    
    def _evict_items(self, space_needed: int):
        """Evict items based on eviction policy"""
        if self.eviction_policy == 'lru':
            self._evict_lru(space_needed)
        elif self.eviction_policy == 'lfu':
            self._evict_lfu(space_needed)
        elif self.eviction_policy == 'size':
            self._evict_largest(space_needed)
    
    def _evict_lru(self, space_needed: int):
        """Evict least recently used items"""
        # Sort by access time (oldest first)
        sorted_items = sorted(
            self.access_times.items(),
            key=lambda x: x[1]
        )
        
        freed_space = 0
        for key, _ in sorted_items:
            if freed_space >= space_needed:
                break
            
            freed_space += self.sizes[key]
            self._remove_item(key)
    
    def _evict_lfu(self, space_needed: int):
        """Evict least frequently used items"""
        # Sort by access count (lowest first)
        sorted_items = sorted(
            self.access_counts.items(),
            key=lambda x: x[1]
        )
        
        freed_space = 0
        for key, _ in sorted_items:
            if freed_space >= space_needed:
                break
            
            freed_space += self.sizes[key]
            self._remove_item(key)
    
    def _evict_largest(self, space_needed: int):
        """Evict largest items first"""
        # Sort by size (largest first)
        sorted_items = sorted(
            self.sizes.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        freed_space = 0
        for key, size in sorted_items:
            if freed_space >= space_needed:
                break
            
            freed_space += size
            self._remove_item(key)
    
    def _remove_item(self, key: str):
        """Remove item from cache"""
        if key in self.cache:
            size = self.sizes[key]
            del self.cache[key]
            del self.sizes[key]
            del self.access_times[key]
            del self.access_counts[key]
            
            self.stats['memory_used'] -= size
            self.stats['items_count'] -= 1
            self.stats['evictions'] += 1
    
    def clear(self):
        """Clear all cached items"""
        with self.lock:
            evicted_count = len(self.cache)
            self.cache.clear()
            self.sizes.clear()
            self.access_times.clear()
            self.access_counts.clear()
            
            self.stats['memory_used'] = 0
            self.stats['items_count'] = 0
            self.stats['evictions'] += evicted_count
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self.lock:
            hit_rate = (
                self.stats['hits'] / max(1, self.stats['hits'] + self.stats['misses']) * 100
            )
            
            memory_usage_mb = self.stats['memory_used'] / (1024 * 1024)
            memory_usage_percent = (self.stats['memory_used'] / self.max_memory_bytes) * 100
            
            return {
                **self.stats.copy(),
                'hit_rate': hit_rate,
                'memory_usage_mb': memory_usage_mb,
                'memory_usage_percent': memory_usage_percent,
                'max_memory_mb': self.max_memory_bytes / (1024 * 1024)
            }

class MemoryOptimizer:
    """Main memory optimization system"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Core components
        self.tracker = MemoryTracker(
            enable_tracemalloc=self.config.get('enable_tracemalloc', True)
        )
        
        # Object pools
        self.pools: Dict[str, MemoryPool] = {}
        
        # Caches
        self.cache_manager = CacheManager(
            max_memory_mb=self.config.get('cache_memory_mb', 100),
            eviction_policy=self.config.get('cache_eviction_policy', 'lru')
        )
        
        # Memory management settings
        self.gc_threshold = self.config.get('gc_threshold', 85)  # % memory usage
        self.auto_optimize = self.config.get('auto_optimize', True)
        self.optimization_interval = self.config.get('optimization_interval', 60)  # seconds
        
        # Optimization state
        self.last_optimization = time.time()
        self.optimization_running = False
        
        # Setup memory pressure handling
        self.tracker.add_pressure_callback(self._handle_memory_pressure)
    
    def create_object_pool(self, 
                          name: str,
                          factory: Callable[[], T],
                          reset_func: Optional[Callable[[T], None]] = None,
                          max_size: int = 1000) -> MemoryPool[T]:
        """Create a new object pool"""
        pool = MemoryPool(
            factory=factory,
            reset_func=reset_func,
            max_size=max_size
        )
        
        self.pools[name] = pool
        return pool
    
    def get_object_pool(self, name: str) -> Optional[MemoryPool]:
        """Get existing object pool"""
        return self.pools.get(name)
    
    def start_monitoring(self, interval: float = 5.0):
        """Start memory monitoring"""
        self.tracker.start_monitoring(interval)
    
    def stop_monitoring(self):
        """Stop memory monitoring"""
        self.tracker.stop_monitoring()
    
    def _handle_memory_pressure(self, usage_percentage: float):
        """Handle memory pressure events"""
        if usage_percentage > self.gc_threshold:
            if self.auto_optimize:
                self.optimize_memory()
    
    def optimize_memory(self, force: bool = False):
        """Perform comprehensive memory optimization"""
        current_time = time.time()
        
        # Check if optimization is needed
        if not force and (
            current_time - self.last_optimization < self.optimization_interval or
            self.optimization_running
        ):
            return
        
        self.optimization_running = True
        self.last_optimization = current_time
        
        try:
            print("Starting memory optimization...")
            
            # 1. Garbage collection
            collected = self._force_garbage_collection()
            
            # 2. Shrink object pools
            pool_savings = self._optimize_object_pools()
            
            # 3. Cache cleanup
            cache_savings = self._optimize_caches()
            
            # 4. System-level optimization
            system_savings = self._system_level_optimization()
            
            total_savings = collected + pool_savings + cache_savings + system_savings
            
            print(f"Memory optimization complete. Freed: {total_savings / (1024*1024):.2f} MB")
            
        except Exception as e:
            print(f"Memory optimization error: {e}")
        
        finally:
            self.optimization_running = False
    
    def _force_garbage_collection(self) -> int:
        """Force comprehensive garbage collection"""
        # Get memory before GC
        process = psutil.Process()
        memory_before = process.memory_info().rss
        
        # Clear weak references
        gc.collect(0)  # Young generation
        gc.collect(1)  # Middle generation
        gc.collect(2)  # Old generation
        
        # Force finalization of unreachable objects
        gc.collect()
        
        # Get memory after GC
        memory_after = process.memory_info().rss
        freed = max(0, memory_before - memory_after)
        
        return freed
    
    def _optimize_object_pools(self) -> int:
        """Optimize object pools"""
        total_freed = 0
        
        for name, pool in self.pools.items():
            # Get current stats
            stats_before = pool.get_stats()
            
            # Shrink pool
            pool.shrink()
            
            # Calculate freed memory (estimate)
            stats_after = pool.get_stats()
            destroyed_objects = stats_after['destroyed'] - stats_before['destroyed']
            
            # Estimate memory freed (rough calculation)
            estimated_freed = destroyed_objects * 1024  # Assume 1KB per object
            total_freed += estimated_freed
        
        return total_freed
    
    def _optimize_caches(self) -> int:
        """Optimize cache memory usage"""
        # Get memory usage before
        cache_stats_before = self.cache_manager.get_stats()
        memory_before = cache_stats_before['memory_used']
        
        # Force cache cleanup to target size
        target_usage = self.cache_manager.max_memory_bytes * 0.5  # 50% of max
        
        if memory_before > target_usage:
            # Calculate how much to free
            space_to_free = int(memory_before - target_usage)
            self.cache_manager._evict_items(space_to_free)
        
        # Get memory usage after
        cache_stats_after = self.cache_manager.get_stats()
        memory_after = cache_stats_after['memory_used']
        
        return max(0, memory_before - memory_after)
    
    def _system_level_optimization(self) -> int:
        """System-level memory optimization"""
        freed = 0
        
        try:
            # Platform-specific optimizations
            if sys.platform == 'linux':
                freed += self._linux_memory_optimization()
            elif sys.platform == 'win32':
                freed += self._windows_memory_optimization()
            elif sys.platform == 'darwin':
                freed += self._macos_memory_optimization()
        
        except Exception as e:
            print(f"System-level optimization error: {e}")
        
        return freed
    
    def _linux_memory_optimization(self) -> int:
        """Linux-specific memory optimization"""
        try:
            # Try to trim malloc arena
            libc = ctypes.CDLL("libc.so.6")
            libc.malloc_trim(0)
            return 1024 * 1024  # Estimate 1MB freed
        except:
            return 0
    
    def _windows_memory_optimization(self) -> int:
        """Windows-specific memory optimization"""
        try:
            # Minimize working set
            import ctypes.wintypes
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            handle = kernel32.GetCurrentProcess()
            kernel32.SetProcessWorkingSetSize(handle, -1, -1)
            return 1024 * 1024  # Estimate 1MB freed
        except:
            return 0
    
    def _macos_memory_optimization(self) -> int:
        """macOS-specific memory optimization"""
        # macOS handles memory pressure automatically
        return 0
    
    def get_comprehensive_report(self) -> Dict[str, Any]:
        """Get comprehensive memory report"""
        # Basic memory report
        memory_report = self.tracker.get_memory_report()
        
        # Object pool stats
        pool_stats = {}
        for name, pool in self.pools.items():
            pool_stats[name] = pool.get_stats()
        
        # Cache stats
        cache_stats = self.cache_manager.get_stats()
        
        # System info
        process = psutil.Process()
        system_memory = psutil.virtual_memory()
        
        return {
            'timestamp': datetime.now().isoformat(),
            'system': {
                'total_memory': system_memory.total,
                'available_memory': system_memory.available,
                'memory_usage_percent': system_memory.percent,
                'process_memory': process.memory_info().rss,
                'process_memory_percent': process.memory_percent()
            },
            'tracking': memory_report,
            'object_pools': pool_stats,
            'cache': cache_stats,
            'optimization': {
                'last_optimization': self.last_optimization,
                'auto_optimize': self.auto_optimize,
                'gc_threshold': self.gc_threshold
            }
        }
    
    def export_memory_profile(self, filename: str):
        """Export detailed memory profile"""
        if not self.tracker.enable_tracemalloc or not tracemalloc.is_tracing():
            print("Tracemalloc not enabled, cannot export profile")
            return
        
        snapshot = tracemalloc.take_snapshot()
        
        # Group by filename
        top_stats = snapshot.statistics('filename')
        
        with open(filename, 'w') as f:
            f.write("Memory Profile Report\n")
            f.write("=" * 50 + "\n\n")
            
            f.write(f"Generated: {datetime.now()}\n")
            f.write(f"Total memory traced: {sum(stat.size for stat in top_stats)} bytes\n\n")
            
            f.write("Top 20 files by memory usage:\n")
            f.write("-" * 50 + "\n")
            
            for index, stat in enumerate(top_stats[:20], 1):
                f.write(f"{index:2d}. {stat.traceback.format()[-1]}\n")
                f.write(f"    Size: {stat.size} bytes ({stat.count} allocations)\n\n")
    
    def cleanup(self):
        """Cleanup memory optimizer"""
        self.stop_monitoring()
        
        # Clear all pools
        for pool in self.pools.values():
            pool.clear()
        
        # Clear cache
        self.cache_manager.clear()
        
        # Final GC
        gc.collect()

# Global memory optimizer instance
_memory_optimizer: Optional[MemoryOptimizer] = None

def get_memory_optimizer(config: Dict[str, Any] = None) -> MemoryOptimizer:
    """Get or create global memory optimizer"""
    global _memory_optimizer
    
    if _memory_optimizer is None:
        _memory_optimizer = MemoryOptimizer(config)
    
    return _memory_optimizer

# Context manager for memory tracking
class memory_profiler:
    """Context manager for profiling memory usage"""
    
    def __init__(self, name: str = "operation"):
        self.name = name
        self.start_memory = 0
        self.end_memory = 0
    
    def __enter__(self):
        self.start_memory = psutil.Process().memory_info().rss
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end_memory = psutil.Process().memory_info().rss
        memory_diff = self.end_memory - self.start_memory
        
        print(f"Memory profile [{self.name}]: {memory_diff / (1024*1024):.2f} MB")

# Export main classes and functions
__all__ = [
    'MemoryPool', 'MemoryTracker', 'MemorySnapshot', 'CacheManager',
    'MemoryOptimizer', 'MemoryEventType', 'get_memory_optimizer', 'memory_profiler'
]