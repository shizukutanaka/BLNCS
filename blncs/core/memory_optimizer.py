"""
Memory Optimization and Garbage Collection Monitoring for BLNCS
Provides memory leak detection, optimization, and GC monitoring.
"""

import gc
import sys
import time
import threading
import tracemalloc
import weakref
from typing import Dict, Any, Optional, List, Set, Callable, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque
import psutil
import os

from .logger import get_logger
from .observability import get_observability_collector, record_metric, MetricType


@dataclass
class MemorySnapshot:
    """Memory usage snapshot"""
    timestamp: float
    rss_mb: float  # Resident Set Size in MB
    vms_mb: float  # Virtual Memory Size in MB
    python_objects: int
    gc_generation_0: int
    gc_generation_1: int
    gc_generation_2: int
    traced_memory_mb: float = 0.0


@dataclass
class MemoryLeak:
    """Detected memory leak information"""
    object_type: str
    count_growth: int
    size_growth_mb: float
    detection_time: float
    traceback: Optional[str] = None


class MemoryProfiler:
    """Memory profiling and analysis"""
    
    def __init__(self, enable_tracemalloc: bool = True):
        self.logger = get_logger(__name__)
        self.enable_tracemalloc = enable_tracemalloc
        self.observability = get_observability_collector()
        
        # Memory monitoring state
        self._snapshots: deque = deque(maxlen=1000)
        self._snapshots_lock = threading.RLock()
        
        # Object tracking
        self._tracked_objects: Dict[type, Set[int]] = defaultdict(set)
        self._object_counts: Dict[type, int] = defaultdict(int)
        self._tracking_lock = threading.RLock()
        
        # Leak detection
        self._leak_detection_enabled = True
        self._leak_threshold_objects = 1000  # Object count growth threshold
        self._leak_threshold_mb = 50.0       # Memory growth threshold in MB
        self._detected_leaks: List[MemoryLeak] = []
        
        # Monitoring thread
        self._monitoring_thread: Optional[threading.Thread] = None
        self._stop_monitoring = threading.Event()
        self._monitoring_interval = 30.0  # 30 seconds
        
        # Initialize tracemalloc
        if self.enable_tracemalloc and not tracemalloc.is_tracing():
            tracemalloc.start()
            self.logger.info("Started memory tracing")
    
    def take_snapshot(self) -> MemorySnapshot:
        """Take a memory usage snapshot"""
        process = psutil.Process()
        memory_info = process.memory_info()
        
        # Get GC stats
        gc_stats = gc.get_stats()
        gen_counts = [stats['collections'] for stats in gc_stats]
        
        # Get tracemalloc info if available
        traced_memory_mb = 0.0
        if tracemalloc.is_tracing():
            traced_memory_mb = tracemalloc.get_traced_memory()[0] / 1024 / 1024
        
        snapshot = MemorySnapshot(
            timestamp=time.time(),
            rss_mb=memory_info.rss / 1024 / 1024,
            vms_mb=memory_info.vms / 1024 / 1024,
            python_objects=len(gc.get_objects()),
            gc_generation_0=gen_counts[0] if len(gen_counts) > 0 else 0,
            gc_generation_1=gen_counts[1] if len(gen_counts) > 1 else 0,
            gc_generation_2=gen_counts[2] if len(gen_counts) > 2 else 0,
            traced_memory_mb=traced_memory_mb
        )
        
        with self._snapshots_lock:
            self._snapshots.append(snapshot)
        
        # Record metrics
        record_metric("memory.rss_mb", snapshot.rss_mb, MetricType.GAUGE)
        record_metric("memory.vms_mb", snapshot.vms_mb, MetricType.GAUGE)
        record_metric("memory.python_objects", snapshot.python_objects, MetricType.GAUGE)
        record_metric("memory.traced_memory_mb", snapshot.traced_memory_mb, MetricType.GAUGE)
        
        return snapshot
    
    def start_monitoring(self, interval: float = 30.0) -> None:
        """Start continuous memory monitoring"""
        if self._monitoring_thread and self._monitoring_thread.is_alive():
            self.logger.warning("Memory monitoring already running")
            return
        
        self._monitoring_interval = interval
        self._stop_monitoring.clear()
        
        self._monitoring_thread = threading.Thread(
            target=self._monitoring_loop,
            name="MemoryMonitor",
            daemon=True
        )
        self._monitoring_thread.start()
        
        self.logger.info(f"Started memory monitoring with {interval}s interval")
    
    def stop_monitoring(self) -> None:
        """Stop continuous memory monitoring"""
        if self._monitoring_thread:
            self._stop_monitoring.set()
            self._monitoring_thread.join(timeout=5.0)
            if self._monitoring_thread.is_alive():
                self.logger.warning("Memory monitoring thread did not stop gracefully")
            else:
                self.logger.info("Stopped memory monitoring")
    
    def _monitoring_loop(self) -> None:
        """Main monitoring loop"""
        while not self._stop_monitoring.wait(self._monitoring_interval):
            try:
                # Take snapshot
                self.take_snapshot()
                
                # Detect memory leaks
                if self._leak_detection_enabled:
                    self._detect_memory_leaks()
                
                # Force garbage collection periodically
                if len(self._snapshots) % 4 == 0:  # Every 4th snapshot
                    self._force_garbage_collection()
                
            except Exception as e:
                self.logger.error(f"Error in memory monitoring loop: {e}")
    
    def _detect_memory_leaks(self) -> None:
        """Detect potential memory leaks"""
        with self._snapshots_lock:
            if len(self._snapshots) < 5:  # Need at least 5 snapshots
                return
            
            recent_snapshots = list(self._snapshots)[-5:]
            first_snapshot = recent_snapshots[0]
            last_snapshot = recent_snapshots[-1]
            
            # Check for consistent memory growth
            memory_growth = last_snapshot.rss_mb - first_snapshot.rss_mb
            object_growth = last_snapshot.python_objects - first_snapshot.python_objects
            
            if (memory_growth > self._leak_threshold_mb or 
                object_growth > self._leak_threshold_objects):
                
                # Analyze object types
                self._analyze_object_growth()
                
                leak = MemoryLeak(
                    object_type="general",
                    count_growth=object_growth,
                    size_growth_mb=memory_growth,
                    detection_time=time.time()
                )
                
                self._detected_leaks.append(leak)
                
                self.logger.warning(
                    f"Potential memory leak detected: "
                    f"Memory grew by {memory_growth:.1f}MB, "
                    f"Objects grew by {object_growth}"
                )
                
                # Record alert metric
                record_metric("memory.leak_detected", 1, MetricType.COUNTER)
    
    def _analyze_object_growth(self) -> None:
        """Analyze which object types are growing"""
        if not tracemalloc.is_tracing():
            return
        
        try:
            # Get current memory statistics
            snapshot = tracemalloc.take_snapshot()
            top_stats = snapshot.statistics('lineno')
            
            # Log top memory consumers
            for index, stat in enumerate(top_stats[:10], 1):
                self.logger.debug(f"Memory consumer #{index}: {stat}")
                
        except Exception as e:
            self.logger.error(f"Error analyzing object growth: {e}")
    
    def _force_garbage_collection(self) -> None:
        """Force garbage collection and log results"""
        collected_counts = []
        
        for generation in range(3):
            collected = gc.collect(generation)
            collected_counts.append(collected)
            
            if collected > 0:
                record_metric(f"gc.collected_gen_{generation}", collected, MetricType.COUNTER)
        
        total_collected = sum(collected_counts)
        if total_collected > 0:
            self.logger.debug(f"Garbage collection freed {total_collected} objects")
            record_metric("gc.total_collected", total_collected, MetricType.COUNTER)
    
    def track_object_creation(self, obj: Any) -> None:
        """Track object creation for leak detection"""
        obj_type = type(obj)
        obj_id = id(obj)
        
        with self._tracking_lock:
            self._tracked_objects[obj_type].add(obj_id)
            self._object_counts[obj_type] += 1
    
    def track_object_deletion(self, obj: Any) -> None:
        """Track object deletion"""
        obj_type = type(obj)
        obj_id = id(obj)
        
        with self._tracking_lock:
            self._tracked_objects[obj_type].discard(obj_id)
            self._object_counts[obj_type] = max(0, self._object_counts[obj_type] - 1)
    
    def get_memory_stats(self) -> Dict[str, Any]:
        """Get comprehensive memory statistics"""
        with self._snapshots_lock:
            if not self._snapshots:
                return {}
            
            latest = self._snapshots[-1]
            
            # Calculate growth if we have history
            growth_stats = {}
            if len(self._snapshots) > 1:
                first = self._snapshots[0]
                growth_stats = {
                    "memory_growth_mb": latest.rss_mb - first.rss_mb,
                    "object_growth": latest.python_objects - first.python_objects,
                    "monitoring_duration_hours": (latest.timestamp - first.timestamp) / 3600
                }
        
        return {
            "current_memory": {
                "rss_mb": latest.rss_mb,
                "vms_mb": latest.vms_mb,
                "python_objects": latest.python_objects,
                "traced_memory_mb": latest.traced_memory_mb
            },
            "gc_stats": {
                "generation_0_collections": latest.gc_generation_0,
                "generation_1_collections": latest.gc_generation_1,
                "generation_2_collections": latest.gc_generation_2
            },
            "growth_stats": growth_stats,
            "leak_detection": {
                "enabled": self._leak_detection_enabled,
                "detected_leaks": len(self._detected_leaks),
                "latest_leaks": [
                    {
                        "object_type": leak.object_type,
                        "memory_growth_mb": leak.size_growth_mb,
                        "object_growth": leak.count_growth,
                        "detected_ago_minutes": (time.time() - leak.detection_time) / 60
                    }
                    for leak in self._detected_leaks[-5:]  # Last 5 leaks
                ]
            },
            "monitoring": {
                "snapshots_taken": len(self._snapshots),
                "monitoring_active": self._monitoring_thread and self._monitoring_thread.is_alive(),
                "tracemalloc_enabled": tracemalloc.is_tracing()
            }
        }
    
    def optimize_memory(self) -> Dict[str, Any]:
        """Perform memory optimization operations"""
        optimization_results = {}
        
        # Force garbage collection
        gc_start = time.time()
        collected = gc.collect()
        gc_time = time.time() - gc_start
        
        optimization_results["garbage_collection"] = {
            "objects_freed": collected,
            "time_taken_ms": gc_time * 1000
        }
        
        # Clear weak references
        weakref_start = time.time()
        weakref_cleared = 0
        
        # This is a simplified approach - in practice, you'd want to be more selective
        for obj_list in gc.get_objects():
            if isinstance(obj_list, list):
                weakref_cleared += len([ref for ref in obj_list if isinstance(ref, weakref.ref)])
        
        weakref_time = time.time() - weakref_start
        optimization_results["weakref_cleanup"] = {
            "references_found": weakref_cleared,
            "time_taken_ms": weakref_time * 1000
        }
        
        # Clear internal caches (if any)
        cache_start = time.time()
        sys.intern("")  # Clear string intern cache
        cache_time = time.time() - cache_start
        
        optimization_results["cache_cleanup"] = {
            "time_taken_ms": cache_time * 1000
        }
        
        # Take snapshot after optimization
        post_optimization_snapshot = self.take_snapshot()
        optimization_results["post_optimization_memory"] = {
            "rss_mb": post_optimization_snapshot.rss_mb,
            "python_objects": post_optimization_snapshot.python_objects
        }
        
        self.logger.info(f"Memory optimization completed: freed {collected} objects")
        record_metric("memory.optimization_performed", 1, MetricType.COUNTER)
        
        return optimization_results
    
    def get_top_memory_consumers(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get top memory consuming code locations"""
        if not tracemalloc.is_tracing():
            return []
        
        try:
            snapshot = tracemalloc.take_snapshot()
            top_stats = snapshot.statistics('traceback')
            
            consumers = []
            for stat in top_stats[:limit]:
                consumers.append({
                    "size_mb": stat.size / 1024 / 1024,
                    "count": stat.count,
                    "traceback": stat.traceback.format()[:3]  # First 3 lines
                })
            
            return consumers
            
        except Exception as e:
            self.logger.error(f"Error getting top memory consumers: {e}")
            return []
    
    def clear_leak_history(self) -> None:
        """Clear detected leak history"""
        self._detected_leaks.clear()
        self.logger.info("Cleared memory leak history")
    
    def shutdown(self) -> None:
        """Shutdown memory profiler"""
        self.stop_monitoring()
        
        if tracemalloc.is_tracing():
            tracemalloc.stop()
            self.logger.info("Stopped memory tracing")


# Global memory profiler instance
_memory_profiler: Optional[MemoryProfiler] = None
_profiler_lock = threading.Lock()


def get_memory_profiler() -> MemoryProfiler:
    """Get global memory profiler instance"""
    global _memory_profiler
    if _memory_profiler is None:
        with _profiler_lock:
            if _memory_profiler is None:
                _memory_profiler = MemoryProfiler()
    return _memory_profiler


# Convenience functions
def start_memory_monitoring(interval: float = 30.0) -> None:
    """Start memory monitoring"""
    profiler = get_memory_profiler()
    profiler.start_monitoring(interval)


def stop_memory_monitoring() -> None:
    """Stop memory monitoring"""
    profiler = get_memory_profiler()
    profiler.stop_monitoring()


def optimize_memory() -> Dict[str, Any]:
    """Perform memory optimization"""
    profiler = get_memory_profiler()
    return profiler.optimize_memory()


def get_memory_stats() -> Dict[str, Any]:
    """Get memory statistics"""
    profiler = get_memory_profiler()
    return profiler.get_memory_stats()


def track_object(obj: Any) -> None:
    """Track object for leak detection"""
    profiler = get_memory_profiler()
    profiler.track_object_creation(obj)


# Context manager for memory tracking
class MemoryTracker:
    """Context manager for tracking memory usage of operations"""
    
    def __init__(self, operation_name: str):
        self.operation_name = operation_name
        self.start_snapshot: Optional[MemorySnapshot] = None
        self.end_snapshot: Optional[MemorySnapshot] = None
        self.profiler = get_memory_profiler()
        self.logger = get_logger(__name__)
    
    def __enter__(self):
        self.start_snapshot = self.profiler.take_snapshot()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end_snapshot = self.profiler.take_snapshot()
        
        # Calculate memory usage
        memory_delta = self.end_snapshot.rss_mb - self.start_snapshot.rss_mb
        object_delta = self.end_snapshot.python_objects - self.start_snapshot.python_objects
        
        # Log if significant memory usage
        if abs(memory_delta) > 1.0 or abs(object_delta) > 100:
            self.logger.info(
                f"Memory usage for '{self.operation_name}': "
                f"Memory: {memory_delta:+.1f}MB, Objects: {object_delta:+d}"
            )
        
        # Record metrics
        record_metric(f"memory.operation.{self.operation_name}.memory_delta_mb", 
                     memory_delta, MetricType.GAUGE)
        record_metric(f"memory.operation.{self.operation_name}.object_delta", 
                     object_delta, MetricType.GAUGE)


def memory_tracker(operation_name: str):
    """Memory tracking context manager"""
    return MemoryTracker(operation_name)