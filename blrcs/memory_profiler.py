# BLRCS Memory Profiler Module
# Advanced memory leak detection and analysis
import gc
import sys
import time
import tracemalloc
import threading
import weakref
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass
from collections import defaultdict
import psutil

@dataclass
class MemorySnapshot:
    """Memory usage snapshot"""
    timestamp: float
    rss_mb: float
    vms_mb: float
    percent: float
    available_mb: float
    gc_counts: Tuple[int, int, int]
    object_counts: Dict[str, int]
    tracemalloc_size: int = 0
    tracemalloc_peak: int = 0

@dataclass
class MemoryLeak:
    """Memory leak detection result"""
    location: str
    size_mb: float
    growth_rate: float
    trace: List[str]
    detected_at: float

class ObjectTracker:
    """Track object creation and deletion"""
    
    def __init__(self):
        self.objects: Dict[type, Set[int]] = defaultdict(set)
        self.creation_traces: Dict[int, List[str]] = {}
        self.lock = threading.Lock()
    
    def track_object(self, obj: Any):
        """Start tracking an object"""
        obj_type = type(obj)
        obj_id = id(obj)
        
        with self.lock:
            self.objects[obj_type].add(obj_id)
            self.creation_traces[obj_id] = traceback.format_stack()
    
    def untrack_object(self, obj: Any):
        """Stop tracking an object"""
        obj_type = type(obj)
        obj_id = id(obj)
        
        with self.lock:
            self.objects[obj_type].discard(obj_id)
            self.creation_traces.pop(obj_id, None)
    
    def get_tracked_counts(self) -> Dict[str, int]:
        """Get count of tracked objects by type"""
        with self.lock:
            return {
                f"{cls.__module__}.{cls.__name__}": len(ids)
                for cls, ids in self.objects.items()
            }
    
    def get_leaked_objects(self, threshold: int = 100) -> List[Tuple[str, int, List[str]]]:
        """Get potentially leaked objects"""
        leaked = []
        
        with self.lock:
            for obj_type, obj_ids in self.objects.items():
                if len(obj_ids) > threshold:
                    # Get sample trace
                    sample_id = next(iter(obj_ids))
                    trace = self.creation_traces.get(sample_id, [])
                    
                    leaked.append((
                        f"{obj_type.__module__}.{obj_type.__name__}",
                        len(obj_ids),
                        trace
                    ))
        
        return leaked

class MemoryProfiler:
    """
    Advanced memory profiler with leak detection.
    Tracks memory usage patterns and identifies leaks.
    """
    
    def __init__(self, check_interval: float = 30.0,
                 snapshot_limit: int = 1000):
        """
        Initialize memory profiler.
        
        Args:
            check_interval: Seconds between memory checks
            snapshot_limit: Maximum number of snapshots to keep
        """
        self.check_interval = check_interval
        self.snapshot_limit = snapshot_limit
        
        # Memory snapshots
        self.snapshots: List[MemorySnapshot] = []
        
        # Leak detection
        self.detected_leaks: List[MemoryLeak] = []
        self.leak_threshold_mb = 10.0  # MB growth for leak detection
        self.leak_duration = 300.0  # 5 minutes
        
        # Object tracking
        self.object_tracker = ObjectTracker()
        
        # Process tracking
        self.process = psutil.Process()
        
        # Monitoring state
        self.running = False
        self.thread: Optional[threading.Thread] = None
        
        # Tracemalloc
        self.tracemalloc_enabled = False
    
    def enable_tracemalloc(self):
        """Enable Python memory tracing"""
        if not self.tracemalloc_enabled:
            tracemalloc.start()
            self.tracemalloc_enabled = True
    
    def disable_tracemalloc(self):
        """Disable Python memory tracing"""
        if self.tracemalloc_enabled:
            tracemalloc.stop()
            self.tracemalloc_enabled = False
    
    def take_snapshot(self) -> MemorySnapshot:
        """Take current memory snapshot"""
        # Process memory info
        memory_info = self.process.memory_info()
        virtual_memory = psutil.virtual_memory()
        
        # GC stats
        gc_counts = gc.get_count()
        
        # Object counts
        object_counts = {}
        
        # Count objects by type
        for obj in gc.get_objects():
            obj_type = type(obj).__name__
            object_counts[obj_type] = object_counts.get(obj_type, 0) + 1
        
        # Add tracked objects
        tracked_counts = self.object_tracker.get_tracked_counts()
        for obj_type, count in tracked_counts.items():
            object_counts[f"tracked_{obj_type}"] = count
        
        # Tracemalloc info
        tracemalloc_size = 0
        tracemalloc_peak = 0
        
        if self.tracemalloc_enabled:
            current, peak = tracemalloc.get_traced_memory()
            tracemalloc_size = current
            tracemalloc_peak = peak
        
        return MemorySnapshot(
            timestamp=time.time(),
            rss_mb=memory_info.rss / 1024 / 1024,
            vms_mb=memory_info.vms / 1024 / 1024,
            percent=self.process.memory_percent(),
            available_mb=virtual_memory.available / 1024 / 1024,
            gc_counts=gc_counts,
            object_counts=object_counts,
            tracemalloc_size=tracemalloc_size,
            tracemalloc_peak=tracemalloc_peak
        )
    
    def add_snapshot(self, snapshot: MemorySnapshot):
        """Add snapshot to history"""
        self.snapshots.append(snapshot)
        
        # Limit snapshots
        if len(self.snapshots) > self.snapshot_limit:
            self.snapshots.pop(0)
        
        # Check for leaks
        self._check_for_leaks(snapshot)
    
    def _check_for_leaks(self, current: MemorySnapshot):
        """Check for memory leaks"""
        if len(self.snapshots) < 2:
            return
        
        # Find snapshots from leak_duration ago
        cutoff_time = current.timestamp - self.leak_duration
        old_snapshots = [
            s for s in self.snapshots
            if s.timestamp >= cutoff_time
        ]
        
        if not old_snapshots:
            return
        
        oldest = old_snapshots[0]
        
        # Check memory growth
        memory_growth = current.rss_mb - oldest.rss_mb
        
        if memory_growth > self.leak_threshold_mb:
            # Potential leak detected
            growth_rate = memory_growth / (current.timestamp - oldest.timestamp)
            
            # Get stack trace if tracemalloc is enabled
            trace = []
            
            if self.tracemalloc_enabled:
                snapshot = tracemalloc.take_snapshot()
                top_stats = snapshot.statistics('lineno')
                
                for stat in top_stats[:10]:
                    trace.append(f"{stat.traceback.format()}: {stat.size / 1024 / 1024:.2f} MB")
            
            leak = MemoryLeak(
                location="Unknown",
                size_mb=memory_growth,
                growth_rate=growth_rate,
                trace=trace,
                detected_at=current.timestamp
            )
            
            self.detected_leaks.append(leak)
    
    def start_monitoring(self):
        """Start background memory monitoring"""
        if self.running:
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.thread.start()
    
    def stop_monitoring(self):
        """Stop background monitoring"""
        self.running = False
        
        if self.thread:
            self.thread.join(timeout=1)
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                snapshot = self.take_snapshot()
                self.add_snapshot(snapshot)
                
                # Trigger GC occasionally
                if len(self.snapshots) % 10 == 0:
                    gc.collect()
                
            except Exception:
                pass
            
            time.sleep(self.check_interval)
    
    def get_memory_trend(self, duration: float = 3600) -> Dict[str, Any]:
        """Get memory usage trend over duration (seconds)"""
        cutoff_time = time.time() - duration
        recent_snapshots = [
            s for s in self.snapshots
            if s.timestamp >= cutoff_time
        ]
        
        if len(recent_snapshots) < 2:
            return {}
        
        first = recent_snapshots[0]
        last = recent_snapshots[-1]
        
        # Calculate trends
        time_diff = last.timestamp - first.timestamp
        memory_diff = last.rss_mb - first.rss_mb
        
        return {
            'duration_minutes': time_diff / 60,
            'memory_change_mb': memory_diff,
            'growth_rate_mb_per_hour': (memory_diff / time_diff) * 3600 if time_diff > 0 else 0,
            'average_memory_mb': sum(s.rss_mb for s in recent_snapshots) / len(recent_snapshots),
            'peak_memory_mb': max(s.rss_mb for s in recent_snapshots),
            'current_memory_mb': last.rss_mb
        }
    
    def get_object_growth(self, duration: float = 3600) -> Dict[str, int]:
        """Get object count growth over duration"""
        cutoff_time = time.time() - duration
        recent_snapshots = [
            s for s in self.snapshots
            if s.timestamp >= cutoff_time
        ]
        
        if len(recent_snapshots) < 2:
            return {}
        
        first = recent_snapshots[0]
        last = recent_snapshots[-1]
        
        growth = {}
        
        for obj_type in set(first.object_counts.keys()) | set(last.object_counts.keys()):
            first_count = first.object_counts.get(obj_type, 0)
            last_count = last.object_counts.get(obj_type, 0)
            change = last_count - first_count
            
            if abs(change) > 10:  # Only significant changes
                growth[obj_type] = change
        
        return growth
    
    def analyze_leaks(self) -> Dict[str, Any]:
        """Analyze detected memory leaks"""
        if not self.detected_leaks:
            return {'status': 'no_leaks', 'leaks': []}
        
        # Group leaks by location
        leak_groups = defaultdict(list)
        
        for leak in self.detected_leaks:
            leak_groups[leak.location].append(leak)
        
        analysis = {
            'status': 'leaks_detected',
            'total_leaks': len(self.detected_leaks),
            'leak_groups': {},
            'recommendations': []
        }
        
        for location, leaks in leak_groups.items():
            total_size = sum(leak.size_mb for leak in leaks)
            avg_growth_rate = sum(leak.growth_rate for leak in leaks) / len(leaks)
            
            analysis['leak_groups'][location] = {
                'count': len(leaks),
                'total_size_mb': total_size,
                'avg_growth_rate': avg_growth_rate,
                'latest_trace': leaks[-1].trace
            }
        
        # Generate recommendations
        if analysis['total_leaks'] > 5:
            analysis['recommendations'].append("High number of leaks detected - review object lifecycle management")
        
        if any(group['total_size_mb'] > 50 for group in analysis['leak_groups'].values()):
            analysis['recommendations'].append("Large memory leaks detected - immediate investigation required")
        
        return analysis
    
    def fix_memory_issues(self) -> Dict[str, Any]:
        """Attempt to fix common memory issues"""
        fixes_applied = []
        
        # Force garbage collection
        collected = gc.collect()
        if collected > 0:
            fixes_applied.append(f"Garbage collected {collected} objects")
        
        # Clear weak references
        weakref.finalize(lambda: None, lambda: None)
        
        # Clear module caches if safe
        if hasattr(sys, '_clear_type_cache'):
            sys._clear_type_cache()
            fixes_applied.append("Cleared type cache")
        
        # Clear import cache selectively
        modules_to_clear = [
            name for name in sys.modules.keys()
            if name.startswith('__pycache__')
        ]
        
        for module_name in modules_to_clear:
            del sys.modules[module_name]
        
        if modules_to_clear:
            fixes_applied.append(f"Cleared {len(modules_to_clear)} cached modules")
        
        return {
            'fixes_applied': fixes_applied,
            'objects_collected': collected
        }
    
    def export_report(self, file_path: Path):
        """Export detailed memory analysis report"""
        report = {
            'timestamp': time.time(),
            'snapshots_count': len(self.snapshots),
            'monitoring_duration': (
                self.snapshots[-1].timestamp - self.snapshots[0].timestamp
                if self.snapshots else 0
            ),
            'memory_trend': self.get_memory_trend(),
            'object_growth': self.get_object_growth(),
            'leak_analysis': self.analyze_leaks(),
            'recent_snapshots': [
                {
                    'timestamp': s.timestamp,
                    'rss_mb': s.rss_mb,
                    'object_counts': dict(list(s.object_counts.items())[:20])  # Top 20
                }
                for s in self.snapshots[-10:]  # Last 10 snapshots
            ]
        }
        
        with open(file_path, 'w') as f:
            import json
            json.dump(report, f, indent=2, default=str)

# Global memory profiler
_memory_profiler: Optional[MemoryProfiler] = None

def get_memory_profiler() -> MemoryProfiler:
    """Get global memory profiler instance"""
    global _memory_profiler
    
    if _memory_profiler is None:
        _memory_profiler = MemoryProfiler()
    
    return _memory_profiler

def start_memory_monitoring():
    """Start memory monitoring"""
    profiler = get_memory_profiler()
    profiler.enable_tracemalloc()
    profiler.start_monitoring()

def check_memory_health() -> Dict[str, Any]:
    """Quick memory health check"""
    profiler = get_memory_profiler()
    
    # Take snapshot
    snapshot = profiler.take_snapshot()
    
    # Basic analysis
    health = {
        'current_memory_mb': snapshot.rss_mb,
        'memory_percent': snapshot.percent,
        'available_memory_mb': snapshot.available_mb,
        'gc_objects': sum(snapshot.gc_counts),
        'status': 'healthy'
    }
    
    # Health checks
    if snapshot.percent > 80:
        health['status'] = 'warning'
        health['issues'] = ['High memory usage']
    
    if snapshot.rss_mb > 1000:  # > 1GB
        health['status'] = 'critical'
        health['issues'] = health.get('issues', []) + ['Very high memory usage']
    
    return health