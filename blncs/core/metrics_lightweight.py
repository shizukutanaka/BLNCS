"""
Lightweight Metrics System for BLNCS
Simple metrics collection and reporting without heavy dependencies.
"""

import time
import threading
import json
import os
from typing import Dict, Any, List, Optional
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path

@dataclass
class MetricPoint:
    """Individual metric measurement"""
    name: str
    value: float
    timestamp: float
    tags: Dict[str, str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'value': self.value,
            'timestamp': self.timestamp,
            'tags': self.tags or {}
        }

class LightweightMetricsCollector:
    """Lightweight metrics collector using only standard library"""
    
    def __init__(self, max_points: int = 10000):
        self.max_points = max_points
        self.metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.counters: Dict[str, float] = defaultdict(float)
        self.gauges: Dict[str, float] = {}
        self.timers: Dict[str, List[float]] = defaultdict(list)
        self.lock = threading.Lock()
        
        # System metrics tracking
        self._start_time = time.time()
        self._last_cleanup = time.time()
        
    def counter(self, name: str, value: float = 1, tags: Dict[str, str] = None):
        """Record counter metric"""
        with self.lock:
            self.counters[name] += value
            self.metrics[name].append(MetricPoint(name, self.counters[name], time.time(), tags))
    
    def gauge(self, name: str, value: float, tags: Dict[str, str] = None):
        """Record gauge metric"""
        with self.lock:
            self.gauges[name] = value
            self.metrics[name].append(MetricPoint(name, value, time.time(), tags))
    
    def timer(self, name: str, value: float, tags: Dict[str, str] = None):
        """Record timer metric (duration in seconds)"""
        with self.lock:
            self.timers[name].append(value)
            # Keep only last 100 timer values
            if len(self.timers[name]) > 100:
                self.timers[name] = self.timers[name][-50:]
            
            self.metrics[name].append(MetricPoint(name, value, time.time(), tags))
    
    def histogram(self, name: str, value: float, tags: Dict[str, str] = None):
        """Record histogram metric (alias for timer)"""
        self.timer(name, value, tags)
    
    def increment(self, name: str, tags: Dict[str, str] = None):
        """Increment counter by 1"""
        self.counter(name, 1, tags)
    
    def decrement(self, name: str, tags: Dict[str, str] = None):
        """Decrement counter by 1"""
        self.counter(name, -1, tags)
    
    def timing_context(self, name: str, tags: Dict[str, str] = None):
        """Context manager for timing operations"""
        return TimingContext(self, name, tags)
    
    def get_counter_value(self, name: str) -> float:
        """Get current counter value"""
        return self.counters.get(name, 0)
    
    def get_gauge_value(self, name: str) -> float:
        """Get current gauge value"""
        return self.gauges.get(name, 0)
    
    def get_timer_stats(self, name: str) -> Dict[str, float]:
        """Get timer statistics"""
        with self.lock:
            values = self.timers.get(name, [])
            if not values:
                return {'count': 0, 'avg': 0, 'min': 0, 'max': 0}
            
            return {
                'count': len(values),
                'avg': sum(values) / len(values),
                'min': min(values),
                'max': max(values),
                'total': sum(values)
            }
    
    def get_all_metrics(self) -> Dict[str, Any]:
        """Get all current metrics"""
        with self.lock:
            result = {
                'counters': dict(self.counters),
                'gauges': dict(self.gauges),
                'timers': {}
            }
            
            for name in self.timers:
                result['timers'][name] = self.get_timer_stats(name)
            
            return result
    
    def get_metric_history(self, name: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get metric history"""
        with self.lock:
            points = list(self.metrics.get(name, []))[-limit:]
            return [point.to_dict() for point in points]
    
    def reset_metric(self, name: str):
        """Reset a specific metric"""
        with self.lock:
            if name in self.counters:
                del self.counters[name]
            if name in self.gauges:
                del self.gauges[name]
            if name in self.timers:
                del self.timers[name]
            if name in self.metrics:
                del self.metrics[name]
    
    def reset_all(self):
        """Reset all metrics"""
        with self.lock:
            self.counters.clear()
            self.gauges.clear()
            self.timers.clear()
            self.metrics.clear()
    
    def export_json(self, file_path: str = None) -> str:
        """Export metrics to JSON"""
        data = {
            'timestamp': time.time(),
            'uptime_seconds': time.time() - self._start_time,
            'metrics': self.get_all_metrics()
        }
        
        json_str = json.dumps(data, indent=2)
        
        if file_path:
            Path(file_path).write_text(json_str, encoding='utf-8')
        
        return json_str
    
    def cleanup_old_metrics(self, max_age_seconds: int = 3600):
        """Remove old metric points"""
        if time.time() - self._last_cleanup < 300:  # Cleanup every 5 minutes max
            return
        
        cutoff_time = time.time() - max_age_seconds
        removed_count = 0
        
        with self.lock:
            for name in list(self.metrics.keys()):
                original_len = len(self.metrics[name])
                # Filter out old points
                self.metrics[name] = deque(
                    (point for point in self.metrics[name] if point.timestamp > cutoff_time),
                    maxlen=self.metrics[name].maxlen
                )
                removed_count += original_len - len(self.metrics[name])
                
                # Remove empty metric collections
                if not self.metrics[name]:
                    del self.metrics[name]
        
        self._last_cleanup = time.time()
        return removed_count

class TimingContext:
    """Context manager for timing operations"""
    
    def __init__(self, collector: LightweightMetricsCollector, name: str, tags: Dict[str, str] = None):
        self.collector = collector
        self.name = name
        self.tags = tags
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.start_time:
            duration = time.time() - self.start_time
            self.collector.timer(self.name, duration, self.tags)

class SystemMetricsCollector(LightweightMetricsCollector):
    """Extended metrics collector with system metrics"""
    
    def __init__(self, max_points: int = 10000, collect_system_metrics: bool = True):
        super().__init__(max_points)
        self.collect_system = collect_system_metrics
        self._collection_thread = None
        self._collecting = False
        
        if self.collect_system:
            self.start_system_collection()
    
    def start_system_collection(self):
        """Start collecting system metrics in background"""
        if self._collecting:
            return
        
        self._collecting = True
        self._collection_thread = threading.Thread(target=self._collect_system_metrics, daemon=True)
        self._collection_thread.start()
    
    def stop_system_collection(self):
        """Stop collecting system metrics"""
        self._collecting = False
        if self._collection_thread:
            self._collection_thread.join(timeout=5)
    
    def _collect_system_metrics(self):
        """Collect system metrics periodically"""
        try:
            import psutil
            HAS_PSUTIL = True
        except ImportError:
            HAS_PSUTIL = False
        
        while self._collecting:
            try:
                if HAS_PSUTIL:
                    # CPU and memory
                    self.gauge('system.cpu_percent', psutil.cpu_percent())
                    memory = psutil.virtual_memory()
                    self.gauge('system.memory_percent', memory.percent)
                    self.gauge('system.memory_available_mb', memory.available / 1024 / 1024)
                    
                    # Disk usage
                    disk = psutil.disk_usage('.')
                    self.gauge('system.disk_percent', (disk.used / disk.total) * 100)
                    self.gauge('system.disk_free_gb', disk.free / 1024 / 1024 / 1024)
                
                # Process-specific metrics
                import os
                import threading
                self.gauge('process.thread_count', threading.active_count())
                self.gauge('process.uptime_seconds', time.time() - self._start_time)
                
            except Exception as e:
                # Don't let metrics collection crash the system
                pass
            
            time.sleep(30)  # Collect every 30 seconds

# Create singleton instances
_metrics_instance = None
_metrics_lock = threading.Lock()

def get_metrics_collector() -> LightweightMetricsCollector:
    """Get or create metrics collector instance"""
    global _metrics_instance
    if _metrics_instance is None:
        with _metrics_lock:
            if _metrics_instance is None:
                _metrics_instance = LightweightMetricsCollector()
    return _metrics_instance

def get_system_metrics_collector() -> SystemMetricsCollector:
    """Get or create system metrics collector with background collection"""
    global _metrics_instance
    if _metrics_instance is None:
        with _metrics_lock:
            if _metrics_instance is None:
                _metrics_instance = SystemMetricsCollector()
    return _metrics_instance

# Convenience functions for quick metric recording
def counter(name: str, value: float = 1, tags: Dict[str, str] = None):
    """Record counter metric"""
    get_metrics_collector().counter(name, value, tags)

def gauge(name: str, value: float, tags: Dict[str, str] = None):
    """Record gauge metric"""
    get_metrics_collector().gauge(name, value, tags)

def timer(name: str, value: float, tags: Dict[str, str] = None):
    """Record timer metric"""
    get_metrics_collector().timer(name, value, tags)

def timing(name: str, tags: Dict[str, str] = None):
    """Context manager for timing operations"""
    return get_metrics_collector().timing_context(name, tags)

def increment(name: str, tags: Dict[str, str] = None):
    """Increment counter"""
    get_metrics_collector().increment(name, tags)

__all__ = [
    'LightweightMetricsCollector', 'SystemMetricsCollector', 'MetricPoint', 'TimingContext',
    'get_metrics_collector', 'counter', 'gauge', 'timer', 'timing', 'increment'
]