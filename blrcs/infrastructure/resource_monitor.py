# BLRCS Resource Monitoring Module
# Lightweight system resource monitoring following Carmack's principles
import time
import threading
import os
import sys
from typing import Dict, List, Optional, Any, Callable
from collections import deque
from dataclasses import dataclass
from datetime import datetime

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

@dataclass
class ResourceSnapshot:
    """Single resource measurement"""
    timestamp: float
    cpu_percent: float
    memory_percent: float
    memory_mb: float
    disk_io_read: int
    disk_io_write: int
    network_sent: int
    network_recv: int
    thread_count: int
    open_files: int

class ResourceMonitor:
    """
    Lightweight resource monitoring.
    Minimal overhead, maximum insight.
    """
    
    def __init__(self, history_size: int = 100):
        self.history_size = history_size
        self.history: deque = deque(maxlen=history_size)
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.interval = 1.0  # Sample every second
        self.process = None
        self.alerts: Dict[str, Any] = {}
        self.callbacks: List[Callable] = []
        
        if PSUTIL_AVAILABLE:
            self.process = psutil.Process()
        
        # Alert thresholds
        self.thresholds = {
            'cpu_percent': 80.0,
            'memory_percent': 80.0,
            'memory_mb': 1024.0,
            'open_files': 1000
        }
        
        # Performance counters
        self.last_disk_io = None
        self.last_network_io = None
    
    def get_current_stats(self) -> ResourceSnapshot:
        """Get current resource usage"""
        if not PSUTIL_AVAILABLE:
            # Fallback to basic stats
            return ResourceSnapshot(
                timestamp=time.time(),
                cpu_percent=0.0,
                memory_percent=0.0,
                memory_mb=0.0,
                disk_io_read=0,
                disk_io_write=0,
                network_sent=0,
                network_recv=0,
                thread_count=threading.active_count(),
                open_files=0
            )
        
        # Get CPU and memory
        cpu_percent = self.process.cpu_percent()
        memory_info = self.process.memory_info()
        memory_percent = self.process.memory_percent()
        memory_mb = memory_info.rss / 1024 / 1024
        
        # Get I/O counters
        try:
            io_counters = self.process.io_counters()
            disk_read = io_counters.read_bytes
            disk_write = io_counters.write_bytes
        except:
            disk_read = disk_write = 0
        
        # Get network I/O
        try:
            net_io = psutil.net_io_counters()
            network_sent = net_io.bytes_sent
            network_recv = net_io.bytes_recv
        except:
            network_sent = network_recv = 0
        
        # Get thread and file counts
        thread_count = self.process.num_threads()
        try:
            open_files = len(self.process.open_files())
        except:
            open_files = 0
        
        return ResourceSnapshot(
            timestamp=time.time(),
            cpu_percent=cpu_percent,
            memory_percent=memory_percent,
            memory_mb=memory_mb,
            disk_io_read=disk_read,
            disk_io_write=disk_write,
            network_sent=network_sent,
            network_recv=network_recv,
            thread_count=thread_count,
            open_files=open_files
        )
    
    def start_monitoring(self):
        """Start resource monitoring"""
        if self.running:
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
    
    def stop_monitoring(self):
        """Stop resource monitoring"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=self.interval * 2)
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                snapshot = self.get_current_stats()
                self.history.append(snapshot)
                
                # Check thresholds
                self._check_alerts(snapshot)
                
                # Call callbacks
                for callback in self.callbacks:
                    try:
                        callback(snapshot)
                    except:
                        pass
            except:
                pass
            
            time.sleep(self.interval)
    
    def _check_alerts(self, snapshot: ResourceSnapshot):
        """Check if any thresholds are exceeded"""
        alerts = []
        
        for metric, threshold in self.thresholds.items():
            value = getattr(snapshot, metric, 0)
            if value > threshold:
                alerts.append({
                    'metric': metric,
                    'value': value,
                    'threshold': threshold,
                    'timestamp': snapshot.timestamp
                })
        
        if alerts:
            self.alerts = {a['metric']: a for a in alerts}
    
    def get_average_stats(self, seconds: int = 60) -> Dict[str, float]:
        """Get average stats over time period"""
        if not self.history:
            return {}
        
        cutoff = time.time() - seconds
        recent = [s for s in self.history if s.timestamp > cutoff]
        
        if not recent:
            return {}
        
        return {
            'cpu_percent': sum(s.cpu_percent for s in recent) / len(recent),
            'memory_percent': sum(s.memory_percent for s in recent) / len(recent),
            'memory_mb': sum(s.memory_mb for s in recent) / len(recent),
            'thread_count': sum(s.thread_count for s in recent) / len(recent)
        }
    
    def get_peak_stats(self) -> Dict[str, float]:
        """Get peak resource usage"""
        if not self.history:
            return {}
        
        return {
            'cpu_percent': max(s.cpu_percent for s in self.history),
            'memory_percent': max(s.memory_percent for s in self.history),
            'memory_mb': max(s.memory_mb for s in self.history),
            'thread_count': max(s.thread_count for s in self.history),
            'open_files': max(s.open_files for s in self.history)
        }
    
    def add_callback(self, callback: Callable):
        """Add monitoring callback"""
        self.callbacks.append(callback)
    
    def set_threshold(self, metric: str, value: float):
        """Set alert threshold"""
        self.thresholds[metric] = value
    
    def get_alerts(self) -> Dict[str, Any]:
        """Get current alerts"""
        return self.alerts.copy()
    
    def clear_alerts(self):
        """Clear alerts"""
        self.alerts.clear()

class SimpleResourceTracker:
    """
    Even simpler resource tracking.
    No dependencies, basic metrics only.
    """
    
    def __init__(self):
        self.start_time = time.time()
        self.measurements = []
    
    def measure(self) -> dict:
        """Take a measurement"""
        import resource
        
        usage = resource.getrusage(resource.RUSAGE_SELF)
        
        measurement = {
            'timestamp': time.time(),
            'uptime': time.time() - self.start_time,
            'user_time': usage.ru_utime,
            'system_time': usage.ru_stime,
            'max_rss_kb': usage.ru_maxrss,
            'page_faults': usage.ru_majflt,
            'context_switches': usage.ru_nvcsw + usage.ru_nivcsw
        }
        
        self.measurements.append(measurement)
        
        # Keep only last 100 measurements
        if len(self.measurements) > 100:
            self.measurements.pop(0)
        
        return measurement
    
    def get_summary(self) -> dict:
        """Get resource usage summary"""
        if not self.measurements:
            return {}
        
        latest = self.measurements[-1]
        
        return {
            'uptime_seconds': latest['uptime'],
            'cpu_time_seconds': latest['user_time'] + latest['system_time'],
            'memory_kb': latest['max_rss_kb'],
            'measurements': len(self.measurements)
        }

# Global monitor instance
_resource_monitor: Optional[ResourceMonitor] = None

def get_resource_monitor() -> ResourceMonitor:
    """Get global resource monitor"""
    global _resource_monitor
    if _resource_monitor is None:
        _resource_monitor = ResourceMonitor()
    return _resource_monitor

def start_monitoring(callback: Optional[Callable] = None) -> ResourceMonitor:
    """Quick start for resource monitoring"""
    monitor = get_resource_monitor()
    
    if callback:
        monitor.add_callback(callback)
    
    monitor.start_monitoring()
    return monitor

def log_resources():
    """Log current resource usage"""
    monitor = get_resource_monitor()
    stats = monitor.get_current_stats()
    
    print(f"[Resources] CPU: {stats.cpu_percent:.1f}% | "
          f"Memory: {stats.memory_mb:.1f}MB ({stats.memory_percent:.1f}%) | "
          f"Threads: {stats.thread_count}")

def check_memory_leak(threshold_mb: float = 100.0, duration: int = 60):
    """Check for potential memory leak"""
    monitor = get_resource_monitor()
    
    if len(monitor.history) < 2:
        return False
    
    # Get memory usage over time
    cutoff = time.time() - duration
    recent = [s for s in monitor.history if s.timestamp > cutoff]
    
    if len(recent) < 2:
        return False
    
    # Check if memory is continuously increasing
    first_memory = recent[0].memory_mb
    last_memory = recent[-1].memory_mb
    
    increase = last_memory - first_memory
    
    return increase > threshold_mb