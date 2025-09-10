"""
Enhanced System Monitoring Module
Provides comprehensive system monitoring with fallback support for missing dependencies.
"""

import os
import time
import platform
import threading
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass
from datetime import datetime, timedelta
from collections import deque
import logging
import subprocess

# Try to import psutil with fallback
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class SystemMetrics:
    """System performance metrics"""
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    memory_available_mb: float
    memory_used_mb: float
    disk_percent: float
    disk_free_gb: float
    disk_used_gb: float
    network_bytes_sent: int = 0
    network_bytes_recv: int = 0
    process_count: int = 0
    load_average: float = 0.0
    uptime_seconds: float = 0.0


@dataclass
class ProcessInfo:
    """Process information"""
    pid: int
    name: str
    cpu_percent: float
    memory_percent: float
    memory_mb: float
    status: str
    create_time: float
    cmdline: List[str]


class FallbackSystemMonitor:
    """
    Fallback system monitoring implementation when psutil is not available
    Uses basic system calls and /proc filesystem on Linux
    """
    
    def __init__(self):
        self.platform = platform.system().lower()
        self.logger = logging.getLogger(self.__class__.__name__)
        
    def get_cpu_percent(self, interval: float = 1.0) -> float:
        """Get CPU usage percentage with fallback implementation"""
        try:
            if self.platform == 'linux':
                return self._get_cpu_percent_linux()
            else:
                # Use basic load average as approximation
                try:
                    load_avg = os.getloadavg()[0]
                    # Rough approximation: load_avg to percentage
                    return min(load_avg * 25, 100.0)
                except (OSError, AttributeError):
                    return 0.0
        except Exception as e:
            self.logger.debug(f"Fallback CPU monitoring failed: {e}")
            return 0.0
    
    def _get_cpu_percent_linux(self) -> float:
        """Get CPU percentage on Linux using /proc/stat"""
        try:
            with open('/proc/stat', 'r') as f:
                line = f.readline()
            
            # Parse CPU stats
            cpu_times = [int(x) for x in line.split()[1:]]
            idle_time = cpu_times[3]  # idle time
            total_time = sum(cpu_times)
            
            # Calculate percentage (simplified single measurement)
            if total_time > 0:
                return max(0, min(100, 100 * (1 - idle_time / total_time)))
            return 0.0
        except Exception:
            return 0.0
    
    def get_memory_info(self) -> Dict[str, float]:
        """Get memory information with fallback implementation"""
        try:
            if self.platform == 'linux':
                return self._get_memory_info_linux()
            else:
                # Use basic system info
                return {'percent': 0.0, 'available_mb': 0.0, 'used_mb': 0.0, 'total_mb': 0.0}
        except Exception as e:
            self.logger.debug(f"Fallback memory monitoring failed: {e}")
            return {'percent': 0.0, 'available_mb': 0.0, 'used_mb': 0.0, 'total_mb': 0.0}
    
    def _get_memory_info_linux(self) -> Dict[str, float]:
        """Get memory info on Linux using /proc/meminfo"""
        try:
            with open('/proc/meminfo', 'r') as f:
                meminfo = {}
                for line in f:
                    key, value = line.split(':')
                    meminfo[key.strip()] = int(value.split()[0])  # Value in KB
            
            total_mb = meminfo.get('MemTotal', 0) / 1024
            available_mb = meminfo.get('MemAvailable', meminfo.get('MemFree', 0)) / 1024
            used_mb = total_mb - available_mb
            percent = (used_mb / total_mb * 100) if total_mb > 0 else 0
            
            return {
                'percent': percent,
                'available_mb': available_mb,
                'used_mb': used_mb,
                'total_mb': total_mb
            }
        except Exception:
            return {'percent': 0.0, 'available_mb': 0.0, 'used_mb': 0.0, 'total_mb': 0.0}
    
    def get_disk_info(self, path: str = '/') -> Dict[str, float]:
        """Get disk usage information"""
        try:
            statvfs = os.statvfs(path)
            total_bytes = statvfs.f_frsize * statvfs.f_blocks
            free_bytes = statvfs.f_frsize * statvfs.f_available
            used_bytes = total_bytes - free_bytes
            
            total_gb = total_bytes / (1024**3)
            free_gb = free_bytes / (1024**3) 
            used_gb = used_bytes / (1024**3)
            percent = (used_gb / total_gb * 100) if total_gb > 0 else 0
            
            return {
                'percent': percent,
                'free_gb': free_gb,
                'used_gb': used_gb,
                'total_gb': total_gb
            }
        except Exception as e:
            self.logger.debug(f"Fallback disk monitoring failed: {e}")
            return {'percent': 0.0, 'free_gb': 0.0, 'used_gb': 0.0, 'total_gb': 0.0}
    
    def get_process_count(self) -> int:
        """Get number of running processes"""
        try:
            if self.platform == 'linux':
                # Count processes in /proc
                proc_dirs = [d for d in os.listdir('/proc') if d.isdigit()]
                return len(proc_dirs)
            else:
                # Use ps command as fallback
                result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=5)
                return len(result.stdout.strip().split('\n')) - 1  # Exclude header
        except Exception:
            return 0
    
    def get_uptime(self) -> float:
        """Get system uptime in seconds"""
        try:
            if self.platform == 'linux':
                with open('/proc/uptime', 'r') as f:
                    uptime_seconds = float(f.read().split()[0])
                return uptime_seconds
            else:
                # Fallback using boot time estimation
                boot_time = time.time() - 3600  # Rough estimate
                return time.time() - boot_time
        except Exception:
            return 0.0


class EnhancedSystemMonitor:
    """
    Enhanced system monitoring with both psutil and fallback implementations
    """
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.fallback_monitor = FallbackSystemMonitor()
        self.monitoring_active = False
        self.metrics_history = deque(maxlen=1000)  # Store last 1000 measurements
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.collection_interval = 30  # seconds
        
        # Performance tracking
        self.last_network_io = None
        self.last_collection_time = None
        
        self.logger.info(f"System monitor initialized (psutil available: {PSUTIL_AVAILABLE})")
    
    def get_current_metrics(self) -> SystemMetrics:
        """Get current system metrics"""
        try:
            if PSUTIL_AVAILABLE:
                return self._get_metrics_psutil()
            else:
                return self._get_metrics_fallback()
        except Exception as e:
            self.logger.error(f"Failed to collect system metrics: {e}")
            return self._get_default_metrics()
    
    def _get_metrics_psutil(self) -> SystemMetrics:
        """Get metrics using psutil library"""
        # CPU
        cpu_percent = psutil.cpu_percent(interval=0.1)
        
        # Memory
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        memory_available_mb = memory.available / (1024**2)
        memory_used_mb = memory.used / (1024**2)
        
        # Disk
        disk = psutil.disk_usage('/')
        disk_percent = (disk.used / disk.total * 100) if disk.total > 0 else 0
        disk_free_gb = disk.free / (1024**3)
        disk_used_gb = disk.used / (1024**3)
        
        # Network
        net_io = psutil.net_io_counters()
        network_bytes_sent = net_io.bytes_sent if net_io else 0
        network_bytes_recv = net_io.bytes_recv if net_io else 0
        
        # Processes
        process_count = len(psutil.pids())
        
        # Load average
        try:
            load_average = psutil.getloadavg()[0] if hasattr(psutil, 'getloadavg') else 0.0
        except (OSError, AttributeError):
            load_average = 0.0
        
        # Uptime
        boot_time = psutil.boot_time()
        uptime_seconds = time.time() - boot_time
        
        return SystemMetrics(
            timestamp=datetime.now(),
            cpu_percent=cpu_percent,
            memory_percent=memory_percent,
            memory_available_mb=memory_available_mb,
            memory_used_mb=memory_used_mb,
            disk_percent=disk_percent,
            disk_free_gb=disk_free_gb,
            disk_used_gb=disk_used_gb,
            network_bytes_sent=network_bytes_sent,
            network_bytes_recv=network_bytes_recv,
            process_count=process_count,
            load_average=load_average,
            uptime_seconds=uptime_seconds
        )
    
    def _get_metrics_fallback(self) -> SystemMetrics:
        """Get metrics using fallback implementation"""
        # CPU
        cpu_percent = self.fallback_monitor.get_cpu_percent()
        
        # Memory
        memory_info = self.fallback_monitor.get_memory_info()
        
        # Disk
        disk_info = self.fallback_monitor.get_disk_info()
        
        # Process count
        process_count = self.fallback_monitor.get_process_count()
        
        # Uptime
        uptime_seconds = self.fallback_monitor.get_uptime()
        
        return SystemMetrics(
            timestamp=datetime.now(),
            cpu_percent=cpu_percent,
            memory_percent=memory_info['percent'],
            memory_available_mb=memory_info['available_mb'],
            memory_used_mb=memory_info['used_mb'],
            disk_percent=disk_info['percent'],
            disk_free_gb=disk_info['free_gb'],
            disk_used_gb=disk_info['used_gb'],
            network_bytes_sent=0,  # Not available in fallback
            network_bytes_recv=0,  # Not available in fallback
            process_count=process_count,
            load_average=0.0,  # Basic approximation only
            uptime_seconds=uptime_seconds
        )
    
    def _get_default_metrics(self) -> SystemMetrics:
        """Get default metrics when monitoring fails"""
        return SystemMetrics(
            timestamp=datetime.now(),
            cpu_percent=0.0,
            memory_percent=0.0,
            memory_available_mb=0.0,
            memory_used_mb=0.0,
            disk_percent=0.0,
            disk_free_gb=0.0,
            disk_used_gb=0.0,
            network_bytes_sent=0,
            network_bytes_recv=0,
            process_count=0,
            load_average=0.0,
            uptime_seconds=0.0
        )
    
    def get_process_list(self, limit: int = 10) -> List[ProcessInfo]:
        """Get list of running processes"""
        processes = []
        
        try:
            if PSUTIL_AVAILABLE:
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 
                                               'memory_info', 'status', 'create_time', 'cmdline']):
                    try:
                        pinfo = proc.info
                        processes.append(ProcessInfo(
                            pid=pinfo['pid'],
                            name=pinfo['name'] or 'Unknown',
                            cpu_percent=pinfo['cpu_percent'] or 0.0,
                            memory_percent=pinfo['memory_percent'] or 0.0,
                            memory_mb=(pinfo['memory_info'].rss / (1024**2)) if pinfo['memory_info'] else 0.0,
                            status=pinfo['status'] or 'unknown',
                            create_time=pinfo['create_time'] or 0.0,
                            cmdline=pinfo['cmdline'] or []
                        ))
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                # Sort by CPU usage (descending)
                processes.sort(key=lambda x: x.cpu_percent, reverse=True)
        except Exception as e:
            self.logger.error(f"Failed to get process list: {e}")
        
        return processes[:limit]
    
    def start_monitoring(self, interval: int = 30) -> bool:
        """Start continuous monitoring"""
        if self.monitoring_active:
            self.logger.warning("Monitoring already active")
            return True
        
        try:
            self.collection_interval = interval
            self._stop_event.clear()
            self._monitor_thread = threading.Thread(
                target=self._monitoring_loop,
                name="SystemMonitor",
                daemon=True
            )
            self._monitor_thread.start()
            self.monitoring_active = True
            
            self.logger.info(f"System monitoring started (interval: {interval}s)")
            return True
        except Exception as e:
            self.logger.error(f"Failed to start monitoring: {e}")
            return False
    
    def stop_monitoring(self) -> None:
        """Stop continuous monitoring"""
        if not self.monitoring_active:
            return
        
        self.logger.info("Stopping system monitoring...")
        self._stop_event.set()
        
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5.0)
            if self._monitor_thread.is_alive():
                self.logger.warning("Monitor thread did not stop gracefully")
        
        self.monitoring_active = False
        self.logger.info("System monitoring stopped")
    
    def _monitoring_loop(self) -> None:
        """Main monitoring loop"""
        while not self._stop_event.is_set():
            try:
                metrics = self.get_current_metrics()
                self.metrics_history.append(metrics)
                self.last_collection_time = datetime.now()
                
                self.logger.debug(f"Collected system metrics: CPU={metrics.cpu_percent:.1f}%, "
                                f"Memory={metrics.memory_percent:.1f}%, Disk={metrics.disk_percent:.1f}%")
                
            except Exception as e:
                self.logger.error(f"Monitoring collection failed: {e}")
            
            # Wait for next collection
            self._stop_event.wait(self.collection_interval)
    
    def get_metrics_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get metrics summary for specified time period"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        recent_metrics = [m for m in self.metrics_history if m.timestamp >= cutoff_time]
        
        if not recent_metrics:
            return {'status': 'no_data', 'period_hours': hours}
        
        # Calculate averages, min, max
        cpu_values = [m.cpu_percent for m in recent_metrics]
        memory_values = [m.memory_percent for m in recent_metrics]
        disk_values = [m.disk_percent for m in recent_metrics]
        
        return {
            'status': 'ok',
            'period_hours': hours,
            'sample_count': len(recent_metrics),
            'first_sample': recent_metrics[0].timestamp.isoformat(),
            'last_sample': recent_metrics[-1].timestamp.isoformat(),
            'cpu': {
                'average': sum(cpu_values) / len(cpu_values),
                'min': min(cpu_values),
                'max': max(cpu_values),
                'current': recent_metrics[-1].cpu_percent
            },
            'memory': {
                'average': sum(memory_values) / len(memory_values),
                'min': min(memory_values),
                'max': max(memory_values),
                'current': recent_metrics[-1].memory_percent
            },
            'disk': {
                'average': sum(disk_values) / len(disk_values),
                'min': min(disk_values),
                'max': max(disk_values),
                'current': recent_metrics[-1].disk_percent
            }
        }
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get system information"""
        info = {
            'platform': platform.platform(),
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'python_version': platform.python_version(),
            'hostname': platform.node(),
            'psutil_available': PSUTIL_AVAILABLE
        }
        
        if PSUTIL_AVAILABLE:
            try:
                info.update({
                    'cpu_count': psutil.cpu_count(),
                    'cpu_count_logical': psutil.cpu_count(logical=True),
                    'memory_total_gb': psutil.virtual_memory().total / (1024**3),
                    'disk_total_gb': psutil.disk_usage('/').total / (1024**3),
                    'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat()
                })
            except Exception as e:
                info['psutil_error'] = str(e)
        
        return info
    
    def is_healthy(self, cpu_threshold: float = 90.0, memory_threshold: float = 90.0, 
                   disk_threshold: float = 90.0) -> Dict[str, Any]:
        """Check if system is healthy based on current metrics"""
        try:
            metrics = self.get_current_metrics()
            
            issues = []
            if metrics.cpu_percent > cpu_threshold:
                issues.append(f"High CPU usage: {metrics.cpu_percent:.1f}%")
            if metrics.memory_percent > memory_threshold:
                issues.append(f"High memory usage: {metrics.memory_percent:.1f}%")
            if metrics.disk_percent > disk_threshold:
                issues.append(f"High disk usage: {metrics.disk_percent:.1f}%")
            
            return {
                'healthy': len(issues) == 0,
                'issues': issues,
                'metrics': {
                    'cpu_percent': metrics.cpu_percent,
                    'memory_percent': metrics.memory_percent,
                    'disk_percent': metrics.disk_percent,
                    'timestamp': metrics.timestamp.isoformat()
                }
            }
        except Exception as e:
            return {
                'healthy': False,
                'issues': [f"Failed to check system health: {e}"],
                'metrics': {}
            }


# Global system monitor instance
_system_monitor = None

def get_system_monitor() -> EnhancedSystemMonitor:
    """Get global system monitor instance"""
    global _system_monitor
    if _system_monitor is None:
        _system_monitor = EnhancedSystemMonitor()
    return _system_monitor


# Convenience functions
def get_current_metrics() -> SystemMetrics:
    """Get current system metrics"""
    return get_system_monitor().get_current_metrics()

def get_system_health(cpu_threshold: float = 90.0, memory_threshold: float = 90.0) -> Dict[str, Any]:
    """Get system health status"""
    return get_system_monitor().is_healthy(cpu_threshold, memory_threshold)

def get_system_info() -> Dict[str, Any]:
    """Get system information"""
    return get_system_monitor().get_system_info()


# Export commonly used functions
__all__ = [
    'EnhancedSystemMonitor',
    'SystemMetrics',
    'ProcessInfo', 
    'FallbackSystemMonitor',
    'get_system_monitor',
    'get_current_metrics',
    'get_system_health',
    'get_system_info',
    'PSUTIL_AVAILABLE'
]