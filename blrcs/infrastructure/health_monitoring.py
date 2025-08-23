"""
Comprehensive Health Monitoring System
Real-time system health checks and diagnostics
"""

import time
import json
import threading
import queue
import psutil
import socket
from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
import subprocess
import requests
from collections import deque


class HealthStatus(Enum):
    """Health check status"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class CheckType(Enum):
    """Health check types"""
    SYSTEM = "system"
    DATABASE = "database"
    CACHE = "cache"
    API = "api"
    NETWORK = "network"
    DISK = "disk"
    MEMORY = "memory"
    CPU = "cpu"
    EXTERNAL = "external"
    CUSTOM = "custom"


@dataclass
class HealthCheck:
    """Health check definition"""
    name: str
    check_type: CheckType
    check_function: Callable
    interval: int = 30  # seconds
    timeout: int = 10   # seconds
    retries: int = 3
    critical: bool = False
    enabled: bool = True
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HealthResult:
    """Health check result"""
    name: str
    status: HealthStatus
    message: str = ""
    duration_ms: float = 0
    timestamp: float = field(default_factory=time.time)
    error: Optional[str] = None
    metrics: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "name": self.name,
            "status": self.status.value,
            "message": self.message,
            "duration_ms": self.duration_ms,
            "timestamp": self.timestamp,
            "error": self.error,
            "metrics": self.metrics
        }


class SystemMetrics:
    """System metrics collector"""
    
    def __init__(self):
        self.metrics = {}
        self.lock = threading.Lock()
        
    def collect_cpu_metrics(self) -> Dict[str, Any]:
        """Collect CPU metrics"""
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_count = psutil.cpu_count()
        cpu_freq = psutil.cpu_freq()
        load_avg = psutil.getloadavg()
        
        return {
            "usage_percent": cpu_percent,
            "core_count": cpu_count,
            "frequency_mhz": cpu_freq.current if cpu_freq else 0,
            "load_avg_1min": load_avg[0],
            "load_avg_5min": load_avg[1],
            "load_avg_15min": load_avg[2]
        }
        
    def collect_memory_metrics(self) -> Dict[str, Any]:
        """Collect memory metrics"""
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        return {
            "total_bytes": memory.total,
            "available_bytes": memory.available,
            "used_bytes": memory.used,
            "free_bytes": memory.free,
            "usage_percent": memory.percent,
            "swap_total_bytes": swap.total,
            "swap_used_bytes": swap.used,
            "swap_free_bytes": swap.free,
            "swap_usage_percent": swap.percent
        }
        
    def collect_disk_metrics(self) -> Dict[str, Any]:
        """Collect disk metrics"""
        disk_usage = psutil.disk_usage('/')
        disk_io = psutil.disk_io_counters()
        
        metrics = {
            "total_bytes": disk_usage.total,
            "used_bytes": disk_usage.used,
            "free_bytes": disk_usage.free,
            "usage_percent": (disk_usage.used / disk_usage.total) * 100
        }
        
        if disk_io:
            metrics.update({
                "read_bytes": disk_io.read_bytes,
                "write_bytes": disk_io.write_bytes,
                "read_count": disk_io.read_count,
                "write_count": disk_io.write_count
            })
            
        return metrics
        
    def collect_network_metrics(self) -> Dict[str, Any]:
        """Collect network metrics"""
        network_io = psutil.net_io_counters()
        connections = len(psutil.net_connections())
        
        metrics = {
            "connections_count": connections
        }
        
        if network_io:
            metrics.update({
                "bytes_sent": network_io.bytes_sent,
                "bytes_recv": network_io.bytes_recv,
                "packets_sent": network_io.packets_sent,
                "packets_recv": network_io.packets_recv,
                "errors_in": network_io.errin,
                "errors_out": network_io.errout,
                "drops_in": network_io.dropin,
                "drops_out": network_io.dropout
            })
            
        return metrics
        
    def collect_process_metrics(self) -> Dict[str, Any]:
        """Collect process metrics"""
        process_count = len(psutil.pids())
        boot_time = psutil.boot_time()
        uptime = time.time() - boot_time
        
        return {
            "process_count": process_count,
            "boot_time": boot_time,
            "uptime_seconds": uptime
        }
        
    def collect_all_metrics(self) -> Dict[str, Any]:
        """Collect all system metrics"""
        with self.lock:
            metrics = {
                "timestamp": time.time(),
                "cpu": self.collect_cpu_metrics(),
                "memory": self.collect_memory_metrics(),
                "disk": self.collect_disk_metrics(),
                "network": self.collect_network_metrics(),
                "process": self.collect_process_metrics()
            }
            
            self.metrics = metrics
            return metrics


class HealthChecker:
    """Health check executor"""
    
    def __init__(self):
        self.checks = {}
        self.results = {}
        self.history = deque(maxlen=1000)
        self.running = False
        self.check_threads = {}
        self.lock = threading.Lock()
        self.system_metrics = SystemMetrics()
        
    def register_check(self, check: HealthCheck):
        """Register health check"""
        with self.lock:
            self.checks[check.name] = check
            
    def unregister_check(self, name: str):
        """Unregister health check"""
        with self.lock:
            if name in self.checks:
                del self.checks[name]
            if name in self.results:
                del self.results[name]
                
    def start(self):
        """Start health checking"""
        self.running = True
        
        # Start check threads
        for check_name, check in self.checks.items():
            if check.enabled:
                thread = threading.Thread(
                    target=self._check_loop,
                    args=(check,),
                    name=f"health-check-{check_name}"
                )
                thread.daemon = True
                thread.start()
                self.check_threads[check_name] = thread
                
    def stop(self):
        """Stop health checking"""
        self.running = False
        
        # Wait for threads to finish
        for thread in self.check_threads.values():
            thread.join(timeout=5)
            
        self.check_threads.clear()
        
    def _check_loop(self, check: HealthCheck):
        """Health check loop"""
        while self.running:
            try:
                result = self._execute_check(check)
                
                with self.lock:
                    self.results[check.name] = result
                    self.history.append(result)
                    
            except Exception as e:
                result = HealthResult(
                    name=check.name,
                    status=HealthStatus.UNKNOWN,
                    error=str(e)
                )
                
                with self.lock:
                    self.results[check.name] = result
                    self.history.append(result)
                    
            time.sleep(check.interval)
            
    def _execute_check(self, check: HealthCheck) -> HealthResult:
        """Execute single health check"""
        start_time = time.time()
        
        for attempt in range(check.retries + 1):
            try:
                # Execute check with timeout
                result = self._run_with_timeout(
                    check.check_function,
                    check.timeout
                )
                
                duration_ms = (time.time() - start_time) * 1000
                
                if isinstance(result, tuple):
                    status, message, metrics = result
                elif isinstance(result, dict):
                    status = result.get('status', HealthStatus.HEALTHY)
                    message = result.get('message', '')
                    metrics = result.get('metrics', {})
                else:
                    status = HealthStatus.HEALTHY if result else HealthStatus.UNHEALTHY
                    message = "Check passed" if result else "Check failed"
                    metrics = {}
                    
                return HealthResult(
                    name=check.name,
                    status=status,
                    message=message,
                    duration_ms=duration_ms,
                    metrics=metrics
                )
                
            except TimeoutError:
                if attempt == check.retries:
                    return HealthResult(
                        name=check.name,
                        status=HealthStatus.CRITICAL if check.critical else HealthStatus.UNHEALTHY,
                        error="Check timeout"
                    )
                    
            except Exception as e:
                if attempt == check.retries:
                    return HealthResult(
                        name=check.name,
                        status=HealthStatus.CRITICAL if check.critical else HealthStatus.UNHEALTHY,
                        error=str(e)
                    )
                    
            time.sleep(1)  # Wait before retry
            
    def _run_with_timeout(self, func: Callable, timeout: int) -> Any:
        """Run function with timeout"""
        result = [None]
        exception = [None]
        
        def target():
            try:
                result[0] = func()
            except Exception as e:
                exception[0] = e
                
        thread = threading.Thread(target=target)
        thread.daemon = True
        thread.start()
        thread.join(timeout)
        
        if thread.is_alive():
            raise TimeoutError("Function execution timeout")
            
        if exception[0]:
            raise exception[0]
            
        return result[0]
        
    def get_health_status(self) -> Dict[str, Any]:
        """Get overall health status"""
        with self.lock:
            if not self.results:
                return {
                    "status": HealthStatus.UNKNOWN.value,
                    "message": "No health checks configured"
                }
                
            # Determine overall status
            statuses = [result.status for result in self.results.values()]
            
            if any(s == HealthStatus.CRITICAL for s in statuses):
                overall_status = HealthStatus.CRITICAL
            elif any(s == HealthStatus.UNHEALTHY for s in statuses):
                overall_status = HealthStatus.UNHEALTHY
            elif any(s == HealthStatus.DEGRADED for s in statuses):
                overall_status = HealthStatus.DEGRADED
            elif all(s == HealthStatus.HEALTHY for s in statuses):
                overall_status = HealthStatus.HEALTHY
            else:
                overall_status = HealthStatus.UNKNOWN
                
            return {
                "status": overall_status.value,
                "checks": {name: result.to_dict() for name, result in self.results.items()},
                "system_metrics": self.system_metrics.metrics,
                "timestamp": time.time()
            }
            
    def get_check_result(self, name: str) -> Optional[HealthResult]:
        """Get specific check result"""
        with self.lock:
            return self.results.get(name)
            
    def get_check_history(self, name: Optional[str] = None, 
                         limit: int = 100) -> List[HealthResult]:
        """Get check history"""
        with self.lock:
            if name:
                history = [r for r in self.history if r.name == name]
            else:
                history = list(self.history)
                
            return history[-limit:]


# Built-in health checks
def check_database_connection():
    """Check database connectivity"""
    try:
        from .database_layer import get_database
        db = get_database()
        result = db.execute("SELECT 1")
        
        if result.success:
            return HealthStatus.HEALTHY, "Database connection OK", {
                "execution_time_ms": result.execution_time * 1000
            }
        else:
            return HealthStatus.UNHEALTHY, f"Database error: {result.error}", {}
            
    except Exception as e:
        return HealthStatus.CRITICAL, f"Database connection failed: {str(e)}", {}


def check_cache_system():
    """Check cache system"""
    try:
        from .cache_system import get_cache
        cache = get_cache()
        
        # Test cache operations
        test_key = "health_check_test"
        test_value = f"test_{time.time()}"
        
        cache.set(test_key, test_value)
        retrieved_value = cache.get(test_key)
        cache.delete(test_key)
        
        if retrieved_value == test_value:
            stats = cache.get_stats()
            return HealthStatus.HEALTHY, "Cache system OK", {
                "cache_stats": stats
            }
        else:
            return HealthStatus.UNHEALTHY, "Cache test failed", {}
            
    except Exception as e:
        return HealthStatus.CRITICAL, f"Cache system error: {str(e)}", {}


def check_api_endpoint(url: str = "http://localhost:8000/health"):
    """Check API endpoint"""
    try:
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            return HealthStatus.HEALTHY, f"API endpoint OK ({response.status_code})", {
                "response_time_ms": response.elapsed.total_seconds() * 1000,
                "status_code": response.status_code
            }
        else:
            return HealthStatus.DEGRADED, f"API endpoint degraded ({response.status_code})", {
                "status_code": response.status_code
            }
            
    except requests.exceptions.Timeout:
        return HealthStatus.UNHEALTHY, "API endpoint timeout", {}
    except Exception as e:
        return HealthStatus.CRITICAL, f"API endpoint error: {str(e)}", {}


def check_disk_space(path: str = "/", threshold: float = 85.0):
    """Check disk space"""
    try:
        usage = psutil.disk_usage(path)
        usage_percent = (usage.used / usage.total) * 100
        
        if usage_percent < threshold:
            return HealthStatus.HEALTHY, f"Disk space OK ({usage_percent:.1f}%)", {
                "usage_percent": usage_percent,
                "free_bytes": usage.free,
                "total_bytes": usage.total
            }
        elif usage_percent < 95.0:
            return HealthStatus.DEGRADED, f"Disk space low ({usage_percent:.1f}%)", {
                "usage_percent": usage_percent,
                "free_bytes": usage.free
            }
        else:
            return HealthStatus.CRITICAL, f"Disk space critical ({usage_percent:.1f}%)", {
                "usage_percent": usage_percent,
                "free_bytes": usage.free
            }
            
    except Exception as e:
        return HealthStatus.UNKNOWN, f"Disk check error: {str(e)}", {}


def check_memory_usage(threshold: float = 85.0):
    """Check memory usage"""
    try:
        memory = psutil.virtual_memory()
        
        if memory.percent < threshold:
            return HealthStatus.HEALTHY, f"Memory usage OK ({memory.percent:.1f}%)", {
                "usage_percent": memory.percent,
                "available_bytes": memory.available,
                "total_bytes": memory.total
            }
        elif memory.percent < 95.0:
            return HealthStatus.DEGRADED, f"Memory usage high ({memory.percent:.1f}%)", {
                "usage_percent": memory.percent,
                "available_bytes": memory.available
            }
        else:
            return HealthStatus.CRITICAL, f"Memory usage critical ({memory.percent:.1f}%)", {
                "usage_percent": memory.percent,
                "available_bytes": memory.available
            }
            
    except Exception as e:
        return HealthStatus.UNKNOWN, f"Memory check error: {str(e)}", {}


def check_cpu_usage(threshold: float = 85.0):
    """Check CPU usage"""
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        
        if cpu_percent < threshold:
            return HealthStatus.HEALTHY, f"CPU usage OK ({cpu_percent:.1f}%)", {
                "usage_percent": cpu_percent
            }
        elif cpu_percent < 95.0:
            return HealthStatus.DEGRADED, f"CPU usage high ({cpu_percent:.1f}%)", {
                "usage_percent": cpu_percent
            }
        else:
            return HealthStatus.CRITICAL, f"CPU usage critical ({cpu_percent:.1f}%)", {
                "usage_percent": cpu_percent
            }
            
    except Exception as e:
        return HealthStatus.UNKNOWN, f"CPU check error: {str(e)}", {}


class HealthMonitoringSystem:
    """Complete health monitoring system"""
    
    def __init__(self):
        self.checker = HealthChecker()
        self._register_default_checks()
        
    def _register_default_checks(self):
        """Register default health checks"""
        # Database check
        self.checker.register_check(HealthCheck(
            name="database",
            check_type=CheckType.DATABASE,
            check_function=check_database_connection,
            interval=30,
            critical=True
        ))
        
        # Cache check
        self.checker.register_check(HealthCheck(
            name="cache",
            check_type=CheckType.CACHE,
            check_function=check_cache_system,
            interval=60
        ))
        
        # API check
        self.checker.register_check(HealthCheck(
            name="api",
            check_type=CheckType.API,
            check_function=check_api_endpoint,
            interval=30
        ))
        
        # System checks
        self.checker.register_check(HealthCheck(
            name="disk_space",
            check_type=CheckType.DISK,
            check_function=lambda: check_disk_space("/", 85.0),
            interval=60
        ))
        
        self.checker.register_check(HealthCheck(
            name="memory_usage",
            check_type=CheckType.MEMORY,
            check_function=lambda: check_memory_usage(85.0),
            interval=30
        ))
        
        self.checker.register_check(HealthCheck(
            name="cpu_usage",
            check_type=CheckType.CPU,
            check_function=lambda: check_cpu_usage(85.0),
            interval=30
        ))
        
    def start(self):
        """Start health monitoring"""
        self.checker.start()
        
    def stop(self):
        """Stop health monitoring"""
        self.checker.stop()
        
    def get_health_status(self) -> Dict[str, Any]:
        """Get overall health status"""
        return self.checker.get_health_status()
        
    def add_custom_check(self, name: str, check_function: Callable,
                        interval: int = 60, critical: bool = False):
        """Add custom health check"""
        check = HealthCheck(
            name=name,
            check_type=CheckType.CUSTOM,
            check_function=check_function,
            interval=interval,
            critical=critical
        )
        self.checker.register_check(check)


# Global health monitoring system
_health_system = None


def get_health_system() -> HealthMonitoringSystem:
    """Get global health monitoring system"""
    global _health_system
    if _health_system is None:
        _health_system = HealthMonitoringSystem()
    return _health_system


def init_health_system() -> HealthMonitoringSystem:
    """Initialize health monitoring system"""
    global _health_system
    _health_system = HealthMonitoringSystem()
    return _health_system