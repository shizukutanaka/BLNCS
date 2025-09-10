"""
Lightweight Health Check System
Simple, fast health checks for production deployment.
"""

import time
import psutil
import threading
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum

from .logger import get_logger
from .config_manager import get_config_manager

logger = get_logger(__name__)

class HealthStatus(Enum):
    """Health check status levels."""
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"

@dataclass
class HealthResult:
    """Health check result."""
    name: str
    status: HealthStatus
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)

class HealthChecker:
    """Lightweight health check system."""
    
    def __init__(self):
        """Initialize health checker."""
        self.logger = get_logger(__name__)
        self.config = get_config_manager()
        self.checks: Dict[str, Callable[[], HealthResult]] = {}
        self._last_results: Dict[str, HealthResult] = {}
        self._check_lock = threading.RLock()
        
        # Register default checks
        self._register_default_checks()
    
    def _register_default_checks(self):
        """Register default health checks."""
        self.register_check("system_memory", self._check_memory)
        self.register_check("system_disk", self._check_disk)
        self.register_check("system_cpu", self._check_cpu)
        self.register_check("config_loaded", self._check_config)
        
    def register_check(self, name: str, check_func: Callable[[], HealthResult]):
        """Register a health check."""
        with self._check_lock:
            self.checks[name] = check_func
        self.logger.debug(f"Registered health check: {name}")
    
    def _check_memory(self) -> HealthResult:
        """Check system memory usage."""
        try:
            memory = psutil.virtual_memory()
            usage_percent = memory.percent
            
            if usage_percent > 90:
                status = HealthStatus.CRITICAL
                message = f"Critical memory usage: {usage_percent:.1f}%"
            elif usage_percent > 80:
                status = HealthStatus.WARNING
                message = f"High memory usage: {usage_percent:.1f}%"
            else:
                status = HealthStatus.HEALTHY
                message = f"Memory usage: {usage_percent:.1f}%"
                
            return HealthResult(
                name="system_memory",
                status=status,
                message=message,
                details={
                    "total_gb": round(memory.total / (1024**3), 2),
                    "available_gb": round(memory.available / (1024**3), 2),
                    "used_percent": usage_percent
                }
            )
        except Exception as e:
            return HealthResult(
                name="system_memory",
                status=HealthStatus.UNKNOWN,
                message=f"Memory check failed: {str(e)}"
            )
    
    def _check_disk(self) -> HealthResult:
        """Check system disk usage."""
        try:
            disk = psutil.disk_usage('/')
            usage_percent = (disk.used / disk.total) * 100
            
            if usage_percent > 95:
                status = HealthStatus.CRITICAL
                message = f"Critical disk usage: {usage_percent:.1f}%"
            elif usage_percent > 85:
                status = HealthStatus.WARNING
                message = f"High disk usage: {usage_percent:.1f}%"
            else:
                status = HealthStatus.HEALTHY
                message = f"Disk usage: {usage_percent:.1f}%"
                
            return HealthResult(
                name="system_disk",
                status=status,
                message=message,
                details={
                    "total_gb": round(disk.total / (1024**3), 2),
                    "free_gb": round(disk.free / (1024**3), 2),
                    "used_percent": usage_percent
                }
            )
        except Exception as e:
            return HealthResult(
                name="system_disk",
                status=HealthStatus.UNKNOWN,
                message=f"Disk check failed: {str(e)}"
            )
    
    def _check_cpu(self) -> HealthResult:
        """Check system CPU usage."""
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            
            if cpu_percent > 95:
                status = HealthStatus.CRITICAL
                message = f"Critical CPU usage: {cpu_percent:.1f}%"
            elif cpu_percent > 80:
                status = HealthStatus.WARNING
                message = f"High CPU usage: {cpu_percent:.1f}%"
            else:
                status = HealthStatus.HEALTHY
                message = f"CPU usage: {cpu_percent:.1f}%"
                
            return HealthResult(
                name="system_cpu",
                status=status,
                message=message,
                details={
                    "usage_percent": cpu_percent,
                    "cpu_count": psutil.cpu_count(),
                    "load_average": psutil.getloadavg() if hasattr(psutil, 'getloadavg') else []
                }
            )
        except Exception as e:
            return HealthResult(
                name="system_cpu",
                status=HealthStatus.UNKNOWN,
                message=f"CPU check failed: {str(e)}"
            )
    
    def _check_config(self) -> HealthResult:
        """Check configuration system."""
        try:
            config_count = len(self.config.get_all())
            
            if config_count > 0:
                status = HealthStatus.HEALTHY
                message = f"Configuration loaded with {config_count} settings"
            else:
                status = HealthStatus.WARNING
                message = "No configuration settings loaded"
                
            return HealthResult(
                name="config_loaded",
                status=status,
                message=message,
                details={"setting_count": config_count}
            )
        except Exception as e:
            return HealthResult(
                name="config_loaded",
                status=HealthStatus.CRITICAL,
                message=f"Configuration check failed: {str(e)}"
            )
    
    def run_check(self, name: str) -> Optional[HealthResult]:
        """Run a specific health check."""
        if name not in self.checks:
            return None
            
        start_time = time.time()
        try:
            result = self.checks[name]()
            result.duration_ms = (time.time() - start_time) * 1000
            
            with self._check_lock:
                self._last_results[name] = result
                
            return result
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            error_result = HealthResult(
                name=name,
                status=HealthStatus.CRITICAL,
                message=f"Health check failed: {str(e)}",
                duration_ms=duration_ms
            )
            
            with self._check_lock:
                self._last_results[name] = error_result
                
            return error_result
    
    def run_all_checks(self) -> Dict[str, HealthResult]:
        """Run all registered health checks."""
        results = {}
        
        for name in self.checks:
            result = self.run_check(name)
            if result:
                results[name] = result
                
        return results
    
    def get_overall_status(self) -> HealthStatus:
        """Get overall system health status."""
        results = self.run_all_checks()
        
        if not results:
            return HealthStatus.UNKNOWN
            
        # Determine overall status based on worst individual status
        status_priority = {
            HealthStatus.HEALTHY: 0,
            HealthStatus.WARNING: 1,
            HealthStatus.CRITICAL: 2,
            HealthStatus.UNKNOWN: 3
        }
        
        worst_status = HealthStatus.HEALTHY
        for result in results.values():
            if status_priority[result.status] > status_priority[worst_status]:
                worst_status = result.status
                
        return worst_status
    
    def get_health_summary(self) -> Dict[str, Any]:
        """Get comprehensive health summary."""
        results = self.run_all_checks()
        overall_status = self.get_overall_status()
        
        # Count statuses
        status_counts = {status.value: 0 for status in HealthStatus}
        for result in results.values():
            status_counts[result.status.value] += 1
        
        return {
            "overall_status": overall_status.value,
            "timestamp": time.time(),
            "total_checks": len(results),
            "status_counts": status_counts,
            "checks": {name: {
                "status": result.status.value,
                "message": result.message,
                "duration_ms": result.duration_ms,
                "details": result.details
            } for name, result in results.items()}
        }
    
    def is_healthy(self) -> bool:
        """Check if system is healthy."""
        return self.get_overall_status() in [HealthStatus.HEALTHY, HealthStatus.WARNING]

# Global health checker instance
_health_checker: Optional[HealthChecker] = None
_checker_lock = threading.Lock()

def get_health_checker() -> HealthChecker:
    """Get global health checker instance."""
    global _health_checker
    if _health_checker is None:
        with _checker_lock:
            if _health_checker is None:
                _health_checker = HealthChecker()
    return _health_checker

def health_endpoint() -> Dict[str, Any]:
    """Simple health check endpoint for web services."""
    checker = get_health_checker()
    return checker.get_health_summary()

def readiness_probe() -> bool:
    """Kubernetes-style readiness probe."""
    checker = get_health_checker()
    return checker.is_healthy()

def liveness_probe() -> bool:
    """Kubernetes-style liveness probe - basic check."""
    try:
        # Simple liveness check - just ensure we can run basic operations
        import os
        return os.getpid() > 0
    except:
        return False

if __name__ == "__main__":
    # Test the health checker
    checker = get_health_checker()
    summary = checker.get_health_summary()
    
    print("Health Check Results:")
    print(f"Overall Status: {summary['overall_status']}")
    print(f"Total Checks: {summary['total_checks']}")
    
    for name, check in summary['checks'].items():
        print(f"- {name}: {check['status']} - {check['message']}")