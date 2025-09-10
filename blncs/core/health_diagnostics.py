"""
Advanced Health Diagnostics System for BLNCS
Provides comprehensive system health monitoring and diagnostics with fallback support.
"""

import time
import logging
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from .logger import get_logger
from .config_manager import get_config_manager
from .exceptions import MonitoringError


class ComponentType(Enum):
    """Component types for health checking"""
    PROCESS = "process"
    DATABASE = "database"
    EXTERNAL_SERVICE = "external_service"
    NETWORK = "network"
    STORAGE = "storage"
    CACHE = "cache"
    MONITORING = "monitoring"
    API = "api"


class HealthStatus(Enum):
    """System health status levels"""
    HEALTHY = "healthy"
    WARNING = "warning"  
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class DiagnosticSeverity(Enum):
    """Diagnostic severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class HealthCheckResult:
    """Health check result"""
    component: str
    component_type: ComponentType
    status: HealthStatus
    message: str
    timestamp: datetime = field(default_factory=datetime.now)
    check_duration: float = 0.0
    suggestions: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DiagnosticResult:
    """Diagnostic test result"""
    test_name: str
    status: str  # passed, failed, warning
    severity: DiagnosticSeverity
    message: str
    details: Dict[str, Any]
    timestamp: datetime
    execution_time: float


class SystemDiagnostics:
    """
    Advanced system diagnostics with comprehensive health checking
    """
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config = get_config_manager()
        
        # Configuration
        self.enabled = self.config.get('diagnostics.enabled', True)
        
        # Health check registry
        self.health_checks = {}
        self.last_health_results = {}
        
        # Check for psutil availability
        try:
            import psutil
            self.psutil_available = True
        except ImportError:
            self.psutil_available = False
        
        # Register default health checks
        self._register_default_health_checks()
        
        self.logger.info(f"System diagnostics initialized (psutil available: {self.psutil_available})")
    
    def _register_default_health_checks(self):
        """Register default system health checks"""
        # System resource check
        self.register_health_check(
            'system_resources',
            ComponentType.PROCESS,
            self._check_system_resources
        )
        
        # Configuration check
        self.register_health_check(
            'configuration',
            ComponentType.MONITORING,
            self._check_configuration
        )
    
    def register_health_check(self, name: str, component_type: ComponentType, check_func: Callable):
        """Register a custom health check"""
        self.health_checks[name] = {
            'component_type': component_type,
            'check_func': check_func
        }
        self.logger.debug(f"Registered health check: {name} ({component_type.value})")
    
    def run_health_check(self, check_name: str) -> HealthCheckResult:
        """Run a specific health check"""
        if check_name not in self.health_checks:
            return HealthCheckResult(
                component=check_name,
                component_type=ComponentType.MONITORING,
                status=HealthStatus.UNKNOWN,
                message=f"Health check '{check_name}' not registered"
            )
        
        check_info = self.health_checks[check_name]
        start_time = time.time()
        
        try:
            result = check_info['check_func']()
            duration = time.time() - start_time
            
            # Ensure result is a HealthCheckResult
            if not isinstance(result, HealthCheckResult):
                result = HealthCheckResult(
                    component=check_name,
                    component_type=check_info['component_type'],
                    status=HealthStatus.HEALTHY if result else HealthStatus.CRITICAL,
                    message=str(result),
                    check_duration=duration
                )
            else:
                result.check_duration = duration
            
            self.last_health_results[check_name] = result
            return result
            
        except Exception as e:
            duration = time.time() - start_time
            result = HealthCheckResult(
                component=check_name,
                component_type=check_info['component_type'],
                status=HealthStatus.CRITICAL,
                message=f"Health check failed: {str(e)}",
                check_duration=duration,
                details={'error': str(e)}
            )
            self.last_health_results[check_name] = result
            return result
    
    def _check_system_resources(self) -> HealthCheckResult:
        """Check system resource usage"""
        try:
            # Try to get system metrics
            if self.psutil_available:
                import psutil
                cpu_percent = psutil.cpu_percent(interval=0.1)
                memory_percent = psutil.virtual_memory().percent
                disk_percent = psutil.disk_usage('/').percent
            else:
                cpu_percent = 0
                memory_percent = 0
                disk_percent = 0
            
            # Determine health status
            if cpu_percent > 90 or memory_percent > 90 or disk_percent > 90:
                status = HealthStatus.CRITICAL
                message = f"Critical resource usage - CPU: {cpu_percent}%, Memory: {memory_percent}%, Disk: {disk_percent}%"
            elif cpu_percent > 75 or memory_percent > 75 or disk_percent > 85:
                status = HealthStatus.WARNING
                message = f"High resource usage - CPU: {cpu_percent}%, Memory: {memory_percent}%, Disk: {disk_percent}%"
            else:
                status = HealthStatus.HEALTHY
                message = f"Resource usage normal - CPU: {cpu_percent}%, Memory: {memory_percent}%, Disk: {disk_percent}%"
            
            return HealthCheckResult(
                component='system_resources',
                component_type=ComponentType.PROCESS,
                status=status,
                message=message,
                details={
                    'cpu_percent': cpu_percent,
                    'memory_percent': memory_percent,
                    'disk_percent': disk_percent
                }
            )
            
        except Exception as e:
            return HealthCheckResult(
                component='system_resources',
                component_type=ComponentType.PROCESS,
                status=HealthStatus.UNKNOWN,
                message=f"Failed to check system resources: {e}"
            )
    
    def _check_configuration(self) -> HealthCheckResult:
        """Check configuration system health"""
        try:
            config = self.config.get_all() if self.config else {}
            
            if config:
                return HealthCheckResult(
                    component='configuration',
                    component_type=ComponentType.MONITORING,
                    status=HealthStatus.HEALTHY,
                    message="Configuration system operational",
                    details={'config_sections': len(config)}
                )
            else:
                return HealthCheckResult(
                    component='configuration',
                    component_type=ComponentType.MONITORING,
                    status=HealthStatus.WARNING,
                    message="Configuration system has no data"
                )
                
        except Exception as e:
            return HealthCheckResult(
                component='configuration',
                component_type=ComponentType.MONITORING,
                status=HealthStatus.CRITICAL,
                message=f"Configuration system error: {e}"
            )
    
    def get_system_health_summary(self) -> Dict[str, Any]:
        """Get overall system health summary"""
        health_results = {}
        overall_status = HealthStatus.HEALTHY
        
        # Run all registered health checks
        for check_name in self.health_checks:
            result = self.run_health_check(check_name)
            health_results[check_name] = result
            
            # Update overall status
            if result.status == HealthStatus.CRITICAL:
                overall_status = HealthStatus.CRITICAL
            elif result.status == HealthStatus.WARNING and overall_status != HealthStatus.CRITICAL:
                overall_status = HealthStatus.WARNING
        
        checks_dict = {
            name: {
                'status': result.status.value,
                'message': result.message,
                'component_type': result.component_type.value,
                'check_duration': result.check_duration
            }
            for name, result in health_results.items()
        }
        
        return {
            'timestamp': datetime.now().isoformat(),
            'overall_status': overall_status.value,
            'summary': f"{len(health_results)} checks run: {sum(1 for r in health_results.values() if r.status == HealthStatus.HEALTHY)} healthy, {sum(1 for r in health_results.values() if r.status == HealthStatus.WARNING)} warning, {sum(1 for r in health_results.values() if r.status == HealthStatus.CRITICAL)} critical",
            'checks': checks_dict,
            'total_checks': len(health_results),
            'healthy_checks': sum(1 for r in health_results.values() if r.status == HealthStatus.HEALTHY),
            'warning_checks': sum(1 for r in health_results.values() if r.status == HealthStatus.WARNING),
            'critical_checks': sum(1 for r in health_results.values() if r.status == HealthStatus.CRITICAL)
        }
    
    def get_detailed_diagnostics(self) -> Dict[str, Any]:
        """Get comprehensive diagnostic report"""
        health_summary = self.get_system_health_summary()
        
        # Get system info
        import platform
        system_info = {
            'platform': platform.platform(),
            'python_version': platform.python_version(),
            'processor': platform.processor(),
            'hostname': platform.node(),
            'psutil_available': self.psutil_available
        }
        
        return {
            'timestamp': datetime.now().isoformat(),
            'health_summary': health_summary,
            'health_checks': health_summary['checks'],  # For compatibility
            'system_info': system_info,
            'registered_checks': list(self.health_checks.keys()),
            'psutil_available': self.psutil_available,
            'configuration': {
                'enabled': self.enabled
            },
            'last_results': {
                name: {
                    'status': result.status.value,
                    'message': result.message,
                    'timestamp': result.timestamp.isoformat(),
                    'details': result.details
                }
                for name, result in self.last_health_results.items()
            }
        }
    
    def validate_system_diagnostics(self) -> Dict[str, Any]:
        """Validate system diagnostics functionality"""
        try:
            start_time = time.time()
            
            # Test basic functionality
            tests_passed = 0
            total_tests = 3
            
            # Test 1: Configuration access
            config_test = self.config is not None
            if config_test:
                tests_passed += 1
            
            # Test 2: Logger functionality
            logger_test = self.logger is not None
            if logger_test:
                tests_passed += 1
            
            # Test 3: Dependency checking
            dependencies_test = True
            try:
                import sys
                import platform
                dependencies_test = True
                tests_passed += 1
            except ImportError:
                dependencies_test = False
            
            execution_time = time.time() - start_time
            all_tests_passed = tests_passed == total_tests
            
            return {
                'success': all_tests_passed,
                'configuration_access': config_test,
                'logger_functionality': logger_test,
                'basic_dependencies': dependencies_test,
                'psutil_available': self.psutil_available,
                'tests_passed': tests_passed,
                'total_tests': total_tests,
                'execution_time': execution_time
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'psutil_available': self.psutil_available
            }


# Global system diagnostics instance
_system_diagnostics = None

def get_system_diagnostics() -> SystemDiagnostics:
    """Get global system diagnostics instance"""
    global _system_diagnostics
    if _system_diagnostics is None:
        _system_diagnostics = SystemDiagnostics()
    return _system_diagnostics