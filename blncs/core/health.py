"""
BLNCS Health Check System
Simple health monitoring and status checking
"""

import time
import asyncio
import logging
import psutil
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass
from datetime import datetime

@dataclass
class HealthCheck:
    """Individual health check configuration"""
    name: str
    check_function: Callable
    timeout: float = 5.0
    critical: bool = False
    enabled: bool = True

class HealthChecker:
    """System health checker"""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.checks: List[HealthCheck] = []

        # Add default system checks
        self._add_default_checks()

    def _add_default_checks(self):
        """Add default system health checks"""
        self.checks.extend([
            HealthCheck("system_memory", self._check_memory, timeout=2.0),
            HealthCheck("system_cpu", self._check_cpu, timeout=2.0),
            HealthCheck("system_disk", self._check_disk, timeout=2.0),
            HealthCheck("system_uptime", self._check_uptime, timeout=1.0),
        ])

    def _check_memory(self) -> Dict[str, Any]:
        """Check system memory"""
        memory = psutil.virtual_memory()

        return {
            'healthy': memory.percent < 90,
            'memory_percent': memory.percent,
            'memory_available_gb': memory.available / (1024**3),
            'message': f"Memory usage: {memory.percent:.1f}%"
        }

    def _check_cpu(self) -> Dict[str, Any]:
        """Check CPU usage"""
        cpu_percent = psutil.cpu_percent(interval=1)

        return {
            'healthy': cpu_percent < 95,
            'cpu_percent': cpu_percent,
            'cpu_count': psutil.cpu_count(),
            'message': f"CPU usage: {cpu_percent:.1f}%"
        }

    def _check_disk(self) -> Dict[str, Any]:
        """Check disk space"""
        try:
            disk = psutil.disk_usage('/')
            percent_used = (disk.used / disk.total) * 100

            return {
                'healthy': percent_used < 95,
                'disk_percent_used': percent_used,
                'disk_free_gb': disk.free / (1024**3),
                'message': f"Disk usage: {percent_used:.1f}%"
            }
        except Exception as e:
            return {
                'healthy': False,
                'error': str(e),
                'message': f"Disk check failed: {e}"
            }

    def _check_uptime(self) -> Dict[str, Any]:
        """Check system uptime"""
        try:
            boot_time = psutil.boot_time()
            uptime = time.time() - boot_time
            uptime_hours = uptime / 3600

            return {
                'healthy': True,
                'uptime_hours': uptime_hours,
                'boot_time': datetime.fromtimestamp(boot_time).isoformat(),
                'message': f"System uptime: {uptime_hours:.1f} hours"
            }
        except Exception as e:
            return {
                'healthy': False,
                'error': str(e),
                'message': f"Uptime check failed: {e}"
            }

    def add_check(self, check: HealthCheck):
        """Add a custom health check"""
        self.checks.append(check)

    async def check_health(self) -> Dict[str, Any]:
        """Run all health checks"""
        results = {}
        overall_healthy = True
        critical_failures = []

        for check in self.checks:
            if not check.enabled:
                continue

            try:
                # Run check with timeout
                if asyncio.iscoroutinefunction(check.check_function):
                    result = await asyncio.wait_for(
                        check.check_function(),
                        timeout=check.timeout
                    )
                else:
                    result = check.check_function()

                results[check.name] = {
                    'status': 'healthy' if result.get('healthy', False) else 'unhealthy',
                    'timestamp': datetime.now().isoformat(),
                    **result
                }

                if not result.get('healthy', False):
                    overall_healthy = False
                    if check.critical:
                        critical_failures.append(check.name)

            except asyncio.TimeoutError:
                results[check.name] = {
                    'status': 'timeout',
                    'timestamp': datetime.now().isoformat(),
                    'healthy': False,
                    'error': f"Check timed out after {check.timeout}s"
                }
                overall_healthy = False
                if check.critical:
                    critical_failures.append(check.name)

            except Exception as e:
                results[check.name] = {
                    'status': 'error',
                    'timestamp': datetime.now().isoformat(),
                    'healthy': False,
                    'error': str(e)
                }
                overall_healthy = False
                if check.critical:
                    critical_failures.append(check.name)

        return {
            'healthy': overall_healthy,
            'timestamp': datetime.now().isoformat(),
            'checks': results,
            'critical_failures': critical_failures,
            'summary': self._generate_summary(results)
        }

    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate health summary"""
        total_checks = len(results)
        healthy_checks = sum(1 for r in results.values() if r.get('healthy', False))

        return {
            'total_checks': total_checks,
            'healthy_checks': healthy_checks,
            'unhealthy_checks': total_checks - healthy_checks,
            'health_percentage': (healthy_checks / total_checks * 100) if total_checks > 0 else 0
        }

    def get_status(self) -> Dict[str, Any]:
        """Get health checker status"""
        return {
            'enabled_checks': len([c for c in self.checks if c.enabled]),
            'total_checks': len(self.checks),
            'critical_checks': len([c for c in self.checks if c.critical])
        }