"""
Specific health check implementations for BLNCS
Individual health checks for different system components.
"""

import os
import time
import asyncio
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    # Mock psutil for systems without it
    class MockProcess:
        def memory_info(self):
            return type('obj', (object,), {'rss': 100 * 1024 * 1024})()
    
    class MockPsutil:
        def cpu_percent(self, interval=None):
            return 50.0
        def virtual_memory(self):
            return type('obj', (object,), {'percent': 50.0, 'available': 1024 * 1024 * 1024})()
        def disk_usage(self, path):
            return type('obj', (object,), {'percent': 50.0, 'free': 10 * 1024 * 1024 * 1024})()
        def Process(self):
            return MockProcess()
    
    psutil = MockPsutil()
from pathlib import Path
from typing import Dict, Any, Optional

from .base import BaseHealthCheck, HealthCheckResult, HealthStatus, CheckCategory, HealthThreshold
from ..logger import get_logger
from ..async_database import get_async_db_manager


class SystemResourceCheck(BaseHealthCheck):
    """Check system resource usage"""
    
    def __init__(self, **kwargs):
        super().__init__(
            name="system_resources",
            category=CheckCategory.SYSTEM,
            **kwargs
        )
        self.logger = get_logger(__name__)
        self.cpu_threshold = HealthThreshold(warning_threshold=80.0, critical_threshold=95.0)
        self.memory_threshold = HealthThreshold(warning_threshold=85.0, critical_threshold=95.0)
    
    async def _perform_check(self) -> HealthCheckResult:
        """Check CPU, memory, and disk usage"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1.0)
            
            # Memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # Disk usage for current directory
            disk_usage = psutil.disk_usage('.')
            disk_percent = (disk_usage.used / disk_usage.total) * 100
            
            # Determine overall status
            cpu_status = self.cpu_threshold.evaluate(cpu_percent)
            memory_status = self.memory_threshold.evaluate(memory_percent)
            disk_status = self.cpu_threshold.evaluate(disk_percent)  # Use same thresholds
            
            overall_status = max(cpu_status, memory_status, disk_status)
            
            details = {
                'cpu_percent': round(cpu_percent, 1),
                'memory_percent': round(memory_percent, 1),
                'memory_available_gb': round(memory.available / (1024**3), 2),
                'disk_percent': round(disk_percent, 1),
                'disk_free_gb': round(disk_usage.free / (1024**3), 2)
            }
            
            if overall_status == HealthStatus.HEALTHY:
                message = "System resources are healthy"
            elif overall_status == HealthStatus.WARNING:
                message = "System resources showing warning levels"
            else:
                message = "System resources are critically high"
            
            recovery_suggestions = []
            if cpu_percent > 80:
                recovery_suggestions.append("Consider closing unnecessary processes")
            if memory_percent > 85:
                recovery_suggestions.append("Free up memory by closing applications")
            if disk_percent > 85:
                recovery_suggestions.append("Clean up disk space")
            
            return HealthCheckResult(
                name=self.name,
                status=overall_status,
                message=message,
                category=self.category,
                details=details,
                recovery_suggestions=recovery_suggestions
            )
            
        except Exception as e:
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.CRITICAL,
                message=f"Failed to check system resources: {e}",
                category=self.category
            )


class DatabaseHealthCheck(BaseHealthCheck):
    """Check database connection and performance"""
    
    def __init__(self, **kwargs):
        super().__init__(
            name="database_health",
            category=CheckCategory.DATABASE,
            **kwargs
        )
        self.logger = get_logger(__name__)
    
    async def _perform_check(self) -> HealthCheckResult:
        """Check database connectivity and performance"""
        try:
            db_manager = await get_async_db_manager()
            
            # Test basic connectivity
            start_time = time.time()
            result = await db_manager.execute("SELECT 1", fetch_results=True)
            query_time = time.time() - start_time
            
            if not result.rows:
                return HealthCheckResult(
                    name=self.name,
                    status=HealthStatus.CRITICAL,
                    message="Database query returned no results",
                    category=self.category
                )
            
            # Get database statistics
            stats = await db_manager.get_statistics()
            
            # Determine status based on query time and connection pool
            if query_time > 5.0:
                status = HealthStatus.CRITICAL
                message = f"Database query very slow ({query_time:.2f}s)"
            elif query_time > 1.0:
                status = HealthStatus.WARNING
                message = f"Database query slow ({query_time:.2f}s)"
            else:
                status = HealthStatus.HEALTHY
                message = "Database is responding normally"
            
            details = {
                'query_time_ms': round(query_time * 1000, 2),
                'database_size_mb': round(stats.get('database_size', 0) / (1024*1024), 2),
                'connection_pool': stats.get('connection_pool', {}),
                'table_counts': stats.get('table_counts', {})
            }
            
            recovery_suggestions = []
            if query_time > 1.0:
                recovery_suggestions.append("Consider database optimization")
                recovery_suggestions.append("Check for long-running queries")
            
            return HealthCheckResult(
                name=self.name,
                status=status,
                message=message,
                category=self.category,
                details=details,
                recovery_suggestions=recovery_suggestions
            )
            
        except Exception as e:
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.CRITICAL,
                message=f"Database health check failed: {e}",
                category=self.category,
                recovery_suggestions=["Check database configuration", "Verify database is running"]
            )


class LightningNodeCheck(BaseHealthCheck):
    """Check Lightning node connectivity and sync status"""
    
    def __init__(self, client_factory: callable = None, **kwargs):
        super().__init__(
            name="lightning_node",
            category=CheckCategory.LIGHTNING,
            **kwargs
        )
        self.client_factory = client_factory
        self.logger = get_logger(__name__)
    
    async def _perform_check(self) -> HealthCheckResult:
        """Check Lightning node health"""
        try:
            if not self.client_factory:
                return HealthCheckResult(
                    name=self.name,
                    status=HealthStatus.UNKNOWN,
                    message="No Lightning client configured",
                    category=self.category
                )
            
            client = self.client_factory()
            
            # Test connection
            try:
                connected = client.connect()
                if not connected:
                    return HealthCheckResult(
                        name=self.name,
                        status=HealthStatus.CRITICAL,
                        message="Cannot connect to Lightning node",
                        category=self.category,
                        recovery_suggestions=[
                            "Check Lightning node is running",
                            "Verify connection configuration",
                            "Check network connectivity"
                        ]
                    )
            except Exception as e:
                return HealthCheckResult(
                    name=self.name,
                    status=HealthStatus.CRITICAL,
                    message=f"Lightning node connection failed: {e}",
                    category=self.category
                )
            
            # Get node information
            node_info = client.get_info()
            if not node_info:
                return HealthCheckResult(
                    name=self.name,
                    status=HealthStatus.CRITICAL,
                    message="Cannot retrieve node information",
                    category=self.category
                )
            
            # Check sync status
            chain_synced = node_info.get('synced_to_chain', False)
            graph_synced = node_info.get('synced_to_graph', False)
            
            if not chain_synced or not graph_synced:
                status = HealthStatus.WARNING
                message = "Lightning node is syncing"
                recovery_suggestions = ["Wait for synchronization to complete"]
            else:
                status = HealthStatus.HEALTHY
                message = "Lightning node is healthy and synced"
                recovery_suggestions = []
            
            details = {
                'alias': node_info.get('alias', 'Unknown'),
                'version': node_info.get('version', 'Unknown'),
                'num_channels': node_info.get('num_channels', 0),
                'num_peers': node_info.get('num_peers', 0),
                'block_height': node_info.get('block_height', 0),
                'synced_to_chain': chain_synced,
                'synced_to_graph': graph_synced,
                'network': node_info.get('network', 'unknown')
            }
            
            return HealthCheckResult(
                name=self.name,
                status=status,
                message=message,
                category=self.category,
                details=details,
                recovery_suggestions=recovery_suggestions
            )
            
        except Exception as e:
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.CRITICAL,
                message=f"Lightning node health check failed: {e}",
                category=self.category
            )


class NetworkConnectivityCheck(BaseHealthCheck):
    """Check network connectivity"""
    
    def __init__(self, test_hosts: list = None, **kwargs):
        super().__init__(
            name="network_connectivity",
            category=CheckCategory.NETWORK,
            **kwargs
        )
        self.test_hosts = test_hosts or ['8.8.8.8', '1.1.1.1']
        self.logger = get_logger(__name__)
    
    async def _perform_check(self) -> HealthCheckResult:
        """Check network connectivity to test hosts"""
        try:
            import socket
            
            successful_connections = 0
            total_hosts = len(self.test_hosts)
            connection_details = {}
            
            for host in self.test_hosts:
                try:
                    start_time = time.time()
                    sock = socket.create_connection((host, 53), timeout=5.0)
                    sock.close()
                    connection_time = time.time() - start_time
                    connection_details[host] = {
                        'status': 'success',
                        'time_ms': round(connection_time * 1000, 2)
                    }
                    successful_connections += 1
                except Exception as e:
                    connection_details[host] = {
                        'status': 'failed',
                        'error': str(e)
                    }
            
            success_rate = successful_connections / total_hosts
            
            if success_rate == 1.0:
                status = HealthStatus.HEALTHY
                message = "Network connectivity is excellent"
            elif success_rate >= 0.5:
                status = HealthStatus.WARNING
                message = f"Network connectivity is limited ({successful_connections}/{total_hosts} hosts reachable)"
            else:
                status = HealthStatus.CRITICAL
                message = f"Network connectivity is poor ({successful_connections}/{total_hosts} hosts reachable)"
            
            details = {
                'success_rate': round(success_rate * 100, 1),
                'successful_connections': successful_connections,
                'total_hosts': total_hosts,
                'connection_details': connection_details
            }
            
            recovery_suggestions = []
            if success_rate < 1.0:
                recovery_suggestions.extend([
                    "Check internet connection",
                    "Verify firewall settings",
                    "Check DNS configuration"
                ])
            
            return HealthCheckResult(
                name=self.name,
                status=status,
                message=message,
                category=self.category,
                details=details,
                recovery_suggestions=recovery_suggestions
            )
            
        except Exception as e:
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.CRITICAL,
                message=f"Network connectivity check failed: {e}",
                category=self.category
            )


class StorageHealthCheck(BaseHealthCheck):
    """Check storage health and space"""
    
    def __init__(self, paths_to_check: list = None, **kwargs):
        super().__init__(
            name="storage_health",
            category=CheckCategory.STORAGE,
            **kwargs
        )
        self.paths_to_check = paths_to_check or ['.', '/tmp']
        self.space_threshold = HealthThreshold(warning_threshold=85.0, critical_threshold=95.0)
        self.logger = get_logger(__name__)
    
    async def _perform_check(self) -> HealthCheckResult:
        """Check storage space and accessibility"""
        try:
            storage_details = {}
            overall_status = HealthStatus.HEALTHY
            issues = []
            
            for path_str in self.paths_to_check:
                path = Path(path_str)
                if not path.exists():
                    continue
                
                try:
                    # Get disk usage
                    disk_usage = psutil.disk_usage(str(path))
                    usage_percent = (disk_usage.used / disk_usage.total) * 100
                    
                    # Test read/write access
                    test_file = path / f".blncs_health_test_{time.time()}"
                    try:
                        test_file.write_text("test")
                        test_file.unlink()
                        read_write = True
                    except Exception:
                        read_write = False
                        issues.append(f"Cannot write to {path}")
                    
                    path_status = self.space_threshold.evaluate(usage_percent)
                    if path_status > overall_status:
                        overall_status = path_status
                    
                    storage_details[str(path)] = {
                        'usage_percent': round(usage_percent, 1),
                        'free_gb': round(disk_usage.free / (1024**3), 2),
                        'total_gb': round(disk_usage.total / (1024**3), 2),
                        'read_write_access': read_write,
                        'status': path_status.value
                    }
                    
                    if usage_percent > 90:
                        issues.append(f"Low space on {path} ({usage_percent:.1f}% used)")
                
                except Exception as e:
                    issues.append(f"Error checking {path}: {e}")
                    if overall_status < HealthStatus.WARNING:
                        overall_status = HealthStatus.WARNING
            
            if issues:
                message = f"Storage issues detected: {'; '.join(issues)}"
            elif overall_status == HealthStatus.HEALTHY:
                message = "Storage is healthy"
            else:
                message = "Storage space is getting low"
            
            recovery_suggestions = []
            if overall_status != HealthStatus.HEALTHY:
                recovery_suggestions.extend([
                    "Clean up unnecessary files",
                    "Archive old data",
                    "Check for large temporary files"
                ])
            
            return HealthCheckResult(
                name=self.name,
                status=overall_status,
                message=message,
                category=self.category,
                details=storage_details,
                recovery_suggestions=recovery_suggestions
            )
            
        except Exception as e:
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.CRITICAL,
                message=f"Storage health check failed: {e}",
                category=self.category
            )


class PerformanceCheck(BaseHealthCheck):
    """Check system performance metrics"""
    
    def __init__(self, **kwargs):
        super().__init__(
            name="performance",
            category=CheckCategory.PERFORMANCE,
            **kwargs
        )
        self.logger = get_logger(__name__)
    
    async def _perform_check(self) -> HealthCheckResult:
        """Check system performance indicators"""
        try:
            # CPU load average
            load_avg = os.getloadavg() if hasattr(os, 'getloadavg') else (0, 0, 0)
            
            # Memory performance
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            # Process information
            current_process = psutil.Process()
            process_memory = current_process.memory_info()
            
            # I/O statistics
            try:
                io_counters = psutil.disk_io_counters()
                io_available = True
            except Exception:
                io_counters = None
                io_available = False
            
            # Determine performance status
            cpu_cores = psutil.cpu_count()
            load_per_core = load_avg[0] / cpu_cores if cpu_cores > 0 else 0
            
            if load_per_core > 2.0 or memory.percent > 90:
                status = HealthStatus.CRITICAL
                message = "System performance is severely degraded"
            elif load_per_core > 1.0 or memory.percent > 80:
                status = HealthStatus.WARNING
                message = "System performance is degraded"
            else:
                status = HealthStatus.HEALTHY
                message = "System performance is good"
            
            details = {
                'load_average': {
                    '1min': round(load_avg[0], 2),
                    '5min': round(load_avg[1], 2),
                    '15min': round(load_avg[2], 2)
                },
                'load_per_core': round(load_per_core, 2),
                'memory_percent': round(memory.percent, 1),
                'swap_percent': round(swap.percent, 1) if swap.total > 0 else 0,
                'process_memory_mb': round(process_memory.rss / (1024*1024), 2),
                'cpu_cores': cpu_cores
            }
            
            if io_available and io_counters:
                details['disk_io'] = {
                    'read_bytes': io_counters.read_bytes,
                    'write_bytes': io_counters.write_bytes,
                    'read_count': io_counters.read_count,
                    'write_count': io_counters.write_count
                }
            
            recovery_suggestions = []
            if status != HealthStatus.HEALTHY:
                recovery_suggestions.extend([
                    "Monitor resource-intensive processes",
                    "Consider system optimization",
                    "Check for memory leaks"
                ])
            
            return HealthCheckResult(
                name=self.name,
                status=status,
                message=message,
                category=self.category,
                details=details,
                recovery_suggestions=recovery_suggestions
            )
            
        except Exception as e:
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.CRITICAL,
                message=f"Performance check failed: {e}",
                category=self.category
            )


__all__ = [
    'SystemResourceCheck',
    'DatabaseHealthCheck', 
    'LightningNodeCheck',
    'NetworkConnectivityCheck',
    'StorageHealthCheck',
    'PerformanceCheck'
]