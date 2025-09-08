"""
BLNCS Health Check Functionality
Comprehensive system health monitoring with automatic recovery.
"""

import os
import time
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import deque

# psutil is treated as an optional dependency for lightweight operation
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

from .logger import get_logger
from .config import get_config
from .connection_pool import ConnectionPool
from .fast_cache import get_fast_cache
from .metrics import get_metrics_collector, increment_counter, set_gauge
from .circuit_breaker import circuit_breaker
from ..lightning.client import LightningClient


class HealthStatus(Enum):
    """Health check status levels"""
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


@dataclass
class HealthCheckResult:
    """Health check result"""
    name: str
    status: HealthStatus
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    check_duration: float = 0.0
    recovery_suggestions: List[str] = field(default_factory=list)


@dataclass
class HealthThreshold:
    """Health check thresholds"""
    warning: float
    critical: float
    unit: str = ""


class HealthChecker:
    """Comprehensive system health checker with automatic recovery"""
    
    # Default thresholds
    DEFAULT_THRESHOLDS = {
        'cpu_percent': HealthThreshold(warning=70.0, critical=90.0, unit="%"),
        'memory_percent': HealthThreshold(warning=80.0, critical=95.0, unit="%"),
        'disk_percent': HealthThreshold(warning=80.0, critical=95.0, unit="%"),
        'response_time': HealthThreshold(warning=1.0, critical=5.0, unit="s"),
        'connection_failures': HealthThreshold(warning=3, critical=10, unit="count"),
    }
    
    def __init__(self) -> None:
        self.logger = get_logger(__name__)
        self.config = get_config()
        self.cache = get_fast_cache()
        self.metrics = get_metrics_collector()
        
        # Health check history
        self.results_history: deque = deque(maxlen=100)
        self.continuous_failures: Dict[str, int] = {}
        
        # Threading
        self._lock = threading.Lock()
        self._monitoring_thread: Optional[threading.Thread] = None
        self._stop_monitoring = threading.Event()
        
        # Recovery callbacks
        self._recovery_callbacks: Dict[str, List[Callable]] = {}
        
        # Thresholds (can be overridden via config)
        self.thresholds = self.DEFAULT_THRESHOLDS.copy()
        self._load_custom_thresholds()
        
    def _load_custom_thresholds(self):
        """Load custom thresholds from configuration"""
        health_config = self.config.get('health', {})
        thresholds_config = health_config.get('thresholds', {})
        
        for key, custom in thresholds_config.items():
            if key in self.thresholds:
                if 'warning' in custom:
                    self.thresholds[key].warning = custom['warning']
                if 'critical' in custom:
                    self.thresholds[key].critical = custom['critical']
    
    def register_recovery_callback(self, check_name: str, callback: Callable):
        """Register a callback for automatic recovery"""
        if check_name not in self._recovery_callbacks:
            self._recovery_callbacks[check_name] = []
        self._recovery_callbacks[check_name].append(callback)
    
    def _execute_recovery_callbacks(self, check_name: str, result: HealthCheckResult):
        """Execute recovery callbacks for a failed check"""
        if check_name in self._recovery_callbacks:
            for callback in self._recovery_callbacks[check_name]:
                try:
                    callback(result)
                except Exception as e:
                    self.logger.error(f"Recovery callback error for {check_name}: {e}")
    
    def _determine_status(self, value: float, threshold: HealthThreshold) -> HealthStatus:
        """Determine health status based on value and thresholds"""
        if value >= threshold.critical:
            return HealthStatus.CRITICAL
        elif value >= threshold.warning:
            return HealthStatus.WARNING
        else:
            return HealthStatus.HEALTHY
    
    @circuit_breaker(name="system_resources", timeout=30.0)
    def check_system_resources(self) -> HealthCheckResult:
        """Check system resources with enhanced monitoring"""
        start_time = time.time()
        
        if not PSUTIL_AVAILABLE:
            return HealthCheckResult(
                name="system_resources",
                status=HealthStatus.WARNING,
                message="psutil not available for system monitoring",
                recovery_suggestions=[
                    "Install psutil: pip install psutil",
                    "System monitoring is limited without psutil"
                ]
            )
        
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=0.1)
            cpu_status = self._determine_status(cpu_percent, self.thresholds['cpu_percent'])
            
            # Memory usage
            memory = psutil.virtual_memory()
            memory_status = self._determine_status(memory.percent, self.thresholds['memory_percent'])
            
            # Disk usage for data directory
            data_dir = self.config.get('system.data_dir', './')
            disk = psutil.disk_usage(data_dir)
            disk_percent = (disk.used / disk.total) * 100
            disk_status = self._determine_status(disk_percent, self.thresholds['disk_percent'])
            
            # Network I/O (if available)
            network_io = {}
            try:
                net_io = psutil.net_io_counters()
                network_io = {
                    'bytes_sent': net_io.bytes_sent,
                    'bytes_recv': net_io.bytes_recv,
                    'packets_sent': net_io.packets_sent,
                    'packets_recv': net_io.packets_recv
                }
            except:
                pass
            
            # Overall status (worst of all checks)
            overall_status = max([cpu_status, memory_status, disk_status], 
                               key=lambda x: list(HealthStatus).index(x))
            
            details = {
                'cpu': {
                    'percent': round(cpu_percent, 1),
                    'status': cpu_status.value,
                    'cores': psutil.cpu_count()
                },
                'memory': {
                    'percent': round(memory.percent, 1),
                    'available_mb': round(memory.available / 1024 / 1024, 1),
                    'total_mb': round(memory.total / 1024 / 1024, 1),
                    'status': memory_status.value
                },
                'disk': {
                    'percent': round(disk_percent, 1),
                    'free_gb': round(disk.free / 1024 / 1024 / 1024, 2),
                    'total_gb': round(disk.total / 1024 / 1024 / 1024, 2),
                    'status': disk_status.value
                }
            }
            
            if network_io:
                details['network'] = network_io
            
            # Update metrics
            set_gauge('system_cpu_percent', cpu_percent)
            set_gauge('system_memory_percent', memory.percent)
            set_gauge('system_disk_percent', disk_percent)
            
            # Generate message and suggestions
            message = "System resources check completed"
            suggestions = []
            
            if cpu_status != HealthStatus.HEALTHY:
                suggestions.append(f"High CPU usage: {cpu_percent:.1f}%")
            if memory_status != HealthStatus.HEALTHY:
                suggestions.append(f"High memory usage: {memory.percent:.1f}%")
            if disk_status != HealthStatus.HEALTHY:
                suggestions.append(f"Low disk space: {disk.free / 1024**3:.1f}GB free")
            
            result = HealthCheckResult(
                name="system_resources",
                status=overall_status,
                message=message,
                details=details,
                check_duration=time.time() - start_time,
                recovery_suggestions=suggestions
            )
            
            increment_counter('health_checks_total', labels={'check': 'system_resources', 'status': overall_status.value})
            return result
            
        except Exception as e:
            self.logger.error(f"System resource check error: {e}")
            return HealthCheckResult(
                name="system_resources",
                status=HealthStatus.CRITICAL,
                message=f"System resource check failed: {str(e)}",
                check_duration=time.time() - start_time,
                recovery_suggestions=["Check system status manually", "Restart system monitoring"]
            )
    
    @circuit_breaker(name="lightning_node", timeout=60.0)
    def check_lightning_node(self) -> HealthCheckResult:
        """Check Lightning node connection and health"""
        start_time = time.time()
        
        try:
            client = LightningClient(self.config.data)
            
            # Connection and info test
            info_start = time.time()
            info = client.get_info()
            response_time = time.time() - info_start
            
            # Determine status based on sync and response time
            if response_time > self.thresholds['response_time'].critical:
                status = HealthStatus.CRITICAL
            elif response_time > self.thresholds['response_time'].warning:
                status = HealthStatus.WARNING
            elif not info.get('synced_to_chain', False):
                status = HealthStatus.WARNING
            else:
                status = HealthStatus.HEALTHY
            
            details = {
                'connected': True,
                'response_time_ms': round(response_time * 1000, 2),
                'node_alias': info.get('alias', 'Unknown'),
                'node_pubkey': info.get('identity_pubkey', '')[:16] + '...',
                'synced_to_chain': info.get('synced_to_chain', False),
                'synced_to_graph': info.get('synced_to_graph', False),
                'block_height': info.get('block_height', 0),
                'num_active_channels': info.get('num_active_channels', 0),
                'num_peers': info.get('num_peers', 0)
            }
            
            # Additional checks if connected
            try:
                # Check wallet balance
                balance = client.get_wallet_balance()
                details['wallet_balance'] = balance.get('confirmed_balance', 0)
                
                # Check channel balance
                channels = client.list_channels()
                if channels:
                    total_capacity = sum(ch.get('capacity', 0) for ch in channels)
                    total_local = sum(ch.get('local_balance', 0) for ch in channels)
                    details['channel_capacity'] = total_capacity
                    details['local_balance'] = total_local
                    details['balance_ratio'] = total_local / total_capacity if total_capacity > 0 else 0
                    
            except Exception as e:
                self.logger.warning(f"Additional Lightning checks failed: {e}")
            
            # Generate message and suggestions
            message = f"Lightning node {info.get('alias', 'Unknown')} is accessible"
            suggestions = []
            
            if not info.get('synced_to_chain'):
                suggestions.append("Node is not synced to blockchain")
            if not info.get('synced_to_graph'):
                suggestions.append("Node is not synced to Lightning network graph")
            if response_time > self.thresholds['response_time'].warning:
                suggestions.append(f"High response time: {response_time:.2f}s")
            
            # Update metrics
            set_gauge('lightning_response_time', response_time)
            set_gauge('lightning_active_channels', info.get('num_active_channels', 0))
            set_gauge('lightning_peers', info.get('num_peers', 0))
            
            result = HealthCheckResult(
                name="lightning_node",
                status=status,
                message=message,
                details=details,
                check_duration=time.time() - start_time,
                recovery_suggestions=suggestions
            )
            
            # Reset failure count on success
            self.continuous_failures.pop('lightning_node', None)
            
            increment_counter('health_checks_total', labels={'check': 'lightning_node', 'status': status.value})
            return result
            
        except Exception as e:
            # Track continuous failures
            self.continuous_failures['lightning_node'] = self.continuous_failures.get('lightning_node', 0) + 1
            failure_count = self.continuous_failures['lightning_node']
            
            self.logger.error(f"Lightning node check failed (failure #{failure_count}): {e}")
            
            suggestions = [
                "Check Lightning node is running",
                "Verify connection settings in config",
                "Check network connectivity",
                "Verify TLS certificate and macaroon paths"
            ]
            
            if failure_count >= self.thresholds['connection_failures'].warning:
                suggestions.append("Consider restarting Lightning node")
            
            result = HealthCheckResult(
                name="lightning_node",
                status=HealthStatus.CRITICAL,
                message=f"Lightning node connection failed: {str(e)}",
                details={
                    'connected': False,
                    'error': str(e),
                    'failure_count': failure_count,
                    'auto_retry_active': True
                },
                check_duration=time.time() - start_time,
                recovery_suggestions=suggestions
            )
            
            increment_counter('health_checks_total', labels={'check': 'lightning_node', 'status': 'critical'})
            increment_counter('lightning_connection_failures')
            
            return result
    
    def check_file_system(self) -> HealthCheckResult:
        """Check file system status and permissions"""
        start_time = time.time()
        
        try:
            details = {}
            suggestions = []
            issues = []
            
            # Check existence of important directories
            important_dirs = {
                'config': self.config.get('system.config_dir', 'config'),
                'data': self.config.get('system.data_dir', 'data'),
                'logs': self.config.get('system.log_dir', 'logs'),
                'backups': self.config.get('system.backup_dir', 'backups')
            }
            
            for name, dir_path in important_dirs.items():
                path = Path(dir_path)
                details[f'{name}_dir'] = {
                    'path': str(path),
                    'exists': path.exists(),
                    'writable': path.exists() and os.access(path, os.W_OK),
                    'readable': path.exists() and os.access(path, os.R_OK)
                }
                
                if not path.exists():
                    issues.append(f"{name} directory missing: {path}")
                    suggestions.append(f"Create {name} directory: mkdir -p {path}")
                elif not os.access(path, os.W_OK):
                    issues.append(f"{name} directory not writable: {path}")
                    suggestions.append(f"Fix permissions: chmod u+w {path}")
            
            # Check configuration file
            config_file = Path(self.config.config_path if hasattr(self.config, 'config_path') else 'config/config.yaml')
            details['config_file'] = {
                'path': str(config_file),
                'exists': config_file.exists(),
                'readable': config_file.exists() and os.access(config_file, os.R_OK),
                'size_kb': round(config_file.stat().st_size / 1024, 2) if config_file.exists() else 0
            }
            
            if not config_file.exists():
                issues.append("Configuration file missing")
                suggestions.append("Create configuration file from template")
            
            # Check disk space for important directories
            for name, dir_path in important_dirs.items():
                if Path(dir_path).exists():
                    try:
                        if PSUTIL_AVAILABLE:
                            disk = psutil.disk_usage(dir_path)
                            free_gb = disk.free / (1024**3)
                            details[f'{name}_disk_space'] = {
                                'free_gb': round(free_gb, 2),
                                'total_gb': round(disk.total / (1024**3), 2),
                                'usage_percent': round((disk.used / disk.total) * 100, 1)
                            }
                            
                            if free_gb < 1:  # Less than 1GB free
                                issues.append(f"Low disk space for {name}: {free_gb:.2f}GB")
                                suggestions.append(f"Free up disk space for {name} directory")
                    except:
                        pass
            
            # Check log file rotation
            log_dir = Path(important_dirs.get('logs', 'logs'))
            if log_dir.exists():
                log_files = list(log_dir.glob('*.log*'))
                total_log_size = sum(f.stat().st_size for f in log_files if f.is_file())
                details['logs'] = {
                    'file_count': len(log_files),
                    'total_size_mb': round(total_log_size / (1024**2), 2)
                }
                
                if total_log_size > 100 * 1024**2:  # > 100MB
                    issues.append("Large log files detected")
                    suggestions.append("Consider log rotation or cleanup")
            
            # Determine overall status
            if not issues:
                status = HealthStatus.HEALTHY
                message = "File system check passed"
            elif any('missing' in issue or 'not writable' in issue for issue in issues):
                status = HealthStatus.CRITICAL
                message = f"File system issues detected: {len(issues)} problems"
            else:
                status = HealthStatus.WARNING
                message = f"File system warnings: {len(issues)} minor issues"
            
            return HealthCheckResult(
                name="file_system",
                status=status,
                message=message,
                details=details,
                check_duration=time.time() - start_time,
                recovery_suggestions=suggestions
            )
            
        except Exception as e:
            self.logger.error(f"File system check error: {e}")
            return HealthCheckResult(
                name="file_system",
                status=HealthStatus.CRITICAL,
                message=f"File system check failed: {str(e)}",
                check_duration=time.time() - start_time,
                recovery_suggestions=["Check file system manually", "Verify directory permissions"]
            )
    
    def check_network_connectivity(self) -> HealthCheckResult:
        """Check network connectivity and Lightning node accessibility"""
        start_time = time.time()
        
        try:
            import socket
            details = {}
            suggestions = []
            issues = []
            
            # DNS resolution test
            try:
                dns_start = time.time()
                socket.gethostbyname('google.com')
                dns_time = time.time() - dns_start
                details['dns'] = {
                    'available': True,
                    'response_time_ms': round(dns_time * 1000, 2)
                }
            except Exception as e:
                details['dns'] = {'available': False, 'error': str(e)}
                issues.append("DNS resolution failed")
                suggestions.append("Check internet connection and DNS settings")
            
            # Lightning node port test
            ln_config = self.config.get('lightning', {})
            ln_host = ln_config.get('host', 'localhost')
            ln_port = ln_config.get('port', 8080)
            
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                
                connect_start = time.time()
                result = sock.connect_ex((ln_host, ln_port))
                connect_time = time.time() - connect_start
                sock.close()
                
                details['lightning_port'] = {
                    'host': ln_host,
                    'port': ln_port,
                    'accessible': result == 0,
                    'response_time_ms': round(connect_time * 1000, 2)
                }
                
                if result != 0:
                    issues.append(f"Lightning port {ln_port} not accessible")
                    suggestions.append("Check if Lightning node is running")
                    suggestions.append("Verify firewall settings")
                    
            except Exception as e:
                details['lightning_port'] = {
                    'host': ln_host,
                    'port': ln_port,
                    'accessible': False,
                    'error': str(e)
                }
                issues.append(f"Lightning port connection test failed: {e}")
            
            # Additional network tests
            try:
                # Check if we can reach common Bitcoin nodes
                btc_nodes = ['seed.bitcoin.sipa.be', 'dnsseed.bluematt.me']
                btc_reachable = []
                
                for node in btc_nodes[:2]:  # Test first 2 only
                    try:
                        socket.gethostbyname(node)
                        btc_reachable.append(node)
                    except:
                        pass
                
                details['bitcoin_network'] = {
                    'reachable_nodes': btc_reachable,
                    'count': len(btc_reachable)
                }
                
                if not btc_reachable:
                    issues.append("Cannot reach Bitcoin network nodes")
                    suggestions.append("Check internet connectivity to Bitcoin network")
                    
            except Exception:
                pass  # Optional test, don't fail on this
            
            # Determine overall status
            if not issues:
                status = HealthStatus.HEALTHY
                message = "Network connectivity check passed"
            elif len(issues) == 1 and "Lightning port" in issues[0]:
                status = HealthStatus.WARNING
                message = "Network connectivity OK, Lightning node port issue"
            else:
                status = HealthStatus.CRITICAL
                message = f"Network connectivity problems: {len(issues)} issues"
            
            return HealthCheckResult(
                name="network_connectivity",
                status=status,
                message=message,
                details=details,
                check_duration=time.time() - start_time,
                recovery_suggestions=suggestions
            )
            
        except Exception as e:
            self.logger.error(f"Network connectivity check error: {e}")
            return HealthCheckResult(
                name="network_connectivity",
                status=HealthStatus.CRITICAL,
                message=f"Network connectivity check failed: {str(e)}",
                check_duration=time.time() - start_time,
                recovery_suggestions=["Check network configuration", "Verify internet connection"]
            )
    
    def run_full_health_check(self) -> Dict[str, Any]:
        """Run comprehensive health check with enhanced reporting"""
        self.logger.info("Starting comprehensive health check...")
        start_time = time.time()
        
        # Run all health checks
        checks = [
            ('system_resources', self.check_system_resources),
            ('lightning_node', self.check_lightning_node),
            ('file_system', self.check_file_system),
            ('network_connectivity', self.check_network_connectivity)
        ]
        
        results = []
        status_counts = {'healthy': 0, 'warning': 0, 'critical': 0, 'unknown': 0}
        all_suggestions = []
        
        for check_name, check_func in checks:
            try:
                result = check_func()
                results.append(result)
                status_counts[result.status.value] += 1
                all_suggestions.extend(result.recovery_suggestions)
                
                # Store result in history
                with self._lock:
                    self.results_history.append(result)
                
                # Handle failures and recovery
                if result.status in [HealthStatus.WARNING, HealthStatus.CRITICAL]:
                    self._execute_recovery_callbacks(check_name, result)
                
            except Exception as e:
                self.logger.error(f"Health check '{check_name}' failed: {e}")
                failed_result = HealthCheckResult(
                    name=check_name,
                    status=HealthStatus.CRITICAL,
                    message=f"Check execution failed: {str(e)}",
                    recovery_suggestions=["Check system logs", "Restart health monitoring"]
                )
                results.append(failed_result)
                status_counts['critical'] += 1
        
        # Determine overall health status
        if status_counts['critical'] > 0:
            overall_status = HealthStatus.CRITICAL
        elif status_counts['warning'] > 0:
            overall_status = HealthStatus.WARNING
        else:
            overall_status = HealthStatus.HEALTHY
        
        # Calculate health score (0-100)
        total_checks = len(checks)
        health_score = (
            (status_counts['healthy'] * 100 +
             status_counts['warning'] * 50 +
             status_counts['critical'] * 0) / total_checks
        ) if total_checks > 0 else 0
        
        # Build comprehensive report
        health_report = {
            'timestamp': datetime.now().isoformat(),
            'check_duration': round(time.time() - start_time, 2),
            'overall_status': overall_status.value,
            'health_score': round(health_score, 1),
            'summary': {
                'total_checks': total_checks,
                'healthy': status_counts['healthy'],
                'warning': status_counts['warning'],
                'critical': status_counts['critical'],
                'unknown': status_counts['unknown']
            },
            'checks': {},
            'recovery_suggestions': list(set(all_suggestions))  # Remove duplicates
        }
        
        # Add detailed check results
        for result in results:
            health_report['checks'][result.name] = {
                'status': result.status.value,
                'message': result.message,
                'details': result.details,
                'duration': result.check_duration,
                'suggestions': result.recovery_suggestions
            }
        
        # Update metrics
        set_gauge('health_overall_score', health_score)
        increment_counter('health_checks_completed')
        
        self.logger.info(
            f"Health check completed: {overall_status.value} (score: {health_score:.1f}/100) "
            f"in {time.time() - start_time:.2f}s"
        )
        
        return health_report
    
    def get_quick_status(self) -> Dict[str, Any]:
        """Quick health status check with minimal overhead"""
        try:
            result = {
                'timestamp': datetime.now().isoformat(),
                'status': HealthStatus.UNKNOWN.value
            }
            
            # Quick Lightning node check
            try:
                client = LightningClient(self.config.data)
                info = client.get_info()
                result['lightning_node'] = {
                    'status': 'connected',
                    'alias': info.get('alias', 'Unknown'),
                    'synced': info.get('synced_to_chain', False)
                }
                ln_healthy = info.get('synced_to_chain', False)
            except Exception as e:
                result['lightning_node'] = {
                    'status': 'disconnected',
                    'error': str(e)
                }
                ln_healthy = False
            
            # Quick system resource check (if available)
            sys_healthy = True
            if PSUTIL_AVAILABLE:
                try:
                    cpu = psutil.cpu_percent(interval=0.1)
                    memory = psutil.virtual_memory()
                    
                    result['system'] = {
                        'cpu_percent': round(cpu, 1),
                        'memory_percent': round(memory.percent, 1),
                        'available_memory_gb': round(memory.available / (1024**3), 2)
                    }
                    
                    sys_healthy = cpu < 90 and memory.percent < 90
                    
                except Exception as e:
                    result['system'] = {'error': str(e)}
                    sys_healthy = False
            else:
                result['system'] = {'note': 'psutil not available'}
            
            # Determine overall quick status
            if ln_healthy and sys_healthy:
                result['status'] = HealthStatus.HEALTHY.value
            elif ln_healthy or sys_healthy:
                result['status'] = HealthStatus.WARNING.value
            else:
                result['status'] = HealthStatus.CRITICAL.value
            
            # Add recent health check summary if available
            if self.results_history:
                recent_results = list(self.results_history)[-5:]  # Last 5 results
                recent_statuses = [r.status.value for r in recent_results]
                result['recent_checks'] = {
                    'count': len(recent_results),
                    'latest': recent_results[-1].status.value,
                    'summary': dict(zip(*zip(*[(s, recent_statuses.count(s)) for s in set(recent_statuses)])))
                }
            
            return result
            
        except Exception as e:
            self.logger.error(f"Quick status check failed: {e}")
            return {
                'timestamp': datetime.now().isoformat(),
                'error': str(e),
                'status': HealthStatus.CRITICAL.value
            }


    def start_continuous_monitoring(self, interval: int = 300) -> None:
        """Start continuous health monitoring in background thread"""
        if self._monitoring_thread and self._monitoring_thread.is_alive():
            self.logger.warning("Continuous monitoring is already running")
            return
        
        self._stop_monitoring.clear()
        self._monitoring_thread = threading.Thread(
            target=self._monitoring_loop,
            args=(interval,),
            daemon=True,
            name="HealthMonitor"
        )
        self._monitoring_thread.start()
        self.logger.info(f"Started continuous health monitoring (interval: {interval}s)")
    
    def stop_continuous_monitoring(self) -> None:
        """Stop continuous health monitoring"""
        self._stop_monitoring.set()
        if self._monitoring_thread:
            self._monitoring_thread.join(timeout=10)
            if self._monitoring_thread.is_alive():
                self.logger.warning("Health monitoring thread did not stop gracefully")
            else:
                self.logger.info("Continuous health monitoring stopped")
    
    def _monitoring_loop(self, interval: int) -> None:
        """Background monitoring loop"""
        self.logger.info("Health monitoring loop started")
        
        while not self._stop_monitoring.wait(interval):
            try:
                # Run lightweight quick check more frequently
                quick_status = self.get_quick_status()
                
                # Log significant status changes
                if hasattr(self, '_last_quick_status'):
                    if self._last_quick_status['status'] != quick_status['status']:
                        self.logger.info(
                            f"Health status changed: {self._last_quick_status['status']} -> {quick_status['status']}"
                        )
                
                self._last_quick_status = quick_status
                
                # Run full check less frequently (every 5 intervals)
                if not hasattr(self, '_full_check_counter'):
                    self._full_check_counter = 0
                
                self._full_check_counter += 1
                if self._full_check_counter >= 5:
                    self._full_check_counter = 0
                    try:
                        full_report = self.run_full_health_check()
                        # Cache the full report
                        self.cache.set('last_full_health_report', full_report, ttl=interval * 6)
                    except Exception as e:
                        self.logger.error(f"Full health check failed in monitoring loop: {e}")
                
            except Exception as e:
                self.logger.error(f"Error in health monitoring loop: {e}")
    
    def get_monitoring_status(self) -> Dict[str, Any]:
        """Get status of health monitoring system"""
        return {
            'continuous_monitoring': {
                'active': self._monitoring_thread and self._monitoring_thread.is_alive(),
                'thread_name': self._monitoring_thread.name if self._monitoring_thread else None
            },
            'check_history': {
                'total_checks': len(self.results_history),
                'recent_checks': len([r for r in self.results_history if (datetime.now() - r.timestamp).total_seconds() < 3600])
            },
            'recovery_callbacks': {
                'registered_checks': list(self._recovery_callbacks.keys()),
                'total_callbacks': sum(len(callbacks) for callbacks in self._recovery_callbacks.values())
            },
            'continuous_failures': dict(self.continuous_failures)
        }


# Global health checker instance
_health_checker = None


def get_health_checker() -> HealthChecker:
    """Get global health checker instance"""
    global _health_checker
    if _health_checker is None:
        _health_checker = HealthChecker()
    return _health_checker


def start_health_monitoring(interval: int = 300) -> None:
    """Start continuous health monitoring"""
    checker = get_health_checker()
    checker.start_continuous_monitoring(interval)


def stop_health_monitoring() -> None:
    """Stop continuous health monitoring"""
    checker = get_health_checker()
    checker.stop_continuous_monitoring()


def get_health_status() -> Dict[str, Any]:
    """Get current health status"""
    checker = get_health_checker()
    return checker.get_quick_status()


def run_health_check() -> Dict[str, Any]:
    """Run full health check"""
    checker = get_health_checker()
    return checker.run_full_health_check()