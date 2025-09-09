"""
Enhanced Unified Monitoring System for BLNCS
Integrates health monitoring, metrics collection, circuit breakers, and recovery systems.
"""

import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable, Set, Union
from collections import deque
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from enum import Enum
import json

from .logger import get_logger
from .config_manager import get_config_manager
from .fast_cache import get_fast_cache
# Lazy imports to avoid circular dependency
from .metrics import get_metrics_collector, MetricsCollector
from .circuit_breaker import CircuitBreaker, CircuitState


class MonitoringLevel(Enum):
    """Monitoring intensity levels"""
    MINIMAL = 1
    BASIC = 2
    STANDARD = 3
    COMPREHENSIVE = 4
    DIAGNOSTIC = 5


class AlertSeverity(Enum):
    """Alert severity levels"""
    INFO = 1
    WARNING = 2
    ERROR = 3
    CRITICAL = 4
    EMERGENCY = 5


@dataclass
class MonitoringAlert:
    """Enhanced monitoring alert"""
    timestamp: datetime
    severity: AlertSeverity
    category: str
    source: str
    message: str
    metric_name: Optional[str] = None
    current_value: Optional[Union[int, float, str]] = None
    threshold: Optional[Union[int, float]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    resolved: bool = False
    resolution_timestamp: Optional[datetime] = None
    alert_id: Optional[str] = None


@dataclass
class SystemSnapshot:
    """Comprehensive system snapshot"""
    timestamp: datetime
    health_status: Dict[str, Any]  # Health check result
    metrics: Dict[str, Any]
    circuit_breaker_states: Dict[str, CircuitState]
    active_recoveries: Set[str]
    performance_summary: Dict[str, Any]
    resource_usage: Dict[str, Any]
    lightning_status: Dict[str, Any]


class EnhancedUnifiedMonitoring:
    """Comprehensive monitoring system with integrated health, metrics, and recovery"""
    
    def __init__(self, lightning_client=None):
        self.logger = get_logger(__name__)
        self.config = get_config_manager()
        self.cache = get_fast_cache()
        # Lazy import to avoid circular dependency
        try:
            from .health import get_health_checker
            self.health_checker = get_health_checker()
        except ImportError:
            self.logger.warning("Health checker unavailable - some monitoring features disabled")
            self.health_checker = None
        self.metrics = get_metrics_collector()
        # Lazy import for recovery system
        try:
            from .recovery_enhanced import get_enhanced_error_recovery
            self.recovery_system = get_enhanced_error_recovery()
        except ImportError:
            self.logger.warning("Enhanced error recovery unavailable - using basic recovery")
            self.recovery_system = None
        self.lightning_client = lightning_client
        
        # Configuration
        self.enabled = self.config.get('monitoring.enabled', True)
        self.monitoring_level = MonitoringLevel(self.config.get('monitoring.level', 3))
        self.collection_interval = self.config.get('monitoring.collection_interval', 30)
        self.health_check_interval = self.config.get('monitoring.health_check_interval', 60)
        self.alert_retention_hours = self.config.get('monitoring.alert_retention_hours', 24)
        self.max_history_items = self.config.get('monitoring.max_history_items', 1000)
        
        # Alert configuration
        self.alert_cooldown_seconds = self.config.get('monitoring.alert_cooldown_seconds', 300)
        self.alert_escalation_enabled = self.config.get('monitoring.alert_escalation_enabled', True)
        self.alert_aggregation_enabled = self.config.get('monitoring.alert_aggregation_enabled', True)
        
        # Data storage
        self.system_snapshots = deque(maxlen=self.max_history_items)
        self.alerts = deque(maxlen=self.max_history_items)
        self.alert_history = deque(maxlen=self.max_history_items * 2)
        self.performance_trends = deque(maxlen=500)
        
        # Threading and synchronization
        self._monitoring_thread = None
        self._health_check_thread = None
        self._alert_processor_thread = None
        self._stop_event = threading.Event()
        self._data_lock = threading.RLock()
        
        # Alert processing
        self.alert_callbacks: List[Callable[[MonitoringAlert], None]] = []
        self.alert_suppression_rules = {}
        self.last_alert_times = {}
        
        # Import circuit breaker config class
        from .circuit_breaker import CircuitBreakerConfig
        
        # Circuit breakers for monitoring components
        self.circuit_breakers = {
            'health_checks': CircuitBreaker(
                CircuitBreakerConfig(
                    name='monitoring_health_checks',
                    failure_threshold=3,
                    timeout=30.0
                )
            ),
            'metrics_collection': CircuitBreaker(
                CircuitBreakerConfig(
                    name='monitoring_metrics_collection', 
                    failure_threshold=5,
                    timeout=60.0
                )
            ),
            'lightning_monitoring': CircuitBreaker(
                CircuitBreakerConfig(
                    name='monitoring_lightning',
                    failure_threshold=3,
                    timeout=45.0
                )
            )
        }
        
        # Performance tracking
        self.collection_stats = {
            'total_collections': 0,
            'successful_collections': 0,
            'failed_collections': 0,
            'average_collection_time': 0.0,
            'last_collection_time': None
        }
        
        # Initialize metric counters
        self._initialize_metrics()
        
        self.logger.info(f"Enhanced unified monitoring initialized (level: {self.monitoring_level.name})")
    
    def _initialize_metrics(self):
        """Initialize monitoring metrics"""
        self.monitoring_collections_counter = self.metrics.counter(
            'monitoring_collections_total'
        )
        self.monitoring_errors_counter = self.metrics.counter(
            'monitoring_errors_total'
        )
        self.monitoring_duration_histogram = self.metrics.histogram(
            'monitoring_collection_duration_seconds'
        )
        self.alerts_generated_counter = self.metrics.counter(
            'alerts_generated_total'
        )
        self.circuit_breaker_trips_counter = self.metrics.counter(
            'monitoring_circuit_breaker_trips_total'
        )
    
    def start(self) -> bool:
        """Start enhanced monitoring with all subsystems"""
        if not self.enabled:
            self.logger.info("Enhanced monitoring is disabled")
            return False
        
        if self.is_running():
            self.logger.warning("Enhanced monitoring already running")
            return True
        
        try:
            self._stop_event.clear()
            
            # Start main monitoring thread
            self._monitoring_thread = threading.Thread(
                target=self._monitoring_loop, 
                name="EnhancedMonitoring",
                daemon=True
            )
            self._monitoring_thread.start()
            
            # Start health check thread
            self._health_check_thread = threading.Thread(
                target=self._health_check_loop,
                name="HealthMonitoring", 
                daemon=True
            )
            self._health_check_thread.start()
            
            # Start alert processor thread
            self._alert_processor_thread = threading.Thread(
                target=self._alert_processing_loop,
                name="AlertProcessing",
                daemon=True
            )
            self._alert_processor_thread.start()
            
            self.logger.info("Enhanced unified monitoring started successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start enhanced monitoring: {e}")
            self.stop()
            return False
    
    def stop(self) -> None:
        """Stop all monitoring threads"""
        self.logger.info("Stopping enhanced unified monitoring...")
        
        self._stop_event.set()
        
        # Stop threads with timeout
        threads = [
            (self._monitoring_thread, "monitoring"),
            (self._health_check_thread, "health check"), 
            (self._alert_processor_thread, "alert processing")
        ]
        
        for thread, name in threads:
            if thread and thread.is_alive():
                thread.join(timeout=5.0)
                if thread.is_alive():
                    self.logger.warning(f"{name} thread did not stop gracefully")
        
        # Close circuit breakers
        for cb in self.circuit_breakers.values():
            cb.close()
        
        self.logger.info("Enhanced unified monitoring stopped")
    
    def is_running(self) -> bool:
        """Check if monitoring is running"""
        return (self._monitoring_thread and self._monitoring_thread.is_alive() and
                not self._stop_event.is_set())
    
    def _monitoring_loop(self) -> None:
        """Main monitoring collection loop"""
        while not self._stop_event.is_set():
            collection_start = time.time()
            
            try:
                # Collect comprehensive system snapshot
                snapshot = self._collect_system_snapshot()
                
                with self._data_lock:
                    self.system_snapshots.append(snapshot)
                    
                    # Update performance trends
                    self._update_performance_trends(snapshot)
                    
                    # Generate alerts based on snapshot
                    self._analyze_snapshot_for_alerts(snapshot)
                
                # Update collection statistics
                collection_time = time.time() - collection_start
                self._update_collection_stats(collection_time, success=True)
                
                self.monitoring_collections_counter.inc()
                self.monitoring_duration_histogram.observe(collection_time)
                
                self.logger.debug(f"Monitoring collection completed in {collection_time:.2f}s")
                
            except Exception as e:
                self.logger.error(f"Monitoring collection failed: {e}")
                self.monitoring_errors_counter.inc()
                self._update_collection_stats(time.time() - collection_start, success=False)
            
            # Wait for next collection
            self._stop_event.wait(self.collection_interval)
    
    def _collect_system_snapshot(self) -> SystemSnapshot:
        """Collect comprehensive system snapshot"""
        snapshot_start = time.time()
        
        # Collect data from various sources with circuit breaker protection
        health_result = self._collect_health_data()
        metrics_data = self._collect_metrics_data()
        circuit_states = self._collect_circuit_breaker_states()
        recovery_data = self._collect_recovery_data()
        performance_data = self._collect_performance_data()
        resource_data = self._collect_resource_data()
        lightning_data = self._collect_lightning_data()
        
        return SystemSnapshot(
            timestamp=datetime.now(),
            health_status=health_result,
            metrics=metrics_data,
            circuit_breaker_states=circuit_states,
            active_recoveries=recovery_data,
            performance_summary=performance_data,
            resource_usage=resource_data,
            lightning_status=lightning_data
        )
    
    def _collect_health_data(self) -> Dict[str, Any]:
        """Collect health check data with circuit breaker protection"""
        cb = self.circuit_breakers['health_checks']
        
        try:
            with cb:
                if self.health_checker:
                    health_result = self.health_checker.run_full_health_check()
                    return health_result
                else:
                    return {
                        'status': 'unknown',
                        'message': "Health checker not available",
                        'checks': {},
                        'metadata': {'health_checker_available': False}
                    }
        except Exception as e:
            self.logger.warning(f"Health data collection failed: {e}")
            if cb.state == CircuitState.OPEN:
                self.circuit_breaker_trips_counter.inc({'component': 'health_checks'})
            
            # Return fallback health result
            return {
                'status': 'unknown',
                'message': "Health check unavailable",
                'checks': {},
                'metadata': {'error': str(e)}
            }
    
    def _collect_metrics_data(self) -> Dict[str, Any]:
        """Collect metrics data with circuit breaker protection"""
        cb = self.circuit_breakers['metrics_collection']
        
        try:
            with cb:
                # Get current metrics snapshot
                if hasattr(self.metrics, 'get_all_metrics'):
                    return self.metrics.get_all_metrics()
                else:
                    return {'metrics_available': False, 'reason': 'metrics collector not fully initialized'}
        except Exception as e:
            self.logger.warning(f"Metrics data collection failed: {e}")
            if cb.state == CircuitState.OPEN:
                self.circuit_breaker_trips_counter.inc({'component': 'metrics_collection'})
            return {'error': str(e)}
    
    def _collect_circuit_breaker_states(self) -> Dict[str, CircuitState]:
        """Collect circuit breaker states"""
        states = {}
        
        # Monitoring circuit breakers
        for name, cb in self.circuit_breakers.items():
            states[f"monitoring_{name}"] = cb.state
        
        # Recovery system circuit breakers
        if hasattr(self.recovery_system, 'circuit_breakers'):
            for name, cb in self.recovery_system.circuit_breakers.items():
                states[f"recovery_{name}"] = cb.state
        
        return states
    
    def _collect_recovery_data(self) -> Set[str]:
        """Collect recovery system data"""
        try:
            recovery_status = self.recovery_system.get_recovery_status()
            return set(recovery_status.get('active_recoveries', []))
        except Exception as e:
            self.logger.warning(f"Recovery data collection failed: {e}")
            return set()
    
    def _collect_performance_data(self) -> Dict[str, Any]:
        """Collect performance metrics"""
        try:
            # Basic system performance
            import psutil
            
            return {
                'cpu_percent': psutil.cpu_percent(interval=0.1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': psutil.disk_usage('/').percent,
                'load_average': psutil.getloadavg()[0] if hasattr(psutil, 'getloadavg') else 0.0,
                'process_count': len(psutil.pids()),
                'boot_time': psutil.boot_time()
            }
        except ImportError:
            return {'psutil_available': False}
        except Exception as e:
            self.logger.warning(f"Performance data collection failed: {e}")
            return {'error': str(e)}
    
    def _collect_resource_data(self) -> Dict[str, Any]:
        """Collect resource usage data"""
        try:
            import psutil
            
            # Network I/O
            net_io = psutil.net_io_counters()
            disk_io = psutil.disk_io_counters()
            
            return {
                'network': {
                    'bytes_sent': net_io.bytes_sent if net_io else 0,
                    'bytes_recv': net_io.bytes_recv if net_io else 0,
                    'packets_sent': net_io.packets_sent if net_io else 0,
                    'packets_recv': net_io.packets_recv if net_io else 0
                },
                'disk': {
                    'read_bytes': disk_io.read_bytes if disk_io else 0,
                    'write_bytes': disk_io.write_bytes if disk_io else 0,
                    'read_count': disk_io.read_count if disk_io else 0,
                    'write_count': disk_io.write_count if disk_io else 0
                }
            }
        except ImportError:
            return {'psutil_available': False}
        except Exception as e:
            return {'error': str(e)}
    
    def _collect_lightning_data(self) -> Dict[str, Any]:
        """Collect Lightning Network data with circuit breaker protection"""
        cb = self.circuit_breakers['lightning_monitoring']
        
        if not self.lightning_client:
            return {'lightning_client_available': False}
        
        try:
            with cb:
                # Collect Lightning metrics based on monitoring level
                data = {}
                
                if self.monitoring_level.value >= MonitoringLevel.BASIC.value:
                    # Basic Lightning info
                    info = self.lightning_client.get_info()
                    data['node_info'] = info
                    data['synced'] = info.get('synced_to_chain', False)
                
                if self.monitoring_level.value >= MonitoringLevel.STANDARD.value:
                    # Balance and channels
                    balance = self.lightning_client.get_balance()
                    channels = self.lightning_client.list_channels()
                    
                    data['balance'] = balance
                    data['channel_count'] = len(channels)
                    data['active_channels'] = sum(1 for ch in channels if ch.get('active', False))
                    data['total_capacity'] = sum(ch.get('capacity', 0) for ch in channels)
                
                if self.monitoring_level.value >= MonitoringLevel.COMPREHENSIVE.value:
                    # Detailed channel analysis
                    data['channels'] = channels
                    
                    # Channel balance analysis
                    unbalanced_count = 0
                    for ch in channels:
                        if ch.get('capacity', 0) > 0:
                            balance_ratio = ch.get('local_balance', 0) / ch.get('capacity', 0)
                            if balance_ratio < 0.2 or balance_ratio > 0.8:
                                unbalanced_count += 1
                    
                    data['unbalanced_channels'] = unbalanced_count
                
                return data
                
        except Exception as e:
            self.logger.warning(f"Lightning data collection failed: {e}")
            if cb.state == CircuitState.OPEN:
                self.circuit_breaker_trips_counter.inc({'component': 'lightning_monitoring'})
            return {'error': str(e)}
    
    def _health_check_loop(self) -> None:
        """Dedicated health check loop"""
        while not self._stop_event.is_set():
            try:
                # Perform deep health checks
                health_result = self.health_checker.check_system_health()
                
                # Generate health-based alerts
                self._process_health_alerts(health_result)
                
            except Exception as e:
                self.logger.error(f"Health check loop error: {e}")
            
            self._stop_event.wait(self.health_check_interval)
    
    def _alert_processing_loop(self) -> None:
        """Dedicated alert processing loop"""
        while not self._stop_event.is_set():
            try:
                # Process alert queue, aggregation, and escalation
                self._process_alert_aggregation()
                self._process_alert_escalation()
                self._cleanup_old_alerts()
                
            except Exception as e:
                self.logger.error(f"Alert processing error: {e}")
            
            self._stop_event.wait(30)  # Process alerts every 30 seconds
    
    def _analyze_snapshot_for_alerts(self, snapshot: SystemSnapshot) -> None:
        """Analyze system snapshot and generate alerts"""
        alerts = []
        
        # Health status alerts
        health_status = snapshot.health_status.get('status', 'unknown') if isinstance(snapshot.health_status, dict) else 'unknown'
        if health_status == 'unhealthy':
            alerts.append(MonitoringAlert(
                timestamp=datetime.now(),
                severity=AlertSeverity.CRITICAL,
                category='health',
                source='health_checker',
                message=f"System health check failed: {snapshot.health_status.message}",
                metadata={'health_result': snapshot.health_status}
            ))
        elif health_status == 'degraded':
            alerts.append(MonitoringAlert(
                timestamp=datetime.now(),
                severity=AlertSeverity.WARNING,
                category='health',
                source='health_checker',
                message=f"System health degraded: {snapshot.health_status.message}",
                metadata={'health_result': snapshot.health_status}
            ))
        
        # Performance alerts
        if 'cpu_percent' in snapshot.performance_summary:
            cpu_percent = snapshot.performance_summary['cpu_percent']
            if cpu_percent > 90:
                alerts.append(MonitoringAlert(
                    timestamp=datetime.now(),
                    severity=AlertSeverity.CRITICAL,
                    category='performance',
                    source='system_monitor',
                    message=f"Critical CPU usage: {cpu_percent}%",
                    metric_name='cpu_percent',
                    current_value=cpu_percent,
                    threshold=90
                ))
            elif cpu_percent > 80:
                alerts.append(MonitoringAlert(
                    timestamp=datetime.now(),
                    severity=AlertSeverity.WARNING,
                    category='performance',
                    source='system_monitor',
                    message=f"High CPU usage: {cpu_percent}%",
                    metric_name='cpu_percent',
                    current_value=cpu_percent,
                    threshold=80
                ))
        
        if 'memory_percent' in snapshot.performance_summary:
            memory_percent = snapshot.performance_summary['memory_percent']
            if memory_percent > 95:
                alerts.append(MonitoringAlert(
                    timestamp=datetime.now(),
                    severity=AlertSeverity.CRITICAL,
                    category='performance',
                    source='system_monitor',
                    message=f"Critical memory usage: {memory_percent}%",
                    metric_name='memory_percent',
                    current_value=memory_percent,
                    threshold=95
                ))
        
        # Circuit breaker alerts
        for cb_name, state in snapshot.circuit_breaker_states.items():
            if state == CircuitState.OPEN:
                alerts.append(MonitoringAlert(
                    timestamp=datetime.now(),
                    severity=AlertSeverity.ERROR,
                    category='circuit_breaker',
                    source='circuit_breaker_monitor',
                    message=f"Circuit breaker '{cb_name}' is open",
                    metadata={'circuit_breaker': cb_name, 'state': state}
                ))
        
        # Active recovery alerts
        if snapshot.active_recoveries:
            alerts.append(MonitoringAlert(
                timestamp=datetime.now(),
                severity=AlertSeverity.WARNING,
                category='recovery',
                source='recovery_monitor',
                message=f"Active recovery operations: {', '.join(snapshot.active_recoveries)}",
                metadata={'active_recoveries': list(snapshot.active_recoveries)}
            ))
        
        # Lightning-specific alerts
        if 'error' not in snapshot.lightning_status:
            if not snapshot.lightning_status.get('synced', True):
                alerts.append(MonitoringAlert(
                    timestamp=datetime.now(),
                    severity=AlertSeverity.CRITICAL,
                    category='lightning',
                    source='lightning_monitor',
                    message="Lightning node is not synced to chain",
                    metadata=snapshot.lightning_status
                ))
            
            unbalanced = snapshot.lightning_status.get('unbalanced_channels', 0)
            if unbalanced > 0:
                alerts.append(MonitoringAlert(
                    timestamp=datetime.now(),
                    severity=AlertSeverity.WARNING,
                    category='lightning',
                    source='lightning_monitor',
                    message=f"{unbalanced} channels need rebalancing",
                    metric_name='unbalanced_channels',
                    current_value=unbalanced
                ))
        
        # Process generated alerts
        for alert in alerts:
            self._queue_alert(alert)
    
    def _queue_alert(self, alert: MonitoringAlert) -> None:
        """Queue alert for processing with deduplication"""
        alert.alert_id = f"{alert.category}:{alert.source}:{alert.metric_name or 'general'}:{hash(alert.message)}"
        
        # Check cooldown period
        last_alert_time = self.last_alert_times.get(alert.alert_id)
        if last_alert_time and (datetime.now() - last_alert_time).total_seconds() < self.alert_cooldown_seconds:
            return  # Alert is in cooldown period
        
        with self._data_lock:
            self.alerts.append(alert)
            self.alert_history.append(alert)
            self.last_alert_times[alert.alert_id] = alert.timestamp
        
        self.alerts_generated_counter.inc({
            'severity': alert.severity.name, 
            'category': alert.category
        })
        
        # Execute alert callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                self.logger.error(f"Alert callback error: {e}")
        
        # Log alert based on severity
        if alert.severity == AlertSeverity.CRITICAL or alert.severity == AlertSeverity.EMERGENCY:
            self.logger.critical(f"ALERT [{alert.severity.name}] {alert.category}: {alert.message}")
        elif alert.severity == AlertSeverity.ERROR:
            self.logger.error(f"ALERT [{alert.severity.name}] {alert.category}: {alert.message}")
        elif alert.severity == AlertSeverity.WARNING:
            self.logger.warning(f"ALERT [{alert.severity.name}] {alert.category}: {alert.message}")
        else:
            self.logger.info(f"ALERT [{alert.severity.name}] {alert.category}: {alert.message}")
    
    def _process_health_alerts(self, health_result: Dict[str, Any]) -> None:
        """Process health-specific alerts"""
        # This method can contain health-specific alert logic
        pass
    
    def _process_alert_aggregation(self) -> None:
        """Process alert aggregation"""
        if not self.alert_aggregation_enabled:
            return
        
        # Implement alert aggregation logic
        # Group similar alerts and create aggregate alerts
        pass
    
    def _process_alert_escalation(self) -> None:
        """Process alert escalation"""
        if not self.alert_escalation_enabled:
            return
        
        # Implement alert escalation logic
        # Escalate unresolved critical alerts
        pass
    
    def _cleanup_old_alerts(self) -> None:
        """Cleanup old alerts"""
        cutoff_time = datetime.now() - timedelta(hours=self.alert_retention_hours)
        
        with self._data_lock:
            # Remove old alerts from history
            self.alert_history = deque([
                alert for alert in self.alert_history 
                if alert.timestamp >= cutoff_time
            ], maxlen=self.alert_history.maxlen)
    
    def _update_performance_trends(self, snapshot: SystemSnapshot) -> None:
        """Update performance trend data"""
        health_status = snapshot.health_status.get('status', 'unknown') if isinstance(snapshot.health_status, dict) else 'unknown'
        trend_data = {
            'timestamp': snapshot.timestamp,
            'cpu_percent': snapshot.performance_summary.get('cpu_percent', 0),
            'memory_percent': snapshot.performance_summary.get('memory_percent', 0),
            'disk_percent': snapshot.performance_summary.get('disk_percent', 0),
            'health_score': 100 if health_status == 'healthy' else 50 if health_status == 'degraded' else 0,
            'active_recoveries': len(snapshot.active_recoveries),
            'circuit_breaker_issues': sum(1 for state in snapshot.circuit_breaker_states.values() 
                                         if state == CircuitState.OPEN)
        }
        
        self.performance_trends.append(trend_data)
    
    def _update_collection_stats(self, duration: float, success: bool) -> None:
        """Update collection statistics"""
        self.collection_stats['total_collections'] += 1
        self.collection_stats['last_collection_time'] = datetime.now()
        
        if success:
            self.collection_stats['successful_collections'] += 1
        else:
            self.collection_stats['failed_collections'] += 1
        
        # Update rolling average
        total = self.collection_stats['total_collections']
        current_avg = self.collection_stats['average_collection_time']
        self.collection_stats['average_collection_time'] = ((current_avg * (total - 1)) + duration) / total
    
    def get_current_status(self) -> Dict[str, Any]:
        """Get comprehensive current monitoring status"""
        with self._data_lock:
            latest_snapshot = self.system_snapshots[-1] if self.system_snapshots else None
            recent_alerts = [alert for alert in self.alerts if not alert.resolved][-10:]
            
            return {
                'monitoring': {
                    'running': self.is_running(),
                    'level': self.monitoring_level.name,
                    'collection_interval': self.collection_interval,
                    'last_collection': latest_snapshot.timestamp.isoformat() if latest_snapshot else None,
                    'statistics': self.collection_stats
                },
                'health': {
                    'status': latest_snapshot.health_status.status.name if latest_snapshot else 'UNKNOWN',
                    'message': latest_snapshot.health_status.message if latest_snapshot else 'No data',
                    'last_check': latest_snapshot.timestamp.isoformat() if latest_snapshot else None
                },
                'performance': latest_snapshot.performance_summary if latest_snapshot else {},
                'circuit_breakers': latest_snapshot.circuit_breaker_states if latest_snapshot else {},
                'active_recoveries': list(latest_snapshot.active_recoveries) if latest_snapshot else [],
                'alerts': {
                    'active_count': len(recent_alerts),
                    'total_generated': len(self.alert_history),
                    'recent_alerts': [
                        {
                            'severity': alert.severity.name,
                            'category': alert.category,
                            'message': alert.message,
                            'timestamp': alert.timestamp.isoformat()
                        }
                        for alert in recent_alerts
                    ]
                },
                'lightning': latest_snapshot.lightning_status if latest_snapshot else {}
            }
    
    def get_performance_trends(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get performance trends for specified time period"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        return [
            trend for trend in self.performance_trends
            if trend['timestamp'] >= cutoff_time
        ]
    
    def get_alert_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get alert summary for specified time period"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        recent_alerts = [
            alert for alert in self.alert_history
            if alert.timestamp >= cutoff_time
        ]
        
        # Group by severity and category
        by_severity = {}
        by_category = {}
        
        for alert in recent_alerts:
            # Count by severity
            severity_name = alert.severity.name
            if severity_name not in by_severity:
                by_severity[severity_name] = 0
            by_severity[severity_name] += 1
            
            # Count by category
            if alert.category not in by_category:
                by_category[alert.category] = 0
            by_category[alert.category] += 1
        
        return {
            'period_hours': hours,
            'total_alerts': len(recent_alerts),
            'by_severity': by_severity,
            'by_category': by_category,
            'active_alerts': len([a for a in recent_alerts if not a.resolved]),
            'resolved_alerts': len([a for a in recent_alerts if a.resolved])
        }
    
    def register_alert_callback(self, callback: Callable[[MonitoringAlert], None]) -> None:
        """Register callback for alert notifications"""
        self.alert_callbacks.append(callback)
        self.logger.debug("Alert callback registered")
    
    def set_monitoring_level(self, level: MonitoringLevel) -> None:
        """Change monitoring level"""
        old_level = self.monitoring_level
        self.monitoring_level = level
        self.logger.info(f"Monitoring level changed: {old_level.name} -> {level.name}")
    
    def force_collection(self) -> SystemSnapshot:
        """Force immediate data collection"""
        self.logger.info("Forcing immediate monitoring collection")
        return self._collect_system_snapshot()
    
    def export_data(self, format: str = 'json', hours: int = 24) -> Union[str, Dict[str, Any]]:
        """Export monitoring data"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        with self._data_lock:
            # Filter data by time period
            snapshots = [s for s in self.system_snapshots if s.timestamp >= cutoff_time]
            alerts = [a for a in self.alert_history if a.timestamp >= cutoff_time]
            trends = [t for t in self.performance_trends if t['timestamp'] >= cutoff_time]
        
        export_data = {
            'export_timestamp': datetime.now().isoformat(),
            'period_hours': hours,
            'snapshots': [
                {
                    'timestamp': s.timestamp.isoformat(),
                    'health_status': s.health_status.status.name,
                    'performance': s.performance_summary,
                    'circuit_breakers': {k: v.name for k, v in s.circuit_breaker_states.items()},
                    'active_recoveries': list(s.active_recoveries),
                    'lightning_status': s.lightning_status
                }
                for s in snapshots
            ],
            'alerts': [
                {
                    'timestamp': a.timestamp.isoformat(),
                    'severity': a.severity.name,
                    'category': a.category,
                    'source': a.source,
                    'message': a.message,
                    'resolved': a.resolved
                }
                for a in alerts
            ],
            'performance_trends': [
                {k: (v.isoformat() if k == 'timestamp' else v) for k, v in trend.items()}
                for trend in trends
            ]
        }
        
        if format.lower() == 'json':
            return json.dumps(export_data, indent=2)
        else:
            return export_data
    
    def shutdown(self) -> None:
        """Graceful shutdown of monitoring system"""
        self.logger.info("Shutting down enhanced unified monitoring...")
        self.stop()


# Global instance
_unified_monitoring = None
_monitoring_lock = threading.Lock()

def get_unified_monitoring(lightning_client=None) -> EnhancedUnifiedMonitoring:
    """Get global unified monitoring instance"""
    global _unified_monitoring
    
    if _unified_monitoring is None:
        with _monitoring_lock:
            if _unified_monitoring is None:
                _unified_monitoring = EnhancedUnifiedMonitoring(lightning_client)
    
    return _unified_monitoring