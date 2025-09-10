"""
Performance Monitoring and Alerting System
Comprehensive system for monitoring performance metrics and generating intelligent alerts.
"""

import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable, NamedTuple
from dataclasses import dataclass, field
from collections import defaultdict, deque
from enum import Enum
import statistics
import json

from .logger import get_logger
from .config_manager import get_config_manager
from .database import get_database_manager
from .metrics import get_metrics_collector, increment_counter, set_gauge, observe_histogram


class AlertSeverity(Enum):
    """Alert severity levels"""
    INFO = 1
    WARNING = 2
    ERROR = 3
    CRITICAL = 4
    EMERGENCY = 5


class AlertCategory(Enum):
    """Alert categories"""
    PERFORMANCE = "performance"
    CONNECTIVITY = "connectivity"
    RESOURCE = "resource"
    SECURITY = "security"
    OPERATIONAL = "operational"


@dataclass
class AlertRule:
    """Performance alert rule configuration"""
    name: str
    category: AlertCategory
    metric_name: str
    condition: str  # 'greater_than', 'less_than', 'equal', 'not_equal', 'trend_up', 'trend_down'
    threshold: float
    severity: AlertSeverity
    duration_seconds: int = 300  # Must be true for this duration
    cooldown_seconds: int = 900  # Minimum time between alerts
    enabled: bool = True
    description: str = ""


@dataclass
class Alert:
    """Generated alert"""
    alert_id: str
    rule_name: str
    category: AlertCategory
    severity: AlertSeverity
    message: str
    metric_name: str
    current_value: float
    threshold: float
    timestamp: datetime
    resolved: bool = False
    resolved_at: Optional[datetime] = None
    acknowledgement: Optional[str] = None


@dataclass
class PerformanceSnapshot:
    """System performance snapshot"""
    timestamp: datetime
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    disk_usage_percent: float = 0.0
    network_connections: int = 0
    database_size_mb: float = 0.0
    active_channels: int = 0
    recent_forwards: int = 0
    node_connectivity: bool = True
    cache_hit_rate: float = 0.0


class PerformanceMonitoringSystem:
    """Comprehensive performance monitoring and alerting system"""
    
    def __init__(self, lightning_client=None):
        self.logger = get_logger(__name__)
        self.config = get_config_manager()
        self.db = get_database_manager()
        self.lightning_client = lightning_client
        
        # Metrics
        self.metrics = get_metrics_collector()
        
        # State management
        self.is_running = False
        self.monitoring_thread = None
        self._stop_event = threading.Event()
        
        # Alert management
        self.alert_rules: List[AlertRule] = []
        self.active_alerts: Dict[str, Alert] = {}
        self.alert_history: deque = deque(maxlen=1000)
        self.rule_last_triggered: Dict[str, datetime] = {}
        
        # Performance data
        self.performance_history: deque = deque(maxlen=288)  # 24 hours at 5-minute intervals
        self.current_snapshot: Optional[PerformanceSnapshot] = None
        
        # Alert callbacks
        self.alert_callbacks: List[Callable[[Alert], None]] = []
        
        # Configuration
        self.monitoring_interval = self.config.get('performance_monitoring.interval_seconds', 60)
        self.retention_hours = self.config.get('performance_monitoring.retention_hours', 24)
        
        # Initialize default alert rules
        self._load_alert_rules()
        
        self.logger.info("Performance monitoring system initialized")
    
    def _load_alert_rules(self):
        """Load alert rules from configuration"""
        # Default alert rules
        default_rules = [
            AlertRule(
                name="High CPU Usage",
                category=AlertCategory.PERFORMANCE,
                metric_name="cpu_percent",
                condition="greater_than",
                threshold=80.0,
                severity=AlertSeverity.WARNING,
                duration_seconds=300,
                cooldown_seconds=900,
                description="CPU usage is consistently high"
            ),
            AlertRule(
                name="Critical CPU Usage",
                category=AlertCategory.PERFORMANCE,
                metric_name="cpu_percent",
                condition="greater_than",
                threshold=95.0,
                severity=AlertSeverity.CRITICAL,
                duration_seconds=60,
                cooldown_seconds=300,
                description="CPU usage is critically high"
            ),
            AlertRule(
                name="High Memory Usage",
                category=AlertCategory.RESOURCE,
                metric_name="memory_percent",
                condition="greater_than",
                threshold=85.0,
                severity=AlertSeverity.WARNING,
                duration_seconds=300,
                cooldown_seconds=900,
                description="Memory usage is high"
            ),
            AlertRule(
                name="Low Disk Space",
                category=AlertCategory.RESOURCE,
                metric_name="disk_usage_percent",
                condition="greater_than",
                threshold=90.0,
                severity=AlertSeverity.ERROR,
                duration_seconds=60,
                cooldown_seconds=600,
                description="Disk space is running low"
            ),
            AlertRule(
                name="Node Connectivity Lost",
                category=AlertCategory.CONNECTIVITY,
                metric_name="node_connectivity",
                condition="equal",
                threshold=0.0,  # False = 0.0
                severity=AlertSeverity.CRITICAL,
                duration_seconds=120,
                cooldown_seconds=300,
                description="Lightning node connectivity has been lost"
            ),
            AlertRule(
                name="Low Cache Hit Rate",
                category=AlertCategory.PERFORMANCE,
                metric_name="cache_hit_rate",
                condition="less_than",
                threshold=70.0,
                severity=AlertSeverity.WARNING,
                duration_seconds=600,
                cooldown_seconds=1800,
                description="Cache hit rate is low, affecting performance"
            ),
            AlertRule(
                name="Database Growing Rapidly",
                category=AlertCategory.RESOURCE,
                metric_name="database_size_mb",
                condition="trend_up",
                threshold=100.0,  # 100MB growth in monitoring period
                severity=AlertSeverity.WARNING,
                duration_seconds=3600,
                cooldown_seconds=7200,
                description="Database size is growing rapidly"
            )
        ]
        
        # Load from config or use defaults
        config_rules = self.config.get('performance_monitoring.alert_rules', [])
        if config_rules:
            try:
                self.alert_rules = [
                    AlertRule(
                        name=rule['name'],
                        category=AlertCategory(rule['category']),
                        metric_name=rule['metric_name'],
                        condition=rule['condition'],
                        threshold=rule['threshold'],
                        severity=AlertSeverity(rule['severity']),
                        duration_seconds=rule.get('duration_seconds', 300),
                        cooldown_seconds=rule.get('cooldown_seconds', 900),
                        enabled=rule.get('enabled', True),
                        description=rule.get('description', '')
                    )
                    for rule in config_rules
                ]
            except Exception as e:
                self.logger.warning(f"Failed to load alert rules from config: {e}, using defaults")
                self.alert_rules = default_rules
        else:
            self.alert_rules = default_rules
        
        self.logger.info(f"Loaded {len(self.alert_rules)} alert rules")
    
    def start_monitoring(self) -> bool:
        """Start performance monitoring"""
        if self.is_running:
            self.logger.warning("Performance monitoring is already running")
            return False
        
        self.is_running = True
        self._stop_event.clear()
        
        self.monitoring_thread = threading.Thread(
            target=self._monitoring_loop,
            name="PerformanceMonitoringThread",
            daemon=True
        )
        self.monitoring_thread.start()
        
        self.logger.info("Performance monitoring started")
        increment_counter('performance_monitoring_starts_total')
        return True
    
    def stop_monitoring(self) -> bool:
        """Stop performance monitoring"""
        if not self.is_running:
            return False
        
        self.is_running = False
        self._stop_event.set()
        
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=10)
        
        self.logger.info("Performance monitoring stopped")
        increment_counter('performance_monitoring_stops_total')
        return True
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        self.logger.info(f"Performance monitoring loop started (interval: {self.monitoring_interval}s)")
        
        while not self._stop_event.wait(self.monitoring_interval):
            try:
                start_time = time.time()
                
                # Collect performance snapshot
                snapshot = self._collect_performance_snapshot()
                
                if snapshot:
                    # Store snapshot
                    self.current_snapshot = snapshot
                    self.performance_history.append(snapshot)
                    
                    # Evaluate alert rules
                    alerts_generated = self._evaluate_alert_rules(snapshot)
                    
                    # Update auto-resolved alerts
                    self._update_auto_resolved_alerts(snapshot)
                    
                    # Cleanup old data
                    self._cleanup_old_data()
                    
                    # Update metrics
                    set_gauge('performance_monitoring_active_alerts', len(self.active_alerts))
                    set_gauge('performance_monitoring_snapshots_collected', len(self.performance_history))
                    
                    if alerts_generated > 0:
                        self.logger.info(f"Performance monitoring cycle: {alerts_generated} new alerts generated")
                        increment_counter('performance_monitoring_cycles_with_alerts_total')
                    else:
                        increment_counter('performance_monitoring_cycles_no_alerts_total')
                
                # Record monitoring duration
                duration = time.time() - start_time
                observe_histogram('performance_monitoring_cycle_duration_seconds', duration)
                
            except Exception as e:
                self.logger.error(f"Performance monitoring loop error: {e}")
                increment_counter('performance_monitoring_errors_total')
        
        self.logger.info("Performance monitoring loop stopped")
    
    def _collect_performance_snapshot(self) -> Optional[PerformanceSnapshot]:
        """Collect current performance metrics"""
        try:
            snapshot = PerformanceSnapshot(timestamp=datetime.now())
            
            # System metrics
            try:
                import psutil
                snapshot.cpu_percent = psutil.cpu_percent(interval=0.1)
                memory = psutil.virtual_memory()
                snapshot.memory_percent = memory.percent
                
                disk = psutil.disk_usage('.')
                snapshot.disk_usage_percent = (disk.used / disk.total) * 100
                
                # Network connections
                connections = psutil.net_connections()
                snapshot.network_connections = len(connections)
                
            except ImportError:
                # psutil not available, use mock data
                snapshot.cpu_percent = 25.0
                snapshot.memory_percent = 60.0
                snapshot.disk_usage_percent = 45.0
                snapshot.network_connections = 10
            
            # Database metrics
            try:
                db_stats = self.db.get_database_stats()
                snapshot.database_size_mb = db_stats.get('file_size_mb', 0)
            except Exception as e:
                self.logger.debug(f"Failed to get database stats: {e}")
            
            # Lightning node metrics
            if self.lightning_client:
                try:
                    self.lightning_client.connect()
                    
                    # Check connectivity
                    info = self.lightning_client.get_info()
                    snapshot.node_connectivity = bool(info)
                    
                    # Get channel count
                    channels = self.lightning_client.list_channels()
                    snapshot.active_channels = len([ch for ch in channels if ch.get('active', False)])
                    
                    # Get recent forwarding activity
                    end_time = int(time.time())
                    start_time = end_time - 3600  # Last hour
                    forwards = self.lightning_client.get_forwarding_events(start_time, end_time)
                    snapshot.recent_forwards = len(forwards) if forwards else 0
                    
                    self.lightning_client.disconnect()
                    
                except Exception as e:
                    self.logger.debug(f"Failed to get Lightning metrics: {e}")
                    snapshot.node_connectivity = False
                    try:
                        self.lightning_client.disconnect()
                    except:
                        pass
            
            # Cache metrics
            try:
                from .fast_cache import get_fast_cache
                cache = get_fast_cache()
                stats = cache.get_stats()
                if stats.get('total_requests', 0) > 0:
                    snapshot.cache_hit_rate = (stats.get('hits', 0) / stats['total_requests']) * 100
            except Exception as e:
                self.logger.debug(f"Failed to get cache stats: {e}")
                snapshot.cache_hit_rate = 85.0  # Default
            
            return snapshot
            
        except Exception as e:
            self.logger.error(f"Failed to collect performance snapshot: {e}")
            return None
    
    def _evaluate_alert_rules(self, snapshot: PerformanceSnapshot) -> int:
        """Evaluate alert rules against current snapshot"""
        alerts_generated = 0
        
        for rule in self.alert_rules:
            if not rule.enabled:
                continue
            
            try:
                # Get metric value from snapshot
                metric_value = getattr(snapshot, rule.metric_name, None)
                if metric_value is None:
                    continue
                
                # Check if condition is met
                condition_met = self._evaluate_condition(rule, metric_value, snapshot)
                
                if condition_met:
                    # Check if we've already generated this alert recently
                    if self._is_in_cooldown(rule.name):
                        continue
                    
                    # Check duration requirement
                    if not self._check_duration_requirement(rule, metric_value):
                        continue
                    
                    # Generate alert
                    alert = self._generate_alert(rule, metric_value, snapshot)
                    if alert:
                        self._process_new_alert(alert)
                        alerts_generated += 1
                
            except Exception as e:
                self.logger.error(f"Error evaluating alert rule {rule.name}: {e}")
        
        return alerts_generated
    
    def _evaluate_condition(self, rule: AlertRule, metric_value: float, snapshot: PerformanceSnapshot) -> bool:
        """Evaluate if alert condition is met"""
        condition = rule.condition
        threshold = rule.threshold
        
        if condition == "greater_than":
            return metric_value > threshold
        elif condition == "less_than":
            return metric_value < threshold
        elif condition == "equal":
            return abs(metric_value - threshold) < 0.001
        elif condition == "not_equal":
            return abs(metric_value - threshold) >= 0.001
        elif condition == "trend_up":
            return self._check_upward_trend(rule.metric_name, threshold)
        elif condition == "trend_down":
            return self._check_downward_trend(rule.metric_name, threshold)
        else:
            self.logger.warning(f"Unknown condition: {condition}")
            return False
    
    def _check_upward_trend(self, metric_name: str, threshold: float) -> bool:
        """Check if metric shows upward trend"""
        if len(self.performance_history) < 5:
            return False
        
        # Get last 5 snapshots
        recent_snapshots = list(self.performance_history)[-5:]
        values = [getattr(snapshot, metric_name, 0) for snapshot in recent_snapshots]
        
        # Calculate trend (simple linear regression slope)
        n = len(values)
        if n < 2:
            return False
        
        x_values = list(range(n))
        sum_x = sum(x_values)
        sum_y = sum(values)
        sum_xy = sum(x * y for x, y in zip(x_values, values))
        sum_x2 = sum(x * x for x in x_values)
        
        # Slope calculation
        slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x)
        
        # Check if slope indicates growth exceeding threshold
        time_span_minutes = (recent_snapshots[-1].timestamp - recent_snapshots[0].timestamp).total_seconds() / 60
        projected_growth = slope * n * time_span_minutes
        
        return projected_growth > threshold
    
    def _check_downward_trend(self, metric_name: str, threshold: float) -> bool:
        """Check if metric shows downward trend"""
        # Similar to upward trend but checking for negative slope
        return self._check_upward_trend(metric_name, -threshold)
    
    def _is_in_cooldown(self, rule_name: str) -> bool:
        """Check if alert rule is in cooldown period"""
        if rule_name not in self.rule_last_triggered:
            return False
        
        rule = next((r for r in self.alert_rules if r.name == rule_name), None)
        if not rule:
            return False
        
        last_triggered = self.rule_last_triggered[rule_name]
        cooldown_delta = timedelta(seconds=rule.cooldown_seconds)
        
        return datetime.now() - last_triggered < cooldown_delta
    
    def _check_duration_requirement(self, rule: AlertRule, metric_value: float) -> bool:
        """Check if condition has been true for required duration"""
        # For simplicity, we'll track this in a basic way
        # In a production system, you'd want more sophisticated duration tracking
        
        if rule.duration_seconds <= self.monitoring_interval:
            return True  # Immediate trigger for short durations
        
        # Check if condition has been consistently true in recent snapshots
        required_snapshots = max(1, rule.duration_seconds // self.monitoring_interval)
        
        if len(self.performance_history) < required_snapshots:
            return False
        
        recent_snapshots = list(self.performance_history)[-required_snapshots:]
        
        for snapshot in recent_snapshots:
            snapshot_value = getattr(snapshot, rule.metric_name, None)
            if snapshot_value is None:
                return False
            
            if not self._evaluate_condition(rule, snapshot_value, snapshot):
                return False
        
        return True
    
    def _generate_alert(self, rule: AlertRule, metric_value: float, snapshot: PerformanceSnapshot) -> Alert:
        """Generate an alert from a rule and metric value"""
        alert_id = f"alert_{rule.name.lower().replace(' ', '_')}_{int(time.time())}"
        
        # Create descriptive message
        if rule.condition in ["greater_than", "less_than"]:
            comparison = "above" if rule.condition == "greater_than" else "below"
            message = f"{rule.name}: {rule.metric_name} is {comparison} threshold ({metric_value:.1f} vs {rule.threshold:.1f})"
        elif rule.condition in ["trend_up", "trend_down"]:
            direction = "increasing" if rule.condition == "trend_up" else "decreasing"
            message = f"{rule.name}: {rule.metric_name} is {direction} rapidly"
        else:
            message = f"{rule.name}: {rule.description or 'Alert condition met'}"
        
        alert = Alert(
            alert_id=alert_id,
            rule_name=rule.name,
            category=rule.category,
            severity=rule.severity,
            message=message,
            metric_name=rule.metric_name,
            current_value=metric_value,
            threshold=rule.threshold,
            timestamp=snapshot.timestamp
        )
        
        return alert
    
    def _process_new_alert(self, alert: Alert):
        """Process a newly generated alert"""
        # Add to active alerts
        self.active_alerts[alert.alert_id] = alert
        
        # Add to history
        self.alert_history.append(alert)
        
        # Update last triggered time
        self.rule_last_triggered[alert.rule_name] = alert.timestamp
        
        # Log alert
        self.logger.warning(f"ALERT [{alert.severity.name}] {alert.message}")
        
        # Execute callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                self.logger.error(f"Alert callback error: {e}")
        
        # Update metrics
        increment_counter('performance_monitoring_alerts_generated_total', {"severity": alert.severity.name})
    
    def _update_auto_resolved_alerts(self, snapshot: PerformanceSnapshot):
        """Automatically resolve alerts when conditions are no longer met"""
        resolved_alerts = []
        
        for alert_id, alert in list(self.active_alerts.items()):
            if alert.resolved:
                continue
            
            # Get current metric value
            current_value = getattr(snapshot, alert.metric_name, None)
            if current_value is None:
                continue
            
            # Find the original rule
            rule = next((r for r in self.alert_rules if r.name == alert.rule_name), None)
            if not rule:
                continue
            
            # Check if condition is no longer met
            condition_met = self._evaluate_condition(rule, current_value, snapshot)
            
            if not condition_met:
                # Auto-resolve the alert
                alert.resolved = True
                alert.resolved_at = snapshot.timestamp
                resolved_alerts.append(alert_id)
                
                self.logger.info(f"Auto-resolved alert: {alert.message}")
                increment_counter('performance_monitoring_alerts_resolved_total')
        
        # Remove resolved alerts from active list
        for alert_id in resolved_alerts:
            del self.active_alerts[alert_id]
    
    def _cleanup_old_data(self):
        """Clean up old performance data"""
        # Remove old snapshots beyond retention period
        cutoff_time = datetime.now() - timedelta(hours=self.retention_hours)
        
        while self.performance_history and self.performance_history[0].timestamp < cutoff_time:
            self.performance_history.popleft()
    
    def add_alert_callback(self, callback: Callable[[Alert], None]):
        """Add a callback function for alert notifications"""
        self.alert_callbacks.append(callback)
    
    def get_monitoring_status(self) -> Dict[str, Any]:
        """Get current monitoring status"""
        return {
            'is_running': self.is_running,
            'monitoring_interval_seconds': self.monitoring_interval,
            'retention_hours': self.retention_hours,
            'active_alerts': len(self.active_alerts),
            'total_alert_rules': len(self.alert_rules),
            'enabled_alert_rules': len([r for r in self.alert_rules if r.enabled]),
            'performance_snapshots': len(self.performance_history),
            'current_snapshot': self.current_snapshot.__dict__ if self.current_snapshot else None
        }
    
    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get current active alerts"""
        return [
            {
                'alert_id': alert.alert_id,
                'rule_name': alert.rule_name,
                'category': alert.category.value,
                'severity': alert.severity.name,
                'message': alert.message,
                'metric_name': alert.metric_name,
                'current_value': alert.current_value,
                'threshold': alert.threshold,
                'timestamp': alert.timestamp.isoformat(),
                'resolved': alert.resolved,
                'resolved_at': alert.resolved_at.isoformat() if alert.resolved_at else None
            }
            for alert in self.active_alerts.values()
        ]
    
    def get_alert_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent alert history"""
        recent_alerts = list(self.alert_history)[-limit:]
        
        return [
            {
                'alert_id': alert.alert_id,
                'rule_name': alert.rule_name,
                'category': alert.category.value,
                'severity': alert.severity.name,
                'message': alert.message,
                'metric_name': alert.metric_name,
                'current_value': alert.current_value,
                'threshold': alert.threshold,
                'timestamp': alert.timestamp.isoformat(),
                'resolved': alert.resolved,
                'resolved_at': alert.resolved_at.isoformat() if alert.resolved_at else None
            }
            for alert in recent_alerts
        ]
    
    def acknowledge_alert(self, alert_id: str, acknowledgement: str) -> bool:
        """Acknowledge an active alert"""
        if alert_id in self.active_alerts:
            self.active_alerts[alert_id].acknowledgement = acknowledgement
            self.logger.info(f"Alert {alert_id} acknowledged: {acknowledgement}")
            return True
        return False
    
    def resolve_alert(self, alert_id: str) -> bool:
        """Manually resolve an active alert"""
        if alert_id in self.active_alerts:
            alert = self.active_alerts[alert_id]
            alert.resolved = True
            alert.resolved_at = datetime.now()
            del self.active_alerts[alert_id]
            
            self.logger.info(f"Alert {alert_id} manually resolved")
            increment_counter('performance_monitoring_alerts_resolved_total')
            return True
        return False


# Global performance monitoring system instance
_performance_monitoring = None

def get_performance_monitoring(lightning_client=None) -> PerformanceMonitoringSystem:
    """Get global performance monitoring instance"""
    global _performance_monitoring
    if _performance_monitoring is None:
        _performance_monitoring = PerformanceMonitoringSystem(lightning_client)
    return _performance_monitoring

def stop_performance_monitoring():
    """Stop the global performance monitoring system"""
    global _performance_monitoring
    if _performance_monitoring:
        _performance_monitoring.stop_monitoring()
        _performance_monitoring = None