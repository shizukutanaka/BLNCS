"""
Advanced Alert Management System for BLNCS
Monitors Lightning Network operations and generates intelligent alerts.
"""

import time
import asyncio
import json
from typing import Dict, List, Optional, Any, Callable, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import threading
from collections import deque, defaultdict

from ..core.logger import get_logger
from ..core.metrics import get_metrics_collector
from ..core.config_manager import get_config_manager
from ..lightning.client import LightningClient
from ..lightning.channel_manager import ChannelManager
from ..lightning.payment_manager import PaymentManager


class AlertSeverity(Enum):
    """Alert severity levels"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class AlertCategory(Enum):
    """Alert categories"""
    NODE_HEALTH = "node_health"
    CHANNEL_MANAGEMENT = "channel_management"
    PAYMENT_PROCESSING = "payment_processing"
    SECURITY = "security"
    PERFORMANCE = "performance"
    SYSTEM = "system"


@dataclass
class Alert:
    """Alert information"""
    id: str
    category: AlertCategory
    severity: AlertSeverity
    title: str
    description: str
    timestamp: datetime = field(default_factory=datetime.now)
    acknowledged: bool = False
    resolved: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    auto_resolve: bool = True
    ttl_seconds: int = 3600  # 1 hour default
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'category': self.category.value,
            'severity': self.severity.value,
            'title': self.title,
            'description': self.description,
            'timestamp': self.timestamp.isoformat(),
            'acknowledged': self.acknowledged,
            'resolved': self.resolved,
            'metadata': self.metadata,
            'auto_resolve': self.auto_resolve,
            'ttl_seconds': self.ttl_seconds
        }


@dataclass
class AlertRule:
    """Alert rule definition"""
    name: str
    category: AlertCategory
    severity: AlertSeverity
    condition: Callable[[Dict[str, Any]], bool]
    description: str
    enabled: bool = True
    cooldown_seconds: int = 300  # 5 minutes
    max_alerts_per_hour: int = 10
    auto_resolve: bool = True


class AlertManager:
    """Advanced alert management system"""
    
    def __init__(self, client: LightningClient):
        self.client = client
        self.logger = get_logger(__name__)
        self.metrics = get_metrics_collector()
        self.config = get_config_manager().get_all()
        
        # Alert storage
        self.active_alerts: Dict[str, Alert] = {}
        self.alert_history: deque = deque(maxlen=10000)
        self.alert_rules: Dict[str, AlertRule] = {}
        
        # Monitoring state
        self.monitoring_active = False
        self.monitoring_thread: Optional[threading.Thread] = None
        self.stop_monitoring = threading.Event()
        
        # Rate limiting
        self.rule_last_triggered: Dict[str, datetime] = {}
        self.rule_trigger_counts: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        
        # Notification handlers
        self.notification_handlers: List[Callable[[Alert], None]] = []
        
        # Initialize monitoring components
        self.channel_manager = ChannelManager(client)
        self.payment_manager = PaymentManager(client)
        
        # Setup default rules
        self._setup_default_rules()
    
    def _setup_default_rules(self):
        """Setup default alert rules"""
        
        # Node connectivity rule
        self.add_alert_rule(AlertRule(
            name="node_disconnected",
            category=AlertCategory.NODE_HEALTH,
            severity=AlertSeverity.CRITICAL,
            condition=lambda data: not data.get('node_connected', True),
            description="Lightning node is disconnected or unreachable",
            cooldown_seconds=60
        ))
        
        # Channel balance rule
        self.add_alert_rule(AlertRule(
            name="channel_severely_imbalanced",
            category=AlertCategory.CHANNEL_MANAGEMENT,
            severity=AlertSeverity.WARNING,
            condition=lambda data: any(
                ch.get('balance_score', 0) > 0.45 
                for ch in data.get('channels', [])
            ),
            description="One or more channels are severely imbalanced",
            cooldown_seconds=1800  # 30 minutes
        ))
        
        # Payment failure rate rule
        self.add_alert_rule(AlertRule(
            name="high_payment_failure_rate",
            category=AlertCategory.PAYMENT_PROCESSING,
            severity=AlertSeverity.WARNING,
            condition=lambda data: data.get('payment_failure_rate', 0) > 0.2,
            description="Payment failure rate is unusually high",
            cooldown_seconds=600  # 10 minutes
        ))
        
        # Low liquidity rule
        self.add_alert_rule(AlertRule(
            name="low_outbound_liquidity",
            category=AlertCategory.CHANNEL_MANAGEMENT,
            severity=AlertSeverity.WARNING,
            condition=lambda data: data.get('outbound_liquidity_ratio', 1.0) < 0.1,
            description="Outbound liquidity is critically low",
            cooldown_seconds=3600  # 1 hour
        ))
        
        # High fee environment
        self.add_alert_rule(AlertRule(
            name="high_fee_environment",
            category=AlertCategory.PERFORMANCE,
            severity=AlertSeverity.INFO,
            condition=lambda data: data.get('avg_fee_rate', 0) > 0.01,  # 1%
            description="Network fees are unusually high",
            cooldown_seconds=7200  # 2 hours
        ))
        
        # Channel force closure
        self.add_alert_rule(AlertRule(
            name="channel_force_closed",
            category=AlertCategory.SECURITY,
            severity=AlertSeverity.CRITICAL,
            condition=lambda data: data.get('forced_channel_closures', 0) > 0,
            description="One or more channels were force-closed",
            auto_resolve=False
        ))
        
        # System resource alerts
        self.add_alert_rule(AlertRule(
            name="high_memory_usage",
            category=AlertCategory.SYSTEM,
            severity=AlertSeverity.WARNING,
            condition=lambda data: data.get('memory_usage_percent', 0) > 85,
            description="System memory usage is high",
            cooldown_seconds=300
        ))
        
        self.add_alert_rule(AlertRule(
            name="high_cpu_usage",
            category=AlertCategory.SYSTEM,
            severity=AlertSeverity.WARNING,
            condition=lambda data: data.get('cpu_usage_percent', 0) > 80,
            description="System CPU usage is high",
            cooldown_seconds=300
        ))
    
    def add_alert_rule(self, rule: AlertRule):
        """Add an alert rule"""
        self.alert_rules[rule.name] = rule
        self.logger.info(f"Added alert rule: {rule.name}")
    
    def remove_alert_rule(self, rule_name: str):
        """Remove an alert rule"""
        if rule_name in self.alert_rules:
            del self.alert_rules[rule_name]
            self.logger.info(f"Removed alert rule: {rule_name}")
    
    def add_notification_handler(self, handler: Callable[[Alert], None]):
        """Add notification handler"""
        self.notification_handlers.append(handler)
    
    def start_monitoring(self, interval: int = 60):
        """Start continuous monitoring"""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.stop_monitoring.clear()
        
        self.monitoring_thread = threading.Thread(
            target=self._monitoring_loop,
            args=(interval,),
            daemon=True
        )
        self.monitoring_thread.start()
        
        self.logger.info("Alert monitoring started")
    
    def stop_monitoring_system(self):
        """Stop monitoring"""
        if not self.monitoring_active:
            return
        
        self.stop_monitoring.set()
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        
        self.monitoring_active = False
        self.logger.info("Alert monitoring stopped")
    
    def _monitoring_loop(self, interval: int):
        """Main monitoring loop"""
        while not self.stop_monitoring.wait(interval):
            try:
                self._check_all_rules()
                self._cleanup_expired_alerts()
                self._record_monitoring_metrics()
                
            except Exception as e:
                self.logger.error(f"Monitoring loop error: {e}")
    
    def _check_all_rules(self):
        """Check all alert rules"""
        try:
            # Collect monitoring data
            monitoring_data = self._collect_monitoring_data()
            
            for rule_name, rule in self.alert_rules.items():
                if not rule.enabled:
                    continue
                
                # Check rate limiting
                if self._is_rate_limited(rule_name, rule):
                    continue
                
                try:
                    # Evaluate rule condition
                    if rule.condition(monitoring_data):
                        self._trigger_alert(rule, monitoring_data)
                        self._record_rule_trigger(rule_name)
                    
                except Exception as e:
                    self.logger.error(f"Error evaluating rule {rule_name}: {e}")
            
        except Exception as e:
            self.logger.error(f"Failed to check alert rules: {e}")
    
    def _collect_monitoring_data(self) -> Dict[str, Any]:
        """Collect monitoring data from various sources"""
        data = {}
        
        try:
            # Node connectivity
            try:
                node_info = self.client.get_info()
                data['node_connected'] = node_info is not None
                if node_info:
                    data['node_block_height'] = node_info.get('block_height', 0)
                    data['node_synced'] = node_info.get('synced_to_chain', False)
            except:
                data['node_connected'] = False
            
            # Channel data
            try:
                channels = self.channel_manager.get_all_channels()
                data['channels'] = [
                    {
                        'id': ch.channel_id,
                        'capacity': ch.capacity,
                        'local_balance': ch.local_balance,
                        'remote_balance': ch.remote_balance,
                        'balance_score': ch.metrics.get('balance_score', 0),
                        'state': ch.state.value
                    }
                    for ch in channels
                ]
                
                # Calculate aggregated metrics
                active_channels = [ch for ch in channels if ch.state.value == 'active']
                if active_channels:
                    total_capacity = sum(ch.capacity for ch in active_channels)
                    total_local = sum(ch.local_balance for ch in active_channels)
                    total_remote = sum(ch.remote_balance for ch in active_channels)
                    
                    data['total_capacity'] = total_capacity
                    data['total_local_balance'] = total_local
                    data['total_remote_balance'] = total_remote
                    data['outbound_liquidity_ratio'] = total_local / total_capacity if total_capacity > 0 else 0
                    data['inbound_liquidity_ratio'] = total_remote / total_capacity if total_capacity > 0 else 0
                
            except Exception as e:
                self.logger.error(f"Failed to collect channel data: {e}")
                data['channels'] = []
            
            # Payment data
            try:
                payment_summary = self.payment_manager.get_payment_summary()
                payments_data = payment_summary.get('payments', {})
                
                data['payment_failure_rate'] = 1.0 - payments_data.get('success_rate', 1.0)
                data['avg_fee_rate'] = payments_data.get('avg_fee_rate', 0)
                data['total_payments'] = payments_data.get('total_count', 0)
                
            except Exception as e:
                self.logger.error(f"Failed to collect payment data: {e}")
            
            # System resources (if available)
            try:
                import psutil
                data['memory_usage_percent'] = psutil.virtual_memory().percent
                data['cpu_usage_percent'] = psutil.cpu_percent(interval=1)
                data['disk_usage_percent'] = psutil.disk_usage('/').percent
            except:
                pass  # psutil not available
            
            # Check for forced closures (mock implementation)
            data['forced_channel_closures'] = 0  # Would check actual force closures
            
        except Exception as e:
            self.logger.error(f"Failed to collect monitoring data: {e}")
        
        return data
    
    def _is_rate_limited(self, rule_name: str, rule: AlertRule) -> bool:
        """Check if rule is rate limited"""
        now = datetime.now()
        
        # Check cooldown
        if rule_name in self.rule_last_triggered:
            time_since_last = (now - self.rule_last_triggered[rule_name]).total_seconds()
            if time_since_last < rule.cooldown_seconds:
                return True
        
        # Check hourly limit
        triggers = self.rule_trigger_counts[rule_name]
        hour_ago = now - timedelta(hours=1)
        recent_triggers = [t for t in triggers if t > hour_ago]
        
        if len(recent_triggers) >= rule.max_alerts_per_hour:
            return True
        
        return False
    
    def _trigger_alert(self, rule: AlertRule, monitoring_data: Dict[str, Any]):
        """Trigger an alert"""
        alert_id = f"{rule.name}_{int(time.time())}"
        
        alert = Alert(
            id=alert_id,
            category=rule.category,
            severity=rule.severity,
            title=f"{rule.name.replace('_', ' ').title()}",
            description=rule.description,
            auto_resolve=rule.auto_resolve,
            metadata={'rule': rule.name, 'data': monitoring_data}
        )
        
        self.active_alerts[alert_id] = alert
        self.alert_history.append(alert)
        
        # Send notifications
        self._send_notifications(alert)
        
        # Record metrics
        self.metrics.record_metric('alert.triggered', 1, {
            'rule': rule.name,
            'category': rule.category.value,
            'severity': rule.severity.value
        })
        
        self.logger.warning(f"Alert triggered: {rule.name} - {rule.description}")
    
    def _record_rule_trigger(self, rule_name: str):
        """Record that a rule was triggered"""
        now = datetime.now()
        self.rule_last_triggered[rule_name] = now
        self.rule_trigger_counts[rule_name].append(now)
    
    def _send_notifications(self, alert: Alert):
        """Send alert notifications"""
        for handler in self.notification_handlers:
            try:
                handler(alert)
            except Exception as e:
                self.logger.error(f"Notification handler failed: {e}")
    
    def _cleanup_expired_alerts(self):
        """Clean up expired alerts"""
        now = datetime.now()
        expired_alerts = []
        
        for alert_id, alert in self.active_alerts.items():
            # Check TTL
            if (now - alert.timestamp).total_seconds() > alert.ttl_seconds:
                expired_alerts.append(alert_id)
            
            # Auto-resolve if conditions no longer met
            elif alert.auto_resolve and not alert.resolved:
                # Would check if conditions are still met
                pass
        
        for alert_id in expired_alerts:
            del self.active_alerts[alert_id]
    
    def _record_monitoring_metrics(self):
        """Record monitoring metrics"""
        self.metrics.record_metric('alerts.active_count', len(self.active_alerts))
        
        # Count by severity
        severity_counts = defaultdict(int)
        for alert in self.active_alerts.values():
            severity_counts[alert.severity.value] += 1
        
        for severity, count in severity_counts.items():
            self.metrics.record_metric(f'alerts.{severity}_count', count)
    
    def acknowledge_alert(self, alert_id: str, user: str = "system") -> bool:
        """Acknowledge an alert"""
        if alert_id in self.active_alerts:
            self.active_alerts[alert_id].acknowledged = True
            self.active_alerts[alert_id].metadata['acknowledged_by'] = user
            self.active_alerts[alert_id].metadata['acknowledged_at'] = datetime.now().isoformat()
            
            self.logger.info(f"Alert acknowledged: {alert_id} by {user}")
            return True
        
        return False
    
    def resolve_alert(self, alert_id: str, user: str = "system") -> bool:
        """Resolve an alert"""
        if alert_id in self.active_alerts:
            self.active_alerts[alert_id].resolved = True
            self.active_alerts[alert_id].metadata['resolved_by'] = user
            self.active_alerts[alert_id].metadata['resolved_at'] = datetime.now().isoformat()
            
            # Remove from active alerts
            del self.active_alerts[alert_id]
            
            self.logger.info(f"Alert resolved: {alert_id} by {user}")
            return True
        
        return False
    
    def get_active_alerts(self, severity: AlertSeverity = None, 
                         category: AlertCategory = None) -> List[Alert]:
        """Get active alerts with optional filtering"""
        alerts = list(self.active_alerts.values())
        
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        
        if category:
            alerts = [a for a in alerts if a.category == category]
        
        # Sort by severity and timestamp
        severity_order = {AlertSeverity.EMERGENCY: 0, AlertSeverity.CRITICAL: 1, 
                         AlertSeverity.WARNING: 2, AlertSeverity.INFO: 3}
        
        alerts.sort(key=lambda a: (severity_order.get(a.severity, 4), a.timestamp))
        
        return alerts
    
    def get_alert_statistics(self) -> Dict[str, Any]:
        """Get alert system statistics"""
        now = datetime.now()
        last_24h = now - timedelta(days=1)
        
        recent_alerts = [a for a in self.alert_history if a.timestamp > last_24h]
        
        stats = {
            'active_alerts': len(self.active_alerts),
            'total_rules': len(self.alert_rules),
            'enabled_rules': len([r for r in self.alert_rules.values() if r.enabled]),
            'alerts_last_24h': len(recent_alerts),
            'monitoring_active': self.monitoring_active,
            'notification_handlers': len(self.notification_handlers)
        }
        
        # Count by severity
        for severity in AlertSeverity:
            count = len([a for a in self.active_alerts.values() if a.severity == severity])
            stats[f'{severity.value}_alerts'] = count
        
        # Count by category  
        for category in AlertCategory:
            count = len([a for a in self.active_alerts.values() if a.category == category])
            stats[f'{category.value}_alerts'] = count
        
        return stats
    
    def export_alerts(self, format: str = 'json') -> str:
        """Export alerts in specified format"""
        alerts_data = {
            'active_alerts': [alert.to_dict() for alert in self.active_alerts.values()],
            'alert_history': [alert.to_dict() for alert in list(self.alert_history)[-100:]],  # Last 100
            'export_timestamp': datetime.now().isoformat()
        }
        
        if format.lower() == 'json':
            return json.dumps(alerts_data, indent=2)
        else:
            raise ValueError(f"Unsupported export format: {format}")


# Notification handlers
def console_notification_handler(alert: Alert):
    """Simple console notification handler"""
    print(f"🚨 ALERT [{alert.severity.value.upper()}] {alert.title}")
    print(f"   {alert.description}")
    print(f"   Time: {alert.timestamp}")
    print(f"   ID: {alert.id}")
    print()


def log_notification_handler(alert: Alert):
    """Log notification handler"""
    logger = get_logger('alerts')
    
    if alert.severity == AlertSeverity.EMERGENCY:
        logger.critical(f"EMERGENCY: {alert.title} - {alert.description}")
    elif alert.severity == AlertSeverity.CRITICAL:
        logger.error(f"CRITICAL: {alert.title} - {alert.description}")
    elif alert.severity == AlertSeverity.WARNING:
        logger.warning(f"WARNING: {alert.title} - {alert.description}")
    else:
        logger.info(f"INFO: {alert.title} - {alert.description}")


def get_alert_manager(client: Optional[LightningClient] = None) -> AlertManager:
    """Get alert manager instance"""
    if client is None:
        from ..lightning.client import LightningClient
        config = get_config_manager().get_all()
        client = LightningClient(config)
    
    alert_manager = AlertManager(client)
    
    # Add default notification handlers
    alert_manager.add_notification_handler(log_notification_handler)
    if get_config_manager().get_all().get('alerts', {}).get('console_notifications', True):
        alert_manager.add_notification_handler(console_notification_handler)
    
    return alert_manager