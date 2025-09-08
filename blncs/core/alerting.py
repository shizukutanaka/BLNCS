"""
Real-time alerting and notification system for BLNCS
Advanced monitoring with customizable alerts and notifications.
"""

import time
import threading
import json
import smtplib
import requests
from typing import Dict, List, Optional, Callable, Any, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import deque

from .logger import get_logger
from .config import get_config
from .fast_cache import get_fast_cache


class AlertSeverity(Enum):
    """Alert severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class NotificationChannel(Enum):
    """Notification delivery channels"""
    LOG = "log"
    EMAIL = "email"
    WEBHOOK = "webhook"
    CONSOLE = "console"


@dataclass
class Alert:
    """Alert data structure"""
    alert_id: str
    title: str
    message: str
    severity: AlertSeverity
    timestamp: datetime
    source: str
    resolved: bool = False
    resolved_timestamp: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary"""
        return {
            'alert_id': self.alert_id,
            'title': self.title,
            'message': self.message,
            'severity': self.severity.value,
            'timestamp': self.timestamp.isoformat(),
            'source': self.source,
            'resolved': self.resolved,
            'resolved_timestamp': self.resolved_timestamp.isoformat() if self.resolved_timestamp else None,
            'metadata': self.metadata
        }


@dataclass
class AlertRule:
    """Alert rule configuration"""
    rule_id: str
    name: str
    condition: Callable[[Any], bool]
    severity: AlertSeverity
    channels: List[NotificationChannel]
    cooldown_seconds: int = 300  # 5 minutes default
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NotificationConfig:
    """Notification channel configuration"""
    channel: NotificationChannel
    config: Dict[str, Any]
    enabled: bool = True


class AlertManager:
    """Advanced alerting and notification system"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config = get_config()
        self.cache = get_fast_cache()
        
        # Alerting configuration
        self.enabled = self.config.get('alerting.enabled', True)
        self.max_alerts = self.config.get('alerting.max_alerts', 1000)
        self.alert_retention_days = self.config.get('alerting.retention_days', 30)
        
        # State tracking
        self.active_alerts: Dict[str, Alert] = {}
        self.alert_history = deque(maxlen=self.max_alerts)
        self.alert_rules: Dict[str, AlertRule] = {}
        self.notification_configs: Dict[NotificationChannel, NotificationConfig] = {}
        self.rule_cooldowns: Dict[str, datetime] = {}
        
        # Threading
        self.alert_lock = threading.Lock()
        self.notification_queue = deque()
        self.notification_thread = None
        self.stop_notifications = threading.Event()
        
        self._initialize_default_rules()
        self._setup_notification_channels()
    
    def _initialize_default_rules(self) -> None:
        """Initialize default alert rules"""
        # System health alerts
        self.add_rule(AlertRule(
            rule_id="system_critical",
            name="System Critical Health",
            condition=lambda data: data.get('health') == 'critical',
            severity=AlertSeverity.CRITICAL,
            channels=[NotificationChannel.LOG, NotificationChannel.EMAIL],
            cooldown_seconds=600
        ))
        
        self.add_rule(AlertRule(
            rule_id="high_error_rate",
            name="High Error Rate",
            condition=lambda data: data.get('error_rate', 0) > 0.05,  # 5% error rate
            severity=AlertSeverity.ERROR,
            channels=[NotificationChannel.LOG, NotificationChannel.WEBHOOK],
            cooldown_seconds=300
        ))
        
        self.add_rule(AlertRule(
            rule_id="connection_failure",
            name="Lightning Connection Failure",
            condition=lambda data: data.get('event_type') == 'connection_failed',
            severity=AlertSeverity.WARNING,
            channels=[NotificationChannel.LOG, NotificationChannel.CONSOLE],
            cooldown_seconds=180
        ))
        
        self.add_rule(AlertRule(
            rule_id="channel_force_close",
            name="Channel Force Close",
            condition=lambda data: data.get('event_type') == 'channel_force_closed',
            severity=AlertSeverity.CRITICAL,
            channels=[NotificationChannel.LOG, NotificationChannel.EMAIL, NotificationChannel.WEBHOOK],
            cooldown_seconds=0  # Always alert
        ))
        
        self.add_rule(AlertRule(
            rule_id="low_balance",
            name="Low Balance Warning",
            condition=lambda data: (
                data.get('balance_type') == 'total' and 
                data.get('balance', 0) < 1000000  # Less than 1M sats
            ),
            severity=AlertSeverity.WARNING,
            channels=[NotificationChannel.LOG],
            cooldown_seconds=3600  # 1 hour
        ))
    
    def _setup_notification_channels(self) -> None:
        """Setup notification channels from configuration"""
        # Email configuration
        if self.config.get('alerting.email.enabled', False):
            self.notification_configs[NotificationChannel.EMAIL] = NotificationConfig(
                channel=NotificationChannel.EMAIL,
                config={
                    'smtp_server': self.config.get('alerting.email.smtp_server'),
                    'smtp_port': self.config.get('alerting.email.smtp_port', 587),
                    'username': self.config.get('alerting.email.username'),
                    'password': self.config.get('alerting.email.password'),
                    'from_email': self.config.get('alerting.email.from_email'),
                    'to_emails': self.config.get('alerting.email.to_emails', []),
                    'use_tls': self.config.get('alerting.email.use_tls', True)
                }
            )
        
        # Webhook configuration
        if self.config.get('alerting.webhook.enabled', False):
            self.notification_configs[NotificationChannel.WEBHOOK] = NotificationConfig(
                channel=NotificationChannel.WEBHOOK,
                config={
                    'url': self.config.get('alerting.webhook.url'),
                    'method': self.config.get('alerting.webhook.method', 'POST'),
                    'headers': self.config.get('alerting.webhook.headers', {}),
                    'timeout': self.config.get('alerting.webhook.timeout', 10)
                }
            )
        
        # Console and log are always available
        self.notification_configs[NotificationChannel.CONSOLE] = NotificationConfig(
            channel=NotificationChannel.CONSOLE,
            config={}
        )
        
        self.notification_configs[NotificationChannel.LOG] = NotificationConfig(
            channel=NotificationChannel.LOG,
            config={}
        )
    
    def start_notification_service(self) -> None:
        """Start notification service"""
        if not self.enabled:
            return
        
        if self.notification_thread and self.notification_thread.is_alive():
            return
        
        self.stop_notifications.clear()
        self.notification_thread = threading.Thread(target=self._notification_worker, daemon=True)
        self.notification_thread.start()
        self.logger.info("Notification service started")
    
    def stop_notification_service(self) -> None:
        """Stop notification service"""
        self.stop_notifications.set()
        if self.notification_thread:
            self.notification_thread.join(timeout=5)
        self.logger.info("Notification service stopped")
    
    def _notification_worker(self) -> None:
        """Background worker for sending notifications"""
        while not self.stop_notifications.is_set():
            try:
                if self.notification_queue:
                    notification = self.notification_queue.popleft()
                    self._send_notification(notification)
                else:
                    time.sleep(0.1)
            except Exception as e:
                self.logger.error(f"Notification worker error: {e}")
                time.sleep(1)
    
    def add_rule(self, rule: AlertRule) -> None:
        """Add an alert rule"""
        self.alert_rules[rule.rule_id] = rule
        self.logger.info(f"Added alert rule: {rule.name}")
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove an alert rule"""
        if rule_id in self.alert_rules:
            del self.alert_rules[rule_id]
            self.logger.info(f"Removed alert rule: {rule_id}")
            return True
        return False
    
    def check_conditions(self, data: Dict[str, Any], source: str = "system") -> None:
        """Check all alert rules against data"""
        if not self.enabled:
            return
        
        current_time = datetime.now()
        
        for rule in self.alert_rules.values():
            if not rule.enabled:
                continue
            
            # Check cooldown
            if rule.rule_id in self.rule_cooldowns:
                last_alert = self.rule_cooldowns[rule.rule_id]
                if (current_time - last_alert).total_seconds() < rule.cooldown_seconds:
                    continue
            
            # Check condition
            try:
                if rule.condition(data):
                    self.trigger_alert(
                        rule_id=rule.rule_id,
                        title=rule.name,
                        message=f"Alert triggered: {rule.name}",
                        severity=rule.severity,
                        source=source,
                        channels=rule.channels,
                        metadata=data
                    )
                    
                    # Update cooldown
                    if rule.cooldown_seconds > 0:
                        self.rule_cooldowns[rule.rule_id] = current_time
                        
            except Exception as e:
                self.logger.error(f"Error checking rule {rule.rule_id}: {e}")
    
    def trigger_alert(self, rule_id: str, title: str, message: str, 
                     severity: AlertSeverity, source: str,
                     channels: List[NotificationChannel],
                     metadata: Dict[str, Any] = None) -> str:
        """Trigger a new alert"""
        if not self.enabled:
            return ""
        
        # Generate alert ID
        alert_id = f"{rule_id}_{int(time.time())}"
        
        # Create alert
        alert = Alert(
            alert_id=alert_id,
            title=title,
            message=message,
            severity=severity,
            timestamp=datetime.now(),
            source=source,
            metadata=metadata or {}
        )
        
        with self.alert_lock:
            # Add to active alerts
            self.active_alerts[alert_id] = alert
            
            # Add to history
            self.alert_history.append(alert)
            
            # Queue notifications
            for channel in channels:
                if channel in self.notification_configs and self.notification_configs[channel].enabled:
                    notification = {
                        'alert': alert,
                        'channel': channel,
                        'config': self.notification_configs[channel].config
                    }
                    self.notification_queue.append(notification)
        
        self.logger.info(f"Alert triggered: {alert_id} - {title}")
        return alert_id
    
    def resolve_alert(self, alert_id: str, resolution_message: str = "") -> bool:
        """Resolve an active alert"""
        with self.alert_lock:
            if alert_id in self.active_alerts:
                alert = self.active_alerts[alert_id]
                alert.resolved = True
                alert.resolved_timestamp = datetime.now()
                if resolution_message:
                    alert.metadata['resolution_message'] = resolution_message
                
                # Remove from active alerts
                del self.active_alerts[alert_id]
                
                self.logger.info(f"Alert resolved: {alert_id}")
                return True
            return False
    
    def _send_notification(self, notification: Dict[str, Any]) -> None:
        """Send a notification through specified channel"""
        alert = notification['alert']
        channel = notification['channel']
        config = notification['config']
        
        try:
            if channel == NotificationChannel.LOG:
                self._send_log_notification(alert)
            elif channel == NotificationChannel.CONSOLE:
                self._send_console_notification(alert)
            elif channel == NotificationChannel.EMAIL:
                self._send_email_notification(alert, config)
            elif channel == NotificationChannel.WEBHOOK:
                self._send_webhook_notification(alert, config)
                
        except Exception as e:
            self.logger.error(f"Failed to send {channel.value} notification: {e}")
    
    def _send_log_notification(self, alert: Alert) -> None:
        """Send notification to log"""
        log_level = {
            AlertSeverity.INFO: self.logger.info,
            AlertSeverity.WARNING: self.logger.warning,
            AlertSeverity.ERROR: self.logger.error,
            AlertSeverity.CRITICAL: self.logger.critical
        }
        
        log_func = log_level.get(alert.severity, self.logger.info)
        log_func(f"ALERT [{alert.severity.value.upper()}] {alert.title}: {alert.message}")
    
    def _send_console_notification(self, alert: Alert) -> None:
        """Send notification to console"""
        severity_colors = {
            AlertSeverity.INFO: '\033[94m',      # Blue
            AlertSeverity.WARNING: '\033[93m',   # Yellow
            AlertSeverity.ERROR: '\033[91m',     # Red
            AlertSeverity.CRITICAL: '\033[95m'   # Magenta
        }
        
        color = severity_colors.get(alert.severity, '')
        reset = '\033[0m'
        
        print(f"{color}[ALERT {alert.severity.value.upper()}]{reset} {alert.title}: {alert.message}")
    
    def _send_email_notification(self, alert: Alert, config: Dict[str, Any]) -> None:
        """Send email notification"""
        if not config.get('to_emails'):
            return
        
        msg = MIMEMultipart()
        msg['From'] = config['from_email']
        msg['To'] = ', '.join(config['to_emails'])
        msg['Subject'] = f"[BLNCS Alert {alert.severity.value.upper()}] {alert.title}"
        
        # Create email body
        body = f"""
BLNCS Alert Notification

Alert ID: {alert.alert_id}
Severity: {alert.severity.value.upper()}
Source: {alert.source}
Timestamp: {alert.timestamp.isoformat()}

Title: {alert.title}
Message: {alert.message}

Additional Information:
{json.dumps(alert.metadata, indent=2)}

--
This is an automated alert from BLNCS.
"""
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Send email
        with smtplib.SMTP(config['smtp_server'], config['smtp_port']) as server:
            if config.get('use_tls', True):
                server.starttls()
            
            if config.get('username') and config.get('password'):
                server.login(config['username'], config['password'])
            
            server.send_message(msg)
    
    def _send_webhook_notification(self, alert: Alert, config: Dict[str, Any]) -> None:
        """Send webhook notification"""
        url = config.get('url')
        if not url:
            return
        
        # Prepare payload
        payload = {
            'alert': alert.to_dict(),
            'timestamp': datetime.now().isoformat(),
            'source': 'BLNCS'
        }
        
        headers = config.get('headers', {})
        headers.setdefault('Content-Type', 'application/json')
        
        method = config.get('method', 'POST').upper()
        timeout = config.get('timeout', 10)
        
        # Send webhook
        if method == 'POST':
            requests.post(url, json=payload, headers=headers, timeout=timeout)
        elif method == 'PUT':
            requests.put(url, json=payload, headers=headers, timeout=timeout)
    
    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get all active alerts"""
        with self.alert_lock:
            return [alert.to_dict() for alert in self.active_alerts.values()]
    
    def get_alert_history(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get alert history for specified period"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        recent_alerts = [
            alert for alert in self.alert_history
            if alert.timestamp >= cutoff_time
        ]
        
        return [alert.to_dict() for alert in recent_alerts]
    
    def get_alert_stats(self, hours: int = 24) -> Dict[str, Any]:
        """Get alert statistics"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        recent_alerts = [
            alert for alert in self.alert_history
            if alert.timestamp >= cutoff_time
        ]
        
        if not recent_alerts:
            return {
                'period_hours': hours,
                'total_alerts': 0,
                'by_severity': {},
                'by_source': {}
            }
        
        # Count by severity
        by_severity = {}
        by_source = {}
        
        for alert in recent_alerts:
            # By severity
            severity = alert.severity.value
            by_severity[severity] = by_severity.get(severity, 0) + 1
            
            # By source
            source = alert.source
            by_source[source] = by_source.get(source, 0) + 1
        
        return {
            'period_hours': hours,
            'total_alerts': len(recent_alerts),
            'active_alerts': len(self.active_alerts),
            'by_severity': by_severity,
            'by_source': by_source,
            'notification_queue_size': len(self.notification_queue)
        }


# Global instance
_alert_manager = None

def get_alert_manager() -> AlertManager:
    """Get global alert manager instance"""
    global _alert_manager
    if _alert_manager is None:
        _alert_manager = AlertManager()
    return _alert_manager