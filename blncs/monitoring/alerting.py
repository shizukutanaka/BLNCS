"""
Enterprise Alerting System
Advanced alerting with escalation, notification routing, and alert correlation.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Callable, Union, Set
from dataclasses import dataclass, field
from enum import Enum
import json
import time
from datetime import datetime, timedelta
from pathlib import Path
import smtplib
import ssl
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
import requests
import threading
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

class AlertSeverity(Enum):
    """Alert severity levels."""
    CRITICAL = "critical"
    HIGH = "high" 
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class AlertState(Enum):
    """Alert lifecycle states."""
    FIRING = "firing"
    RESOLVED = "resolved"
    ACKNOWLEDGED = "acknowledged"
    SILENCED = "silenced"
    ESCALATED = "escalated"

class NotificationChannel(Enum):
    """Supported notification channels."""
    EMAIL = "email"
    SLACK = "slack"
    WEBHOOK = "webhook"
    SMS = "sms"
    PAGERDUTY = "pagerduty"

@dataclass
class AlertRule:
    """Alert rule configuration."""
    name: str
    condition: str  # PromQL-like expression
    severity: AlertSeverity
    threshold: float
    duration: timedelta
    description: str
    labels: Dict[str, str] = field(default_factory=dict)
    annotations: Dict[str, str] = field(default_factory=dict)
    notification_channels: List[NotificationChannel] = field(default_factory=list)
    escalation_delay: Optional[timedelta] = None
    auto_resolve: bool = True
    silence_duration: Optional[timedelta] = None

@dataclass
class Alert:
    """Active alert instance."""
    rule_name: str
    severity: AlertSeverity
    state: AlertState
    message: str
    value: float
    threshold: float
    labels: Dict[str, str] = field(default_factory=dict)
    annotations: Dict[str, str] = field(default_factory=dict)
    starts_at: datetime = field(default_factory=datetime.utcnow)
    ends_at: Optional[datetime] = None
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = None
    escalated_at: Optional[datetime] = None
    notification_sent: Set[NotificationChannel] = field(default_factory=set)
    
    @property
    def duration(self) -> timedelta:
        """Get alert duration."""
        end_time = self.ends_at or datetime.utcnow()
        return end_time - self.starts_at
    
    @property
    def is_active(self) -> bool:
        """Check if alert is currently active."""
        return self.state in [AlertState.FIRING, AlertState.ESCALATED]

@dataclass
class NotificationConfig:
    """Notification channel configuration."""
    channel: NotificationChannel
    config: Dict[str, Any]
    enabled: bool = True
    rate_limit: Optional[timedelta] = None
    last_sent: Optional[datetime] = None

class AlertManager:
    """Enterprise alert management system."""
    
    def __init__(self):
        """Initialize the alert manager."""
        self.rules: Dict[str, AlertRule] = {}
        self.active_alerts: Dict[str, Alert] = {}
        self.alert_history: List[Alert] = []
        self.notification_configs: Dict[NotificationChannel, NotificationConfig] = {}
        
        # Threading
        self.evaluation_thread: Optional[threading.Thread] = None
        self.notification_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="alerting")
        
        # Configuration
        self.evaluation_interval = 30.0  # seconds
        self.max_alert_history = 10000
        
        # Correlation and grouping
        self.alert_groups: Dict[str, List[str]] = {}
        self.correlation_rules: List[Dict[str, Any]] = []
        
        logger.info("Alert manager initialized")
    
    def add_rule(self, rule: AlertRule) -> None:
        """Add an alert rule."""
        self.rules[rule.name] = rule
        logger.info(f"Added alert rule: {rule.name} (severity: {rule.severity.value})")
    
    def remove_rule(self, rule_name: str) -> None:
        """Remove an alert rule."""
        if rule_name in self.rules:
            del self.rules[rule_name]
            # Resolve any active alerts for this rule
            alert_id = self._get_alert_id(rule_name, {})
            if alert_id in self.active_alerts:
                self.resolve_alert(alert_id)
            logger.info(f"Removed alert rule: {rule_name}")
    
    def configure_notification(self, config: NotificationConfig) -> None:
        """Configure a notification channel."""
        self.notification_configs[config.channel] = config
        logger.info(f"Configured notification channel: {config.channel.value}")
    
    def _get_alert_id(self, rule_name: str, labels: Dict[str, str]) -> str:
        """Generate unique alert ID."""
        label_str = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
        return f"{rule_name}|{label_str}"
    
    def evaluate_rules(self, metrics: Dict[str, float]) -> None:
        """Evaluate alert rules against current metrics."""
        current_time = datetime.utcnow()
        
        for rule in self.rules.values():
            try:
                self._evaluate_rule(rule, metrics, current_time)
            except Exception as e:
                logger.error(f"Failed to evaluate rule {rule.name}: {e}")
    
    def _evaluate_rule(self, rule: AlertRule, metrics: Dict[str, float], current_time: datetime) -> None:
        """Evaluate a single alert rule."""
        # Simplified metric evaluation - in production would use PromQL
        metric_name = rule.condition.split()[0]  # Extract metric name
        current_value = metrics.get(metric_name, 0.0)
        
        alert_id = self._get_alert_id(rule.name, rule.labels)
        existing_alert = self.active_alerts.get(alert_id)
        
        # Check if threshold is breached
        threshold_breached = self._check_threshold(current_value, rule.threshold, rule.condition)
        
        if threshold_breached:
            if existing_alert:
                # Update existing alert
                existing_alert.value = current_value
                
                # Check for escalation
                if (rule.escalation_delay and 
                    existing_alert.state == AlertState.FIRING and
                    not existing_alert.escalated_at and
                    existing_alert.duration > rule.escalation_delay):
                    self._escalate_alert(existing_alert)
            else:
                # Create new alert
                alert = Alert(
                    rule_name=rule.name,
                    severity=rule.severity,
                    state=AlertState.FIRING,
                    message=self._format_alert_message(rule, current_value),
                    value=current_value,
                    threshold=rule.threshold,
                    labels=rule.labels.copy(),
                    annotations=rule.annotations.copy(),
                    starts_at=current_time
                )
                
                self.active_alerts[alert_id] = alert
                
                # Schedule notification
                self._schedule_notification(alert, rule)
                
                logger.warning(f"Alert fired: {rule.name} (value: {current_value}, threshold: {rule.threshold})")
        else:
            # Resolve alert if it exists and auto-resolve is enabled
            if existing_alert and rule.auto_resolve and existing_alert.state == AlertState.FIRING:
                self.resolve_alert(alert_id)
    
    def _check_threshold(self, value: float, threshold: float, condition: str) -> bool:
        """Check if value breaches threshold based on condition."""
        if ">" in condition:
            return value > threshold
        elif "<" in condition:
            return value < threshold
        elif ">=" in condition:
            return value >= threshold
        elif "<=" in condition:
            return value <= threshold
        elif "==" in condition:
            return abs(value - threshold) < 0.001
        else:
            return value > threshold  # Default to greater than
    
    def _format_alert_message(self, rule: AlertRule, value: float) -> str:
        """Format alert message."""
        return f"{rule.description} - Current value: {value:.2f}, Threshold: {rule.threshold:.2f}"
    
    def _escalate_alert(self, alert: Alert) -> None:
        """Escalate an alert."""
        alert.state = AlertState.ESCALATED
        alert.escalated_at = datetime.utcnow()
        
        # Send escalation notifications
        rule = self.rules.get(alert.rule_name)
        if rule:
            self._schedule_notification(alert, rule, escalation=True)
        
        logger.critical(f"Alert escalated: {alert.rule_name}")
    
    def resolve_alert(self, alert_id: str, resolved_by: Optional[str] = None) -> None:
        """Resolve an active alert."""
        if alert_id not in self.active_alerts:
            return
        
        alert = self.active_alerts[alert_id]
        alert.state = AlertState.RESOLVED
        alert.ends_at = datetime.utcnow()
        
        # Move to history
        self.alert_history.append(alert)
        del self.active_alerts[alert_id]
        
        # Trim history if needed
        if len(self.alert_history) > self.max_alert_history:
            self.alert_history = self.alert_history[-self.max_alert_history:]
        
        logger.info(f"Alert resolved: {alert.rule_name}")
    
    def acknowledge_alert(self, alert_id: str, acknowledged_by: str) -> None:
        """Acknowledge an active alert."""
        if alert_id not in self.active_alerts:
            return
        
        alert = self.active_alerts[alert_id]
        alert.state = AlertState.ACKNOWLEDGED
        alert.acknowledged_at = datetime.utcnow()
        alert.acknowledged_by = acknowledged_by
        
        logger.info(f"Alert acknowledged: {alert.rule_name} by {acknowledged_by}")
    
    def silence_alert(self, alert_id: str, duration: timedelta) -> None:
        """Silence an alert for a specified duration."""
        if alert_id not in self.active_alerts:
            return
        
        alert = self.active_alerts[alert_id]
        alert.state = AlertState.SILENCED
        
        # Schedule automatic unsilencing
        def unsilence():
            time.sleep(duration.total_seconds())
            if alert_id in self.active_alerts and self.active_alerts[alert_id].state == AlertState.SILENCED:
                self.active_alerts[alert_id].state = AlertState.FIRING
        
        self.executor.submit(unsilence)
        
        logger.info(f"Alert silenced: {alert.rule_name} for {duration}")
    
    def _schedule_notification(self, alert: Alert, rule: AlertRule, escalation: bool = False) -> None:
        """Schedule notification for an alert."""
        self.executor.submit(self._send_notifications, alert, rule, escalation)
    
    def _send_notifications(self, alert: Alert, rule: AlertRule, escalation: bool = False) -> None:
        """Send notifications for an alert."""
        for channel in rule.notification_channels:
            if channel not in self.notification_configs:
                continue
            
            config = self.notification_configs[channel]
            if not config.enabled:
                continue
            
            # Check rate limiting
            if config.rate_limit and config.last_sent:
                if datetime.utcnow() - config.last_sent < config.rate_limit:
                    continue
            
            try:
                self._send_notification(alert, channel, config, escalation)
                config.last_sent = datetime.utcnow()
                alert.notification_sent.add(channel)
                
            except Exception as e:
                logger.error(f"Failed to send notification via {channel.value}: {e}")
    
    def _send_notification(self, alert: Alert, channel: NotificationChannel, 
                          config: NotificationConfig, escalation: bool) -> None:
        """Send notification via specific channel."""
        message = self._format_notification_message(alert, escalation)
        
        if channel == NotificationChannel.EMAIL:
            self._send_email_notification(alert, message, config.config)
        elif channel == NotificationChannel.SLACK:
            self._send_slack_notification(alert, message, config.config)
        elif channel == NotificationChannel.WEBHOOK:
            self._send_webhook_notification(alert, message, config.config)
        elif channel == NotificationChannel.SMS:
            self._send_sms_notification(alert, message, config.config)
        elif channel == NotificationChannel.PAGERDUTY:
            self._send_pagerduty_notification(alert, message, config.config)
    
    def _format_notification_message(self, alert: Alert, escalation: bool) -> str:
        """Format notification message."""
        prefix = "🚨 ESCALATED" if escalation else "⚠️"
        severity_emoji = {
            AlertSeverity.CRITICAL: "🔥",
            AlertSeverity.HIGH: "❗",
            AlertSeverity.MEDIUM: "⚠️",
            AlertSeverity.LOW: "ℹ️",
            AlertSeverity.INFO: "💡"
        }
        
        emoji = severity_emoji.get(alert.severity, "⚠️")
        
        return f"""{prefix} {emoji} BLNCS Alert

Alert: {alert.rule_name}
Severity: {alert.severity.value.upper()}
State: {alert.state.value}
Message: {alert.message}
Duration: {alert.duration}
Started: {alert.starts_at.strftime('%Y-%m-%d %H:%M:%S')} UTC

Labels: {', '.join(f'{k}={v}' for k, v in alert.labels.items())}
"""
    
    def _send_email_notification(self, alert: Alert, message: str, config: Dict[str, Any]) -> None:
        """Send email notification."""
        smtp_server = config.get('smtp_server', 'localhost')
        smtp_port = config.get('smtp_port', 587)
        username = config.get('username', '')
        password = config.get('password', '')
        from_email = config.get('from_email', 'blncs@localhost')
        to_emails = config.get('to_emails', [])
        
        if not to_emails:
            return
        
        msg = MimeMultipart()
        msg['From'] = from_email
        msg['To'] = ', '.join(to_emails)
        msg['Subject'] = f"BLNCS Alert: {alert.rule_name} [{alert.severity.value.upper()}]"
        
        msg.attach(MimeText(message, 'plain'))
        
        context = ssl.create_default_context()
        
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            if config.get('use_tls', True):
                server.starttls(context=context)
            if username and password:
                server.login(username, password)
            
            text = msg.as_string()
            server.sendmail(from_email, to_emails, text)
    
    def _send_slack_notification(self, alert: Alert, message: str, config: Dict[str, Any]) -> None:
        """Send Slack notification."""
        webhook_url = config.get('webhook_url')
        channel = config.get('channel', '#alerts')
        username = config.get('username', 'BLNCS Alerting')
        
        if not webhook_url:
            return
        
        color_map = {
            AlertSeverity.CRITICAL: 'danger',
            AlertSeverity.HIGH: 'warning', 
            AlertSeverity.MEDIUM: 'warning',
            AlertSeverity.LOW: 'good',
            AlertSeverity.INFO: 'good'
        }
        
        payload = {
            'channel': channel,
            'username': username,
            'attachments': [{
                'color': color_map.get(alert.severity, 'warning'),
                'title': f"Alert: {alert.rule_name}",
                'text': message,
                'footer': 'BLNCS Monitoring',
                'ts': int(alert.starts_at.timestamp())
            }]
        }
        
        response = requests.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status()
    
    def _send_webhook_notification(self, alert: Alert, message: str, config: Dict[str, Any]) -> None:
        """Send webhook notification."""
        url = config.get('url')
        headers = config.get('headers', {})
        
        if not url:
            return
        
        payload = {
            'alert': {
                'rule_name': alert.rule_name,
                'severity': alert.severity.value,
                'state': alert.state.value,
                'message': alert.message,
                'value': alert.value,
                'threshold': alert.threshold,
                'labels': alert.labels,
                'annotations': alert.annotations,
                'starts_at': alert.starts_at.isoformat(),
                'duration': alert.duration.total_seconds()
            },
            'notification_message': message
        }
        
        response = requests.post(url, json=payload, headers=headers, timeout=10)
        response.raise_for_status()
    
    def _send_sms_notification(self, alert: Alert, message: str, config: Dict[str, Any]) -> None:
        """Send SMS notification (placeholder - integrate with SMS provider)."""
        # This would integrate with SMS providers like Twilio, AWS SNS, etc.
        logger.info(f"SMS notification would be sent: {message[:100]}...")
    
    def _send_pagerduty_notification(self, alert: Alert, message: str, config: Dict[str, Any]) -> None:
        """Send PagerDuty notification."""
        integration_key = config.get('integration_key')
        
        if not integration_key:
            return
        
        payload = {
            'routing_key': integration_key,
            'event_action': 'trigger' if alert.state == AlertState.FIRING else 'resolve',
            'dedup_key': f"blncs-{alert.rule_name}",
            'payload': {
                'summary': f"BLNCS Alert: {alert.rule_name}",
                'severity': alert.severity.value,
                'source': 'BLNCS',
                'component': alert.labels.get('component', 'unknown'),
                'group': alert.labels.get('service', 'lightning'),
                'class': 'alert',
                'custom_details': {
                    'message': alert.message,
                    'value': alert.value,
                    'threshold': alert.threshold,
                    'labels': alert.labels
                }
            }
        }
        
        response = requests.post(
            'https://events.pagerduty.com/v2/enqueue',
            json=payload,
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        response.raise_for_status()
    
    def start_evaluation(self) -> None:
        """Start the rule evaluation loop."""
        if self.evaluation_thread and self.evaluation_thread.is_alive():
            logger.warning("Alert evaluation already running")
            return
        
        self.stop_event.clear()
        self.evaluation_thread = threading.Thread(
            target=self._evaluation_loop,
            name="alert-evaluator",
            daemon=True
        )
        self.evaluation_thread.start()
        
        logger.info(f"Started alert evaluation (interval: {self.evaluation_interval}s)")
    
    def stop_evaluation(self) -> None:
        """Stop the rule evaluation loop."""
        if not self.evaluation_thread or not self.evaluation_thread.is_alive():
            return
        
        self.stop_event.set()
        self.evaluation_thread.join(timeout=5.0)
        
        if self.evaluation_thread.is_alive():
            logger.warning("Alert evaluation thread did not stop gracefully")
        else:
            logger.info("Stopped alert evaluation")
    
    def _evaluation_loop(self) -> None:
        """Main evaluation loop."""
        from .prometheus_metrics import get_metrics_collector
        
        while not self.stop_event.is_set():
            try:
                # Get current metrics (simplified - in production would query Prometheus)
                collector = get_metrics_collector()
                metrics = self._extract_current_metrics(collector)
                
                # Evaluate rules
                self.evaluate_rules(metrics)
                
                # Wait for next evaluation
                if self.stop_event.wait(self.evaluation_interval):
                    break
                    
            except Exception as e:
                logger.error(f"Error in alert evaluation loop: {e}")
                # Wait before retrying
                if self.stop_event.wait(min(self.evaluation_interval, 30.0)):
                    break
    
    def _extract_current_metrics(self, collector) -> Dict[str, float]:
        """Extract current metric values for evaluation."""
        # This is a simplified implementation
        # In production, would query Prometheus or use metric collector data
        return {
            'system_cpu_usage_percent': 50.0,
            'system_memory_usage_percent': 70.0,
            'lightning_channels_total': 10.0,
            'lightning_payment_failure_rate': 0.05,
            'database_connection_errors_total': 0.0
        }
    
    def get_active_alerts(self) -> List[Alert]:
        """Get all active alerts."""
        return list(self.active_alerts.values())
    
    def get_alert_history(self, limit: int = 100) -> List[Alert]:
        """Get alert history."""
        return self.alert_history[-limit:]
    
    def get_alert_summary(self) -> Dict[str, Any]:
        """Get alert summary statistics."""
        active = list(self.active_alerts.values())
        
        severity_counts = {}
        for severity in AlertSeverity:
            severity_counts[severity.value] = len([a for a in active if a.severity == severity])
        
        return {
            'total_active': len(active),
            'by_severity': severity_counts,
            'by_state': {
                state.value: len([a for a in active if a.state == state])
                for state in AlertState
            },
            'total_resolved_today': len([
                a for a in self.alert_history
                if a.ends_at and a.ends_at.date() == datetime.utcnow().date()
            ])
        }
    
    async def shutdown(self) -> None:
        """Shutdown the alert manager."""
        logger.info("Shutting down alert manager...")
        
        self.stop_evaluation()
        self.executor.shutdown(wait=True, timeout=10.0)
        
        logger.info("Alert manager shutdown complete")

# Global instance
_alert_manager: Optional[AlertManager] = None

def get_alert_manager() -> AlertManager:
    """Get the global alert manager instance."""
    global _alert_manager
    
    if _alert_manager is None:
        _alert_manager = AlertManager()
    
    return _alert_manager

def initialize_alerting() -> AlertManager:
    """Initialize the global alert manager."""
    global _alert_manager
    
    _alert_manager = AlertManager()
    
    # Add default Lightning Network alert rules
    _add_default_alert_rules(_alert_manager)
    
    logger.info("Initialized global alert manager with default rules")
    return _alert_manager

def _add_default_alert_rules(alert_manager: AlertManager) -> None:
    """Add default alert rules for Lightning Network monitoring."""
    
    # Critical system alerts
    alert_manager.add_rule(AlertRule(
        name="high_cpu_usage",
        condition="system_cpu_usage_percent > 90",
        severity=AlertSeverity.HIGH,
        threshold=90.0,
        duration=timedelta(minutes=5),
        description="High CPU usage detected",
        notification_channels=[NotificationChannel.SLACK, NotificationChannel.EMAIL]
    ))
    
    alert_manager.add_rule(AlertRule(
        name="high_memory_usage", 
        condition="system_memory_usage_percent > 85",
        severity=AlertSeverity.HIGH,
        threshold=85.0,
        duration=timedelta(minutes=5),
        description="High memory usage detected",
        notification_channels=[NotificationChannel.SLACK, NotificationChannel.EMAIL]
    ))
    
    alert_manager.add_rule(AlertRule(
        name="lightning_payment_failures",
        condition="lightning_payment_failure_rate > 0.1",
        severity=AlertSeverity.CRITICAL,
        threshold=0.1,
        duration=timedelta(minutes=2),
        description="High Lightning payment failure rate",
        escalation_delay=timedelta(minutes=15),
        notification_channels=[NotificationChannel.SLACK, NotificationChannel.EMAIL, NotificationChannel.PAGERDUTY]
    ))
    
    alert_manager.add_rule(AlertRule(
        name="channel_count_low",
        condition="lightning_channels_total < 5",
        severity=AlertSeverity.MEDIUM,
        threshold=5.0,
        duration=timedelta(minutes=10),
        description="Low number of Lightning channels",
        notification_channels=[NotificationChannel.SLACK]
    ))
    
    alert_manager.add_rule(AlertRule(
        name="database_connection_errors",
        condition="database_connection_errors_total > 0",
        severity=AlertSeverity.HIGH,
        threshold=0.0,
        duration=timedelta(minutes=1),
        description="Database connection errors detected",
        notification_channels=[NotificationChannel.SLACK, NotificationChannel.EMAIL]
    ))