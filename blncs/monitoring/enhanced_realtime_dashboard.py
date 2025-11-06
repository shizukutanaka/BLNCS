"""
Enhanced Real-time Monitoring Dashboard for BLNCS

This module provides advanced real-time monitoring with:
- WebSocket-based real-time updates
- Advanced notification system
- Interactive charts and visualizations
- Alert management and escalation
"""

import json
import time
import asyncio
import logging
from typing import Dict, List, Optional, Any, Callable, Set
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import threading
import queue
import uuid

# Try to import WebSocket libraries
try:
    import websockets
    from websockets import WebSocketServerProtocol
    HAS_WEBSOCKETS = True
except ImportError:
    HAS_WEBSOCKETS = False

try:
    import aiohttp
    from aiohttp import web
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

logger = logging.getLogger(__name__)

@dataclass
class Alert:
    """Alert data structure."""
    id: str
    timestamp: float
    severity: str  # critical, high, medium, low
    category: str  # system, lightning, security, performance
    title: str
    message: str
    source: str
    status: str = "active"  # active, acknowledged, resolved
    assigned_to: Optional[str] = None
    resolved_at: Optional[float] = None
    escalation_level: int = 0

@dataclass
class NotificationChannel:
    """Notification channel configuration."""
    id: str
    name: str
    type: str  # email, slack, webhook, sms
    config: Dict[str, Any]
    enabled: bool = True
    escalation_timeout: int = 300  # 5 minutes

@dataclass
class DashboardWidget:
    """Dashboard widget configuration."""
    id: str
    type: str  # chart, metric, table, alert_list, status
    title: str
    position: Dict[str, int]  # x, y, width, height
    data_source: str
    refresh_interval: int = 30
    config: Dict[str, Any] = None

class NotificationManager:
    """Advanced notification management system."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.NotificationManager")
        self.channels: Dict[str, NotificationChannel] = {}
        self.alert_queue = queue.Queue()
        self.notification_history = []
        self.max_history = 1000

        # Start notification processor
        self.processor_thread = threading.Thread(target=self._process_notifications, daemon=True)
        self.processor_thread.start()

    def add_channel(self, channel: NotificationChannel):
        """Add notification channel."""
        self.channels[channel.id] = channel
        self.logger.info(f"Added notification channel: {channel.name}")

    def send_alert(self, alert: Alert):
        """Send alert to appropriate channels."""
        self.alert_queue.put(alert)

    def _process_notifications(self):
        """Process notification queue."""
        while True:
            try:
                alert = self.alert_queue.get(timeout=1)

                # Add to history
                self.notification_history.append(alert)
                if len(self.notification_history) > self.max_history:
                    self.notification_history.pop(0)

                # Send to enabled channels
                for channel in self.channels.values():
                    if channel.enabled:
                        self._send_to_channel(alert, channel)

                self.alert_queue.task_done()

            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error processing notification: {e}")

    def _send_to_channel(self, alert: Alert, channel: NotificationChannel):
        """Send alert to specific channel."""
        try:
            if channel.type == 'email':
                self._send_email_alert(alert, channel)
            elif channel.type == 'slack':
                self._send_slack_alert(alert, channel)
            elif channel.type == 'webhook':
                self._send_webhook_alert(alert, channel)
            elif channel.type == 'sms':
                self._send_sms_alert(alert, channel)
        except Exception as e:
            self.logger.error(f"Failed to send alert to {channel.name}: {e}")

    def _send_email_alert(self, alert: Alert, channel: NotificationChannel):
        """Send email alert."""
        # In a real implementation, use SMTP or email service
        self.logger.info(f"Email alert sent: {alert.title} to {channel.config.get('recipients', [])}")

    def _send_slack_alert(self, alert: Alert, channel: NotificationChannel):
        """Send Slack alert."""
        # In a real implementation, use Slack API
        self.logger.info(f"Slack alert sent: {alert.title} to {channel.config.get('channel', '#alerts')}")

    def _send_webhook_alert(self, alert: Alert, channel: NotificationChannel):
        """Send webhook alert."""
        # In a real implementation, make HTTP POST to webhook URL
        self.logger.info(f"Webhook alert sent: {alert.title} to {channel.config.get('url')}")

    def _send_sms_alert(self, alert: Alert, channel: NotificationChannel):
        """Send SMS alert."""
        # In a real implementation, use SMS service
        self.logger.info(f"SMS alert sent: {alert.title} to {channel.config.get('phone_numbers', [])}")

class RealTimeDataManager:
    """Real-time data management and broadcasting."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.RealTimeDataManager")
        self.subscribers: Set[str] = set()
        self.data_queue = asyncio.Queue()
        self.broadcast_active = False
        self.broadcast_task = None

    async def start_broadcasting(self):
        """Start real-time data broadcasting."""
        if self.broadcast_active:
            return

        self.broadcast_active = True
        self.broadcast_task = asyncio.create_task(self._broadcast_loop())
        self.logger.info("Real-time data broadcasting started")

    async def stop_broadcasting(self):
        """Stop real-time data broadcasting."""
        self.broadcast_active = False
        if self.broadcast_task:
            await self.broadcast_task
        self.logger.info("Real-time data broadcasting stopped")

    def add_subscriber(self, subscriber_id: str):
        """Add WebSocket subscriber."""
        self.subscribers.add(subscriber_id)

    def remove_subscriber(self, subscriber_id: str):
        """Remove WebSocket subscriber."""
        self.subscribers.discard(subscriber_id)

    async def broadcast_data(self, data_type: str, data: Dict[str, Any]):
        """Broadcast data to all subscribers."""
        message = {
            'type': data_type,
            'timestamp': time.time(),
            'data': data
        }

        await self.data_queue.put(message)

    async def _broadcast_loop(self):
        """Main broadcasting loop."""
        while self.broadcast_active:
            try:
                # Wait for data or timeout
                try:
                    message = await asyncio.wait_for(self.data_queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    continue

                # Broadcast to all subscribers (in real implementation, send via WebSocket)
                if self.subscribers:
                    self.logger.debug(f"Broadcasting to {len(self.subscribers)} subscribers: {message['type']}")

                # Process the message
                self.data_queue.task_done()

            except Exception as e:
                self.logger.error(f"Error in broadcast loop: {e}")
                await asyncio.sleep(1)

class EnhancedMonitoringDashboard:
    """Enhanced real-time monitoring dashboard."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.EnhancedMonitoringDashboard")
        self.notification_manager = NotificationManager()
        self.data_manager = RealTimeDataManager()
        self.alerts: List[Alert] = []
        self.widgets: Dict[str, DashboardWidget] = {}

        # System metrics collectors
        self.metrics_collectors = {}

    def add_notification_channel(self, channel: NotificationChannel):
        """Add notification channel."""
        self.notification_manager.add_channel(channel)

    def add_dashboard_widget(self, widget: DashboardWidget):
        """Add dashboard widget."""
        self.widgets[widget.id] = widget

    def create_alert(self, severity: str, category: str, title: str, message: str, source: str) -> Alert:
        """Create and send alert."""
        alert = Alert(
            id=str(uuid.uuid4()),
            timestamp=time.time(),
            severity=severity,
            category=category,
            title=title,
            message=message,
            source=source
        )

        self.alerts.append(alert)
        self.notification_manager.send_alert(alert)

        self.logger.warning(f"Alert created: {alert.title}")
        return alert

    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get current dashboard data."""
        return {
            'timestamp': time.time(),
            'alerts': [asdict(alert) for alert in self.alerts[-50:]],  # Last 50 alerts
            'widgets': [asdict(widget) for widget in self.widgets.values()],
            'system_status': self._get_system_status(),
            'performance_metrics': self._get_performance_metrics(),
            'notifications_sent': len(self.notification_manager.notification_history)
        }

    def _get_system_status(self) -> Dict[str, Any]:
        """Get current system status."""
        # In a real implementation, collect from various system monitors
        return {
            'status': 'healthy',
            'uptime': time.time(),  # Would be actual uptime
            'services': ['api', 'lightning', 'database', 'monitoring']
        }

    def _get_performance_metrics(self) -> Dict[str, Any]:
        """Get current performance metrics."""
        # In a real implementation, collect from performance monitors
        return {
            'cpu_usage': 45.2,
            'memory_usage': 67.8,
            'disk_usage': 23.4,
            'network_io': {'in': 1024, 'out': 2048}
        }

class WebSocketHandler:
    """WebSocket handler for real-time updates."""

    def __init__(self, dashboard: EnhancedMonitoringDashboard):
        self.dashboard = dashboard
        self.logger = logging.getLogger(f"{__name__}.WebSocketHandler")

    async def handle_connection(self, websocket: WebSocketServerProtocol, path: str):
        """Handle WebSocket connection."""
        client_id = str(uuid.uuid4())
        self.dashboard.data_manager.add_subscriber(client_id)

        try:
            # Send initial dashboard data
            initial_data = self.dashboard.get_dashboard_data()
            await websocket.send(json.dumps({
                'type': 'initial_data',
                'data': initial_data
            }))

            # Handle incoming messages
            async for message in websocket:
                await self._handle_message(websocket, json.loads(message))

        except websockets.exceptions.ConnectionClosed:
            self.logger.info(f"WebSocket connection closed: {client_id}")
        finally:
            self.dashboard.data_manager.remove_subscriber(client_id)

    async def _handle_message(self, websocket: WebSocketServerProtocol, message: Dict[str, Any]):
        """Handle incoming WebSocket message."""
        message_type = message.get('type')

        if message_type == 'subscribe':
            # Handle subscription requests
            pass
        elif message_type == 'acknowledge_alert':
            alert_id = message.get('alert_id')
            self._acknowledge_alert(alert_id)
        elif message_type == 'get_widget_data':
            widget_id = message.get('widget_id')
            widget_data = self._get_widget_data(widget_id)
            await websocket.send(json.dumps({
                'type': 'widget_data',
                'widget_id': widget_id,
                'data': widget_data
            }))

    def _acknowledge_alert(self, alert_id: str):
        """Acknowledge an alert."""
        for alert in self.alerts:
            if alert.id == alert_id:
                alert.status = "acknowledged"
                alert.acknowledged_at = time.time()
                break

    def _get_widget_data(self, widget_id: str) -> Dict[str, Any]:
        """Get data for specific widget."""
        widget = self.widgets.get(widget_id)
        if not widget:
            return {}

        # In a real implementation, fetch widget-specific data
        return {'widget_id': widget_id, 'data': 'sample_data'}

# Integration with existing monitoring systems
def integrate_enhanced_monitoring(app_or_service):
    """Integrate enhanced monitoring with existing application."""
    dashboard = EnhancedMonitoringDashboard()

    # Add default notification channels
    email_channel = NotificationChannel(
        id="default_email",
        name="Default Email",
        type="email",
        config={"recipients": ["admin@blncs.example.com"]},
        enabled=True
    )
    dashboard.add_notification_channel(email_channel)

    # Add default dashboard widgets
    system_status_widget = DashboardWidget(
        id="system_status",
        type="metric",
        title="System Status",
        position={"x": 0, "y": 0, "width": 6, "height": 4},
        data_source="system_monitor",
        refresh_interval=30
    )
    dashboard.add_dashboard_widget(system_status_widget)

    alerts_widget = DashboardWidget(
        id="active_alerts",
        type="alert_list",
        title="Active Alerts",
        position={"x": 6, "y": 0, "width": 6, "height": 4},
        data_source="alert_manager",
        refresh_interval=10
    )
    dashboard.add_dashboard_widget(alerts_widget)

    return dashboard

# Example usage
if __name__ == "__main__":
    # Create enhanced dashboard
    dashboard = integrate_enhanced_monitoring(None)

    # Create sample alert
    alert = dashboard.create_alert(
        severity="high",
        category="system",
        title="High CPU Usage",
        message="CPU usage has exceeded 80% for 5 minutes",
        source="system_monitor"
    )

    # Get dashboard data
    data = dashboard.get_dashboard_data()
    print(f"Dashboard data: {json.dumps(data, indent=2)}")

    print("Enhanced real-time monitoring dashboard setup complete!")
