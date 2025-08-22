# BLRCS Real-time Monitoring Dashboard
# Comprehensive real-time monitoring with web-based dashboard and alerting

import asyncio
import json
import time
import threading
import logging
import hashlib
import psutil
from typing import Dict, List, Any, Optional, Callable, Union
from dataclasses import dataclass, field, asdict
from pathlib import Path
from collections import deque, defaultdict
from datetime import datetime, timedelta
import websockets
import http.server
import socketserver
import socket
from contextlib import asynccontextmanager
import os
import sys

logger = logging.getLogger(__name__)

@dataclass
class MetricPoint:
    """Single metric data point"""
    timestamp: float
    value: Union[float, int, str]
    metric_name: str
    labels: Dict[str, str] = field(default_factory=dict)

@dataclass
class Alert:
    """System alert"""
    id: str
    severity: str  # critical, high, medium, low
    message: str
    metric_name: str
    current_value: Union[float, str]
    threshold: Union[float, str]
    timestamp: float
    resolved: bool = False

@dataclass
class DashboardWidget:
    """Dashboard widget configuration"""
    id: str
    title: str
    widget_type: str  # chart, gauge, table, text
    metrics: List[str]
    config: Dict[str, Any] = field(default_factory=dict)

class MetricsCollector:
    """Real-time metrics collection system"""
    
    def __init__(self):
        self.metrics_buffer: deque = deque(maxlen=10000)
        self.metric_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.collectors: Dict[str, Callable] = {}
        self.collection_interval = 5  # seconds
        self.running = False
        self._collection_task = None
        
    def register_collector(self, name: str, collector_func: Callable):
        """Register a metrics collector function"""
        self.collectors[name] = collector_func
        logger.info(f"Registered metrics collector: {name}")
    
    async def start_collection(self):
        """Start metrics collection"""
        if self.running:
            return
            
        self.running = True
        self._collection_task = asyncio.create_task(self._collection_loop())
        logger.info("Started metrics collection")
    
    async def stop_collection(self):
        """Stop metrics collection"""
        self.running = False
        if self._collection_task:
            self._collection_task.cancel()
            try:
                await self._collection_task
            except asyncio.CancelledError:
                pass
        logger.info("Stopped metrics collection")
    
    async def _collection_loop(self):
        """Main collection loop"""
        while self.running:
            try:
                await self._collect_all_metrics()
                await asyncio.sleep(self.collection_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in metrics collection: {e}")
                await asyncio.sleep(1)
    
    async def _collect_all_metrics(self):
        """Collect all registered metrics"""
        timestamp = time.time()
        
        for collector_name, collector_func in self.collectors.items():
            try:
                if asyncio.iscoroutinefunction(collector_func):
                    metrics = await collector_func()
                else:
                    metrics = collector_func()
                
                if isinstance(metrics, dict):
                    for metric_name, value in metrics.items():
                        self._add_metric_point(metric_name, value, timestamp, {"collector": collector_name})
                elif isinstance(metrics, list):
                    for metric in metrics:
                        if isinstance(metric, MetricPoint):
                            self._add_metric_point(metric.metric_name, metric.value, 
                                                 metric.timestamp, metric.labels)
                        
            except Exception as e:
                logger.warning(f"Failed to collect metrics from {collector_name}: {e}")
    
    def _add_metric_point(self, metric_name: str, value: Union[float, int, str], 
                         timestamp: float, labels: Dict[str, str] = None):
        """Add metric point to buffers"""
        point = MetricPoint(
            timestamp=timestamp,
            value=value,
            metric_name=metric_name,
            labels=labels or {}
        )
        
        self.metrics_buffer.append(point)
        self.metric_history[metric_name].append(point)
    
    def get_metric_history(self, metric_name: str, duration_seconds: int = 300) -> List[MetricPoint]:
        """Get metric history for specified duration"""
        cutoff_time = time.time() - duration_seconds
        history = self.metric_history.get(metric_name, deque())
        
        return [point for point in history if point.timestamp >= cutoff_time]
    
    def get_current_metrics(self) -> Dict[str, Any]:
        """Get current metric values"""
        current = {}
        
        for metric_name, history in self.metric_history.items():
            if history:
                latest = history[-1]
                current[metric_name] = {
                    "value": latest.value,
                    "timestamp": latest.timestamp,
                    "labels": latest.labels
                }
        
        return current

class AlertManager:
    """Alert management and notification system"""
    
    def __init__(self):
        self.active_alerts: Dict[str, Alert] = {}
        self.alert_history: deque = deque(maxlen=1000)
        self.alert_rules: Dict[str, Dict[str, Any]] = {}
        self.notification_handlers: List[Callable] = []
        
    def add_alert_rule(self, metric_name: str, condition: str, threshold: Union[float, str],
                      severity: str = "medium", message_template: str = None):
        """Add alert rule for metric"""
        rule_id = f"{metric_name}_{condition}_{threshold}"
        
        self.alert_rules[rule_id] = {
            "metric_name": metric_name,
            "condition": condition,  # gt, lt, eq, ne
            "threshold": threshold,
            "severity": severity,
            "message_template": message_template or f"{metric_name} {condition} {threshold}"
        }
        
        logger.info(f"Added alert rule: {rule_id}")
    
    def add_notification_handler(self, handler: Callable):
        """Add notification handler for alerts"""
        self.notification_handlers.append(handler)
    
    def check_alerts(self, current_metrics: Dict[str, Any]):
        """Check all alert rules against current metrics"""
        for rule_id, rule in self.alert_rules.items():
            metric_name = rule["metric_name"]
            
            if metric_name not in current_metrics:
                continue
            
            current_value = current_metrics[metric_name]["value"]
            
            if self._evaluate_condition(current_value, rule["condition"], rule["threshold"]):
                self._trigger_alert(rule_id, rule, current_value)
            else:
                self._resolve_alert(rule_id)
    
    def _evaluate_condition(self, value: Union[float, str], condition: str, 
                          threshold: Union[float, str]) -> bool:
        """Evaluate alert condition"""
        try:
            if condition == "gt":
                return float(value) > float(threshold)
            elif condition == "lt":
                return float(value) < float(threshold)
            elif condition == "eq":
                return value == threshold
            elif condition == "ne":
                return value != threshold
            elif condition == "gte":
                return float(value) >= float(threshold)
            elif condition == "lte":
                return float(value) <= float(threshold)
        except (ValueError, TypeError):
            return False
        
        return False
    
    def _trigger_alert(self, rule_id: str, rule: Dict[str, Any], current_value: Union[float, str]):
        """Trigger an alert"""
        alert_id = hashlib.sha256(f"{rule_id}_{time.time()}".encode()).hexdigest()[:16]
        
        # Don't create duplicate alerts
        if any(alert.metric_name == rule["metric_name"] and not alert.resolved 
               for alert in self.active_alerts.values()):
            return
        
        alert = Alert(
            id=alert_id,
            severity=rule["severity"],
            message=rule["message_template"],
            metric_name=rule["metric_name"],
            current_value=current_value,
            threshold=rule["threshold"],
            timestamp=time.time()
        )
        
        self.active_alerts[alert_id] = alert
        self.alert_history.append(alert)
        
        # Send notifications
        for handler in self.notification_handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    asyncio.create_task(handler(alert))
                else:
                    handler(alert)
            except Exception as e:
                logger.error(f"Failed to send alert notification: {e}")
        
        logger.warning(f"Alert triggered: {alert.message}")
    
    def _resolve_alert(self, rule_id: str):
        """Resolve alerts for a rule"""
        for alert_id, alert in list(self.active_alerts.items()):
            if not alert.resolved and f"{alert.metric_name}_" in rule_id:
                alert.resolved = True
                del self.active_alerts[alert_id]
                logger.info(f"Alert resolved: {alert.message}")
    
    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get all active alerts"""
        return [asdict(alert) for alert in self.active_alerts.values()]

class DashboardServer:
    """Web-based dashboard server"""
    
    def __init__(self, port: int = 8888):
        self.port = port
        self.websocket_clients: set = set()
        self.dashboard_config = self._get_default_dashboard()
        self._server = None
        self._websocket_server = None
        
    def _get_default_dashboard(self) -> Dict[str, Any]:
        """Get default dashboard configuration"""
        return {
            "title": "BLRCS Monitoring Dashboard",
            "refresh_interval": 5,
            "widgets": [
                DashboardWidget(
                    id="system_overview",
                    title="System Overview",
                    widget_type="table",
                    metrics=["cpu_usage", "memory_usage", "disk_usage"]
                ),
                DashboardWidget(
                    id="response_time_chart",
                    title="Response Time",
                    widget_type="chart",
                    metrics=["response_time"],
                    config={"chart_type": "line", "time_range": 300}
                ),
                DashboardWidget(
                    id="database_performance",
                    title="Database Performance",
                    widget_type="gauge",
                    metrics=["db_query_time", "db_connection_count"]
                ),
                DashboardWidget(
                    id="alerts_panel",
                    title="Active Alerts",
                    widget_type="table",
                    metrics=["alerts"]
                )
            ]
        }
    
    async def start_server(self):
        """Start dashboard web server"""
        # Start HTTP server for static files
        self._start_http_server()
        
        # Start WebSocket server for real-time updates
        self._websocket_server = await websockets.serve(
            self._websocket_handler,
            "localhost",
            self.port + 1
        )
        
        logger.info(f"Dashboard server started on http://localhost:{self.port}")
        logger.info(f"WebSocket server started on ws://localhost:{self.port + 1}")
    
    def _start_http_server(self):
        """Start HTTP server for dashboard"""
        
        class DashboardHandler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, dashboard_instance=None, **kwargs):
                self.dashboard_instance = dashboard_instance
                super().__init__(*args, **kwargs)
            
            def do_GET(self):
                if self.path == "/" or self.path == "/dashboard":
                    self._serve_dashboard()
                elif self.path == "/api/config":
                    self._serve_config()
                elif self.path == "/api/metrics":
                    self._serve_metrics()
                else:
                    self.send_error(404)
            
            def _serve_dashboard(self):
                html_content = self._generate_dashboard_html()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(html_content.encode())
            
            def _serve_config(self):
                config = json.dumps(asdict(self.dashboard_instance.dashboard_config))
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(config.encode())
            
            def _serve_metrics(self):
                # This would be connected to metrics collector
                metrics = {"timestamp": time.time(), "metrics": {}}
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(metrics).encode())
            
            def _generate_dashboard_html(self):
                return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BLRCS Monitoring Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; }
        .header { background: #2c3e50; color: white; padding: 20px; text-align: center; }
        .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; padding: 20px; }
        .widget { background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .widget-title { font-size: 18px; font-weight: bold; margin-bottom: 15px; color: #2c3e50; }
        .metric-value { font-size: 24px; font-weight: bold; color: #27ae60; }
        .metric-label { color: #7f8c8d; margin-bottom: 10px; }
        .alert-critical { border-left: 4px solid #e74c3c; background: #fdf2f2; }
        .alert-high { border-left: 4px solid #f39c12; background: #fef9f3; }
        .chart-container { height: 200px; background: #ecf0f1; border-radius: 4px; display: flex; align-items: center; justify-content: center; }
        .status-indicator { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 8px; }
        .status-ok { background: #27ae60; }
        .status-warning { background: #f39c12; }
        .status-error { background: #e74c3c; }
        .refresh-info { text-align: center; color: #7f8c8d; margin: 20px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ecf0f1; }
        th { background: #f8f9fa; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 BLRCS Real-time Monitoring Dashboard</h1>
        <p>Enterprise Security and Monitoring System - Live Metrics</p>
    </div>
    
    <div class="dashboard">
        <div class="widget">
            <div class="widget-title">System Overview</div>
            <table>
                <tr><th>Metric</th><th>Value</th><th>Status</th></tr>
                <tr><td>CPU Usage</td><td id="cpu-usage">--</td><td><span class="status-indicator status-ok"></span>Normal</td></tr>
                <tr><td>Memory Usage</td><td id="memory-usage">--</td><td><span class="status-indicator status-ok"></span>Normal</td></tr>
                <tr><td>Database</td><td id="db-status">--</td><td><span class="status-indicator status-ok"></span>Connected</td></tr>
                <tr><td>Response Time</td><td id="response-time">--</td><td><span class="status-indicator status-ok"></span>Good</td></tr>
            </table>
        </div>
        
        <div class="widget">
            <div class="widget-title">Performance Metrics</div>
            <div class="chart-container">
                <div style="text-align: center;">
                    <div class="metric-label">Average Response Time</div>
                    <div class="metric-value" id="avg-response">0 ms</div>
                </div>
            </div>
        </div>
        
        <div class="widget">
            <div class="widget-title">Active Alerts</div>
            <div id="alerts-container">
                <div style="text-align: center; color: #27ae60; padding: 20px;">
                    ✅ No active alerts
                </div>
            </div>
        </div>
        
        <div class="widget">
            <div class="widget-title">BLRCS Components</div>
            <table>
                <tr><th>Component</th><th>Status</th><th>Last Update</th></tr>
                <tr><td>Authentication</td><td><span class="status-indicator status-ok"></span>Active</td><td id="auth-update">--</td></tr>
                <tr><td>Lightning Node</td><td><span class="status-indicator status-ok"></span>Connected</td><td id="lnd-update">--</td></tr>
                <tr><td>Security Monitor</td><td><span class="status-indicator status-ok"></span>Running</td><td id="security-update">--</td></tr>
                <tr><td>UX Optimizer</td><td><span class="status-indicator status-ok"></span>Active</td><td id="ux-update">--</td></tr>
            </table>
        </div>
    </div>
    
    <div class="refresh-info">
        Dashboard updates every 5 seconds | Last update: <span id="last-update">--</span>
    </div>
    
    <script>
        // WebSocket connection for real-time updates
        const ws = new WebSocket('ws://localhost:8889');
        
        ws.onmessage = function(event) {
            const data = JSON.parse(event.data);
            updateDashboard(data);
        };
        
        function updateDashboard(data) {
            if (data.metrics) {
                // Update system metrics
                document.getElementById('cpu-usage').textContent = 
                    data.metrics.cpu_usage ? data.metrics.cpu_usage.value.toFixed(1) + '%' : '--';
                document.getElementById('memory-usage').textContent = 
                    data.metrics.memory_usage ? data.metrics.memory_usage.value.toFixed(1) + '%' : '--';
                document.getElementById('response-time').textContent = 
                    data.metrics.response_time ? data.metrics.response_time.value.toFixed(1) + 'ms' : '--';
                
                // Update performance metrics
                document.getElementById('avg-response').textContent = 
                    data.metrics.response_time ? data.metrics.response_time.value.toFixed(1) + ' ms' : '0 ms';
            }
            
            if (data.alerts) {
                updateAlerts(data.alerts);
            }
            
            // Update timestamp
            document.getElementById('last-update').textContent = new Date().toLocaleTimeString();
        }
        
        function updateAlerts(alerts) {
            const container = document.getElementById('alerts-container');
            
            if (alerts.length === 0) {
                container.innerHTML = '<div style="text-align: center; color: #27ae60; padding: 20px;">✅ No active alerts</div>';
            } else {
                let html = '<table><tr><th>Severity</th><th>Message</th><th>Time</th></tr>';
                alerts.forEach(alert => {
                    const severityClass = alert.severity === 'critical' ? 'alert-critical' : 
                                        alert.severity === 'high' ? 'alert-high' : '';
                    html += `<tr class="${severityClass}">
                        <td>${alert.severity.toUpperCase()}</td>
                        <td>${alert.message}</td>
                        <td>${new Date(alert.timestamp * 1000).toLocaleTimeString()}</td>
                    </tr>`;
                });
                html += '</table>';
                container.innerHTML = html;
            }
        }
        
        // Fallback polling if WebSocket fails
        setInterval(() => {
            if (ws.readyState !== WebSocket.OPEN) {
                fetch('/api/metrics')
                    .then(response => response.json())
                    .then(data => updateDashboard(data))
                    .catch(console.error);
            }
        }, 5000);
        
        // Initial load
        document.getElementById('last-update').textContent = new Date().toLocaleTimeString();
    </script>
</body>
</html>
                """
        
        def create_handler(*args, **kwargs):
            return DashboardHandler(*args, dashboard_instance=self, **kwargs)
        
        self._server = socketserver.TCPServer(("", self.port), create_handler)
        
        # Start server in separate thread
        server_thread = threading.Thread(target=self._server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
    
    async def _websocket_handler(self, websocket, path):
        """Handle WebSocket connections"""
        self.websocket_clients.add(websocket)
        logger.info(f"WebSocket client connected: {websocket.remote_address}")
        
        try:
            await websocket.wait_closed()
        finally:
            self.websocket_clients.remove(websocket)
            logger.info(f"WebSocket client disconnected: {websocket.remote_address}")
    
    async def broadcast_update(self, data: Dict[str, Any]):
        """Broadcast update to all connected clients"""
        if not self.websocket_clients:
            return
        
        message = json.dumps(data)
        disconnected = set()
        
        for client in self.websocket_clients:
            try:
                await client.send(message)
            except websockets.exceptions.ConnectionClosed:
                disconnected.add(client)
            except Exception as e:
                logger.warning(f"Failed to send to WebSocket client: {e}")
                disconnected.add(client)
        
        # Remove disconnected clients
        self.websocket_clients -= disconnected
    
    def stop_server(self):
        """Stop dashboard server"""
        if self._server:
            self._server.shutdown()
        if self._websocket_server:
            self._websocket_server.close()

class RealtimeMonitor:
    """Main real-time monitoring system"""
    
    def __init__(self, dashboard_port: int = 8888):
        self.metrics_collector = MetricsCollector()
        self.alert_manager = AlertManager()
        self.dashboard_server = DashboardServer(dashboard_port)
        self.running = False
        
        # Setup default collectors
        self._setup_default_collectors()
        
        # Setup default alerts
        self._setup_default_alerts()
    
    def _setup_default_collectors(self):
        """Setup default system metrics collectors"""
        
        def collect_system_metrics():
            """Collect basic system metrics"""
            return {
                "cpu_usage": psutil.cpu_percent(),
                "memory_usage": psutil.virtual_memory().percent,
                "disk_usage": psutil.disk_usage('/').percent,
                "process_count": len(psutil.pids())
            }
        
        def collect_blrcs_metrics():
            """Collect BLRCS-specific metrics"""
            try:
                # Try to get metrics from UX optimizer
                from blrcs import ux_optimizer
                if ux_optimizer:
                    dashboard = ux_optimizer.get_ux_dashboard()
                    return {
                        "ux_score": dashboard.get("ux_score", 0),
                        "response_time": dashboard.get("performance", {}).get("average_response_ms", 0)
                    }
            except ImportError:
                pass
            
            return {"response_time": 50}  # Default value
        
        async def collect_async_metrics():
            """Collect asynchronous metrics"""
            # Simulate some async work
            await asyncio.sleep(0.1)
            return {
                "async_operations": 42,
                "queue_size": 0
            }
        
        self.metrics_collector.register_collector("system", collect_system_metrics)
        self.metrics_collector.register_collector("blrcs", collect_blrcs_metrics)
        self.metrics_collector.register_collector("async", collect_async_metrics)
    
    def _setup_default_alerts(self):
        """Setup default alert rules"""
        self.alert_manager.add_alert_rule(
            "cpu_usage", "gt", 90, "critical", "High CPU usage: {value}%"
        )
        self.alert_manager.add_alert_rule(
            "memory_usage", "gt", 85, "high", "High memory usage: {value}%"
        )
        self.alert_manager.add_alert_rule(
            "response_time", "gt", 1000, "medium", "Slow response time: {value}ms"
        )
        self.alert_manager.add_alert_rule(
            "disk_usage", "gt", 95, "critical", "Disk space critically low: {value}%"
        )
        
        # Add notification handler
        def log_alert(alert: Alert):
            logger.warning(f"ALERT [{alert.severity}]: {alert.message}")
        
        self.alert_manager.add_notification_handler(log_alert)
    
    async def start_monitoring(self):
        """Start comprehensive monitoring"""
        if self.running:
            return
        
        self.running = True
        
        # Start metrics collection
        await self.metrics_collector.start_collection()
        
        # Start dashboard server
        await self.dashboard_server.start_server()
        
        # Start monitoring loop
        asyncio.create_task(self._monitoring_loop())
        
        logger.info("🔍 Real-time monitoring started")
    
    async def stop_monitoring(self):
        """Stop monitoring"""
        self.running = False
        
        await self.metrics_collector.stop_collection()
        self.dashboard_server.stop_server()
        
        logger.info("Monitoring stopped")
    
    async def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                # Get current metrics
                current_metrics = self.metrics_collector.get_current_metrics()
                
                # Check alerts
                self.alert_manager.check_alerts(current_metrics)
                
                # Prepare dashboard update
                dashboard_data = {
                    "timestamp": time.time(),
                    "metrics": current_metrics,
                    "alerts": self.alert_manager.get_active_alerts()
                }
                
                # Broadcast to dashboard
                await self.dashboard_server.broadcast_update(dashboard_data)
                
                await asyncio.sleep(5)  # Update every 5 seconds
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(1)
    
    def get_monitoring_status(self) -> Dict[str, Any]:
        """Get current monitoring status"""
        current_metrics = self.metrics_collector.get_current_metrics()
        active_alerts = self.alert_manager.get_active_alerts()
        
        return {
            "running": self.running,
            "metrics_count": len(current_metrics),
            "active_alerts": len(active_alerts),
            "dashboard_clients": len(self.dashboard_server.websocket_clients),
            "collectors": list(self.metrics_collector.collectors.keys()),
            "alert_rules": len(self.alert_manager.alert_rules),
            "uptime_seconds": time.time() - getattr(self, '_start_time', time.time())
        }

# Global monitoring instance
realtime_monitor = RealtimeMonitor()

async def start_monitoring():
    """Start real-time monitoring"""
    await realtime_monitor.start_monitoring()

async def stop_monitoring():
    """Stop real-time monitoring"""
    await realtime_monitor.stop_monitoring()

def get_monitoring_dashboard_url() -> str:
    """Get monitoring dashboard URL"""
    return f"http://localhost:{realtime_monitor.dashboard_server.port}"

def get_monitoring_status() -> Dict[str, Any]:
    """Get monitoring status"""
    return realtime_monitor.get_monitoring_status()