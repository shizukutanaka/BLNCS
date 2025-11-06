"""
BLNCS Production Monitoring Dashboard
Real-time monitoring, alerting, and performance analytics
"""

import asyncio
import json
import time
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from pathlib import Path
import psutil
import sqlite3
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
import threading
from functools import wraps

try:
    import websockets
    from aiohttp import web, WSMsgType
    import aiohttp_cors
except ImportError:
    websockets = None
    web = None
    aiohttp_cors = None

@dataclass
class MetricData:
    """Metric data structure for dashboard"""
    name: str
    value: float
    unit: str
    timestamp: float
    tags: Dict[str, str] = None
    threshold_warning: Optional[float] = None
    threshold_critical: Optional[float] = None

@dataclass
class Alert:
    """Alert data structure"""
    id: str
    level: str  # info, warning, critical
    title: str
    message: str
    timestamp: float
    component: str
    acknowledged: bool = False
    resolved: bool = False

class MetricsCollector:
    """Collects and stores metrics for the dashboard"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.metrics: deque = deque(maxlen=config.get('max_metrics', 10000))
        self.alerts: deque = deque(maxlen=config.get('max_alerts', 1000))
        self._collection_interval = config.get('collection_interval', 5)
        self._shutdown_event = asyncio.Event()

        # Initialize database for persistence
        self._init_database()

        # Start collection task
        self._collection_task = None

    def _init_database(self):
        """Initialize SQLite database for metrics storage"""
        db_path = self.config.get('database_path', 'metrics/dashboard.db')
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

        self.db_path = db_path
        with sqlite3.connect(db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    value REAL NOT NULL,
                    unit TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    tags TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            conn.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    level TEXT NOT NULL,
                    title TEXT NOT NULL,
                    message TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    component TEXT NOT NULL,
                    acknowledged BOOLEAN DEFAULT FALSE,
                    resolved BOOLEAN DEFAULT FALSE,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            conn.execute('CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics(timestamp)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_metrics_name ON metrics(name)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)')

    async def start_collection(self):
        """Start metrics collection"""
        self.logger.info("Starting metrics collection...")
        self._collection_task = asyncio.create_task(self._collect_metrics_loop())

    async def stop_collection(self):
        """Stop metrics collection"""
        self.logger.info("Stopping metrics collection...")
        self._shutdown_event.set()
        if self._collection_task:
            await self._collection_task

    async def _collect_metrics_loop(self):
        """Main metrics collection loop"""
        while not self._shutdown_event.is_set():
            try:
                await self._collect_system_metrics()
                await self._collect_application_metrics()
                await self._check_thresholds()

                # Store metrics to database
                await self._store_metrics()

                await asyncio.sleep(self._collection_interval)

            except Exception as e:
                self.logger.error(f"Error in metrics collection: {e}")
                await asyncio.sleep(1)

    async def _collect_system_metrics(self):
        """Collect system-level metrics"""
        timestamp = time.time()

        # CPU metrics
        cpu_percent = psutil.cpu_percent(interval=None)
        self.add_metric('system.cpu.percent', cpu_percent, '%', timestamp,
                       threshold_warning=80, threshold_critical=95)

        load_avg = psutil.getloadavg() if hasattr(psutil, 'getloadavg') else (0, 0, 0)
        self.add_metric('system.load.1min', load_avg[0], 'load', timestamp)
        self.add_metric('system.load.5min', load_avg[1], 'load', timestamp)
        self.add_metric('system.load.15min', load_avg[2], 'load', timestamp)

        # Memory metrics
        memory = psutil.virtual_memory()
        self.add_metric('system.memory.percent', memory.percent, '%', timestamp,
                       threshold_warning=85, threshold_critical=95)
        self.add_metric('system.memory.available', memory.available / (1024**3), 'GB', timestamp)
        self.add_metric('system.memory.used', memory.used / (1024**3), 'GB', timestamp)

        # Disk metrics
        disk = psutil.disk_usage('/')
        disk_percent = (disk.used / disk.total) * 100
        self.add_metric('system.disk.percent', disk_percent, '%', timestamp,
                       threshold_warning=85, threshold_critical=95)
        self.add_metric('system.disk.free', disk.free / (1024**3), 'GB', timestamp)

        # Network metrics
        try:
            net_io = psutil.net_io_counters()
            self.add_metric('system.network.bytes_sent', net_io.bytes_sent, 'bytes', timestamp)
            self.add_metric('system.network.bytes_recv', net_io.bytes_recv, 'bytes', timestamp)
        except AttributeError:
            pass  # Some systems don't support network metrics

    async def _collect_application_metrics(self):
        """Collect application-specific metrics"""
        timestamp = time.time()

        # Check if BLNCS process is running
        blncs_running = False
        blncs_memory = 0
        blncs_cpu = 0

        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'memory_info', 'cpu_percent']):
            try:
                if any('blncs' in str(cmd).lower() for cmd in proc.info['cmdline']):
                    blncs_running = True
                    blncs_memory += proc.info['memory_info'].rss / (1024**2)  # MB
                    blncs_cpu += proc.info['cpu_percent'] or 0
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        self.add_metric('blncs.process.running', 1 if blncs_running else 0, 'boolean', timestamp,
                       threshold_critical=0.5)
        self.add_metric('blncs.process.memory', blncs_memory, 'MB', timestamp)
        self.add_metric('blncs.process.cpu', blncs_cpu, '%', timestamp)

        # Check service status
        try:
            import subprocess
            result = subprocess.run(['systemctl', 'is-active', 'blncs'],
                                  capture_output=True, text=True)
            service_active = 1 if result.stdout.strip() == 'active' else 0
            self.add_metric('blncs.service.active', service_active, 'boolean', timestamp,
                           threshold_critical=0.5)
        except Exception:
            pass

        # Check database connectivity
        try:
            db_path = '/var/lib/blncs/blncs.db'
            if Path(db_path).exists():
                conn = sqlite3.connect(db_path, timeout=5)
                conn.execute('SELECT 1')
                conn.close()
                self.add_metric('blncs.database.connected', 1, 'boolean', timestamp)
            else:
                self.add_metric('blncs.database.connected', 0, 'boolean', timestamp)
        except Exception:
            self.add_metric('blncs.database.connected', 0, 'boolean', timestamp,
                           threshold_critical=0.5)

        # Check API health
        try:
            import urllib.request
            response = urllib.request.urlopen('http://localhost:8080/health', timeout=5)
            api_healthy = 1 if response.getcode() == 200 else 0
            self.add_metric('blncs.api.healthy', api_healthy, 'boolean', timestamp,
                           threshold_critical=0.5)
        except Exception:
            self.add_metric('blncs.api.healthy', 0, 'boolean', timestamp,
                           threshold_critical=0.5)

    def add_metric(self, name: str, value: float, unit: str, timestamp: float,
                   tags: Dict[str, str] = None, threshold_warning: float = None,
                   threshold_critical: float = None):
        """Add a metric to the collection"""
        metric = MetricData(
            name=name,
            value=value,
            unit=unit,
            timestamp=timestamp,
            tags=tags or {},
            threshold_warning=threshold_warning,
            threshold_critical=threshold_critical
        )
        self.metrics.append(metric)

    async def _check_thresholds(self):
        """Check metrics against thresholds and generate alerts"""
        current_time = time.time()
        recent_cutoff = current_time - 60  # Last minute

        # Group recent metrics by name
        recent_metrics = defaultdict(list)
        for metric in self.metrics:
            if metric.timestamp >= recent_cutoff:
                recent_metrics[metric.name].append(metric)

        for name, metrics_list in recent_metrics.items():
            if not metrics_list:
                continue

            latest_metric = max(metrics_list, key=lambda m: m.timestamp)

            # Check critical threshold
            if (latest_metric.threshold_critical is not None and
                latest_metric.value >= latest_metric.threshold_critical):

                await self.add_alert(
                    level='critical',
                    title=f'Critical: {name}',
                    message=f'{name} is {latest_metric.value} {latest_metric.unit} '
                           f'(threshold: {latest_metric.threshold_critical})',
                    component=name.split('.')[0]
                )

            # Check warning threshold
            elif (latest_metric.threshold_warning is not None and
                  latest_metric.value >= latest_metric.threshold_warning):

                await self.add_alert(
                    level='warning',
                    title=f'Warning: {name}',
                    message=f'{name} is {latest_metric.value} {latest_metric.unit} '
                           f'(threshold: {latest_metric.threshold_warning})',
                    component=name.split('.')[0]
                )

    async def add_alert(self, level: str, title: str, message: str, component: str):
        """Add an alert"""
        alert_id = f"{component}_{level}_{int(time.time())}"

        # Check if similar alert already exists (prevent spam)
        recent_cutoff = time.time() - 300  # 5 minutes
        similar_alerts = [
            alert for alert in self.alerts
            if (alert.component == component and alert.level == level and
                alert.timestamp >= recent_cutoff and not alert.resolved)
        ]

        if similar_alerts:
            return  # Don't create duplicate alerts

        alert = Alert(
            id=alert_id,
            level=level,
            title=title,
            message=message,
            timestamp=time.time(),
            component=component
        )

        self.alerts.append(alert)
        self.logger.warning(f"Alert: {title} - {message}")

    async def _store_metrics(self):
        """Store metrics to database"""
        try:
            metrics_to_store = list(self.metrics)[-100:]  # Store last 100 metrics

            with sqlite3.connect(self.db_path) as conn:
                for metric in metrics_to_store:
                    conn.execute('''
                        INSERT INTO metrics (name, value, unit, timestamp, tags)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (
                        metric.name,
                        metric.value,
                        metric.unit,
                        metric.timestamp,
                        json.dumps(metric.tags) if metric.tags else None
                    ))

                # Store alerts
                for alert in self.alerts:
                    conn.execute('''
                        INSERT OR REPLACE INTO alerts
                        (id, level, title, message, timestamp, component, acknowledged, resolved)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        alert.id,
                        alert.level,
                        alert.title,
                        alert.message,
                        alert.timestamp,
                        alert.component,
                        alert.acknowledged,
                        alert.resolved
                    ))

        except Exception as e:
            self.logger.error(f"Error storing metrics: {e}")

    def get_recent_metrics(self, minutes: int = 60) -> List[MetricData]:
        """Get recent metrics"""
        cutoff_time = time.time() - (minutes * 60)
        return [m for m in self.metrics if m.timestamp >= cutoff_time]

    def get_metric_summary(self) -> Dict[str, Any]:
        """Get summary of current metrics"""
        recent_metrics = self.get_recent_metrics(5)  # Last 5 minutes

        # Group by metric name and get latest values
        latest_metrics = {}
        for metric in recent_metrics:
            if (metric.name not in latest_metrics or
                metric.timestamp > latest_metrics[metric.name].timestamp):
                latest_metrics[metric.name] = metric

        # Calculate health score
        health_score = 100
        issues = []

        for metric in latest_metrics.values():
            if metric.threshold_critical and metric.value >= metric.threshold_critical:
                health_score -= 20
                issues.append(f"{metric.name} critical")
            elif metric.threshold_warning and metric.value >= metric.threshold_warning:
                health_score -= 10
                issues.append(f"{metric.name} warning")

        health_score = max(0, health_score)

        # Count active alerts
        active_alerts = [a for a in self.alerts if not a.resolved]
        critical_alerts = [a for a in active_alerts if a.level == 'critical']
        warning_alerts = [a for a in active_alerts if a.level == 'warning']

        return {
            'timestamp': time.time(),
            'health_score': health_score,
            'status': 'healthy' if health_score >= 80 else 'degraded' if health_score >= 60 else 'critical',
            'total_metrics': len(latest_metrics),
            'active_alerts': len(active_alerts),
            'critical_alerts': len(critical_alerts),
            'warning_alerts': len(warning_alerts),
            'issues': issues,
            'metrics': {name: {
                'value': metric.value,
                'unit': metric.unit,
                'timestamp': metric.timestamp
            } for name, metric in latest_metrics.items()}
        }

class DashboardWebServer:
    """Web server for the monitoring dashboard"""

    def __init__(self, metrics_collector: MetricsCollector, config: Dict[str, Any]):
        self.metrics = metrics_collector
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.app = None
        self.websocket_clients = set()

        if web is None:
            raise ImportError("aiohttp is required for web dashboard")

    async def create_app(self):
        """Create the web application"""
        self.app = web.Application()

        # Setup CORS
        cors = aiohttp_cors.setup(self.app, defaults={
            "*": aiohttp_cors.ResourceOptions(
                allow_credentials=True,
                expose_headers="*",
                allow_headers="*",
                allow_methods="*"
            )
        })

        # API routes
        self.app.router.add_get('/api/status', self.get_status)
        self.app.router.add_get('/api/metrics', self.get_metrics)
        self.app.router.add_get('/api/alerts', self.get_alerts)
        self.app.router.add_post('/api/alerts/{alert_id}/acknowledge', self.acknowledge_alert)
        self.app.router.add_get('/api/health', self.health_check)
        self.app.router.add_get('/ws', self.websocket_handler)

        # Static files (dashboard UI)
        self.app.router.add_get('/', self.serve_dashboard)
        self.app.router.add_static('/static', str(Path(__file__).parent / 'static'))

        # Add CORS to all routes
        for route in list(self.app.router.routes()):
            cors.add(route)

        return self.app

    async def serve_dashboard(self, request):
        """Serve the main dashboard HTML"""
        html_content = self._generate_dashboard_html()
        return web.Response(text=html_content, content_type='text/html')

    def _generate_dashboard_html(self):
        """Generate the dashboard HTML"""
        return '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BLNCS Production Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1a1a1a; color: #fff; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { text-align: center; margin-bottom: 30px; }
        .status-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .status-card { background: #2a2a2a; border-radius: 8px; padding: 20px; border-left: 4px solid #4CAF50; }
        .status-card.warning { border-left-color: #FF9800; }
        .status-card.critical { border-left-color: #F44336; }
        .metric-value { font-size: 2em; font-weight: bold; margin: 10px 0; }
        .metric-label { color: #aaa; font-size: 0.9em; }
        .alerts-section { background: #2a2a2a; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
        .alert { background: #333; border-radius: 4px; padding: 15px; margin: 10px 0; border-left: 4px solid #666; }
        .alert.warning { border-left-color: #FF9800; }
        .alert.critical { border-left-color: #F44336; }
        .charts-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; }
        .chart-container { background: #2a2a2a; border-radius: 8px; padding: 20px; height: 300px; }
        .refresh-info { text-align: center; color: #aaa; margin-top: 20px; }
        .health-indicator { display: inline-block; width: 12px; height: 12px; border-radius: 50%; margin-right: 8px; }
        .healthy { background: #4CAF50; }
        .degraded { background: #FF9800; }
        .critical { background: #F44336; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>BLNCS Production Dashboard</h1>
            <p>Real-time monitoring and alerting</p>
        </div>

        <div class="status-grid" id="statusGrid">
            <!-- Status cards will be populated by JavaScript -->
        </div>

        <div class="alerts-section">
            <h2>Active Alerts</h2>
            <div id="alertsList">
                <!-- Alerts will be populated by JavaScript -->
            </div>
        </div>

        <div class="charts-grid">
            <div class="chart-container">
                <h3>System CPU Usage</h3>
                <canvas id="cpuChart"></canvas>
            </div>
            <div class="chart-container">
                <h3>Memory Usage</h3>
                <canvas id="memoryChart"></canvas>
            </div>
            <div class="chart-container">
                <h3>BLNCS Health Status</h3>
                <canvas id="healthChart"></canvas>
            </div>
        </div>

        <div class="refresh-info">
            <p>Last updated: <span id="lastUpdate">-</span> | Auto-refresh: 10s</p>
        </div>
    </div>

    <script>
        // WebSocket connection for real-time updates
        let ws = null;

        function connectWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            ws = new WebSocket(`${protocol}//${window.location.host}/ws`);

            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                updateDashboard(data);
            };

            ws.onclose = function() {
                setTimeout(connectWebSocket, 5000); // Reconnect after 5 seconds
            };
        }

        function updateDashboard(data) {
            updateStatusCards(data);
            updateAlerts(data.alerts || []);
            document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString();
        }

        function updateStatusCards(data) {
            const statusGrid = document.getElementById('statusGrid');
            const metrics = data.metrics || {};

            const cards = [
                {
                    title: 'Overall Health',
                    value: `${data.health_score || 0}%`,
                    label: data.status || 'unknown',
                    status: data.status || 'unknown'
                },
                {
                    title: 'CPU Usage',
                    value: `${(metrics['system.cpu.percent']?.value || 0).toFixed(1)}%`,
                    label: 'System CPU',
                    status: metrics['system.cpu.percent']?.value > 80 ? 'critical' :
                           metrics['system.cpu.percent']?.value > 60 ? 'warning' : 'healthy'
                },
                {
                    title: 'Memory Usage',
                    value: `${(metrics['system.memory.percent']?.value || 0).toFixed(1)}%`,
                    label: 'System Memory',
                    status: metrics['system.memory.percent']?.value > 85 ? 'critical' :
                           metrics['system.memory.percent']?.value > 70 ? 'warning' : 'healthy'
                },
                {
                    title: 'BLNCS Service',
                    value: metrics['blncs.service.active']?.value ? 'Active' : 'Inactive',
                    label: 'Service Status',
                    status: metrics['blncs.service.active']?.value ? 'healthy' : 'critical'
                },
                {
                    title: 'API Health',
                    value: metrics['blncs.api.healthy']?.value ? 'Healthy' : 'Unhealthy',
                    label: 'API Status',
                    status: metrics['blncs.api.healthy']?.value ? 'healthy' : 'critical'
                },
                {
                    title: 'Active Alerts',
                    value: data.active_alerts || 0,
                    label: `${data.critical_alerts || 0} critical, ${data.warning_alerts || 0} warnings`,
                    status: data.critical_alerts > 0 ? 'critical' :
                           data.warning_alerts > 0 ? 'warning' : 'healthy'
                }
            ];

            statusGrid.innerHTML = cards.map(card => `
                <div class="status-card ${card.status}">
                    <div class="metric-label">${card.title}</div>
                    <div class="metric-value">${card.value}</div>
                    <div class="metric-label">${card.label}</div>
                </div>
            `).join('');
        }

        function updateAlerts(alerts) {
            const alertsList = document.getElementById('alertsList');

            if (alerts.length === 0) {
                alertsList.innerHTML = '<p style="color: #4CAF50;">No active alerts</p>';
                return;
            }

            alertsList.innerHTML = alerts.map(alert => `
                <div class="alert ${alert.level}">
                    <strong>${alert.title}</strong>
                    <p>${alert.message}</p>
                    <small>${new Date(alert.timestamp * 1000).toLocaleString()}</small>
                </div>
            `).join('');
        }

        // Fallback polling if WebSocket fails
        function pollData() {
            fetch('/api/status')
                .then(response => response.json())
                .then(data => updateDashboard(data))
                .catch(console.error);
        }

        // Initialize
        connectWebSocket();
        pollData(); // Initial load
        setInterval(pollData, 10000); // Fallback polling every 10 seconds
    </script>
</body>
</html>
        '''

    async def get_status(self, request):
        """Get overall system status"""
        summary = self.metrics.get_metric_summary()
        alerts = [asdict(alert) for alert in self.metrics.alerts if not alert.resolved]

        return web.json_response({
            **summary,
            'alerts': alerts
        })

    async def get_metrics(self, request):
        """Get recent metrics"""
        minutes = int(request.query.get('minutes', 60))
        metrics = self.metrics.get_recent_metrics(minutes)

        return web.json_response({
            'metrics': [asdict(metric) for metric in metrics],
            'count': len(metrics)
        })

    async def get_alerts(self, request):
        """Get alerts"""
        resolved = request.query.get('resolved', 'false').lower() == 'true'
        alerts = [alert for alert in self.metrics.alerts if alert.resolved == resolved]

        return web.json_response({
            'alerts': [asdict(alert) for alert in alerts],
            'count': len(alerts)
        })

    async def acknowledge_alert(self, request):
        """Acknowledge an alert"""
        alert_id = request.match_info['alert_id']

        for alert in self.metrics.alerts:
            if alert.id == alert_id:
                alert.acknowledged = True
                return web.json_response({'status': 'acknowledged'})

        return web.json_response({'error': 'Alert not found'}, status=404)

    async def health_check(self, request):
        """Health check endpoint"""
        return web.json_response({'status': 'healthy', 'timestamp': time.time()})

    async def websocket_handler(self, request):
        """WebSocket handler for real-time updates"""
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        self.websocket_clients.add(ws)

        try:
            # Send initial status
            summary = self.metrics.get_metric_summary()
            alerts = [asdict(alert) for alert in self.metrics.alerts if not alert.resolved]
            await ws.send_str(json.dumps({**summary, 'alerts': alerts}))

            async for msg in ws:
                if msg.type == WSMsgType.ERROR:
                    self.logger.error(f'WebSocket error: {ws.exception()}')
                    break

        except Exception as e:
            self.logger.error(f"WebSocket error: {e}")
        finally:
            self.websocket_clients.discard(ws)

        return ws

    async def broadcast_update(self, data):
        """Broadcast update to all WebSocket clients"""
        if not self.websocket_clients:
            return

        message = json.dumps(data)
        dead_clients = set()

        for client in self.websocket_clients:
            try:
                await client.send_str(message)
            except Exception:
                dead_clients.add(client)

        # Remove dead clients
        self.websocket_clients -= dead_clients

class ProductionMonitoringDashboard:
    """Main production monitoring dashboard"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # Initialize components
        self.metrics_collector = MetricsCollector(self.config.get('metrics', {}))
        self.web_server = DashboardWebServer(
            self.metrics_collector,
            self.config.get('web', {})
        )

        # Real-time update task
        self._update_task = None

    async def start(self):
        """Start the monitoring dashboard"""
        self.logger.info("Starting production monitoring dashboard...")

        # Start metrics collection
        await self.metrics_collector.start_collection()

        # Create and start web application
        app = await self.web_server.create_app()

        # Start real-time updates
        self._update_task = asyncio.create_task(self._broadcast_updates())

        # Start web server
        host = self.config.get('web', {}).get('host', '0.0.0.0')
        port = self.config.get('web', {}).get('port', 9090)

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, host, port)
        await site.start()

        self.logger.info(f"Dashboard started at http://{host}:{port}")

    async def stop(self):
        """Stop the monitoring dashboard"""
        self.logger.info("Stopping production monitoring dashboard...")

        # Stop metrics collection
        await self.metrics_collector.stop_collection()

        # Stop update task
        if self._update_task:
            self._update_task.cancel()
            try:
                await self._update_task
            except asyncio.CancelledError:
                pass

    async def _broadcast_updates(self):
        """Broadcast real-time updates to WebSocket clients"""
        while True:
            try:
                summary = self.metrics_collector.get_metric_summary()
                alerts = [asdict(alert) for alert in self.metrics_collector.alerts
                         if not alert.resolved]

                await self.web_server.broadcast_update({
                    **summary,
                    'alerts': alerts
                })

                await asyncio.sleep(5)  # Update every 5 seconds

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error broadcasting updates: {e}")
                await asyncio.sleep(1)

# Global instance
_dashboard = None

async def start_dashboard(config: Optional[Dict[str, Any]] = None):
    """Start the production monitoring dashboard"""
    global _dashboard
    if _dashboard is None:
        _dashboard = ProductionMonitoringDashboard(config)
        await _dashboard.start()
    return _dashboard

async def stop_dashboard():
    """Stop the production monitoring dashboard"""
    global _dashboard
    if _dashboard:
        await _dashboard.stop()
        _dashboard = None

__all__ = [
    'ProductionMonitoringDashboard',
    'MetricsCollector',
    'DashboardWebServer',
    'start_dashboard',
    'stop_dashboard'
]