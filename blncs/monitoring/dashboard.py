"""
Simple monitoring dashboard for BLNCS
Lightweight web dashboard with core functionality.
"""

import json
import time
from datetime import datetime
from typing import Dict, Any
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import threading

from ..core.metrics import get_metrics
from ..core.logger import get_logger
from ..lightning.simple_client import get_lightning_client

logger = get_logger(__name__)


class SimpleDashboardHandler(BaseHTTPRequestHandler):
    """Simple HTTP handler for dashboard"""

    def do_GET(self):
        """Handle GET requests"""
        path = urlparse(self.path).path

        if path == '/':
            self._serve_dashboard()
        elif path == '/api/status':
            self._serve_status()
        elif path == '/api/metrics':
            self._serve_metrics()
        elif path == '/api/channels':
            self._serve_channels()
        else:
            self._serve_404()

    def _serve_dashboard(self):
        """Serve main dashboard HTML"""
        html = """
<!DOCTYPE html>
<html>
<head>
    <title>BLNCS Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .card { background: white; padding: 20px; margin: 10px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .metric { display: inline-block; margin: 10px 20px 10px 0; }
        .metric-value { font-size: 24px; font-weight: bold; color: #2196F3; }
        .metric-label { font-size: 14px; color: #666; }
        .status-ok { color: #4CAF50; }
        .status-error { color: #f44336; }
        .refresh-btn { background: #2196F3; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; }
        .refresh-btn:hover { background: #1976D2; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="container">
        <h1>BLNCS Lightning Dashboard</h1>

        <div class="card">
            <h2>Node Status</h2>
            <div id="node-status">Loading...</div>
            <button class="refresh-btn" onclick="refreshData()">Refresh</button>
        </div>

        <div class="card">
            <h2>Metrics</h2>
            <div id="metrics">Loading...</div>
        </div>

        <div class="card">
            <h2>Channels</h2>
            <div id="channels">Loading...</div>
        </div>
    </div>

    <script>
        async function fetchData(url) {
            try {
                const response = await fetch(url);
                return await response.json();
            } catch (error) {
                return { error: error.message };
            }
        }

        async function updateStatus() {
            const status = await fetchData('/api/status');
            const statusDiv = document.getElementById('node-status');

            if (status.error) {
                statusDiv.innerHTML = `<span class="status-error">Error: ${status.error}</span>`;
            } else {
                statusDiv.innerHTML = `
                    <div class="metric">
                        <div class="metric-value ${status.connected ? 'status-ok' : 'status-error'}">
                            ${status.connected ? 'Connected' : 'Disconnected'}
                        </div>
                        <div class="metric-label">Connection Status</div>
                    </div>
                    <div class="metric">
                        <div class="metric-value">${status.alias || 'Unknown'}</div>
                        <div class="metric-label">Node Alias</div>
                    </div>
                    <div class="metric">
                        <div class="metric-value">${status.num_channels || 0}</div>
                        <div class="metric-label">Channels</div>
                    </div>
                `;
            }
        }

        async function updateMetrics() {
            const metrics = await fetchData('/api/metrics');
            const metricsDiv = document.getElementById('metrics');

            if (metrics.error) {
                metricsDiv.innerHTML = `<span class="status-error">Error: ${metrics.error}</span>`;
            } else {
                let html = '';

                if (metrics.counters) {
                    for (const [key, value] of Object.entries(metrics.counters)) {
                        html += `
                            <div class="metric">
                                <div class="metric-value">${value}</div>
                                <div class="metric-label">${key}</div>
                            </div>
                        `;
                    }
                }

                metricsDiv.innerHTML = html || 'No metrics available';
            }
        }

        async function updateChannels() {
            const channels = await fetchData('/api/channels');
            const channelsDiv = document.getElementById('channels');

            if (channels.error) {
                channelsDiv.innerHTML = `<span class="status-error">Error: ${channels.error}</span>`;
            } else if (channels.length === 0) {
                channelsDiv.innerHTML = 'No channels found';
            } else {
                let html = `
                    <table>
                        <tr>
                            <th>Channel ID</th>
                            <th>Remote Pubkey</th>
                            <th>Capacity</th>
                            <th>Local Balance</th>
                            <th>Remote Balance</th>
                            <th>Status</th>
                        </tr>
                `;

                for (const channel of channels) {
                    html += `
                        <tr>
                            <td>${channel.channel_id}</td>
                            <td>${channel.remote_pubkey.substring(0, 20)}...</td>
                            <td>${channel.capacity}</td>
                            <td>${channel.local_balance}</td>
                            <td>${channel.remote_balance}</td>
                            <td class="${channel.active ? 'status-ok' : 'status-error'}">
                                ${channel.active ? 'Active' : 'Inactive'}
                            </td>
                        </tr>
                    `;
                }

                html += '</table>';
                channelsDiv.innerHTML = html;
            }
        }

        async function refreshData() {
            await updateStatus();
            await updateMetrics();
            await updateChannels();
        }

        // Initial load and auto-refresh
        refreshData();
        setInterval(refreshData, 30000); // Refresh every 30 seconds
    </script>
</body>
</html>
        """
        self._send_response(200, html, 'text/html')

    def _serve_status(self):
        """Serve node status API"""
        try:
            client = get_lightning_client()
            info = client.get_info()
            status = {
                'connected': client.is_connected(),
                'alias': info.get('alias', 'Unknown'),
                'pubkey': info.get('identity_pubkey', ''),
                'version': info.get('version', ''),
                'num_channels': info.get('num_channels', 0),
                'num_peers': info.get('num_peers', 0),
                'synced': info.get('synced_to_chain', False),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            status = {'error': str(e), 'connected': False}

        self._send_json(status)

    def _serve_metrics(self):
        """Serve metrics API"""
        try:
            metrics = get_metrics()
            data = metrics.get_summary()
            data['timestamp'] = datetime.now().isoformat()
        except Exception as e:
            data = {'error': str(e)}

        self._send_json(data)

    def _serve_channels(self):
        """Serve channels API"""
        try:
            client = get_lightning_client()
            channels = client.list_channels()
            # Convert dataclass to dict
            channels_data = []
            for channel in channels:
                if hasattr(channel, '__dict__'):
                    channels_data.append(channel.__dict__)
                else:
                    channels_data.append(channel)
        except Exception as e:
            channels_data = {'error': str(e)}

        self._send_json(channels_data)

    def _serve_404(self):
        """Serve 404 response"""
        self._send_response(404, '404 Not Found')

    def _send_response(self, status_code: int, content: str, content_type: str = 'text/plain'):
        """Send HTTP response"""
        self.send_response(status_code)
        self.send_header('Content-Type', content_type)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(content.encode('utf-8'))

    def _send_json(self, data: Any):
        """Send JSON response"""
        content = json.dumps(data, indent=2)
        self._send_response(200, content, 'application/json')

    def log_message(self, format, *args):
        """Override to suppress default logging"""
        pass


class SimpleDashboard:
    """Simple web dashboard"""

    def __init__(self, host: str = '127.0.0.1', port: int = 8080):
        self.host = host
        self.port = port
        self.server = None
        self.thread = None
        self.running = False

    def start(self):
        """Start dashboard server"""
        if self.running:
            return

        try:
            self.server = HTTPServer((self.host, self.port), SimpleDashboardHandler)
            self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.thread.start()
            self.running = True
            logger.info(f"Dashboard started at http://{self.host}:{self.port}")
        except Exception as e:
            logger.error(f"Failed to start dashboard: {e}")
            raise

    def stop(self):
        """Stop dashboard server"""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.running = False
            logger.info("Dashboard stopped")

    def is_running(self) -> bool:
        """Check if dashboard is running"""
        return self.running


# Global dashboard instance
_dashboard: SimpleDashboard = None


def get_dashboard() -> SimpleDashboard:
    """Get global dashboard instance"""
    global _dashboard
    if _dashboard is None:
        _dashboard = SimpleDashboard()
    return _dashboard


def start_dashboard(host: str = '127.0.0.1', port: int = 8080):
    """Start dashboard"""
    dashboard = get_dashboard()
    dashboard.host = host
    dashboard.port = port
    dashboard.start()
    return dashboard


def stop_dashboard():
    """Stop dashboard"""
    dashboard = get_dashboard()
    dashboard.stop()