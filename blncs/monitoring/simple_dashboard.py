"""
Simple Web Dashboard
Lightweight web interface for monitoring BLNCS status.
"""

import json
import time
import threading
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from ..core.logger import get_logger
from ..core.health_check import get_health_checker
from ..core.rate_limiter import get_rate_limiter
from ..automation.simple_backup import get_backup_manager

logger = get_logger(__name__)

class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the dashboard."""
    
    def log_message(self, format, *args):
        """Override to use our logger."""
        logger.debug(f"Dashboard request: {format % args}")
    
    def do_GET(self):
        """Handle GET requests."""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        query_params = parse_qs(parsed_path.query)
        
        try:
            if path == "/" or path == "/dashboard":
                self._serve_dashboard()
            elif path == "/health":
                self._serve_health()
            elif path == "/api/status":
                self._serve_api_status()
            elif path == "/api/metrics":
                self._serve_api_metrics()
            elif path == "/api/backups":
                self._serve_api_backups()
            elif path == "/api/rate_limits":
                self._serve_api_rate_limits()
            elif path.startswith("/static/"):
                self._serve_static_file(path)
            else:
                self._serve_404()
        except Exception as e:
            logger.error(f"Dashboard error: {e}")
            self._serve_error(str(e))
    
    def do_POST(self):
        """Handle POST requests."""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            if path == "/api/backup/run":
                self._handle_backup_run(post_data)
            else:
                self._serve_404()
        except Exception as e:
            logger.error(f"Dashboard POST error: {e}")
            self._serve_error(str(e))
    
    def _serve_dashboard(self):
        """Serve the main dashboard page."""
        html_content = self._get_dashboard_html()
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Content-Length', str(len(html_content)))
        self.end_headers()
        self.wfile.write(html_content.encode())
    
    def _serve_health(self):
        """Serve health check endpoint."""
        health_checker = get_health_checker()
        health_data = health_checker.get_health_summary()
        
        self._serve_json(health_data)
    
    def _serve_api_status(self):
        """Serve API status."""
        health_checker = get_health_checker()
        backup_manager = get_backup_manager()
        
        status_data = {
            "timestamp": datetime.now().isoformat(),
            "uptime_seconds": time.time() - getattr(self.server, 'start_time', time.time()),
            "health": health_checker.get_health_summary(),
            "backup_status": backup_manager.get_backup_status()
        }
        
        self._serve_json(status_data)
    
    def _serve_api_metrics(self):
        """Serve metrics data."""
        try:
            import psutil
            
            metrics = {
                "system": {
                    "cpu_percent": psutil.cpu_percent(),
                    "memory_percent": psutil.virtual_memory().percent,
                    "disk_percent": psutil.disk_usage('/').used / psutil.disk_usage('/').total * 100,
                    "load_average": psutil.getloadavg() if hasattr(psutil, 'getloadavg') else [0, 0, 0]
                },
                "rate_limits": get_rate_limiter().get_stats(),
                "timestamp": datetime.now().isoformat()
            }
            
            self._serve_json(metrics)
        except Exception as e:
            self._serve_error(f"Failed to get metrics: {e}")
    
    def _serve_api_backups(self):
        """Serve backup status."""
        backup_manager = get_backup_manager()
        backup_data = backup_manager.get_backup_status()
        
        self._serve_json(backup_data)
    
    def _serve_api_rate_limits(self):
        """Serve rate limit status."""
        rate_limiter = get_rate_limiter()
        rate_limit_data = rate_limiter.get_stats()
        
        self._serve_json(rate_limit_data)
    
    def _handle_backup_run(self, post_data: bytes):
        """Handle backup run request."""
        try:
            data = json.loads(post_data.decode())
            job_name = data.get('job_name', 'all')
            
            backup_manager = get_backup_manager()
            
            if job_name == 'all':
                results = backup_manager.run_all_backups()
            else:
                result = backup_manager.run_backup(job_name)
                results = {job_name: result}
            
            response_data = {
                "success": all(r.success for r in results.values()),
                "results": {k: {
                    "success": v.success,
                    "files_backed_up": v.files_backed_up,
                    "total_size_bytes": v.total_size_bytes,
                    "duration_seconds": (v.end_time - v.start_time).total_seconds(),
                    "error_message": v.error_message
                } for k, v in results.items()}
            }
            
            self._serve_json(response_data)
            
        except Exception as e:
            self._serve_error(f"Backup operation failed: {e}")
    
    def _serve_static_file(self, path: str):
        """Serve static files (CSS, JS)."""
        if path == "/static/dashboard.css":
            css_content = self._get_dashboard_css()
            self.send_response(200)
            self.send_header('Content-type', 'text/css')
            self.send_header('Content-Length', str(len(css_content)))
            self.end_headers()
            self.wfile.write(css_content.encode())
        elif path == "/static/dashboard.js":
            js_content = self._get_dashboard_js()
            self.send_response(200)
            self.send_header('Content-type', 'application/javascript')
            self.send_header('Content-Length', str(len(js_content)))
            self.end_headers()
            self.wfile.write(js_content.encode())
        else:
            self._serve_404()
    
    def _serve_json(self, data: Dict[str, Any]):
        """Serve JSON response."""
        json_data = json.dumps(data, indent=2, default=str)
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Content-Length', str(len(json_data)))
        self.end_headers()
        self.wfile.write(json_data.encode())
    
    def _serve_404(self):
        """Serve 404 response."""
        self.send_response(404)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'404 Not Found')
    
    def _serve_error(self, message: str):
        """Serve error response."""
        error_data = {"error": message, "timestamp": datetime.now().isoformat()}
        json_data = json.dumps(error_data)
        
        self.send_response(500)
        self.send_header('Content-type', 'application/json')
        self.send_header('Content-Length', str(len(json_data)))
        self.end_headers()
        self.wfile.write(json_data.encode())
    
    def _get_dashboard_html(self) -> str:
        """Get the dashboard HTML content."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BLNCS Dashboard</title>
    <link rel="stylesheet" href="/static/dashboard.css">
    <script src="/static/dashboard.js"></script>
</head>
<body>
    <div class="container">
        <header>
            <h1>BLNCS Dashboard</h1>
            <div id="status-indicator" class="status-indicator">
                <span id="status-text">Checking...</span>
            </div>
        </header>
        
        <div class="grid">
            <div class="card">
                <h2>System Health</h2>
                <div id="health-status">Loading...</div>
            </div>
            
            <div class="card">
                <h2>System Metrics</h2>
                <div id="metrics-display">Loading...</div>
            </div>
            
            <div class="card">
                <h2>Backup Status</h2>
                <div id="backup-status">Loading...</div>
                <button onclick="runBackup()" class="btn btn-primary">Run All Backups</button>
            </div>
            
            <div class="card">
                <h2>Rate Limiting</h2>
                <div id="rate-limits">Loading...</div>
            </div>
        </div>
        
        <footer>
            <p>Last updated: <span id="last-update">Never</span></p>
            <p>Auto-refresh: <span id="refresh-status">On</span></p>
        </footer>
    </div>
</body>
</html>"""
    
    def _get_dashboard_css(self) -> str:
        """Get the dashboard CSS content."""
        return """
* { box-sizing: border-box; margin: 0; padding: 0; }

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #f5f6fa;
    color: #2c3e50;
    line-height: 1.6;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}

header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 30px;
    padding: 20px 0;
    border-bottom: 2px solid #ddd;
}

h1 {
    color: #2c3e50;
    font-size: 2.5rem;
    font-weight: 300;
}

.status-indicator {
    display: flex;
    align-items: center;
    font-weight: 600;
}

.status-indicator.healthy { color: #27ae60; }
.status-indicator.warning { color: #f39c12; }
.status-indicator.critical { color: #e74c3c; }
.status-indicator.unknown { color: #95a5a6; }

.grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}

.card {
    background: white;
    padding: 25px;
    border-radius: 10px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    border: 1px solid #e0e0e0;
}

.card h2 {
    margin-bottom: 15px;
    color: #2c3e50;
    font-size: 1.4rem;
    font-weight: 500;
}

.metric {
    display: flex;
    justify-content: space-between;
    margin: 8px 0;
    padding: 5px 0;
    border-bottom: 1px solid #f0f0f0;
}

.metric:last-child {
    border-bottom: none;
}

.metric-label {
    font-weight: 500;
    color: #555;
}

.metric-value {
    font-weight: 600;
}

.metric-value.good { color: #27ae60; }
.metric-value.warning { color: #f39c12; }
.metric-value.bad { color: #e74c3c; }

.btn {
    background: #3498db;
    color: white;
    border: none;
    padding: 10px 20px;
    border-radius: 5px;
    cursor: pointer;
    font-size: 14px;
    margin-top: 15px;
    transition: background 0.2s;
}

.btn:hover {
    background: #2980b9;
}

.btn-primary {
    background: #3498db;
}

.btn-success {
    background: #27ae60;
}

.btn-warning {
    background: #f39c12;
}

footer {
    text-align: center;
    padding: 20px 0;
    color: #7f8c8d;
    border-top: 1px solid #ddd;
}

.loading {
    text-align: center;
    color: #7f8c8d;
    font-style: italic;
}

.error {
    color: #e74c3c;
    background: #fdf2f2;
    padding: 10px;
    border-radius: 5px;
    border: 1px solid #f5c6cb;
}
"""
    
    def _get_dashboard_js(self) -> str:
        """Get the dashboard JavaScript content."""
        return """
let refreshInterval;
let isRefreshing = true;

document.addEventListener('DOMContentLoaded', function() {
    loadDashboardData();
    startAutoRefresh();
});

function loadDashboardData() {
    Promise.all([
        fetch('/api/status').then(r => r.json()),
        fetch('/api/metrics').then(r => r.json()),
        fetch('/api/backups').then(r => r.json()),
        fetch('/api/rate_limits').then(r => r.json())
    ]).then(([status, metrics, backups, rateLimits]) => {
        updateHealthStatus(status.health);
        updateMetrics(metrics);
        updateBackupStatus(backups);
        updateRateLimits(rateLimits);
        updateLastUpdate();
    }).catch(error => {
        console.error('Failed to load dashboard data:', error);
        showError('Failed to load dashboard data');
    });
}

function updateHealthStatus(health) {
    const statusEl = document.getElementById('status-text');
    const statusIndicator = document.getElementById('status-indicator');
    const healthStatusEl = document.getElementById('health-status');
    
    // Update status indicator
    statusEl.textContent = health.overall_status.toUpperCase();
    statusIndicator.className = 'status-indicator ' + health.overall_status;
    
    // Update health details
    let healthHtml = '<div class="metric"><span class="metric-label">Overall Status</span><span class="metric-value ' + getStatusClass(health.overall_status) + '">' + health.overall_status + '</span></div>';
    
    Object.entries(health.checks).forEach(([name, check]) => {
        healthHtml += '<div class="metric"><span class="metric-label">' + formatLabel(name) + '</span><span class="metric-value ' + getStatusClass(check.status) + '">' + check.status + '</span></div>';
    });
    
    healthStatusEl.innerHTML = healthHtml;
}

function updateMetrics(metrics) {
    const metricsEl = document.getElementById('metrics-display');
    
    let metricsHtml = '';
    metricsHtml += '<div class="metric"><span class="metric-label">CPU Usage</span><span class="metric-value ' + getPercentageClass(metrics.system.cpu_percent) + '">' + metrics.system.cpu_percent.toFixed(1) + '%</span></div>';
    metricsHtml += '<div class="metric"><span class="metric-label">Memory Usage</span><span class="metric-value ' + getPercentageClass(metrics.system.memory_percent) + '">' + metrics.system.memory_percent.toFixed(1) + '%</span></div>';
    metricsHtml += '<div class="metric"><span class="metric-label">Disk Usage</span><span class="metric-value ' + getPercentageClass(metrics.system.disk_percent) + '">' + metrics.system.disk_percent.toFixed(1) + '%</span></div>';
    
    metricsEl.innerHTML = metricsHtml;
}

function updateBackupStatus(backups) {
    const backupEl = document.getElementById('backup-status');
    
    let backupHtml = '';
    backupHtml += '<div class="metric"><span class="metric-label">Total Jobs</span><span class="metric-value">' + backups.total_jobs + '</span></div>';
    backupHtml += '<div class="metric"><span class="metric-label">Enabled Jobs</span><span class="metric-value good">' + backups.enabled_jobs + '</span></div>';
    
    Object.entries(backups.jobs).forEach(([name, job]) => {
        const status = job.should_run ? 'overdue' : 'scheduled';
        const statusClass = job.should_run ? 'warning' : 'good';
        backupHtml += '<div class="metric"><span class="metric-label">' + formatLabel(name) + '</span><span class="metric-value ' + statusClass + '">' + status + '</span></div>';
    });
    
    backupEl.innerHTML = backupHtml;
}

function updateRateLimits(rateLimits) {
    const rateLimitEl = document.getElementById('rate-limits');
    
    let rateLimitHtml = '';
    rateLimitHtml += '<div class="metric"><span class="metric-label">Active Keys</span><span class="metric-value">' + rateLimits.active_keys + '</span></div>';
    rateLimitHtml += '<div class="metric"><span class="metric-label">Blocked Keys</span><span class="metric-value ' + (rateLimits.blocked_keys > 0 ? 'warning' : 'good') + '">' + rateLimits.blocked_keys + '</span></div>';
    rateLimitHtml += '<div class="metric"><span class="metric-label">Total Keys</span><span class="metric-value">' + rateLimits.total_keys + '</span></div>';
    
    rateLimitEl.innerHTML = rateLimitHtml;
}

function runBackup() {
    const btn = event.target;
    btn.disabled = true;
    btn.textContent = 'Running...';
    
    fetch('/api/backup/run', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({job_name: 'all'})
    })
    .then(r => r.json())
    .then(result => {
        if (result.success) {
            alert('All backups completed successfully');
        } else {
            alert('Some backups failed - check logs');
        }
        loadDashboardData();
    })
    .catch(error => {
        alert('Backup failed: ' + error);
    })
    .finally(() => {
        btn.disabled = false;
        btn.textContent = 'Run All Backups';
    });
}

function startAutoRefresh() {
    refreshInterval = setInterval(loadDashboardData, 30000); // 30 seconds
    document.getElementById('refresh-status').textContent = 'On (30s)';
}

function updateLastUpdate() {
    document.getElementById('last-update').textContent = new Date().toLocaleTimeString();
}

function formatLabel(str) {
    return str.replace(/_/g, ' ').replace(/\\b\\w/g, l => l.toUpperCase());
}

function getStatusClass(status) {
    if (status === 'healthy') return 'good';
    if (status === 'warning') return 'warning';
    if (status === 'critical') return 'bad';
    return '';
}

function getPercentageClass(percent) {
    if (percent < 70) return 'good';
    if (percent < 90) return 'warning';
    return 'bad';
}

function showError(message) {
    const errorEl = document.createElement('div');
    errorEl.className = 'error';
    errorEl.textContent = message;
    document.querySelector('.container').prepend(errorEl);
    setTimeout(() => errorEl.remove(), 5000);
}
"""

class SimpleDashboard:
    """Simple web dashboard for BLNCS monitoring."""
    
    def __init__(self, port: int = 8080, host: str = "0.0.0.0"):
        """Initialize dashboard."""
        self.port = port
        self.host = host
        self.server: Optional[HTTPServer] = None
        self.server_thread: Optional[threading.Thread] = None
        self.logger = get_logger(__name__)
        self.running = False
    
    def start(self):
        """Start the dashboard server."""
        if self.running:
            self.logger.warning("Dashboard is already running")
            return
        
        try:
            self.server = HTTPServer((self.host, self.port), DashboardHandler)
            self.server.start_time = time.time()
            
            def server_thread():
                self.logger.info(f"Dashboard started on http://{self.host}:{self.port}")
                self.server.serve_forever()
            
            self.server_thread = threading.Thread(target=server_thread, daemon=True)
            self.server_thread.start()
            self.running = True
            
        except Exception as e:
            self.logger.error(f"Failed to start dashboard: {e}")
            raise
    
    def stop(self):
        """Stop the dashboard server."""
        if not self.running or not self.server:
            return
        
        self.server.shutdown()
        self.server.server_close()
        
        if self.server_thread:
            self.server_thread.join(timeout=5)
        
        self.running = False
        self.logger.info("Dashboard stopped")

# Global dashboard instance
_dashboard: Optional[SimpleDashboard] = None

def get_dashboard(port: int = 8080) -> SimpleDashboard:
    """Get global dashboard instance."""
    global _dashboard
    if _dashboard is None:
        _dashboard = SimpleDashboard(port=port)
    return _dashboard

if __name__ == "__main__":
    # Start the dashboard
    dashboard = get_dashboard()
    
    try:
        dashboard.start()
        print("Dashboard running at http://localhost:8080")
        print("Press Ctrl+C to stop")
        
        # Keep running
        import signal
        signal.pause()
    except KeyboardInterrupt:
        print("Stopping dashboard...")
        dashboard.stop()