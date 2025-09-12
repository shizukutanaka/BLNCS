#!/usr/bin/env python3
"""
BLNCS Static Routes
Routes for serving static content and assets.
"""

from flask import Blueprint, send_file, send_from_directory, request, jsonify
from pathlib import Path
import mimetypes
import logging

logger = logging.getLogger(__name__)

static_routes = Blueprint('static', __name__)

# Define static directories
STATIC_DIR = Path(__file__).parent / 'static'
TEMPLATE_DIR = Path(__file__).parent / 'templates'

@static_routes.route('/static/<path:filename>')
def serve_static(filename):
    """Serve static files"""
    try:
        return send_from_directory(STATIC_DIR, filename)
    except FileNotFoundError:
        return jsonify({'error': 'File not found'}), 404

@static_routes.route('/assets/<path:filename>')
def serve_assets(filename):
    """Serve asset files (alias for static)"""
    try:
        return send_from_directory(STATIC_DIR, filename)
    except FileNotFoundError:
        return jsonify({'error': 'Asset not found'}), 404

@static_routes.route('/favicon.ico')
def favicon():
    """Serve favicon"""
    favicon_path = STATIC_DIR / 'images' / 'favicon.ico'
    if favicon_path.exists():
        return send_file(favicon_path)
    else:
        # Return default favicon if custom one doesn't exist
        return '', 204

@static_routes.route('/robots.txt')
def robots():
    """Serve robots.txt"""
    robots_content = """User-agent: *
Disallow: /api/
Disallow: /admin/
Allow: /
"""
    return robots_content, 200, {'Content-Type': 'text/plain'}

@static_routes.route('/manifest.json')
def manifest():
    """Serve PWA manifest"""
    manifest_data = {
        "name": "BLNCS Dashboard",
        "short_name": "BLNCS",
        "description": "Bitcoin Lightning Network Control System Dashboard",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#ffffff",
        "theme_color": "#0066cc",
        "icons": [
            {
                "src": "/static/images/icon-192.png",
                "sizes": "192x192",
                "type": "image/png"
            },
            {
                "src": "/static/images/icon-512.png",
                "sizes": "512x512",
                "type": "image/png"
            }
        ]
    }
    
    return jsonify(manifest_data)

@static_routes.route('/sw.js')
def service_worker():
    """Serve service worker for PWA"""
    sw_content = """
// BLNCS Service Worker
const CACHE_NAME = 'blncs-dashboard-v1';
const urlsToCache = [
    '/',
    '/static/css/dashboard.css',
    '/static/js/dashboard.js',
    '/static/images/logo.png'
];

self.addEventListener('install', function(event) {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(function(cache) {
                return cache.addAll(urlsToCache);
            })
    );
});

self.addEventListener('fetch', function(event) {
    event.respondWith(
        caches.match(event.request)
            .then(function(response) {
                if (response) {
                    return response;
                }
                return fetch(event.request);
            }
        )
    );
});
"""
    
    return sw_content, 200, {'Content-Type': 'application/javascript'}

@static_routes.route('/.well-known/security.txt')
def security_txt():
    """Serve security.txt for security contact info"""
    security_content = """Contact: security@blncs.org
Expires: 2024-12-31T23:59:59.000Z
Encryption: https://keys.openpgp.org/vks/v1/by-fingerprint/YOUR_PGP_KEY
Preferred-Languages: en
Canonical: https://blncs.org/.well-known/security.txt
Policy: https://blncs.org/security-policy
"""
    
    return security_content, 200, {'Content-Type': 'text/plain'}

def init_static_files():
    """Initialize static file structure"""
    # Create static directories if they don't exist
    directories = [
        STATIC_DIR / 'css',
        STATIC_DIR / 'js',
        STATIC_DIR / 'images',
        STATIC_DIR / 'fonts',
        STATIC_DIR / 'data'
    ]
    
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)
    
    # Create basic CSS file if it doesn't exist
    css_file = STATIC_DIR / 'css' / 'dashboard.css'
    if not css_file.exists():
        create_default_css(css_file)
    
    # Create basic JS file if it doesn't exist
    js_file = STATIC_DIR / 'js' / 'dashboard.js'
    if not js_file.exists():
        create_default_js(js_file)

def create_default_css(css_file: Path):
    """Create default CSS file"""
    css_content = """/* BLNCS Dashboard Styles */
:root {
    --primary-color: #0066cc;
    --secondary-color: #6c757d;
    --success-color: #28a745;
    --warning-color: #ffc107;
    --danger-color: #dc3545;
    --info-color: #17a2b8;
    --light-color: #f8f9fa;
    --dark-color: #343a40;
    --font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: var(--font-family);
    line-height: 1.6;
    color: var(--dark-color);
    background-color: #f5f5f5;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 0 15px;
}

.header {
    background: var(--primary-color);
    color: white;
    padding: 1rem 0;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.nav {
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.nav-brand {
    font-size: 1.5rem;
    font-weight: bold;
}

.nav-menu {
    display: flex;
    list-style: none;
    gap: 2rem;
}

.nav-menu a {
    color: white;
    text-decoration: none;
    padding: 0.5rem 1rem;
    border-radius: 4px;
    transition: background-color 0.3s;
}

.nav-menu a:hover,
.nav-menu a.active {
    background-color: rgba(255,255,255,0.1);
}

.main-content {
    padding: 2rem 0;
}

.dashboard-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 2rem;
    margin-top: 2rem;
}

.card {
    background: white;
    border-radius: 8px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    padding: 1.5rem;
    border: 1px solid #e9ecef;
}

.card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1rem;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid #e9ecef;
}

.card-title {
    font-size: 1.25rem;
    font-weight: 600;
    color: var(--dark-color);
}

.badge {
    display: inline-block;
    padding: 0.25rem 0.5rem;
    font-size: 0.75rem;
    font-weight: 600;
    border-radius: 4px;
    text-transform: uppercase;
}

.badge-success {
    background-color: var(--success-color);
    color: white;
}

.badge-warning {
    background-color: var(--warning-color);
    color: var(--dark-color);
}

.badge-danger {
    background-color: var(--danger-color);
    color: white;
}

.btn {
    display: inline-block;
    padding: 0.5rem 1rem;
    border: none;
    border-radius: 4px;
    text-decoration: none;
    cursor: pointer;
    transition: all 0.3s;
    font-size: 0.9rem;
}

.btn-primary {
    background-color: var(--primary-color);
    color: white;
}

.btn-primary:hover {
    background-color: #0056b3;
}

.btn-success {
    background-color: var(--success-color);
    color: white;
}

.btn-success:hover {
    background-color: #1e7e34;
}

.btn-warning {
    background-color: var(--warning-color);
    color: var(--dark-color);
}

.btn-warning:hover {
    background-color: #e0a800;
}

.table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 1rem;
}

.table th,
.table td {
    padding: 0.75rem;
    text-align: left;
    border-bottom: 1px solid #e9ecef;
}

.table th {
    background-color: var(--light-color);
    font-weight: 600;
}

.progress {
    width: 100%;
    height: 20px;
    background-color: #e9ecef;
    border-radius: 10px;
    overflow: hidden;
}

.progress-bar {
    height: 100%;
    background-color: var(--primary-color);
    transition: width 0.3s;
}

.alert {
    padding: 1rem;
    border-radius: 4px;
    margin-bottom: 1rem;
}

.alert-success {
    background-color: #d4edda;
    color: #155724;
    border: 1px solid #c3e6cb;
}

.alert-warning {
    background-color: #fff3cd;
    color: #856404;
    border: 1px solid #ffeaa7;
}

.alert-danger {
    background-color: #f8d7da;
    color: #721c24;
    border: 1px solid #f5c6cb;
}

.loading {
    display: inline-block;
    width: 20px;
    height: 20px;
    border: 2px solid #f3f3f3;
    border-top: 2px solid var(--primary-color);
    border-radius: 50%;
    animation: spin 1s linear infinite;
}

@keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}

/* Responsive design */
@media (max-width: 768px) {
    .nav-menu {
        flex-direction: column;
        gap: 0.5rem;
    }
    
    .dashboard-grid {
        grid-template-columns: 1fr;
    }
}
"""
    
    with open(css_file, 'w') as f:
        f.write(css_content)

def create_default_js(js_file: Path):
    """Create default JavaScript file"""
    js_content = """// BLNCS Dashboard JavaScript
class BLNCSDashboard {
    constructor() {
        this.socket = null;
        this.refreshInterval = null;
        this.init();
    }
    
    init() {
        this.initWebSocket();
        this.initEventListeners();
        this.startAutoRefresh();
        console.log('BLNCS Dashboard initialized');
    }
    
    initWebSocket() {
        if (typeof io !== 'undefined') {
            this.socket = io();
            
            this.socket.on('connect', () => {
                console.log('WebSocket connected');
                this.subscribeToUpdates();
            });
            
            this.socket.on('disconnect', () => {
                console.log('WebSocket disconnected');
            });
            
            this.socket.on('metrics_update', (data) => {
                this.updateMetrics(data);
            });
            
            this.socket.on('status_update', (data) => {
                this.updateStatus(data);
            });
            
            this.socket.on('activity_update', (data) => {
                this.updateActivity(data);
            });
        }
    }
    
    subscribeToUpdates() {
        if (this.socket) {
            this.socket.emit('subscribe', { channel: 'metrics' });
            this.socket.emit('subscribe', { channel: 'status' });
            this.socket.emit('subscribe', { channel: 'activity' });
        }
    }
    
    initEventListeners() {
        // Navigation
        document.querySelectorAll('.nav-menu a').forEach(link => {
            link.addEventListener('click', this.handleNavigation.bind(this));
        });
        
        // Refresh buttons
        document.querySelectorAll('.btn-refresh').forEach(btn => {
            btn.addEventListener('click', this.handleRefresh.bind(this));
        });
        
        // Action buttons
        document.querySelectorAll('.btn-action').forEach(btn => {
            btn.addEventListener('click', this.handleAction.bind(this));
        });
    }
    
    startAutoRefresh() {
        this.refreshInterval = setInterval(() => {
            this.refreshDashboard();
        }, 30000); // 30 seconds
    }
    
    refreshDashboard() {
        fetch('/api/dashboard/status')
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    this.updateDashboardData(data);
                }
            })
            .catch(error => {
                console.error('Dashboard refresh failed:', error);
            });
    }
    
    updateDashboardData(data) {
        // Update system status
        const statusElement = document.querySelector('.system-status');
        if (statusElement && data.status) {
            statusElement.textContent = data.status.health || 'Unknown';
            statusElement.className = `system-status badge badge-${this.getStatusClass(data.status.health)}`;
        }
        
        // Update metrics
        if (data.metrics) {
            this.updateMetrics({ data: data.metrics });
        }
    }
    
    updateMetrics(data) {
        const metrics = data.data;
        
        // CPU usage
        this.updateProgressBar('.cpu-usage', metrics.system?.cpu_percent || 0);
        
        // Memory usage
        this.updateProgressBar('.memory-usage', metrics.system?.memory_percent || 0);
        
        // Disk usage
        this.updateProgressBar('.disk-usage', metrics.system?.disk_usage || 0);
    }
    
    updateStatus(data) {
        // Update system status indicators
        const statusData = data.status?.data || {};
        
        // Update version
        const versionElement = document.querySelector('.system-version');
        if (versionElement) {
            versionElement.textContent = statusData.version || '2.0.0';
        }
    }
    
    updateActivity(data) {
        const activityList = document.querySelector('.activity-list');
        if (!activityList || !data.data) return;
        
        activityList.innerHTML = '';
        
        data.data.slice(0, 5).forEach(activity => {
            const item = document.createElement('div');
            item.className = 'activity-item';
            item.innerHTML = `
                <div class="activity-type">${activity.type}</div>
                <div class="activity-description">${activity.action} - ${activity.resource}</div>
                <div class="activity-time">${this.formatTime(activity.timestamp)}</div>
            `;
            activityList.appendChild(item);
        });
    }
    
    updateProgressBar(selector, value) {
        const progressBar = document.querySelector(`${selector} .progress-bar`);
        if (progressBar) {
            progressBar.style.width = `${value}%`;
            
            // Update color based on value
            if (value > 90) {
                progressBar.style.backgroundColor = 'var(--danger-color)';
            } else if (value > 70) {
                progressBar.style.backgroundColor = 'var(--warning-color)';
            } else {
                progressBar.style.backgroundColor = 'var(--success-color)';
            }
        }
        
        const valueElement = document.querySelector(`${selector} .progress-value`);
        if (valueElement) {
            valueElement.textContent = `${value}%`;
        }
    }
    
    getStatusClass(status) {
        switch (status) {
            case 'healthy': return 'success';
            case 'warning': return 'warning';
            case 'unhealthy': return 'danger';
            default: return 'secondary';
        }
    }
    
    formatTime(timestamp) {
        const date = new Date(timestamp);
        const now = new Date();
        const diff = now - date;
        
        if (diff < 60000) return 'Just now';
        if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
        if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
        return `${Math.floor(diff / 86400000)}d ago`;
    }
    
    handleNavigation(event) {
        const link = event.currentTarget;
        const href = link.getAttribute('href');
        
        if (href.startsWith('#')) {
            event.preventDefault();
            this.showSection(href.substring(1));
        }
    }
    
    handleRefresh(event) {
        const btn = event.currentTarget;
        btn.classList.add('loading');
        
        this.refreshDashboard();
        
        setTimeout(() => {
            btn.classList.remove('loading');
        }, 1000);
    }
    
    handleAction(event) {
        const btn = event.currentTarget;
        const action = btn.dataset.action;
        
        switch (action) {
            case 'create_backup':
                this.createBackup();
                break;
            case 'validate_backups':
                this.validateBackups();
                break;
            case 'create_schedule':
                this.createSchedule();
                break;
            default:
                console.log('Unknown action:', action);
        }
    }
    
    createBackup() {
        // Open backup creation modal/form
        console.log('Creating backup...');
    }
    
    validateBackups() {
        // Validate existing backups
        console.log('Validating backups...');
    }
    
    createSchedule() {
        // Open schedule creation modal/form
        console.log('Creating schedule...');
    }
    
    showSection(sectionId) {
        // Hide all sections
        document.querySelectorAll('.dashboard-section').forEach(section => {
            section.style.display = 'none';
        });
        
        // Show target section
        const targetSection = document.getElementById(sectionId);
        if (targetSection) {
            targetSection.style.display = 'block';
        }
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new BLNCSDashboard();
});
"""
    
    with open(js_file, 'w') as f:
        f.write(js_content)

# Initialize static files when module is imported
init_static_files()